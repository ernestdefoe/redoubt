//! The `redoubt scan` command.

use anyhow::{Context, Result};
use redoubt_core::config::Config;
use redoubt_core::scanner::{ScanEngine, ScanOutcome};
use redoubt_core::verdict::{Severity, Verdict};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use crate::term::{self, Style};

/// Counters shared across scan workers.
#[derive(Default)]
struct Counters {
    scanned: AtomicU64,
    skipped: AtomicU64,
    malicious: AtomicU64,
    suspicious: AtomicU64,
    allowlisted: AtomicU64,
    bytes: AtomicU64,
}

pub struct ScanArgs {
    pub paths: Vec<PathBuf>,
    pub threads: usize,
    pub show_clean: bool,
    pub json: bool,
    pub follow_symlinks: bool,
    pub show_skipped: bool,
}

pub fn run(cfg: &Config, args: ScanArgs) -> Result<()> {
    let load_started = Instant::now();
    let engine = ScanEngine::load(cfg.clone()).context("loading the scanning engine")?;
    let stats = engine.stats();
    let load_time = load_started.elapsed();

    if !args.json {
        println!(
            "{}",
            Style::Dim.paint(&format!(
                "engine loaded in {:.2}s  \u{2022}  db v{}  \u{2022}  {} hashes, {} section hashes, \
                 {} body patterns, {} YARA rules",
                load_time.as_secs_f64(),
                stats.db_version,
                crate::commas(stats.file_hashes),
                crate::commas(stats.section_hashes),
                crate::commas(stats.body_patterns as u64),
                crate::commas(stats.yara_rules as u64),
            ))
        );
        if stats.yara_rules == 0 {
            println!(
                "{}",
                Style::Warn.paint(
                    "  note: no YARA rules installed - run `redoubt rules update` to add them"
                )
            );
        }
        println!(
            "{}",
            Style::Dim.paint(&format!("mode: {}", describe_mode(cfg)))
        );
        println!();
    }

    // Enumerate first so the work can be spread across threads and so the
    // total is known before scanning starts.
    let mut files = Vec::new();
    let mut walk_errors = Vec::new();
    for root in &args.paths {
        collect_files(root, args.follow_symlinks, &mut files, &mut walk_errors);
    }

    let counters = Counters::default();
    let findings: Mutex<Vec<Verdict>> = Mutex::new(Vec::new());
    let skips: Mutex<Vec<(PathBuf, String)>> = Mutex::new(Vec::new());
    let started = Instant::now();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(args.threads.max(1))
        .build()
        .context("building the scan thread pool")?;

    pool.install(|| {
        use rayon::prelude::*;
        // A session per worker thread: the YARA scanner inside it is not
        // shareable, and rebuilding one per file would dominate the cost.
        files.par_iter().for_each_init(
            || engine.session(),
            |session, path| {
                match session.scan_path(path) {
                    ScanOutcome::Skipped(reason) => {
                        counters.skipped.fetch_add(1, Ordering::Relaxed);
                        if args.show_skipped {
                            skips.lock().unwrap().push((path.clone(), reason.to_string()));
                        }
                    }
                    ScanOutcome::Scanned(v) => {
                        counters.scanned.fetch_add(1, Ordering::Relaxed);
                        counters.bytes.fetch_add(v.identity.size, Ordering::Relaxed);
                        if v.allowlisted_as.is_some() {
                            counters.allowlisted.fetch_add(1, Ordering::Relaxed);
                        }
                        match v.severity {
                            Severity::Malicious => {
                                counters.malicious.fetch_add(1, Ordering::Relaxed);
                            }
                            Severity::Suspicious => {
                                counters.suspicious.fetch_add(1, Ordering::Relaxed);
                            }
                            Severity::Clean => {}
                        }
                        if !v.is_clean() || args.show_clean {
                            findings.lock().unwrap().push(*v);
                        }
                    }
                }
            },
        );
    });

    let elapsed = started.elapsed();
    let mut findings = findings.into_inner().unwrap();
    // Worst first, then slowest, so the important line is never buried.
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.scan_micros.cmp(&a.scan_micros))
    });

    if args.json {
        for v in &findings {
            println!("{}", serde_json::to_string(v)?);
        }
        return Ok(());
    }

    for v in &findings {
        print_verdict(v);
    }

    let skips = skips.into_inner().unwrap();
    if !skips.is_empty() {
        for (path, reason) in &skips {
            println!(
                "{}  {}",
                Style::Dim.paint(&format!("{:>10}", "skipped")),
                path.display()
            );
            println!("            {}", Style::Dim.paint(reason));
        }
        println!();
    }

    print_summary(&counters, findings.len(), elapsed, cfg);

    if !walk_errors.is_empty() {
        println!();
        println!(
            "{}",
            Style::Warn.paint(&format!(
                "  {} path(s) could not be enumerated and were NOT scanned:",
                walk_errors.len()
            ))
        );
        for e in walk_errors.iter().take(10) {
            println!("    {}", Style::Dim.paint(e));
        }
        if walk_errors.len() > 10 {
            println!(
                "    {}",
                Style::Dim.paint(&format!("... and {} more", walk_errors.len() - 10))
            );
        }
    }
    Ok(())
}

fn describe_mode(cfg: &Config) -> String {
    match cfg.mode {
        redoubt_core::config::Mode::Observe => {
            "observe - detections are reported only, nothing is quarantined".to_string()
        }
        redoubt_core::config::Mode::Enforce => {
            "ENFORCE - malicious files will be quarantined".to_string()
        }
    }
}

/// Walk `root`, collecting files and *reporting* anything that could not be
/// enumerated.
///
/// Swallowing walk errors would be a real hole: a directory the scanner cannot
/// read would silently contribute zero files, and the run would still report
/// success. A scanner that quietly covers less than it claims is worse than
/// one that admits it missed something.
fn collect_files(
    root: &Path,
    follow_symlinks: bool,
    out: &mut Vec<PathBuf>,
    errors: &mut Vec<String>,
) {
    if root.is_file() {
        out.push(root.to_path_buf());
        return;
    }
    for entry in walkdir::WalkDir::new(root).follow_links(follow_symlinks) {
        match entry {
            Ok(e) if e.file_type().is_file() => out.push(e.into_path()),
            Ok(_) => {}
            Err(e) => {
                let where_ = e
                    .path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| root.display().to_string());
                errors.push(format!("{where_}: {e}"));
            }
        }
    }
}

fn print_verdict(v: &Verdict) {
    let (tag, style) = match v.severity {
        Severity::Malicious => ("MALICIOUS", Style::Bad),
        Severity::Suspicious => ("suspicious", Style::Warn),
        Severity::Clean => ("clean", Style::Good),
    };

    println!("{}  {}", style.paint(&format!("{tag:>10}")), v.path.display());

    if let Some(name) = &v.allowlisted_as {
        println!("            {}", Style::Dim.paint(&format!("allowlisted as {name}")));
    }
    for d in &v.detections {
        let detail = d.detail.as_deref().unwrap_or("");
        println!(
            "            {} {}  {}",
            Style::Dim.paint(&format!("[{}]", d.engine)),
            d.name,
            Style::Dim.paint(detail)
        );
    }
    if !v.detections.is_empty() || v.allowlisted_as.is_some() {
        println!(
            "            {}",
            Style::Dim.paint(&format!(
                "{} bytes  \u{2022}  {:.1} ms  \u{2022}  sha256 {}",
                crate::commas(v.identity.size),
                v.scan_micros as f64 / 1000.0,
                v.identity.sha256.as_deref().unwrap_or("-")
            ))
        );
    }
    println!();
}

fn print_summary(counters: &Counters, _findings: usize, elapsed: std::time::Duration, cfg: &Config) {
    let scanned = counters.scanned.load(Ordering::Relaxed);
    let skipped = counters.skipped.load(Ordering::Relaxed);
    let malicious = counters.malicious.load(Ordering::Relaxed);
    let suspicious = counters.suspicious.load(Ordering::Relaxed);
    let allowlisted = counters.allowlisted.load(Ordering::Relaxed);
    let bytes = counters.bytes.load(Ordering::Relaxed);
    let secs = elapsed.as_secs_f64().max(0.000_001);

    term::rule();
    println!("{}", Style::Bold.paint("  scan summary"));
    println!(
        "  scanned      {:>10}   in {:.2}s  ({:.0} files/s, {:.1} MiB/s)",
        crate::commas(scanned),
        elapsed.as_secs_f64(),
        scanned as f64 / secs,
        bytes as f64 / 1_048_576.0 / secs,
    );
    if skipped > 0 {
        println!("  skipped      {:>10}", crate::commas(skipped));
    }
    if allowlisted > 0 {
        println!("  allowlisted  {:>10}", crate::commas(allowlisted));
    }

    let mal_line = format!("  malicious    {:>10}", crate::commas(malicious));
    println!(
        "{}",
        if malicious > 0 { Style::Bad.paint(&mal_line) } else { mal_line }
    );
    let sus_line = format!("  suspicious   {:>10}", crate::commas(suspicious));
    println!(
        "{}",
        if suspicious > 0 { Style::Warn.paint(&sus_line) } else { sus_line }
    );

    if malicious > 0 && cfg.mode == redoubt_core::config::Mode::Observe {
        println!();
        println!(
            "{}",
            Style::Warn.paint(
                "  observe mode: nothing was quarantined. Review the findings above, then \
                 set mode = \"enforce\" in config.toml when you trust them."
            )
        );
    }
}
