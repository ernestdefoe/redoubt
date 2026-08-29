//! `redoubt` - command line front end.
//!
//! Everything the service does is reachable from here, which keeps the engine
//! testable without installing anything.

mod scan;
mod term;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use redoubt_core::config::Config;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser)]
#[command(
    name = "redoubt",
    version,
    about = "Redoubt - signature database and scanning engine"
)]
struct Cli {
    /// Config file to use. Defaults to %ProgramData%\Redoubt\config.toml.
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Signature database operations.
    #[command(subcommand)]
    Db(DbCommand),

    /// YARA rule set operations.
    #[command(subcommand)]
    Rules(RulesCommand),

    /// Scan files or directories on demand.
    Scan {
        /// Files or directories to scan.
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// Worker threads. 0 picks a sensible default for this machine.
        #[arg(long, short = 'j', default_value_t = 0)]
        threads: usize,

        /// Also list files that came back clean.
        #[arg(long)]
        show_clean: bool,

        /// Emit one JSON verdict per line instead of formatted output.
        #[arg(long)]
        json: bool,

        /// Follow symbolic links while walking directories.
        #[arg(long)]
        follow_symlinks: bool,

        /// List files that were not scanned, and why.
        #[arg(long)]
        show_skipped: bool,
    },

    /// Open the Redoubt interface.
    Ui {
        /// Port to bind on loopback. 0 picks a free one.
        #[arg(long, default_value_t = 7311)]
        port: u16,

        /// Do not open a browser window automatically.
        #[arg(long)]
        no_open: bool,
    },

    /// Show resolved configuration and where everything lives.
    Config,
}

#[derive(Subcommand)]
enum RulesCommand {
    /// Fetch the configured YARA rule repositories and recompile.
    Update,
    /// Report on the installed rule set without changing anything.
    Status,
}

#[derive(Subcommand)]
enum DbCommand {
    /// Fetch new containers from the mirror and recompile the index.
    Update {
        /// Recompile even if every container is already current.
        #[arg(long)]
        force: bool,
    },
    /// Report on the compiled index without changing anything.
    Status,
    /// Look up a hash in the compiled index.
    Lookup {
        /// Hex MD5, SHA-1 or SHA-256.
        hash: String,
        /// File size in bytes. Signatures constrained to a size need this to
        /// match; omit to test only against any-size signatures.
        #[arg(long)]
        size: Option<u64>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = match &cli.config {
        Some(p) => Config::load(p).with_context(|| format!("loading {}", p.display()))?,
        None => Config::load_or_init().context("loading configuration")?,
    };
    cfg.ensure_dirs().context("creating data directories")?;

    match cli.command {
        Command::Db(cmd) => run_db(&cfg, cmd),
        Command::Rules(cmd) => run_rules(&cfg, cmd),
        Command::Ui { port, no_open } => {
            let path = cli
                .config
                .clone()
                .unwrap_or_else(redoubt_core::config::default_config_path);
            redoubt_ui::serve(cfg.clone(), path, port, |bound| {
                let url = format!("http://127.0.0.1:{bound}/");
                println!("Redoubt interface running at {url}");
                println!("Press Ctrl-C to stop.");
                if !no_open {
                    // `start` is a cmd builtin, so it needs a shell. The empty
                    // first argument is the window title cmd otherwise steals
                    // from a quoted URL.
                    let _ = std::process::Command::new("cmd")
                        .args(["/C", "start", "", &url])
                        .spawn();
                }
            })
        }
        Command::Scan { paths, threads, show_clean, json, follow_symlinks, show_skipped } => {
            let threads = if threads > 0 { threads } else { cfg.worker_count() };
            scan::run(
                &cfg,
                scan::ScanArgs {
                    paths,
                    threads,
                    show_clean,
                    json,
                    follow_symlinks,
                    show_skipped,
                },
            )
        }
        Command::Config => {
            println!("{}", toml::to_string_pretty(&cfg)?);
            println!("# config file: {}", redoubt_core::config::default_config_path().display());
            Ok(())
        }
    }
}

fn run_rules(cfg: &Config, cmd: RulesCommand) -> Result<()> {
    match cmd {
        RulesCommand::Update => {
            println!("rules       {}", cfg.paths.rules.display());
            let enabled: Vec<_> =
                cfg.updates.yara_sources.iter().filter(|s| s.enabled).collect();
            println!("sources     {}
", enabled.len());

            let started = Instant::now();
            let report = redoubt_core::rulesupdate::update_rules(cfg, |line| {
                println!("{line}");
                let _ = std::io::stdout().flush();
            })?;

            println!();
            for s in &report.sources {
                match &s.error {
                    None => println!(
                        "  {:<12} {:>5} rule file(s)  {:>8.1} KiB",
                        s.name,
                        s.files_written,
                        s.bytes as f64 / 1024.0
                    ),
                    Some(e) => println!("  {:<12} FAILED  {e}", s.name),
                }
            }

            println!("
{} rules compiled", commas(report.compiled_rules as u64));
            if !report.compile_failures.is_empty() {
                println!(
                    "
  {} rule file(s) did not compile and are not loaded:",
                    report.compile_failures.len()
                );
                for (path, why) in report.compile_failures.iter().take(10) {
                    let name = path.file_name().map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| path.display().to_string());
                    println!("    {name}");
                    println!("      {}", why.lines().next().unwrap_or(why));
                }
                if report.compile_failures.len() > 10 {
                    println!("    ... and {} more", report.compile_failures.len() - 10);
                }
            }
            println!("
completed in {:.1}s", started.elapsed().as_secs_f64());
            Ok(())
        }

        RulesCommand::Status => {
            if !cfg.paths.rules.exists() {
                println!("no rules directory at {}", cfg.paths.rules.display());
                println!("run `redoubt rules update` to fetch them");
                return Ok(());
            }
            let started = Instant::now();
            let set = redoubt_core::rules::RuleSet::compile_dir(&cfg.paths.rules)?;
            let r = set.report();
            println!("rules dir      {}", cfg.paths.rules.display());
            println!("rule files     {:>12}", commas(r.compiled.len() as u64));
            println!("rules loaded   {:>12}", commas(r.total_rules as u64));
            println!("failed files   {:>12}", commas(r.failed.len() as u64));
            println!("compile time   {:>11.1}s", started.elapsed().as_secs_f64());
            Ok(())
        }
    }
}

fn index_path(cfg: &Config) -> PathBuf {
    cfg.paths.signatures.join("redoubt.sigidx")
}

fn run_db(cfg: &Config, cmd: DbCommand) -> Result<()> {
    match cmd {
        DbCommand::Update { force } => {
            let idx = index_path(cfg);
            println!("signatures  {}", cfg.paths.signatures.display());
            println!("index       {}", idx.display());
            println!(
                "clamav      {}",
                if cfg.updates.clamav_enabled { "via freshclam" } else { "disabled" }
            );
            println!("direct      {} source(s)\n", cfg.updates.direct_sources.len());

            let started = Instant::now();
            let report = redoubt_core::update::update(cfg, &idx, force, |line| {
                println!("{line}");
                let _ = std::io::stdout().flush();
            })?;

            println!();
            if let Some(compile) = &report.recompiled {
                println!("{}\n", compile.summary());
                println!("  file hashes    {:>12}", commas(compile.index.file_hashes));
                println!("  section hashes {:>12}", commas(compile.index.section_hashes));
                println!("  body patterns  {:>12}", commas(compile.index.body_patterns));
                println!("  allowlisted    {:>12}", commas(compile.index.allowlisted));
                if compile.malformed() > 0 {
                    println!("  malformed      {:>12}", commas(compile.malformed()));
                }
                let skipped = compile.skipped_by_format();
                if !skipped.is_empty() {
                    println!("\n  not indexed (formats this engine does not evaluate):");
                    for s in &skipped {
                        println!(
                            "    .{:<6} {:>3} file(s) {:>9.1} KiB   {}",
                            s.extension,
                            s.files,
                            s.bytes as f64 / 1024.0,
                            s.note
                        );
                    }
                }
            } else {
                println!("index unchanged");
            }

            let warnings = report.warnings();
            if !warnings.is_empty() {
                println!("\nwarnings:");
                for w in &warnings {
                    println!("  - {w}");
                }
            }
            println!("\ncompleted in {:.1}s", started.elapsed().as_secs_f64());
            Ok(())
        }

        DbCommand::Status => {
            let idx = index_path(cfg);
            if !idx.exists() {
                println!("no compiled index at {}", idx.display());
                println!("run `redoubt db update` to build one");
                return Ok(());
            }
            let index = redoubt_core::sigindex::SigIndex::open(&idx)?;
            let stats = index.stats();
            let size = std::fs::metadata(&idx)?.len();

            println!("index          {}", idx.display());
            println!("size           {:.1} MiB", size as f64 / 1048576.0);
            println!("database ver   {}", index.db_version());
            println!("built          {}", format_epoch(index.built_epoch()));
            println!();
            println!("file hashes    {:>12}", commas(stats.file_hashes));
            println!("section hashes {:>12}", commas(stats.section_hashes));
            println!("body patterns  {:>12}", commas(stats.body_patterns));
            println!("allowlisted    {:>12}", commas(stats.allowlisted));
            println!("               {:>12}  total", commas(stats.total()));
            println!();
            println!(
                "bytes per signature: {:.1}",
                size as f64 / stats.total().max(1) as f64
            );
            Ok(())
        }

        DbCommand::Lookup { hash, size } => {
            let idx = index_path(cfg);
            let index = redoubt_core::sigindex::SigIndex::open(&idx)
                .with_context(|| format!("opening {}", idx.display()))?;
            let parsed = redoubt_core::sigs::HashValue::from_hex(hash.trim())
                .context("hash must be 32, 40 or 64 hex characters")?;

            use redoubt_core::sigindex::Group;
            let size = size.unwrap_or(u64::MAX);
            let mut found = false;
            for (group, label) in [
                (Group::File, "file hash"),
                (Group::Section, "section hash"),
                (Group::Allow, "ALLOWLISTED"),
            ] {
                if let Some(name) = index.lookup(&parsed, group, size) {
                    println!("{label:<12} {name}");
                    found = true;
                }
            }
            if !found {
                println!("no match ({} {})", parsed.kind_str(), parsed);
            }
            Ok(())
        }
    }
}

fn format_epoch(epoch: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp(epoch as i64)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339).ok()
        })
        .unwrap_or_else(|| format!("epoch {epoch}"))
}

/// Thousands separators, because "6217483" tells you much less than "6,217,483".
pub fn commas(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::commas;

    #[test]
    fn formats_thousands_separators() {
        assert_eq!(commas(0), "0");
        assert_eq!(commas(7), "7");
        assert_eq!(commas(999), "999");
        assert_eq!(commas(1_000), "1,000");
        assert_eq!(commas(6_217_483), "6,217,483");
        assert_eq!(commas(1_000_000_000), "1,000,000,000");
    }
}
