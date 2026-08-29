//! `redoubtd` - Redoubt's resident protection, headless.
//!
//! Runs the watcher and scan workers with no interface attached. The same
//! [`redoubt_service::Protection`] type is what the UI process drives, so
//! there is one implementation of protection rather than two that drift.
//!
//! Registering this as a Windows service is not done yet; for now it runs in
//! the foreground until interrupted, which is enough to leave it running in a
//! terminal or under any process supervisor.

use anyhow::{Context, Result};
use redoubt_core::config::Config;
use redoubt_core::scanner::ScanEngine;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "redoubt_service=info,redoubt_core=warn".into()),
        )
        .init();

    let cfg = Config::load_or_init().context("loading configuration")?;
    cfg.ensure_dirs().context("creating data directories")?;

    let engine = Arc::new(
        ScanEngine::load(cfg.clone())
            .context("loading the scanning engine - run `redoubt db update` first")?,
    );
    let stats = engine.stats();

    let protection = redoubt_service::Protection::new(cfg.clone(), engine);
    let roots = protection.watch_roots();
    if roots.is_empty() {
        anyhow::bail!(
            "no watchable directories found; set realtime.watch_paths in {}",
            redoubt_core::config::default_config_path().display()
        );
    }

    protection.start().context("starting resident protection")?;

    println!("Redoubt resident protection");
    println!(
        "  engine     db v{}, {} signatures, {} YARA rules",
        stats.db_version,
        stats.file_hashes + stats.section_hashes + stats.body_patterns as u64,
        stats.yara_rules
    );
    println!("  mode       {}", cfg.mode.as_str());
    println!("  workers    {}", cfg.worker_count());
    println!("  watching");
    for root in &roots {
        println!("               {}", root.display());
    }
    println!("\n{}\n", protection.status().note);
    println!("Press Ctrl-C to stop.");

    // Ctrl-C should stop the watcher and drain the workers rather than tearing
    // the process down mid-scan.
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc_handler(move || stop.store(true, Ordering::Relaxed));
    }

    let mut last_report = std::time::Instant::now();
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(250));

        if last_report.elapsed() >= std::time::Duration::from_secs(60) {
            let s = protection.status();
            tracing::info!(
                events = s.counters.events,
                scanned = s.counters.scanned,
                cache_hits = s.counters.cache_hits,
                malicious = s.counters.malicious,
                quarantined = s.counters.quarantined,
                dropped = s.counters.dropped,
                queue = s.queue_depth,
                "status"
            );
            last_report = std::time::Instant::now();
        }
    }

    println!("\nstopping...");
    protection.stop();

    let s = protection.status();
    println!(
        "{} events, {} scanned, {} cache hits, {} malicious, {} quarantined",
        s.counters.events,
        s.counters.scanned,
        s.counters.cache_hits,
        s.counters.malicious,
        s.counters.quarantined
    );
    Ok(())
}

/// Minimal Ctrl-C handling without pulling in another dependency.
///
/// `SetConsoleCtrlHandler` needs a plain function pointer, so the callback is
/// parked in a static rather than passed through.
fn ctrlc_handler<F: Fn() + Send + Sync + 'static>(f: F) {
    use std::sync::OnceLock;
    static HANDLER: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();
    let _ = HANDLER.set(Box::new(f));

    #[cfg(windows)]
    unsafe {
        unsafe extern "system" fn handler(_ctrl_type: u32) -> i32 {
            if let Some(f) = HANDLER.get() {
                f();
            }
            1 // handled
        }
        unsafe extern "system" {
            fn SetConsoleCtrlHandler(
                handler: Option<unsafe extern "system" fn(u32) -> i32>,
                add: i32,
            ) -> i32;
        }
        SetConsoleCtrlHandler(Some(handler), 1);
    }
}
