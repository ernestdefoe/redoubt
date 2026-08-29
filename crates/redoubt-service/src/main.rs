//! `redoubtd` - Redoubt's resident protection.
//!
//! Runs three ways, all driving the same [`redoubt_service::Protection`] so
//! there is one implementation of protection rather than several that drift:
//!
//! - `redoubtd` - in the foreground, until interrupted.
//! - `redoubtd --service` - started by the Service Control Manager.
//! - `redoubtd install|uninstall|start|stop|status` - service management.

use anyhow::{Context, Result};
use redoubt_core::config::Config;
use redoubt_core::scanner::ScanEngine;
use redoubt_service::{install, Protection};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        Some("--service") => service_entry(),
        Some("install") => cmd_install(),
        Some("uninstall") => cmd_uninstall(),
        Some("start") => {
            install::start()?;
            println!("Redoubt protection started.");
            Ok(())
        }
        Some("stop") => {
            install::stop()?;
            println!("Redoubt protection stopped.");
            Ok(())
        }
        Some("status") => cmd_status(),
        Some("--help" | "-h" | "help") => {
            print_help();
            Ok(())
        }
        Some(other) => {
            eprintln!("unknown argument: {other}\n");
            print_help();
            std::process::exit(2);
        }
        None => run_foreground(),
    }
}

fn print_help() {
    println!(
        "redoubtd - Redoubt resident protection\n\
         \n\
         USAGE:\n\
         \x20 redoubtd                run in the foreground until interrupted\n\
         \x20 redoubtd install        register as a Windows service (needs admin)\n\
         \x20 redoubtd uninstall      remove the service (needs admin)\n\
         \x20 redoubtd start|stop     control the installed service (needs admin)\n\
         \x20 redoubtd status         report whether the service is installed\n\
         \n\
         Configuration lives at %ProgramData%\\Redoubt\\config.toml."
    );
}

fn cmd_install() -> Result<()> {
    let exe = install::install()?;
    println!("Registered '{}' as a Windows service.", install::DISPLAY_NAME);
    println!("  image: {}", exe.display());
    println!(
        "\nThe service is registered where the binary currently sits. Moving or \
         rebuilding it elsewhere will stop the service from starting."
    );
    println!("\nStart it now with:  redoubtd start");
    Ok(())
}

fn cmd_uninstall() -> Result<()> {
    install::uninstall()?;
    println!("Removed the Redoubt service.");
    Ok(())
}

fn cmd_status() -> Result<()> {
    match install::status() {
        install::Installed::Yes { running, image } => {
            println!("service   installed");
            println!("state     {}", if running { "running" } else { "stopped" });
            if let Some(p) = image {
                println!("image     {}", p.display());
            }
        }
        install::Installed::No => {
            println!("service   not installed");
            println!("\nInstall with an elevated prompt:  redoubtd install");
        }
        install::Installed::Unknown(e) => {
            println!("service   could not be determined");
            println!("reason    {e}");
        }
    }
    Ok(())
}

/// Build the engine and protection from the on-disk configuration.
fn build() -> Result<(Config, Protection)> {
    let cfg = Config::load_or_init().context("loading configuration")?;
    cfg.ensure_dirs().context("creating data directories")?;

    let engine = Arc::new(
        ScanEngine::load(cfg.clone())
            .context("loading the scanning engine - run `redoubt db update` first")?,
    );
    let protection = Protection::new(cfg.clone(), engine);
    Ok((cfg, protection))
}

fn run_foreground() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "redoubt_service=info,redoubt_core=warn".into()),
        )
        .init();

    let (cfg, protection) = build()?;
    let roots = protection.watch_roots();
    if roots.is_empty() {
        anyhow::bail!(
            "no watchable directories found; set realtime.watch_paths in {}",
            redoubt_core::config::default_config_path().display()
        );
    }
    protection.start().context("starting resident protection")?;

    println!("Redoubt resident protection");
    println!("  mode       {}", cfg.mode.as_str());
    println!("  workers    {}", cfg.worker_count());
    println!("  watching");
    for root in &roots {
        println!("               {}", root.display());
    }
    println!("\n{}\n", protection.status().note);
    println!("Press Ctrl-C to stop.");

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc_handler(move || stop.store(true, Ordering::Relaxed));
    }

    let mut last_report = std::time::Instant::now();
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(250));
        if last_report.elapsed() >= Duration::from_secs(60) {
            log_status(&protection);
            last_report = std::time::Instant::now();
        }
    }

    println!("\nstopping...");
    protection.stop();
    let s = protection.status();
    println!(
        "{} events, {} scanned, {} malicious, {} quarantined, {} ransomware alerts",
        s.counters.events,
        s.counters.scanned,
        s.counters.malicious,
        s.counters.quarantined,
        s.counters.ransomware_alerts
    );
    Ok(())
}

fn log_status(protection: &Protection) {
    let s = protection.status();
    tracing::info!(
        events = s.counters.events,
        scanned = s.counters.scanned,
        cache_hits = s.counters.cache_hits,
        malicious = s.counters.malicious,
        quarantined = s.counters.quarantined,
        ransomware = s.counters.ransomware_alerts,
        dropped = s.counters.dropped,
        queue = s.queue_depth,
        "status"
    );
}

// ---------------------------------------------------------------------------
// Service mode
// ---------------------------------------------------------------------------

windows_service::define_windows_service!(ffi_service_main, service_main);

fn service_entry() -> Result<()> {
    windows_service::service_dispatcher::start(install::SERVICE_NAME, ffi_service_main)
        .context("starting the service dispatcher")?;
    Ok(())
}

/// The SCM's entry point.
///
/// Failures here cannot be printed anywhere useful, so everything goes to the
/// Windows event log via `tracing` and the service reports a non-zero exit code
/// rather than appearing to start successfully and doing nothing.
fn service_main(_args: Vec<std::ffi::OsString>) {
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let log_dir = redoubt_core::config::data_root().join("logs");
    let _ = std::fs::create_dir_all(&log_dir);
    if let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir.join("service.log"))
    {
        let _ = tracing_subscriber::fmt()
            .with_writer(std::sync::Mutex::new(file))
            .with_ansi(false)
            .try_init();
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_handler = stop.clone();

    let handler = move |control| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                stop_for_handler.store(true, Ordering::Relaxed);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let Ok(handle) = service_control_handler::register(install::SERVICE_NAME, handler) else {
        return;
    };

    let running = |state, exit: u32| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    };

    let _ = handle.set_service_status(running(ServiceState::StartPending, 0));

    let protection = match build() {
        Ok((_, p)) => p,
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "could not start protection");
            // ERROR_SERVICE_SPECIFIC_ERROR; the log says what happened.
            let _ = handle.set_service_status(ServiceStatus {
                current_state: ServiceState::Stopped,
                exit_code: ServiceExitCode::ServiceSpecific(1),
                ..running(ServiceState::Stopped, 0)
            });
            return;
        }
    };

    if let Err(e) = protection.start() {
        tracing::error!(error = %format!("{e:#}"), "could not start the watcher");
        let _ = handle.set_service_status(ServiceStatus {
            current_state: ServiceState::Stopped,
            exit_code: ServiceExitCode::ServiceSpecific(2),
            ..running(ServiceState::Stopped, 0)
        });
        return;
    }

    let _ = handle.set_service_status(running(ServiceState::Running, 0));
    tracing::info!("Redoubt service started");

    let mut last_report = std::time::Instant::now();
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(250));
        if last_report.elapsed() >= Duration::from_secs(300) {
            log_status(&protection);
            last_report = std::time::Instant::now();
        }
    }

    let _ = handle.set_service_status(running(ServiceState::StopPending, 0));
    protection.stop();
    tracing::info!("Redoubt service stopped");
    let _ = handle.set_service_status(running(ServiceState::Stopped, 0));
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
