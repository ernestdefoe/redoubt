//! Resident protection.
//!
//! Watches the places files actually arrive, scans what changes, and - only in
//! enforce mode, and only for genuinely malicious verdicts - quarantines.
//!
//! # What this covers, and what it does not
//!
//! This is **detect-and-react**, not pre-execution blocking: a file is scanned
//! shortly after it lands, not before it can be opened. That is an honest and
//! useful level of protection for the way malware usually arrives on a desktop
//! (a download, an archive extraction, a dropper writing to `%TEMP%`), and it
//! needs no driver and no elevation.
//!
//! True pre-execution blocking needs a filesystem minifilter, and script
//! blocking needs an AMSI provider. Neither is built yet, and [`Status::note`]
//! says so rather than letting the UI imply otherwise.
//!
//! # Why a debounce
//!
//! A single file copy produces a burst of change notifications. Scanning on
//! each one would rescan a partially written file repeatedly and report
//! nonsense. Paths are therefore held for a short settle period and coalesced,
//! so one copy costs one scan.

pub mod elevate;
pub mod install;
pub mod ipc;
pub mod netblock;
pub mod process;
pub mod ransomware;
pub mod watcher;

use ransomware::{Alert, RansomwareGuard};

use anyhow::{Context, Result};
use crossbeam_channel::{bounded, Receiver, Sender};
use parking_lot::Mutex;
use redoubt_core::cache::{CacheKey, CachedVerdict, VerdictCache};
use redoubt_core::config::{Config, Mode};
use redoubt_core::quarantine::Quarantine;
use redoubt_core::scanner::{ScanEngine, ScanOutcome};
use redoubt_core::verdict::{Severity, Verdict};
use serde::Serialize;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// How many recent verdicts to keep for the UI.
const RECENT_CAPACITY: usize = 200;

/// Live counters.
#[derive(Debug, Default, Serialize)]
pub struct Counters {
    /// Change notifications received from the OS.
    pub events: AtomicU64,
    /// Paths that reached a scan worker.
    pub scanned: AtomicU64,
    /// Answered from the verdict cache without touching the file.
    pub cache_hits: AtomicU64,
    /// Dropped because the queue was full.
    pub dropped: AtomicU64,
    pub malicious: AtomicU64,
    pub suspicious: AtomicU64,
    pub quarantined: AtomicU64,
    /// Enforcement was wanted but failed.
    pub quarantine_failures: AtomicU64,
    /// Ransomware alerts raised.
    pub ransomware_alerts: AtomicU64,
    /// Processes terminated in response to one.
    pub processes_terminated: AtomicU64,
    /// Recovery-destroying tools seen starting.
    pub recovery_tools_seen: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> CounterSnapshot {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        CounterSnapshot {
            events: g(&self.events),
            scanned: g(&self.scanned),
            cache_hits: g(&self.cache_hits),
            dropped: g(&self.dropped),
            malicious: g(&self.malicious),
            suspicious: g(&self.suspicious),
            quarantined: g(&self.quarantined),
            quarantine_failures: g(&self.quarantine_failures),
            ransomware_alerts: g(&self.ransomware_alerts),
            processes_terminated: g(&self.processes_terminated),
            recovery_tools_seen: g(&self.recovery_tools_seen),
        }
    }
}

/// A plain copy of the counters, for serialising.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct CounterSnapshot {
    pub events: u64,
    pub scanned: u64,
    pub cache_hits: u64,
    pub dropped: u64,
    pub malicious: u64,
    pub suspicious: u64,
    pub quarantined: u64,
    pub quarantine_failures: u64,
    pub ransomware_alerts: u64,
    pub processes_terminated: u64,
    pub recovery_tools_seen: u64,
}

/// What the UI shows about resident protection.
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub running: bool,
    pub mode: String,
    /// Directories being watched.
    pub watching: Vec<PathBuf>,
    pub workers: usize,
    pub queue_depth: usize,
    pub counters: CounterSnapshot,
    pub cache_entries: usize,
    pub cache_hit_rate: f64,
    /// Behavioural ransomware detection.
    pub ransomware: RansomwareStatus,
    /// The scan channel the AMSI provider talks to.
    pub scan_channel: ScanChannelStatus,
    pub network: NetworkStatus,
    /// Plain statement of the protection level. Never dressed up.
    pub note: String,
}

/// The named-pipe scan channel.
#[derive(Debug, Clone, Serialize)]
pub struct ScanChannelStatus {
    pub listening: bool,
    /// Whether the AMSI provider is registered with Windows.
    ///
    /// Reported separately from `listening` because the two fail in opposite
    /// directions and are indistinguishable from outside: a pipe listening
    /// that nothing ever calls, and a registered provider with no service to
    /// ask. Either one on its own means scripts are not being scanned.
    pub provider_registered: bool,
    pub pipe: String,
    pub requests: u64,
    pub malicious: u64,
    pub suspicious: u64,
}

/// Outbound connection blocking.
#[derive(Debug, Clone, Serialize)]
pub struct NetworkStatus {
    /// Turned on in the configuration.
    pub enabled: bool,
    /// Filters are installed right now.
    pub enforcing: bool,
    /// Whether this process could install them at all. False in the
    /// interface, which is not elevated - reported so the page can explain
    /// that rather than show a permission error to somebody blameless.
    pub available: bool,
    pub ranges: usize,
    pub filters: usize,
    pub sources: Vec<String>,
    /// Why it is not enforcing, when it is not. Empty when it is.
    pub note: String,
}

/// What the ransomware guard is doing.
#[derive(Debug, Clone, Serialize)]
pub struct RansomwareStatus {
    pub enabled: bool,
    /// Decoy files currently planted.
    pub canaries: usize,
    /// Terminate the responsible process on a critical alert. Requires
    /// enforce mode as well.
    pub will_terminate: bool,
    pub alerts: Vec<Alert>,
}

struct Inner {
    cfg: Config,
    engine: Arc<ScanEngine>,
    cache: VerdictCache,
    quarantine: Quarantine,
    counters: Counters,
    recent: Mutex<VecDeque<Verdict>>,
    running: AtomicBool,
    tx: Sender<PathBuf>,
    rx: Receiver<PathBuf>,
    generation: u32,
    guard: RansomwareGuard,
    /// Sampled continuously by `process_loop`, and shared with the ransomware
    /// guard so attribution reads the sample from around the time of the
    /// event rather than taking a fresh one after the fact.
    proc_monitor: Arc<process::ProcessMonitor>,
}

/// A running (or stopped) protection instance.
#[derive(Clone)]
pub struct Protection {
    inner: Arc<Inner>,
    watcher: Arc<Mutex<Option<watcher::Watcher>>>,
    workers: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    proc_thread: Arc<Mutex<Option<std::thread::JoinHandle<()>>>>,
    /// Serves scan requests from the AMSI provider, which cannot hold an
    /// engine of its own - it is loaded into every AMSI host on the machine.
    scan_server: Arc<Mutex<Option<ipc::ScanServer>>>,
    netblock: Arc<Mutex<Option<netblock::NetBlocker>>>,
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Protection {
    /// Build a protection instance around an already-loaded engine.
    pub fn new(cfg: Config, engine: Arc<ScanEngine>) -> Self {
        let capacity = cfg.realtime.queue_capacity.max(64);
        let (tx, rx) = bounded(capacity);
        let generation = engine.stats().db_version;

        Self {
            inner: Arc::new(Inner {
                cache: VerdictCache::new(capacity * 8),
                quarantine: Quarantine::new(cfg.paths.quarantine.clone()),
                counters: Counters::default(),
                recent: Mutex::new(VecDeque::with_capacity(RECENT_CAPACITY)),
                running: AtomicBool::new(false),
                tx,
                rx,
                generation,
                guard: RansomwareGuard::new(cfg.ransomware.clone()),
                proc_monitor: Arc::new(process::ProcessMonitor::new()),
                engine,
                cfg,
            }),
            watcher: Arc::new(Mutex::new(None)),
            workers: Arc::new(Mutex::new(Vec::new())),
            proc_thread: Arc::new(Mutex::new(None)),
            scan_server: Arc::new(Mutex::new(None)),
            netblock: Arc::new(Mutex::new(None)),
        }
    }

    pub fn is_running(&self) -> bool {
        self.inner.running.load(Ordering::Relaxed)
    }

    /// Directories that will be watched.
    pub fn watch_roots(&self) -> Vec<PathBuf> {
        watcher::default_roots(&self.inner.cfg)
    }

    /// Start watching and scanning. Idempotent.
    pub fn start(&self) -> Result<()> {
        if self.is_running() {
            return Ok(());
        }
        let roots = self.watch_roots();
        if roots.is_empty() {
            anyhow::bail!("no watchable directories are configured");
        }

        self.inner.running.store(true, Ordering::Relaxed);

        // Workers first, so nothing is queued before anyone can drain it.
        let worker_count = self.inner.cfg.worker_count();
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let inner = self.inner.clone();
            handles.push(std::thread::spawn(move || worker_loop(inner)));
        }
        *self.workers.lock() = handles;

        let inner = self.inner.clone();
        let w = watcher::Watcher::start(&roots, move |path| {
            inner.counters.events.fetch_add(1, Ordering::Relaxed);
            // A full queue means the machine is producing files faster than we
            // can scan them. Dropping is the right failure: blocking here would
            // stall the watcher thread and lose events anyway, silently.
            if inner.tx.try_send(path).is_err() {
                inner.counters.dropped.fetch_add(1, Ordering::Relaxed);
            }
        })
        .context("starting the filesystem watcher")?;
        *self.watcher.lock() = Some(w);

        // Decoys go in after the watcher, so planting them is not itself seen
        // as suspicious activity - and they are planted only once, because
        // rewriting them on every start would look exactly like an attack.
        let planted = self.inner.guard.plant_canaries(&roots);

        // The guard attributes from the same continuously-sampled monitor.
        self.inner.guard.attach_monitor(self.inner.proc_monitor.clone());

        // Process polling runs on its own thread: it is the only way to see a
        // program start without a driver, and it must not compete with the
        // scan workers for the queue.
        {
            let inner = self.inner.clone();
            *self.proc_thread.lock() =
                Some(std::thread::spawn(move || process_loop(inner)));
        }

        // The scan channel. A failure here must not stop protection: file
        // watching is the primary defence and works without it; only script
        // scanning is lost.
        match ipc::ScanServer::start(self.inner.engine.clone()) {
            Ok(server) => *self.scan_server.lock() = Some(server),
            Err(e) => tracing::error!(error = %e, "scan channel unavailable"),
        }

        // Outbound blocking. Off unless asked for, and a failure here is
        // reported rather than fatal: losing C2 blocking is bad, losing file
        // scanning because of it would be worse.
        if self.inner.cfg.network.enabled {
            match self.start_netblock() {
                Ok(n) if n > 0 => tracing::info!(filters = n, "outbound blocking active"),
                Ok(_) => tracing::warn!("outbound blocking on, but no addresses to block"),
                Err(e) => tracing::error!(error = %e, "outbound blocking unavailable"),
            }
        }

        tracing::info!(
            roots = roots.len(),
            workers = worker_count,
            canaries = planted,
            "resident protection started"
        );
        Ok(())
    }

    /// Stop watching and drain the workers.
    pub fn stop(&self) {
        if !self.is_running() {
            return;
        }
        self.inner.running.store(false, Ordering::Relaxed);
        // Dropping the watcher stops new events; workers then see the flag.
        *self.watcher.lock() = None;

        let handles = std::mem::take(&mut *self.workers.lock());
        for h in handles {
            let _ = h.join();
        }
        if let Some(h) = self.proc_thread.lock().take() {
            let _ = h.join();
        }
        if let Some(mut server) = self.scan_server.lock().take() {
            server.stop();
        }
        // Dropping the blocker closes its dynamic WFP session, which is what
        // removes the filters. Leaving them behind would cut the machine off
        // with nothing running to explain why.
        *self.netblock.lock() = None;

        // Decoys are ours; do not leave them in the user's folders.
        self.inner.guard.remove_canaries();

        tracing::info!("resident protection stopped");
    }

    pub fn status(&self) -> Status {
        let cache = self.inner.cache.stats();
        let running = self.is_running();
        Status {
            running,
            mode: self.inner.cfg.mode.as_str().to_string(),
            watching: if running { self.watch_roots() } else { Vec::new() },
            workers: self.inner.cfg.worker_count(),
            queue_depth: self.inner.rx.len(),
            counters: self.inner.counters.snapshot(),
            cache_entries: cache.entries,
            cache_hit_rate: cache.hit_rate(),
            ransomware: RansomwareStatus {
                enabled: self.inner.cfg.ransomware.enabled,
                canaries: self.inner.guard.canary_count(),
                will_terminate: self.inner.cfg.ransomware.terminate_on_critical
                    && self.inner.cfg.mode == Mode::Enforce,
                alerts: self.inner.guard.alerts(),
            },
            network: {
                // Everything is read out of the lock and the guard dropped
                // before anything slow happens. Holding it across a filtering
                // engine call wedged every request on the machine: status is
                // polled every couple of seconds, and one blocked call there
                // takes the whole interface with it.
                let (enforcing, ranges, filters, sources) = {
                    let n = self.netblock.lock();
                    (
                        n.is_some(),
                        n.as_ref().map(|b| b.blocked_ranges()).unwrap_or(0),
                        n.as_ref().map(|b| b.filters_installed()).unwrap_or(0),
                        n.as_ref().map(|b| b.sources().to_vec()).unwrap_or_default(),
                    )
                };
                NetworkStatus {
                    enabled: self.inner.cfg.network.enabled,
                    enforcing,
                    available: enforcing || netblock::available(),
                    ranges,
                    filters,
                    sources,
                    note: self.network_note(enforcing),
                }
            },
            scan_channel: {
                let server = self.scan_server.lock();
                let c = server.as_ref().map(|s| s.counters());
                ScanChannelStatus {
                    listening: server.is_some(),
                    provider_registered: matches!(
                        install::amsi::status(),
                        install::amsi::Registration::Complete { .. }
                    ),
                    pipe: ipc::PIPE_NAME.to_string(),
                    requests: c
                        .as_ref()
                        .map(|c| c.requests.load(Ordering::Relaxed))
                        .unwrap_or(0),
                    malicious: c
                        .as_ref()
                        .map(|c| c.malicious.load(Ordering::Relaxed))
                        .unwrap_or(0),
                    suspicious: c
                        .as_ref()
                        .map(|c| c.suspicious.load(Ordering::Relaxed))
                        .unwrap_or(0),
                }
            },
            note: self.note(),
        }
    }

    /// Load the blocklists and install filters for them.
    fn start_netblock(&self) -> Result<usize> {
        let list = redoubt_core::blocklist::Blocklist::load_dir(&self.inner.cfg.paths.blocklists);
        if list.stats.refused_protected > 0 {
            // Worth saying out loud. A feed asking to block loopback or the
            // local network is either broken or hostile, and either way the
            // person should hear about it rather than have it silently
            // dropped.
            tracing::warn!(
                refused = list.stats.refused_protected,
                "blocklist entries covering loopback or private networks were refused"
            );
        }

        let mut blocker = netblock::NetBlocker::open()?;
        let installed = blocker.apply(&list)?;
        *self.netblock.lock() = Some(blocker);
        Ok(installed)
    }

    /// Why outbound blocking is not enforcing, in words meant for a person.
    fn network_note(&self, enforcing: bool) -> String {
        if enforcing {
            return String::new();
        }
        if !self.inner.cfg.network.enabled {
            return "Off. Outbound connections are not filtered.".into();
        }
        if !self.is_running() {
            return "Waiting for protection to start.".into();
        }
        let dir = &self.inner.cfg.paths.blocklists;
        if redoubt_core::blocklist::Blocklist::load_dir(dir).is_empty() {
            return format!(
                "On, but there are no addresses to block. Put a list of                  addresses in {}.",
                dir.display()
            );
        }
        "On, but filters could not be installed. This needs the Redoubt          service, which runs with the rights required."
            .into()
    }

    /// Ransomware alerts raised so far, newest last.
    pub fn ransomware_alerts(&self) -> Vec<Alert> {
        self.inner.guard.alerts()
    }

    pub fn clear_ransomware_alerts(&self) {
        self.inner.guard.clear_alerts();
    }

    /// An honest description of the protection level.
    fn note(&self) -> String {
        if !self.is_running() {
            return "On-demand scanning only. Resident protection is not running.".to_string();
        }
        let enforcing = self.inner.cfg.mode == Mode::Enforce;
        let canaries = self.inner.guard.canary_count();
        format!(
            "Watching {} location(s); files are scanned shortly after they change. \
             {}{} Pre-execution blocking needs a filesystem minifilter, which is not built yet.",
            self.watch_roots().len(),
            if enforcing {
                "Malicious files are quarantined."
            } else {
                "Detections are reported only - nothing is quarantined."
            },
            if canaries > 0 {
                format!(" {canaries} ransomware decoys planted.")
            } else {
                String::new()
            },
        )
    }

    /// Recent non-clean verdicts, newest first.
    pub fn recent(&self) -> Vec<Verdict> {
        self.inner.recent.lock().iter().rev().cloned().collect()
    }

    pub fn quarantine(&self) -> &Quarantine {
        &self.inner.quarantine
    }

    /// Queue a path explicitly. Used by tests and by anything that wants a
    /// specific file looked at.
    pub fn submit(&self, path: PathBuf) -> bool {
        self.inner.counters.events.fetch_add(1, Ordering::Relaxed);
        match self.inner.tx.try_send(path) {
            Ok(()) => true,
            Err(_) => {
                self.inner.counters.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Drain the queue synchronously. Tests use this instead of sleeping.
    pub fn drain_for_test(&self) {
        while let Ok(path) = self.inner.rx.try_recv() {
            handle_path(&self.inner, &path, &mut self.inner.engine.session());
        }
    }
}

fn worker_loop(inner: Arc<Inner>) {
    let mut session = inner.engine.session();
    while inner.running.load(Ordering::Relaxed) {
        // A timeout rather than a blocking recv, so a stop is noticed promptly
        // instead of waiting for the next file to change.
        match inner.rx.recv_timeout(std::time::Duration::from_millis(250)) {
            Ok(path) => handle_path(&inner, &path, &mut session),
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }
}

/// Run the behavioural checks for one path and act on any alert.
fn check_ransomware(inner: &Arc<Inner>, path: &std::path::Path) {
    if !inner.cfg.ransomware.enabled {
        return;
    }

    // Only read the file when the entropy check could actually use it: a
    // decoy or a ransom-note filename needs no contents at all.
    let data = std::fs::metadata(path)
        .ok()
        .filter(|m| m.is_file() && m.len() >= 512 && m.len() <= 4 * 1024 * 1024)
        .and_then(|_| std::fs::read(path).ok());

    let Some(mut alert) = inner.guard.observe(path, data.as_deref(), now_epoch()) else {
        return;
    };

    inner.counters.ransomware_alerts.fetch_add(1, Ordering::Relaxed);
    tracing::error!(
        confidence = ?alert.confidence,
        summary = %alert.summary,
        suspects = alert.suspects.len(),
        "RANSOMWARE"
    );
    for s in &alert.signals {
        tracing::error!(signal = %s.describe());
    }

    // Two independent switches, because being wrong here is destructive:
    // enforcement must be on *and* termination explicitly chosen.
    let may_terminate = inner.cfg.mode == Mode::Enforce
        && inner.cfg.ransomware.terminate_on_critical
        && alert.confidence == ransomware::Confidence::Critical;

    if may_terminate {
        match inner.guard.terminate_suspect(&mut alert) {
            Ok(pid) => {
                inner.counters.processes_terminated.fetch_add(1, Ordering::Relaxed);
                tracing::error!(pid, "terminated the process responsible");
            }
            Err(e) => tracing::error!(error = %e, "could not terminate the suspect"),
        }
    }
}

/// Poll for newly started processes.
///
/// Sampling, not interception: a program that starts and exits between two
/// polls is never seen. The interval is short enough to catch anything that
/// does real work, and this is stated rather than glossed over.
fn process_loop(inner: Arc<Inner>) {
    // Establish a baseline so every process already running is not reported as
    // having just started.
    inner.proc_monitor.newly_started();

    while inner.running.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(400));
        if !inner.running.load(Ordering::Relaxed) {
            break;
        }

        // Sample every round so a baseline exists before anything goes wrong.
        // Attribution after the fact is worthless: by then the culprit has
        // usually exited.
        inner.proc_monitor.sample();

        for p in inner.proc_monitor.newly_started() {
            // Living-off-the-land tools that destroy the ability to recover.
            // Their presence is a signal, never a verdict: they are ordinary
            // Windows utilities.
            if let Some(why) = process::recovery_destroyer(&p.name) {
                inner.counters.recovery_tools_seen.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    process = %p.name,
                    pid = p.pid,
                    reason = why,
                    "a recovery-destroying tool started"
                );
            }

            // Scan the image of anything that starts, so a known-bad binary is
            // caught at launch rather than only when it was written.
            if let Some(image) = &p.image {
                let _ = inner.tx.try_send(image.clone());
            }
        }
    }
}

fn handle_path(
    inner: &Arc<Inner>,
    path: &std::path::Path,
    session: &mut redoubt_core::scanner::ScanSession<'_>,
) {
    // Cache check before touching the file's contents.
    let key = std::fs::metadata(path)
        .ok()
        .and_then(|m| CacheKey::from_metadata(&m, inner.generation));
    if let Some(key) = key {
        if let Some(hit) = inner.cache.get(path, &key) {
            inner.counters.cache_hits.fetch_add(1, Ordering::Relaxed);
            let _ = hit;
            return;
        }
    }

    // Behavioural ransomware checks run on every event, including ones the
    // verdict cache would otherwise short-circuit: an encrypted file has a new
    // mtime and size, so it always reaches here, and the decoy check must not
    // depend on the file being scannable.
    check_ransomware(inner, path);

    let ScanOutcome::Scanned(verdict) = session.scan_path(path) else {
        return;
    };
    inner.counters.scanned.fetch_add(1, Ordering::Relaxed);

    if let Some(key) = key {
        inner.cache.insert(
            path,
            CachedVerdict {
                key,
                severity: verdict.severity,
                name: verdict.primary_name().map(str::to_string),
            },
        );
    }

    if verdict.is_clean() {
        return;
    }

    match verdict.severity {
        Severity::Malicious => {
            inner.counters.malicious.fetch_add(1, Ordering::Relaxed);
        }
        Severity::Suspicious => {
            inner.counters.suspicious.fetch_add(1, Ordering::Relaxed);
        }
        Severity::Clean => {}
    }

    tracing::warn!(
        path = %path.display(),
        severity = %verdict.severity,
        detection = verdict.primary_name().unwrap_or("-"),
        "detection"
    );

    {
        let mut recent = inner.recent.lock();
        if recent.len() == RECENT_CAPACITY {
            recent.pop_front();
        }
        recent.push_back((*verdict).clone());
    }

    // Enforcement. Both conditions are required, and `is_actionable` is the
    // structural guarantee that a heuristic or PUA finding can never get here.
    if inner.cfg.mode == Mode::Enforce && verdict.severity.is_actionable() {
        match inner.quarantine.take(path, &verdict, now_epoch()) {
            Ok(entry) => {
                inner.counters.quarantined.fetch_add(1, Ordering::Relaxed);
                inner.cache.invalidate(path);
                tracing::warn!(
                    path = %path.display(),
                    id = %entry.id,
                    "quarantined"
                );
            }
            Err(e) => {
                inner.counters.quarantine_failures.fetch_add(1, Ordering::Relaxed);
                tracing::error!(path = %path.display(), error = %e, "quarantine failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redoubt_core::sigindex::{Group, IndexBuilder};
    use redoubt_core::sigs::{HashSig, HashValue};

    const SAMPLE: &[u8] = b"REDOUBT-REALTIME-TEST-SAMPLE-not-real-malware";

    /// Serialises the tests that bind the scan pipe.
    ///
    /// The pipe name is deliberately fixed - the AMSI provider is loaded into
    /// processes that know nothing about Redoubt and has no configuration - so
    /// it is a single global resource. Two tests binding it at once will serve
    /// each other's clients, which is a property of the harness rather than of
    /// the code.
    static PIPE: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn pipe_guard() -> std::sync::MutexGuard<'static, ()> {
        PIPE.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Connect to the scan pipe, waiting for the accept loop to come up.
    fn connect_to_pipe() -> std::fs::File {
        for _ in 0..100 {
            if let Ok(c) = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(ipc::PIPE_NAME)
            {
                return c;
            }
            std::thread::sleep(std::time::Duration::from_millis(40));
        }
        panic!("the scan pipe never accepted a connection");
    }

    struct Fixture {
        dir: PathBuf,
        protection: Protection,
        /// Held for the fixture's lifetime. Starting protection binds the scan
        /// pipe, whose name is fixed by design, so only one fixture may be
        /// running at a time.
        _pipe: std::sync::MutexGuard<'static, ()>,
        /// And held against the *other* test binary, which cargo runs in a
        /// separate process where an in-process mutex is invisible.
        _pipe_across_processes: ipc::testlock::PipeLock,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.protection.stop();
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    // Written field-by-field on purpose: it names exactly what the fixture
    // changes from the default, which a struct-update expression buries.
    #[allow(clippy::field_reassign_with_default)]
    fn fixture(tag: &str, mode: Mode) -> Fixture {
        let dir = std::env::temp_dir().join(format!("redoubt-rt-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        for sub in ["signatures", "rules", "quarantine", "watch", "logs", "cache"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }

        let mut b = IndexBuilder::new(9001, 0);
        b.add_hash(
            HashSig {
                hash: HashValue::from_hex(
                    &redoubt_core::hashing::digest_bytes(SAMPLE).sha256_value().to_string(),
                )
                .unwrap(),
                size: Some(SAMPLE.len() as u64),
                name: "Redoubt.Test.RealtimeSample".into(),
            },
            Group::File,
        );
        b.write(&dir.join("signatures/redoubt.sigidx")).unwrap();

        let mut cfg = Config::default();
        cfg.mode = mode;
        cfg.paths.signatures = dir.join("signatures");
        cfg.paths.rules = dir.join("rules");
        cfg.paths.quarantine = dir.join("quarantine");
        cfg.exclusions.paths = Vec::new();
        cfg.realtime.watch_paths = vec![dir.join("watch")];

        let engine = Arc::new(ScanEngine::load(cfg.clone()).unwrap());
        Fixture {
            dir,
            protection: Protection::new(cfg, engine),
            _pipe: pipe_guard(),
            _pipe_across_processes: ipc::testlock::acquire(),
        }
    }

    #[test]
    fn a_malicious_file_is_detected_in_observe_mode() {
        let f = fixture("observe", Mode::Observe);
        let victim = f.dir.join("watch").join("sample.bin");
        std::fs::write(&victim, SAMPLE).unwrap();

        f.protection.submit(victim.clone());
        f.protection.drain_for_test();

        let recent = f.protection.recent();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].severity, Severity::Malicious);
        assert_eq!(recent[0].primary_name(), Some("Redoubt.Test.RealtimeSample"));

        // The whole point of observe mode.
        assert!(victim.exists(), "observe mode must not touch the file");
        assert!(f.protection.quarantine().held().is_empty());
        assert_eq!(f.protection.status().counters.quarantined, 0);
    }

    #[test]
    fn enforce_mode_quarantines_a_malicious_file() {
        let f = fixture("enforce", Mode::Enforce);
        let victim = f.dir.join("watch").join("sample.bin");
        std::fs::write(&victim, SAMPLE).unwrap();

        f.protection.submit(victim.clone());
        f.protection.drain_for_test();

        assert!(!victim.exists(), "enforce mode should have removed it");
        let held = f.protection.quarantine().held();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].original_path, victim);
        assert_eq!(f.protection.status().counters.quarantined, 1);

        // And it is recoverable.
        f.protection.quarantine().restore(&held[0].id).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), SAMPLE);
    }

    #[test]
    fn a_clean_file_is_ignored_in_both_modes() {
        for mode in [Mode::Observe, Mode::Enforce] {
            let f = fixture(&format!("clean{}", mode.as_str()), mode);
            let ok = f.dir.join("watch").join("notes.txt");
            std::fs::write(&ok, b"just some ordinary notes").unwrap();

            f.protection.submit(ok.clone());
            f.protection.drain_for_test();

            assert!(ok.exists());
            assert!(f.protection.recent().is_empty(), "a clean file must not be reported");
            assert!(f.protection.quarantine().held().is_empty());
        }
    }

    #[test]
    fn a_suspicious_file_is_never_quarantined_even_when_enforcing() {
        // The safety property, end to end: enforcement is on, the file is
        // flagged, and it still must not be touched.
        let f = fixture("suspicious", Mode::Enforce);
        let victim = f.dir.join("watch").join("invoice.pdf.exe");
        std::fs::write(&victim, b"totally harmless content").unwrap();

        f.protection.submit(victim.clone());
        f.protection.drain_for_test();

        let recent = f.protection.recent();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].severity, Severity::Suspicious);
        assert!(victim.exists(), "a suspicious file must survive enforce mode");
        assert!(f.protection.quarantine().held().is_empty());
    }

    #[test]
    fn the_cache_prevents_a_rescan_of_an_unchanged_file() {
        let f = fixture("cache", Mode::Observe);
        let victim = f.dir.join("watch").join("sample.bin");
        std::fs::write(&victim, SAMPLE).unwrap();

        for _ in 0..5 {
            f.protection.submit(victim.clone());
            f.protection.drain_for_test();
        }

        let c = f.protection.status().counters;
        assert_eq!(c.scanned, 1, "the file should have been read exactly once");
        assert_eq!(c.cache_hits, 4);
    }

    #[test]
    fn status_is_honest_about_not_running() {
        let f = fixture("status", Mode::Observe);
        let s = f.protection.status();
        assert!(!s.running);
        assert!(s.watching.is_empty(), "nothing is being watched while stopped");
        assert!(
            s.note.contains("not running"),
            "status must not imply protection that is not there: {}",
            s.note
        );
    }

    #[test]
    fn status_never_claims_pre_execution_blocking() {
        let f = fixture("claims", Mode::Enforce);
        f.protection.start().unwrap();
        let s = f.protection.status();
        assert!(s.running);
        assert!(
            s.note.contains("minifilter") && s.note.contains("not built"),
            "the note must state the limitation: {}",
            s.note
        );
        f.protection.stop();
    }

    #[test]
    fn a_full_queue_drops_rather_than_blocking() {
        let f = fixture("backpressure", Mode::Observe);
        // Never started, so nothing drains: the queue fills and then refuses.
        let mut accepted = 0;
        for i in 0..100_000 {
            if f.protection.submit(f.dir.join(format!("watch/f{i}.bin"))) {
                accepted += 1;
            } else {
                break;
            }
        }
        assert!(accepted > 0);
        assert!(
            f.protection.status().counters.dropped > 0,
            "a full queue must drop and count, not block"
        );
    }

    #[test]
    fn canaries_are_planted_on_start_and_removed_on_stop() {
        let f = fixture("canaries", Mode::Observe);
        let watch = f.dir.join("watch");

        f.protection.start().unwrap();
        let planted: Vec<_> = std::fs::read_dir(&watch)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(!planted.is_empty(), "no decoys were planted");
        assert!(f.protection.status().ransomware.canaries > 0);

        f.protection.stop();
        let left: Vec<_> = std::fs::read_dir(&watch)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(left.is_empty(), "decoys were left behind: {left:?}");
    }

    #[test]
    fn a_simulated_ransomware_run_raises_a_critical_alert() {
        // The scenario end to end: decoys are planted, something rewrites one,
        // and the guard reacts.
        let f = fixture("ransomware", Mode::Observe);
        let watch = f.dir.join("watch");
        f.protection.start().unwrap();

        let decoy = std::fs::read_dir(&watch)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .next()
            .expect("a decoy should exist");

        // "Encrypt" it.
        std::fs::write(&decoy, b"encrypted-by-the-thing-we-are-simulating").unwrap();
        check_ransomware(&f.protection.inner, &decoy);

        let alerts = f.protection.ransomware_alerts();
        assert_eq!(alerts.len(), 1, "a modified decoy must raise exactly one alert");
        assert_eq!(alerts[0].confidence, ransomware::Confidence::Critical);
        assert!(alerts[0].summary.contains("encrypting"));
        assert_eq!(f.protection.status().counters.ransomware_alerts, 1);

        f.protection.stop();
    }

    #[test]
    fn observe_mode_never_terminates_anything() {
        // Two switches guard termination; observe mode alone must be enough to
        // prevent it even if the ransomware setting is on.
        let f = fixture("no-kill", Mode::Observe);
        let mut cfg = f.protection.inner.cfg.clone();
        cfg.ransomware.terminate_on_critical = true;
        assert_eq!(cfg.mode, Mode::Observe);

        let engine = f.protection.inner.engine.clone();
        let p = Protection::new(cfg, engine);
        assert!(
            !p.status().ransomware.will_terminate,
            "observe mode must veto termination regardless of the ransomware setting"
        );
    }

    #[test]
    fn termination_requires_both_switches() {
        let f = fixture("two-switches", Mode::Enforce);
        let engine = f.protection.inner.engine.clone();

        // Enforce mode alone is not enough.
        let mut cfg = f.protection.inner.cfg.clone();
        cfg.ransomware.terminate_on_critical = false;
        let p = Protection::new(cfg.clone(), engine.clone());
        assert!(!p.status().ransomware.will_terminate);

        // Both together, and only then.
        cfg.ransomware.terminate_on_critical = true;
        let p = Protection::new(cfg, engine);
        assert!(p.status().ransomware.will_terminate);
    }

    #[test]
    fn ordinary_file_activity_raises_no_ransomware_alert() {
        let f = fixture("quiet", Mode::Observe);
        let watch = f.dir.join("watch");

        for i in 0..40 {
            let p = watch.join(format!("note{i}.txt"));
            std::fs::write(&p, format!("some perfectly ordinary text, file {i}")).unwrap();
            check_ransomware(&f.protection.inner, &p);
        }
        assert!(
            f.protection.ransomware_alerts().is_empty(),
            "writing ordinary text files must not look like ransomware"
        );
    }

    #[test]
    fn the_scan_channel_answers_over_a_real_pipe() {
        // The AMSI provider is a separate DLL in a foreign process, so the
        // only meaningful test of this path is an actual pipe round-trip.
        use std::io::{Read, Write};

        let f = fixture("ipc", Mode::Observe);
        f.protection.start().unwrap();
        assert!(f.protection.status().scan_channel.listening);

        let mut client = connect_to_pipe();

        // SAMPLE is in the fixture index, so this must come back malicious.
        client.write_all(&ipc::encode_request(SAMPLE)).unwrap();
        client.flush().unwrap();

        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).unwrap();
        let (verdict, name) = ipc::decode_response(&buf[..n]).expect("a decodable response");

        assert_eq!(verdict, ipc::VERDICT_MALICIOUS);
        assert_eq!(name, "Redoubt.Test.RealtimeSample");
        assert_eq!(f.protection.status().scan_channel.malicious, 1);

        f.protection.stop();
    }

    #[test]
    fn the_scan_channel_reports_clean_content_as_clean() {
        use std::io::{Read, Write};

        let f = fixture("ipc-clean", Mode::Observe);
        f.protection.start().unwrap();

        let mut client = connect_to_pipe();

        client
            .write_all(&ipc::encode_request(b"Write-Host 'an ordinary script'"))
            .unwrap();
        client.flush().unwrap();

        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).unwrap();
        let (verdict, _) = ipc::decode_response(&buf[..n]).unwrap();
        assert_eq!(verdict, ipc::VERDICT_CLEAN);

        f.protection.stop();
    }

    #[test]
    fn the_scan_channel_is_not_listening_while_stopped() {
        let f = fixture("ipc-off", Mode::Observe);
        assert!(!f.protection.status().scan_channel.listening);
    }

    #[test]
    fn start_and_stop_are_idempotent() {
        let f = fixture("idempotent", Mode::Observe);
        f.protection.start().unwrap();
        f.protection.start().unwrap();
        assert!(f.protection.is_running());
        f.protection.stop();
        f.protection.stop();
        assert!(!f.protection.is_running());
    }
}
