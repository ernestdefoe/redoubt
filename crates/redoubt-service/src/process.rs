//! Process monitoring and attribution.
//!
//! The file watcher reports *what* changed, never *who* changed it. That gap
//! is the difference between "your files are being encrypted" and "this
//! program is encrypting your files, stop it". This module closes it without
//! a driver, using two plain Win32 facilities:
//!
//! - **Toolhelp snapshots** for the process list and image paths.
//! - **`GetProcessIoCounters`** for per-process write volume.
//!
//! # Why write rate identifies ransomware
//!
//! Encrypting a document set means reading and rewriting every file in it. The
//! responsible process therefore has a write rate far above everything else on
//! an idle desktop - typically by one to three orders of magnitude. Sampling
//! I/O counters at the moment a canary is touched names the culprit with very
//! little ambiguity.
//!
//! # Honest limits
//!
//! - Counters for processes owned by other users, or by the system, are not
//!   readable without elevation. An unelevated Redoubt attributes activity by
//!   the current user, which is where ransomware runs anyway.
//! - This is sampling, not interception. A process that finishes between two
//!   samples is invisible. The poll interval is therefore short.
//! - Command lines are not read. That needs elevation or PEB access, so
//!   recovery-destroying commands are recognised by *image name* instead,
//!   which is coarser and is described as such.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
use windows_sys::Win32::System::Threading::{
    GetProcessIoCounters, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
    TerminateProcess, IO_COUNTERS, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
};

/// Programs whose only common use during a ransomware run is destroying the
/// user's ability to recover.
///
/// These are legitimate Windows tools - that is the point of a "living off the
/// land" technique - so their presence is a signal, never a verdict. On a
/// desktop none of them normally runs unattended.
pub const RECOVERY_DESTROYERS: &[(&str, &str)] = &[
    ("vssadmin.exe", "can delete Volume Shadow Copies, removing Previous Versions"),
    ("wbadmin.exe", "can delete Windows Backup catalogs"),
    ("bcdedit.exe", "can disable Windows recovery and automatic repair"),
    ("wmic.exe", "can delete shadow copies via the shadowcopy class"),
    ("cipher.exe", "can wipe free space, defeating file recovery"),
];

/// True when `image_name` is one of the recovery-destroying tools.
pub fn recovery_destroyer(image_name: &str) -> Option<&'static str> {
    let lower = image_name.to_ascii_lowercase();
    RECOVERY_DESTROYERS
        .iter()
        .find(|(n, _)| *n == lower)
        .map(|(_, why)| *why)
}

/// One process at one moment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub image: Option<PathBuf>,
    /// Cumulative bytes written since the process started, when readable.
    pub write_bytes: Option<u64>,
    /// How long the process has actually been running.
    ///
    /// Taken from the kernel's creation time, not from when Redoubt first saw
    /// it. Those differ enormously right after the service starts, when every
    /// process on the machine has just been "seen" for the first time - and
    /// treating them all as newly started made every heavy writer look like a
    /// freshly launched dropper.
    pub age_secs: Option<f64>,
}

/// A process's recent write throughput.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteRate {
    pub pid: u32,
    pub name: String,
    pub image: Option<PathBuf>,
    pub bytes_per_sec: f64,
    pub bytes_in_window: u64,
    /// This process's own typical rate over the recent history.
    ///
    /// Attribution compares against *this*, not against other processes. A
    /// browser or an editor that constantly writes several MiB/s is not
    /// suspicious for doing what it always does, and naming it would be worse
    /// than naming nobody - the response to a critical alert can be to kill
    /// the named process.
    #[serde(default)]
    pub baseline_bytes_per_sec: f64,
    /// Current rate divided by baseline. Large means "doing something it does
    /// not normally do".
    #[serde(default)]
    pub anomaly_ratio: f64,
}

/// Median of a sample. Used for baselines because a single spike must not
/// drag the "normal" value up with it, which is exactly what a mean does.
fn median(values: impl Iterator<Item = f64>) -> f64 {
    let mut v: Vec<f64> = values.collect();
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = v.len() / 2;
    if v.len().is_multiple_of(2) {
        (v[mid - 1] + v[mid]) / 2.0
    } else {
        v[mid]
    }
}

/// A process's typical bytes-per-second, from the median of its per-sample
/// deltas. Median rather than mean so one spike does not raise the very
/// number the spike is being compared against.
fn baseline_per_sec(track: &Track) -> f64 {
    if track.samples.len() < 2 {
        return 0.0;
    }
    let span = track
        .samples
        .back()
        .zip(track.samples.front())
        .map(|(b, f)| b.0.duration_since(f.0).as_secs_f64())
        .unwrap_or(0.0);
    if span <= 0.0 {
        return 0.0;
    }
    let per_sample = median(track.samples.iter().map(|(_, b)| *b as f64));
    let interval = span / (track.samples.len().saturating_sub(1)).max(1) as f64;
    if interval <= 0.0 {
        0.0
    } else {
        per_sample / interval
    }
}

/// `value / baseline`, capped and finite.
///
/// `f64::INFINITY` serialises to JSON `null`, which silently destroys the
/// field for every consumer, so an absent baseline yields the cap rather than
/// infinity. A caller must still require a minimum history before treating a
/// large ratio as meaningful.
fn ratio(value: f64, baseline: f64) -> f64 {
    if baseline > 1.0 {
        (value / baseline).min(MAX_RATIO)
    } else if value > 0.0 {
        MAX_RATIO
    } else {
        0.0
    }
}

fn wide_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Open a process for a limited query. Returns `None` when access is denied,
/// which is normal for system and other-user processes.
fn open_query(pid: u32) -> Option<HANDLE> {
    // SAFETY: a null return is the documented failure mode and is checked.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        None
    } else {
        Some(h)
    }
}

fn image_path(handle: HANDLE) -> Option<PathBuf> {
    let mut buf = [0u16; 32768];
    let mut len = buf.len() as u32;
    // SAFETY: buf and len describe the same buffer; the call writes at most
    // `len` code units and updates `len` with what it wrote.
    let ok = unsafe {
        QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len)
    };
    if ok == 0 {
        return None;
    }
    Some(PathBuf::from(wide_to_string(&buf[..len as usize])))
}

/// A FILETIME as 100-nanosecond ticks since 1601.
fn filetime_ticks(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64
}

/// How long this process has been running, from the kernel's own record.
fn process_age_secs(handle: HANDLE) -> Option<f64> {
    let mut created: FILETIME = unsafe { std::mem::zeroed() };
    let mut exited: FILETIME = unsafe { std::mem::zeroed() };
    let mut kernel: FILETIME = unsafe { std::mem::zeroed() };
    let mut user: FILETIME = unsafe { std::mem::zeroed() };

    // SAFETY: all four out-parameters are correctly sized, zeroed FILETIMEs.
    let ok = unsafe {
        GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user)
    };
    if ok == 0 {
        return None;
    }

    let mut now: FILETIME = unsafe { std::mem::zeroed() };
    // SAFETY: `now` is a correctly sized, zeroed FILETIME.
    unsafe { GetSystemTimeAsFileTime(&mut now) };

    let started = filetime_ticks(created);
    let current = filetime_ticks(now);
    if current <= started {
        return Some(0.0);
    }
    // FILETIME ticks are 100 ns.
    Some((current - started) as f64 / 10_000_000.0)
}

fn write_bytes(handle: HANDLE) -> Option<u64> {
    let mut counters: IO_COUNTERS = unsafe { std::mem::zeroed() };
    // SAFETY: `counters` is a correctly sized, zeroed IO_COUNTERS.
    let ok = unsafe { GetProcessIoCounters(handle, &mut counters) };
    if ok == 0 {
        None
    } else {
        Some(counters.WriteTransferCount)
    }
}

/// Every process this session can see.
pub fn snapshot() -> Vec<ProcessInfo> {
    let mut out = Vec::new();

    // SAFETY: an invalid handle is the documented failure mode and is checked.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap.is_null() {
        return out;
    }

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    // SAFETY: `entry.dwSize` is set as the API requires before the first call.
    let mut ok = unsafe { Process32FirstW(snap, &mut entry) };
    while ok != 0 {
        let name = wide_to_string(&entry.szExeFile);
        let pid = entry.th32ProcessID;

        let (image, written, age) = match open_query(pid) {
            Some(h) => {
                let r = (image_path(h), write_bytes(h), process_age_secs(h));
                // SAFETY: `h` came from OpenProcess and is closed exactly once.
                unsafe { CloseHandle(h) };
                r
            }
            None => (None, None, None),
        };

        out.push(ProcessInfo { pid, name, image, write_bytes: written, age_secs: age });
        ok = unsafe { Process32NextW(snap, &mut entry) };
    }

    // SAFETY: `snap` came from CreateToolhelp32Snapshot and is closed once.
    unsafe { CloseHandle(snap) };
    out
}

/// Ask a process to stop.
///
/// Deliberately a thin wrapper with no policy of its own: deciding *whether*
/// to terminate belongs to the caller, and is gated behind an explicit setting
/// that is off by default. Killing the wrong process loses a user's unsaved
/// work.
pub fn terminate(pid: u32) -> anyhow::Result<()> {
    if pid <= 4 {
        anyhow::bail!("refusing to terminate system process {pid}");
    }
    if pid == std::process::id() {
        anyhow::bail!("refusing to terminate Redoubt itself");
    }

    // SAFETY: a null return is the documented failure mode and is checked.
    let h = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
    if h.is_null() {
        anyhow::bail!("could not open process {pid} for termination (access denied?)");
    }
    // SAFETY: `h` was opened with PROCESS_TERMINATE and is closed once below.
    let ok = unsafe { TerminateProcess(h, 1) };
    unsafe { CloseHandle(h) };

    if ok == 0 {
        anyhow::bail!("TerminateProcess failed for pid {pid}");
    }
    Ok(())
}

/// How many samples of per-process history to keep. At the ~400 ms poll
/// interval this is roughly sixteen seconds.
const HISTORY: usize = 40;

/// How long a process's history is kept after it disappears.
///
/// This exists because of a failure observed in testing: a program that
/// encrypts a folder and exits is already gone when the alert surfaces, so
/// attribution that only looks at live processes names a bystander or nobody.
/// Keeping the dead process's record briefly is what allows it to be named.
const RETAIN_EXITED: Duration = Duration::from_secs(20);

/// The stretch of time an alert is attributed over. Matched to the burst
/// window, so "who did this" covers the same period as "this happened".
const INCIDENT_WINDOW: Duration = Duration::from_secs(10);

/// A process needs at least this many samples before anything can be called
/// unusual for it. Without a history there is no "normal" to compare against,
/// and treating an unknown process as infinitely anomalous is precisely how a
/// bystander gets named.
const MIN_SAMPLES: usize = 4;

/// Bytes a process must have written within the window before it is worth
/// naming. Encrypting a document set moves far more than this; a background
/// helper flushing a log does not.
const MIN_INCIDENT_BYTES: u64 = 8 * 1024 * 1024;

/// How far above its own baseline a process must be.
const ANOMALY_FACTOR: f64 = 5.0;

/// Ratios are capped rather than allowed to reach infinity: `f64::INFINITY`
/// serialises to JSON `null`, which silently destroys the field for every
/// consumer of the API.
const MAX_RATIO: f64 = 9999.0;

/// How far ahead of the runner-up a candidate must be before it is treated as
/// definitely responsible rather than merely suspicious.
const DECISIVE_MARGIN: f64 = 3.0;

/// A process first seen this recently has no innocent past to compare
/// against, and heavy writing from it is judged on volume alone.
const YOUNG: Duration = Duration::from_secs(60);

/// One process's recent write history.
struct Track {
    name: String,
    image: Option<PathBuf>,
    /// `(when, bytes written since the previous sample)`, oldest first.
    samples: VecDeque<(Instant, u64)>,
    /// Cumulative counter at the last sample, for computing the next delta.
    last_total: u64,
    /// The process's real age at the last sample, from the kernel.
    age_secs: Option<f64>,
    last_seen: Instant,
}

/// Tracks write throughput between samples.
pub struct ProcessMonitor {
    /// Image paths seen in the last snapshot, for spotting new processes.
    known: Mutex<HashMap<u32, String>>,
    /// Per-process write history, retained briefly past process exit.
    history: Mutex<HashMap<u32, Track>>,
    /// The most recent sample, so an alert can be attributed without taking a
    /// fresh one - by then the culprit has often already exited.
    last: Mutex<Vec<WriteRate>>,
}

impl Default for ProcessMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessMonitor {
    pub fn new() -> Self {
        Self {
            known: Mutex::new(HashMap::new()),
            history: Mutex::new(HashMap::new()),
            last: Mutex::new(Vec::new()),
        }
    }

    /// Take a sample and return per-process write rates since the previous one.
    ///
    /// The first call establishes a baseline and returns nothing: a rate needs
    /// two points, and reporting cumulative totals as a rate would name
    /// whichever process had simply been running longest.
    pub fn sample(&self) -> Vec<WriteRate> {
        let now = Instant::now();
        let processes = snapshot();
        let mut history = self.history.lock();
        let mut rates = Vec::new();

        for p in &processes {
            let Some(total) = p.write_bytes else {
                continue;
            };

            match history.get_mut(&p.pid) {
                Some(track) => {
                    let elapsed = now.duration_since(track.last_seen).as_secs_f64();
                    // A pid can be reused after a process exits, which shows as
                    // a negative delta. Saturating treats that as no activity
                    // rather than an enormous bogus rate.
                    let delta = total.saturating_sub(track.last_total);

                    track.samples.push_back((now, delta));
                    if track.samples.len() > HISTORY {
                        track.samples.pop_front();
                    }
                    track.last_total = total;
                    track.last_seen = now;
                    track.age_secs = p.age_secs;
                    track.name = p.name.clone();
                    if track.image.is_none() {
                        track.image = p.image.clone();
                    }

                    if elapsed > 0.05 && delta > 0 {
                        rates.push(WriteRate {
                            pid: p.pid,
                            name: p.name.clone(),
                            image: p.image.clone(),
                            bytes_per_sec: delta as f64 / elapsed,
                            bytes_in_window: delta,
                            baseline_bytes_per_sec: 0.0,
                            anomaly_ratio: 0.0,
                        });
                    }
                }
                None => {
                    // First sighting: record the counter, report nothing. There
                    // is no interval to divide by yet.
                    history.insert(
                        p.pid,
                        Track {
                            name: p.name.clone(),
                            image: p.image.clone(),
                            samples: VecDeque::new(),
                            last_total: total,
                            age_secs: p.age_secs,
                            last_seen: now,
                        },
                    );
                }
            }
        }

        // Keep the records of processes that have just exited. A program that
        // encrypts a folder and terminates is gone before the alert surfaces,
        // and dropping it here is what made attribution name bystanders.
        history.retain(|_, t| now.duration_since(t.last_seen) < RETAIN_EXITED);

        // Annotate each rate with the process's own baseline.
        for r in rates.iter_mut() {
            if let Some(track) = history.get(&r.pid) {
                r.baseline_bytes_per_sec = baseline_per_sec(track);
                r.anomaly_ratio = ratio(r.bytes_per_sec, r.baseline_bytes_per_sec);
            }
        }

        rates.sort_by(|a, b| {
            b.bytes_per_sec
                .partial_cmp(&a.bytes_per_sec)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        *self.last.lock() = rates.clone();
        rates
    }

    /// The most recent sample, without taking a new one.
    pub fn last_sample(&self) -> Vec<WriteRate> {
        self.last.lock().clone()
    }

    /// Processes that wrote far more during the incident window than they
    /// normally do.
    ///
    /// Ranked by **bytes written in the window**, not by instantaneous rate.
    /// Encryption is characterised by sustained volume, and a rate sampled at
    /// one instant misses a process that has already finished.
    ///
    /// Returns an empty list when nothing stands out. That is the honest
    /// answer and is reported as such: the configured response to a critical
    /// alert can be to terminate what this names, so naming a bystander is
    /// worse than naming nobody.
    pub fn anomalous_writers(&self, n: usize) -> Vec<WriteRate> {
        let me = std::process::id();
        let now = Instant::now();
        let history = self.history.lock();
        let mut out = Vec::new();

        for (pid, track) in history.iter() {
            if *pid <= 4 || *pid == me {
                continue;
            }
            // Without enough history there is no "normal" for this process, so
            // nothing about it can be called unusual.
            if track.samples.len() < MIN_SAMPLES {
                continue;
            }

            let window_bytes: u64 = track
                .samples
                .iter()
                .filter(|(at, _)| now.duration_since(*at) <= INCIDENT_WINDOW)
                .map(|(_, b)| *b)
                .sum();
            if window_bytes < MIN_INCIDENT_BYTES {
                continue;
            }

            // What this process would normally write over a window this long.
            let baseline = baseline_per_sec(track) * INCIDENT_WINDOW.as_secs_f64();
            let r = ratio(window_bytes as f64, baseline);

            // Two ways to qualify, because a baseline only means something for
            // a process that has an innocent past:
            //
            //  * An established process writing far above its own norm. This
            //    catches a long-running program that has been hijacked.
            //  * A process young enough to have no norm, writing heavily. A
            //    program whose entire life so far is one large burst of writes
            //    has a median equal to its attack rate, so it can never look
            //    anomalous relative to itself - which is exactly the shape of
            //    a dropper that starts, encrypts, and exits.
            //
            // The byte floor does the real work in the second case: a helper
            // flushing a log will not clear 8 MiB in ten seconds.
            // Real process age, from the kernel - not how long Redoubt has
            // been watching. Those are the same number only if the service has
            // been running longer than every process on the machine, which is
            // never true just after it starts. Using observation time made
            // every process look newly launched for the first minute.
            let young = track
                .age_secs
                .map(|a| a <= YOUNG.as_secs_f64())
                .unwrap_or(false);
            if r < ANOMALY_FACTOR && !young {
                continue;
            }

            out.push(WriteRate {
                pid: *pid,
                name: track.name.clone(),
                image: track.image.clone(),
                bytes_per_sec: window_bytes as f64 / INCIDENT_WINDOW.as_secs_f64(),
                bytes_in_window: window_bytes,
                baseline_bytes_per_sec: baseline / INCIDENT_WINDOW.as_secs_f64(),
                anomaly_ratio: r,
            });
        }

        // Rank by how unusual the activity is, not by raw volume. A busy
        // machine always has something writing more in absolute terms - a
        // browser, an editor, a build - and ranking by bytes puts those first,
        // which is what put the user's own tools at the top of a ransomware
        // alert during testing. A brand-new process writing 16 MiB is far more
        // suspicious than a long-running one writing 44 MiB.
        out.sort_by(|a, b| {
            b.anomaly_ratio
                .partial_cmp(&a.anomaly_ratio)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.bytes_in_window.cmp(&a.bytes_in_window))
        });
        out.truncate(n);
        out
    }

    /// The single process responsible, when the evidence is unambiguous.
    ///
    /// Returns `None` whenever more than one candidate is plausible. This is
    /// the gate on the only destructive action Redoubt takes automatically,
    /// and testing on a busy desktop showed exactly why it is needed: I/O
    /// attribution routinely surfaces two or three heavy writers, and killing
    /// the top of that list is how a tool terminates its user's browser.
    ///
    /// "Decisive" means one candidate that is both clearly anomalous and
    /// clearly ahead of whatever is second.
    pub fn decisive_suspect(&self) -> Option<WriteRate> {
        let candidates = self.anomalous_writers(3);
        let first = candidates.first()?;

        match candidates.get(1) {
            // Nothing else in the frame.
            None => Some(first.clone()),
            Some(second) => {
                let clear_on_anomaly =
                    first.anomaly_ratio >= second.anomaly_ratio * DECISIVE_MARGIN;
                let clear_on_volume = first.bytes_in_window
                    >= second.bytes_in_window.saturating_mul(DECISIVE_MARGIN as u64);
                if clear_on_anomaly && clear_on_volume {
                    Some(first.clone())
                } else {
                    None
                }
            }
        }
    }


    /// Processes that started since the last call to this method.
    pub fn newly_started(&self) -> Vec<ProcessInfo> {
        let processes = snapshot();
        let mut known = self.known.lock();
        let first_run = known.is_empty();

        let mut fresh = Vec::new();
        for p in &processes {
            if !known.contains_key(&p.pid) && !first_run {
                fresh.push(p.clone());
            }
        }
        *known = processes.iter().map(|p| (p.pid, p.name.clone())).collect();
        fresh
    }

    /// Best candidates for whatever is writing heavily right now.
    ///
    /// Excludes Redoubt itself and the system idle/kernel pids. It does *not*
    /// exclude signed Microsoft binaries: ransomware routinely runs inside a
    /// hollowed legitimate process, and hiding those would hide the attack.
    pub fn top_writers(&self, n: usize) -> Vec<WriteRate> {
        let me = std::process::id();
        self.sample()
            .into_iter()
            .filter(|r| r.pid > 4 && r.pid != me)
            .take(n)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_sees_this_process() {
        let all = snapshot();
        assert!(all.len() > 5, "a Windows session has more processes than this");

        let me = all
            .iter()
            .find(|p| p.pid == std::process::id())
            .expect("our own process should be in the snapshot");
        assert!(
            me.name.to_lowercase().contains("redoubt") || me.name.to_lowercase().ends_with(".exe"),
            "unexpected own process name: {}",
            me.name
        );
        assert!(me.image.is_some(), "we can always read our own image path");
        assert!(me.write_bytes.is_some(), "we can always read our own IO counters");
    }

    #[test]
    fn the_first_sample_establishes_a_baseline_rather_than_reporting_totals() {
        // Reporting cumulative counters as a rate would name whichever process
        // had simply been running longest.
        let m = ProcessMonitor::new();
        assert!(
            m.sample().is_empty(),
            "the first sample has nothing to compare against"
        );
    }

    #[test]
    fn writing_shows_up_as_a_write_rate() {
        let m = ProcessMonitor::new();
        m.sample(); // baseline

        // Do some real writing so our own process has measurable throughput.
        let path = std::env::temp_dir().join(format!("redoubt-io-{}.bin", std::process::id()));
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&path).unwrap();
            for _ in 0..64 {
                f.write_all(&vec![0u8; 64 * 1024]).unwrap();
            }
            f.sync_all().unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(120));

        let rates = m.sample();
        let me = rates.iter().find(|r| r.pid == std::process::id());
        assert!(
            me.is_some(),
            "4 MB of writes should register as write activity for our own pid"
        );
        assert!(me.unwrap().bytes_in_window > 1_000_000);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rates_are_sorted_heaviest_first() {
        let m = ProcessMonitor::new();
        m.sample();
        std::thread::sleep(std::time::Duration::from_millis(80));
        let rates = m.sample();
        for w in rates.windows(2) {
            assert!(
                w[0].bytes_per_sec >= w[1].bytes_per_sec,
                "rates are not sorted heaviest first"
            );
        }
    }

    #[test]
    fn top_writers_never_includes_redoubt_itself() {
        let m = ProcessMonitor::new();
        m.sample();
        // Generate our own I/O so we would otherwise rank highly.
        let path = std::env::temp_dir().join(format!("redoubt-self-{}.bin", std::process::id()));
        std::fs::write(&path, vec![0u8; 4 * 1024 * 1024]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(120));

        let top = m.top_writers(10);
        assert!(
            !top.iter().any(|r| r.pid == std::process::id()),
            "Redoubt must never nominate itself as the culprit"
        );
        assert!(!top.iter().any(|r| r.pid <= 4), "system pids must be excluded");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn newly_started_is_quiet_on_the_first_call() {
        // Otherwise every process on the machine reads as "just started".
        let m = ProcessMonitor::new();
        assert!(m.newly_started().is_empty());
    }

    #[test]
    fn newly_started_sees_a_process_we_launch() {
        let m = ProcessMonitor::new();
        m.newly_started(); // baseline

        let mut child = std::process::Command::new("cmd")
            .args(["/C", "ping -n 3 127.0.0.1 > nul"])
            .spawn()
            .expect("spawning cmd should work on Windows");
        std::thread::sleep(std::time::Duration::from_millis(250));

        let fresh = m.newly_started();
        assert!(
            fresh.iter().any(|p| p.pid == child.id()),
            "a process we just launched should be reported as new"
        );

        child.kill().ok();
        child.wait().ok();
    }

    #[test]
    fn median_ignores_a_single_spike() {
        assert_eq!(median([1.0, 1.0, 1.0, 1.0, 1000.0].into_iter()), 1.0);
        assert_eq!(median(std::iter::empty()), 0.0);
        assert_eq!(median([2.0, 4.0].into_iter()), 3.0);
    }

    #[test]
    fn a_steady_heavy_writer_is_not_flagged_as_anomalous() {
        // The bug this exists to prevent: a browser or an editor that always
        // writes several MiB/s was being named as the ransomware, because it
        // was simply the loudest process on the machine.
        let m = ProcessMonitor::new();

        // Build a history where our own process writes steadily.
        let path = std::env::temp_dir().join(format!("redoubt-steady-{}.bin", std::process::id()));
        m.sample();
        for _ in 0..6 {
            std::fs::write(&path, vec![0u8; 2 * 1024 * 1024]).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(60));
            m.sample();
        }

        // Our own pid is excluded from nomination anyway, but the ratio itself
        // must show as unremarkable for a process doing its usual thing.
        let me = m
            .last_sample()
            .into_iter()
            .find(|r| r.pid == std::process::id());
        if let Some(me) = me {
            if me.baseline_bytes_per_sec > 1.0 {
                assert!(
                    me.anomaly_ratio < ANOMALY_FACTOR,
                    "steady writing scored {:.1}x its own baseline; it should look normal",
                    me.anomaly_ratio
                );
            }
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn attribution_returns_nothing_when_nothing_stands_out() {
        // Better to say "could not identify it" than to name a bystander.
        let m = ProcessMonitor::new();
        m.sample();
        std::thread::sleep(std::time::Duration::from_millis(80));
        m.sample();

        for w in m.anomalous_writers(5) {
            assert!(
                w.anomaly_ratio >= ANOMALY_FACTOR,
                "{} was nominated at only {:.1}x its baseline",
                w.name,
                w.anomaly_ratio
            );
            assert!(
                w.bytes_in_window >= MIN_INCIDENT_BYTES,
                "{} was nominated on only {} bytes",
                w.name,
                w.bytes_in_window
            );
            assert!(
                w.anomaly_ratio.is_finite(),
                "an infinite ratio serialises to JSON null and destroys the field"
            );
        }
    }

    #[test]
    fn ratios_are_always_finite() {
        // f64::INFINITY serialises to JSON `null`, which silently blanks the
        // field for every consumer of the API. This was a real bug.
        assert!(ratio(1.0, 0.0).is_finite());
        assert!(ratio(1e18, 0.0000001).is_finite());
        assert_eq!(ratio(0.0, 0.0), 0.0);
        assert_eq!(ratio(100.0, 10.0), 10.0);
        assert!(ratio(1e18, 1.5) <= MAX_RATIO);

        let v = serde_json::to_string(&ratio(1.0, 0.0)).unwrap();
        assert_ne!(v, "null", "the ratio must survive JSON serialisation");
    }

    #[test]
    fn a_process_without_enough_history_is_never_nominated() {
        // The exact bug found in testing: a helper with no baseline wrote once
        // and was named as the ransomware, because "no history" was being
        // treated as infinitely anomalous.
        let m = ProcessMonitor::new();
        m.sample(); // first sighting only; no samples recorded yet

        for w in m.anomalous_writers(20) {
            // Anything nominated must have a real history behind it.
            let history = m.history.lock();
            let track = history.get(&w.pid).expect("nominee should have a track");
            assert!(
                track.samples.len() >= MIN_SAMPLES,
                "{} was nominated on only {} sample(s)",
                w.name,
                track.samples.len()
            );
        }
    }

    #[test]
    fn anomalous_writers_never_includes_redoubt_or_system_pids() {
        let m = ProcessMonitor::new();
        m.sample();
        std::thread::sleep(std::time::Duration::from_millis(60));
        m.sample();
        for w in m.anomalous_writers(20) {
            assert_ne!(w.pid, std::process::id());
            assert!(w.pid > 4);
        }
    }

    #[test]
    fn last_sample_does_not_take_a_fresh_reading() {
        // Attribution must use the sample from around the time of the event;
        // the culprit is often gone moments later.
        let m = ProcessMonitor::new();
        assert!(m.last_sample().is_empty(), "nothing sampled yet");
        m.sample();
        std::thread::sleep(std::time::Duration::from_millis(80));
        let taken = m.sample();
        assert_eq!(m.last_sample().len(), taken.len());
    }

    #[test]
    fn snapshot_reports_a_real_process_age() {
        let all = snapshot();
        let me = all
            .iter()
            .find(|p| p.pid == std::process::id())
            .expect("our own process should be present");
        let age = me.age_secs.expect("we can always read our own creation time");
        assert!((0.0..86_400.0).contains(&age), "implausible age {age}");
    }

    #[test]
    fn process_age_is_the_kernels_not_how_long_we_have_watched() {
        // The bug this prevents: right after the service starts, every process
        // on the machine has just been observed for the first time. Treating
        // that as "newly launched" made every heavy writer look like a
        // freshly-dropped payload.
        let m = ProcessMonitor::new();
        m.sample();

        // A long-lived system process must not read as young.
        let all = snapshot();
        let old = all
            .iter()
            .filter_map(|p| p.age_secs.map(|a| (p, a)))
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        if let Some((p, age)) = old {
            assert!(
                age > 60.0,
                "the oldest process on this machine reads as {age:.0}s old ({}), \
                 which suggests age is being measured from observation",
                p.name
            );
        }
    }

    #[test]
    fn recovery_destroyers_are_recognised_case_insensitively() {
        assert!(recovery_destroyer("vssadmin.exe").is_some());
        assert!(recovery_destroyer("VSSADMIN.EXE").is_some());
        assert!(recovery_destroyer("BCDEdit.exe").is_some());
        assert!(recovery_destroyer("notepad.exe").is_none());
        assert!(recovery_destroyer("").is_none());
    }

    #[test]
    fn every_recovery_destroyer_explains_the_risk() {
        for (name, why) in RECOVERY_DESTROYERS {
            assert!(!why.is_empty(), "{name} has no explanation");
            assert!(
                why.len() > 20,
                "{name}'s explanation is too terse to be useful: {why}"
            );
        }
    }

    #[test]
    fn terminate_refuses_system_and_self() {
        // The two ways an over-eager response could take the machine down.
        for pid in [0u32, 4] {
            let err = terminate(pid).unwrap_err();
            assert!(err.to_string().contains("system process"), "pid {pid}: {err}");
        }
        let err = terminate(std::process::id()).unwrap_err();
        assert!(err.to_string().contains("Redoubt itself"), "{err}");
    }

    #[test]
    fn terminate_actually_stops_a_process() {
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "ping -n 30 127.0.0.1 > nul"])
            .spawn()
            .expect("spawning cmd should work");
        let pid = child.id();
        std::thread::sleep(std::time::Duration::from_millis(200));

        terminate(pid).expect("we should be able to kill our own child");
        let status = child.wait().expect("the child should be reapable");
        assert!(!status.success(), "a terminated process should not exit cleanly");
    }

    #[test]
    fn terminating_a_dead_pid_reports_an_error_rather_than_pretending() {
        // A pid that is almost certainly not in use.
        let err = terminate(0x7FFF_FFF0).unwrap_err();
        assert!(err.to_string().contains("could not open process"), "{err}");
    }
}
