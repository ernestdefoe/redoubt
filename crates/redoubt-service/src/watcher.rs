//! The filesystem event source.
//!
//! Built on `ReadDirectoryChangesW` via `notify`, which needs no driver and no
//! elevation. It reports changes *after* they happen, which is what makes this
//! detect-and-react rather than pre-execution blocking.
//!
//! # Debouncing
//!
//! Copying one file produces a burst of notifications - create, then a write
//! per buffer, then close. Scanning each one would read a half-written file
//! repeatedly and produce meaningless verdicts. Paths are therefore held for a
//! settle period and coalesced, so one copy costs one scan of the finished
//! file.

use anyhow::{Context, Result};
use notify::{Event, EventKind, RecursiveMode, Watcher as _};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use redoubt_core::config::Config;

/// How long a path must be quiet before it is considered finished.
const SETTLE: Duration = Duration::from_millis(400);

/// How often the debounce map is swept.
const SWEEP: Duration = Duration::from_millis(150);

/// Where files actually arrive on a Windows desktop.
///
/// Watching the whole disk would be mostly wasted: `C:\Windows` changes only
/// through Windows Update, and build trees generate enormous churn with no
/// security value. These are the paths malware lands in.
pub fn default_roots(cfg: &Config) -> Vec<PathBuf> {
    if !cfg.realtime.watch_paths.is_empty() {
        return cfg
            .realtime
            .watch_paths
            .iter()
            .filter(|p| p.is_dir())
            .cloned()
            .collect();
    }

    let mut roots = Vec::new();
    if let Some(home) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
        for sub in ["Downloads", "Desktop", "Documents"] {
            let p = home.join(sub);
            if p.is_dir() {
                roots.push(p);
            }
        }
    }
    for var in ["TEMP", "LOCALAPPDATA"] {
        if let Some(p) = std::env::var_os(var).map(PathBuf::from) {
            if p.is_dir() && !roots.contains(&p) {
                roots.push(p);
            }
        }
    }
    roots
}

/// True for event kinds worth scanning.
///
/// Reads and metadata changes are ignored: a file that was only read has not
/// become malicious since the last look, and acting on access events is what
/// makes naive real-time scanners cripple a machine.
fn is_interesting(kind: &EventKind) -> bool {
    matches!(kind, EventKind::Create(_) | EventKind::Modify(_))
}

/// A running watcher. Dropping it stops the watch and its sweeper thread.
pub struct Watcher {
    _inner: notify::RecommendedWatcher,
    stop: Arc<AtomicBool>,
    sweeper: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.sweeper.take() {
            let _ = h.join();
        }
    }
}

impl Watcher {
    /// Watch `roots` recursively, calling `on_settled` once per path once it
    /// has been quiet for [`SETTLE`].
    pub fn start<F>(roots: &[PathBuf], on_settled: F) -> Result<Self>
    where
        F: Fn(PathBuf) + Send + Sync + 'static,
    {
        let pending: Arc<Mutex<HashMap<PathBuf, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let pending_for_events = pending.clone();
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            let Ok(event) = res else {
                return;
            };
            if !is_interesting(&event.kind) {
                return;
            }
            let now = Instant::now();
            let mut map = pending_for_events.lock();
            for path in event.paths {
                // Directories are watched, not scanned.
                if path.is_dir() {
                    continue;
                }
                map.insert(path, now);
            }
        })
        .context("creating the filesystem watcher")?;

        for root in roots {
            watcher
                .watch(root, RecursiveMode::Recursive)
                .with_context(|| format!("watching {}", root.display()))?;
        }

        let sweeper = {
            let pending = pending.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(SWEEP);
                    let due: Vec<PathBuf> = {
                        let mut map = pending.lock();
                        let now = Instant::now();
                        let ready: Vec<PathBuf> = map
                            .iter()
                            .filter(|(_, seen)| now.duration_since(**seen) >= SETTLE)
                            .map(|(p, _)| p.clone())
                            .collect();
                        for p in &ready {
                            map.remove(p);
                        }
                        ready
                    };
                    for path in due {
                        // A file can vanish between the event and the sweep -
                        // a temp file, or something we already quarantined.
                        if path.is_file() {
                            on_settled(path);
                        }
                    }
                }
            })
        };

        Ok(Self { _inner: watcher, stop, sweeper: Some(sweeper) })
    }
}

/// True when `path` sits under any of `roots`. Used to keep a watcher from
/// reacting to its own quarantine writes.
pub fn is_under(path: &Path, roots: &[PathBuf]) -> bool {
    let lower = path.to_string_lossy().to_lowercase();
    roots
        .iter()
        .any(|r| lower.starts_with(&r.to_string_lossy().to_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{CreateKind, DataChange, ModifyKind};
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn only_create_and_modify_are_interesting() {
        assert!(is_interesting(&EventKind::Create(CreateKind::File)));
        assert!(is_interesting(&EventKind::Modify(ModifyKind::Data(DataChange::Content))));
        // Reads and removals must not queue work: a file that was merely read
        // has not changed, and a removed one is not there to scan.
        assert!(!is_interesting(&EventKind::Access(
            notify::event::AccessKind::Read
        )));
        assert!(!is_interesting(&EventKind::Remove(notify::event::RemoveKind::File)));
        assert!(!is_interesting(&EventKind::Any));
    }

    #[test]
    fn default_roots_honour_an_explicit_config() {
        let dir = std::env::temp_dir().join(format!("redoubt-roots-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let mut cfg = Config::default();
        cfg.realtime.watch_paths = vec![dir.clone(), PathBuf::from("Z:/does/not/exist")];

        let roots = default_roots(&cfg);
        assert_eq!(roots, vec![dir.clone()], "missing directories must be dropped");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn default_roots_fall_back_to_the_usual_places() {
        let cfg = Config::default();
        let roots = default_roots(&cfg);
        // Whatever this machine has, every root must actually exist.
        for r in &roots {
            assert!(r.is_dir(), "{} is not a directory", r.display());
        }
    }

    #[test]
    fn is_under_is_case_insensitive() {
        let roots = vec![PathBuf::from(r"C:\Users\me\Downloads")];
        assert!(is_under(Path::new(r"c:\users\me\downloads\a.exe"), &roots));
        assert!(is_under(Path::new(r"C:\Users\me\Downloads\sub\b.exe"), &roots));
        assert!(!is_under(Path::new(r"C:\Users\me\Documents\c.exe"), &roots));
    }

    #[test]
    fn a_written_file_is_reported_once_after_settling() {
        let dir = std::env::temp_dir().join(format!("redoubt-watch-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();

        let hits = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(Vec::<PathBuf>::new()));
        let (h, s) = (hits.clone(), seen.clone());

        let watcher = Watcher::start(&[dir.clone()], move |p| {
            h.fetch_add(1, Ordering::Relaxed);
            s.lock().push(p);
        })
        .unwrap();

        // Write in several chunks, the way a download would.
        let target = dir.join("download.bin");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&target).unwrap();
            for _ in 0..8 {
                f.write_all(&[0u8; 4096]).unwrap();
                f.flush().unwrap();
                std::thread::sleep(Duration::from_millis(15));
            }
        }

        // Wait past the settle window plus a sweep or two.
        std::thread::sleep(SETTLE + SWEEP * 4);
        drop(watcher);

        let count = hits.load(Ordering::Relaxed);
        assert_eq!(
            count, 1,
            "a single file write produced {count} scans; the debounce is not coalescing"
        );
        assert_eq!(seen.lock().len(), 1);
        assert!(seen.lock()[0].ends_with("download.bin"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
