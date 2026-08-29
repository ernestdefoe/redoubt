//! Ransomware detection.
//!
//! Signatures cannot catch ransomware. By the time a sample is known, the
//! family has rebuilt; and the damaging step is not a file arriving, it is
//! thousands of *existing* files being rewritten. So this watches behaviour
//! instead, and reads five independent signals off the same file-event stream
//! the scanner already consumes.
//!
//! # The signals, strongest first
//!
//! 1. **Canaries.** Decoy files planted in watched directories. Nothing has
//!    any legitimate reason to modify or delete one, so a touched canary is
//!    the highest-confidence signal available and on its own is enough to
//!    raise a critical alert. Real ransomware enumerates directories and
//!    encrypts what it finds; the decoys are named so they are met early.
//! 2. **Ransom notes.** A file called `HOW_TO_DECRYPT.txt` appearing next to
//!    your documents means the encryption already happened.
//! 3. **Known extensions.** Files renamed to `.locky`, `.wncry` and friends.
//! 4. **Modification bursts.** One process rewriting many files quickly.
//!    Alone this is ordinary - an installer, a build, a sync client - so it
//!    never alerts by itself.
//! 5. **Entropy rise.** A `.txt` or `.docx` whose contents are now
//!    indistinguishable from random has been encrypted. Combined with a burst
//!    this is strong; alone it is a compressed file.
//!
//! # Attribution, and how far to trust it
//!
//! `ReadDirectoryChangesW` reports *paths*, not the process that touched them.
//! Redoubt closes that gap by inference: [`crate::process`] samples per-process
//! write volume continuously, and an alert lists whatever was writing far
//! above its own normal rate.
//!
//! That inference is **context, not proof**, and testing on a real desktop is
//! why it is described that way. An early version ranked by absolute write
//! rate and confidently named the user's own browser and editor, which were
//! simply the busiest processes present. Ranking is now by how unusual a
//! process's behaviour is for itself, and automatic termination does not use
//! the list at all - it uses
//! [`crate::process::ProcessMonitor::decisive_suspect`], which declines to act
//! whenever more than one candidate is plausible.
//!
//! What remains genuinely out of reach: writes cannot be intercepted *before*
//! they land. That needs a filesystem minifilter, which is not built. Files
//! changed before an alert are already changed, and every alert says so.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Decoy filenames.
///
/// The leading characters are chosen so the files sort to the very start and
/// very end of a directory listing: ransomware that walks a directory in order
/// meets one before it has done much damage, whichever direction it walks.
const CANARY_NAMES: &[&str] = &[
    "!!! Redoubt ransomware decoy - do not delete.docx",
    "Redoubt ransomware decoy - do not delete.xlsx",
    "zzz Redoubt ransomware decoy - do not delete.pdf",
];

/// Content written into decoys. Plain text, so the entropy check has something
/// to compare against if one is encrypted in place.
const CANARY_CONTENT: &[u8] =
    b"This file belongs to Redoubt. It is a decoy used to detect ransomware.\r\n\
      Nothing needs to read, modify or delete it. If you are seeing this file\r\n\
      change, something on this machine is encrypting documents.\r\n";

/// Filename fragments that indicate a ransom note.
const NOTE_PATTERNS: &[&str] = &[
    "how_to_decrypt",
    "how-to-decrypt",
    "howtodecrypt",
    "how_to_recover",
    "how-to-back-files",
    "readme_to_restore",
    "restore_my_files",
    "restore-my-files",
    "recover_your_files",
    "recovery_key",
    "decrypt_instruction",
    "decrypt-instruction",
    "your_files_are_encrypted",
    "!!!readme",
    "_readme.txt",
    "-decrypt.txt",
    "unlock_your_files",
    "id-recover",
];

/// Extensions used by known ransomware families.
const RANSOM_EXTENSIONS: &[&str] = &[
    "locky", "wncry", "wcry", "wannacry", "cerber", "zepto", "odin", "thor", "aesir", "osiris",
    "crypt", "crypted", "crypto", "cryptolocker", "cryptowall", "encrypted", "enc", "ezz",
    "exx", "ecc", "vvv", "ttt", "xyz", "abc", "micro", "zzz", "petya", "notpetya", "gandcrab",
    "sodinokibi", "revil", "ryuk", "rryk", "conti", "maze", "egregor", "darkside", "lockbit",
    "blackcat", "hive", "avoslocker", "makop", "phobos", "dharma", "djvu", "stop", "medusa",
];

/// Extensions whose contents should never look random. High entropy in one of
/// these means it was encrypted, not compressed.
const LOW_ENTROPY_EXTENSIONS: &[&str] = &[
    "txt", "csv", "log", "md", "rtf", "html", "htm", "xml", "json", "ini", "cfg", "bmp", "doc",
    "xls", "ppt", "sql", "c", "h", "cpp", "rs", "py", "js", "java", "cs", "php", "wav",
];

/// How sure we are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Worth recording; not worth interrupting anyone.
    Low,
    /// Several signals agree.
    High,
    /// A canary was touched, or a ransom note appeared. Act now.
    Critical,
}

/// Which signal fired.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    CanaryTouched { path: PathBuf },
    RansomNote { path: PathBuf, matched: String },
    KnownExtension { path: PathBuf, extension: String },
    ModificationBurst { files: usize, seconds: f64 },
    EntropyRise { path: PathBuf, extension: String, entropy: f64 },
}

impl Signal {
    pub fn describe(&self) -> String {
        match self {
            Signal::CanaryTouched { path } => format!(
                "a decoy file was modified or deleted: {}",
                path.display()
            ),
            Signal::RansomNote { path, matched } => format!(
                "a file named like a ransom note appeared ({matched}): {}",
                path.display()
            ),
            Signal::KnownExtension { path, extension } => format!(
                "a file was renamed to .{extension}, used by known ransomware: {}",
                path.display()
            ),
            Signal::ModificationBurst { files, seconds } => {
                format!("{files} files modified in {seconds:.1} seconds")
            }
            Signal::EntropyRise { path, extension, entropy } => format!(
                "a .{extension} file now looks random (entropy {entropy:.2}): {}",
                path.display()
            ),
        }
    }
}

/// A raised alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub confidence: Confidence,
    pub signals: Vec<Signal>,
    pub summary: String,
    /// What Redoubt can and cannot do about it. Always present, so an alert
    /// never implies containment that did not happen.
    pub limitation: String,
    pub at_epoch: u64,
    /// Processes writing far more than they normally do, most unusual first.
    ///
    /// **Context, not an accusation.** Redoubt cannot see which process wrote
    /// which file without a driver, so this is an inference from I/O
    /// behaviour. On a busy machine several entries are normal and only one of
    /// them - possibly none - is responsible. Automatic termination ignores
    /// this list and uses `decisive_suspect`, which refuses to act when more
    /// than one candidate is plausible.
    #[serde(default)]
    pub suspects: Vec<crate::process::WriteRate>,
    /// A process Redoubt terminated, if enforcement was configured to.
    #[serde(default)]
    pub terminated: Option<u32>,
}

/// Tunables. Defined in the core config so one file describes the whole
/// product's behaviour rather than settings living in two places.
pub type Settings = redoubt_core::config::Ransomware;

/// A planted decoy.
#[derive(Debug, Clone)]
struct Canary {
    path: PathBuf,
    /// Size at plant time. A cheap check that does not require reading it.
    size: u64,
}

#[derive(Debug, Clone, Copy)]
struct Touch {
    at: Instant,
}

/// The behavioural detector.
pub struct RansomwareGuard {
    settings: Settings,
    canaries: Mutex<Vec<Canary>>,
    /// Recent modifications, for the burst window.
    window: Mutex<VecDeque<(PathBuf, Touch)>>,
    /// Files that looked encrypted, keyed by path so one file cannot count
    /// repeatedly toward the same alert.
    encrypted: Mutex<HashMap<PathBuf, f64>>,
    alerts: Mutex<Vec<Alert>>,
    /// Suppresses repeat alerts while one incident is ongoing.
    last_alert: Mutex<Option<Instant>>,
    /// Sampled continuously by the service, so attribution can look at the
    /// moment the event happened rather than the moment it was noticed.
    monitor: Mutex<std::sync::Arc<crate::process::ProcessMonitor>>,
    shared_monitor: Mutex<Option<std::sync::Arc<crate::process::ProcessMonitor>>>,
}

/// How long to stay quiet after alerting, so one incident does not produce
/// hundreds of notifications.
const ALERT_COOLDOWN: Duration = Duration::from_secs(30);

impl RansomwareGuard {
    pub fn new(settings: Settings) -> Self {
        Self {
            settings,
            canaries: Mutex::new(Vec::new()),
            window: Mutex::new(VecDeque::new()),
            encrypted: Mutex::new(HashMap::new()),
            alerts: Mutex::new(Vec::new()),
            last_alert: Mutex::new(None),
            monitor: Mutex::new(std::sync::Arc::new(crate::process::ProcessMonitor::new())),
            shared_monitor: Mutex::new(None),
        }
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Plant decoys in each directory, returning how many were placed.
    ///
    /// Existing decoys are left as they are: rewriting one on every start
    /// would make its own modification indistinguishable from an attack.
    pub fn plant_canaries(&self, roots: &[PathBuf]) -> usize {
        if !self.settings.enabled || !self.settings.canaries {
            return 0;
        }
        let mut planted = 0;
        let mut list = self.canaries.lock();

        for root in roots {
            if !root.is_dir() {
                continue;
            }
            for name in CANARY_NAMES {
                let path = root.join(name);
                if !path.exists() && std::fs::write(&path, CANARY_CONTENT).is_err() {
                    continue;
                }
                let Ok(meta) = std::fs::metadata(&path) else {
                    continue;
                };
                // Deliberately NOT hidden.
                //
                // Hiding them looked tidier and was actively harmful: a great
                // deal of ransomware skips hidden and system files, so a
                // hidden decoy is one the attacker never touches - which
                // silently disables the strongest signal this module has.
                // (Windows also refuses a truncating write to a hidden file,
                // which made a decoy look protected when it was merely
                // unreachable.) A few clearly-named files in a folder is the
                // right price for a tripwire that actually trips.
                list.push(Canary { path, size: meta.len() });
                planted += 1;
            }
        }
        planted
    }

    /// Remove the decoys. Called when protection stops, so they do not linger
    /// in the user's folders.
    pub fn remove_canaries(&self) {
        let mut list = self.canaries.lock();
        for c in list.iter() {
            let _ = std::fs::remove_file(&c.path);
        }
        list.clear();
    }

    pub fn canary_count(&self) -> usize {
        self.canaries.lock().len()
    }

    /// True if `path` is one of our decoys.
    pub fn is_canary(&self, path: &Path) -> bool {
        let p = path.to_string_lossy().to_lowercase();
        self.canaries
            .lock()
            .iter()
            .any(|c| c.path.to_string_lossy().to_lowercase() == p)
    }

    /// Feed one file event. Returns an alert when the signals justify one.
    ///
    /// `data` is the file's current contents when the caller already has them,
    /// which lets the entropy check run without a second read.
    pub fn observe(&self, path: &Path, data: Option<&[u8]>, now_epoch: u64) -> Option<Alert> {
        if !self.settings.enabled {
            return None;
        }

        let mut signals = Vec::new();

        // ── 1. canaries ────────────────────────────────────────────────
        if self.is_canary(path) {
            let changed = match std::fs::metadata(path) {
                Err(_) => true, // deleted
                Ok(m) => {
                    let list = self.canaries.lock();
                    list.iter()
                        .find(|c| c.path == path)
                        .map(|c| m.len() != c.size)
                        .unwrap_or(false)
                }
            };
            if changed {
                signals.push(Signal::CanaryTouched { path: path.to_path_buf() });
            }
        }

        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        // ── 2. ransom notes ────────────────────────────────────────────
        if let Some(m) = NOTE_PATTERNS.iter().find(|p| name.contains(**p)) {
            signals.push(Signal::RansomNote {
                path: path.to_path_buf(),
                matched: (*m).to_string(),
            });
        }

        // ── 3. known extensions ────────────────────────────────────────
        if !ext.is_empty() && RANSOM_EXTENSIONS.contains(&ext.as_str()) {
            signals.push(Signal::KnownExtension {
                path: path.to_path_buf(),
                extension: ext.clone(),
            });
        }

        // ── 4. burst ───────────────────────────────────────────────────
        let burst = self.record_and_measure_burst(path);

        // ── 5. entropy ─────────────────────────────────────────────────
        if let Some(data) = data {
            if data.len() >= 512 && LOW_ENTROPY_EXTENSIONS.contains(&ext.as_str()) {
                let e = redoubt_core::hashing::entropy(data);
                if e >= self.settings.entropy_threshold {
                    self.encrypted.lock().insert(path.to_path_buf(), e);
                    signals.push(Signal::EntropyRise {
                        path: path.to_path_buf(),
                        extension: ext,
                        entropy: e,
                    });
                }
            }
        }

        self.decide(signals, burst, now_epoch)
    }

    /// Add `path` to the sliding window and report the current count.
    fn record_and_measure_burst(&self, path: &Path) -> Option<Signal> {
        let mut window = self.window.lock();
        let now = Instant::now();
        let horizon = Duration::from_secs(self.settings.burst_window_secs);

        window.push_back((path.to_path_buf(), Touch { at: now }));
        while let Some((_, t)) = window.front() {
            if now.duration_since(t.at) > horizon {
                window.pop_front();
            } else {
                break;
            }
        }

        // Distinct paths, so one file rewritten repeatedly is not a burst.
        let distinct: std::collections::HashSet<&PathBuf> =
            window.iter().map(|(p, _)| p).collect();

        if distinct.len() >= self.settings.burst_threshold {
            Some(Signal::ModificationBurst {
                files: distinct.len(),
                seconds: self.settings.burst_window_secs as f64,
            })
        } else {
            None
        }
    }

    /// Weigh the signals.
    ///
    /// A burst or an entropy reading on its own never alerts: builds, syncs
    /// and installers produce both all day, and an alert that fires during an
    /// npm install is an alert nobody reads.
    fn decide(&self, mut signals: Vec<Signal>, burst: Option<Signal>, now_epoch: u64) -> Option<Alert> {
        let had_burst = burst.is_some();
        if let Some(b) = burst {
            signals.push(b);
        }
        if signals.is_empty() {
            return None;
        }

        let canary = signals.iter().any(|s| matches!(s, Signal::CanaryTouched { .. }));
        let note = signals.iter().any(|s| matches!(s, Signal::RansomNote { .. }));
        let known_ext = signals.iter().any(|s| matches!(s, Signal::KnownExtension { .. }));
        let entropy = signals.iter().any(|s| matches!(s, Signal::EntropyRise { .. }));

        let confidence = if canary || note {
            Confidence::Critical
        } else if known_ext || (had_burst && entropy) {
            Confidence::High
        } else if had_burst || entropy {
            // Not enough on its own.
            return None;
        } else {
            Confidence::Low
        };

        // One incident, one alert.
        {
            let mut last = self.last_alert.lock();
            if let Some(t) = *last {
                if t.elapsed() < ALERT_COOLDOWN && confidence < Confidence::Critical {
                    return None;
                }
            }
            *last = Some(Instant::now());
        }

        let summary = match confidence {
            Confidence::Critical => {
                "Something is encrypting files on this machine.".to_string()
            }
            Confidence::High => {
                "File activity consistent with ransomware.".to_string()
            }
            Confidence::Low => "Unusual file activity.".to_string(),
        };

        // Attribution: whatever is writing hardest right now is very likely
        // what tripped the signals.
        let suspects = if self.settings.attribute_process {
            self.attribute()
        } else {
            Vec::new()
        };

        let limitation = if suspects.is_empty() {
            "Redoubt cannot say which process is responsible: nothing was writing far \
             enough above its own normal rate to name. That usually means the program has \
             already exited, or is running as another user. Naming a bystander would be \
             worse than naming nobody, so it names nobody. Disconnect from the network and \
             stop the machine if this is unexpected."
                .to_string()
        } else {
            "The process named above is inferred from an unusually high write rate, not \
             proven. Redoubt cannot intercept writes before they happen - that needs a \
             filesystem minifilter, which is not built - so files changed before this alert \
             are already changed. Disconnect from the network if this is unexpected."
                .to_string()
        };

        let alert = Alert {
            confidence,
            signals,
            summary,
            limitation,
            at_epoch: now_epoch,
            suspects,
            terminated: None,
        };

        self.alerts.lock().push(alert.clone());
        Some(alert)
    }

    /// Name whatever is writing far more than it normally does.
    ///
    /// Two things here were wrong in the first version and are worth stating,
    /// because both produced confidently incorrect answers:
    ///
    /// 1. It sampled *when the alert fired*. A program that encrypts a folder
    ///    and exits is already gone by then, so the sample described only the
    ///    bystanders. The shared monitor is now sampled continuously and this
    ///    reads the most recent one.
    /// 2. It ranked by absolute write rate, which nominates whichever process
    ///    is busiest - a browser, an editor, a sync client. Ranking is now by
    ///    how far a process exceeds *its own* baseline.
    ///
    /// An empty result means "could not tell", and is reported that way rather
    /// than falling back to the loudest neighbour. That matters because the
    /// configured response to a critical alert can be to kill what this names.
    fn attribute(&self) -> Vec<crate::process::WriteRate> {
        // Prefer the shared monitor: it is the one with continuous history.
        // The guard's own is a fallback for tests and for callers that drive
        // the guard directly.
        if let Some(shared) = self.shared_monitor.lock().as_ref() {
            return shared.anomalous_writers(5);
        }
        self.monitor.lock().anomalous_writers(5)
    }

    /// Give the guard the monitor that the service samples continuously.
    pub fn attach_monitor(&self, monitor: std::sync::Arc<crate::process::ProcessMonitor>) {
        *self.shared_monitor.lock() = Some(monitor);
    }

    /// Terminate the most likely culprit.
    ///
    /// The caller decides whether this is allowed; the guard never kills
    /// anything on its own initiative.
    pub fn terminate_suspect(&self, alert: &mut Alert) -> anyhow::Result<u32> {
        // Deliberately not `alert.suspects.first()`. That list is ranked
        // context; on a busy machine it routinely holds two or three plausible
        // heavy writers, and killing its head is how a security tool
        // terminates the user's browser. Only an unambiguous candidate is
        // acted on, and ambiguity is reported rather than resolved by guessing.
        let decisive = self
            .shared_monitor
            .lock()
            .as_ref()
            .and_then(|m| m.decisive_suspect())
            .or_else(|| self.monitor.lock().decisive_suspect())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no single process stood out clearly enough to act on;                      several were writing heavily, so nothing was terminated"
                )
            })?;

        crate::process::terminate(decisive.pid)?;
        alert.terminated = Some(decisive.pid);
        Ok(decisive.pid)
    }

    pub fn alerts(&self) -> Vec<Alert> {
        self.alerts.lock().clone()
    }

    pub fn clear_alerts(&self) {
        self.alerts.lock().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("redoubt-ransom-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&p).ok();
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn guard() -> RansomwareGuard {
        RansomwareGuard::new(Settings::default())
    }

    fn random_bytes(n: usize) -> Vec<u8> {
        let mut state = 0x2545F4914F6CDD1Du64;
        (0..n)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn canaries_are_not_hidden() {
        // A hidden decoy is one that ransomware skipping hidden files never
        // touches, which silently disables the strongest signal here. It also
        // cannot be truncated by an ordinary write, which made it look
        // protected when it was only unreachable.
        let dir = temp("visible");
        let g = guard();
        g.plant_canaries(&[dir.clone()]);

        let path = dir.join(CANARY_NAMES[0]);
        // The check that matters: an ordinary truncating write must succeed,
        // exactly as it would for one of the user's own documents.
        std::fs::write(&path, b"rewritten").expect("a decoy must be writable like any file");

        g.remove_canaries();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn canary_names_say_what_they_are() {
        // They are visible in the user's folders, so they have to explain
        // themselves without anyone looking anything up.
        for name in CANARY_NAMES {
            let lower = name.to_lowercase();
            assert!(lower.contains("redoubt"), "{name} does not name the tool");
            assert!(lower.contains("do not delete"), "{name} does not warn the user");
        }
    }

    #[test]
    fn canaries_are_planted_and_removed() {
        let dir = temp("plant");
        let g = guard();

        let n = g.plant_canaries(&[dir.clone()]);
        assert_eq!(n, CANARY_NAMES.len());
        for name in CANARY_NAMES {
            assert!(dir.join(name).is_file(), "{name} was not planted");
        }

        g.remove_canaries();
        for name in CANARY_NAMES {
            assert!(!dir.join(name).exists(), "{name} was left behind");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn planting_twice_does_not_rewrite_an_existing_canary() {
        // Rewriting on every start would make our own modification
        // indistinguishable from an attack.
        let dir = temp("replant");
        let g = guard();
        g.plant_canaries(&[dir.clone()]);

        let path = dir.join(CANARY_NAMES[0]);
        let before = std::fs::metadata(&path).unwrap().len();

        let g2 = guard();
        g2.plant_canaries(&[dir.clone()]);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), before);

        g.remove_canaries();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_modified_canary_raises_a_critical_alert_on_its_own() {
        let dir = temp("canary-mod");
        let g = guard();
        g.plant_canaries(&[dir.clone()]);

        let path = dir.join(CANARY_NAMES[0]);
        std::fs::write(&path, b"encrypted-by-something").unwrap();

        let alert = g.observe(&path, None, 1).expect("a touched canary must alert");
        assert_eq!(alert.confidence, Confidence::Critical);
        assert!(alert.signals.iter().any(|s| matches!(s, Signal::CanaryTouched { .. })));
        // And it must be honest about what it can do.
        assert!(alert.limitation.contains("cannot"), "{}", alert.limitation);

        g.remove_canaries();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_deleted_canary_also_alerts() {
        let dir = temp("canary-del");
        let g = guard();
        g.plant_canaries(&[dir.clone()]);
        let path = dir.join(CANARY_NAMES[0]);
        std::fs::remove_file(&path).unwrap();

        let alert = g.observe(&path, None, 1).expect("a deleted canary must alert");
        assert_eq!(alert.confidence, Confidence::Critical);

        g.remove_canaries();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_untouched_canary_is_silent() {
        let dir = temp("canary-quiet");
        let g = guard();
        g.plant_canaries(&[dir.clone()]);
        let path = dir.join(CANARY_NAMES[0]);

        assert!(
            g.observe(&path, None, 1).is_none(),
            "an unchanged canary must not alert"
        );

        g.remove_canaries();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_ransom_note_alerts_critically() {
        let g = guard();
        for name in [
            "HOW_TO_DECRYPT.txt",
            "!!!README!!!.txt",
            "restore-my-files.html",
            "YOUR_FILES_ARE_ENCRYPTED.TXT",
        ] {
            let alert = g
                .observe(Path::new(&format!(r"C:\Users\me\Documents\{name}")), None, 1)
                .unwrap_or_else(|| panic!("{name} should alert"));
            assert_eq!(alert.confidence, Confidence::Critical, "{name}");
            g.clear_alerts();
        }
    }

    #[test]
    fn ordinary_readme_files_do_not_alert() {
        // The obvious false positive: every source tree has one.
        let g = guard();
        for name in ["README.md", "readme.txt", "CHANGELOG.md", "notes.txt", "LICENSE"] {
            assert!(
                g.observe(Path::new(&format!(r"C:\src\project\{name}")), None, 1).is_none(),
                "{name} must not alert"
            );
        }
    }

    #[test]
    fn a_known_ransomware_extension_alerts() {
        let g = guard();
        let alert = g
            .observe(Path::new(r"C:\Users\me\Documents\budget.xlsx.locky"), None, 1)
            .expect("a .locky file should alert");
        assert_eq!(alert.confidence, Confidence::High);
        assert!(alert
            .signals
            .iter()
            .any(|s| matches!(s, Signal::KnownExtension { .. })));
    }

    #[test]
    fn a_burst_alone_does_not_alert() {
        // An npm install or a build touches thousands of files. If this
        // alerted, the alert would be worthless.
        let g = guard();
        for i in 0..500 {
            let p = PathBuf::from(format!(r"C:\src\project\node_modules\pkg{i}\index.js"));
            assert!(
                g.observe(&p, None, 1).is_none(),
                "a modification burst alone must not alert (file {i})"
            );
        }
    }

    #[test]
    fn high_entropy_alone_does_not_alert() {
        // A compressed or encrypted file the user made themselves.
        let g = guard();
        let data = random_bytes(4096);
        assert!(g.observe(Path::new(r"C:\Users\me\archive.txt"), Some(&data), 1).is_none());
    }

    #[test]
    fn a_burst_plus_entropy_alerts() {
        // Together they are the signature of encryption in progress.
        let g = guard();
        let data = random_bytes(4096);

        let mut alert = None;
        for i in 0..200 {
            let p = PathBuf::from(format!(r"C:\Users\me\Documents\file{i}.txt"));
            if let Some(a) = g.observe(&p, Some(&data), 1) {
                alert = Some(a);
                break;
            }
        }
        let alert = alert.expect("a burst of high-entropy .txt writes must alert");
        assert_eq!(alert.confidence, Confidence::High);
        assert!(alert.signals.iter().any(|s| matches!(s, Signal::EntropyRise { .. })));
        assert!(alert
            .signals
            .iter()
            .any(|s| matches!(s, Signal::ModificationBurst { .. })));
    }

    #[test]
    fn normal_text_does_not_look_encrypted() {
        let g = guard();
        let text = "The quick brown fox jumps over the lazy dog. ".repeat(200);
        for i in 0..200 {
            let p = PathBuf::from(format!(r"C:\Users\me\Documents\note{i}.txt"));
            assert!(
                g.observe(&p, Some(text.as_bytes()), 1).is_none(),
                "ordinary text must never read as encrypted"
            );
        }
    }

    #[test]
    fn a_high_entropy_zip_is_not_treated_as_encrypted() {
        // Compressed formats are supposed to look random; only file types that
        // should not are considered.
        let g = guard();
        let data = random_bytes(8192);
        for i in 0..200 {
            let p = PathBuf::from(format!(r"C:\Users\me\Downloads\archive{i}.zip"));
            assert!(
                g.observe(&p, Some(&data), 1).is_none(),
                "a .zip looking random is entirely normal"
            );
        }
    }

    #[test]
    fn one_file_rewritten_repeatedly_is_not_a_burst() {
        // A log file being appended to is not thousands of files changing.
        let g = guard();
        let data = random_bytes(4096);
        for _ in 0..500 {
            let p = PathBuf::from(r"C:\Users\me\Documents\same.txt");
            assert!(g.observe(&p, Some(&data), 1).is_none());
        }
    }

    #[test]
    fn repeat_alerts_are_suppressed_during_one_incident() {
        let g = guard();
        // First .locky raises High.
        let first = g.observe(Path::new(r"C:\Users\me\a.locky"), None, 1);
        assert!(first.is_some());
        // Immediately after, the same class of signal is held back.
        let second = g.observe(Path::new(r"C:\Users\me\b.locky"), None, 1);
        assert!(second.is_none(), "one incident should not produce a flood");
    }

    #[test]
    fn a_critical_signal_is_never_suppressed() {
        // Cooldown must not hide the strongest evidence.
        let g = guard();
        g.observe(Path::new(r"C:\Users\me\a.locky"), None, 1);
        let critical = g.observe(Path::new(r"C:\Users\me\HOW_TO_DECRYPT.txt"), None, 1);
        assert!(critical.is_some(), "a critical signal must always get through");
        assert_eq!(critical.unwrap().confidence, Confidence::Critical);
    }

    #[test]
    fn termination_refuses_when_no_suspect_is_decisive() {
        // The gate on the only destructive automatic action. On a busy machine
        // several processes write heavily, and killing the top of that list is
        // how a security tool terminates its user's browser.
        let g = guard();
        let mut alert = g
            .observe(Path::new(r"C:\\Users\\me\\HOW_TO_DECRYPT.txt"), None, 1)
            .expect("a ransom note should alert");

        // Whatever the machine is doing, terminate must either act on a single
        // unambiguous candidate or refuse with a reason - never guess.
        match g.terminate_suspect(&mut alert) {
            Ok(pid) => {
                assert!(pid > 4, "must never act on a system pid");
                assert_eq!(alert.terminated, Some(pid));
            }
            Err(e) => {
                assert!(
                    e.to_string().contains("stood out") || e.to_string().contains("access"),
                    "a refusal should explain itself: {e}"
                );
                assert_eq!(alert.terminated, None, "a refusal must not record a kill");
            }
        }
    }

    #[test]
    fn an_alert_never_presents_suspects_as_proof() {
        let g = guard();
        let alert = g.observe(Path::new(r"C:\\Users\\me\\HOW_TO_DECRYPT.txt"), None, 1).unwrap();
        let l = alert.limitation.to_lowercase();
        assert!(
            l.contains("not proof") || l.contains("cannot say"),
            "the limitation must not imply certainty: {}",
            alert.limitation
        );
    }

    #[test]
    fn disabling_the_guard_silences_everything() {
        let g = RansomwareGuard::new(Settings { enabled: false, ..Default::default() });
        assert!(g.observe(Path::new(r"C:\HOW_TO_DECRYPT.txt"), None, 1).is_none());
        assert_eq!(g.plant_canaries(&[std::env::temp_dir()]), 0);
    }

    #[test]
    fn alerts_accumulate_and_can_be_cleared() {
        let g = guard();
        g.observe(Path::new(r"C:\HOW_TO_DECRYPT.txt"), None, 1);
        assert_eq!(g.alerts().len(), 1);
        g.clear_alerts();
        assert!(g.alerts().is_empty());
    }

    #[test]
    fn every_signal_describes_itself_in_plain_words() {
        let signals = [
            Signal::CanaryTouched { path: PathBuf::from("a") },
            Signal::RansomNote { path: PathBuf::from("b"), matched: "x".into() },
            Signal::KnownExtension { path: PathBuf::from("c"), extension: "locky".into() },
            Signal::ModificationBurst { files: 100, seconds: 10.0 },
            Signal::EntropyRise {
                path: PathBuf::from("d"),
                extension: "txt".into(),
                entropy: 7.9,
            },
        ];
        for s in signals {
            let d = s.describe();
            assert!(d.len() > 20, "signal description too terse: {d}");
            assert!(!d.contains("Signal::"), "description leaks a type name: {d}");
        }
    }
}
