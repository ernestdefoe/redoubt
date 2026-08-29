//! On-disk configuration.
//!
//! Lives at `%ProgramData%\Redoubt\config.toml`. Every field has a default, so
//! a missing or partial file is not an error - the service starts with sane
//! settings and writes the full file back out on first run.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// What the service is allowed to *do* about a detection.
///
/// The distinction is deliberate and load-bearing: a brand-new AV on a daily
/// driver has no business deleting anything until its false-positive rate is
/// known. `Observe` is the shipped default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Detect, log, alert. Touch nothing.
    #[default]
    Observe,
    /// Quarantine malicious files and terminate the processes backing them.
    Enforce,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Observe => "observe",
            Mode::Enforce => "enforce",
        }
    }
}

fn default_true() -> bool {
    true
}

/// Root of the configuration tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
    pub paths: Paths,
    pub realtime: Realtime,
    pub scan: ScanLimits,
    pub engines: Engines,
    pub heuristics: Heuristics,
    pub exclusions: Exclusions,
    pub ransomware: Ransomware,
    pub updates: Updates,
}

/// Behavioural ransomware detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ransomware {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Plant decoy files in watched directories. Nothing legitimate modifies
    /// them, which makes a touched decoy the highest-confidence signal there
    /// is.
    #[serde(default = "default_true")]
    pub canaries: bool,
    /// Distinct files modified within the window before it counts as a burst.
    /// Well above ordinary build and sync activity, and never enough to alert
    /// on its own.
    pub burst_threshold: usize,
    pub burst_window_secs: u64,
    /// Entropy at or above which file contents are treated as encrypted.
    pub entropy_threshold: f64,
    /// Sample process I/O to name what is doing the writing.
    #[serde(default = "default_true")]
    pub attribute_process: bool,
    /// Terminate the responsible process on a critical alert.
    ///
    /// **Off by default, deliberately.** Attribution is a strong inference,
    /// not a certainty, and killing the wrong process loses unsaved work. This
    /// also requires enforce mode - two switches, because the consequence of
    /// being wrong is destructive.
    pub terminate_on_critical: bool,
}

impl Default for Ransomware {
    fn default() -> Self {
        Self {
            enabled: true,
            canaries: true,
            burst_threshold: 60,
            burst_window_secs: 10,
            entropy_threshold: 7.5,
            attribute_process: true,
            terminate_on_critical: false,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Observe,
            paths: Paths::default(),
            realtime: Realtime::default(),
            scan: ScanLimits::default(),
            engines: Engines::default(),
            heuristics: Heuristics::default(),
            exclusions: Exclusions::default(),
            ransomware: Ransomware::default(),
            updates: Updates::default(),
        }
    }
}

/// Where Redoubt keeps its state. All under `%ProgramData%\Redoubt` by default.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Paths {
    /// Downloaded ClamAV `.cvd`/`.cld` files and the compiled index.
    pub signatures: PathBuf,
    /// Compiled + source YARA rules.
    pub rules: PathBuf,
    /// Encrypted quarantine store plus its manifest.
    pub quarantine: PathBuf,
    /// Rotating JSON event log.
    pub logs: PathBuf,
    /// Persistent verdict cache.
    pub cache: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        let root = data_root();
        Self {
            signatures: root.join("signatures"),
            rules: root.join("rules"),
            quarantine: root.join("quarantine"),
            logs: root.join("logs"),
            cache: root.join("cache"),
        }
    }
}

/// Which real-time event sources are live.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Realtime {
    /// Master switch for all real-time sources.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// ETW `Microsoft-Windows-Kernel-File` - scan files shortly after write.
    #[serde(default = "default_true")]
    pub file_events: bool,
    /// ETW `Microsoft-Windows-Kernel-Process` - scan images at process start.
    #[serde(default = "default_true")]
    pub process_events: bool,
    /// AMSI provider - pre-execution blocking for scripts. Requires the
    /// provider DLL to be registered separately.
    #[serde(default = "default_true")]
    pub amsi: bool,
    /// Directories watched for changes. Empty means "pick the usual places" -
    /// Downloads, Desktop, Documents, %TEMP% and %LOCALAPPDATA%.
    ///
    /// Watching the whole disk is deliberately not the default: `C:\Windows`
    /// only changes through Windows Update, and a build tree generates
    /// enormous churn with no security value.
    pub watch_paths: Vec<PathBuf>,
    /// How many scan workers to run. 0 = one per core less one, capped at 8.
    pub workers: usize,
    /// Bound on the pending-scan queue. Past this, the oldest low-priority
    /// entries are dropped rather than letting the service grow without limit
    /// during something like an npm install.
    pub queue_capacity: usize,
}

impl Default for Realtime {
    fn default() -> Self {
        Self {
            enabled: true,
            file_events: true,
            process_events: true,
            amsi: true,
            watch_paths: Vec::new(),
            workers: 0,
            queue_capacity: 8192,
        }
    }
}

/// Guard rails so one hostile file cannot stall the scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanLimits {
    /// Files larger than this are hashed but not pattern-scanned. Malware is
    /// almost never 200 MB, and mmap-scanning a VM image costs seconds.
    pub max_scan_bytes: u64,
    /// Hard ceiling on one file's scan. Exceeding it yields a clean verdict
    /// with a logged timeout rather than a stuck worker.
    pub timeout_ms: u64,
    /// How deep to recurse into archives. 0 disables archive expansion.
    pub archive_depth: u8,
    /// Refuse to expand an archive entry that inflates beyond this (zip bomb).
    pub max_archive_entry_bytes: u64,

    /// Shortest literal accepted from a multi-part logical signature.
    ///
    /// This is the main lever on resident memory, and the numbers are
    /// measured rather than guessed. Against the real ClamAV database:
    ///
    /// | floor | logical rules | resident |
    /// |-------|---------------|----------|
    /// | 4     | 158,770       | ~520 MB  |
    /// | 8     | 48,931        | ~300 MB  |
    ///
    /// The cost is the pattern-matching automaton, which grows quickly with
    /// short patterns because they make its state graph dense. Eight is the
    /// default because short literals are the weakest signals in the set, so
    /// the first ones dropped are the ones contributing least - this is a
    /// quality threshold that happens to bound memory, not an arbitrary cap.
    ///
    /// Lower it to 4 for maximum coverage if the memory is available.
    pub min_logical_pattern_bytes: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_scan_bytes: 256 * 1024 * 1024,
            timeout_ms: 5_000,
            archive_depth: 2,
            max_archive_entry_bytes: 512 * 1024 * 1024,
            min_logical_pattern_bytes: 8,
        }
    }
}

/// Individual detection engines, each independently switchable so a noisy one
/// can be turned off without losing the rest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Engines {
    #[serde(default = "default_true")]
    pub hash: bool,
    #[serde(default = "default_true")]
    pub section_hash: bool,
    #[serde(default = "default_true")]
    pub body_pattern: bool,
    #[serde(default = "default_true")]
    pub yara: bool,
    #[serde(default = "default_true")]
    pub heuristics: bool,
}

impl Default for Engines {
    fn default() -> Self {
        Self {
            hash: true,
            section_hash: true,
            body_pattern: true,
            yara: true,
            heuristics: true,
        }
    }
}

/// Built-in heuristics. All produce `Suspicious` at most, never `Malicious`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Heuristics {
    /// Flag PE files whose entropy suggests packing or encryption.
    #[serde(default = "default_true")]
    pub high_entropy: bool,
    /// Entropy threshold, in bits per byte. 7.2 is the conventional line;
    /// legitimate installers and compressed resources routinely hit 7.0.
    pub entropy_threshold: f64,
    /// Flag a PE whose section is writable *and* executable.
    #[serde(default = "default_true")]
    pub writable_executable_section: bool,
    /// Flag a PE with no imports at all - typical of a packed dropper that
    /// resolves everything at runtime.
    #[serde(default = "default_true")]
    pub no_imports: bool,
    /// Flag an executable wearing a document extension, e.g. `invoice.pdf.exe`.
    #[serde(default = "default_true")]
    pub double_extension: bool,
    /// Flag names containing a right-to-left override, the classic trick for
    /// displaying `exe.pdf` as `fdp.exe`.
    #[serde(default = "default_true")]
    pub rtl_override: bool,
}

impl Default for Heuristics {
    fn default() -> Self {
        Self {
            high_entropy: true,
            entropy_threshold: 7.2,
            writable_executable_section: true,
            no_imports: true,
            double_extension: true,
            rtl_override: true,
        }
    }
}

/// Paths and patterns the scanner skips entirely.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Exclusions {
    /// Directory prefixes, case-insensitive. Anything beneath is skipped.
    pub paths: Vec<PathBuf>,
    /// Lowercase extensions without the dot.
    pub extensions: Vec<String>,
    /// Full paths of processes whose file I/O is ignored. Redoubt's own
    /// binaries are always excluded regardless of this list.
    pub processes: Vec<PathBuf>,
}

impl Default for Exclusions {
    fn default() -> Self {
        // Defender's own store and the update cache are the two that will
        // otherwise generate constant, useless churn.
        Self {
            paths: vec![
                PathBuf::from(r"C:\Windows\System32\LogFiles"),
                PathBuf::from(r"C:\Windows\SoftwareDistribution"),
                PathBuf::from(r"C:\ProgramData\Microsoft\Windows Defender"),
                PathBuf::from(r"C:\ProgramData\Redoubt\quarantine"),
            ],
            extensions: Vec::new(),
            processes: Vec::new(),
        }
    }
}

/// Signature update settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Updates {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Minutes between update checks. ClamAV mirrors publish several times a
    /// day; hourly is polite and plenty.
    pub interval_minutes: u64,

    /// Pull ClamAV main/daily by driving `freshclam`.
    ///
    /// ClamAV's CDN only answers to their own client, so this is the honest
    /// route - and it gets incremental `.cdiff` updates for free. Turn it off
    /// to run on third-party sources alone.
    #[serde(default = "default_true")]
    pub clamav_enabled: bool,
    /// Explicit path to `freshclam.exe`. `None` searches the usual install
    /// locations.
    pub freshclam_path: Option<PathBuf>,
    /// Mirror hostname handed to freshclam.
    pub clamav_mirror: String,

    /// ClamAV-format databases Redoubt fetches itself, from publishers that
    /// permit direct download.
    pub direct_sources: Vec<crate::update::DirectSource>,

    /// YARA rule repositories, fetched into `paths.rules`.
    pub yara_sources: Vec<crate::rulesupdate::YaraSource>,
}

impl Default for Updates {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_minutes: 60,
            clamav_enabled: true,
            freshclam_path: None,
            // freshclam wants a hostname, not a URL.
            clamav_mirror: "database.clamav.net".to_string(),
            direct_sources: crate::update::default_direct_sources(),
            yara_sources: crate::rulesupdate::default_yara_sources(),
        }
    }
}

/// `%ProgramData%\Redoubt`, falling back to a sensible literal if the
/// environment is missing the variable.
pub fn data_root() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Redoubt")
}

/// Default config file location.
pub fn default_config_path() -> PathBuf {
    data_root().join("config.toml")
}

impl Config {
    /// Load from `path`, or return defaults if it does not exist.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: Config = toml::from_str(&text)
            .with_context(|| format!("parsing config {}", path.display()))?;
        Ok(cfg)
    }

    /// Load from the default location, creating it if absent.
    pub fn load_or_init() -> Result<Self> {
        let path = default_config_path();
        if path.exists() {
            Self::load(&path)
        } else {
            let cfg = Self::default();
            cfg.save(&path)?;
            Ok(cfg)
        }
    }

    /// Write to `path`, creating parent directories as needed.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let text = toml::to_string_pretty(self).context("serialising config")?;
        std::fs::write(path, text)
            .with_context(|| format!("writing config {}", path.display()))?;
        Ok(())
    }

    /// Create every directory named in `paths`.
    pub fn ensure_dirs(&self) -> Result<()> {
        for dir in [
            &self.paths.signatures,
            &self.paths.rules,
            &self.paths.quarantine,
            &self.paths.logs,
            &self.paths.cache,
        ] {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("creating {}", dir.display()))?;
        }
        Ok(())
    }

    /// Resolved worker count.
    pub fn worker_count(&self) -> usize {
        if self.realtime.workers > 0 {
            return self.realtime.workers;
        }
        std::thread::available_parallelism()
            .map(|n| n.get().saturating_sub(1).clamp(1, 8))
            .unwrap_or(2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_observe_mode() {
        // The whole safety story rests on this. If it ever flips, a fresh
        // install starts deleting files on a machine nobody has tuned it for.
        assert_eq!(Config::default().mode, Mode::Observe);
    }

    #[test]
    fn round_trips_through_toml() {
        let cfg = Config::default();
        let text = toml::to_string_pretty(&cfg).unwrap();
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back.mode, cfg.mode);
        assert_eq!(back.scan.max_scan_bytes, cfg.scan.max_scan_bytes);
        assert_eq!(
            back.heuristics.entropy_threshold,
            cfg.heuristics.entropy_threshold
        );
    }

    #[test]
    fn partial_config_fills_in_defaults() {
        // A user hand-editing the file should not have to write every key.
        let cfg: Config = toml::from_str("mode = \"enforce\"\n").unwrap();
        assert_eq!(cfg.mode, Mode::Enforce);
        assert!(cfg.engines.yara);
        assert_eq!(cfg.scan.timeout_ms, 5_000);
    }

    #[test]
    fn destructive_ransomware_response_is_off_by_default() {
        // Terminating a process on an inference is the most destructive thing
        // Redoubt can do. It must never be on unless deliberately chosen.
        let r = Ransomware::default();
        assert!(r.enabled, "detection itself should be on");
        assert!(!r.terminate_on_critical, "killing processes must be opt-in");
    }

    #[test]
    fn worker_count_is_bounded() {
        let mut cfg = Config::default();
        cfg.realtime.workers = 0;
        let n = cfg.worker_count();
        assert!((1..=8).contains(&n), "unexpected worker count {n}");
    }
}
