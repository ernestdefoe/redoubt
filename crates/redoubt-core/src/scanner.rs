//! The scan orchestrator: everything above, in the right order.
//!
//! # Ordering
//!
//! The sequence is not arbitrary. Cheap and decisive checks run first so the
//! common case - a clean file - costs as little as possible:
//!
//! 1. **Exclusions**, before the file is even opened.
//! 2. **Hashing**, one pass, all three digests.
//! 3. **Allowlist**, which short-circuits. A file ClamAV ships a `.fp` entry
//!    for is known good, and nothing after this point may override that.
//! 4. **Whole-file hash** signatures - one binary search, definitive.
//! 5. **PE section hashes**, which survive the repacking that defeats step 4.
//! 6. **Body patterns** and **YARA**, the expensive full-content passes.
//! 7. **Heuristics**, which can only ever add `Suspicious`.
//!
//! # Threading
//!
//! [`ScanEngine`] is immutable and shared. Each worker thread takes its own
//! [`ScanSession`], because a YARA scanner carries mutable per-scan state.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::bodyscan::{BodyScanner, FileKind};
use crate::config::Config;
use crate::hashing;
use crate::pe::PeInfo;
use crate::rules::{RuleScanner, RuleSet};
use crate::sigindex::{Group, SigIndex};
use crate::verdict::{Detection, Engine, FileIdentity, Verdict};

/// Cap on body-pattern matches collected per file. One pathological sample can
/// otherwise trip thousands of signatures; the first handful is all a verdict
/// needs, and the rest are just allocation.
const MAX_BODY_MATCHES: usize = 16;

/// Why a path was not scanned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    ExcludedPath(PathBuf),
    ExcludedExtension(String),
    NotAFile,
    Unreadable(String),
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkipReason::ExcludedPath(p) => write!(f, "excluded by path rule {}", p.display()),
            SkipReason::ExcludedExtension(e) => write!(f, "excluded extension .{e}"),
            SkipReason::NotAFile => write!(f, "not a regular file"),
            SkipReason::Unreadable(e) => write!(f, "unreadable: {e}"),
        }
    }
}

/// Outcome of asking the engine about a path.
#[derive(Debug, Clone)]
pub enum ScanOutcome {
    Scanned(Box<Verdict>),
    Skipped(SkipReason),
}

/// What is loaded, for the UI and for `redoubt db status`.
#[derive(Debug, Clone, Copy, Default)]
pub struct EngineStats {
    pub db_version: u32,
    /// When the newest source database was built, as a Unix timestamp.
    pub built_epoch: u64,
    pub file_hashes: u64,
    pub section_hashes: u64,
    pub allowlisted: u64,
    pub body_patterns: usize,
    pub yara_rules: usize,
}

/// Immutable, shareable scanning engine.
pub struct ScanEngine {
    index: SigIndex,
    body: BodyScanner,
    rules: RuleSet,
    cfg: Config,
}

impl ScanEngine {
    /// Load the compiled index and rule set described by `cfg`.
    pub fn load(cfg: Config) -> Result<Self> {
        let index_path = cfg.paths.signatures.join("redoubt.sigidx");
        let index = SigIndex::open(&index_path).with_context(|| {
            format!(
                "opening signature index {} - run `redoubt db update` to build one",
                index_path.display()
            )
        })?;

        let body = if cfg.engines.body_pattern {
            BodyScanner::build(&index)?
        } else {
            BodyScanner::from_patterns(Vec::new())?
        };

        let rules = if cfg.engines.yara {
            RuleSet::compile_dir(&cfg.paths.rules)?
        } else {
            RuleSet::empty()?
        };

        Ok(Self { index, body, rules, cfg })
    }

    pub fn stats(&self) -> EngineStats {
        let s = self.index.stats();
        EngineStats {
            db_version: self.index.db_version(),
            built_epoch: self.index.built_epoch(),
            file_hashes: s.file_hashes,
            section_hashes: s.section_hashes,
            allowlisted: s.allowlisted,
            body_patterns: self.body.pattern_count(),
            yara_rules: self.rules.rule_count(),
        }
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    /// Take a scanning session. One per thread.
    pub fn session(&self) -> ScanSession<'_> {
        ScanSession {
            engine: self,
            yara: self
                .cfg
                .engines
                .yara
                .then(|| self.rules.scanner(Duration::from_millis(self.cfg.scan.timeout_ms))),
        }
    }

    /// Whether `path` is excluded by configuration.
    fn exclusion_for(&self, path: &Path) -> Option<SkipReason> {
        let lower = path.to_string_lossy().to_lowercase();
        for prefix in &self.cfg.exclusions.paths {
            if lower.starts_with(&prefix.to_string_lossy().to_lowercase()) {
                return Some(SkipReason::ExcludedPath(prefix.clone()));
            }
        }
        if let Some(ext) = path.extension() {
            let ext = ext.to_string_lossy().to_lowercase();
            if self.cfg.exclusions.extensions.iter().any(|e| e.to_lowercase() == ext) {
                return Some(SkipReason::ExcludedExtension(ext));
            }
        }
        None
    }
}

/// A per-thread scanning session.
pub struct ScanSession<'a> {
    engine: &'a ScanEngine,
    yara: Option<RuleScanner<'a>>,
}

impl ScanSession<'_> {
    /// Scan a file on disk.
    pub fn scan_path(&mut self, path: &Path) -> ScanOutcome {
        if let Some(reason) = self.engine.exclusion_for(path) {
            return ScanOutcome::Skipped(reason);
        }

        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => return ScanOutcome::Skipped(SkipReason::Unreadable(e.to_string())),
        };
        if !meta.is_file() {
            return ScanOutcome::Skipped(SkipReason::NotAFile);
        }

        let started = Instant::now();
        let size = meta.len();
        let cfg = &self.engine.cfg;

        // Under the limit: read once and use the same buffer for hashing and
        // every content pass. Over it: stream-hash only, so a disk image is
        // never buffered.
        if size <= cfg.scan.max_scan_bytes {
            match std::fs::read(path) {
                Ok(data) => {
                    let mut v = self.scan_bytes(path, &data);
                    v.scan_micros = started.elapsed().as_micros() as u64;
                    ScanOutcome::Scanned(Box::new(v))
                }
                Err(e) => ScanOutcome::Skipped(SkipReason::Unreadable(e.to_string())),
            }
        } else {
            match std::fs::File::open(path)
                .and_then(|f| hashing::digest_reader(std::io::BufReader::new(f)))
            {
                Ok((digests, actual_size)) => {
                    let mut v = self.hash_only_verdict(path, digests, actual_size);
                    v.scan_micros = started.elapsed().as_micros() as u64;
                    ScanOutcome::Scanned(Box::new(v))
                }
                Err(e) => ScanOutcome::Skipped(SkipReason::Unreadable(e.to_string())),
            }
        }
    }

    /// Scan an in-memory buffer. `path` is used for name-based heuristics and
    /// for reporting only; it need not exist on disk.
    pub fn scan_bytes(&mut self, path: &Path, data: &[u8]) -> Verdict {
        let started = Instant::now();
        let cfg = &self.engine.cfg;
        let index = &self.engine.index;
        let size = data.len() as u64;

        let digests = hashing::digest_bytes(data);
        let identity = digests.to_identity(size);
        let mut verdict = Verdict::clean(path.to_path_buf(), identity, 0);

        // An empty file has no content and cannot be malware. Signature
        // databases nonetheless contain the empty-file digest, so this is a
        // hard guard rather than an optimisation - without it every zero-byte
        // file on the system becomes a detection.
        if data.is_empty() {
            verdict.scan_micros = started.elapsed().as_micros() as u64;
            return verdict;
        }

        // --- 1. Allowlist. Decisive; nothing after this may override it. ---
        for hash in digests.all() {
            if let Some(name) = index.is_allowlisted(&hash, size) {
                verdict.allowlisted_as = Some(name.to_string());
                verdict.scan_micros = started.elapsed().as_micros() as u64;
                return verdict;
            }
        }

        // --- 2. Whole-file hash signatures ---
        if cfg.engines.hash {
            for hash in digests.all() {
                if let Some(name) = index.lookup(&hash, Group::File, size) {
                    let severity = crate::sigs::implied_severity(name);
                    verdict.detections.push(
                        Detection::new(name, Engine::Hash, severity)
                            .with_detail(format!("{} {}", hash.kind_str(), hash)),
                    );
                    break; // one whole-file hash hit is enough
                }
            }
        }

        let pe = PeInfo::parse(data);

        // --- 3. PE section hashes ---
        if cfg.engines.section_hash {
            if let Some(pe) = &pe {
                'sections: for (sec_size, md5, sha256) in pe.section_hashes(data) {
                    for hash in [sha256, md5] {
                        if let Some(name) = index.lookup(&hash, Group::Section, sec_size) {
                            let severity = crate::sigs::implied_severity(name);
                            verdict.detections.push(
                                Detection::new(name, Engine::SectionHash, severity)
                                    .with_detail(format!("section of {sec_size} bytes")),
                            );
                            break 'sections;
                        }
                    }
                }
            }
        }

        // --- 4. Body patterns ---
        if cfg.engines.body_pattern && !self.engine.body.is_empty() {
            let kind = FileKind::sniff(data);
            for m in self.engine.body.scan(data, kind, MAX_BODY_MATCHES) {
                let severity = crate::sigs::implied_severity(&m.name);
                verdict.detections.push(
                    Detection::new(m.name, Engine::BodyPattern, severity)
                        .with_detail(format!("matched at offset {}", m.offset)),
                );
            }
        }

        // --- 5. YARA ---
        if let Some(yara) = self.yara.as_mut() {
            match yara.scan(data) {
                Ok(hits) => verdict.detections.extend(hits.iter().map(|h| h.to_detection())),
                Err(e) => {
                    // A YARA failure (usually a timeout) must not turn into a
                    // clean verdict by silence.
                    tracing::warn!(path = %path.display(), error = %e, "YARA scan failed");
                }
            }
        }

        // --- 6. Heuristics ---
        if cfg.engines.heuristics {
            verdict
                .detections
                .extend(crate::heuristics::evaluate(path, pe.as_ref(), &cfg.heuristics));
        }

        verdict.recompute_severity();
        verdict.scan_micros = started.elapsed().as_micros() as u64;
        verdict
    }

    /// Verdict for a file too large to pattern-scan: hashes only.
    fn hash_only_verdict(
        &self,
        path: &Path,
        digests: hashing::Digests,
        size: u64,
    ) -> Verdict {
        if size == 0 {
            return Verdict::clean(path.to_path_buf(), digests.to_identity(0), 0);
        }
        let index = &self.engine.index;
        let identity = digests.to_identity(size);
        let mut verdict = Verdict::clean(path.to_path_buf(), identity, 0);

        for hash in digests.all() {
            if let Some(name) = index.is_allowlisted(&hash, size) {
                verdict.allowlisted_as = Some(name.to_string());
                return verdict;
            }
        }
        if self.engine.cfg.engines.hash {
            for hash in digests.all() {
                if let Some(name) = index.lookup(&hash, Group::File, size) {
                    let severity = crate::sigs::implied_severity(name);
                    verdict.detections.push(
                        Detection::new(name, Engine::Hash, severity)
                            .with_detail(format!("{} {} (hash-only: file exceeds scan limit)",
                                hash.kind_str(), hash)),
                    );
                    break;
                }
            }
        }
        verdict.recompute_severity();
        verdict
    }
}

/// A synthetic identity, for tests and for callers that already have digests.
pub fn identity_of(data: &[u8]) -> FileIdentity {
    hashing::digest_bytes(data).to_identity(data.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigindex::IndexBuilder;
    use crate::verdict::Severity;
    use crate::sigs::{HashSig, HashValue, Offset};

    const EICAR: &[u8] =
        br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;
    const BODY_MARKER: &[u8] = b"REDOUBT-BODY-PATTERN-MARKER";

    /// Stand-in for EICAR in tests that touch the disk.
    ///
    /// The real EICAR string cannot be written to a temp file on a machine
    /// with a working resident AV - Defender quarantines it between the write
    /// and the read, and the test fails with "the file contains a virus"
    /// rather than anything to do with Redoubt. In-memory tests still use
    /// real EICAR; only disk-backed ones use this.
    const DISK_SAMPLE: &[u8] = b"REDOUBT-SYNTHETIC-DISK-SAMPLE-not-real-malware";

    struct Fixture {
        dir: PathBuf,
        engine: ScanEngine,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    /// Build a self-contained engine over a small synthetic index.
    fn fixture(tag: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("redoubt-scan-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("signatures")).unwrap();
        std::fs::create_dir_all(dir.join("rules")).unwrap();

        let mut b = IndexBuilder::new(1234, 1_756_000_000);
        // EICAR by its real MD5.
        b.add_hash(
            HashSig {
                hash: HashValue::from_hex("44d88612fea8a8f36de82e1278abb02f").unwrap(),
                size: Some(68),
                name: "Redoubt.Test.Eicar".into(),
            },
            Group::File,
        );
        // A known-good file, to prove the allowlist short-circuits.
        let good = b"this file is explicitly known to be safe";
        b.add_hash(
            HashSig {
                hash: hashing::digest_bytes(good).md5_value(),
                size: Some(good.len() as u64),
                name: "Redoubt.Test.KnownGood".into(),
            },
            Group::Allow,
        );
        // ...and the same file flagged as malicious, so allowlist precedence
        // is actually exercised rather than assumed.
        b.add_hash(
            HashSig {
                hash: hashing::digest_bytes(good).sha256_value(),
                size: Some(good.len() as u64),
                name: "Redoubt.Test.ShouldBeSuppressed".into(),
            },
            Group::File,
        );
        // The on-disk stand-in, matched by hash like EICAR is.
        b.add_hash(
            HashSig {
                hash: hashing::digest_bytes(DISK_SAMPLE).sha256_value(),
                size: Some(DISK_SAMPLE.len() as u64),
                name: "Redoubt.Test.DiskSample".into(),
            },
            Group::File,
        );
        // The empty-file SHA-256, exactly as Sanesecurity ships it. The
        // compiler normally refuses this, but adding it directly proves the
        // scanner-side guard holds independently.
        b.add_hash(
            HashSig {
                hash: HashValue::from_hex(crate::sigs::EMPTY_SHA256).unwrap(),
                size: Some(0),
                name: "Sanesecurity.MalwareHash.HoneyPot".into(),
            },
            Group::File,
        );
        // A PUA-namespaced packer signature.
        b.add_body(crate::sigs::BodySig {
            name: "PUA.Win.Packer.Testpack-1".into(),
            target: 0,
            offset: Offset::Any,
            pattern: b"REDOUBT-PACKER-STUB-MARKER".to_vec(),
        });
        b.add_body(crate::sigs::BodySig {
            name: "Redoubt.Test.BodyMarker".into(),
            target: 0,
            offset: Offset::Any,
            pattern: BODY_MARKER.to_vec(),
        });
        b.write(&dir.join("signatures/redoubt.sigidx")).unwrap();

        std::fs::write(
            dir.join("rules/test.yar"),
            r#"rule Redoubt_Test_Yara {
                 meta:
                   description = "yara marker"
                 strings:
                   $a = "REDOUBT-YARA-MARKER"
                 condition:
                   $a
               }"#,
        )
        .unwrap();

        let mut cfg = Config::default();
        cfg.paths.signatures = dir.join("signatures");
        cfg.paths.rules = dir.join("rules");
        cfg.exclusions.paths = vec![dir.join("excluded")];
        cfg.exclusions.extensions = vec!["log".into()];

        let engine = ScanEngine::load(cfg).unwrap();
        Fixture { dir, engine }
    }

    #[test]
    fn detects_eicar_by_hash() {
        let f = fixture("eicar");
        let mut s = f.engine.session();
        let v = s.scan_bytes(Path::new("eicar.com"), EICAR);

        assert_eq!(v.severity, Severity::Malicious);
        assert_eq!(v.primary_name(), Some("Redoubt.Test.Eicar"));
        assert_eq!(v.detections[0].engine, Engine::Hash);
        assert_eq!(v.identity.size, 68);
    }

    #[test]
    fn clean_data_is_clean() {
        let f = fixture("clean");
        let mut s = f.engine.session();
        let v = s.scan_bytes(Path::new("notes.txt"), b"perfectly ordinary file contents");

        assert!(v.is_clean(), "{:?}", v.detections);
        assert_eq!(v.severity, Severity::Clean);
        assert!(v.primary_name().is_none());
    }

    #[test]
    fn allowlist_suppresses_a_malicious_hash() {
        // The precedence rule: a .fp entry wins over a detection signature for
        // the same bytes. Without this, a vendor false positive is unfixable.
        let f = fixture("allow");
        let mut s = f.engine.session();
        let v = s.scan_bytes(
            Path::new("safe.bin"),
            b"this file is explicitly known to be safe",
        );

        assert!(v.is_clean(), "allowlisted file reported detections: {:?}", v.detections);
        assert_eq!(v.allowlisted_as.as_deref(), Some("Redoubt.Test.KnownGood"));
        assert!(v.detections.is_empty());
    }

    #[test]
    fn detects_a_body_pattern() {
        let f = fixture("body");
        let mut s = f.engine.session();
        let mut data = vec![b'.'; 500];
        data.extend_from_slice(BODY_MARKER);
        let v = s.scan_bytes(Path::new("sample.bin"), &data);

        assert_eq!(v.severity, Severity::Malicious);
        let d = v.detections.iter().find(|d| d.engine == Engine::BodyPattern).unwrap();
        assert_eq!(d.name, "Redoubt.Test.BodyMarker");
        assert!(d.detail.as_ref().unwrap().contains("offset 500"));
    }

    #[test]
    fn detects_a_yara_rule() {
        let f = fixture("yara");
        assert_eq!(f.engine.stats().yara_rules, 1);

        let mut s = f.engine.session();
        let v = s.scan_bytes(Path::new("sample.bin"), b"xx REDOUBT-YARA-MARKER xx");

        let d = v.detections.iter().find(|d| d.engine == Engine::Yara).unwrap();
        assert_eq!(d.name, "Redoubt_Test_Yara");
        assert_eq!(v.severity, Severity::Malicious);
    }

    #[test]
    fn heuristics_alone_only_reach_suspicious() {
        let f = fixture("heuristic");
        let mut s = f.engine.session();
        // Clean content, but a filename that lies about what it is.
        let v = s.scan_bytes(Path::new("invoice.pdf.exe"), b"harmless content");

        assert_eq!(v.severity, Severity::Suspicious);
        assert!(!v.severity.is_actionable(), "a heuristic must never be enforceable");
        assert!(v.detections.iter().all(|d| d.engine == Engine::Heuristic));
    }

    #[test]
    fn several_engines_can_fire_on_one_file() {
        let f = fixture("multi");
        let mut s = f.engine.session();
        let mut data = Vec::new();
        data.extend_from_slice(BODY_MARKER);
        data.extend_from_slice(b" and REDOUBT-YARA-MARKER too");

        let v = s.scan_bytes(Path::new("invoice.pdf.exe"), &data);
        let engines: std::collections::HashSet<_> =
            v.detections.iter().map(|d| d.engine).collect();

        assert!(engines.contains(&Engine::BodyPattern));
        assert!(engines.contains(&Engine::Yara));
        assert!(engines.contains(&Engine::Heuristic));
        assert_eq!(v.severity, Severity::Malicious, "the worst detection should win");
        // The single displayed name must not be the heuristic.
        assert_ne!(v.primary_name(), Some("Heuristic.Filename.DoubleExtension"));
    }

    #[test]
    fn scans_a_real_file_from_disk() {
        let f = fixture("ondisk");
        let path = f.dir.join("sample.bin");
        std::fs::write(&path, DISK_SAMPLE).unwrap();

        let mut s = f.engine.session();
        match s.scan_path(&path) {
            ScanOutcome::Scanned(v) => {
                assert_eq!(v.severity, Severity::Malicious);
                assert_eq!(v.primary_name(), Some("Redoubt.Test.DiskSample"));
                assert!(v.scan_micros > 0, "timing should be recorded");
            }
            other => panic!("expected a scan, got {other:?}"),
        }
    }

    #[test]
    fn honours_path_and_extension_exclusions() {
        let f = fixture("excl");

        let excluded_dir = f.dir.join("excluded");
        std::fs::create_dir_all(&excluded_dir).unwrap();
        let in_excluded = excluded_dir.join("sample.bin");
        std::fs::write(&in_excluded, DISK_SAMPLE).unwrap();

        let log = f.dir.join("sample.log");
        std::fs::write(&log, DISK_SAMPLE).unwrap();

        let mut s = f.engine.session();
        assert!(
            matches!(s.scan_path(&in_excluded), ScanOutcome::Skipped(SkipReason::ExcludedPath(_))),
            "excluded directory was scanned anyway"
        );
        assert!(matches!(
            s.scan_path(&log),
            ScanOutcome::Skipped(SkipReason::ExcludedExtension(_))
        ));
    }

    #[test]
    fn a_missing_file_is_skipped_not_an_error() {
        let f = fixture("missing");
        let mut s = f.engine.session();
        assert!(matches!(
            s.scan_path(&f.dir.join("no-such-file")),
            ScanOutcome::Skipped(SkipReason::Unreadable(_))
        ));
    }

    #[test]
    fn a_directory_is_skipped() {
        let f = fixture("dir");
        let mut s = f.engine.session();
        assert!(matches!(
            s.scan_path(&f.dir.join("rules")),
            ScanOutcome::Skipped(SkipReason::NotAFile)
        ));
    }

    #[test]
    fn oversized_files_still_get_a_hash_verdict() {
        let f = fixture("oversize");
        // Rebuild the engine with a tiny scan limit so a small file counts as
        // oversized without writing hundreds of megabytes to a temp dir.
        let mut cfg = f.engine.config().clone();
        cfg.scan.max_scan_bytes = 8;
        let engine = ScanEngine::load(cfg).unwrap();

        let path = f.dir.join("big-sample.bin");
        std::fs::write(&path, DISK_SAMPLE).unwrap();

        let mut s = engine.session();
        match s.scan_path(&path) {
            ScanOutcome::Scanned(v) => {
                assert_eq!(v.severity, Severity::Malicious, "hash must still be checked");
                assert!(v.detections[0].detail.as_ref().unwrap().contains("hash-only"));
            }
            other => panic!("expected a scan, got {other:?}"),
        }
    }

    #[test]
    fn empty_files_do_not_panic() {
        let f = fixture("empty");
        let mut s = f.engine.session();
        let v = s.scan_bytes(Path::new("empty.bin"), b"");
        assert!(v.is_clean());
        assert_eq!(v.identity.size, 0);
    }

    #[test]
    fn an_empty_file_never_matches_even_a_matching_signature() {
        // The single worst false positive class found on a real System32
        // sweep: 20 zero-byte files reported as malware.
        let f = fixture("emptyfp");
        let mut s = f.engine.session();
        let v = s.scan_bytes(Path::new("DEL988D.tmp"), b"");

        assert!(v.is_clean(), "an empty file was reported as {:?}", v.detections);
        assert!(v.detections.is_empty());
    }

    #[test]
    fn an_empty_file_on_disk_is_clean_too() {
        let f = fixture("emptydisk");
        let path = f.dir.join("empty.tmp");
        std::fs::write(&path, b"").unwrap();

        let mut s = f.engine.session();
        match s.scan_path(&path) {
            ScanOutcome::Scanned(v) => assert!(v.is_clean(), "{:?}", v.detections),
            other => panic!("expected a scan, got {other:?}"),
        }
    }

    #[test]
    fn pua_signatures_do_not_reach_malicious() {
        // Windows' own MRT.exe trips packer signatures. If those read as
        // malicious, a stock install looks infected.
        let f = fixture("pua");
        let mut s = f.engine.session();
        let mut data = vec![b'.'; 100];
        data.extend_from_slice(b"REDOUBT-PACKER-STUB-MARKER");

        let v = s.scan_bytes(Path::new("packed.exe"), &data);
        assert_eq!(v.severity, Severity::Suspicious);
        assert!(!v.severity.is_actionable(), "a packer must never be auto-quarantined");
        assert_eq!(v.detections[0].name, "PUA.Win.Packer.Testpack-1");
    }

    #[test]
    fn engine_stats_report_what_is_loaded() {
        let f = fixture("stats");
        let st = f.engine.stats();
        assert_eq!(st.db_version, 1234);
        assert_eq!(st.file_hashes, 4);
        assert_eq!(st.allowlisted, 1);
        assert_eq!(st.body_patterns, 2);
        assert_eq!(st.yara_rules, 1);
    }
}
