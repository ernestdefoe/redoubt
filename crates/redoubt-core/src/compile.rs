//! Turn ClamAV signature data into a compiled [`SigIndex`].
//!
//! Two shapes of input arrive here:
//!
//! - **Containers** (`.cvd`, `.cld`) - what freshclam downloads. A header plus
//!   a tar of signature files.
//! - **Loose files** (`.ndb`, `.hdb`, ...) - what third-party sources such as
//!   Sanesecurity and abuse.ch publish directly.
//!
//! Both funnel into the same [`Compiler`], which feeds an
//! [`IndexBuilder`]. This runs in the updater, never on the scan path.

use anyhow::{Context, Result};
use std::path::Path;

use crate::sigindex::{Group, IndexBuilder, IndexStats};
use crate::sigs::{self, ParseStats, SigFileKind};

/// Minimum length for a literal body pattern to be worth indexing.
///
/// ClamAV pairs short patterns with anchors and target types this engine does
/// not implement, so a short literal that is safe there is not safe here.
/// Sixteen bytes is long enough that a chance collision is not a concern.
pub const MIN_BODY_PATTERN_LEN: usize = 16;

/// Extensions that are metadata, not signatures. Seeing these is normal and
/// they should not show up in the "unsupported" report as noise.
const METADATA_EXTENSIONS: &[&str] = &["info", "", "cfg", "cat", "txt", "md", "sha256", "sign"];

/// What a compile run did, including everything it could not use.
#[derive(Debug, Clone, Default)]
pub struct CompileReport {
    /// Inputs consumed, as `(name, version)`. Loose files report version 0.
    pub sources: Vec<(String, u32)>,
    pub index: IndexStats,
    pub hashes: ParseStats,
    pub sections: ParseStats,
    pub allowlist: ParseStats,
    pub body: ParseStats,
    /// Hash signatures refused because they match a zero-length file.
    pub degenerate_rejected: u64,
    /// Signature files whose format this engine does not handle, as
    /// `(filename, byte_length)`. Reported rather than ignored so coverage
    /// claims stay honest.
    pub skipped_files: Vec<(String, usize)>,
}

impl CompileReport {
    /// Signatures actually loaded into the index.
    pub fn accepted(&self) -> u64 {
        self.index.total()
    }

    /// Well-formed signatures understood but not evaluatable by this engine.
    pub fn unsupported(&self) -> u64 {
        self.hashes.unsupported
            + self.sections.unsupported
            + self.allowlist.unsupported
            + self.body.unsupported
    }

    /// Lines that could not be parsed at all.
    pub fn malformed(&self) -> u64 {
        self.hashes.malformed
            + self.sections.malformed
            + self.allowlist.malformed
            + self.body.malformed
    }

    /// Fraction of parsed signature lines that made it into the index.
    pub fn coverage(&self) -> f64 {
        let seen = self.hashes.total_seen()
            + self.sections.total_seen()
            + self.allowlist.total_seen()
            + self.body.total_seen();
        if seen == 0 {
            return 0.0;
        }
        let accepted = self.hashes.accepted
            + self.sections.accepted
            + self.allowlist.accepted
            + self.body.accepted;
        accepted as f64 / seen as f64
    }

    /// Unhandled signature files rolled up by format, largest first.
    ///
    /// Listing them individually is useless: a single freshclam run drops well
    /// over a hundred `.cbc` bytecode files. What matters is *which formats*
    /// are missing and how much signature data sits behind each.
    pub fn skipped_by_format(&self) -> Vec<SkippedFormat> {
        let mut by_ext: std::collections::HashMap<String, (usize, usize)> =
            std::collections::HashMap::new();
        for (name, len) in &self.skipped_files {
            let ext = name.rsplit_once('.').map(|(_, e)| e).unwrap_or("(none)").to_lowercase();
            let slot = by_ext.entry(ext).or_insert((0, 0));
            slot.0 += 1;
            slot.1 += len;
        }
        let mut out: Vec<SkippedFormat> = by_ext
            .into_iter()
            .map(|(extension, (files, bytes))| SkippedFormat {
                note: format_note(&extension),
                extension,
                files,
                bytes,
            })
            .collect();
        out.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        out
    }

    /// One-line summary for logs and the UI.
    pub fn summary(&self) -> String {
        format!(
            "{} signatures indexed ({} file hashes, {} section hashes, {} body patterns, \
             {} allowlisted) from {} source(s); {} unsupported, {:.1}% of parsed lines used",
            self.accepted(),
            self.index.file_hashes,
            self.index.section_hashes,
            self.index.body_patterns,
            self.index.allowlisted,
            self.sources.len(),
            self.unsupported(),
            self.coverage() * 100.0,
        )
    }
}

/// One unhandled signature format, rolled up across every file using it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedFormat {
    pub extension: String,
    pub files: usize,
    pub bytes: usize,
    /// What the format is and whether supporting it is on the table.
    pub note: &'static str,
}

/// Plain-English explanation for each format we do not consume, so the gap
/// report says *what is missing* rather than just naming an extension.
fn format_note(extension: &str) -> &'static str {
    match extension {
        "ldb" | "ldu" => "logical signatures - multi-pattern boolean rules; the largest gap",
        "cbc" => "ClamAV bytecode - requires their VM; out of scope",
        "cdb" => "container metadata rules (archive/attachment properties)",
        "ftm" => "file type magic definitions",
        "idb" => "icon similarity signatures",
        "pdb" | "wdb" => "phishing URL rules (email-oriented)",
        "crb" => "certificate trust/revocation rules",
        "ign" | "ign2" => "signature suppression lists",
        "yara" | "yar" => "YARA rules - handled by the YARA engine, not this index",
        _ => "unrecognised signature format",
    }
}

/// Accumulates signatures from any number of inputs, then writes the index.
pub struct Compiler {
    builder: IndexBuilder,
    report: CompileReport,
    db_version: u32,
    built_epoch: u64,
}

impl Default for Compiler {
    fn default() -> Self {
        Self::new()
    }
}

impl Compiler {
    pub fn new() -> Self {
        Self {
            builder: IndexBuilder::new(0, 0),
            report: CompileReport::default(),
            db_version: 0,
            built_epoch: 0,
        }
    }

    /// Feed one signature file's bytes, dispatching on its extension.
    fn ingest(&mut self, name: &str, extension: &str, data: &[u8]) {
        let Some(kind) = sigs::classify(extension) else {
            if !METADATA_EXTENSIONS.contains(&extension) {
                self.report.skipped_files.push((name.to_string(), data.len()));
            }
            return;
        };

        match kind {
            SigFileKind::FileHash => {
                let b = &mut self.builder;
                let mut rejected = 0u64;
                let s = sigs::parse_hash_db(data, |sig| {
                    if sigs::is_degenerate(&sig.hash) {
                        rejected += 1;
                        return;
                    }
                    b.add_hash(sig, Group::File)
                });
                self.report.degenerate_rejected += rejected;
                self.report.hashes.merge(s);
            }
            SigFileKind::SectionHash => {
                let b = &mut self.builder;
                let mut rejected = 0u64;
                let s = sigs::parse_section_db(data, |sig| {
                    if sigs::is_degenerate(&sig.hash) {
                        rejected += 1;
                        return;
                    }
                    b.add_hash(sig, Group::Section)
                });
                self.report.degenerate_rejected += rejected;
                self.report.sections.merge(s);
            }
            SigFileKind::Allowlist => {
                let b = &mut self.builder;
                let s = sigs::parse_hash_db(data, |sig| b.add_hash(sig, Group::Allow));
                self.report.allowlist.merge(s);
            }
            SigFileKind::Body => {
                let b = &mut self.builder;
                let s = sigs::parse_body_db(data, MIN_BODY_PATTERN_LEN, |sig| b.add_body(sig));
                self.report.body.merge(s);
            }
        }
    }

    /// Add a ClamAV container (`.cvd` or `.cld`).
    pub fn add_container(&mut self, path: &Path) -> Result<()> {
        let display = file_label(path);
        let header = crate::cvd::for_each_entry(path, |entry| {
            let ext = entry.extension().to_string();
            self.ingest(&entry.name, &ext, &entry.data);
            Ok(())
        })
        .with_context(|| format!("reading container {}", path.display()))?;

        if header.version > self.db_version {
            self.db_version = header.version;
            self.built_epoch = header.build_epoch;
        }
        self.report.sources.push((display, header.version));
        Ok(())
    }

    /// Add a bare signature file such as a Sanesecurity `.ndb`.
    pub fn add_loose_file(&mut self, path: &Path) -> Result<()> {
        let display = file_label(path);
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let data = std::fs::read(path)
            .with_context(|| format!("reading signature file {}", path.display()))?;
        self.ingest(&display, &ext, &data);
        self.report.sources.push((display, 0));
        Ok(())
    }

    /// Sort, deduplicate and write the index.
    pub fn finish(mut self, out: &Path) -> Result<CompileReport> {
        let builder = self.builder.retag(self.db_version, self.built_epoch);
        self.report.index = builder
            .write(out)
            .with_context(|| format!("writing index {}", out.display()))?;
        Ok(self.report)
    }
}

fn file_label(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// True for a path this compiler knows how to consume.
pub fn is_signature_input(path: &Path) -> bool {
    let Some(ext) = path.extension().map(|e| e.to_string_lossy().to_lowercase()) else {
        return false;
    };
    matches!(ext.as_str(), "cvd" | "cld") || sigs::classify(&ext).is_some()
}

/// Compile every signature input found directly inside `dir`.
///
/// Containers are added first so their versions establish the index version
/// before loose third-party files (which carry no version) are folded in.
pub fn compile_dir(dir: &Path, out: &Path) -> Result<CompileReport> {
    let mut containers = Vec::new();
    let mut loose = Vec::new();

    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("listing {}", dir.display()))?
    {
        let path = entry?.path();
        if !path.is_file() || !is_signature_input(&path) {
            continue;
        }
        match path.extension().map(|e| e.to_string_lossy().to_lowercase()).as_deref() {
            Some("cvd") | Some("cld") => containers.push(path),
            _ => loose.push(path),
        }
    }

    containers.sort();
    loose.sort();

    let mut compiler = Compiler::new();
    for path in &containers {
        compiler.add_container(path)?;
    }
    for path in &loose {
        compiler.add_loose_file(path)?;
    }
    compiler.finish(out)
}

/// Compile a specific list of containers. Kept for callers that know exactly
/// what they want compiled.
pub fn compile_containers(containers: &[&Path], out: &Path) -> Result<CompileReport> {
    let mut compiler = Compiler::new();
    for path in containers {
        compiler.add_container(path)?;
    }
    compiler.finish(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    /// Build a synthetic `.cvd` in memory so the compiler is tested without a
    /// 200 MB download.
    fn synthetic_cvd(version: u32, files: &[(&str, &str)]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut ar = tar::Builder::new(&mut tar_bytes);
            for (name, body) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(body.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                ar.append_data(&mut header, name, body.as_bytes()).unwrap();
            }
            ar.finish().unwrap();
        }
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        gz.write_all(&tar_bytes).unwrap();
        let payload = gz.finish().unwrap();

        let head = format!(
            "ClamAV-VDB:23 Aug 2026 08-15 -0400:{version}:100:90:\
             a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:dsig:raynman:1756000000"
        );
        let mut out = head.into_bytes();
        out.resize(512, b' ');
        out.extend_from_slice(&payload);
        out
    }

    fn temp(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("redoubt-compile-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    const LITERAL_NDB: &str =
        "Win.Test.Literal:0:*:5245444f5542542d544553542d5041545445524e\n";

    #[test]
    fn compiles_a_synthetic_container_end_to_end() {
        let dir = temp("e2e");
        let cvd = dir.join("test.cvd");
        let idx = dir.join("test.sigidx");

        std::fs::write(
            &cvd,
            synthetic_cvd(
                27100,
                &[
                    ("test.hdb", "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature\n"),
                    ("test.mdb", "4096:5d41402abc4b2a76b9719d911017c592:Win.Packed.Sect\n"),
                    ("test.fp", "098f6bcd4621d373cade4e832627b4f6:100:Known.Good\n"),
                    (
                        "test.ndb",
                        "Win.Test.Literal:0:*:5245444f5542542d544553542d5041545445524e\n\
                         Win.Test.Wild:0:*:4d5a??00deadbeefdeadbeefdeadbeef\n",
                    ),
                    ("test.ldb", "Win.Logical;Engine:81-255,Target:1;0&1;aabb;ccdd\n"),
                    ("test.info", "ClamAV-VDB metadata\n"),
                ],
            ),
        )
        .unwrap();

        let report = compile_containers(&[&cvd], &idx).unwrap();
        assert_eq!(report.index.file_hashes, 1);
        assert_eq!(report.index.section_hashes, 1);
        assert_eq!(report.index.allowlisted, 1);
        assert_eq!(report.index.body_patterns, 1, "only the literal should index");
        assert_eq!(report.body.unsupported, 1, "the wildcard must be counted, not dropped");

        let skipped: Vec<&str> = report.skipped_files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(skipped, vec!["test.ldb"], ".info is metadata and must not be reported");

        let index = crate::sigindex::SigIndex::open(&idx).unwrap();
        assert_eq!(index.db_version(), 27100);
        let eicar = sigs::HashValue::from_hex("44d88612fea8a8f36de82e1278abb02f").unwrap();
        assert_eq!(index.lookup(&eicar, Group::File, 68), Some("Eicar-Test-Signature"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn newest_container_version_wins() {
        let dir = temp("versions");
        let main = dir.join("main.cvd");
        let daily = dir.join("daily.cvd");
        let idx = dir.join("merged.sigidx");

        std::fs::write(
            &main,
            synthetic_cvd(62, &[("main.hdb", "44d88612fea8a8f36de82e1278abb02f:68:Old.Sig\n")]),
        )
        .unwrap();
        std::fs::write(
            &daily,
            synthetic_cvd(27100, &[("daily.hdb", "098f6bcd4621d373cade4e832627b4f6:9:New.Sig\n")]),
        )
        .unwrap();

        let report = compile_containers(&[&main, &daily], &idx).unwrap();
        assert_eq!(report.index.file_hashes, 2);
        assert_eq!(report.index.db_version, 27100);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn compile_dir_mixes_containers_and_loose_files() {
        // The freshclam + third-party arrangement in miniature.
        let dir = temp("mixed");
        let idx = dir.join("out.sigidx");

        std::fs::write(
            dir.join("daily.cvd"),
            synthetic_cvd(27100, &[("daily.hdb", "44d88612fea8a8f36de82e1278abb02f:68:Clam.Sig\n")]),
        )
        .unwrap();
        // A Sanesecurity-style loose file.
        std::fs::write(dir.join("badmacro.ndb"), LITERAL_NDB).unwrap();
        // An abuse.ch-style loose hash file.
        std::fs::write(
            dir.join("urlhaus.hdb"),
            "098f6bcd4621d373cade4e832627b4f6:*:Urlhaus.Sig\n",
        )
        .unwrap();
        // Things that must be ignored entirely.
        std::fs::write(dir.join("readme.txt"), "hello").unwrap();
        std::fs::write(dir.join("freshclam.conf"), "DatabaseDirectory .\n").unwrap();

        let report = compile_dir(dir.as_path(), &idx).unwrap();
        assert_eq!(report.index.file_hashes, 2, "container + loose hdb");
        assert_eq!(report.index.body_patterns, 1, "loose ndb");
        assert_eq!(report.index.db_version, 27100, "version comes from the container");

        let names: Vec<&str> = report.sources.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["daily.cvd", "badmacro.ndb", "urlhaus.hdb"]);
        assert!(report.skipped_files.is_empty(), "{:?}", report.skipped_files);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_file_hashes_are_refused_at_index_time() {
        let dir = temp("degenerate");
        let cvd = dir.join("t.cvd");
        let idx = dir.join("t.sigidx");

        std::fs::write(
            &cvd,
            synthetic_cvd(
                1,
                &[(
                    "t.hsb",
                    // The empty-file SHA-256, then an ordinary signature.
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855:0:                     Sanesecurity.MalwareHash.HoneyPot\n                     275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:68:                     Eicar-Test-Signature\n",
                )],
            ),
        )
        .unwrap();

        let report = compile_containers(&[&cvd], &idx).unwrap();
        assert_eq!(report.degenerate_rejected, 1, "the empty-file hash must be refused");
        assert_eq!(report.index.file_hashes, 1, "the real signature must survive");

        let index = crate::sigindex::SigIndex::open(&idx).unwrap();
        let empty = sigs::HashValue::from_hex(sigs::EMPTY_SHA256).unwrap();
        assert_eq!(index.lookup(&empty, Group::File, 0), None);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn recognises_signature_inputs() {
        for good in ["a.cvd", "a.cld", "a.ndb", "a.hdb", "a.hsb", "a.mdb", "a.fp"] {
            assert!(is_signature_input(Path::new(good)), "{good} should be accepted");
        }
        for bad in ["a.txt", "a.conf", "a.exe", "a.log", "noextension"] {
            assert!(!is_signature_input(Path::new(bad)), "{bad} should be rejected");
        }
    }

    #[test]
    fn coverage_reflects_rejected_lines() {
        let dir = temp("coverage");
        let cvd = dir.join("c.cvd");
        let idx = dir.join("c.sigidx");

        std::fs::write(
            &cvd,
            synthetic_cvd(
                1,
                &[(
                    "t.ndb",
                    "A:0:*:5245444f5542542d544553542d5041545445524e\n\
                     B:0:*:4d5a??00deadbeefdeadbeefdeadbeef\n\
                     C:0:EP+4:4d5a9000deadbeefdeadbeefdeadbeef\n\
                     D:0:*:4d5a*00deadbeefdeadbeefdeadbeef\n",
                )],
            ),
        )
        .unwrap();

        let report = compile_containers(&[&cvd], &idx).unwrap();
        assert_eq!(report.body.accepted, 1);
        assert_eq!(report.body.unsupported, 3);
        assert!((report.coverage() - 0.25).abs() < 1e-9, "coverage {}", report.coverage());
        assert!(report.summary().contains("3 unsupported"), "{}", report.summary());
        std::fs::remove_dir_all(&dir).ok();
    }
}
