//! Multi-pattern body scanning.
//!
//! The index holds tens of thousands of literal byte patterns. Testing each
//! one separately would be hopeless, so they are compiled into a single
//! Aho-Corasick automaton that finds all of them in one pass over the file.
//!
//! Two filters run *after* a raw match, because the automaton itself knows
//! nothing about them:
//!
//! - **Target type.** A pattern declared for PE files must not fire on a text
//!   file that happens to contain the same bytes.
//! - **Offset.** A pattern anchored to an absolute offset must have matched
//!   *there*, not merely somewhere.

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use anyhow::{Context, Result};

use crate::sigindex::SigIndex;
use crate::sigs::Offset;

/// ClamAV target types this engine understands.
///
/// The full list is longer; anything not named here is treated as `Any`, which
/// is the conservative choice (it can only cost extra checks, never miss).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Any,
    PortableExecutable,
    OleDocument,
    Html,
    Mail,
    Graphics,
    Elf,
    AsciiText,
    Other(u8),
}

impl Target {
    pub fn from_clamav(code: u8) -> Self {
        match code {
            0 => Target::Any,
            1 => Target::PortableExecutable,
            2 => Target::OleDocument,
            3 => Target::Html,
            4 => Target::Mail,
            5 => Target::Graphics,
            6 => Target::Elf,
            7 => Target::AsciiText,
            other => Target::Other(other),
        }
    }
}

/// What the scanner knows about the file being examined, used to decide which
/// targeted patterns are eligible.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileKind {
    pub is_pe: bool,
    pub is_elf: bool,
}

impl FileKind {
    /// Classify from the leading bytes.
    pub fn sniff(data: &[u8]) -> Self {
        Self {
            is_pe: data.len() >= 2 && &data[..2] == b"MZ",
            is_elf: data.len() >= 4 && &data[..4] == b"\x7fELF",
        }
    }

    /// Whether a pattern declared for `target` may fire on this file.
    fn accepts(&self, target: Target) -> bool {
        match target {
            Target::Any => true,
            Target::PortableExecutable => self.is_pe,
            Target::Elf => self.is_elf,
            // Types we do not sniff for are allowed through rather than
            // silently suppressed - a false positive is recoverable, a
            // signature that can never fire is invisible.
            _ => true,
        }
    }
}

/// Per-pattern metadata, parallel to the automaton's pattern ids.
struct PatternMeta {
    name: String,
    target: Target,
    offset: Offset,
    len: usize,
}

/// A compiled set of literal body signatures.
pub struct BodyScanner {
    automaton: AhoCorasick,
    meta: Vec<PatternMeta>,
}

/// One confirmed body-pattern hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyMatch {
    pub name: String,
    pub offset: usize,
}

impl BodyScanner {
    /// Compile every literal pattern in `index` into one automaton.
    ///
    /// `ContiguousNFA` is chosen deliberately: a full DFA over tens of
    /// thousands of patterns would cost hundreds of megabytes to gain a small
    /// constant factor, which is the wrong trade for a resident service.
    pub fn build(index: &SigIndex) -> Result<Self> {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut meta: Vec<PatternMeta> = Vec::new();

        for p in index.body_patterns() {
            patterns.push(p.pattern.to_vec());
            meta.push(PatternMeta {
                name: p.name.to_string(),
                target: Target::from_clamav(p.target),
                offset: p.offset,
                len: p.pattern.len(),
            });
        }

        let automaton = AhoCorasick::builder()
            .kind(Some(AhoCorasickKind::ContiguousNFA))
            .match_kind(MatchKind::Standard)
            .build(&patterns)
            .context("compiling body-pattern automaton")?;

        Ok(Self { automaton, meta })
    }

    /// Build from an explicit pattern list. Used by tests and by any future
    /// rule source that is not the compiled index.
    pub fn from_patterns(
        patterns: Vec<(String, u8, Offset, Vec<u8>)>,
    ) -> Result<Self> {
        let mut raw = Vec::with_capacity(patterns.len());
        let mut meta = Vec::with_capacity(patterns.len());
        for (name, target, offset, pattern) in patterns {
            meta.push(PatternMeta {
                name,
                target: Target::from_clamav(target),
                offset,
                len: pattern.len(),
            });
            raw.push(pattern);
        }
        let automaton = AhoCorasick::builder()
            .kind(Some(AhoCorasickKind::ContiguousNFA))
            .match_kind(MatchKind::Standard)
            .build(&raw)
            .context("compiling body-pattern automaton")?;
        Ok(Self { automaton, meta })
    }

    pub fn pattern_count(&self) -> usize {
        self.meta.len()
    }

    pub fn is_empty(&self) -> bool {
        self.meta.is_empty()
    }

    /// Scan `data`, returning every eligible match.
    ///
    /// `limit` caps how many matches are collected. One pathological file can
    /// otherwise trip thousands of signatures and turn a scan into an
    /// allocation storm; the first few are all a verdict needs.
    pub fn scan(&self, data: &[u8], kind: FileKind, limit: usize) -> Vec<BodyMatch> {
        if self.meta.is_empty() || data.is_empty() || limit == 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        for m in self.automaton.find_iter(data) {
            let meta = &self.meta[m.pattern().as_usize()];

            if !kind.accepts(meta.target) {
                continue;
            }
            if let Offset::Absolute(want) = meta.offset {
                if m.start() as u64 != want {
                    continue;
                }
            }
            debug_assert_eq!(m.end() - m.start(), meta.len);

            out.push(BodyMatch { name: meta.name.clone(), offset: m.start() });
            if out.len() >= limit {
                break;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAT_A: &[u8] = b"REDOUBT-PATTERN-ALPHA";
    const PAT_B: &[u8] = b"REDOUBT-PATTERN-BRAVO";

    fn scanner(specs: &[(&str, u8, Offset, &[u8])]) -> BodyScanner {
        BodyScanner::from_patterns(
            specs
                .iter()
                .map(|(n, t, o, p)| (n.to_string(), *t, *o, p.to_vec()))
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn finds_a_literal_anywhere() {
        let s = scanner(&[("Sig.Alpha", 0, Offset::Any, PAT_A)]);
        let mut data = vec![b'.'; 5000];
        data[3000..3000 + PAT_A.len()].copy_from_slice(PAT_A);

        let hits = s.scan(&data, FileKind::default(), 16);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "Sig.Alpha");
        assert_eq!(hits[0].offset, 3000);
    }

    #[test]
    fn finds_several_distinct_patterns_in_one_pass() {
        let s = scanner(&[
            ("Sig.Alpha", 0, Offset::Any, PAT_A),
            ("Sig.Bravo", 0, Offset::Any, PAT_B),
        ]);
        let mut data = Vec::new();
        data.extend_from_slice(PAT_A);
        data.extend_from_slice(b"..........");
        data.extend_from_slice(PAT_B);

        let hits = s.scan(&data, FileKind::default(), 16);
        let names: Vec<&str> = hits.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, vec!["Sig.Alpha", "Sig.Bravo"]);
    }

    #[test]
    fn clean_data_produces_no_hits() {
        let s = scanner(&[("Sig.Alpha", 0, Offset::Any, PAT_A)]);
        assert!(s.scan(b"nothing interesting here at all", FileKind::default(), 16).is_empty());
        assert!(s.scan(b"", FileKind::default(), 16).is_empty());
    }

    #[test]
    fn absolute_offset_must_match_exactly() {
        let s = scanner(&[("Sig.AtTen", 0, Offset::Absolute(10), PAT_A)]);

        let mut right = vec![b'.'; 10];
        right.extend_from_slice(PAT_A);
        assert_eq!(s.scan(&right, FileKind::default(), 16).len(), 1);

        // Same bytes, wrong place - must not fire.
        let mut wrong = vec![b'.'; 11];
        wrong.extend_from_slice(PAT_A);
        assert!(s.scan(&wrong, FileKind::default(), 16).is_empty());
    }

    #[test]
    fn pe_targeted_patterns_do_not_fire_on_non_pe_files() {
        let s = scanner(&[("Sig.PeOnly", 1, Offset::Any, PAT_A)]);

        // A text file containing the same bytes must be left alone.
        let mut text = b"just a text file: ".to_vec();
        text.extend_from_slice(PAT_A);
        assert!(
            s.scan(&text, FileKind::sniff(&text), 16).is_empty(),
            "a PE signature fired on a text file"
        );

        // The same bytes inside something that looks like a PE should hit.
        let mut pe = b"MZ".to_vec();
        pe.extend_from_slice(PAT_A);
        assert_eq!(s.scan(&pe, FileKind::sniff(&pe), 16).len(), 1);
    }

    #[test]
    fn elf_targeted_patterns_respect_the_elf_magic() {
        let s = scanner(&[("Sig.ElfOnly", 6, Offset::Any, PAT_A)]);

        let mut elf = b"\x7fELF".to_vec();
        elf.extend_from_slice(PAT_A);
        assert_eq!(s.scan(&elf, FileKind::sniff(&elf), 16).len(), 1);

        let mut pe = b"MZ".to_vec();
        pe.extend_from_slice(PAT_A);
        assert!(s.scan(&pe, FileKind::sniff(&pe), 16).is_empty());
    }

    #[test]
    fn target_any_fires_on_everything() {
        let s = scanner(&[("Sig.Any", 0, Offset::Any, PAT_A)]);
        for prefix in [&b"MZ"[..], &b"\x7fELF"[..], &b"plain"[..]] {
            let mut data = prefix.to_vec();
            data.extend_from_slice(PAT_A);
            assert_eq!(
                s.scan(&data, FileKind::sniff(&data), 16).len(),
                1,
                "target 0 should match regardless of file type"
            );
        }
    }

    #[test]
    fn match_limit_is_respected() {
        let s = scanner(&[("Sig.Alpha", 0, Offset::Any, PAT_A)]);
        let mut data = Vec::new();
        for _ in 0..100 {
            data.extend_from_slice(PAT_A);
            data.push(b'.');
        }
        assert_eq!(s.scan(&data, FileKind::default(), 5).len(), 5);
        assert_eq!(s.scan(&data, FileKind::default(), 0).len(), 0);
    }

    #[test]
    fn file_kind_sniffing() {
        assert!(FileKind::sniff(b"MZ\x90\x00").is_pe);
        assert!(FileKind::sniff(b"\x7fELF\x02").is_elf);
        let plain = FileKind::sniff(b"hello");
        assert!(!plain.is_pe && !plain.is_elf);
        // Too short to tell must not panic or guess.
        let empty = FileKind::sniff(b"");
        assert!(!empty.is_pe && !empty.is_elf);
    }

    #[test]
    fn an_empty_scanner_is_harmless() {
        let s = BodyScanner::from_patterns(Vec::new()).unwrap();
        assert!(s.is_empty());
        assert_eq!(s.pattern_count(), 0);
        assert!(s.scan(b"anything at all", FileKind::default(), 16).is_empty());
    }
}
