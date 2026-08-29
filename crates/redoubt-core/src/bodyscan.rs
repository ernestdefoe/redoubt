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
//!
//! # Triggers, and why logical rules are not all in the automaton
//!
//! Logical signatures multiply patterns fast: 158,000 rules carry roughly
//! 370,000 subsignatures between them. Putting every one into the automaton
//! measured at **1.3 GB resident and eight seconds to load** - which destroys
//! the entire reason the index is memory-mapped in the first place.
//!
//! So a rule contributes a **trigger** instead. For a pure conjunction
//! (`0&1&2`), every subsignature must be present for the rule to fire, so any
//! single one is sufficient to notice the rule is worth considering - and the
//! *longest* is chosen, because it is the least likely to fire by chance. Only
//! when a trigger hits are the remaining subsignatures verified with a direct
//! substring search.
//!
//! Rules whose expression contains `|` cannot use one trigger: a disjunction
//! can be satisfied without the chosen branch appearing at all. Those
//! contribute every subsignature, and they are a small minority (`&` outnumbers
//! `|` roughly fifty to one in the real database).

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

/// Per-pattern metadata for a standalone `.ndb` literal.
struct PatternMeta {
    name: String,
    target: Target,
    offset: Offset,
    len: usize,
}

/// A logical signature: several patterns plus a boolean expression over which
/// of them matched.
struct LogicalRule {
    name: String,
    target: Target,
    /// Expression source, parsed only when a trigger has actually fired.
    /// Matches are rare, and 158,000 pre-parsed trees is memory spent on
    /// nothing.
    expr: String,
    /// Every subsignature, in the order the expression indexes them. The ones
    /// that are not triggers are verified by direct search when a trigger hits.
    subsigs: Vec<Vec<u8>>,
}

/// What a pattern in the automaton belongs to.
enum Owner {
    /// A standalone `.ndb` literal; index into `body_meta`.
    Body(usize),
    /// One subsignature of a logical rule.
    Subsig { rule: u32, index: u8 },
}

/// ClamAV allows up to 64 subsignatures, which fits a `u64` bitmask exactly.
const MAX_SUBSIGS: u8 = 64;

/// Which subsignatures of a rule go into the automaton.
///
/// A pure conjunction needs only one: if every subsignature must be present,
/// spotting any one of them is enough to know the rule is worth checking. The
/// longest is chosen because a longer literal fires by chance far less often,
/// so the expensive verification step runs less.
///
/// Anything containing `|` gets all of them: a disjunction can be satisfied
/// without any particular branch appearing, so a single trigger would miss
/// matches outright.
fn trigger_indices(expr: &str, subsigs: &[Vec<u8>]) -> Vec<u8> {
    let pure_conjunction = !expr.contains('|');
    if pure_conjunction {
        let longest = subsigs
            .iter()
            .enumerate()
            .max_by_key(|(_, s)| s.len())
            .map(|(i, _)| i as u8)
            .unwrap_or(0);
        vec![longest]
    } else {
        (0..subsigs.len() as u8).collect()
    }
}

/// A compiled set of literal body signatures and logical rules.
///
/// Both share one automaton. A file is walked exactly once however many
/// thousands of patterns are loaded, which is the whole reason Aho-Corasick is
/// here; running a second pass for logical subsignatures would double the cost
/// of every scan.
pub struct BodyScanner {
    automaton: AhoCorasick,
    owners: Vec<Owner>,
    meta: Vec<PatternMeta>,
    rules: Vec<LogicalRule>,
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
        let mut owners: Vec<Owner> = Vec::new();
        let mut meta: Vec<PatternMeta> = Vec::new();
        let mut rules: Vec<LogicalRule> = Vec::new();

        for p in index.body_patterns() {
            owners.push(Owner::Body(meta.len()));
            patterns.push(p.pattern.to_vec());
            meta.push(PatternMeta {
                name: p.name.to_string(),
                target: Target::from_clamav(p.target),
                offset: p.offset,
                len: p.pattern.len(),
            });
        }

        for rule in index.logical_rules() {
            if rule.subsigs.is_empty() || rule.subsigs.len() > MAX_SUBSIGS as usize {
                continue;
            }
            let rule_id = rules.len() as u32;
            let subsigs: Vec<Vec<u8>> = rule.subsigs.iter().map(|s| s.to_vec()).collect();

            for i in trigger_indices(rule.expr, &subsigs) {
                owners.push(Owner::Subsig { rule: rule_id, index: i });
                patterns.push(subsigs[i as usize].clone());
            }

            rules.push(LogicalRule {
                name: rule.name.to_string(),
                target: Target::from_clamav(rule.target),
                expr: rule.expr.to_string(),
                subsigs,
            });
        }

        let automaton = AhoCorasick::builder()
            .kind(Some(AhoCorasickKind::NoncontiguousNFA))
            .match_kind(MatchKind::Standard)
            .build(&patterns)
            .context("compiling body-pattern automaton")?;

        Ok(Self { automaton, owners, meta, rules })
    }

    /// Build from an explicit pattern list. Used by tests and by any future
    /// rule source that is not the compiled index.
    pub fn from_patterns(
        patterns: Vec<(String, u8, Offset, Vec<u8>)>,
    ) -> Result<Self> {
        Self::from_parts(patterns, Vec::new())
    }

    /// Build from explicit literals and logical rules. Used by tests.
    ///
    /// Logical rules are `(name, target, expression, subsignature patterns)`.
    pub fn from_parts(
        literals: Vec<(String, u8, Offset, Vec<u8>)>,
        logical: Vec<(String, u8, String, Vec<Vec<u8>>)>,
    ) -> Result<Self> {
        let mut raw = Vec::new();
        let mut owners = Vec::new();
        let mut meta = Vec::new();
        let mut rules = Vec::new();

        for (name, target, offset, pattern) in literals {
            owners.push(Owner::Body(meta.len()));
            meta.push(PatternMeta {
                name,
                target: Target::from_clamav(target),
                offset,
                len: pattern.len(),
            });
            raw.push(pattern);
        }

        for (name, target, expr, subsigs) in logical {
            if subsigs.is_empty() || subsigs.len() > MAX_SUBSIGS as usize {
                continue;
            }
            let rule_id = rules.len() as u32;
            for i in trigger_indices(&expr, &subsigs) {
                owners.push(Owner::Subsig { rule: rule_id, index: i });
                raw.push(subsigs[i as usize].clone());
            }
            rules.push(LogicalRule {
                name,
                target: Target::from_clamav(target),
                expr,
                subsigs,
            });
        }

        let automaton = AhoCorasick::builder()
            .kind(Some(AhoCorasickKind::NoncontiguousNFA))
            .match_kind(MatchKind::Standard)
            .build(&raw)
            .context("compiling body-pattern automaton")?;
        Ok(Self { automaton, owners, meta, rules })
    }

    pub fn pattern_count(&self) -> usize {
        self.meta.len()
    }

    /// Number of logical rules loaded.
    pub fn logical_count(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.meta.is_empty() && self.rules.is_empty()
    }

    /// Scan `data`, returning every eligible match.
    ///
    /// `limit` caps how many matches are collected. One pathological file can
    /// otherwise trip thousands of signatures and turn a scan into an
    /// allocation storm; the first few are all a verdict needs.
    pub fn scan(&self, data: &[u8], kind: FileKind, limit: usize) -> Vec<BodyMatch> {
        if self.is_empty() || data.is_empty() || limit == 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        // Which subsignatures of which rules have been seen, as a bitmask per
        // rule. Only rules with at least one hit ever enter the map, so a scan
        // that matches nothing costs no allocation.
        let mut hits: std::collections::HashMap<u32, (u64, usize)> =
            std::collections::HashMap::new();

        for m in self.automaton.find_iter(data) {
            match &self.owners[m.pattern().as_usize()] {
                Owner::Body(idx) => {
                    let meta = &self.meta[*idx];
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
                        return out;
                    }
                }
                Owner::Subsig { rule, index } => {
                    let entry = hits.entry(*rule).or_insert((0, m.start()));
                    entry.0 |= 1u64 << *index;
                }
            }
        }

        // Evaluate only the rules that had something match. A rule whose
        // subsignatures never appeared cannot possibly be satisfied, so the
        // overwhelming majority are never looked at.
        for (rule_id, (mask, first_offset)) in hits {
            let Some(rule) = self.rules.get(rule_id as usize) else {
                continue;
            };
            if !kind.accepts(rule.target) {
                continue;
            }

            // A trigger fired, so this rule is a candidate. Verify whichever
            // subsignatures were not triggers with a direct search. This runs
            // only for candidates, which is why keeping 370,000 patterns out
            // of the automaton costs nothing on the common path.
            let matched: Vec<bool> = rule
                .subsigs
                .iter()
                .enumerate()
                .map(|(i, pattern)| {
                    if mask & (1u64 << i) != 0 {
                        true
                    } else {
                        memchr::memmem::find(data, pattern).is_some()
                    }
                })
                .collect();

            let Some(expr) = crate::ldb::parse_expression(&rule.expr) else {
                // Stored expressions come from our own writer, so this should
                // not happen; skipping is the safe direction if it ever does.
                continue;
            };
            if expr.eval(&matched) {
                out.push(BodyMatch { name: rule.name.clone(), offset: first_offset });
                if out.len() >= limit {
                    break;
                }
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

    fn logical_scanner(
        specs: &[(&str, u8, &str, &[&[u8]])],
    ) -> BodyScanner {
        BodyScanner::from_parts(
            Vec::new(),
            specs
                .iter()
                .map(|(n, t, e, subs)| {
                    (
                        n.to_string(),
                        *t,
                        e.to_string(),
                        subs.iter().map(|s| s.to_vec()).collect(),
                    )
                })
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn a_logical_rule_fires_only_when_the_expression_holds() {
        let s = logical_scanner(&[("Rule.And", 0, "0&1", &[b"ALPHA-PART", b"BRAVO-PART"])]);

        // Both present.
        let both = b"xxx ALPHA-PART yyy BRAVO-PART zzz";
        let hits = s.scan(both, FileKind::default(), 16);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "Rule.And");

        // Only one: the whole point of a logical signature is that this is
        // not enough.
        assert!(s.scan(b"xxx ALPHA-PART yyy", FileKind::default(), 16).is_empty());
        assert!(s.scan(b"yyy BRAVO-PART zzz", FileKind::default(), 16).is_empty());
        assert!(s.scan(b"nothing here", FileKind::default(), 16).is_empty());
    }

    #[test]
    fn a_logical_or_fires_on_either_branch() {
        let s = logical_scanner(&[("Rule.Or", 0, "0|1", &[b"ALPHA-PART", b"BRAVO-PART"])]);
        assert_eq!(s.scan(b"xx ALPHA-PART", FileKind::default(), 16).len(), 1);
        assert_eq!(s.scan(b"xx BRAVO-PART", FileKind::default(), 16).len(), 1);
        assert!(s.scan(b"xx CHARLIE", FileKind::default(), 16).is_empty());
    }

    #[test]
    fn logical_precedence_is_respected_at_match_time() {
        // `0|1&2` is `0 or (1 and 2)`.
        let s = logical_scanner(&[(
            "Rule.Mixed",
            0,
            "0|1&2",
            &[b"ALPHA-PART", b"BRAVO-PART", b"CHARLIE-PT"],
        )]);
        assert_eq!(s.scan(b"ALPHA-PART only", FileKind::default(), 16).len(), 1);
        assert!(
            s.scan(b"BRAVO-PART only", FileKind::default(), 16).is_empty(),
            "one half of the conjunction must not be enough"
        );
        assert_eq!(
            s.scan(b"BRAVO-PART and CHARLIE-PT", FileKind::default(), 16).len(),
            1
        );
    }

    #[test]
    fn a_logical_rule_respects_its_target_type() {
        let s = logical_scanner(&[("Rule.PeOnly", 1, "0&1", &[b"ALPHA-PART", b"BRAVO-PART"])]);
        let text = b"ALPHA-PART BRAVO-PART in a text file";
        assert!(
            s.scan(text, FileKind::sniff(text), 16).is_empty(),
            "a PE-targeted rule must not fire on a text file"
        );

        let mut pe = b"MZ".to_vec();
        pe.extend_from_slice(b"ALPHA-PART BRAVO-PART");
        assert_eq!(s.scan(&pe, FileKind::sniff(&pe), 16).len(), 1);
    }

    #[test]
    fn literals_and_logical_rules_share_one_pass() {
        let s = BodyScanner::from_parts(
            vec![("Lit.One".to_string(), 0, Offset::Any, PAT_A.to_vec())],
            vec![(
                "Rule.And".to_string(),
                0,
                "0&1".to_string(),
                vec![b"ALPHA-PART".to_vec(), b"BRAVO-PART".to_vec()],
            )],
        )
        .unwrap();
        assert_eq!(s.pattern_count(), 1);
        assert_eq!(s.logical_count(), 1);

        let mut data = PAT_A.to_vec();
        data.extend_from_slice(b" ALPHA-PART BRAVO-PART");
        let names: Vec<&str> = s
            .scan(&data, FileKind::default(), 16)
            .iter()
            .map(|m| m.name.clone())
            .collect::<Vec<_>>()
            .leak()
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert!(names.contains(&"Lit.One"));
        assert!(names.contains(&"Rule.And"));
    }

    #[test]
    fn a_conjunction_contributes_one_trigger_and_it_is_the_longest() {
        // Putting every subsignature in the automaton measured at 1.3 GB
        // resident across the real database.
        let subs = vec![b"SHORT".to_vec(), b"THE-LONGEST-ONE-HERE".to_vec(), b"MEDIUM!!".to_vec()];
        assert_eq!(trigger_indices("0&1&2", &subs), vec![1]);
        assert_eq!(trigger_indices("(0&1)&2", &subs), vec![1]);
    }

    #[test]
    fn a_disjunction_contributes_every_subsignature() {
        // One trigger would miss a match satisfied through another branch.
        let subs = vec![b"AAAA".to_vec(), b"BBBBBBBB".to_vec()];
        assert_eq!(trigger_indices("0|1", &subs), vec![0, 1]);
        assert_eq!(trigger_indices("0&(1|0)", &subs), vec![0, 1]);
    }

    #[test]
    fn a_conjunction_still_matches_through_verification() {
        // Only the longest subsignature is in the automaton; the other two
        // must be found by the verification pass or the rule never fires.
        let s = logical_scanner(&[(
            "Rule.Verify",
            0,
            "0&1&2",
            &[b"AAAA-SHORT", b"THE-LONGEST-TRIGGER-PATTERN", b"BBBB-SHORT"],
        )]);

        let all = b"xx AAAA-SHORT yy THE-LONGEST-TRIGGER-PATTERN zz BBBB-SHORT";
        assert_eq!(s.scan(all, FileKind::default(), 16).len(), 1);

        // Missing one of the verified parts: must not fire.
        let missing = b"xx AAAA-SHORT yy THE-LONGEST-TRIGGER-PATTERN zz";
        assert!(s.scan(missing, FileKind::default(), 16).is_empty());

        // Trigger absent: nothing to verify, so nothing fires.
        let no_trigger = b"xx AAAA-SHORT yy BBBB-SHORT";
        assert!(s.scan(no_trigger, FileKind::default(), 16).is_empty());
    }

    #[test]
    fn an_empty_scanner_is_harmless() {
        let s = BodyScanner::from_patterns(Vec::new()).unwrap();
        assert!(s.is_empty());
        assert_eq!(s.pattern_count(), 0);
        assert!(s.scan(b"anything at all", FileKind::default(), 16).is_empty());
    }
}
