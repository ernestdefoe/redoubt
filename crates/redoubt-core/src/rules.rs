//! YARA rule compilation and matching, via `yara-x`.
//!
//! YARA is where this engine gets its teeth beyond hashes: rules express
//! structure and behaviour, so they catch families rather than exact builds.
//! `yara-x` is VirusTotal's Rust implementation, which keeps the whole engine
//! free of a C toolchain dependency.
//!
//! Compiled [`RuleSet`]s are shared across threads; each scanning thread takes
//! its own [`RuleScanner`], because a scanner carries mutable per-scan state.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::verdict::{Detection, Engine, Severity};

/// Extensions treated as YARA sources.
const RULE_EXTENSIONS: &[&str] = &["yar", "yara"];

/// One rule that matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMatch {
    pub identifier: String,
    pub severity: Severity,
    /// Value of the rule's `description` metadata, when it has one.
    pub description: Option<String>,
    /// Tags declared on the rule.
    pub tags: Vec<String>,
}

impl RuleMatch {
    pub fn to_detection(&self) -> Detection {
        let mut d = Detection::new(self.identifier.clone(), Engine::Yara, self.severity);
        if let Some(desc) = &self.description {
            d = d.with_detail(desc.clone());
        } else if !self.tags.is_empty() {
            d = d.with_detail(format!("tags: {}", self.tags.join(", ")));
        }
        d
    }
}

/// Report from compiling a directory of rules.
#[derive(Debug, Clone, Default)]
pub struct RuleCompileReport {
    /// Files that compiled cleanly.
    pub compiled: Vec<PathBuf>,
    /// Files that failed, with the reason. A broken third-party rule file must
    /// not take the whole rule set down with it.
    pub failed: Vec<(PathBuf, String)>,
    pub total_rules: usize,
}

impl RuleCompileReport {
    pub fn summary(&self) -> String {
        format!(
            "{} YARA rules from {} file(s){}",
            self.total_rules,
            self.compiled.len(),
            if self.failed.is_empty() {
                String::new()
            } else {
                format!(", {} file(s) failed to compile", self.failed.len())
            }
        )
    }
}

/// A compiled, shareable set of YARA rules.
pub struct RuleSet {
    rules: yara_x::Rules,
    report: RuleCompileReport,
}

impl RuleSet {
    /// Compile from a single source string.
    pub fn from_source(source: &str) -> Result<Self> {
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(source)
            .map_err(|e| anyhow::anyhow!("{e}"))
            .context("compiling YARA source")?;
        let rules = compiler.build();
        let total = rules.iter().count();
        Ok(Self {
            rules,
            report: RuleCompileReport {
                compiled: vec![PathBuf::from("<inline>")],
                failed: Vec::new(),
                total_rules: total,
            },
        })
    }

    /// Compile every `.yar`/`.yara` file under `dir`, recursively.
    ///
    /// Files are added one at a time so a single malformed rule file is
    /// reported and skipped rather than aborting the whole compile - which
    /// matters when the rules come from a third-party repository that updates
    /// independently of us.
    pub fn compile_dir(dir: &Path) -> Result<Self> {
        let mut compiler = yara_x::Compiler::new();
        let mut report = RuleCompileReport::default();

        let mut files: Vec<PathBuf> = walkdir::WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.into_path())
            .filter(|p| {
                p.extension()
                    .map(|e| RULE_EXTENSIONS.contains(&e.to_string_lossy().to_lowercase().as_str()))
                    .unwrap_or(false)
            })
            .collect();
        files.sort();

        for path in files {
            let source = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(e) => {
                    report.failed.push((path, format!("read failed: {e}")));
                    continue;
                }
            };
            match compiler.add_source(source.as_str()) {
                Ok(_) => report.compiled.push(path),
                Err(e) => report.failed.push((path, format!("{e}"))),
            }
        }

        let rules = compiler.build();
        report.total_rules = rules.iter().count();
        Ok(Self { rules, report })
    }

    /// An empty rule set, for when YARA is disabled or no rules are installed.
    pub fn empty() -> Result<Self> {
        Self::from_source("").map(|mut s| {
            s.report = RuleCompileReport::default();
            s
        })
    }

    pub fn report(&self) -> &RuleCompileReport {
        &self.report
    }

    pub fn rule_count(&self) -> usize {
        self.report.total_rules
    }

    pub fn is_empty(&self) -> bool {
        self.report.total_rules == 0
    }

    /// Make a scanner bound to this rule set. One per thread.
    pub fn scanner(&self, timeout: Duration) -> RuleScanner<'_> {
        let mut inner = yara_x::Scanner::new(&self.rules);
        inner.set_timeout(timeout);
        RuleScanner { inner }
    }
}

/// A per-thread YARA scanner.
pub struct RuleScanner<'a> {
    inner: yara_x::Scanner<'a>,
}

impl RuleScanner<'_> {
    /// Scan `data`, returning every matching rule.
    pub fn scan(&mut self, data: &[u8]) -> Result<Vec<RuleMatch>> {
        let results = self
            .inner
            .scan(data)
            .map_err(|e| anyhow::anyhow!("YARA scan failed: {e}"))?;

        Ok(results
            .matching_rules()
            .map(|rule| {
                let mut description = None;
                let mut severity = Severity::Malicious;

                for (key, value) in rule.metadata() {
                    match key {
                        "description" | "desc" => {
                            if let yara_x::MetaValue::String(s) = value {
                                description = Some(s.to_string());
                            }
                        }
                        // A rule set can opt its noisier rules down to
                        // `Suspicious` so they never trigger enforcement.
                        "severity" | "redoubt_severity" => {
                            if let yara_x::MetaValue::String(s) = value {
                                severity = match s.to_ascii_lowercase().as_str() {
                                    "suspicious" | "low" | "info" => Severity::Suspicious,
                                    _ => Severity::Malicious,
                                };
                            }
                        }
                        _ => {}
                    }
                }

                RuleMatch {
                    identifier: rule.identifier().to_string(),
                    severity,
                    description,
                    tags: rule.tags().map(|t| t.identifier().to_string()).collect(),
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE: &str = r#"
rule Redoubt_Test_Alpha {
    meta:
        description = "matches the alpha test marker"
    strings:
        $a = "REDOUBT-YARA-ALPHA"
    condition:
        $a
}
"#;

    const TAGGED_AND_DOWNGRADED: &str = r#"
rule Redoubt_Test_Noisy : heuristic packer {
    meta:
        description = "a deliberately noisy rule"
        severity = "suspicious"
    strings:
        $a = "REDOUBT-YARA-NOISY"
    condition:
        $a
}
"#;

    #[test]
    fn compiles_and_matches_a_simple_rule() {
        let rules = RuleSet::from_source(SIMPLE).unwrap();
        assert_eq!(rules.rule_count(), 1);

        let mut scanner = rules.scanner(Duration::from_secs(5));
        let hits = scanner.scan(b"padding REDOUBT-YARA-ALPHA padding").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].identifier, "Redoubt_Test_Alpha");
        assert_eq!(hits[0].severity, Severity::Malicious);
        assert_eq!(hits[0].description.as_deref(), Some("matches the alpha test marker"));
    }

    #[test]
    fn clean_data_matches_nothing() {
        let rules = RuleSet::from_source(SIMPLE).unwrap();
        let mut scanner = rules.scanner(Duration::from_secs(5));
        assert!(scanner.scan(b"entirely ordinary file contents").unwrap().is_empty());
        assert!(scanner.scan(b"").unwrap().is_empty());
    }

    #[test]
    fn severity_metadata_can_downgrade_a_rule() {
        // Without this, every YARA hit would be enforcement-eligible, and a
        // broad heuristic rule could quarantine legitimate software.
        let rules = RuleSet::from_source(TAGGED_AND_DOWNGRADED).unwrap();
        let mut scanner = rules.scanner(Duration::from_secs(5));
        let hits = scanner.scan(b"xx REDOUBT-YARA-NOISY xx").unwrap();

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Suspicious);
        assert!(!hits[0].severity.is_actionable(), "suspicious must never be enforced");
    }

    #[test]
    fn tags_are_captured() {
        let rules = RuleSet::from_source(TAGGED_AND_DOWNGRADED).unwrap();
        let mut scanner = rules.scanner(Duration::from_secs(5));
        let hits = scanner.scan(b"REDOUBT-YARA-NOISY").unwrap();
        assert_eq!(hits[0].tags, vec!["heuristic", "packer"]);
    }

    #[test]
    fn detection_carries_the_description() {
        let rules = RuleSet::from_source(SIMPLE).unwrap();
        let mut scanner = rules.scanner(Duration::from_secs(5));
        let hits = scanner.scan(b"REDOUBT-YARA-ALPHA").unwrap();

        let d = hits[0].to_detection();
        assert_eq!(d.engine, Engine::Yara);
        assert_eq!(d.name, "Redoubt_Test_Alpha");
        assert_eq!(d.detail.as_deref(), Some("matches the alpha test marker"));
    }

    #[test]
    fn a_broken_rule_file_does_not_sink_the_whole_directory() {
        let dir = std::env::temp_dir().join(format!("redoubt-yara-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("good.yar"), SIMPLE).unwrap();
        std::fs::write(dir.join("broken.yar"), "rule Broken { this is not yara }").unwrap();
        std::fs::write(dir.join("notes.txt"), "ignored, not a rule file").unwrap();

        let rules = RuleSet::compile_dir(&dir).unwrap();
        assert_eq!(rules.rule_count(), 1, "the good rule should survive");
        assert_eq!(rules.report().failed.len(), 1);
        assert!(rules.report().failed[0].0.ends_with("broken.yar"));
        assert!(rules.report().compiled.iter().any(|p| p.ends_with("good.yar")));
        assert!(rules.report().summary().contains("failed to compile"));

        let mut scanner = rules.scanner(Duration::from_secs(5));
        assert_eq!(scanner.scan(b"REDOUBT-YARA-ALPHA").unwrap().len(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_empty_rule_set_is_harmless() {
        let rules = RuleSet::empty().unwrap();
        assert!(rules.is_empty());
        let mut scanner = rules.scanner(Duration::from_secs(5));
        assert!(scanner.scan(b"REDOUBT-YARA-ALPHA").unwrap().is_empty());
    }

    #[test]
    fn compiling_a_missing_directory_yields_an_empty_set() {
        let rules = RuleSet::compile_dir(Path::new("does-not-exist-anywhere")).unwrap();
        assert!(rules.is_empty());
        assert!(rules.report().compiled.is_empty());
    }
}
