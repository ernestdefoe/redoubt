//! The result vocabulary shared by every engine and every consumer.
//!
//! A `Verdict` is what the scanner returns; a `Detection` is one engine's
//! reason for it. Keeping detections as a list (rather than collapsing to a
//! single name) means the UI can show *why* something was flagged when three
//! engines disagree, which is the difference between a tool you trust and a
//! tool you turn off.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// How bad is it. Ordered, so `max()` over a detection list gives the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Nothing matched, and nothing looked odd.
    Clean,
    /// Heuristics only. Never auto-actioned - far too noisy to act on alone.
    Suspicious,
    /// A signature or a high-confidence rule matched.
    Malicious,
}

impl Severity {
    /// Whether a verdict at this severity may be enforced (quarantined/killed)
    /// even when the user has enabled enforcement. Heuristics never qualify;
    /// they exist to raise an eyebrow, not to delete a file.
    pub fn is_actionable(self) -> bool {
        matches!(self, Severity::Malicious)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Clean => "clean",
            Severity::Suspicious => "suspicious",
            Severity::Malicious => "malicious",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which engine produced a detection. Surfaced in the UI so a false positive
/// can be traced back to the thing that needs tuning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Engine {
    /// Whole-file hash matched a signature (MD5 / SHA-1 / SHA-256).
    Hash,
    /// A PE section hash matched.
    SectionHash,
    /// A ClamAV body-pattern signature matched.
    BodyPattern,
    /// A YARA rule matched.
    Yara,
    /// A built-in heuristic fired.
    Heuristic,
}

impl Engine {
    pub fn as_str(self) -> &'static str {
        match self {
            Engine::Hash => "hash",
            Engine::SectionHash => "section-hash",
            Engine::BodyPattern => "body-pattern",
            Engine::Yara => "yara",
            Engine::Heuristic => "heuristic",
        }
    }
}

impl fmt::Display for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One engine's reason for flagging a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detection {
    /// Signature or rule name, e.g. `Win.Trojan.Agent-1234567`.
    pub name: String,
    pub engine: Engine,
    pub severity: Severity,
    /// Free-form supporting detail: matched offset, section name, entropy value.
    /// Shown in the UI's detail pane; never parsed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Detection {
    pub fn new(name: impl Into<String>, engine: Engine, severity: Severity) -> Self {
        Self { name: name.into(), engine, severity, detail: None }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// Identity of the bytes we scanned. Kept separate from the verdict so the
/// cache can key on it and the quarantine can record it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileIdentity {
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// The scanner's answer about one file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub path: PathBuf,
    pub identity: FileIdentity,
    pub severity: Severity,
    pub detections: Vec<Detection>,
    /// Wall-clock cost of this scan. Drives the "slowest paths" view, which is
    /// how you find the directory that needs an exclusion.
    pub scan_micros: u64,
    /// True when this came back from the verdict cache rather than a real scan.
    #[serde(default)]
    pub cached: bool,
    /// Set when an allowlist entry (ClamAV `.fp`, or the user's own list)
    /// suppressed what would otherwise have been a detection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowlisted_as: Option<String>,
}

impl Verdict {
    pub fn clean(path: PathBuf, identity: FileIdentity, scan_micros: u64) -> Self {
        Self {
            path,
            identity,
            severity: Severity::Clean,
            detections: Vec::new(),
            scan_micros,
            cached: false,
            allowlisted_as: None,
        }
    }

    /// Recompute `severity` from the current detection list.
    pub fn recompute_severity(&mut self) {
        self.severity = self
            .detections
            .iter()
            .map(|d| d.severity)
            .max()
            .unwrap_or(Severity::Clean);
    }

    pub fn is_clean(&self) -> bool {
        self.severity == Severity::Clean
    }

    /// The name to show when the UI has room for exactly one. Prefers the
    /// highest-severity detection, and among equals prefers a real signature
    /// over a heuristic.
    pub fn primary_name(&self) -> Option<&str> {
        self.detections
            .iter()
            .max_by_key(|d| (d.severity, d.engine != Engine::Heuristic))
            .map(|d| d.name.as_str())
    }
}
