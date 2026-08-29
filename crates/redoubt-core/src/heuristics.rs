//! Built-in heuristics.
//!
//! Every heuristic here produces [`Severity::Suspicious`] and never
//! [`Severity::Malicious`]. That is a hard rule, not a default: heuristics
//! describe *shapes* that malware often has and legitimate software sometimes
//! has, so acting on one destroys real files. They exist to raise an eyebrow
//! in the UI, and [`Severity::is_actionable`] keeps them out of enforcement.
//!
//! Each check is individually switchable, because the right threshold depends
//! on what a given machine actually runs.

use std::path::Path;

use crate::config::Heuristics as HeuristicsConfig;
use crate::pe::PeInfo;
use crate::verdict::{Detection, Engine, Severity};

/// Extensions that execute when double-clicked.
const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "wsh", "hta",
    "ps1", "msi", "cpl", "jar", "lnk", "reg",
];

/// Extensions a user reads as "this is a harmless document".
const DOCUMENT_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png",
    "gif", "bmp", "mp3", "mp4", "avi", "csv", "htm", "html", "zip", "rar",
];

/// Unicode bidirectional control characters.
///
/// U+202E RIGHT-TO-LEFT OVERRIDE is the classic filename spoof: a file named
/// `invoice\u{202E}fdp.exe` renders as `invoiceexe.pdf`. The rest are included
/// because they enable the same class of trick.
const BIDI_CONTROLS: &[char] = &[
    '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}',
    '\u{2068}', '\u{2069}', '\u{200F}', '\u{200E}',
];

fn suspicious(name: &str, detail: String) -> Detection {
    Detection::new(name, Engine::Heuristic, Severity::Suspicious).with_detail(detail)
}

/// Run every enabled heuristic. `pe` is `None` for non-PE files.
pub fn evaluate(
    path: &Path,
    pe: Option<&PeInfo>,
    cfg: &HeuristicsConfig,
) -> Vec<Detection> {
    let mut out = Vec::new();
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    if cfg.rtl_override {
        if let Some(found) = find_bidi_control(&file_name) {
            out.push(suspicious(
                "Heuristic.Filename.BidiOverride",
                format!(
                    "filename contains U+{:04X}, which makes the displayed name differ \
                     from the real one",
                    found as u32
                ),
            ));
        }
    }

    if cfg.double_extension {
        if let Some((doc, exe)) = find_double_extension(&file_name) {
            out.push(suspicious(
                "Heuristic.Filename.DoubleExtension",
                format!("presents as .{doc} but is executed as .{exe}"),
            ));
        }
    }

    let Some(pe) = pe else {
        return out;
    };

    if cfg.high_entropy {
        let e = pe.max_executable_entropy();
        if e >= cfg.entropy_threshold {
            out.push(suspicious(
                "Heuristic.PE.HighEntropyCode",
                format!(
                    "executable section entropy {e:.2} >= {:.2}, consistent with packing \
                     or encryption",
                    cfg.entropy_threshold
                ),
            ));
        }
    }

    if cfg.writable_executable_section {
        let wx = pe.writable_executable_sections();
        if !wx.is_empty() {
            let names: Vec<&str> = wx.iter().map(|s| s.name.as_str()).collect();
            out.push(suspicious(
                "Heuristic.PE.WritableExecutableSection",
                format!("section(s) {} are both writable and executable", names.join(", ")),
            ));
        }
    }

    if cfg.no_imports && pe.has_suspiciously_few_imports() {
        out.push(suspicious(
            "Heuristic.PE.MinimalImports",
            format!(
                "only {} imported symbol(s); typical of a packer that resolves APIs at runtime",
                pe.import_count
            ),
        ));
    }

    out
}

/// First bidirectional control character in `name`, if any.
fn find_bidi_control(name: &str) -> Option<char> {
    name.chars().find(|c| BIDI_CONTROLS.contains(c))
}

/// Detect `something.pdf.exe`: a document extension immediately followed by an
/// executable one.
///
/// Returns `(document_extension, executable_extension)`.
fn find_double_extension(name: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() < 3 {
        return None;
    }
    let last = parts[parts.len() - 1].to_ascii_lowercase();
    let second_last = parts[parts.len() - 2].to_ascii_lowercase();

    if EXECUTABLE_EXTENSIONS.contains(&last.as_str())
        && DOCUMENT_EXTENSIONS.contains(&second_last.as_str())
    {
        return Some((second_last, last));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cfg() -> HeuristicsConfig {
        HeuristicsConfig::default()
    }

    fn names(dets: &[Detection]) -> Vec<&str> {
        dets.iter().map(|d| d.name.as_str()).collect()
    }

    #[test]
    fn every_heuristic_is_only_ever_suspicious() {
        // The safety property the whole module rests on.
        let path = PathBuf::from("invoice.pdf.exe\u{202E}");
        let dets = evaluate(&path, None, &cfg());
        assert!(!dets.is_empty());
        for d in &dets {
            assert_eq!(d.severity, Severity::Suspicious, "{} was not suspicious", d.name);
            assert!(!d.severity.is_actionable(), "{} must not be enforceable", d.name);
            assert_eq!(d.engine, Engine::Heuristic);
        }
    }

    #[test]
    fn detects_a_double_extension() {
        let dets = evaluate(Path::new("invoice.pdf.exe"), None, &cfg());
        assert_eq!(names(&dets), vec!["Heuristic.Filename.DoubleExtension"]);
        assert!(dets[0].detail.as_ref().unwrap().contains("presents as .pdf"));
    }

    #[test]
    fn ordinary_filenames_are_left_alone() {
        for name in [
            "setup.exe",
            "report.pdf",
            "archive.tar.gz",
            "my.notes.txt",
            "libssl-3-x64.dll",
            "v1.2.3.zip",
            "file",
        ] {
            let dets = evaluate(Path::new(name), None, &cfg());
            assert!(dets.is_empty(), "{name} should not trip a filename heuristic: {dets:?}");
        }
    }

    #[test]
    fn detects_a_right_to_left_override() {
        let dets = evaluate(Path::new("invoice\u{202E}fdp.exe"), None, &cfg());
        assert!(names(&dets).contains(&"Heuristic.Filename.BidiOverride"));
        assert!(dets[0].detail.as_ref().unwrap().contains("U+202E"));
    }

    #[test]
    fn heuristics_can_be_switched_off_individually() {
        let mut c = cfg();
        c.double_extension = false;
        assert!(evaluate(Path::new("invoice.pdf.exe"), None, &c).is_empty());

        let mut c = cfg();
        c.rtl_override = false;
        assert!(evaluate(Path::new("a\u{202E}b.exe"), None, &c).is_empty());
    }

    #[test]
    fn double_extension_needs_a_document_then_an_executable() {
        assert_eq!(
            find_double_extension("invoice.pdf.exe"),
            Some(("pdf".into(), "exe".into()))
        );
        assert_eq!(find_double_extension("photo.jpg.scr"), Some(("jpg".into(), "scr".into())));
        // Not a document-then-executable pair.
        assert_eq!(find_double_extension("archive.tar.gz"), None);
        assert_eq!(find_double_extension("app.exe"), None);
        assert_eq!(find_double_extension("setup.x64.exe"), None);
    }

    #[test]
    fn bidi_detection_covers_the_whole_control_family() {
        assert_eq!(find_bidi_control("plain.txt"), None);
        for c in BIDI_CONTROLS {
            let name = format!("file{c}name.exe");
            assert_eq!(find_bidi_control(&name), Some(*c));
        }
    }
}
