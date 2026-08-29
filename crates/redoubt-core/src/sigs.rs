//! Parsers for the individual ClamAV signature file formats.
//!
//! Each format is one signature per line, `#`-commented, colon-delimited. The
//! field *order* differs between them in ways that are easy to get backwards -
//! `.hdb` is `hash:size:name` while `.mdb` is `size:hash:name` - so each
//! format gets its own function and its own test.
//!
//! Formats handled here:
//!
//! | Ext            | Meaning                        | Layout                              |
//! |----------------|--------------------------------|-------------------------------------|
//! | `.hdb`, `.hdu` | whole-file MD5                 | `md5:size:name`                     |
//! | `.hsb`, `.hsu` | whole-file SHA-1 / SHA-256     | `hash:size:name`                    |
//! | `.mdb`, `.mdu` | PE section MD5                 | `size:md5:name`                     |
//! | `.msb`, `.msu` | PE section SHA-1 / SHA-256     | `size:hash:name`                    |
//! | `.fp`          | allowlist, MD5                 | `md5:size:name`                     |
//! | `.sfp`         | allowlist, SHA-1 / SHA-256     | `hash:size:name`                    |
//! | `.ndb`, `.ndu` | body pattern                   | `name:target:offset:hex[:fl[:fl]]`  |

use std::fmt;

/// A signature hash, sized by algorithm so lookups never allocate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HashValue {
    Md5([u8; 16]),
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}

impl HashValue {
    /// Decode a hex string, inferring the algorithm from its length.
    /// Returns `None` for any length that is not 32, 40 or 64 hex chars.
    pub fn from_hex(s: &str) -> Option<Self> {
        match s.len() {
            32 => {
                let mut b = [0u8; 16];
                hex::decode_to_slice(s, &mut b).ok()?;
                Some(HashValue::Md5(b))
            }
            40 => {
                let mut b = [0u8; 20];
                hex::decode_to_slice(s, &mut b).ok()?;
                Some(HashValue::Sha1(b))
            }
            64 => {
                let mut b = [0u8; 32];
                hex::decode_to_slice(s, &mut b).ok()?;
                Some(HashValue::Sha256(b))
            }
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            HashValue::Md5(b) => b,
            HashValue::Sha1(b) => b,
            HashValue::Sha256(b) => b,
        }
    }

    pub fn kind_str(&self) -> &'static str {
        match self {
            HashValue::Md5(_) => "md5",
            HashValue::Sha1(_) => "sha1",
            HashValue::Sha256(_) => "sha256",
        }
    }
}

impl fmt::Display for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.as_bytes()))
    }
}

/// Digests of a zero-length input.
///
/// These appear in real signature databases - Sanesecurity's honeypot set
/// ships the empty-file SHA-256 - and matching them flags *every* zero-byte
/// file on the system. On a stock Windows install that is thousands of files,
/// and in enforcing mode it would quarantine all of them. An empty file has no
/// content and cannot be malware, so these are refused at index time.
pub const EMPTY_MD5: &str = "d41d8cd98f00b204e9800998ecf8427e";
pub const EMPTY_SHA1: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
pub const EMPTY_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// True if `hash` is the digest of zero bytes.
pub fn is_degenerate(hash: &HashValue) -> bool {
    let hex = hash.to_string();
    hex == EMPTY_MD5 || hex == EMPTY_SHA1 || hex == EMPTY_SHA256
}

/// Severity a signature name implies.
///
/// ClamAV namespaces "potentially unwanted" signatures under a `PUA.` prefix -
/// packers, adware bundlers, remote-admin tools. They describe things a user
/// may have installed deliberately, so treating them as malicious produces
/// alarming false positives (Windows ships `MRT.exe`, which trips two packer
/// signatures). They map to `Suspicious` instead.
pub fn implied_severity(name: &str) -> crate::verdict::Severity {
    if name.starts_with("PUA.") || name.starts_with("Pua.") {
        crate::verdict::Severity::Suspicious
    } else {
        crate::verdict::Severity::Malicious
    }
}

/// A hash-based signature: "these exact bytes are (or are not) malware".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashSig {
    pub hash: HashValue,
    /// Expected file (or section) size. `None` means the signature used `*`,
    /// i.e. it matches at any size.
    pub size: Option<u64>,
    pub name: String,
}

/// Where in the file a body pattern must appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offset {
    /// `*` - match anywhere.
    Any,
    /// An absolute byte offset from the start of the file.
    Absolute(u64),
}

/// A literal body-pattern signature from a `.ndb` file.
///
/// Only wildcard-free patterns are represented. ClamAV's pattern language also
/// has `??` nibble wildcards, `*` gaps, `{n-m}` ranges and `(a|b)` alternation;
/// those lines are counted as unsupported rather than silently dropped, so the
/// UI can report honest coverage instead of implying the whole database loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodySig {
    pub name: String,
    /// ClamAV target type: 0 = any, 1 = PE, 3 = HTML, 6 = ELF, 7 = ASCII, ...
    pub target: u8,
    pub offset: Offset,
    pub pattern: Vec<u8>,
}

/// Tally of what a parse run did, so coverage can be reported rather than assumed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ParseStats {
    pub accepted: u64,
    /// Well-formed but using a feature this engine does not implement.
    pub unsupported: u64,
    /// Malformed enough that we could not read it at all.
    pub malformed: u64,
}

impl ParseStats {
    pub fn total_seen(&self) -> u64 {
        self.accepted + self.unsupported + self.malformed
    }

    pub fn merge(&mut self, other: ParseStats) {
        self.accepted += other.accepted;
        self.unsupported += other.unsupported;
        self.malformed += other.malformed;
    }
}

/// True for blank lines and comments, which every format shares.
fn is_skippable(line: &str) -> bool {
    let t = line.trim();
    t.is_empty() || t.starts_with('#')
}

/// Parse a size field, where `*` means "any size".
fn parse_size(field: &str) -> Option<Option<u64>> {
    let f = field.trim();
    if f == "*" {
        return Some(None);
    }
    f.parse::<u64>().ok().map(Some)
}

/// Parse `.hdb` / `.hsb` / `.fp` / `.sfp`: `hash:size:name`.
pub fn parse_hash_db(data: &[u8], mut emit: impl FnMut(HashSig)) -> ParseStats {
    let mut stats = ParseStats::default();
    for line in data.split(|&b| b == b'\n') {
        let Ok(line) = std::str::from_utf8(line) else {
            stats.malformed += 1;
            continue;
        };
        let line = line.trim_end_matches('\r');
        if is_skippable(line) {
            continue;
        }
        // Signature names can themselves contain colons, so split from the
        // left exactly twice and let the remainder be the name.
        let mut parts = line.splitn(3, ':');
        let (Some(hash), Some(size), Some(name)) = (parts.next(), parts.next(), parts.next())
        else {
            stats.malformed += 1;
            continue;
        };
        let (Some(hash), Some(size)) = (HashValue::from_hex(hash.trim()), parse_size(size)) else {
            stats.malformed += 1;
            continue;
        };
        emit(HashSig { hash, size, name: name.trim().to_string() });
        stats.accepted += 1;
    }
    stats
}

/// Parse `.mdb` / `.msb`: `size:hash:name`. Note the reversed field order.
pub fn parse_section_db(data: &[u8], mut emit: impl FnMut(HashSig)) -> ParseStats {
    let mut stats = ParseStats::default();
    for line in data.split(|&b| b == b'\n') {
        let Ok(line) = std::str::from_utf8(line) else {
            stats.malformed += 1;
            continue;
        };
        let line = line.trim_end_matches('\r');
        if is_skippable(line) {
            continue;
        }
        let mut parts = line.splitn(3, ':');
        let (Some(size), Some(hash), Some(name)) = (parts.next(), parts.next(), parts.next())
        else {
            stats.malformed += 1;
            continue;
        };
        let (Some(size), Some(hash)) = (parse_size(size), HashValue::from_hex(hash.trim())) else {
            stats.malformed += 1;
            continue;
        };
        emit(HashSig { hash, size, name: name.trim().to_string() });
        stats.accepted += 1;
    }
    stats
}

/// True if a `.ndb` pattern body uses any feature beyond plain hex.
fn pattern_has_wildcards(pat: &str) -> bool {
    pat.bytes()
        .any(|b| matches!(b, b'?' | b'*' | b'{' | b'}' | b'(' | b')' | b'[' | b']' | b'|' | b'!'))
}

/// Parse `.ndb`: `name:target:offset:hexsig[:minfl[:maxfl]]`.
///
/// Lines using wildcards, non-absolute offsets (`EP+n`, `EOF-n`, `Sx+n`), or
/// patterns shorter than `min_pattern_len` are reported as unsupported. The
/// length floor matters: a two-byte literal would match constantly and drown
/// the user in false positives.
pub fn parse_body_db(
    data: &[u8],
    min_pattern_len: usize,
    mut emit: impl FnMut(BodySig),
) -> ParseStats {
    let mut stats = ParseStats::default();
    for line in data.split(|&b| b == b'\n') {
        let Ok(line) = std::str::from_utf8(line) else {
            stats.malformed += 1;
            continue;
        };
        let line = line.trim_end_matches('\r');
        if is_skippable(line) {
            continue;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 4 {
            stats.malformed += 1;
            continue;
        }
        // `name` is parts[0]; target/offset/pattern follow. Trailing feature
        // levels are ignored - they gate on ClamAV engine version, not on us.
        let name = parts[0].trim();
        let Ok(target) = parts[1].trim().parse::<u8>() else {
            stats.malformed += 1;
            continue;
        };

        let offset = match parts[2].trim() {
            "*" => Offset::Any,
            other => match other.parse::<u64>() {
                Ok(n) => Offset::Absolute(n),
                // EP+n, EOF-n, Sx+n and friends need a PE-aware matcher.
                Err(_) => {
                    stats.unsupported += 1;
                    continue;
                }
            },
        };

        let pat = parts[3].trim();
        if pattern_has_wildcards(pat) {
            stats.unsupported += 1;
            continue;
        }
        let Ok(pattern) = hex::decode(pat) else {
            stats.malformed += 1;
            continue;
        };
        if pattern.len() < min_pattern_len {
            stats.unsupported += 1;
            continue;
        }

        emit(BodySig { name: name.to_string(), target, offset, pattern });
        stats.accepted += 1;
    }
    stats
}

/// What kind of signature file an extension denotes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigFileKind {
    /// Whole-file hash, malicious.
    FileHash,
    /// PE section hash, malicious.
    SectionHash,
    /// Whole-file hash, known good - suppresses detections.
    Allowlist,
    /// Literal body pattern.
    Body,
}

/// Map a signature file extension to its kind, or `None` if we do not handle it.
///
/// `.ldb` (logical), `.cdb` (container metadata), `.crb` (certificate trust)
/// and the `.info`/`COPYING` metadata files all land here as `None`.
pub fn classify(extension: &str) -> Option<SigFileKind> {
    match extension {
        "hdb" | "hdu" | "hsb" | "hsu" => Some(SigFileKind::FileHash),
        "mdb" | "mdu" | "msb" | "msu" => Some(SigFileKind::SectionHash),
        "fp" | "sfp" => Some(SigFileKind::Allowlist),
        "ndb" | "ndu" => Some(SigFileKind::Body),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_value_infers_algorithm_from_length() {
        assert!(matches!(
            HashValue::from_hex(&"ab".repeat(16)),
            Some(HashValue::Md5(_))
        ));
        assert!(matches!(
            HashValue::from_hex(&"ab".repeat(20)),
            Some(HashValue::Sha1(_))
        ));
        assert!(matches!(
            HashValue::from_hex(&"ab".repeat(32)),
            Some(HashValue::Sha256(_))
        ));
        assert_eq!(HashValue::from_hex("abcd"), None);
        assert_eq!(HashValue::from_hex(&"zz".repeat(16)), None);
    }

    #[test]
    fn parses_hdb_lines() {
        let db = b"# comment line\n\
                   44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature\n\
                   \n\
                   5d41402abc4b2a76b9719d911017c592:*:Win.Trojan.Sized-Any\n";
        let mut out = Vec::new();
        let stats = parse_hash_db(db, |s| out.push(s));
        assert_eq!(stats.accepted, 2);
        assert_eq!(stats.malformed, 0);
        assert_eq!(out[0].name, "Eicar-Test-Signature");
        assert_eq!(out[0].size, Some(68));
        assert_eq!(out[1].size, None, "'*' should mean any size");
    }

    #[test]
    fn hdb_keeps_colons_inside_signature_names() {
        let db = b"44d88612fea8a8f36de82e1278abb02f:68:Some:Name:With:Colons\n";
        let mut out = Vec::new();
        parse_hash_db(db, |s| out.push(s));
        assert_eq!(out[0].name, "Some:Name:With:Colons");
    }

    #[test]
    fn counts_malformed_hdb_lines_without_panicking() {
        let db = b"not-a-hash:68:Bad\n\
                   44d88612fea8a8f36de82e1278abb02f:notanumber:Bad2\n\
                   toofewfields\n\
                   44d88612fea8a8f36de82e1278abb02f:68:Good\n";
        let mut out = Vec::new();
        let stats = parse_hash_db(db, |s| out.push(s));
        assert_eq!(stats.accepted, 1);
        assert_eq!(stats.malformed, 3);
    }

    #[test]
    fn parses_mdb_with_reversed_field_order() {
        // This is the one that bites: size comes FIRST in .mdb.
        let db = b"4096:5d41402abc4b2a76b9719d911017c592:Win.Packed.Section\n";
        let mut out = Vec::new();
        let stats = parse_section_db(db, |s| out.push(s));
        assert_eq!(stats.accepted, 1);
        assert_eq!(out[0].size, Some(4096));
        assert_eq!(out[0].name, "Win.Packed.Section");
        assert!(matches!(out[0].hash, HashValue::Md5(_)));
    }

    #[test]
    fn parses_literal_ndb_patterns() {
        let db = b"Win.Test.Literal:0:*:4d5a90000300000004000000ffff0000\n";
        let mut out = Vec::new();
        let stats = parse_body_db(db, 4, |s| out.push(s));
        assert_eq!(stats.accepted, 1);
        assert_eq!(out[0].offset, Offset::Any);
        assert_eq!(out[0].target, 0);
        assert_eq!(&out[0].pattern[..2], b"MZ");
    }

    #[test]
    fn parses_absolute_ndb_offsets() {
        let db = b"Win.Test.AtZero:1:0:4d5a9000\n";
        let mut out = Vec::new();
        parse_body_db(db, 4, |s| out.push(s));
        assert_eq!(out[0].offset, Offset::Absolute(0));
    }

    #[test]
    fn reports_wildcard_ndb_patterns_as_unsupported() {
        let db = b"Win.Wild.Star:0:*:4d5a*0000\n\
                   Win.Wild.Nibble:0:*:4d5a??00\n\
                   Win.Wild.Range:0:*:4d5a{2-4}0000\n\
                   Win.Wild.Alt:0:*:4d5a(41|42)00\n";
        let mut out = Vec::new();
        let stats = parse_body_db(db, 4, |s| out.push(s));
        assert_eq!(stats.accepted, 0);
        assert_eq!(stats.unsupported, 4, "every wildcard form must be counted");
        assert!(out.is_empty());
    }

    #[test]
    fn reports_relative_ndb_offsets_as_unsupported() {
        let db = b"Win.Test.EntryPoint:1:EP+16:4d5a9000\n\
                   Win.Test.Eof:1:EOF-64:4d5a9000\n\
                   Win.Test.Section:1:S1+0:4d5a9000\n";
        let mut out = Vec::new();
        let stats = parse_body_db(db, 4, |s| out.push(s));
        assert_eq!(stats.unsupported, 3);
        assert!(out.is_empty());
    }

    #[test]
    fn rejects_short_ndb_patterns() {
        // A 2-byte literal would match half the files on the disk.
        let db = b"Win.Test.TooShort:0:*:4d5a\n";
        let mut out = Vec::new();
        let stats = parse_body_db(db, 4, |s| out.push(s));
        assert_eq!(stats.accepted, 0);
        assert_eq!(stats.unsupported, 1);
    }

    #[test]
    fn classifies_known_extensions() {
        assert_eq!(classify("hdb"), Some(SigFileKind::FileHash));
        assert_eq!(classify("hsb"), Some(SigFileKind::FileHash));
        assert_eq!(classify("mdb"), Some(SigFileKind::SectionHash));
        assert_eq!(classify("msb"), Some(SigFileKind::SectionHash));
        assert_eq!(classify("fp"), Some(SigFileKind::Allowlist));
        assert_eq!(classify("sfp"), Some(SigFileKind::Allowlist));
        assert_eq!(classify("ndb"), Some(SigFileKind::Body));
        // Formats we knowingly do not implement yet.
        assert_eq!(classify("ldb"), None);
        assert_eq!(classify("cdb"), None);
        assert_eq!(classify("info"), None);
    }

    #[test]
    fn empty_file_digests_are_recognised_as_degenerate() {
        // Sanesecurity's honeypot database really does ship the empty-file
        // SHA-256. Indexing it flags every zero-byte file on the system - 20
        // of them in System32 alone on a clean install.
        for hex in [EMPTY_MD5, EMPTY_SHA1, EMPTY_SHA256] {
            let h = HashValue::from_hex(hex).unwrap();
            assert!(is_degenerate(&h), "{hex} should be refused");
        }
    }

    #[test]
    fn ordinary_hashes_are_not_degenerate() {
        let eicar = HashValue::from_hex("44d88612fea8a8f36de82e1278abb02f").unwrap();
        assert!(!is_degenerate(&eicar));
    }

    #[test]
    fn pua_signatures_are_only_suspicious() {
        use crate::verdict::Severity;
        // Windows ships MRT.exe, which trips two of these. Reporting a
        // packer as malicious on a stock install destroys trust in the tool.
        assert_eq!(implied_severity("PUA.Win.Packer.Lzexe-1"), Severity::Suspicious);
        assert_eq!(implied_severity("PUA.Win.Packer.Nspack-34"), Severity::Suspicious);
        assert!(!implied_severity("PUA.Win.Packer.Lzexe-1").is_actionable());

        assert_eq!(implied_severity("Win.Trojan.Agent-123"), Severity::Malicious);
        assert_eq!(implied_severity("Eicar-Test-Signature"), Severity::Malicious);
    }

    #[test]
    fn parse_stats_merge_accumulates() {
        let mut a = ParseStats { accepted: 1, unsupported: 2, malformed: 3 };
        a.merge(ParseStats { accepted: 10, unsupported: 20, malformed: 30 });
        assert_eq!(a.accepted, 11);
        assert_eq!(a.unsupported, 22);
        assert_eq!(a.malformed, 33);
        assert_eq!(a.total_seen(), 66);
    }
}
