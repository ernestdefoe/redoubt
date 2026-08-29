//! Looking inside archives.
//!
//! Malware overwhelmingly arrives inside a container - a zip attachment, a
//! gzipped dropper, a nested archive built specifically to get past a scanner
//! that only looks at the outer file. Scanning only the outer bytes means a
//! signature for the payload never fires.
//!
//! # Everything here is a bomb-handling problem
//!
//! An archive is attacker-controlled input whose *decompressed* size is not
//! bounded by its compressed size. `42.zip` is 42 KB and expands to 4.5 PB.
//! Three independent limits therefore apply, and all of them are enforced
//! during extraction rather than checked afterwards:
//!
//! 1. **Per-entry size** - an entry that inflates past the limit is abandoned
//!    mid-read, not read and then rejected.
//! 2. **Total expansion budget** - shared across the whole archive, so a
//!    thousand entries just under the per-entry limit cannot add up to
//!    something ruinous.
//! 3. **Depth** - an archive inside an archive inside an archive terminates.
//!
//! Hitting a limit is reported as [`Limit`] rather than passed over silently:
//! "we could not look inside this" is a materially different answer from
//! "we looked inside and it was clean".

use serde::{Deserialize, Serialize};
use std::io::Read;

/// Formats we can open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Zip,
    Gzip,
}

impl Format {
    /// Identify by magic bytes rather than extension - the extension is
    /// whatever the attacker felt like naming it.
    pub fn sniff(data: &[u8]) -> Option<Self> {
        if data.len() >= 4 && (&data[..4] == b"PK\x03\x04" || &data[..4] == b"PK\x05\x06") {
            return Some(Format::Zip);
        }
        if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
            return Some(Format::Gzip);
        }
        None
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Format::Zip => "zip",
            Format::Gzip => "gzip",
        }
    }
}

/// Why extraction stopped short.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Limit {
    /// An entry inflated past the per-entry cap.
    EntryTooLarge { name: String, cap: u64 },
    /// The archive as a whole inflated past the budget.
    BudgetExhausted { cap: u64 },
    /// Nesting went deeper than allowed.
    TooDeep { depth: u8 },
    /// Too many entries to be worth walking.
    TooManyEntries { cap: usize },
    /// The container would not parse.
    Unreadable { reason: String },
}

impl std::fmt::Display for Limit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Limit::EntryTooLarge { name, cap } => {
                write!(f, "entry {name:?} inflates past {cap} bytes")
            }
            Limit::BudgetExhausted { cap } => {
                write!(f, "archive inflates past the {cap} byte budget")
            }
            Limit::TooDeep { depth } => write!(f, "nesting deeper than {depth}"),
            Limit::TooManyEntries { cap } => write!(f, "more than {cap} entries"),
            Limit::Unreadable { reason } => write!(f, "unreadable: {reason}"),
        }
    }
}

/// Bounds on one extraction.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_depth: u8,
    pub max_entry_bytes: u64,
    /// Total decompressed bytes across the whole archive tree.
    pub max_total_bytes: u64,
    pub max_entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 2,
            max_entry_bytes: 64 * 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
            max_entries: 2_000,
        }
    }
}

impl Limits {
    pub fn from_config(scan: &crate::config::ScanLimits) -> Self {
        Self {
            max_depth: scan.archive_depth,
            max_entry_bytes: scan.max_archive_entry_bytes,
            // The whole tree may not exceed what a single file may.
            max_total_bytes: scan.max_scan_bytes,
            max_entries: 2_000,
        }
    }
}

/// One extracted member.
pub struct Member {
    /// Display path, e.g. `outer.zip!/inner.zip!/payload.exe`.
    pub path: String,
    pub data: Vec<u8>,
    pub depth: u8,
}

/// What an extraction produced.
#[derive(Default)]
pub struct Extraction {
    pub members: Vec<Member>,
    /// Limits that were hit. A non-empty list means coverage was incomplete.
    pub limits_hit: Vec<Limit>,
    pub total_bytes: u64,
}

impl Extraction {
    /// True when every member was extracted with nothing skipped.
    pub fn is_complete(&self) -> bool {
        self.limits_hit.is_empty()
    }
}

/// Running budget, shared across the whole nested walk.
struct Budget {
    remaining: u64,
    entries_remaining: usize,
}

/// Outcome of a bounded read.
struct Capped {
    data: Vec<u8>,
    /// The source had more than the cap allowed.
    truncated: bool,
    /// Decompression failed part-way. Reported rather than swallowed: bytes we
    /// could not decompress are bytes we did not scan, and treating that as a
    /// clean empty entry is exactly how a scanner comes to believe it looked
    /// inside something it never read.
    error: Option<String>,
}

/// Read at most `cap` bytes.
///
/// The reader is bounded *while* reading; a decompressor is never allowed to
/// run to completion and hand back however much it produced.
fn read_capped<R: Read>(reader: R, cap: u64) -> Capped {
    let mut data = Vec::new();
    let mut limited = reader.take(cap + 1);
    let error = match limited.read_to_end(&mut data) {
        Ok(_) => None,
        Err(e) => Some(e.to_string()),
    };
    let truncated = data.len() as u64 > cap;
    if truncated {
        data.truncate(cap as usize);
    }
    Capped { data, truncated, error }
}

/// Expand `data`, recursing into nested archives up to the depth limit.
pub fn extract(data: &[u8], name: &str, limits: &Limits) -> Extraction {
    let mut out = Extraction::default();
    let mut budget = Budget {
        remaining: limits.max_total_bytes,
        entries_remaining: limits.max_entries,
    };
    walk(data, name, 0, limits, &mut budget, &mut out);
    out
}

fn walk(
    data: &[u8],
    prefix: &str,
    depth: u8,
    limits: &Limits,
    budget: &mut Budget,
    out: &mut Extraction,
) {
    if depth >= limits.max_depth {
        out.limits_hit.push(Limit::TooDeep { depth: limits.max_depth });
        return;
    }
    let Some(format) = Format::sniff(data) else {
        return;
    };

    match format {
        Format::Zip => walk_zip(data, prefix, depth, limits, budget, out),
        Format::Gzip => walk_gzip(data, prefix, depth, limits, budget, out),
    }
}

fn walk_zip(
    data: &[u8],
    prefix: &str,
    depth: u8,
    limits: &Limits,
    budget: &mut Budget,
    out: &mut Extraction,
) {
    let cursor = std::io::Cursor::new(data);
    let mut zip = match zip::ZipArchive::new(cursor) {
        Ok(z) => z,
        Err(e) => {
            out.limits_hit.push(Limit::Unreadable { reason: e.to_string() });
            return;
        }
    };

    for i in 0..zip.len() {
        if budget.entries_remaining == 0 {
            out.limits_hit.push(Limit::TooManyEntries { cap: limits.max_entries });
            return;
        }
        if budget.remaining == 0 {
            out.limits_hit.push(Limit::BudgetExhausted { cap: limits.max_total_bytes });
            return;
        }

        let mut entry = match zip.by_index(i) {
            Ok(e) => e,
            Err(e) => {
                out.limits_hit.push(Limit::Unreadable { reason: e.to_string() });
                continue;
            }
        };
        if !entry.is_file() {
            continue;
        }
        budget.entries_remaining -= 1;

        // The archive's own name for the entry is never used as a filesystem
        // path - nothing here is written to disk - but it does reach the UI,
        // so it is kept as a label only.
        let name = entry.name().to_string();
        let member_path = format!("{prefix}!/{name}");

        let cap = limits.max_entry_bytes.min(budget.remaining);
        let capped = read_capped(&mut entry, cap);
        let bytes = capped.data;
        if capped.truncated {
            out.limits_hit.push(Limit::EntryTooLarge {
                name: member_path.clone(),
                cap: limits.max_entry_bytes,
            });
            // The bytes read so far are still scanned: a signature near the
            // start of a bomb should still fire.
        }
        if let Some(reason) = capped.error {
            out.limits_hit.push(Limit::Unreadable {
                reason: format!("{member_path}: {reason}"),
            });
        }

        budget.remaining = budget.remaining.saturating_sub(bytes.len() as u64);
        out.total_bytes += bytes.len() as u64;

        // Recurse before moving the buffer into the member list.
        if Format::sniff(&bytes).is_some() {
            walk(&bytes, &member_path, depth + 1, limits, budget, out);
        }

        out.members.push(Member { path: member_path, data: bytes, depth: depth + 1 });
    }
}

fn walk_gzip(
    data: &[u8],
    prefix: &str,
    depth: u8,
    limits: &Limits,
    budget: &mut Budget,
    out: &mut Extraction,
) {
    if budget.remaining == 0 {
        out.limits_hit.push(Limit::BudgetExhausted { cap: limits.max_total_bytes });
        return;
    }
    let cap = limits.max_entry_bytes.min(budget.remaining);
    let decoder = flate2::read::GzDecoder::new(data);
    let capped = read_capped(decoder, cap);
    let bytes = capped.data;

    let member_path = format!("{prefix}!/(gzip)");
    if let Some(reason) = capped.error {
        out.limits_hit.push(Limit::Unreadable {
            reason: format!("{member_path}: {reason}"),
        });
    }
    if bytes.is_empty() {
        return;
    }
    if capped.truncated {
        out.limits_hit.push(Limit::EntryTooLarge {
            name: member_path.clone(),
            cap: limits.max_entry_bytes,
        });
    }

    budget.remaining = budget.remaining.saturating_sub(bytes.len() as u64);
    out.total_bytes += bytes.len() as u64;

    if Format::sniff(&bytes).is_some() {
        walk(&bytes, &member_path, depth + 1, limits, budget, out);
    }
    out.members.push(Member { path: member_path, data: bytes, depth: depth + 1 });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn zip_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            for (name, data) in files {
                w.start_file(*name, opts).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        buf
    }

    fn gzip_of(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn sniffs_formats_by_magic_not_extension() {
        assert_eq!(Format::sniff(&zip_of(&[("a.txt", b"x")])), Some(Format::Zip));
        assert_eq!(Format::sniff(&gzip_of(b"hello")), Some(Format::Gzip));
        assert_eq!(Format::sniff(b"MZ\x90\x00"), None);
        assert_eq!(Format::sniff(b"plain text"), None);
        assert_eq!(Format::sniff(b""), None);
        assert_eq!(Format::sniff(b"PK"), None, "too short to decide");
    }

    #[test]
    fn extracts_zip_members() {
        let data = zip_of(&[("a.txt", b"first"), ("dir/b.bin", b"second")]);
        let e = extract(&data, "outer.zip", &Limits::default());

        assert!(e.is_complete(), "{:?}", e.limits_hit);
        assert_eq!(e.members.len(), 2);
        let paths: Vec<&str> = e.members.iter().map(|m| m.path.as_str()).collect();
        assert!(paths.contains(&"outer.zip!/a.txt"));
        assert!(paths.contains(&"outer.zip!/dir/b.bin"));
        assert_eq!(e.members[0].data, b"first");
    }

    #[test]
    fn extracts_gzip() {
        let data = gzip_of(b"the decompressed payload");
        let e = extract(&data, "thing.gz", &Limits::default());
        assert_eq!(e.members.len(), 1);
        assert_eq!(e.members[0].data, b"the decompressed payload");
        assert_eq!(e.members[0].path, "thing.gz!/(gzip)");
    }

    #[test]
    fn recurses_into_nested_archives() {
        let inner = zip_of(&[("payload.exe", b"MZ the actual malware")]);
        let outer = zip_of(&[("inner.zip", &inner)]);

        let e = extract(&outer, "outer.zip", &Limits::default());
        let paths: Vec<&str> = e.members.iter().map(|m| m.path.as_str()).collect();
        assert!(
            paths.contains(&"outer.zip!/inner.zip!/payload.exe"),
            "nested payload not reached: {paths:?}"
        );
        // The inner archive itself is also a member, so its own hash can match.
        assert!(paths.contains(&"outer.zip!/inner.zip"));
    }

    #[test]
    fn depth_is_bounded_and_reported() {
        let l3 = zip_of(&[("deep.txt", b"too deep to reach")]);
        let l2 = zip_of(&[("l3.zip", &l3)]);
        let l1 = zip_of(&[("l2.zip", &l2)]);

        let limits = Limits { max_depth: 2, ..Default::default() };
        let e = extract(&l1, "l1.zip", &limits);

        let paths: Vec<&str> = e.members.iter().map(|m| m.path.as_str()).collect();
        assert!(paths.contains(&"l1.zip!/l2.zip"));
        assert!(paths.contains(&"l1.zip!/l2.zip!/l3.zip"));
        assert!(
            !paths.iter().any(|p| p.contains("deep.txt")),
            "recursion went past the depth limit"
        );
        // And it says so, rather than implying it looked and found nothing.
        assert!(
            e.limits_hit.iter().any(|l| matches!(l, Limit::TooDeep { .. })),
            "hitting the depth limit must be reported: {:?}",
            e.limits_hit
        );
        assert!(!e.is_complete());
    }

    #[test]
    fn a_zip_bomb_is_capped_rather_than_expanded() {
        // A highly compressible entry: ~1 MB of zeroes in a few hundred bytes.
        let bomb = zip_of(&[("bomb.bin", &vec![0u8; 1_000_000])]);
        assert!(bomb.len() < 20_000, "fixture is not compressed enough to be a test");

        let limits = Limits {
            max_entry_bytes: 4096,
            max_total_bytes: 8192,
            ..Default::default()
        };
        let e = extract(&bomb, "bomb.zip", &limits);

        assert!(e.total_bytes <= 8192, "expanded {} bytes past the budget", e.total_bytes);
        assert_eq!(e.members[0].data.len(), 4096, "the entry should be cut at the cap");
        assert!(
            e.limits_hit
                .iter()
                .any(|l| matches!(l, Limit::EntryTooLarge { .. })),
            "the cap must be reported: {:?}",
            e.limits_hit
        );
    }

    #[test]
    fn the_total_budget_is_shared_across_entries() {
        // Many entries each under the per-entry cap must still not add up past
        // the overall budget.
        let files: Vec<(String, Vec<u8>)> = (0..50)
            .map(|i| (format!("f{i}.bin"), vec![b'A'; 10_000]))
            .collect();
        let refs: Vec<(&str, &[u8])> =
            files.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();
        let data = zip_of(&refs);

        let limits = Limits {
            max_entry_bytes: 100_000,
            max_total_bytes: 25_000,
            ..Default::default()
        };
        let e = extract(&data, "many.zip", &limits);

        assert!(
            e.total_bytes <= 25_000,
            "expanded {} bytes past a 25,000 byte budget",
            e.total_bytes
        );
        assert!(!e.is_complete());
    }

    #[test]
    fn the_entry_count_is_bounded() {
        let files: Vec<(String, Vec<u8>)> =
            (0..200).map(|i| (format!("f{i}.txt"), b"x".to_vec())).collect();
        let refs: Vec<(&str, &[u8])> =
            files.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();
        let data = zip_of(&refs);

        let limits = Limits { max_entries: 10, ..Default::default() };
        let e = extract(&data, "many.zip", &limits);

        assert!(e.members.len() <= 10, "extracted {} entries", e.members.len());
        assert!(e
            .limits_hit
            .iter()
            .any(|l| matches!(l, Limit::TooManyEntries { .. })));
    }

    #[test]
    fn a_truncated_bomb_entry_is_still_scanned() {
        // A signature near the start of an oversized entry must still be
        // reachable: capping is about bounding work, not giving up.
        let mut payload = b"REDOUBT-MARKER-AT-THE-START".to_vec();
        payload.extend(std::iter::repeat(0u8).take(500_000));
        let data = zip_of(&[("big.bin", &payload)]);

        let limits = Limits { max_entry_bytes: 1024, ..Default::default() };
        let e = extract(&data, "a.zip", &limits);

        assert_eq!(e.members.len(), 1);
        assert!(
            e.members[0].data.starts_with(b"REDOUBT-MARKER-AT-THE-START"),
            "the readable prefix should survive the cap"
        );
    }

    #[test]
    fn a_corrupt_archive_is_reported_not_ignored() {
        let mut data = zip_of(&[("a.txt", b"hello")]);
        // Wreck the middle, keeping the magic intact.
        let mid = data.len() / 2;
        for b in data[mid..mid + 8].iter_mut() {
            *b = 0xFF;
        }
        let e = extract(&data, "broken.zip", &Limits::default());
        // Either it read nothing or it reported a problem, but it must never
        // claim a clean complete look.
        assert!(
            !e.is_complete() || e.members.is_empty(),
            "a corrupt archive must not report a complete extraction"
        );
    }

    #[test]
    fn depth_zero_disables_archive_scanning() {
        let data = zip_of(&[("a.txt", b"hello")]);
        let limits = Limits { max_depth: 0, ..Default::default() };
        let e = extract(&data, "a.zip", &limits);
        assert!(e.members.is_empty());
    }

    #[test]
    fn non_archives_produce_nothing() {
        let e = extract(b"MZ\x90\x00 an ordinary executable", "a.exe", &Limits::default());
        assert!(e.members.is_empty());
        assert!(e.is_complete(), "a non-archive is not an incomplete extraction");
    }

    #[test]
    fn limits_come_from_the_scan_config() {
        let mut scan = crate::config::ScanLimits::default();
        scan.archive_depth = 3;
        scan.max_archive_entry_bytes = 12345;
        let l = Limits::from_config(&scan);
        assert_eq!(l.max_depth, 3);
        assert_eq!(l.max_entry_bytes, 12345);
        assert_eq!(l.max_total_bytes, scan.max_scan_bytes);
    }
}
