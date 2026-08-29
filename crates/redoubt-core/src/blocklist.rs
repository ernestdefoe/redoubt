//! The set of addresses Redoubt will not let anything talk to.
//!
//! Malware that has already run still has to reach somebody: a command server
//! to take orders from, or somewhere to send what it stole. Cutting that off
//! does not undo an infection, but it turns a breach into an incident - which
//! is most of the difference that matters to the person whose machine it is.
//!
//! Kept deliberately dull. Parsing a blocklist is the sort of thing that
//! quietly drops half its input and reports success, so every line that is not
//! an address is counted and the counts are surfaced rather than swallowed.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// One blocked range, stored as an address and a prefix length.
///
/// A bare address is simply a /32 (or /128). Storing everything as a prefix
/// means the enforcement side has exactly one shape to deal with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Cidr {
    V4 { addr: Ipv4Addr, prefix: u8 },
    V6 { addr: Ipv6Addr, prefix: u8 },
}

impl Cidr {
    pub fn is_v4(&self) -> bool {
        matches!(self, Cidr::V4 { .. })
    }

    /// Whether this range covers `ip`.
    pub fn contains(&self, ip: std::net::IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4 { addr, prefix }, std::net::IpAddr::V4(other)) => {
                let mask = v4_mask(*prefix);
                (u32::from(*addr) & mask) == (u32::from(other) & mask)
            }
            (Cidr::V6 { addr, prefix }, std::net::IpAddr::V6(other)) => {
                let mask = v6_mask(*prefix);
                (u128::from(*addr) & mask) == (u128::from(other) & mask)
            }
            _ => false,
        }
    }
}

pub fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.min(32))
    }
}

pub fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix.min(128))
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cidr::V4 { addr, prefix } => write!(f, "{addr}/{prefix}"),
            Cidr::V6 { addr, prefix } => write!(f, "{addr}/{prefix}"),
        }
    }
}

/// Ranges that must never be blocked, whatever a feed says.
///
/// A feed with a bad entry - or one that has been tampered with - could
/// otherwise cut the machine off from its own network, its DNS resolver, or
/// the loopback interface the interface itself runs on. Redoubt would then
/// look exactly like the thing it is supposed to stop, and the person would
/// have no working machine to fix it from.
///
/// This is a floor, not a preference. It is applied at parse time so a refused
/// entry never reaches the enforcement layer at all.
const NEVER_BLOCK: &[(&str, u8)] = &[
    ("0.0.0.0", 8),      // "this network"
    ("10.0.0.0", 8),     // RFC1918
    ("127.0.0.0", 8),    // loopback
    ("169.254.0.0", 16), // link-local
    ("172.16.0.0", 12),  // RFC1918
    ("192.168.0.0", 16), // RFC1918
    ("224.0.0.0", 4),    // multicast
    ("255.255.255.255", 32),
];

fn is_protected(c: &Cidr) -> bool {
    match c {
        Cidr::V4 { addr, prefix } => {
            // A short prefix covering a large slice of the internet is refused
            // outright: no legitimate C2 feed asks for a /8.
            if *prefix < 8 {
                return true;
            }
            NEVER_BLOCK.iter().any(|(net, bits)| {
                let net: Ipv4Addr = net.parse().expect("static table");
                let mask = v4_mask(*bits);
                (u32::from(net) & mask) == (u32::from(*addr) & mask)
            })
        }
        Cidr::V6 { addr, prefix } => {
            *prefix < 16
                || addr.is_loopback()
                || addr.is_unspecified()
                // Unique-local and link-local.
                || (addr.segments()[0] & 0xfe00) == 0xfc00
                || (addr.segments()[0] & 0xffc0) == 0xfe80
                || addr.is_multicast()
        }
    }
}

/// What a parse run did. Every input line ends up in exactly one of these.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ParseStats {
    pub accepted: u64,
    pub duplicates: u64,
    /// Refused for covering loopback, private space, or too much of the
    /// internet. Counted separately because a feed producing these is a feed
    /// worth distrusting, not just a line worth skipping.
    pub refused_protected: u64,
    pub comments: u64,
    pub malformed: u64,
}

impl ParseStats {
    pub fn total_lines(&self) -> u64 {
        self.accepted + self.duplicates + self.refused_protected + self.comments + self.malformed
    }
}

/// Parse one line into a range, if it is one.
///
/// Accepts the shapes real feeds use: a bare address, CIDR notation, and
/// hosts-file lines (`0.0.0.0 evil.example`), whose address is deliberately
/// *ignored* - that is the sinkhole, not the target.
fn parse_entry(line: &str) -> Option<Cidr> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    // A hosts-file line names a host, not an address to block. Blocking
    // 0.0.0.0 because a hosts feed said so would be a catastrophic misreading,
    // so those lines are skipped rather than guessed at.
    if line.split_whitespace().count() > 1 {
        return None;
    }

    let (addr_part, prefix_part) = match line.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (line, None),
    };

    if let Ok(v4) = addr_part.parse::<Ipv4Addr>() {
        let prefix = match prefix_part {
            Some(p) => p.parse::<u8>().ok().filter(|p| *p <= 32)?,
            None => 32,
        };
        return Some(Cidr::V4 { addr: v4, prefix });
    }
    if let Ok(v6) = addr_part.parse::<Ipv6Addr>() {
        let prefix = match prefix_part {
            Some(p) => p.parse::<u8>().ok().filter(|p| *p <= 128)?,
            None => 128,
        };
        return Some(Cidr::V6 { addr: v6, prefix });
    }
    None
}

/// A parsed set of ranges, with the tally of how it was arrived at.
#[derive(Debug, Clone, Default)]
pub struct Blocklist {
    ranges: BTreeSet<Cidr>,
    pub stats: ParseStats,
    /// Files that contributed, for reporting.
    pub sources: Vec<String>,
}

impl Blocklist {
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Cidr> {
        self.ranges.iter()
    }

    pub fn contains(&self, ip: std::net::IpAddr) -> bool {
        self.ranges.iter().any(|r| r.contains(ip))
    }

    /// Add every entry in `text`, attributing it to `source`.
    pub fn add_text(&mut self, source: &str, text: &str) {
        let mut contributed = false;
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                self.stats.comments += 1;
                continue;
            }
            match parse_entry(line) {
                Some(cidr) if is_protected(&cidr) => self.stats.refused_protected += 1,
                Some(cidr) => {
                    if self.ranges.insert(cidr) {
                        self.stats.accepted += 1;
                        contributed = true;
                    } else {
                        self.stats.duplicates += 1;
                    }
                }
                None => self.stats.malformed += 1,
            }
        }
        if contributed {
            self.sources.push(source.to_string());
        }
    }

    /// Load every `.txt` in `dir`. A missing directory is not an error - it
    /// just means nothing is blocked yet.
    pub fn load_dir(dir: &Path) -> Self {
        let mut list = Self::default();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return list;
        };
        let mut files: Vec<_> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("txt")))
            .collect();
        // Sorted so the same directory always yields the same list; an
        // enforcement set that changes order between runs is hard to diff.
        files.sort();

        for path in files {
            if let Ok(text) = std::fs::read_to_string(&path) {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                list.add_text(&name, &text);
            }
        }
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_addresses_and_cidrs_both_parse() {
        let mut b = Blocklist::default();
        b.add_text("test", "203.0.113.5\n198.51.100.0/24\n");
        assert_eq!(b.len(), 2);
        assert!(b.contains("203.0.113.5".parse().unwrap()));
        assert!(b.contains("198.51.100.77".parse().unwrap()));
        assert!(!b.contains("198.51.101.1".parse().unwrap()));
    }

    #[test]
    fn loopback_is_never_blocked_however_it_is_written() {
        // The interface itself runs on loopback. Blocking it would leave
        // somebody with no working machine to undo it from.
        let mut b = Blocklist::default();
        b.add_text("hostile", "127.0.0.1\n127.0.0.0/8\n::1\n");
        assert!(b.is_empty(), "loopback must never reach the enforcement layer");
        assert_eq!(b.stats.refused_protected, 3);
    }

    #[test]
    fn private_networks_are_never_blocked() {
        // Blocking the local network would cut the machine off from its own
        // router, printer and DNS - indistinguishable from the malware.
        let mut b = Blocklist::default();
        b.add_text("hostile", "192.168.1.1\n10.0.0.0/8\n172.16.5.5\n169.254.1.1\n");
        assert!(b.is_empty());
        assert_eq!(b.stats.refused_protected, 4);
    }

    #[test]
    fn an_absurdly_wide_range_is_refused() {
        // No real C2 feed asks for a /4. One that does is either broken or
        // tampered with, and either way must not take the machine offline.
        let mut b = Blocklist::default();
        b.add_text("hostile", "8.0.0.0/4\n0.0.0.0/0\n");
        assert!(b.is_empty());
        assert_eq!(b.stats.refused_protected, 2);
    }

    #[test]
    fn a_hosts_file_line_does_not_block_the_sinkhole() {
        // `0.0.0.0 evil.example` names a host. Reading the address off the
        // front and blocking it would block everything.
        let mut b = Blocklist::default();
        b.add_text("hosts", "0.0.0.0 evil.example\n127.0.0.1 also.evil\n");
        assert!(b.is_empty(), "{:?}", b.stats);
        assert_eq!(b.stats.malformed, 2, "counted, not silently dropped");
    }

    #[test]
    fn comments_and_blank_lines_are_counted_not_dropped() {
        let mut b = Blocklist::default();
        b.add_text("test", "# a comment\n\n; another\n203.0.113.1\n");
        assert_eq!(b.len(), 1);
        assert_eq!(b.stats.comments, 3);
        assert_eq!(b.stats.total_lines(), 4);
    }

    #[test]
    fn duplicates_are_counted_separately_from_acceptances() {
        let mut b = Blocklist::default();
        b.add_text("a", "203.0.113.1\n203.0.113.1\n");
        assert_eq!(b.len(), 1);
        assert_eq!(b.stats.accepted, 1);
        assert_eq!(b.stats.duplicates, 1);
    }

    #[test]
    fn rubbish_is_counted_as_malformed() {
        // A feed that starts returning an HTML error page must show up as a
        // parse failure, not as an empty blocklist that looks like success.
        let mut b = Blocklist::default();
        b.add_text("broken", "<!DOCTYPE html>\nnot-an-address\n999.1.1.1\n");
        assert!(b.is_empty());
        assert_eq!(b.stats.malformed, 3);
    }

    #[test]
    fn v6_ranges_work_and_v4_does_not_match_them() {
        let mut b = Blocklist::default();
        b.add_text("test", "2001:db8::/32\n");
        assert!(b.contains("2001:db8::1".parse().unwrap()));
        assert!(!b.contains("2001:db9::1".parse().unwrap()));
        assert!(!b.contains("203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn masks_are_right_at_the_edges() {
        assert_eq!(v4_mask(0), 0);
        assert_eq!(v4_mask(32), u32::MAX);
        assert_eq!(v4_mask(24), 0xFFFF_FF00);
        assert_eq!(v6_mask(0), 0);
        assert_eq!(v6_mask(128), u128::MAX);
    }

    #[test]
    fn a_missing_directory_is_an_empty_list_not_an_error() {
        let b = Blocklist::load_dir(Path::new(r"Z:\no\such\place"));
        assert!(b.is_empty());
        assert_eq!(b.stats.total_lines(), 0);
    }
}
