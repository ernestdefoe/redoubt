//! Fetching addresses that malware is known to phone home to.
//!
//! Feeds arrive in whatever shape their publisher chose. Rather than teach the
//! blocklist parser every one of them, each feed is normalised here into the
//! one dull format the parser reads - a plain list of addresses - and written
//! into the blocklist directory. The parser stays boring, which is what you
//! want in the thing deciding whether a machine can reach the internet.
//!
//! # Terms
//!
//! The default feed is abuse.ch's ThreatFox, whose terms are at
//! <https://threatfox.abuse.ch/faq/#tos>. It is free to use and needs no key.
//! Anyone redistributing Redoubt commercially should read those terms rather
//! than assume this file settled the question.

use anyhow::{Context, Result};
use std::path::Path;

/// How to get addresses out of a feed's own format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// One address or CIDR per line, `#` comments. What we write out.
    Plain,
    /// abuse.ch CSV, quoted fields, with `ip:port` in the third column.
    ThreatFoxCsv,
}

#[derive(Debug, Clone)]
pub struct Feed {
    pub name: String,
    pub url: String,
    pub format: Format,
    /// Shown to a person deciding whether they want it.
    pub description: String,
}

/// The feeds Redoubt knows about.
///
/// Deliberately short. A blocklist is a list of things a machine may not talk
/// to, and every entry is a chance to break something that was working; more
/// feeds is not obviously better.
pub fn default_feeds() -> Vec<Feed> {
    vec![Feed {
        name: "threatfox".into(),
        url: "https://threatfox.abuse.ch/export/csv/ip-port/recent/".into(),
        format: Format::ThreatFoxCsv,
        description: "abuse.ch ThreatFox: recent botnet command-and-control addresses".into(),
    }]
}

/// Pull the addresses out of a feed body.
///
/// Returns the addresses and the number of rows it could not read. A feed that
/// changes format silently yields zero addresses and looks exactly like a feed
/// with nothing in it, so the unreadable count is what tells them apart.
pub fn extract(body: &str, format: Format) -> (Vec<String>, u64) {
    let mut out = Vec::new();
    let mut unreadable = 0u64;

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match format {
            Format::Plain => out.push(line.to_string()),
            Format::ThreatFoxCsv => {
                // "date", "id", "1.2.3.4:443", "ip:port", ...
                let field = line
                    .split(',')
                    .nth(2)
                    .map(|f| f.trim().trim_matches('"').trim());
                match field.and_then(strip_port) {
                    Some(addr) => out.push(addr),
                    None => unreadable += 1,
                }
            }
        }
    }
    (out, unreadable)
}

/// Take `1.2.3.4:443` down to `1.2.3.4`, leaving bare addresses alone.
///
/// IPv6 is written `[::1]:443` when it carries a port, so the brackets are
/// what say where the address ends - splitting on the last colon would cut a
/// bare IPv6 address in half.
fn strip_port(field: &str) -> Option<String> {
    let field = field.trim();
    if field.is_empty() {
        return None;
    }
    if let Some(rest) = field.strip_prefix('[') {
        let (addr, _) = rest.split_once(']')?;
        return Some(addr.to_string());
    }
    // More than one colon and no brackets means a bare IPv6 address.
    if field.matches(':').count() > 1 {
        return Some(field.to_string());
    }
    Some(field.split(':').next()?.to_string())
}

/// What one feed refresh did.
#[derive(Debug, Clone)]
pub struct FeedReport {
    pub name: String,
    pub addresses: usize,
    pub unreadable: u64,
    pub error: Option<String>,
}

/// Refresh every feed into `dir`.
///
/// One feed failing does not stop the others: a stale list is better than no
/// list, and the report says which is which rather than reporting a single
/// pass or fail for the lot.
pub fn update(dir: &Path, feeds: &[Feed]) -> Result<Vec<FeedReport>> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating {}", dir.display()))?;

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(60)))
        .user_agent(crate::update::user_agent())
        .build()
        .into();

    let mut reports = Vec::new();
    for feed in feeds {
        let mut report = FeedReport {
            name: feed.name.clone(),
            addresses: 0,
            unreadable: 0,
            error: None,
        };

        match agent.get(&feed.url).call() {
            Ok(mut response) => match response.body_mut().read_to_string() {
                Ok(body) => {
                    let (addresses, unreadable) = extract(&body, feed.format);
                    report.addresses = addresses.len();
                    report.unreadable = unreadable;

                    // Refuse to overwrite a working list with an empty one. A
                    // feed that has been deprecated, rate-limited or replaced
                    // with an error page answers 200 with nothing usable in
                    // it, and silently disarming is the worst outcome.
                    if addresses.is_empty() {
                        report.error = Some(
                            "the feed returned no usable addresses; the existing list was kept"
                                .into(),
                        );
                    } else {
                        let path = dir.join(format!("{}.txt", feed.name));
                        let header = format!(
                            "# {}\n# {}\n# fetched by Redoubt; do not edit, it is overwritten\n",
                            feed.description, feed.url
                        );
                        let text = header + &addresses.join("\n") + "\n";
                        if let Err(e) = std::fs::write(&path, text) {
                            report.error = Some(format!("could not write {}: {e}", path.display()));
                        }
                    }
                }
                Err(e) => report.error = Some(format!("reading the response failed: {e}")),
            },
            Err(e) => report.error = Some(format!("fetching failed: {e}")),
        }

        reports.push(report);
    }
    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    const THREATFOX: &str = r#"# comment line
"2026-08-29 16:05:06", "1891100", "45.192.105.141:60001", "ip:port", "botnet_cc"
"2026-08-29 15:05:05", "1891085", "45.140.213.2:443", "ip:port", "botnet_cc"
"2026-08-29 15:05:05", "1891086", "[2001:db8::1]:8080", "ip:port", "botnet_cc"
"#;

    #[test]
    fn threatfox_rows_yield_bare_addresses() {
        let (addrs, bad) = extract(THREATFOX, Format::ThreatFoxCsv);
        assert_eq!(addrs, vec!["45.192.105.141", "45.140.213.2", "2001:db8::1"]);
        assert_eq!(bad, 0);
    }

    #[test]
    fn a_bare_ipv6_address_is_not_cut_in_half() {
        // Splitting on the last colon would turn 2001:db8::1 into 2001:db8:
        // and block something else entirely.
        assert_eq!(strip_port("2001:db8::1").unwrap(), "2001:db8::1");
        assert_eq!(strip_port("[2001:db8::1]:443").unwrap(), "2001:db8::1");
        assert_eq!(strip_port("1.2.3.4:80").unwrap(), "1.2.3.4");
        assert_eq!(strip_port("1.2.3.4").unwrap(), "1.2.3.4");
    }

    #[test]
    fn a_feed_that_changed_shape_is_counted_not_silently_empty() {
        // The failure that matters: a feed still answers 200, but with
        // something we cannot read. Zero addresses and zero complaints would
        // look exactly like a quiet day.
        let (addrs, bad) = extract("\"a\", \"b\"\n\"c\", \"d\"\n", Format::ThreatFoxCsv);
        assert!(addrs.is_empty());
        assert_eq!(bad, 2, "unreadable rows must be counted");
    }

    #[test]
    fn comments_are_skipped_in_both_formats() {
        let (addrs, _) = extract("# header\n\n1.2.3.4\n", Format::Plain);
        assert_eq!(addrs, vec!["1.2.3.4"]);
    }

    #[test]
    fn the_default_feed_is_fetched_over_tls() {
        for f in default_feeds() {
            assert!(f.url.starts_with("https://"), "{} must use TLS", f.name);
            assert!(!f.description.is_empty(), "{} needs a description", f.name);
        }
    }
}
