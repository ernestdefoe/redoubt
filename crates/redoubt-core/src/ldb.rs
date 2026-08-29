//! ClamAV logical signatures (`.ldb`).
//!
//! A logical signature is several byte patterns plus a boolean expression over
//! which of them matched:
//!
//! ```text
//! Js.Trojan.Agent-1553;Engine:81-255,Target:3;0&1&2;3c7363726970...;6a71756572...;73657474...
//! ```
//!
//! # Why these matter enough to implement
//!
//! They are the largest single block of signature data ClamAV ships - about
//! 86 MB across `daily` and `main`, roughly 273,000 rules - and none of it was
//! being used. Measured against the real database, 51% of those rules use only
//! literal subsignatures and plain `&`/`|` expressions, which is what this
//! module supports.
//!
//! # Why short patterns are safe here but not in `.ndb`
//!
//! A lone 6-byte literal matches constantly, which is why
//! [`crate::compile::MIN_BODY_PATTERN_LEN`] refuses them for `.ndb`. A logical
//! signature requiring *three* 6-byte patterns to co-occur is a far more
//! specific statement than one 16-byte pattern. So the length floor is relaxed
//! only for multi-subsignature rules, and a single-subsignature `.ldb` rule is
//! held to the same 16-byte floor as any other literal.

use serde::{Deserialize, Serialize};

/// The subset of the expression grammar this engine evaluates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Expr {
    /// "subsignature N matched"
    Sub(u8),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

impl Expr {
    /// Evaluate against the set of subsignature indices that matched.
    pub fn eval(&self, matched: &[bool]) -> bool {
        match self {
            Expr::Sub(i) => matched.get(*i as usize).copied().unwrap_or(false),
            Expr::And(a, b) => a.eval(matched) && b.eval(matched),
            Expr::Or(a, b) => a.eval(matched) || b.eval(matched),
        }
    }

    /// Highest subsignature index referenced, for validation.
    pub fn max_index(&self) -> u8 {
        match self {
            Expr::Sub(i) => *i,
            Expr::And(a, b) | Expr::Or(a, b) => a.max_index().max(b.max_index()),
        }
    }

    /// Render back to ClamAV's syntax. Used to store the expression compactly
    /// in the index and to make failures readable.
    pub fn to_source(&self) -> String {
        match self {
            Expr::Sub(i) => i.to_string(),
            Expr::And(a, b) => format!("({}&{})", a.to_source(), b.to_source()),
            Expr::Or(a, b) => format!("({}|{})", a.to_source(), b.to_source()),
        }
    }
}

/// Why a rule could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    /// The expression uses match counts (`0>2`), ranges, or similar.
    Expression,
    /// A subsignature uses PCRE, wildcards or byte ranges.
    Subsignature,
    /// Structurally malformed.
    Malformed,
    /// Literal patterns too short to be worth matching.
    TooShort,
}

/// A logical signature this engine can evaluate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalSig {
    pub name: String,
    /// ClamAV target type; 0 means any.
    pub target: u8,
    pub expr: Expr,
    /// Literal patterns, indexed as the expression refers to them.
    pub subsigs: Vec<Vec<u8>>,
}

/// Recursive-descent parser for the supported expression subset.
///
/// Grammar, tightest binding last:
/// ```text
/// or     := and ('|' and)*
/// and    := factor ('&' factor)*
/// factor := NUMBER | '(' or ')'
/// ```
struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(s: &'a str) -> Self {
        Self { bytes: s.as_bytes(), pos: 0 }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_ws();
        self.bytes.get(self.pos).copied()
    }

    fn parse(mut self) -> Option<Expr> {
        let e = self.parse_or()?;
        self.skip_ws();
        // Anything left over means an operator we do not implement.
        if self.pos != self.bytes.len() {
            return None;
        }
        Some(e)
    }

    fn parse_or(&mut self) -> Option<Expr> {
        let mut left = self.parse_and()?;
        while self.peek() == Some(b'|') {
            self.pos += 1;
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Some(left)
    }

    fn parse_and(&mut self) -> Option<Expr> {
        let mut left = self.parse_factor()?;
        while self.peek() == Some(b'&') {
            self.pos += 1;
            let right = self.parse_factor()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Some(left)
    }

    fn parse_factor(&mut self) -> Option<Expr> {
        match self.peek()? {
            b'(' => {
                self.pos += 1;
                let inner = self.parse_or()?;
                if self.peek()? != b')' {
                    return None;
                }
                self.pos += 1;
                Some(inner)
            }
            c if c.is_ascii_digit() => {
                let start = self.pos;
                while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
                    self.pos += 1;
                }
                let text = std::str::from_utf8(&self.bytes[start..self.pos]).ok()?;
                text.parse::<u8>().ok().map(Expr::Sub)
            }
            _ => None,
        }
    }
}

/// Parse a logical expression, or `None` if it uses anything unsupported.
pub fn parse_expression(src: &str) -> Option<Expr> {
    Parser::new(src).parse()
}

/// True if a subsignature body is anything other than plain hex.
fn has_unsupported_syntax(body: &str) -> bool {
    body.bytes()
        .any(|b| matches!(b, b'?' | b'*' | b'{' | b'}' | b'(' | b')' | b'[' | b']' | b'|' | b'!'))
        || !body.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Default minimum literal length for a rule with several subsignatures.
///
/// Co-occurrence carries the specificity here, so this is lower than the floor
/// a lone literal needs. It is also the main lever on resident memory - see
/// [`crate::config::ScanLimits::min_logical_pattern_bytes`].
pub const MIN_MULTI_SUBSIG_LEN: usize = 8;

/// Minimum literal length for a rule with exactly one subsignature, which is
/// effectively an `.ndb` pattern wearing a different hat.
pub const MIN_SINGLE_SUBSIG_LEN: usize = 16;

/// Parse one `.ldb` line using the default length floor.
pub fn parse_line(line: &str) -> Result<LogicalSig, Unsupported> {
    parse_line_with(line, MIN_MULTI_SUBSIG_LEN)
}

/// Parse one `.ldb` line, with an explicit floor for multi-part rules.
pub fn parse_line_with(line: &str, min_multi: usize) -> Result<LogicalSig, Unsupported> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.is_empty() || line.starts_with('#') {
        return Err(Unsupported::Malformed);
    }

    let parts: Vec<&str> = line.split(';').collect();
    if parts.len() < 4 {
        return Err(Unsupported::Malformed);
    }

    let name = parts[0].trim();
    if name.is_empty() {
        return Err(Unsupported::Malformed);
    }

    // Target description block: `Engine:81-255,Target:3,...`. Only the target
    // type is used; engine levels gate on ClamAV versions, not on us.
    let target = parts[1]
        .split(',')
        .find_map(|kv| kv.strip_prefix("Target:"))
        .and_then(|v| v.split('-').next())
        .and_then(|v| v.trim().parse::<u8>().ok())
        .unwrap_or(0);

    let expr = parse_expression(parts[2]).ok_or(Unsupported::Expression)?;

    let mut subsigs = Vec::new();
    for raw in &parts[3..] {
        // A subsignature may carry an offset prefix, e.g. `0:4d5a` or `EP+7:..`.
        // Offsets other than "anywhere" need a PE-aware matcher, so any
        // prefixed subsignature is treated as unsupported rather than silently
        // matched in the wrong place.
        let body = match raw.split_once(':') {
            Some(_) => return Err(Unsupported::Subsignature),
            None => *raw,
        };
        if body.is_empty() || has_unsupported_syntax(body) {
            return Err(Unsupported::Subsignature);
        }
        let bytes = hex::decode(body).map_err(|_| Unsupported::Subsignature)?;
        subsigs.push(bytes);
    }

    if subsigs.is_empty() {
        return Err(Unsupported::Malformed);
    }
    // The expression must not refer to a subsignature that does not exist.
    if expr.max_index() as usize >= subsigs.len() {
        return Err(Unsupported::Malformed);
    }

    let floor = if subsigs.len() == 1 {
        MIN_SINGLE_SUBSIG_LEN
    } else {
        min_multi
    };
    if subsigs.iter().any(|s| s.len() < floor) {
        return Err(Unsupported::TooShort);
    }

    Ok(LogicalSig { name: name.to_string(), target, expr, subsigs })
}

/// Tally of a parse run over a whole `.ldb` file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LdbStats {
    pub accepted: u64,
    pub unsupported_expression: u64,
    pub unsupported_subsignature: u64,
    pub too_short: u64,
    pub malformed: u64,
}

impl LdbStats {
    pub fn total_seen(&self) -> u64 {
        self.accepted
            + self.unsupported_expression
            + self.unsupported_subsignature
            + self.too_short
            + self.malformed
    }

    pub fn merge(&mut self, o: LdbStats) {
        self.accepted += o.accepted;
        self.unsupported_expression += o.unsupported_expression;
        self.unsupported_subsignature += o.unsupported_subsignature;
        self.too_short += o.too_short;
        self.malformed += o.malformed;
    }
}

/// Parse a whole `.ldb` file using the default floor.
pub fn parse_ldb(data: &[u8], emit: impl FnMut(LogicalSig)) -> LdbStats {
    parse_ldb_with(data, MIN_MULTI_SUBSIG_LEN, emit)
}

/// Parse a whole `.ldb` file, handing each usable rule to `emit`.
pub fn parse_ldb_with(
    data: &[u8],
    min_multi: usize,
    mut emit: impl FnMut(LogicalSig),
) -> LdbStats {
    let mut stats = LdbStats::default();
    for raw in data.split(|&b| b == b'\n') {
        let Ok(line) = std::str::from_utf8(raw) else {
            stats.malformed += 1;
            continue;
        };
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_line_with(line, min_multi) {
            Ok(sig) => {
                stats.accepted += 1;
                emit(sig);
            }
            Err(Unsupported::Expression) => stats.unsupported_expression += 1,
            Err(Unsupported::Subsignature) => stats.unsupported_subsignature += 1,
            Err(Unsupported::TooShort) => stats.too_short += 1,
            Err(Unsupported::Malformed) => stats.malformed += 1,
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_conjunction() {
        let e = parse_expression("0&1&2").unwrap();
        assert!(e.eval(&[true, true, true]));
        assert!(!e.eval(&[true, true, false]));
        assert!(!e.eval(&[false, true, true]));
    }

    #[test]
    fn parses_a_disjunction() {
        let e = parse_expression("0|1").unwrap();
        assert!(e.eval(&[true, false]));
        assert!(e.eval(&[false, true]));
        assert!(!e.eval(&[false, false]));
    }

    #[test]
    fn and_binds_tighter_than_or() {
        // `0|1&2` is `0 or (1 and 2)`. Getting this backwards would make rules
        // fire on a single subsignature.
        let e = parse_expression("0|1&2").unwrap();
        assert!(e.eval(&[true, false, false]), "0 alone should satisfy it");
        assert!(e.eval(&[false, true, true]));
        assert!(!e.eval(&[false, true, false]), "1 alone must not satisfy it");
    }

    #[test]
    fn honours_parentheses() {
        let e = parse_expression("(0|1)&2").unwrap();
        assert!(!e.eval(&[true, false, false]), "2 is required");
        assert!(e.eval(&[true, false, true]));
        assert!(e.eval(&[false, true, true]));
    }

    #[test]
    fn tolerates_whitespace() {
        let e = parse_expression(" 0 & 1 ").unwrap();
        assert!(e.eval(&[true, true]));
    }

    #[test]
    fn rejects_expressions_we_do_not_implement() {
        // Match counts and ranges. Accepting these by ignoring the operator
        // would turn "matched more than 200 times" into "matched at all".
        assert!(parse_expression("0 & 1 > 200").is_none());
        assert!(parse_expression("0=2").is_none());
        assert!(parse_expression("0,1").is_none());
        assert!(parse_expression("").is_none());
        assert!(parse_expression("&0").is_none());
        assert!(parse_expression("(0&1").is_none());
        assert!(parse_expression("0&").is_none());
    }

    #[test]
    fn parses_a_real_rule() {
        let line = "Js.Trojan.Agent-1553495;Engine:81-255,Target:3;0&1&2;\
                    3c736372697074747970653d22746578742f6a617661736372697074227372633d;\
                    6a71756572792e6d696e2e706870;73657474696d656f7574283130293b";
        let sig = parse_line(line).unwrap();
        assert_eq!(sig.name, "Js.Trojan.Agent-1553495");
        assert_eq!(sig.target, 3);
        assert_eq!(sig.subsigs.len(), 3);
        assert!(sig.subsigs[1].starts_with(b"jquery.min.php"));
        assert!(sig.expr.eval(&[true, true, true]));
        assert!(!sig.expr.eval(&[true, true, false]));
    }

    #[test]
    fn rejects_a_rule_with_a_count_expression() {
        let line = "Js.Ransomware.Locky-30743;Engine:51-255,Target:7;0 & 1 > 200;\
                    222e73706c697428276d73656d736527293b;6d73656d7365";
        assert_eq!(parse_line(line), Err(Unsupported::Expression));
    }

    #[test]
    fn rejects_subsignatures_with_wildcards_or_ranges() {
        for body in ["4d5a??00aabbccdd", "4d5a{2-6}aabbccdd", "4d5a*aabbccdd", "(a|b)ccdd"] {
            let line = format!("X;Target:0;0;{body}");
            assert_eq!(
                parse_line(&line),
                Err(Unsupported::Subsignature),
                "{body} should be refused"
            );
        }
    }

    #[test]
    fn rejects_subsignatures_with_an_offset_prefix() {
        // `EP+7:` and friends need a PE-aware matcher. Matching the pattern
        // anywhere instead would be matching it in the wrong place.
        let line = "X;Target:1;0;EP+7:4d5a9000aabbccdd11223344";
        assert_eq!(parse_line(line), Err(Unsupported::Subsignature));
        let line = "X;Target:1;0;0:4d5a9000aabbccdd11223344";
        assert_eq!(parse_line(line), Err(Unsupported::Subsignature));
    }

    #[test]
    fn a_lone_short_literal_is_refused() {
        // One 6-byte pattern would match constantly. With no co-occurrence to
        // add specificity it is held to the same floor as an .ndb literal.
        let line = "X;Target:0;0;4d5a9000aabb";
        assert_eq!(parse_line(line), Err(Unsupported::TooShort));
    }

    #[test]
    fn short_literals_are_allowed_when_several_must_co_occur() {
        // Three 6-byte patterns together are far more specific than one
        // 16-byte pattern, which is the entire point of logical signatures.
        let line = "X;Target:0;0&1&2;4d5a9000aabb;112233445566;778899aabbcc";
        let sig = parse_line_with(line, 4).unwrap();
        assert_eq!(sig.subsigs.len(), 3);
    }

    #[test]
    fn the_floor_is_configurable_and_trades_coverage_for_memory() {
        // Six-byte patterns: accepted at a floor of 4, refused at 8. This is
        // the dial that took resident memory from ~520 MB to ~300 MB against
        // the real database.
        let line = "X;Target:0;0&1;4d5a9000aabb;112233445566";
        assert!(parse_line_with(line, 4).is_ok());
        assert_eq!(parse_line_with(line, 8), Err(Unsupported::TooShort));
    }

    #[test]
    fn rejects_an_expression_referring_to_a_missing_subsignature() {
        let line = "X;Target:0;0&7;4d5a9000aabbccdd11223344";
        assert_eq!(parse_line(line), Err(Unsupported::Malformed));
    }

    #[test]
    fn rejects_structurally_broken_lines() {
        assert_eq!(parse_line("only;two;parts"), Err(Unsupported::Malformed));
        assert_eq!(parse_line(""), Err(Unsupported::Malformed));
        assert_eq!(parse_line(";Target:0;0;aabb"), Err(Unsupported::Malformed));
    }

    #[test]
    fn defaults_to_target_any_when_absent() {
        let line = "X;Engine:51-255;0;4d5a9000aabbccdd1122334455667788";
        assert_eq!(parse_line(line).unwrap().target, 0);
    }

    #[test]
    fn parsing_a_file_tallies_every_outcome() {
        let data = b"Good;Target:0;0&1;4d5a9000aabb;112233445566\n\
                     Counted;Target:0;0 & 1 > 200;4d5a9000aabb;112233445566\n\
                     Wild;Target:0;0;4d5a??00aabbccdd11223344\n\
                     Short;Target:0;0;4d5aaabb\n\
                     broken\n\
                     \n\
                     # a comment\n";
        let mut out = Vec::new();
        let stats = parse_ldb_with(data, 4, |s| out.push(s));

        assert_eq!(stats.accepted, 1);
        assert_eq!(stats.unsupported_expression, 1);
        assert_eq!(stats.unsupported_subsignature, 1);
        assert_eq!(stats.too_short, 1);
        assert_eq!(stats.malformed, 1);
        assert_eq!(stats.total_seen(), 5, "comments and blanks are not counted");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "Good");
    }

    #[test]
    fn expressions_round_trip_through_source() {
        for src in ["0", "0&1", "0|1", "(0|1)&2", "0&1&2&3"] {
            let e = parse_expression(src).unwrap();
            let round = parse_expression(&e.to_source()).unwrap();
            // The rendered form is fully parenthesised, so compare behaviour
            // rather than text.
            for mask in 0..16u8 {
                let m: Vec<bool> = (0..4).map(|i| mask & (1 << i) != 0).collect();
                assert_eq!(e.eval(&m), round.eval(&m), "{src} differed on mask {mask}");
            }
        }
    }
}
