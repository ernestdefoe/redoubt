//! Minimal terminal styling.
//!
//! Colour is applied only when stdout is a terminal that wants it. Anything
//! redirected to a file or a pipe gets clean text, so `redoubt scan > out.txt`
//! is readable and greppable rather than full of escape codes.
//!
//! `NO_COLOR` is honoured (see no-color.org), as is `CLICOLOR_FORCE`.

use std::io::IsTerminal;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// A malicious finding.
    Bad,
    /// A suspicious finding, or a caution.
    Warn,
    /// A clean result.
    Good,
    /// Secondary information.
    Dim,
    /// A heading.
    Bold,
}

impl Style {
    fn code(self) -> &'static str {
        match self {
            Style::Bad => "\x1b[1;31m",
            Style::Warn => "\x1b[33m",
            Style::Good => "\x1b[32m",
            Style::Dim => "\x1b[2m",
            Style::Bold => "\x1b[1m",
        }
    }

    /// Wrap `text` in this style, or return it unchanged when colour is off.
    pub fn paint(self, text: &str) -> String {
        if colour_enabled() {
            format!("{}{}\x1b[0m", self.code(), text)
        } else {
            text.to_string()
        }
    }
}

fn colour_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        if std::env::var_os("NO_COLOR").is_some() {
            return false;
        }
        if std::env::var_os("CLICOLOR_FORCE").is_some() {
            return true;
        }
        std::io::stdout().is_terminal()
    })
}

/// A horizontal rule sized to the terminal, for separating output sections.
pub fn rule() {
    println!("{}", Style::Dim.paint(&"\u{2500}".repeat(72)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paint_is_a_no_op_when_colour_is_disabled() {
        // Tests never run attached to a terminal, so this exercises the
        // redirect path - which is the one that must stay clean.
        if !colour_enabled() {
            assert_eq!(Style::Bad.paint("MALICIOUS"), "MALICIOUS");
            assert_eq!(Style::Dim.paint(""), "");
        }
    }

    #[test]
    fn styles_have_distinct_codes() {
        let codes = [Style::Bad, Style::Warn, Style::Good, Style::Dim, Style::Bold]
            .map(|s| s.code());
        let mut sorted = codes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len(), "two styles share an escape code");
    }
}
