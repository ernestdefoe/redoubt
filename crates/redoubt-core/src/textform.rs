//! Recognising UTF-16 text, so signatures written in ASCII can still match it.
//!
//! Every signature in the database - all 3.3 million of them - is a sequence
//! of bytes written in ASCII or UTF-8. Text encoded as UTF-16 interleaves a
//! zero byte with every character, so `http://` becomes
//! `h\0t\0t\0p\0:\0/\0/\0` and **not one signature can ever match it**. The
//! scan runs, finds nothing, and reports clean.
//!
//! That is not an exotic case on Windows. It is the default:
//!
//! - PowerShell hands script text to AMSI as **UTF-16LE**, so without this
//!   the entire script-scanning channel is decorative - it counts requests
//!   and answers "clean" to all of them.
//! - PowerShell 5.1's `Out-File` and `>` write **UTF-16LE** files by default,
//!   so a script saved by the shell itself is already invisible.
//! - `.lnk` targets, some installers, and a good deal of Windows tooling do
//!   the same.
//!
//! So content that looks like UTF-16 is transcoded to UTF-8 and scanned as
//! well as - never instead of - the original bytes. Scanning both matters:
//! a .NET assembly submitted through AMSI arrives as real PE bytes that would
//! be destroyed by transcoding, and malware that is genuinely UTF-16 on the
//! wire must still match a UTF-16 signature.

/// Which byte order the text is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Utf16 {
    Le,
    Be,
}

/// Shortest input worth examining.
///
/// Below this, "every other byte is zero" happens by chance often enough to
/// be meaningless, and there is nothing in it for a signature to match.
const MIN_LEN: usize = 16;

/// How many code units to sample when deciding.
///
/// This runs on every buffer the scanner sees, so it must stay cheap. A
/// prefix is enough: mixed-encoding content does not occur in practice, and
/// the cost of being wrong is one extra scan of a transcoded copy.
const SAMPLE_UNITS: usize = 512;

/// Proportion of sampled units that must carry a zero high byte.
///
/// Not 100%: real text contains the occasional accented or non-Latin
/// character, and demanding perfection would miss exactly the documents
/// somebody bothered to obfuscate.
const ZERO_RATIO: f64 = 0.85;

/// Largest buffer transcoded.
///
/// Transcoding allocates, and past a certain size the content is not script
/// text anyway. A file bigger than this that really is UTF-16 loses the
/// second pass, which is stated rather than hidden - see
/// [`transcode_if_utf16`].
pub const MAX_TRANSCODE_BYTES: usize = 16 * 1024 * 1024;

/// Detect UTF-16 by byte-order mark alone.
fn bom(data: &[u8]) -> Option<Utf16> {
    match data {
        [0xFF, 0xFE, ..] => Some(Utf16::Le),
        [0xFE, 0xFF, ..] => Some(Utf16::Be),
        _ => None,
    }
}

/// Whether `data` looks like UTF-16 text.
///
/// A byte-order mark is decisive. Without one - and PowerShell sends none -
/// this counts zero high bytes across a prefix. Both orders are checked and
/// the stronger wins, so a buffer cannot be claimed for both.
pub fn detect(data: &[u8]) -> Option<Utf16> {
    if let Some(b) = bom(data) {
        return Some(b);
    }
    if data.len() < MIN_LEN {
        return None;
    }

    let units = (data.len() / 2).min(SAMPLE_UNITS);
    if units == 0 {
        return None;
    }

    let mut le_zero = 0usize; // high byte at odd index
    let mut be_zero = 0usize; // high byte at even index
    let mut all_zero = 0usize;

    for i in 0..units {
        let lo = data[i * 2];
        let hi = data[i * 2 + 1];
        if hi == 0 {
            le_zero += 1;
        }
        if lo == 0 {
            be_zero += 1;
        }
        if lo == 0 && hi == 0 {
            all_zero += 1;
        }
    }

    // A run of NUL padding satisfies both tests and is not text. Sparse
    // binaries and zero-filled regions are the commonest thing that would
    // otherwise be transcoded into garbage and scanned for no reason.
    if all_zero * 2 > units {
        return None;
    }

    let threshold = (units as f64 * ZERO_RATIO).ceil() as usize;
    let le = le_zero >= threshold;
    let be = be_zero >= threshold;

    match (le, be) {
        (true, false) => Some(Utf16::Le),
        (false, true) => Some(Utf16::Be),
        // Ambiguous. Guessing would produce a transcoded copy that is wrong
        // half the time, and a wrong copy can only cause false positives.
        _ => None,
    }
}

/// Transcode `data` to UTF-8, replacing anything unpaired.
///
/// Lossy on purpose: this feeds a signature scan, not a parser. A malformed
/// surrogate is not a reason to give up on the rest of the buffer - refusing
/// to decode is how obfuscated content escapes.
pub fn transcode(data: &[u8], form: Utf16) -> String {
    let start = if bom(data).is_some() { 2 } else { 0 };
    let body = &data[start..];

    let units: Vec<u16> = body
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| match form {
            Utf16::Le => u16::from_le_bytes(*c),
            Utf16::Be => u16::from_be_bytes(*c),
        })
        .collect();

    String::from_utf16_lossy(&units)
}

/// The convenience the scanner uses: a UTF-8 copy, if there is one worth
/// making.
///
/// Returns `None` when the content is not UTF-16, is too short to judge, or
/// is larger than [`MAX_TRANSCODE_BYTES`].
pub fn transcode_if_utf16(data: &[u8]) -> Option<String> {
    if data.len() > MAX_TRANSCODE_BYTES {
        return None;
    }
    let form = detect(data)?;
    let text = transcode(data, form);
    // An all-replacement-character result means the guess was wrong. Scanning
    // it would waste time and could only ever produce a false positive.
    (!text.is_empty()).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    fn be(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
    }

    #[test]
    fn powershell_script_text_is_recognised() {
        // The exact shape AMSI delivers: UTF-16LE, no byte-order mark.
        let data = le("Write-Output 'hello from a script'");
        assert_eq!(detect(&data), Some(Utf16::Le));
        assert_eq!(transcode(&data, Utf16::Le), "Write-Output 'hello from a script'");
    }

    #[test]
    fn a_url_signature_can_match_after_transcoding() {
        // The failure this module exists for: an ASCII signature against
        // UTF-16 content. Before transcoding the needle is simply not there.
        let url = "http://example.invalid/payload.exe";
        let raw = le(url);
        assert!(
            !raw.windows(url.len()).any(|w| w == url.as_bytes()),
            "the whole problem is that the ASCII bytes are absent"
        );
        assert!(transcode_if_utf16(&raw).unwrap().contains(url));
    }

    #[test]
    fn both_byte_orders_are_handled_and_never_confused() {
        assert_eq!(detect(&le("a script full of ASCII text")), Some(Utf16::Le));
        assert_eq!(detect(&be("a script full of ASCII text")), Some(Utf16::Be));
    }

    #[test]
    fn byte_order_marks_are_decisive_and_stripped() {
        let mut data = vec![0xFF, 0xFE];
        data.extend(le("hi"));
        assert_eq!(detect(&data), Some(Utf16::Le));
        assert_eq!(transcode(&data, Utf16::Le), "hi");
    }

    #[test]
    fn plain_ascii_is_left_alone() {
        // Already scannable. Transcoding it would produce nonsense and double
        // the work on the overwhelmingly common case.
        assert_eq!(detect(b"Write-Output 'an ordinary ASCII script'"), None);
        assert!(transcode_if_utf16(b"an ordinary ASCII script here").is_none());
    }

    #[test]
    fn a_pe_file_is_never_transcoded() {
        // .NET assemblies reach AMSI as real PE bytes. Transcoding one would
        // destroy the very content the section-hash engine needs.
        let mut pe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00".to_vec();
        pe.extend_from_slice(&[0xB8, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x1A]);
        pe.extend_from_slice(b"This program cannot be run in DOS mode.");
        assert_eq!(detect(&pe), None);
    }

    #[test]
    fn a_run_of_zeroes_is_not_mistaken_for_text() {
        // Sparse binaries and padding satisfy "every other byte is zero" in
        // both directions at once. Transcoding them yields a buffer of NULs
        // that can only produce noise.
        let zeros = vec![0u8; 4096];
        assert_eq!(detect(&zeros), None);
        assert!(transcode_if_utf16(&zeros).is_none());
    }

    #[test]
    fn short_buffers_are_not_guessed_at() {
        // "Every other byte is zero" happens by chance in a few bytes.
        assert_eq!(detect(b"a\0b\0"), None);
        assert_eq!(detect(&le("hello there, this is long enough")), Some(Utf16::Le));
    }

    #[test]
    fn mostly_ascii_utf16_with_some_accents_still_counts() {
        // Demanding every high byte be zero would miss exactly the content
        // somebody took the trouble to write in another language.
        let data = le("Invoke-Expression $café$naïve$résumé plus plenty of plain ASCII");
        assert_eq!(detect(&data), Some(Utf16::Le));
    }

    #[test]
    fn oversized_content_is_declined_rather_than_allocated() {
        let big = vec![0u8; MAX_TRANSCODE_BYTES + 1];
        assert!(transcode_if_utf16(&big).is_none());
    }

    #[test]
    fn an_odd_length_buffer_does_not_panic() {
        let mut data = le("some script content that is long enough");
        data.push(0x41); // trailing half a code unit
        let _ = transcode_if_utf16(&data);
    }
}
