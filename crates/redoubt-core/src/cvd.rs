//! Reader for ClamAV database containers (`.cvd` and `.cld`).
//!
//! A CVD is a 512-byte ASCII header followed by a gzipped tar. A CLD is the
//! same header followed by a *plain* tar - that is the only difference, and
//! getting it wrong produces a confusing "not a gzip stream" error, so we
//! sniff the magic rather than trusting the extension.
//!
//! The tar holds the actual signature files (`main.hdb`, `daily.hsb`, ...),
//! which [`crate::sigs`] knows how to parse.

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

/// Length of the fixed-size ASCII header at the front of every container.
const HEADER_LEN: usize = 512;
const HEADER_MAGIC: &str = "ClamAV-VDB:";

/// Metadata from the container header.
///
/// The digital signature (`dsig`) is captured but not verified: verification
/// needs ClamAV's RSA public key and their custom base-64 alphabet. Until that
/// is implemented, integrity rests on fetching over HTTPS from the official
/// mirror, which is noted here so the gap is not mistaken for a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CvdHeader {
    /// Human-readable build time, e.g. `23 Aug 2026 08-15 -0400`.
    pub build_time: String,
    /// Monotonic database version. This is what an update check compares.
    pub version: u32,
    /// Number of signatures the builder claims are inside.
    pub signature_count: u32,
    /// Minimum ClamAV functionality level. We record it for display only.
    pub functionality_level: u32,
    /// MD5 of the tar payload, as hex.
    pub md5: String,
    /// RSA signature over the payload. Not currently verified - see above.
    pub dsig: String,
    pub builder: String,
    /// Build time as a Unix timestamp.
    pub build_epoch: u64,
}

impl CvdHeader {
    /// Parse the 512-byte header block.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < HEADER_LEN {
            bail!("container header truncated: {} bytes, need {HEADER_LEN}", raw.len());
        }
        let text = std::str::from_utf8(&raw[..HEADER_LEN])
            .context("container header is not valid UTF-8")?;
        if !text.starts_with(HEADER_MAGIC) {
            bail!("not a ClamAV container: header does not start with {HEADER_MAGIC:?}");
        }

        // Trailing space padding fills the block out to 512 bytes.
        let fields: Vec<&str> = text.trim_end().split(':').collect();
        if fields.len() < 9 {
            bail!("container header has {} fields, expected at least 9", fields.len());
        }

        let parse_num = |idx: usize, what: &str| -> Result<u64> {
            fields[idx]
                .trim()
                .parse::<u64>()
                .with_context(|| format!("container header field {idx} ({what}) = {:?}", fields[idx]))
        };

        Ok(Self {
            build_time: fields[1].trim().to_string(),
            version: parse_num(2, "version")? as u32,
            signature_count: parse_num(3, "signature count")? as u32,
            functionality_level: parse_num(4, "functionality level")? as u32,
            md5: fields[5].trim().to_string(),
            dsig: fields[6].trim().to_string(),
            builder: fields[7].trim().to_string(),
            build_epoch: parse_num(8, "build epoch")?,
        })
    }
}

/// Whether the payload after the header is gzipped.
fn payload_is_gzip(first_two: &[u8]) -> bool {
    first_two.len() >= 2 && first_two[0] == 0x1f && first_two[1] == 0x8b
}

/// Read just the header of a container. Cheap - touches 512 bytes.
///
/// Used by the updater to compare the on-disk version against the mirror's
/// without decompressing a 200 MB payload.
pub fn read_header(path: &Path) -> Result<CvdHeader> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let mut buf = [0u8; HEADER_LEN];
    file.read_exact(&mut buf)
        .with_context(|| format!("reading header of {}", path.display()))?;
    CvdHeader::parse(&buf)
}

/// One signature file extracted from a container.
pub struct CvdEntry {
    /// Base name inside the tar, e.g. `daily.hsb`.
    pub name: String,
    pub data: Vec<u8>,
}

impl CvdEntry {
    /// Lowercase extension, e.g. `hsb`. Empty when the name has none.
    pub fn extension(&self) -> &str {
        self.name.rsplit_once('.').map(|(_, ext)| ext).unwrap_or("")
    }
}

/// Open a container and hand each tar entry to `visit`.
///
/// Streaming rather than collecting: `main.cvd` expands to well over a
/// gigabyte of text, and holding all of it plus the parsed index at once is
/// what makes naive implementations of this need 4 GB of RAM.
pub fn for_each_entry<F>(path: &Path, mut visit: F) -> Result<CvdHeader>
where
    F: FnMut(CvdEntry) -> Result<()>,
{
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("opening {}", path.display()))?;

    let mut header_buf = [0u8; HEADER_LEN];
    file.read_exact(&mut header_buf)
        .with_context(|| format!("reading header of {}", path.display()))?;
    let header = CvdHeader::parse(&header_buf)?;

    // Sniff two bytes to decide gzip vs plain tar, then rewind to the payload.
    let mut magic = [0u8; 2];
    let sniffed = file.read(&mut magic).unwrap_or(0);
    file.seek(SeekFrom::Start(HEADER_LEN as u64))
        .context("seeking to container payload")?;

    let reader = BufReader::with_capacity(1 << 20, file);
    if payload_is_gzip(&magic[..sniffed]) {
        visit_tar(tar::Archive::new(GzDecoder::new(reader)), &mut visit)?;
    } else {
        visit_tar(tar::Archive::new(reader), &mut visit)?;
    }

    Ok(header)
}

fn visit_tar<R: Read, F>(mut archive: tar::Archive<R>, visit: &mut F) -> Result<()>
where
    F: FnMut(CvdEntry) -> Result<()>,
{
    for entry in archive.entries().context("reading container tar")? {
        let mut entry = entry.context("reading container tar entry")?;
        let name = entry
            .path()
            .context("container tar entry has an unreadable path")?
            .to_string_lossy()
            .into_owned();

        // Guard against a malicious container writing outside its own tree.
        // We never extract to disk, but the name reaches logs and the UI.
        if name.contains("..") || name.contains('/') || name.contains('\\') {
            tracing::warn!(entry = %name, "skipping container entry with a suspicious name");
            continue;
        }

        let mut data = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut data)
            .with_context(|| format!("reading container entry {name}"))?;

        visit(CvdEntry { name, data })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "ClamAV-VDB:23 Aug 2026 08-15 -0400:27100:2000000:90:\
                          a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:sig-goes-here:raynman:1756000000";

    fn padded(s: &str) -> Vec<u8> {
        let mut v = s.as_bytes().to_vec();
        v.resize(HEADER_LEN, b' ');
        v
    }

    #[test]
    fn parses_a_well_formed_header() {
        let h = CvdHeader::parse(&padded(SAMPLE)).unwrap();
        assert_eq!(h.version, 27100);
        assert_eq!(h.signature_count, 2_000_000);
        assert_eq!(h.functionality_level, 90);
        assert_eq!(h.md5, "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6");
        assert_eq!(h.builder, "raynman");
        assert_eq!(h.build_epoch, 1_756_000_000);
    }

    #[test]
    fn rejects_a_non_clamav_file() {
        let err = CvdHeader::parse(&padded("PK\x03\x04 this is a zip")).unwrap_err();
        assert!(err.to_string().contains("not a ClamAV container"), "{err}");
    }

    #[test]
    fn rejects_a_truncated_header() {
        let err = CvdHeader::parse(b"ClamAV-VDB:short").unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");
    }

    #[test]
    fn rejects_a_header_with_too_few_fields() {
        let err = CvdHeader::parse(&padded("ClamAV-VDB:23 Aug 2026:27100")).unwrap_err();
        assert!(err.to_string().contains("expected at least 9"), "{err}");
    }

    #[test]
    fn detects_gzip_magic() {
        assert!(payload_is_gzip(&[0x1f, 0x8b]));
        assert!(!payload_is_gzip(b"us"));   // plain tar (ustar)
        assert!(!payload_is_gzip(&[0x1f]));          // too short to tell
    }

    #[test]
    fn entry_extension_is_extracted() {
        let e = CvdEntry { name: "daily.hsb".into(), data: Vec::new() };
        assert_eq!(e.extension(), "hsb");
        let e = CvdEntry { name: "COPYING".into(), data: Vec::new() };
        assert_eq!(e.extension(), "");
    }
}
