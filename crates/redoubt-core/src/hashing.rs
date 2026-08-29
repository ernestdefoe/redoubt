//! File hashing.
//!
//! All three digests are computed in a single pass over the bytes. The file is
//! read once, so hashing a 100 MB binary costs one traversal rather than
//! three - which matters when the scanner is doing this on every file write.

use sha2::Digest;
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;

use crate::sigs::HashValue;
use crate::verdict::FileIdentity;

/// The three digests ClamAV signature formats can reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Digests {
    pub md5: [u8; 16],
    pub sha1: [u8; 20],
    pub sha256: [u8; 32],
}

impl Digests {
    pub fn md5_value(&self) -> HashValue {
        HashValue::Md5(self.md5)
    }
    pub fn sha1_value(&self) -> HashValue {
        HashValue::Sha1(self.sha1)
    }
    pub fn sha256_value(&self) -> HashValue {
        HashValue::Sha256(self.sha256)
    }

    /// All three, in the order a scanner should try them: strongest first, so
    /// a SHA-256 signature wins over a weaker MD5 one for the same bytes.
    pub fn all(&self) -> [HashValue; 3] {
        [self.sha256_value(), self.sha1_value(), self.md5_value()]
    }

    pub fn to_identity(self, size: u64) -> FileIdentity {
        FileIdentity {
            size,
            md5: Some(hex::encode(self.md5)),
            sha1: Some(hex::encode(self.sha1)),
            sha256: Some(hex::encode(self.sha256)),
        }
    }
}

/// Hash a byte slice with all three algorithms in one pass.
pub fn digest_bytes(data: &[u8]) -> Digests {
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();

    // Chunked so each digest's input stays in cache rather than streaming the
    // whole file through three times.
    for chunk in data.chunks(64 * 1024) {
        md5.update(chunk);
        sha1.update(chunk);
        sha256.update(chunk);
    }

    Digests {
        md5: md5.finalize().into(),
        sha1: sha1.finalize().into(),
        sha256: sha256.finalize().into(),
    }
}

/// Hash a stream without holding it in memory.
///
/// Used for files above the pattern-scan size limit: they still get a hash
/// verdict, but a 4 GB disk image is never buffered to get one.
pub fn digest_reader<R: std::io::Read>(mut reader: R) -> std::io::Result<(Digests, u64)> {
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();

    let mut buf = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        md5.update(&buf[..n]);
        sha1.update(&buf[..n]);
        sha256.update(&buf[..n]);
        total += n as u64;
    }

    Ok((
        Digests {
            md5: md5.finalize().into(),
            sha1: sha1.finalize().into(),
            sha256: sha256.finalize().into(),
        },
        total,
    ))
}

/// MD5 of a slice, for PE section hashing where only MD5 is needed.
pub fn md5_bytes(data: &[u8]) -> HashValue {
    HashValue::Md5(Md5::digest(data).into())
}

/// SHA-256 of a slice.
pub fn sha256_bytes(data: &[u8]) -> HashValue {
    HashValue::Sha256(Sha256::digest(data).into())
}

/// Shannon entropy in bits per byte, 0.0 to 8.0.
///
/// The packing heuristic reads this: compiled code sits around 6.0-6.5, while
/// compressed or encrypted data pushes past 7.5. Note that legitimate
/// installers and embedded media hit those numbers too, which is why the
/// heuristic can only ever produce `Suspicious`.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    -counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            p * p.log2()
        })
        .sum::<f64>()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The EICAR test string - the industry-standard harmless test file.
    const EICAR: &[u8] =
        br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

    #[test]
    fn digests_match_known_values() {
        // These are the published EICAR digests; if the one-pass chunking ever
        // breaks, this catches it immediately.
        let d = digest_bytes(EICAR);
        assert_eq!(EICAR.len(), 68);
        assert_eq!(hex::encode(d.md5), "44d88612fea8a8f36de82e1278abb02f");
        assert_eq!(hex::encode(d.sha1), "3395856ce81f2b7382dee72602f798b642f14140");
        assert_eq!(
            hex::encode(d.sha256),
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        );
    }

    #[test]
    fn chunking_does_not_change_the_result() {
        // Bigger than the 64 KiB chunk size, so the loop runs many times.
        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let chunked = digest_bytes(&big);

        use sha2::Digest;
        let direct_sha256: [u8; 32] = sha2::Sha256::digest(&big).into();
        assert_eq!(chunked.sha256, direct_sha256);
    }

    #[test]
    fn empty_input_hashes_to_the_known_empty_digests() {
        let d = digest_bytes(b"");
        assert_eq!(hex::encode(d.md5), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            hex::encode(d.sha256),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn strongest_hash_is_tried_first() {
        let d = digest_bytes(EICAR);
        assert!(matches!(d.all()[0], HashValue::Sha256(_)));
        assert!(matches!(d.all()[2], HashValue::Md5(_)));
    }

    #[test]
    fn identity_carries_all_three_hex_digests() {
        let id = digest_bytes(EICAR).to_identity(68);
        assert_eq!(id.size, 68);
        assert_eq!(id.md5.as_deref(), Some("44d88612fea8a8f36de82e1278abb02f"));
        assert!(id.sha256.is_some());
    }

    #[test]
    fn entropy_of_uniform_data_is_zero() {
        assert_eq!(entropy(&[0u8; 4096]), 0.0);
        assert_eq!(entropy(b""), 0.0);
    }

    #[test]
    fn entropy_of_every_byte_once_is_eight() {
        let all: Vec<u8> = (0..=255u8).collect();
        assert!((entropy(&all) - 8.0).abs() < 1e-9, "got {}", entropy(&all));
    }

    #[test]
    fn entropy_of_english_text_is_moderate() {
        // Real text should land well below the 7.2 packing threshold, or the
        // heuristic would fire on every readme on the disk.
        let text = "the quick brown fox jumps over the lazy dog. ".repeat(100);
        let e = entropy(text.as_bytes());
        assert!(e > 3.0 && e < 5.0, "english text entropy was {e}");
    }

    #[test]
    fn entropy_of_random_bytes_is_high() {
        // A cheap deterministic PRNG stands in for compressed/encrypted data.
        let mut state = 0x2545F4914F6CDD1Du64;
        let data: Vec<u8> = (0..65536)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect();
        let e = entropy(&data);
        assert!(e > 7.9, "pseudo-random entropy was {e}, expected near 8.0");
    }
}
