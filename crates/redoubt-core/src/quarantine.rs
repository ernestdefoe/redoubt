//! The quarantine store.
//!
//! Quarantining moves a file out of reach and records everything needed to put
//! it back. Three properties matter:
//!
//! 1. **Neutralised on disk.** Stored files are XOR-obfuscated with a
//!    per-file key. This is *not* encryption and is not claimed to be - the key
//!    sits in the manifest beside it. Its job is to stop the quarantined copy
//!    from being executed by accident, matched by another scanner, or restored
//!    by a click in Explorer. Anyone with the manifest can recover the bytes,
//!    which is the point: restore has to work.
//! 2. **Reversible.** Every entry records the original path, its hashes, what
//!    detected it and when. A false positive must be undoable.
//! 3. **Crash-safe.** The payload is written and fsynced *before* the manifest
//!    records it, and the original is deleted last. A crash at any point
//!    leaves either the original or a complete quarantine entry - never
//!    neither.

use anyhow::{bail, Context, Result};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::verdict::{Detection, Verdict};

const MANIFEST_NAME: &str = "manifest.jsonl";
const PAYLOAD_DIR: &str = "store";

/// One quarantined file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// Stable id, also the payload's filename.
    pub id: String,
    /// Where it came from, so it can go back.
    pub original_path: PathBuf,
    pub size: u64,
    pub sha256: Option<String>,
    /// Unix timestamp of quarantine.
    pub quarantined_at: u64,
    /// Why it was taken.
    pub detections: Vec<Detection>,
    /// Obfuscation key. Recorded openly: this is tamper-resistance, not
    /// secrecy, and restore must not depend on a secret that could be lost.
    pub key: u8,
    /// Set once restored, so the log keeps the history.
    #[serde(default)]
    pub restored: bool,
}

impl Entry {
    pub fn primary_name(&self) -> &str {
        self.detections
            .iter()
            .max_by_key(|d| d.severity)
            .map(|d| d.name.as_str())
            .unwrap_or("unknown")
    }
}

/// Obfuscate in place. XOR is its own inverse, so this both stores and
/// restores.
fn scramble(data: &mut [u8], key: u8) {
    // A zero key would be a no-op and leave a live executable on disk.
    debug_assert_ne!(key, 0);
    for b in data.iter_mut() {
        *b ^= key;
    }
}

/// Derive a non-zero key from the content hash, so it is deterministic and
/// needs no random source.
fn key_for(sha256: Option<&str>, size: u64) -> u8 {
    let seed = match sha256 {
        Some(h) => h.bytes().fold(0u8, |a, b| a.wrapping_add(b)),
        None => (size & 0xff) as u8,
    };
    if seed == 0 {
        0xA5
    } else {
        seed
    }
}

/// The quarantine store.
pub struct Quarantine {
    root: PathBuf,
    /// Serialises manifest appends across scan workers.
    lock: Mutex<()>,
}

impl Quarantine {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into(), lock: Mutex::new(()) }
    }

    fn payload_dir(&self) -> PathBuf {
        self.root.join(PAYLOAD_DIR)
    }

    fn manifest_path(&self) -> PathBuf {
        self.root.join(MANIFEST_NAME)
    }

    /// Move `path` into quarantine, based on `verdict`.
    pub fn take(&self, path: &Path, verdict: &Verdict, now: u64) -> Result<Entry> {
        if !verdict.severity.is_actionable() {
            bail!(
                "refusing to quarantine {} - severity is {}, and only malicious findings \
                 may be enforced",
                path.display(),
                verdict.severity
            );
        }

        std::fs::create_dir_all(self.payload_dir())
            .with_context(|| format!("creating {}", self.payload_dir().display()))?;

        let mut data = std::fs::read(path)
            .with_context(|| format!("reading {} for quarantine", path.display()))?;
        let size = data.len() as u64;
        let key = key_for(verdict.identity.sha256.as_deref(), size);

        let id = format!(
            "{now:010}-{}",
            verdict
                .identity
                .sha256
                .as_deref()
                .map(|h| &h[..16.min(h.len())])
                .unwrap_or("nohash")
        );

        scramble(&mut data, key);

        // Payload first, fully durable, before anything claims it exists.
        let payload = self.payload_dir().join(&id);
        {
            let mut f = std::fs::File::create(&payload)
                .with_context(|| format!("creating {}", payload.display()))?;
            f.write_all(&data).context("writing quarantine payload")?;
            f.sync_all().context("fsync on quarantine payload")?;
        }

        let entry = Entry {
            id,
            original_path: path.to_path_buf(),
            size,
            sha256: verdict.identity.sha256.clone(),
            quarantined_at: now,
            detections: verdict.detections.clone(),
            key,
            restored: false,
        };

        self.append(&entry)?;

        // Only now is it safe to remove the original.
        if let Err(e) = std::fs::remove_file(path) {
            // The payload and manifest entry are already durable, so the file
            // is recoverable; report rather than leaving a silent half-state.
            bail!(
                "quarantined a copy of {} but could not remove the original: {e}",
                path.display()
            );
        }
        Ok(entry)
    }

    fn append(&self, entry: &Entry) -> Result<()> {
        let _guard = self.lock.lock();
        std::fs::create_dir_all(&self.root)?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.manifest_path())
            .with_context(|| format!("opening {}", self.manifest_path().display()))?;
        let line = serde_json::to_string(entry).context("serialising quarantine entry")?;
        writeln!(f, "{line}").context("appending to quarantine manifest")?;
        f.sync_all().context("fsync on quarantine manifest")?;
        Ok(())
    }

    /// Every entry, oldest first. Later records for the same id win, so a
    /// restore supersedes the original quarantine record.
    pub fn entries(&self) -> Vec<Entry> {
        let Ok(text) = std::fs::read_to_string(self.manifest_path()) else {
            return Vec::new();
        };
        let mut out: Vec<Entry> = Vec::new();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let Ok(entry) = serde_json::from_str::<Entry>(line) else {
                continue;
            };
            match out.iter_mut().find(|e| e.id == entry.id) {
                Some(existing) => *existing = entry,
                None => out.push(entry),
            }
        }
        out
    }

    /// Entries still held (not restored).
    pub fn held(&self) -> Vec<Entry> {
        self.entries().into_iter().filter(|e| !e.restored).collect()
    }

    /// Put a quarantined file back where it came from.
    ///
    /// Refuses to overwrite something that now exists at the original path -
    /// restoring must never destroy a file that arrived in the meantime.
    pub fn restore(&self, id: &str) -> Result<PathBuf> {
        let mut entry = self
            .entries()
            .into_iter()
            .find(|e| e.id == id)
            .with_context(|| format!("no quarantine entry {id}"))?;

        if entry.restored {
            bail!("quarantine entry {id} was already restored");
        }
        if entry.original_path.exists() {
            bail!(
                "refusing to restore over {} - something already exists there",
                entry.original_path.display()
            );
        }

        let payload = self.payload_dir().join(&entry.id);
        let mut data = std::fs::read(&payload)
            .with_context(|| format!("reading quarantine payload {}", payload.display()))?;
        scramble(&mut data, entry.key);

        if let Some(parent) = entry.original_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("recreating {}", parent.display()))?;
        }
        std::fs::write(&entry.original_path, &data)
            .with_context(|| format!("restoring {}", entry.original_path.display()))?;

        entry.restored = true;
        self.append(&entry)?;
        std::fs::remove_file(&payload).ok();
        Ok(entry.original_path)
    }

    /// Permanently delete a quarantined payload.
    ///
    /// The manifest record is kept: the log of what was found and removed is
    /// worth more than the disk space, and losing it makes an FP impossible to
    /// diagnose after the fact.
    pub fn purge(&self, id: &str) -> Result<()> {
        let payload = self.payload_dir().join(id);
        if payload.exists() {
            std::fs::remove_file(&payload)
                .with_context(|| format!("deleting {}", payload.display()))?;
        }
        Ok(())
    }

    /// Total bytes held.
    pub fn bytes_held(&self) -> u64 {
        self.held().iter().map(|e| e.size).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Engine, FileIdentity, Severity};

    fn temp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("redoubt-q-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&p).ok();
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn malicious_verdict(path: &Path, data: &[u8]) -> Verdict {
        let digests = crate::hashing::digest_bytes(data);
        let mut v = Verdict::clean(
            path.to_path_buf(),
            digests.to_identity(data.len() as u64),
            10,
        );
        v.detections.push(Detection::new(
            "Redoubt.Test.Malware",
            Engine::Hash,
            Severity::Malicious,
        ));
        v.recompute_severity();
        v
    }

    #[test]
    fn quarantining_moves_the_file_and_records_it() {
        let dir = temp("take");
        let victim = dir.join("bad.exe");
        std::fs::write(&victim, b"malicious payload bytes").unwrap();

        let q = Quarantine::new(dir.join("q"));
        let entry = q
            .take(&victim, &malicious_verdict(&victim, b"malicious payload bytes"), 1_700_000_000)
            .unwrap();

        assert!(!victim.exists(), "the original must be gone");
        assert_eq!(entry.original_path, victim);
        assert_eq!(entry.size, 23);
        assert_eq!(entry.primary_name(), "Redoubt.Test.Malware");
        assert_eq!(q.held().len(), 1);
        assert_eq!(q.bytes_held(), 23);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_stored_payload_is_not_the_original_bytes() {
        // If the payload were stored verbatim it would still be executable and
        // would still trip other scanners sitting on the same machine.
        let dir = temp("scramble");
        let victim = dir.join("bad.exe");
        let content = b"MZ\x90\x00this looks like a PE";
        std::fs::write(&victim, content).unwrap();

        let q = Quarantine::new(dir.join("q"));
        let entry = q.take(&victim, &malicious_verdict(&victim, content), 1).unwrap();

        let stored = std::fs::read(dir.join("q").join(PAYLOAD_DIR).join(&entry.id)).unwrap();
        assert_ne!(stored, content, "payload was stored verbatim");
        assert_ne!(&stored[..2], b"MZ", "the executable magic survived");
        assert_eq!(stored.len(), content.len());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restore_returns_the_exact_original_bytes() {
        let dir = temp("restore");
        let victim = dir.join("sub").join("bad.exe");
        std::fs::create_dir_all(victim.parent().unwrap()).unwrap();
        let content: Vec<u8> = (0..=255u8).cycle().take(5000).collect();
        std::fs::write(&victim, &content).unwrap();

        let q = Quarantine::new(dir.join("q"));
        let entry = q.take(&victim, &malicious_verdict(&victim, &content), 1).unwrap();
        assert!(!victim.exists());

        let back = q.restore(&entry.id).unwrap();
        assert_eq!(back, victim);
        assert_eq!(std::fs::read(&victim).unwrap(), content, "restore must be byte-exact");
        assert!(q.held().is_empty(), "a restored entry is no longer held");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn suspicious_findings_are_never_quarantined() {
        // The safety property: heuristics and PUA signatures reach only
        // `Suspicious`, and nothing at that level may be acted on.
        let dir = temp("suspicious");
        let victim = dir.join("maybe.exe");
        std::fs::write(&victim, b"probably fine").unwrap();

        let mut v = Verdict::clean(victim.clone(), FileIdentity::default(), 1);
        v.detections.push(Detection::new(
            "Heuristic.PE.HighEntropyCode",
            Engine::Heuristic,
            Severity::Suspicious,
        ));
        v.recompute_severity();

        let q = Quarantine::new(dir.join("q"));
        let err = q.take(&victim, &v, 1).unwrap_err();
        assert!(err.to_string().contains("only malicious"), "{err}");
        assert!(victim.exists(), "a suspicious file must be left alone");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn clean_files_are_never_quarantined() {
        let dir = temp("clean");
        let victim = dir.join("fine.txt");
        std::fs::write(&victim, b"ordinary").unwrap();

        let v = Verdict::clean(victim.clone(), FileIdentity::default(), 1);
        let q = Quarantine::new(dir.join("q"));
        assert!(q.take(&victim, &v, 1).is_err());
        assert!(victim.exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restore_refuses_to_overwrite_a_file_that_reappeared() {
        let dir = temp("noclobber");
        let victim = dir.join("bad.exe");
        std::fs::write(&victim, b"original malware").unwrap();

        let q = Quarantine::new(dir.join("q"));
        let entry = q.take(&victim, &malicious_verdict(&victim, b"original malware"), 1).unwrap();

        // Something legitimate now occupies that path.
        std::fs::write(&victim, b"a completely different, wanted file").unwrap();

        let err = q.restore(&entry.id).unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"a completely different, wanted file",
            "restore must not destroy what is there now"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restoring_twice_is_refused() {
        let dir = temp("twice");
        let victim = dir.join("bad.exe");
        std::fs::write(&victim, b"payload").unwrap();

        let q = Quarantine::new(dir.join("q"));
        let entry = q.take(&victim, &malicious_verdict(&victim, b"payload"), 1).unwrap();
        q.restore(&entry.id).unwrap();
        std::fs::remove_file(&victim).unwrap();

        let err = q.restore(&entry.id).unwrap_err();
        assert!(err.to_string().contains("already restored"), "{err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_manifest_survives_many_entries_and_a_reopen() {
        let dir = temp("manifest");
        let q = Quarantine::new(dir.join("q"));
        for i in 0..25 {
            let victim = dir.join(format!("bad{i}.exe"));
            let content = format!("payload {i}");
            std::fs::write(&victim, &content).unwrap();
            q.take(&victim, &malicious_verdict(&victim, content.as_bytes()), i as u64).unwrap();
        }

        // A fresh handle reads the same store.
        let reopened = Quarantine::new(dir.join("q"));
        assert_eq!(reopened.held().len(), 25);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_corrupt_manifest_line_does_not_lose_the_rest() {
        let dir = temp("corrupt");
        let q = Quarantine::new(dir.join("q"));
        let victim = dir.join("bad.exe");
        std::fs::write(&victim, b"payload").unwrap();
        q.take(&victim, &malicious_verdict(&victim, b"payload"), 1).unwrap();

        // Something appended garbage.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join("q").join(MANIFEST_NAME))
            .unwrap();
        writeln!(f, "{{not valid json").unwrap();
        drop(f);

        assert_eq!(q.held().len(), 1, "the good entry must survive a bad line");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn keys_are_never_zero() {
        // A zero key makes scrambling a no-op, leaving a live executable in
        // the store.
        assert_ne!(key_for(None, 0), 0);
        assert_ne!(key_for(Some(""), 0), 0);
        for size in [0u64, 1, 255, 256, 1_000_000] {
            assert_ne!(key_for(None, size), 0, "size {size}");
        }
    }

    #[test]
    fn scramble_round_trips() {
        let original: Vec<u8> = (0..=255u8).collect();
        let mut data = original.clone();
        scramble(&mut data, 0x5C);
        assert_ne!(data, original);
        scramble(&mut data, 0x5C);
        assert_eq!(data, original);
    }
}
