//! Verdict cache.
//!
//! Real-time scanning without a cache is unusable. A single build, npm
//! install, or Explorer refresh generates thousands of write events against
//! files that have not meaningfully changed, and rescanning each one turns a
//! background service into a space heater.
//!
//! The cache keys a verdict on **path + size + modification time**. If any of
//! those move, the entry is stale and the file is scanned again.
//!
//! # What this deliberately does not do
//!
//! It does not key on content hash - that would require reading the file,
//! which is most of the cost the cache exists to avoid. The trade is explicit:
//! a file modified within the filesystem's timestamp resolution, to the same
//! length, can return a stale verdict. Signature updates invalidate everything
//! via [`CacheKey::generation`], so the window is narrow and bounded.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::verdict::Severity;

/// Identity of a cached scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub size: u64,
    /// Modification time as whole nanoseconds since the epoch.
    pub mtime_nanos: u128,
    /// Signature database version at the time of the scan. Bumping the
    /// database invalidates every entry, because a file that was clean under
    /// yesterday's signatures may not be under today's.
    pub generation: u32,
}

impl CacheKey {
    /// Build a key from filesystem metadata.
    pub fn from_metadata(meta: &std::fs::Metadata, generation: u32) -> Option<Self> {
        let mtime = meta.modified().ok()?;
        let nanos = mtime
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()?
            .as_nanos();
        Some(Self { size: meta.len(), mtime_nanos: nanos, generation })
    }
}

/// The compact result kept per file. Full verdicts are not stored: the
/// detection list can be long, and the cache exists to answer "do I need to
/// look at this again", not to reproduce a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedVerdict {
    pub key: CacheKey,
    pub severity: Severity,
    /// Primary detection name, when there was one.
    pub name: Option<String>,
}

/// Statistics, for the UI's "is this thing actually helping" panel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub stale: u64,
    pub evictions: u64,
    pub entries: usize,
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses + self.stale;
        if total == 0 {
            return 0.0;
        }
        self.hits as f64 / total as f64
    }
}

/// A bounded, in-memory verdict cache.
///
/// Eviction is a simple random-ish sweep rather than true LRU: tracking exact
/// recency costs a second data structure and a write on every *read*, which is
/// the wrong trade when the goal is to make repeat lookups nearly free.
pub struct VerdictCache {
    inner: Mutex<Inner>,
    capacity: usize,
}

struct Inner {
    map: HashMap<PathBuf, CachedVerdict>,
    stats: CacheStats,
}

impl VerdictCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                stats: CacheStats::default(),
            }),
            capacity: capacity.max(1),
        }
    }

    /// Look up `path`. Returns `Some` only when the cached entry's key matches
    /// exactly - same size, same mtime, same signature generation.
    pub fn get(&self, path: &Path, key: &CacheKey) -> Option<CachedVerdict> {
        let mut inner = self.inner.lock();
        match inner.map.get(path) {
            Some(entry) if &entry.key == key => {
                let entry = entry.clone();
                inner.stats.hits += 1;
                Some(entry)
            }
            Some(_) => {
                inner.stats.stale += 1;
                // The old entry is now wrong; drop it rather than let a stale
                // verdict linger for a file that will be rescanned anyway.
                inner.map.remove(path);
                None
            }
            None => {
                inner.stats.misses += 1;
                None
            }
        }
    }

    /// Record a verdict.
    pub fn insert(&self, path: &Path, verdict: CachedVerdict) {
        let mut inner = self.inner.lock();
        if inner.map.len() >= self.capacity && !inner.map.contains_key(path) {
            // Drop a chunk at once rather than one per insert, so eviction
            // does not run on every single write once the cache is full.
            let to_drop = (self.capacity / 8).max(1);
            let victims: Vec<PathBuf> =
                inner.map.keys().take(to_drop).cloned().collect();
            for v in victims {
                inner.map.remove(&v);
                inner.stats.evictions += 1;
            }
        }
        inner.map.insert(path.to_path_buf(), verdict);
    }

    /// Forget one path, e.g. after quarantining it.
    pub fn invalidate(&self, path: &Path) {
        self.inner.lock().map.remove(path);
    }

    /// Drop everything. Called when the signature database changes.
    pub fn clear(&self) {
        let mut inner = self.inner.lock();
        inner.map.clear();
    }

    pub fn stats(&self) -> CacheStats {
        let inner = self.inner.lock();
        CacheStats { entries: inner.map.len(), ..inner.stats }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(size: u64, mtime: u128, generation: u32) -> CacheKey {
        CacheKey { size, mtime_nanos: mtime, generation }
    }

    fn verdict(k: CacheKey, severity: Severity) -> CachedVerdict {
        CachedVerdict { key: k, severity, name: None }
    }

    #[test]
    fn a_hit_returns_the_cached_verdict() {
        let cache = VerdictCache::new(16);
        let p = Path::new("C:/tmp/a.exe");
        let k = key(100, 1_000, 1);

        assert_eq!(cache.get(p, &k), None);
        cache.insert(p, verdict(k, Severity::Clean));
        assert_eq!(cache.get(p, &k).unwrap().severity, Severity::Clean);

        let s = cache.stats();
        assert_eq!(s.hits, 1);
        assert_eq!(s.misses, 1);
    }

    #[test]
    fn a_changed_size_invalidates() {
        let cache = VerdictCache::new(16);
        let p = Path::new("C:/tmp/a.exe");
        cache.insert(p, verdict(key(100, 1_000, 1), Severity::Clean));

        assert_eq!(cache.get(p, &key(200, 1_000, 1)), None, "size change must miss");
        assert_eq!(cache.stats().stale, 1);
    }

    #[test]
    fn a_changed_mtime_invalidates() {
        let cache = VerdictCache::new(16);
        let p = Path::new("C:/tmp/a.exe");
        cache.insert(p, verdict(key(100, 1_000, 1), Severity::Clean));

        assert_eq!(cache.get(p, &key(100, 2_000, 1)), None, "mtime change must miss");
    }

    #[test]
    fn a_signature_update_invalidates_everything() {
        // The important one: a file that was clean yesterday is not
        // necessarily clean under today's signatures.
        let cache = VerdictCache::new(16);
        let p = Path::new("C:/tmp/a.exe");
        cache.insert(p, verdict(key(100, 1_000, 27_000), Severity::Clean));

        assert_eq!(
            cache.get(p, &key(100, 1_000, 27_001)),
            None,
            "a new database generation must not reuse an old verdict"
        );
    }

    #[test]
    fn a_stale_entry_is_dropped_not_kept() {
        let cache = VerdictCache::new(16);
        let p = Path::new("C:/tmp/a.exe");
        cache.insert(p, verdict(key(100, 1_000, 1), Severity::Clean));
        cache.get(p, &key(100, 2_000, 1));
        assert!(cache.is_empty(), "stale entries should not linger");
    }

    #[test]
    fn malicious_verdicts_are_cached_too() {
        let cache = VerdictCache::new(16);
        let p = Path::new("C:/tmp/bad.exe");
        let k = key(68, 1_000, 1);
        cache.insert(
            p,
            CachedVerdict {
                key: k,
                severity: Severity::Malicious,
                name: Some("Eicar-Test-Signature".into()),
            },
        );
        let got = cache.get(p, &k).unwrap();
        assert_eq!(got.severity, Severity::Malicious);
        assert_eq!(got.name.as_deref(), Some("Eicar-Test-Signature"));
    }

    #[test]
    fn capacity_is_enforced() {
        let cache = VerdictCache::new(32);
        for i in 0..200u64 {
            let p = PathBuf::from(format!("C:/tmp/file{i}.bin"));
            cache.insert(&p, verdict(key(i, i as u128, 1), Severity::Clean));
        }
        assert!(cache.len() <= 32, "cache grew to {} past its capacity", cache.len());
        assert!(cache.stats().evictions > 0);
    }

    #[test]
    fn invalidate_removes_one_entry() {
        let cache = VerdictCache::new(16);
        let a = Path::new("C:/tmp/a.exe");
        let b = Path::new("C:/tmp/b.exe");
        let k = key(1, 1, 1);
        cache.insert(a, verdict(k, Severity::Clean));
        cache.insert(b, verdict(k, Severity::Clean));

        cache.invalidate(a);
        assert_eq!(cache.get(a, &k), None);
        assert!(cache.get(b, &k).is_some());
    }

    #[test]
    fn clear_empties_the_cache() {
        let cache = VerdictCache::new(16);
        cache.insert(Path::new("C:/tmp/a.exe"), verdict(key(1, 1, 1), Severity::Clean));
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn hit_rate_reflects_usage() {
        let cache = VerdictCache::new(16);
        let p = Path::new("C:/tmp/a.exe");
        let k = key(1, 1, 1);

        assert_eq!(cache.stats().hit_rate(), 0.0, "no lookups yet");
        cache.get(p, &k); // miss
        cache.insert(p, verdict(k, Severity::Clean));
        for _ in 0..3 {
            cache.get(p, &k); // 3 hits
        }
        assert!((cache.stats().hit_rate() - 0.75).abs() < 1e-9);
    }

    #[test]
    fn key_from_metadata_reads_real_files() {
        let p = std::env::temp_dir().join(format!("redoubt-cache-{}.bin", std::process::id()));
        std::fs::write(&p, b"hello").unwrap();
        let meta = std::fs::metadata(&p).unwrap();

        let k = CacheKey::from_metadata(&meta, 42).unwrap();
        assert_eq!(k.size, 5);
        assert_eq!(k.generation, 42);
        assert!(k.mtime_nanos > 0);

        std::fs::remove_file(&p).ok();
    }
}
