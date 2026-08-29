//! A compiled, memory-mapped signature index.
//!
//! # Why not just a HashMap
//!
//! ClamAV's `main` + `daily` databases carry several million hash signatures.
//! Loading those into `HashMap<[u8; 32], String>` costs somewhere north of a
//! gigabyte of resident memory - which is exactly why ClamAV itself is known
//! for it, and it is unacceptable for a thing that sits running all day on a
//! desktop.
//!
//! So instead we compile the databases once into a flat file of **sorted,
//! fixed-stride records** and `mmap` it. Lookups are a binary search over
//! borrowed bytes: no heap allocation, no deserialisation, and the OS page
//! cache keeps only the pages actually touched resident. A cold lookup costs a
//! handful of page faults; a warm one costs nothing.
//!
//! Compilation happens in the updater, not on the hot path.
//!
//! # File layout
//!
//! ```text
//! [0, 256)      header (fixed size, little-endian)
//! [.. )         9 record tables, each sorted ascending by hash bytes
//! [.. )         body-pattern blob (literal .ndb signatures)
//! [.. )         names blob (NUL-separated UTF-8)
//! ```
//!
//! Records are `hash || size:u64 || name_offset:u32`, packed with no padding.
//! `size == u64::MAX` is the sentinel for a signature that matches any size.

use anyhow::{bail, Context, Result};
use memmap2::Mmap;
use std::collections::HashMap;
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::sigs::{BodySig, HashSig, HashValue, Offset};

const MAGIC: &[u8; 8] = b"RDBTIDX\x01";
const FORMAT_VERSION: u32 = 1;
const HEADER_SIZE: usize = 256;

/// Sentinel in the `size` field meaning "matches at any size".
const ANY_SIZE: u64 = u64::MAX;

/// Which table a lookup should consult.
///
/// The three groups are kept separate rather than merged with a tag byte so a
/// section-hash lookup never has to walk past millions of file-hash records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Table {
    FileMd5 = 0,
    FileSha1 = 1,
    FileSha256 = 2,
    SectionMd5 = 3,
    SectionSha1 = 4,
    SectionSha256 = 5,
    AllowMd5 = 6,
    AllowSha1 = 7,
    AllowSha256 = 8,
}

const TABLE_COUNT: usize = 9;

/// Byte width of one record in each table: hash + u64 size + u32 name offset.
const fn stride(table: usize) -> usize {
    let hash_len = match table % 3 {
        0 => 16, // md5
        1 => 20, // sha1
        _ => 32, // sha256
    };
    hash_len + 8 + 4
}

const fn hash_len_for(table: usize) -> usize {
    match table % 3 {
        0 => 16,
        1 => 20,
        _ => 32,
    }
}

fn table_for(hash: &HashValue, group: Group) -> usize {
    let base = match group {
        Group::File => 0,
        Group::Section => 3,
        Group::Allow => 6,
    };
    let within = match hash {
        HashValue::Md5(_) => 0,
        HashValue::Sha1(_) => 1,
        HashValue::Sha256(_) => 2,
    };
    base + within
}

/// Which family of table a signature belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    /// Whole-file malicious hashes.
    File,
    /// PE section malicious hashes.
    Section,
    /// Known-good hashes that suppress a detection.
    Allow,
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Accumulates signatures in memory, then writes the compiled index.
///
/// Peak memory is roughly `record_size * signature_count` plus the interned
/// name blob - a few hundred MB for the full ClamAV set. That is fine for a
/// one-shot update task and is never paid by the resident service.
pub struct IndexBuilder {
    /// One `(hash_bytes, size, name_id)` list per table.
    tables: Vec<Vec<(Vec<u8>, u64, u32)>>,
    body: Vec<(u32, u8, Offset, Vec<u8>)>,
    /// `(name_id, target, expression source, subsignature patterns)`
    logical: Vec<(u32, u8, String, Vec<Vec<u8>>)>,
    names: Vec<String>,
    name_ids: HashMap<String, u32>,
    db_version: u32,
    built_epoch: u64,
}

impl IndexBuilder {
    pub fn new(db_version: u32, built_epoch: u64) -> Self {
        Self {
            tables: (0..TABLE_COUNT).map(|_| Vec::new()).collect(),
            body: Vec::new(),
            logical: Vec::new(),
            names: Vec::new(),
            name_ids: HashMap::new(),
            db_version,
            built_epoch,
        }
    }

    /// Intern a signature name, returning its id. Malware families repeat
    /// heavily across signatures, so this collapses a lot of duplication.
    fn intern(&mut self, name: &str) -> u32 {
        if let Some(&id) = self.name_ids.get(name) {
            return id;
        }
        let id = self.names.len() as u32;
        self.names.push(name.to_string());
        self.name_ids.insert(name.to_string(), id);
        id
    }

    pub fn add_hash(&mut self, sig: HashSig, group: Group) {
        let name_id = self.intern(&sig.name);
        let table = table_for(&sig.hash, group);
        self.tables[table].push((
            sig.hash.as_bytes().to_vec(),
            sig.size.unwrap_or(ANY_SIZE),
            name_id,
        ));
    }

    pub fn add_body(&mut self, sig: BodySig) {
        let name_id = self.intern(&sig.name);
        self.body.push((name_id, sig.target, sig.offset, sig.pattern));
    }

    /// Add a logical signature.
    pub fn add_logical(&mut self, sig: crate::ldb::LogicalSig) {
        let name_id = self.intern(&sig.name);
        self.logical
            .push((name_id, sig.target, sig.expr.to_source(), sig.subsigs));
    }

    /// Stamp the index with a database version and build time.
    ///
    /// Compiling several containers at once means the version is only known
    /// after the last header has been read, so it is applied at the end
    /// rather than up front.
    pub fn retag(mut self, db_version: u32, built_epoch: u64) -> Self {
        self.db_version = db_version;
        self.built_epoch = built_epoch;
        self
    }

    /// Total accepted signatures across every table.
    pub fn len(&self) -> u64 {
        self.tables.iter().map(|t| t.len() as u64).sum::<u64>()
            + self.body.len() as u64
            + self.logical.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Sort, deduplicate and write the index to `path`.
    ///
    /// Written to a sibling temp file and renamed, so a crash mid-write cannot
    /// leave the service with a half-built index it would happily mmap.
    pub fn write(mut self, path: &Path) -> Result<IndexStats> {
        let mut stats = IndexStats { db_version: self.db_version, ..Default::default() };

        for table in self.tables.iter_mut() {
            table.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
            table.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
        }

        // Name offsets are byte positions into the blob, so build it first.
        let mut names_blob = Vec::new();
        let mut name_offsets = Vec::with_capacity(self.names.len());
        for name in &self.names {
            name_offsets.push(names_blob.len() as u32);
            names_blob.extend_from_slice(name.as_bytes());
            names_blob.push(0);
        }

        let tmp = path.with_extension("tmp");
        if let Some(parent) = tmp.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let file = std::fs::File::create(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        let mut out = BufWriter::with_capacity(1 << 20, file);

        // Reserve the header; offsets are backfilled once sizes are known.
        out.write_all(&[0u8; HEADER_SIZE])?;
        let mut cursor = HEADER_SIZE as u64;

        let mut table_offsets = [0u64; TABLE_COUNT];
        let mut table_counts = [0u64; TABLE_COUNT];

        for (idx, table) in self.tables.iter().enumerate() {
            table_offsets[idx] = cursor;
            table_counts[idx] = table.len() as u64;
            let hash_len = hash_len_for(idx);
            for (hash, size, name_id) in table {
                debug_assert_eq!(hash.len(), hash_len);
                out.write_all(hash)?;
                out.write_all(&size.to_le_bytes())?;
                out.write_all(&name_offsets[*name_id as usize].to_le_bytes())?;
            }
            cursor += table.len() as u64 * stride(idx) as u64;
        }
        stats.file_hashes = table_counts[0] + table_counts[1] + table_counts[2];
        stats.section_hashes = table_counts[3] + table_counts[4] + table_counts[5];
        stats.allowlisted = table_counts[6] + table_counts[7] + table_counts[8];

        // Body patterns: name_off:u32 | target:u8 | off_kind:u8 | pat_len:u16
        //                | abs_offset:u64 | pattern bytes
        let body_offset = cursor;
        let mut body_count = 0u64;
        for (name_id, target, offset, pattern) in &self.body {
            if pattern.len() > u16::MAX as usize {
                continue;
            }
            let (kind, abs) = match offset {
                Offset::Any => (0u8, 0u64),
                Offset::Absolute(n) => (1u8, *n),
            };
            out.write_all(&name_offsets[*name_id as usize].to_le_bytes())?;
            out.write_all(&[*target, kind])?;
            out.write_all(&(pattern.len() as u16).to_le_bytes())?;
            out.write_all(&abs.to_le_bytes())?;
            out.write_all(pattern)?;
            cursor += 16 + pattern.len() as u64;
            body_count += 1;
        }
        let body_len = cursor - body_offset;
        stats.body_patterns = body_count;

        // Logical signatures.
        //
        // Layout per rule:
        //   name_off:u32 | target:u8 | n_subsigs:u8 | expr_len:u16 | expr bytes
        //   then n_subsigs x ( len:u16 | pattern bytes )
        //
        // The expression is stored as source rather than a compiled tree: it
        // is only parsed when at least one of the rule's subsignatures has
        // actually matched, which is rare, and storing text keeps ~138,000
        // rules to a few megabytes.
        let logical_offset = cursor;
        let mut logical_count = 0u64;
        for (name_id, target, expr, subsigs) in &self.logical {
            if subsigs.len() > u8::MAX as usize || expr.len() > u16::MAX as usize {
                continue;
            }
            if subsigs.iter().any(|s| s.len() > u16::MAX as usize) {
                continue;
            }
            out.write_all(&name_offsets[*name_id as usize].to_le_bytes())?;
            out.write_all(&[*target, subsigs.len() as u8])?;
            out.write_all(&(expr.len() as u16).to_le_bytes())?;
            out.write_all(expr.as_bytes())?;
            cursor += 8 + expr.len() as u64;
            for sub in subsigs {
                out.write_all(&(sub.len() as u16).to_le_bytes())?;
                out.write_all(sub)?;
                cursor += 2 + sub.len() as u64;
            }
            logical_count += 1;
        }
        let logical_len = cursor - logical_offset;
        stats.logical_rules = logical_count;

        let names_offset = cursor;
        out.write_all(&names_blob)?;
        let names_len = names_blob.len() as u64;
        stats.unique_names = self.names.len() as u64;

        // Backfill the header.
        let mut header = [0u8; HEADER_SIZE];
        header[0..8].copy_from_slice(MAGIC);
        header[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        header[12..16].copy_from_slice(&0u32.to_le_bytes()); // flags, reserved
        header[16..20].copy_from_slice(&self.db_version.to_le_bytes());
        header[24..32].copy_from_slice(&self.built_epoch.to_le_bytes());
        header[32..40].copy_from_slice(&stats.total().to_le_bytes());
        for i in 0..TABLE_COUNT {
            let base = 40 + i * 16;
            header[base..base + 8].copy_from_slice(&table_offsets[i].to_le_bytes());
            header[base + 8..base + 16].copy_from_slice(&table_counts[i].to_le_bytes());
        }
        header[184..192].copy_from_slice(&names_offset.to_le_bytes());
        header[192..200].copy_from_slice(&names_len.to_le_bytes());
        header[200..208].copy_from_slice(&body_offset.to_le_bytes());
        header[208..216].copy_from_slice(&body_len.to_le_bytes());
        header[216..224].copy_from_slice(&body_count.to_le_bytes());
        header[224..232].copy_from_slice(&logical_offset.to_le_bytes());
        header[232..240].copy_from_slice(&logical_len.to_le_bytes());
        header[240..248].copy_from_slice(&logical_count.to_le_bytes());

        let mut file = out.into_inner().context("flushing index writer")?;
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&header)?;
        file.sync_all().context("fsync on index")?;
        drop(file);

        std::fs::rename(&tmp, path)
            .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
        Ok(stats)
    }
}

/// Summary of a compiled index, for the UI and the logs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IndexStats {
    pub db_version: u32,
    pub file_hashes: u64,
    pub section_hashes: u64,
    pub body_patterns: u64,
    /// Logical signatures: several patterns plus a boolean expression.
    pub logical_rules: u64,
    pub allowlisted: u64,
    pub unique_names: u64,
}

impl IndexStats {
    pub fn total(&self) -> u64 {
        self.file_hashes
            + self.section_hashes
            + self.body_patterns
            + self.logical_rules
            + self.allowlisted
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// A memory-mapped, read-only signature index.
///
/// Cheap to open and cheap to hold: the struct itself is a handful of offsets
/// over an `mmap`. Safe to share across threads behind an `Arc`.
pub struct SigIndex {
    map: Mmap,
    table_offsets: [u64; TABLE_COUNT],
    table_counts: [u64; TABLE_COUNT],
    names_offset: u64,
    names_len: u64,
    body_offset: u64,
    body_len: u64,
    body_count: u64,
    logical_offset: u64,
    logical_len: u64,
    logical_count: u64,
    db_version: u32,
    built_epoch: u64,
}

// Hand-written so a failed assertion prints the shape of the index rather
// than trying to format several hundred megabytes of mapped bytes.
impl std::fmt::Debug for SigIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.stats();
        f.debug_struct("SigIndex")
            .field("db_version", &self.db_version)
            .field("mapped_bytes", &self.map.len())
            .field("file_hashes", &s.file_hashes)
            .field("section_hashes", &s.section_hashes)
            .field("allowlisted", &s.allowlisted)
            .field("body_patterns", &s.body_patterns)
            .finish()
    }
}

impl SigIndex {
    /// Open and validate a compiled index.
    pub fn open(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("opening index {}", path.display()))?;
        // SAFETY: the index is written atomically via rename and is only
        // rewritten by replacing the whole file, so the mapping cannot be
        // truncated underneath us while this handle is alive.
        let map = unsafe { Mmap::map(&file) }
            .with_context(|| format!("mapping index {}", path.display()))?;

        if map.len() < HEADER_SIZE {
            bail!("index {} is truncated ({} bytes)", path.display(), map.len());
        }
        if &map[0..8] != MAGIC {
            bail!("index {} has a bad magic number", path.display());
        }
        let format_version = u32::from_le_bytes(map[8..12].try_into().unwrap());
        if format_version != FORMAT_VERSION {
            bail!(
                "index {} is format v{format_version}, this build expects v{FORMAT_VERSION}",
                path.display()
            );
        }

        let db_version = u32::from_le_bytes(map[16..20].try_into().unwrap());
        let built_epoch = u64::from_le_bytes(map[24..32].try_into().unwrap());

        let mut table_offsets = [0u64; TABLE_COUNT];
        let mut table_counts = [0u64; TABLE_COUNT];
        for i in 0..TABLE_COUNT {
            let base = 40 + i * 16;
            table_offsets[i] = u64::from_le_bytes(map[base..base + 8].try_into().unwrap());
            table_counts[i] = u64::from_le_bytes(map[base + 8..base + 16].try_into().unwrap());
        }
        let names_offset = u64::from_le_bytes(map[184..192].try_into().unwrap());
        let names_len = u64::from_le_bytes(map[192..200].try_into().unwrap());
        let body_offset = u64::from_le_bytes(map[200..208].try_into().unwrap());
        let body_len = u64::from_le_bytes(map[208..216].try_into().unwrap());
        let body_count = u64::from_le_bytes(map[216..224].try_into().unwrap());
        let logical_offset = u64::from_le_bytes(map[224..232].try_into().unwrap());
        let logical_len = u64::from_le_bytes(map[232..240].try_into().unwrap());
        let logical_count = u64::from_le_bytes(map[240..248].try_into().unwrap());

        let index = Self {
            map,
            table_offsets,
            table_counts,
            names_offset,
            names_len,
            body_offset,
            body_len,
            body_count,
            logical_offset,
            logical_len,
            logical_count,
            db_version,
            built_epoch,
        };
        index.validate_bounds(path)?;
        Ok(index)
    }

    /// Confirm every declared region actually lies inside the file, so a
    /// corrupt header cannot turn into an out-of-bounds read later.
    fn validate_bounds(&self, path: &Path) -> Result<()> {
        let len = self.map.len() as u64;
        for i in 0..TABLE_COUNT {
            let end = self.table_offsets[i]
                .checked_add(self.table_counts[i].saturating_mul(stride(i) as u64))
                .context("index table extent overflows")?;
            if end > len {
                bail!("index {} table {i} extends past end of file", path.display());
            }
        }
        for (name, off, extent) in [
            ("names", self.names_offset, self.names_len),
            ("body", self.body_offset, self.body_len),
            ("logical", self.logical_offset, self.logical_len),
        ] {
            let end = off.checked_add(extent).context("index section overflows")?;
            if end > len {
                bail!("index {} {name} section extends past end of file", path.display());
            }
        }
        Ok(())
    }

    pub fn db_version(&self) -> u32 {
        self.db_version
    }

    pub fn built_epoch(&self) -> u64 {
        self.built_epoch
    }

    pub fn stats(&self) -> IndexStats {
        IndexStats {
            db_version: self.db_version,
            file_hashes: self.table_counts[0] + self.table_counts[1] + self.table_counts[2],
            section_hashes: self.table_counts[3] + self.table_counts[4] + self.table_counts[5],
            body_patterns: self.body_count,
            logical_rules: self.logical_count,
            allowlisted: self.table_counts[6] + self.table_counts[7] + self.table_counts[8],
            unique_names: 0, // not stored; the builder reports it at compile time
        }
    }

    /// Read an interned name by byte offset.
    fn name_at(&self, offset: u32) -> &str {
        let start = self.names_offset as usize + offset as usize;
        let blob_end = (self.names_offset + self.names_len) as usize;
        if start >= blob_end {
            return "<corrupt-name>";
        }
        let slice = &self.map[start..blob_end];
        let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        std::str::from_utf8(&slice[..end]).unwrap_or("<invalid-utf8-name>")
    }

    /// Binary search one table for `hash`, honouring the size constraint.
    ///
    /// Duplicate hashes with different size constraints are possible, so on a
    /// hit we walk backwards to the first equal hash and scan forward.
    fn search(&self, table: usize, hash: &[u8], size: u64) -> Option<&str> {
        let count = self.table_counts[table];
        if count == 0 {
            return None;
        }
        let stride = stride(table);
        let hash_len = hash_len_for(table);
        if hash.len() != hash_len {
            return None;
        }
        let base = self.table_offsets[table] as usize;

        let record = |i: u64| -> &[u8] {
            let start = base + (i as usize) * stride;
            &self.map[start..start + stride]
        };

        let (mut lo, mut hi) = (0u64, count);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match record(mid)[..hash_len].cmp(hash) {
                std::cmp::Ordering::Less => lo = mid + 1,
                _ => hi = mid,
            }
        }
        if lo >= count || &record(lo)[..hash_len] != hash {
            return None;
        }

        // Scan the run of equal hashes for one whose size constraint matches.
        let mut i = lo;
        while i < count {
            let rec = record(i);
            if &rec[..hash_len] != hash {
                break;
            }
            let rec_size = u64::from_le_bytes(rec[hash_len..hash_len + 8].try_into().unwrap());
            if rec_size == ANY_SIZE || rec_size == size {
                let name_off =
                    u32::from_le_bytes(rec[hash_len + 8..hash_len + 12].try_into().unwrap());
                return Some(self.name_at(name_off));
            }
            i += 1;
        }
        None
    }

    /// Look up a hash in the given group. `size` is the file (or section) size.
    pub fn lookup(&self, hash: &HashValue, group: Group, size: u64) -> Option<&str> {
        self.search(table_for(hash, group), hash.as_bytes(), size)
    }

    /// True if `hash` is on the known-good allowlist.
    pub fn is_allowlisted(&self, hash: &HashValue, size: u64) -> Option<&str> {
        self.lookup(hash, Group::Allow, size)
    }

    /// Iterate every logical signature.
    pub fn logical_rules(&self) -> LogicalIter<'_> {
        LogicalIter {
            index: self,
            cursor: self.logical_offset as usize,
            end: (self.logical_offset + self.logical_len) as usize,
            remaining: self.logical_count,
        }
    }

    /// Iterate every literal body pattern. The scanner uses this once at
    /// startup to build its multi-pattern automaton.
    pub fn body_patterns(&self) -> BodyPatternIter<'_> {
        BodyPatternIter {
            index: self,
            cursor: self.body_offset as usize,
            end: (self.body_offset + self.body_len) as usize,
            remaining: self.body_count,
        }
    }
}

/// One logical signature read back out of the index.
pub struct LogicalRef<'a> {
    pub name: &'a str,
    pub target: u8,
    /// Expression source, parsed only when the rule has candidate matches.
    pub expr: &'a str,
    pub subsigs: Vec<&'a [u8]>,
}

pub struct LogicalIter<'a> {
    index: &'a SigIndex,
    cursor: usize,
    end: usize,
    remaining: u64,
}

impl<'a> Iterator for LogicalIter<'a> {
    type Item = LogicalRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.cursor + 8 > self.end {
            return None;
        }
        let map = &self.index.map;
        let name_off = u32::from_le_bytes(map[self.cursor..self.cursor + 4].try_into().unwrap());
        let target = map[self.cursor + 4];
        let n_subs = map[self.cursor + 5] as usize;
        let expr_len =
            u16::from_le_bytes(map[self.cursor + 6..self.cursor + 8].try_into().unwrap()) as usize;

        let expr_start = self.cursor + 8;
        if expr_start + expr_len > self.end {
            self.remaining = 0;
            return None;
        }
        let expr = std::str::from_utf8(&map[expr_start..expr_start + expr_len]).unwrap_or("");

        let mut at = expr_start + expr_len;
        let mut subsigs = Vec::with_capacity(n_subs);
        for _ in 0..n_subs {
            if at + 2 > self.end {
                self.remaining = 0;
                return None;
            }
            let len = u16::from_le_bytes(map[at..at + 2].try_into().unwrap()) as usize;
            if at + 2 + len > self.end {
                self.remaining = 0;
                return None;
            }
            subsigs.push(&map[at + 2..at + 2 + len]);
            at += 2 + len;
        }

        self.cursor = at;
        self.remaining -= 1;
        Some(LogicalRef { name: self.index.name_at(name_off), target, expr, subsigs })
    }
}

/// One literal body signature read back out of the index.
pub struct BodyPatternRef<'a> {
    pub name: &'a str,
    pub target: u8,
    pub offset: Offset,
    pub pattern: &'a [u8],
}

pub struct BodyPatternIter<'a> {
    index: &'a SigIndex,
    cursor: usize,
    end: usize,
    remaining: u64,
}

impl<'a> Iterator for BodyPatternIter<'a> {
    type Item = BodyPatternRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.cursor + 16 > self.end {
            return None;
        }
        let map = &self.index.map;
        let name_off = u32::from_le_bytes(map[self.cursor..self.cursor + 4].try_into().unwrap());
        let target = map[self.cursor + 4];
        let kind = map[self.cursor + 5];
        let pat_len =
            u16::from_le_bytes(map[self.cursor + 6..self.cursor + 8].try_into().unwrap()) as usize;
        let abs = u64::from_le_bytes(map[self.cursor + 8..self.cursor + 16].try_into().unwrap());
        let pat_start = self.cursor + 16;
        if pat_start + pat_len > self.end {
            self.remaining = 0;
            return None;
        }
        self.cursor = pat_start + pat_len;
        self.remaining -= 1;
        Some(BodyPatternRef {
            name: self.index.name_at(name_off),
            target,
            offset: if kind == 0 { Offset::Any } else { Offset::Absolute(abs) },
            pattern: &map[pat_start..pat_start + pat_len],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn md5(byte: u8) -> HashValue {
        HashValue::Md5([byte; 16])
    }
    fn sha256(byte: u8) -> HashValue {
        HashValue::Sha256([byte; 32])
    }

    fn build(path: &Path) -> IndexStats {
        let mut b = IndexBuilder::new(27100, 1_756_000_000);
        b.add_hash(
            HashSig { hash: md5(0x11), size: Some(68), name: "Eicar-Test".into() },
            Group::File,
        );
        b.add_hash(
            HashSig { hash: md5(0x22), size: None, name: "Win.Trojan.AnySize".into() },
            Group::File,
        );
        b.add_hash(
            HashSig { hash: sha256(0x33), size: Some(4096), name: "Win.Trojan.Sha".into() },
            Group::File,
        );
        b.add_hash(
            HashSig { hash: md5(0x44), size: Some(512), name: "Win.Packed.Sect".into() },
            Group::Section,
        );
        b.add_hash(
            HashSig { hash: md5(0x55), size: Some(1024), name: "Known.Good.Installer".into() },
            Group::Allow,
        );
        b.add_body(BodySig {
            name: "Win.Test.Literal".into(),
            target: 1,
            offset: Offset::Any,
            pattern: b"REDOUBT-PATTERN".to_vec(),
        });
        b.add_body(BodySig {
            name: "Win.Test.AtZero".into(),
            target: 0,
            offset: Offset::Absolute(4),
            pattern: b"MZ\x90\x00".to_vec(),
        });
        b.write(path).unwrap()
    }

    fn temp_path(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("redoubt-test-{tag}-{}.sigidx", std::process::id()));
        p
    }

    #[test]
    fn builds_and_reads_back_every_group() {
        let path = temp_path("roundtrip");
        let stats = build(&path);
        assert_eq!(stats.file_hashes, 3);
        assert_eq!(stats.section_hashes, 1);
        assert_eq!(stats.allowlisted, 1);
        assert_eq!(stats.body_patterns, 2);

        let idx = SigIndex::open(&path).unwrap();
        assert_eq!(idx.db_version(), 27100);
        assert_eq!(idx.built_epoch(), 1_756_000_000);

        assert_eq!(idx.lookup(&md5(0x11), Group::File, 68), Some("Eicar-Test"));
        assert_eq!(idx.lookup(&sha256(0x33), Group::File, 4096), Some("Win.Trojan.Sha"));
        assert_eq!(idx.lookup(&md5(0x44), Group::Section, 512), Some("Win.Packed.Sect"));
        assert_eq!(idx.is_allowlisted(&md5(0x55), 1024), Some("Known.Good.Installer"));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn size_constraint_is_enforced() {
        let path = temp_path("size");
        build(&path);
        let idx = SigIndex::open(&path).unwrap();

        // Right hash, wrong size -> no match.
        assert_eq!(idx.lookup(&md5(0x11), Group::File, 999), None);
        // The '*' signature matches whatever size we ask about.
        assert_eq!(idx.lookup(&md5(0x22), Group::File, 1), Some("Win.Trojan.AnySize"));
        assert_eq!(idx.lookup(&md5(0x22), Group::File, 999_999), Some("Win.Trojan.AnySize"));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn groups_do_not_leak_into_each_other() {
        let path = temp_path("groups");
        build(&path);
        let idx = SigIndex::open(&path).unwrap();

        // A section hash must not answer a whole-file query, or a packed
        // section would get reported as a malicious file.
        assert_eq!(idx.lookup(&md5(0x44), Group::File, 512), None);
        assert_eq!(idx.lookup(&md5(0x11), Group::Section, 68), None);
        assert_eq!(idx.lookup(&md5(0x55), Group::File, 1024), None);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn misses_return_none() {
        let path = temp_path("miss");
        build(&path);
        let idx = SigIndex::open(&path).unwrap();
        assert_eq!(idx.lookup(&md5(0xEE), Group::File, 68), None);
        assert_eq!(idx.lookup(&sha256(0xEE), Group::File, 68), None);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn body_patterns_round_trip() {
        let path = temp_path("body");
        build(&path);
        let idx = SigIndex::open(&path).unwrap();

        let pats: Vec<_> = idx.body_patterns().collect();
        assert_eq!(pats.len(), 2);
        let literal = pats.iter().find(|p| p.name == "Win.Test.Literal").unwrap();
        assert_eq!(literal.pattern, b"REDOUBT-PATTERN");
        assert_eq!(literal.target, 1);
        assert_eq!(literal.offset, Offset::Any);

        let at_zero = pats.iter().find(|p| p.name == "Win.Test.AtZero").unwrap();
        assert_eq!(at_zero.offset, Offset::Absolute(4));
        assert_eq!(at_zero.pattern, b"MZ\x90\x00");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn duplicate_hashes_with_different_sizes_both_resolve() {
        let path = temp_path("dupes");
        let mut b = IndexBuilder::new(1, 0);
        b.add_hash(HashSig { hash: md5(0x77), size: Some(100), name: "Sig.A".into() }, Group::File);
        b.add_hash(HashSig { hash: md5(0x77), size: Some(200), name: "Sig.B".into() }, Group::File);
        b.write(&path).unwrap();

        let idx = SigIndex::open(&path).unwrap();
        assert_eq!(idx.lookup(&md5(0x77), Group::File, 100), Some("Sig.A"));
        assert_eq!(idx.lookup(&md5(0x77), Group::File, 200), Some("Sig.B"));
        assert_eq!(idx.lookup(&md5(0x77), Group::File, 300), None);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn names_are_interned_not_duplicated() {
        let mut b = IndexBuilder::new(1, 0);
        for i in 0..50u8 {
            b.add_hash(
                HashSig { hash: md5(i), size: Some(1), name: "Same.Family.Name".into() },
                Group::File,
            );
        }
        let path = temp_path("intern");
        let stats = b.write(&path).unwrap();
        assert_eq!(stats.file_hashes, 50);
        assert_eq!(stats.unique_names, 1, "50 signatures should share 1 interned name");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rejects_a_file_that_is_not_an_index() {
        let path = temp_path("garbage");
        std::fs::write(&path, vec![0u8; 512]).unwrap();
        let err = SigIndex::open(&path).unwrap_err();
        assert!(err.to_string().contains("bad magic"), "{err}");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rejects_a_truncated_index() {
        let path = temp_path("short");
        std::fs::write(&path, b"RDBTIDX\x01").unwrap();
        let err = SigIndex::open(&path).unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn empty_index_is_valid_and_answers_none() {
        let path = temp_path("empty");
        IndexBuilder::new(0, 0).write(&path).unwrap();
        let idx = SigIndex::open(&path).unwrap();
        assert_eq!(idx.lookup(&md5(0x01), Group::File, 1), None);
        assert_eq!(idx.body_patterns().count(), 0);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn stride_matches_hash_widths() {
        assert_eq!(stride(Table::FileMd5 as usize), 28);
        assert_eq!(stride(Table::FileSha1 as usize), 32);
        assert_eq!(stride(Table::FileSha256 as usize), 44);
        assert_eq!(stride(Table::AllowSha256 as usize), 44);
    }
}
