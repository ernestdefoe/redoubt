//! Portable Executable inspection.
//!
//! Two jobs:
//!
//! 1. **Section hashing**, so ClamAV `.mdb`/`.msb` signatures can match. Those
//!    identify malware by a single section's bytes, which survives the
//!    repacking that changes a whole-file hash.
//! 2. **Structural signals** for the heuristics - entropy, writable+executable
//!    sections, a missing import table.
//!
//! Parsing is delegated to `goblin` rather than hand-rolled. This code reads
//! attacker-controlled headers by definition, and a battle-tested parser is
//! worth more here than saving a dependency. Everything below still bounds-
//! checks against the real file length, because a PE header is free to claim
//! a section extends past the end of the file - and plenty of malware does
//! exactly that to trip naive scanners.

use crate::hashing::{entropy, md5_bytes, sha256_bytes};
use crate::sigs::HashValue;

/// `IMAGE_SCN_MEM_EXECUTE`
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// `IMAGE_SCN_MEM_WRITE`
const SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Sections smaller than this are not worth hashing or scoring for entropy;
/// short buffers produce meaningless entropy values.
const MIN_SECTION_BYTES: usize = 64;

/// One PE section, already clamped to what is actually present in the file.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    /// Offset of the section's raw data within the file.
    pub raw_offset: usize,
    /// Raw data length, clamped to the real end of the file.
    pub raw_size: usize,
    /// Size the header *claimed*, before clamping. A mismatch is itself a
    /// signal that something is lying.
    pub declared_size: u32,
    pub characteristics: u32,
    pub entropy: f64,
}

impl Section {
    pub fn is_executable(&self) -> bool {
        self.characteristics & SCN_MEM_EXECUTE != 0
    }
    pub fn is_writable(&self) -> bool {
        self.characteristics & SCN_MEM_WRITE != 0
    }
    /// Writable *and* executable: normal for a packer's unpacking stub,
    /// abnormal for a compiler's output.
    pub fn is_writable_executable(&self) -> bool {
        self.is_executable() && self.is_writable()
    }

    /// `INIT` in a kernel driver is writable, executable and discardable by
    /// design - it holds `DriverEntry` and is freed once boot completes. Every
    /// driver on the system has one, so counting it is pure noise.
    pub fn is_conventional_rwx(&self) -> bool {
        self.name.eq_ignore_ascii_case("INIT")
    }
    /// True when the header declared more bytes than the file contains.
    pub fn is_truncated(&self) -> bool {
        self.declared_size as usize > self.raw_size
    }
}

/// Everything the scanner needs to know about a PE.
#[derive(Debug, Clone)]
pub struct PeInfo {
    pub is_dll: bool,
    /// True when the CLR runtime header data directory is present.
    ///
    /// This matters a great deal for the import heuristic: a .NET assembly
    /// imports exactly one symbol (`mscoree!_CorExeMain`) by design. Without
    /// this flag, "suspiciously few imports" would fire on essentially every
    /// managed executable on the machine.
    pub is_dotnet: bool,
    pub machine: u16,
    pub sections: Vec<Section>,
    /// Number of imported symbols across all libraries.
    pub import_count: usize,
    /// Distinct DLLs imported.
    pub imported_libraries: Vec<String>,
    /// Entropy over the whole file.
    pub overall_entropy: f64,
    /// Bytes after the last section - installers and self-extractors put
    /// payloads here, and so do some droppers.
    pub overlay_size: usize,
}

impl PeInfo {
    /// Parse `data` as a PE. Returns `None` for anything that is not one, or
    /// that is too malformed for goblin to make sense of.
    pub fn parse(data: &[u8]) -> Option<Self> {
        // Cheap rejection before handing malformed input to a full parser.
        if data.len() < 64 || &data[..2] != b"MZ" {
            return None;
        }
        let pe = goblin::pe::PE::parse(data).ok()?;

        let mut sections = Vec::with_capacity(pe.sections.len());
        let mut highest_end = 0usize;

        for s in &pe.sections {
            let declared_size = s.size_of_raw_data;
            let raw_offset = s.pointer_to_raw_data as usize;

            // A header may point past the end of the file, or claim a size
            // that overflows. Clamp to what really exists.
            let (raw_offset, raw_size) = if raw_offset >= data.len() {
                (data.len(), 0)
            } else {
                let avail = data.len() - raw_offset;
                (raw_offset, (declared_size as usize).min(avail))
            };
            highest_end = highest_end.max(raw_offset + raw_size);

            let bytes = &data[raw_offset..raw_offset + raw_size];
            sections.push(Section {
                name: s.name().unwrap_or("<unnamed>").trim_end_matches('\0').to_string(),
                raw_offset,
                raw_size,
                declared_size,
                characteristics: s.characteristics,
                entropy: if raw_size >= MIN_SECTION_BYTES { entropy(bytes) } else { 0.0 },
            });
        }

        let imported_libraries = {
            let mut libs: Vec<String> =
                pe.imports.iter().map(|i| i.dll.to_ascii_lowercase()).collect();
            libs.sort_unstable();
            libs.dedup();
            libs
        };

        let is_dotnet = pe
            .header
            .optional_header
            .as_ref()
            .and_then(|oh| oh.data_directories.get_clr_runtime_header())
            .map(|d| d.virtual_address != 0)
            .unwrap_or(false);

        Some(PeInfo {
            is_dll: pe.is_lib,
            is_dotnet,
            machine: pe.header.coff_header.machine,
            import_count: pe.imports.len(),
            imported_libraries,
            overall_entropy: entropy(data),
            overlay_size: data.len().saturating_sub(highest_end),
            sections,
        })
    }

    /// MD5 and SHA-256 of each section, paired with its size, for matching
    /// against `.mdb` and `.msb` signatures.
    ///
    /// ClamAV keys those on the section's *raw size*, so a section whose
    /// header size was clamped is skipped rather than hashed at the wrong
    /// length - a wrong-length hash cannot match anything and would only cost
    /// time.
    pub fn section_hashes<'a>(
        &'a self,
        data: &'a [u8],
    ) -> impl Iterator<Item = (u64, HashValue, HashValue)> + 'a {
        self.sections.iter().filter_map(move |s| {
            if s.raw_size < MIN_SECTION_BYTES || s.is_truncated() {
                return None;
            }
            let bytes = data.get(s.raw_offset..s.raw_offset + s.raw_size)?;
            Some((s.raw_size as u64, md5_bytes(bytes), sha256_bytes(bytes)))
        })
    }

    /// The highest entropy of any code section, which is what packing shows up
    /// in. Whole-file entropy is diluted by resources and is a poorer signal.
    pub fn max_executable_entropy(&self) -> f64 {
        self.sections
            .iter()
            .filter(|s| s.is_executable() && s.raw_size >= MIN_SECTION_BYTES)
            .map(|s| s.entropy)
            .fold(0.0, f64::max)
    }

    /// Sections that are both writable and executable, excluding those that
    /// are conventionally so.
    pub fn writable_executable_sections(&self) -> Vec<&Section> {
        self.sections
            .iter()
            .filter(|s| s.is_writable_executable() && !s.is_conventional_rwx())
            .collect()
    }

    /// True when the file actually carries executable code.
    ///
    /// Resource-only modules - `.mui` satellite DLLs, API-set forwarder stubs,
    /// icon libraries - are PE files with no code at all. They are the bulk of
    /// what lives in System32, and treating them like programs is what makes
    /// naive import heuristics fire thousands of times on a clean machine.
    pub fn has_executable_code(&self) -> bool {
        self.sections
            .iter()
            .any(|s| s.is_executable() && s.raw_size >= MIN_SECTION_BYTES)
    }

    /// True when the import table is empty or trivially small.
    ///
    /// A real native program imports dozens of symbols. A packed dropper
    /// typically imports only `LoadLibrary`/`GetProcAddress` and resolves the
    /// rest at runtime, so the threshold is low rather than zero.
    ///
    /// Three exemptions, each measured against a real System32 sweep:
    ///
    /// - **.NET assemblies** import exactly one symbol by design.
    /// - **DLLs** are frequently resource-only or pure forwarders; a dropper
    ///   is almost always an `.exe`.
    /// - **Code-free modules** have nothing to resolve imports *for*.
    ///
    /// Without these this fired on 3,598 of 24,869 files in System32 - 14% of
    /// a clean Windows install, which is worse than useless.
    pub fn has_suspiciously_few_imports(&self) -> bool {
        !self.is_dotnet && !self.is_dll && self.has_executable_code() && self.import_count <= 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but structurally valid PE32+ so the parser has
    /// something real to chew on without checking a binary into the repo.
    fn synthetic_pe(section_chars: u32, section_body: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 0x400];
        // DOS header: MZ + e_lfanew at 0x3C pointing to the PE header.
        buf[0..2].copy_from_slice(b"MZ");
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

        let pe = 0x80usize;
        buf[pe..pe + 4].copy_from_slice(b"PE\0\0");
        // COFF header
        buf[pe + 4..pe + 6].copy_from_slice(&0x8664u16.to_le_bytes()); // machine x86-64
        buf[pe + 6..pe + 8].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        buf[pe + 20..pe + 22].copy_from_slice(&240u16.to_le_bytes()); // opt header size
        buf[pe + 22..pe + 24].copy_from_slice(&0x0022u16.to_le_bytes()); // EXECUTABLE_IMAGE

        // Optional header (PE32+)
        let opt = pe + 24;
        buf[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+ magic
        buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry point
        buf[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes()); // image base
        buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section align
        buf[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file align
        buf[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // size of image
        buf[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes()); // size of headers
        buf[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // rva count

        // Section table follows the optional header.
        let sec = opt + 240;
        buf[sec..sec + 8].copy_from_slice(b".text\0\0\0");
        buf[sec + 8..sec + 12].copy_from_slice(&(section_body.len() as u32).to_le_bytes()); // virtual size
        buf[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual address
        buf[sec + 16..sec + 20].copy_from_slice(&(section_body.len() as u32).to_le_bytes()); // raw size
        buf[sec + 20..sec + 24].copy_from_slice(&0x400u32.to_le_bytes()); // raw offset
        buf[sec + 36..sec + 40].copy_from_slice(&section_chars.to_le_bytes());

        buf.extend_from_slice(section_body);
        buf
    }

    fn low_entropy_body() -> Vec<u8> {
        b"function_prologue_and_ordinary_code_bytes_".repeat(16)
    }

    fn high_entropy_body() -> Vec<u8> {
        let mut state = 0x2545F4914F6CDD1Du64;
        (0..4096)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn rejects_things_that_are_not_pe_files() {
        assert!(PeInfo::parse(b"").is_none());
        assert!(PeInfo::parse(b"#!/bin/sh\necho hi\n").is_none());
        assert!(PeInfo::parse(&[0u8; 4096]).is_none());
        assert!(PeInfo::parse(b"PK\x03\x04zipfile").is_none());
        // MZ but nothing behind it.
        assert!(PeInfo::parse(b"MZ").is_none());
    }

    #[test]
    fn parses_a_minimal_pe() {
        let body = low_entropy_body();
        let data = synthetic_pe(SCN_MEM_EXECUTE, &body);
        let pe = PeInfo::parse(&data).expect("should parse as PE");

        assert_eq!(pe.machine, 0x8664);
        assert_eq!(pe.sections.len(), 1);
        assert_eq!(pe.sections[0].name, ".text");
        assert_eq!(pe.sections[0].raw_size, body.len());
        assert!(pe.sections[0].is_executable());
        assert!(!pe.sections[0].is_writable());
    }

    #[test]
    fn clamps_a_section_that_claims_to_run_past_the_end_of_the_file() {
        // The classic malformed-header trick: declare a huge section so a
        // naive parser reads (or panics) out of bounds.
        let body = low_entropy_body();
        let mut data = synthetic_pe(SCN_MEM_EXECUTE, &body);
        let sec = 0x80 + 24 + 240;
        data[sec + 16..sec + 20].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());

        let pe = PeInfo::parse(&data).expect("should still parse");
        let s = &pe.sections[0];
        assert!(s.raw_offset + s.raw_size <= data.len(), "must not exceed the file");
        assert!(s.is_truncated(), "the lie should be recorded");
        // And a truncated section must not be hashed at the wrong length.
        assert_eq!(pe.section_hashes(&data).count(), 0);
    }

    #[test]
    fn clamps_a_section_whose_offset_is_past_the_end_of_the_file() {
        let body = low_entropy_body();
        let mut data = synthetic_pe(SCN_MEM_EXECUTE, &body);
        let sec = 0x80 + 24 + 240;
        data[sec + 20..sec + 24].copy_from_slice(&0x7FFF_0000u32.to_le_bytes());

        let pe = PeInfo::parse(&data).expect("should still parse");
        assert_eq!(pe.sections[0].raw_size, 0);
        assert_eq!(pe.section_hashes(&data).count(), 0);
    }

    #[test]
    fn detects_writable_executable_sections() {
        let body = low_entropy_body();

        let normal = synthetic_pe(SCN_MEM_EXECUTE, &body);
        let pe = PeInfo::parse(&normal).unwrap();
        assert!(pe.writable_executable_sections().is_empty());

        let packed = synthetic_pe(SCN_MEM_EXECUTE | SCN_MEM_WRITE, &body);
        let pe = PeInfo::parse(&packed).unwrap();
        assert_eq!(pe.writable_executable_sections().len(), 1);
        assert!(pe.sections[0].is_writable_executable());
    }

    #[test]
    fn executable_entropy_separates_code_from_packed_data() {
        let plain = synthetic_pe(SCN_MEM_EXECUTE, &low_entropy_body());
        let packed = synthetic_pe(SCN_MEM_EXECUTE, &high_entropy_body());

        let plain_e = PeInfo::parse(&plain).unwrap().max_executable_entropy();
        let packed_e = PeInfo::parse(&packed).unwrap().max_executable_entropy();

        assert!(plain_e < 5.0, "ordinary code entropy was {plain_e}");
        assert!(packed_e > 7.5, "packed entropy was {packed_e}");
        // And the default 7.2 threshold must sit between them.
        assert!(plain_e < 7.2 && packed_e > 7.2);
    }

    #[test]
    fn non_executable_sections_do_not_count_toward_code_entropy() {
        // A high-entropy *resource* section is ordinary (compressed images);
        // only executable sections should drive the packing heuristic.
        let data = synthetic_pe(SCN_MEM_WRITE, &high_entropy_body());
        let pe = PeInfo::parse(&data).unwrap();
        assert_eq!(pe.max_executable_entropy(), 0.0);
        assert!(pe.sections[0].entropy > 7.5, "the section itself is still high-entropy");
    }

    #[test]
    fn section_hashes_are_stable_and_sized() {
        let body = low_entropy_body();
        let data = synthetic_pe(SCN_MEM_EXECUTE, &body);
        let pe = PeInfo::parse(&data).unwrap();

        let hashes: Vec<_> = pe.section_hashes(&data).collect();
        assert_eq!(hashes.len(), 1);
        let (size, md5, sha256) = &hashes[0];
        assert_eq!(*size, body.len() as u64);

        // The hash must be over the section bytes alone, not the whole file.
        assert_eq!(*md5, crate::hashing::md5_bytes(&body));
        assert_eq!(*sha256, crate::hashing::sha256_bytes(&body));
    }

    #[test]
    fn tiny_sections_are_skipped() {
        let data = synthetic_pe(SCN_MEM_EXECUTE, b"tiny");
        let pe = PeInfo::parse(&data).unwrap();
        assert_eq!(pe.section_hashes(&data).count(), 0, "4 bytes is not worth a signature");
        assert_eq!(pe.sections[0].entropy, 0.0);
    }

    #[test]
    fn a_pe_with_no_imports_is_flagged() {
        let data = synthetic_pe(SCN_MEM_EXECUTE, &low_entropy_body());
        let pe = PeInfo::parse(&data).unwrap();
        assert_eq!(pe.import_count, 0);
        assert!(pe.has_executable_code());
        assert!(pe.has_suspiciously_few_imports());
    }

    #[test]
    fn a_module_with_no_code_is_not_flagged_for_missing_imports() {
        // Resource-only modules - .mui satellites, API-set forwarders - have
        // no imports because they have nothing to import *for*. They are the
        // bulk of System32, and flagging them fired on 14% of a clean install.
        let data = synthetic_pe(SCN_MEM_WRITE, &low_entropy_body());
        let pe = PeInfo::parse(&data).unwrap();
        assert!(!pe.has_executable_code());
        assert!(
            !pe.has_suspiciously_few_imports(),
            "a code-free module must not trip the import heuristic"
        );
    }

    #[test]
    fn a_dll_is_not_flagged_for_missing_imports() {
        let mut data = synthetic_pe(SCN_MEM_EXECUTE, &low_entropy_body());
        // Set IMAGE_FILE_DLL (0x2000) in the COFF characteristics.
        let pe_off = 0x80usize;
        let chars = u16::from_le_bytes(
            data[pe_off + 22..pe_off + 24].try_into().unwrap(),
        ) | 0x2000;
        data[pe_off + 22..pe_off + 24].copy_from_slice(&chars.to_le_bytes());

        let pe = PeInfo::parse(&data).unwrap();
        assert!(pe.is_dll);
        assert!(
            !pe.has_suspiciously_few_imports(),
            "DLLs are routinely forwarders; a dropper is almost always an .exe"
        );
    }

    #[test]
    fn a_driver_init_section_is_not_reported_as_writable_executable() {
        // INIT is RWX and discardable by design in every kernel driver on the
        // system; counting it produced 87 findings across System32.
        let mut data = synthetic_pe(SCN_MEM_EXECUTE | SCN_MEM_WRITE, &low_entropy_body());
        let sec = 0x80 + 24 + 240;
        data[sec..sec + 8].copy_from_slice(b"INIT\0\0\0\0");

        let pe = PeInfo::parse(&data).unwrap();
        assert_eq!(pe.sections[0].name, "INIT");
        assert!(pe.sections[0].is_writable_executable(), "it really is RWX");
        assert!(
            pe.writable_executable_sections().is_empty(),
            "but INIT is conventional and must not be reported"
        );
    }
}
