//! SigmaOS DOS component — PC-DOS/MS-DOS/FreeDOS compatibility layer.
//!
//! Parses DOS executable formats (MZ .EXE, raw .COM) into structured
//! metadata for emulation/inspection. Pure safe Rust, zero unsafe.

#![forbid(unsafe_code)]

use std::fmt;

/// Errors produced while parsing DOS executables.
#[derive(Debug)]
pub enum DosError {
    /// Input too short to contain a valid header.
    TooShort { need: usize, got: usize },
    /// Magic signature mismatch.
    BadMagic { expected: &'static str, found: u16 },
    /// Header fields are internally inconsistent.
    Malformed(&'static str),
}

impl fmt::Display for DosError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { need, got } => write!(f, "need {need} bytes, got {got}"),
            Self::BadMagic { expected, found } => write!(f, "bad magic: expected {expected}, found 0x{found:04X}"),
            Self::Malformed(m) => write!(f, "malformed: {m}"),
        }
    }
}

impl std::error::Error for DosError {}

fn u16le(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn u32le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Parsed MZ executable header (DOS .EXE).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MzHeader {
    /// Bytes in last page (0 = full 512).
    pub last_page_bytes: u16,
    /// Pages in file (excluding last partial page).
    pub pages: u16,
    /// Relocation item count.
    pub reloc_count: u16,
    /// Header size in 16-byte paragraphs.
    pub header_paragraphs: u16,
    /// Minimum allocation in paragraphs.
    pub min_alloc: u16,
    /// Maximum allocation in paragraphs.
    pub max_alloc: u16,
    /// Initial SS relative to load module.
    pub ss: u16,
    /// Initial SP.
    pub sp: u16,
    /// Checksum (0 = none).
    pub checksum: u16,
    /// Initial IP.
    pub ip: u16,
    /// Initial CS relative to load module.
    pub cs: u16,
    /// Relocation table file offset.
    pub reloc_offset: u32,
    /// Overlay number.
    pub overlay: u16,
}

/// Size of an MZ header in bytes (64 bytes fixed portion).
pub const MZ_HEADER_SIZE: usize = 64;

/// Parse an MZ (.EXE) header from raw bytes.
pub fn parse_mz(data: &[u8]) -> Result<MzHeader, DosError> {
    if data.len() < MZ_HEADER_SIZE {
        return Err(DosError::TooShort { need: MZ_HEADER_SIZE, got: data.len() });
    }
    let magic = u16le(data, 0);
    if magic != 0x5A4D {
        return Err(DosError::BadMagic { expected: "MZ", found: magic });
    }
    Ok(MzHeader {
        last_page_bytes: u16le(data, 2),
        pages: u16le(data, 4),
        reloc_count: u16le(data, 6),
        header_paragraphs: u16le(data, 8),
        min_alloc: u16le(data, 10),
        max_alloc: u16le(data, 12),
        ss: u16le(data, 14),
        sp: u16le(data, 16),
        checksum: u16le(data, 18),
        ip: u16le(data, 20),
        cs: u16le(data, 22),
        reloc_offset: u32le(data, 24),
        overlay: u16le(data, 28),
    })
}

/// Compute total image size in bytes implied by the header.
pub fn image_size(h: &MzHeader) -> u64 {
    let last = if h.last_page_bytes == 0 { 512 } else { h.last_page_bytes as u64 };
    (h.pages as u64 - 1) * 512 + last
}

/// Header size in bytes.
pub fn header_size(h: &MzHeader) -> usize {
    h.header_paragraphs as usize * 16
}

/// Determine executable kind from magic bytes.
pub fn detect_kind(data: &[u8]) -> &'static str {
    if data.len() < 2 { return "unknown"; }
    match u16le(data, 0) {
        0x5A4D => "mz-exe",
        0x454E => "ne-exe",   // 'NE'
        0x454C => "le-exe",   // 'LE'
        0x5843 => "com",      // heuristic: no magic — see below
        _ => {
            // .COM files have no magic; detect by absence of MZ/NE/LE
            "com-or-data"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mz_fixture() -> Vec<u8> {
        let mut b = vec![0u8; MZ_HEADER_SIZE];
        b[0] = 0x4D; b[1] = 0x5A; // 'MZ'
        b[2] = 0x00; b[3] = 0x02; // last page 512 → 0 means full page; use 512? spec: 0=full
        // set realistic values
        b[4] = 0x02; b[5] = 0x00; // pages = 2
        b[6] = 0x01; b[7] = 0x00; // reloc_count = 1
        b[8] = 0x04; b[9] = 0x00; // header_paragraphs = 4 → 64 bytes
        b[20] = 0x00; b[21] = 0x00; // ip
        b[22] = 0x00; b[23] = 0x00; // cs
        b
    }

    #[test]
    fn parses_mz_header() {
        let h = parse_mz(&mz_fixture()).unwrap();
        assert_eq!(h.pages, 2);
        assert_eq!(h.reloc_count, 1);
        assert_eq!(h.header_paragraphs, 4);
        assert_eq!(header_size(&h), 64);
    }

    #[test]
    fn image_size_math() {
        let h = parse_mz(&mz_fixture()).unwrap();
        // pages=2, last_page_bytes=0x0200=512 → (2-1)*512+512 = 1024
        assert_eq!(image_size(&h), 1024);
    }

    #[test]
    fn rejects_short() {
        assert!(matches!(parse_mz(&[0u8; 10]), Err(DosError::TooShort { .. })));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut b = vec![0u8; MZ_HEADER_SIZE];
        b[0] = 0x00; b[1] = 0x00;
        assert!(matches!(parse_mz(&b), Err(DosError::BadMagic { .. })));
    }

    #[test]
    fn detects_kind() {
        assert_eq!(detect_kind(&[0x4D, 0x5A]), "mz-exe");
        assert_eq!(detect_kind(&[0x00, 0x00]), "com-or-data");
    }
}
