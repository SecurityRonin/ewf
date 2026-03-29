use crate::error::{EwfError, Result};

/// EWF v1 magic signature: `"EVF\x09\x0d\x0a\xff\x00"` (8 bytes).
pub const EVF_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];

/// Size of the EWF v1 file header in bytes.
pub(crate) const FILE_HEADER_SIZE: usize = 13;

/// Size of a section descriptor in bytes.
pub(crate) const SECTION_DESCRIPTOR_SIZE: usize = 76;

/// Default LRU cache size (number of decompressed chunks to keep).
pub(crate) const DEFAULT_LRU_SIZE: usize = 100;

// ---------------------------------------------------------------------------
// EWF File Header (13 bytes)
// ---------------------------------------------------------------------------

/// Parsed EWF v1 file header. Present at offset 0 of every segment file.
///
/// Layout (little-endian):
/// | Offset | Size | Field          |
/// |--------|------|----------------|
/// | 0      | 8    | EVF signature  |
/// | 8      | 1    | Fields_start   |
/// | 9      | 2    | Segment number |
/// | 11     | 2    | Fields_end     |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EwfFileHeader {
    pub segment_number: u16,
}

impl EwfFileHeader {
    /// Parse a file header from a byte slice (must be >= 13 bytes).
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < FILE_HEADER_SIZE {
            return Err(EwfError::BufferTooShort {
                expected: FILE_HEADER_SIZE,
                got: buf.len(),
            });
        }
        if buf[0..8] != EVF_SIGNATURE {
            return Err(EwfError::InvalidSignature);
        }
        let segment_number = u16::from_le_bytes([buf[9], buf[10]]);
        Ok(Self { segment_number })
    }
}

// ---------------------------------------------------------------------------
// Section Descriptor (76 bytes)
// ---------------------------------------------------------------------------

/// Parsed EWF v1 section descriptor. Forms a linked list within each segment.
///
/// Layout (little-endian):
/// | Offset | Size | Field       |
/// |--------|------|-------------|
/// | 0      | 16   | Type (NUL-padded string) |
/// | 16     | 8    | Next (absolute file offset) |
/// | 24     | 8    | SectionSize |
/// | 72     | 4    | Checksum    |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionDescriptor {
    /// Section type string (e.g. "header", "volume", "table", "sectors", "done").
    pub section_type: String,
    /// Absolute file offset of the next section descriptor (0 = end of chain).
    pub next: u64,
    /// Size of this section's data (including the 76-byte descriptor itself).
    pub section_size: u64,
    /// Absolute file offset where this descriptor was found.
    pub offset: u64,
}

impl SectionDescriptor {
    /// Parse a section descriptor from a 76-byte buffer.
    /// `offset` is the absolute file position where this descriptor starts.
    pub fn parse(buf: &[u8], offset: u64) -> Result<Self> {
        if buf.len() < SECTION_DESCRIPTOR_SIZE {
            return Err(EwfError::BufferTooShort {
                expected: SECTION_DESCRIPTOR_SIZE,
                got: buf.len(),
            });
        }
        // Type: 16 bytes, NUL-terminated
        let type_end = buf[..16].iter().position(|&b| b == 0).unwrap_or(16);
        let section_type = String::from_utf8_lossy(&buf[..type_end]).into_owned();
        let next = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let section_size = u64::from_le_bytes(buf[24..32].try_into().unwrap());
        Ok(Self {
            section_type,
            next,
            section_size,
            offset,
        })
    }
}

// ---------------------------------------------------------------------------
// Volume Section (parsed from "volume" or "disk" section data)
// ---------------------------------------------------------------------------

/// Image geometry extracted from the EWF volume section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EwfVolume {
    pub chunk_count: u32,
    pub sectors_per_chunk: u32,
    pub bytes_per_sector: u32,
    pub sector_count: u64,
}

impl EwfVolume {
    /// Parse volume data from bytes following a "volume"/"disk" section descriptor.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 24 {
            return Err(EwfError::BufferTooShort {
                expected: 24,
                got: buf.len(),
            });
        }
        let chunk_count = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let sectors_per_chunk = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let bytes_per_sector = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        let sector_count = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        Ok(Self {
            chunk_count,
            sectors_per_chunk,
            bytes_per_sector,
            sector_count,
        })
    }

    /// Chunk size in bytes (sectors_per_chunk * bytes_per_sector).
    pub fn chunk_size(&self) -> u64 {
        self.sectors_per_chunk as u64 * self.bytes_per_sector as u64
    }

    /// Total image size in bytes (bytes_per_sector * sector_count).
    pub fn total_size(&self) -> u64 {
        self.bytes_per_sector as u64 * self.sector_count
    }
}

// ---------------------------------------------------------------------------
// Table Entry (4 bytes) and Chunk metadata
// ---------------------------------------------------------------------------

/// A single table entry: 4-byte bitfield where bit 31 = compressed, bits 0-30 = offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableEntry {
    pub compressed: bool,
    pub chunk_offset: u32,
}

impl TableEntry {
    /// Parse a table entry from a 4-byte little-endian value.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            return Err(EwfError::BufferTooShort {
                expected: 4,
                got: buf.len(),
            });
        }
        let raw = u32::from_le_bytes(buf[..4].try_into().unwrap());
        let compressed = (raw >> 31) != 0;
        let chunk_offset = raw & 0x7FFF_FFFF;
        Ok(Self {
            compressed,
            chunk_offset,
        })
    }
}

/// Internal chunk metadata: where to find and how to read one chunk of image data.
#[derive(Debug, Clone)]
pub(crate) struct Chunk {
    /// Index of the segment file that contains this chunk.
    pub(crate) segment_idx: usize,
    /// Whether this chunk is zlib-compressed.
    pub(crate) compressed: bool,
    /// Absolute file offset of the chunk data within its segment file.
    pub(crate) offset: u64,
    /// Size of the chunk data on disk (compressed size if compressed, else chunk_size).
    pub(crate) size: u64,
}
