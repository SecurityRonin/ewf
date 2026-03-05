//! Pure Rust reader for Expert Witness Format (E01/EWF) forensic disk images.
//!
//! Provides a `Read + Seek` interface over E01 images, supporting:
//! - EWF v1 format (`.E01` files produced by EnCase, FTK Imager, etc.)
//! - Multi-segment images (`.E01`, `.E02`, ..., `.E99`, `.EAA`, ..., `.EZZ`)
//! - zlib-compressed chunks with LRU caching
//! - O(1) seeking via flat chunk index

use std::io::{self, Read, Seek, SeekFrom};
use std::fs::File;
use std::path::{Path, PathBuf};

use flate2::read::ZlibDecoder;
use lru::LruCache;
use thiserror::Error;

/// EWF v1 magic signature: `"EVF\x09\x0d\x0a\xff\x00"` (8 bytes).
pub const EVF_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];

/// Size of the EWF v1 file header in bytes.
const FILE_HEADER_SIZE: usize = 13;

/// Size of a section descriptor in bytes.
const SECTION_DESCRIPTOR_SIZE: usize = 76;

/// Default LRU cache size (number of decompressed chunks to keep).
const DEFAULT_LRU_SIZE: usize = 100;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum EwfError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid EWF signature")]
    InvalidSignature,

    #[error("buffer too short: expected {expected}, got {got}")]
    BufferTooShort { expected: usize, got: usize },

    #[error("invalid chunk size: {0}")]
    InvalidChunkSize(u32),

    #[error("missing volume section")]
    MissingVolume,

    #[error("decompression error: {0}")]
    Decompression(String),

    #[error("segment gap: expected segment {expected}, got {got}")]
    SegmentGap { expected: u16, got: u16 },

    #[error("no segment files found matching: {0}")]
    NoSegments(String),
}

pub type Result<T> = std::result::Result<T, EwfError>;

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
struct Chunk {
    /// Index of the segment file that contains this chunk.
    segment_idx: usize,
    /// Whether this chunk is zlib-compressed.
    compressed: bool,
    /// Absolute file offset of the chunk data within its segment file.
    offset: u64,
    /// Size of the chunk data on disk (compressed size if compressed, else chunk_size).
    size: u64,
}

// ---------------------------------------------------------------------------
// Segment file discovery
// ---------------------------------------------------------------------------

/// Discover all segment files for an E01 image.
///
/// Given `image.E01`, finds `image.E02`, ..., `image.E99`, `image.EAA`, ..., `image.EZZ`.
/// Returns paths sorted by expected segment order.
fn discover_segments(first: &Path) -> Result<Vec<PathBuf>> {
    let stem = first
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| EwfError::NoSegments(first.display().to_string()))?;
    let parent = first.parent().unwrap_or_else(|| Path::new("."));

    // Glob for segment extensions: .E01-.E99, .EAA-.EZZ (and lowercase)
    // We use two patterns to match numeric (.E01) and alpha (.EAA) extensions
    let escaped_stem = glob::Pattern::escape(stem);
    let parent_str = parent.display();
    let mut paths: Vec<PathBuf> = Vec::new();
    for pattern in &[
        format!("{}/{}.[Ee][0-9][0-9]", parent_str, escaped_stem),
        format!("{}/{}.[Ee][A-Za-z][A-Za-z]", parent_str, escaped_stem),
    ] {
        if let Ok(entries) = glob::glob(pattern) {
            paths.extend(entries.filter_map(|r| r.ok()));
        }
    }

    if paths.is_empty() {
        return Err(EwfError::NoSegments(first.display().to_string()));
    }

    // Sort by extension to get natural segment order (E01 < E02 < ... < E99 < EAA < ... < EZZ)
    paths.sort_by(|a, b| {
        let ext_a = a.extension().and_then(|e| e.to_str()).unwrap_or("");
        let ext_b = b.extension().and_then(|e| e.to_str()).unwrap_or("");
        ext_a.to_ascii_uppercase().cmp(&ext_b.to_ascii_uppercase())
    });

    Ok(paths)
}

// ---------------------------------------------------------------------------
// EwfReader - main public API
// ---------------------------------------------------------------------------

/// A reader for Expert Witness Format (E01/EWF) forensic disk images.
///
/// Implements `Read` and `Seek` over the logical disk image stored across
/// one or more `.E01`/`.E02`/... segment files.
///
/// # Example
/// ```no_run
/// use std::io::Read;
/// let mut reader = ewf::EwfReader::open("disk.E01").unwrap();
/// let mut buf = [0u8; 512];
/// reader.read_exact(&mut buf).unwrap(); // read first sector
/// ```
pub struct EwfReader {
    /// Opened segment file handles.
    segments: Vec<File>,
    /// Flat chunk table: chunk[i] covers logical bytes [i*chunk_size, (i+1)*chunk_size).
    chunks: Vec<Chunk>,
    /// Chunk size in bytes (typically 32 KB).
    chunk_size: u64,
    /// Total logical image size in bytes.
    total_size: u64,
    /// Current read position (for Read + Seek).
    position: u64,
    /// LRU cache: chunk_id -> decompressed chunk data.
    cache: LruCache<usize, Vec<u8>>,
}

impl EwfReader {
    /// Open an EWF image from a path to the first segment file (e.g. `image.E01`).
    ///
    /// Automatically discovers and opens all additional segment files.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let paths = discover_segments(path.as_ref())?;
        Self::open_segments(&paths)
    }

    /// Open an EWF image with a custom LRU cache size.
    ///
    /// `cache_size` is the number of decompressed chunks to keep in memory.
    /// Each chunk is typically 32 KB, so 100 chunks ≈ 3.2 MB, 1000 ≈ 32 MB.
    pub fn open_with_cache_size<P: AsRef<Path>>(path: P, cache_size: usize) -> Result<Self> {
        let paths = discover_segments(path.as_ref())?;
        Self::open_segments_with_cache_size(&paths, cache_size)
    }

    /// Open an EWF image from explicit segment file paths (must be in order).
    pub fn open_segments(paths: &[PathBuf]) -> Result<Self> {
        Self::open_segments_with_cache_size(paths, DEFAULT_LRU_SIZE)
    }

    /// Open from explicit segment paths with a custom LRU cache size.
    pub fn open_segments_with_cache_size(paths: &[PathBuf], cache_size: usize) -> Result<Self> {
        if paths.is_empty() {
            return Err(EwfError::NoSegments("empty path list".into()));
        }

        // Open all segment files
        let mut segments = Vec::with_capacity(paths.len());
        let mut headers = Vec::with_capacity(paths.len());
        for path in paths {
            let mut f = File::open(path)?;
            let mut hdr_buf = [0u8; FILE_HEADER_SIZE];
            f.read_exact(&mut hdr_buf)?;
            headers.push(EwfFileHeader::parse(&hdr_buf)?);
            segments.push(f);
        }

        // Sort by segment number, validate sequential
        let mut indexed: Vec<(usize, u16)> = headers
            .iter()
            .enumerate()
            .map(|(i, h)| (i, h.segment_number))
            .collect();
        indexed.sort_by_key(|&(_, seg)| seg);

        let order: Vec<usize> = indexed.iter().map(|&(i, _)| i).collect();

        // Validate sequential segment numbers (1, 2, 3, ...)
        for (expected_pos, &(_, seg_num)) in indexed.iter().enumerate() {
            let expected = (expected_pos + 1) as u16;
            if seg_num != expected {
                return Err(EwfError::SegmentGap {
                    expected,
                    got: seg_num,
                });
            }
        }

        // Reorder the file handles
        let mut final_segments: Vec<Option<File>> = segments.into_iter().map(Some).collect();
        let mut ordered_segments = Vec::with_capacity(final_segments.len());
        for &idx in &order {
            ordered_segments.push(final_segments[idx].take().unwrap());
        }

        // Walk section descriptors in each segment to find volume and table sections
        let mut chunk_size: u64 = 0;
        let mut total_size: u64 = 0;
        let mut chunks: Vec<Chunk> = Vec::new();

        for (seg_idx, file) in ordered_segments.iter_mut().enumerate() {
            // First section descriptor starts at offset 13 (right after file header)
            let mut desc_offset: u64 = FILE_HEADER_SIZE as u64;
            // Collect section descriptors for this segment, then process.
            // This lets us prefer "table" over "table2" without losing multi-table support.
            let mut descriptors = Vec::new();

            loop {
                // Read section descriptor
                file.seek(SeekFrom::Start(desc_offset))?;
                let mut desc_buf = [0u8; SECTION_DESCRIPTOR_SIZE];
                file.read_exact(&mut desc_buf)?;
                let desc = SectionDescriptor::parse(&desc_buf, desc_offset)?;
                let next = desc.next;
                descriptors.push(desc);

                if next == 0 || next <= desc_offset {
                    break;
                }
                desc_offset = next;
            }

            // Determine which table type to use: prefer "table", fall back to "table2"
            let has_table = descriptors.iter().any(|d| d.section_type == "table");
            let table_type = if has_table { "table" } else { "table2" };

            for desc in &descriptors {
                match desc.section_type.as_str() {
                    "volume" | "disk" => {
                        // Read volume data right after the descriptor
                        let mut vol_buf = [0u8; 94];
                        file.seek(SeekFrom::Start(desc.offset + SECTION_DESCRIPTOR_SIZE as u64))?;
                        file.read_exact(&mut vol_buf)?;
                        let vol = EwfVolume::parse(&vol_buf)?;
                        chunk_size = vol.chunk_size();
                        total_size = vol.total_size();
                        if total_size == 0 {
                            total_size = chunk_size * vol.chunk_count as u64;
                        }
                        chunks.reserve(vol.chunk_count as usize);
                    }
                    t if t == table_type => {
                        // Read table header (24 bytes after descriptor)
                        let desc_offset = desc.offset;
                        file.seek(SeekFrom::Start(desc_offset + SECTION_DESCRIPTOR_SIZE as u64))?;
                        let mut tbl_hdr = [0u8; 24];
                        file.read_exact(&mut tbl_hdr)?;

                        let entry_count =
                            u64::from_le_bytes(tbl_hdr[0..8].try_into().unwrap()) as usize;
                        let base_offset = u64::from_le_bytes(tbl_hdr[8..16].try_into().unwrap());

                        // Read all table entries at once
                        let entries_offset =
                            desc_offset + SECTION_DESCRIPTOR_SIZE as u64 + 24;
                        file.seek(SeekFrom::Start(entries_offset))?;
                        let mut entries_buf = vec![0u8; entry_count * 4];
                        file.read_exact(&mut entries_buf)?;

                        // Parse entries and build chunk metadata
                        let mut prev_offset: Option<u64> = None;
                        for i in 0..entry_count {
                            let entry =
                                TableEntry::parse(&entries_buf[i * 4..(i + 1) * 4])?;
                            let abs_offset = entry.chunk_offset as u64 + base_offset;

                            // Compute previous chunk's compressed size
                            if let Some(po) = prev_offset {
                                if let Some(prev_chunk) = chunks.last_mut() {
                                    if prev_chunk.compressed {
                                        let sz = abs_offset.saturating_sub(po);
                                        if sz > 0 {
                                            prev_chunk.size = sz;
                                        }
                                    }
                                }
                            }

                            chunks.push(Chunk {
                                segment_idx: seg_idx,
                                compressed: entry.compressed,
                                offset: abs_offset,
                                size: chunk_size, // default; overwritten for compressed
                            });

                            prev_offset = Some(abs_offset);
                        }
                    }
                    _ => {
                        // Skip header, header2, sectors, hash, digest, done, etc.
                    }
                }
            }
        }

        if chunk_size == 0 {
            return Err(EwfError::MissingVolume);
        }

        let cache = LruCache::new(
            std::num::NonZeroUsize::new(cache_size.max(1)).unwrap(),
        );

        Ok(Self {
            segments: ordered_segments,
            chunks,
            chunk_size,
            total_size,
            position: 0,
            cache,
        })
    }

    /// Total logical size of the disk image in bytes.
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Chunk size in bytes (typically 32768).
    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }

    /// Number of chunks in the image.
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Read and decompress a single chunk by its index.
    fn read_chunk(&mut self, chunk_id: usize) -> Result<Vec<u8>> {
        // Check cache
        if let Some(cached) = self.cache.get(&chunk_id) {
            return Ok(cached.clone());
        }

        let mut page = vec![0u8; self.chunk_size as usize];

        if chunk_id >= self.chunks.len() {
            // Out of range: return zero-filled
            return Ok(page);
        }

        let chunk = self.chunks[chunk_id].clone();
        let file = &mut self.segments[chunk.segment_idx];

        if !chunk.compressed {
            // Raw read
            file.seek(SeekFrom::Start(chunk.offset))?;
            let to_read = std::cmp::min(chunk.size as usize, page.len());
            file.read_exact(&mut page[..to_read])?;
        } else {
            // Read compressed data (may be shorter than chunk.size for last chunk)
            let mut compressed = vec![0u8; chunk.size as usize];
            file.seek(SeekFrom::Start(chunk.offset))?;
            let mut total_read = 0;
            while total_read < compressed.len() {
                match file.read(&mut compressed[total_read..]) {
                    Ok(0) => break,
                    Ok(n) => total_read += n,
                    Err(e) => return Err(EwfError::Io(e)),
                }
            }
            let compressed = &compressed[..total_read];

            // zlib decompress
            let mut decoder = ZlibDecoder::new(&compressed[..]);
            let mut total = 0;
            loop {
                match decoder.read(&mut page[total..]) {
                    Ok(0) => break,
                    Ok(n) => total += n,
                    Err(e) => {
                        return Err(EwfError::Decompression(e.to_string()));
                    }
                }
            }
        }

        // Cache the result
        self.cache.put(chunk_id, page.clone());
        Ok(page)
    }

    /// Read bytes at an arbitrary logical offset (internal, no position tracking).
    fn read_at(&mut self, buf: &mut [u8], offset: u64) -> Result<usize> {
        let mut buf_idx = 0usize;
        let mut off = offset;

        loop {
            let remaining_image = self.total_size.saturating_sub(off);
            let remaining_buf = buf.len() - buf_idx;
            let in_chunk = self.chunk_size - (off % self.chunk_size);

            let to_read = in_chunk
                .min(remaining_image)
                .min(remaining_buf as u64) as usize;

            if to_read == 0 {
                break;
            }

            let chunk_id = (off / self.chunk_size) as usize;
            let page = self.read_chunk(chunk_id)?;

            let page_offset = (off % self.chunk_size) as usize;
            buf[buf_idx..buf_idx + to_read]
                .copy_from_slice(&page[page_offset..page_offset + to_read]);

            off += to_read as u64;
            buf_idx += to_read;
        }

        Ok(buf_idx)
    }
}

impl Read for EwfReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self
            .read_at(buf, self.position)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for EwfReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(p) => p as i64,
            SeekFrom::End(p) => self.total_size as i64 + p,
            SeekFrom::Current(p) => self.position as i64 + p,
        };
        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek to negative position",
            ));
        }
        self.position = new_pos as u64;
        Ok(self.position)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- EwfFileHeader tests --

    fn make_file_header(segment_number: u16) -> [u8; 13] {
        let mut buf = [0u8; FILE_HEADER_SIZE];
        buf[0..8].copy_from_slice(&EVF_SIGNATURE);
        buf[8] = 0x01; // Fields_start
        buf[9..11].copy_from_slice(&segment_number.to_le_bytes());
        buf[11] = 0x00; // Fields_end (low byte)
        buf[12] = 0x00; // Fields_end (high byte)
        buf
    }

    #[test]
    fn parse_file_header_segment_1() {
        let buf = make_file_header(1);
        let header = EwfFileHeader::parse(&buf).unwrap();
        assert_eq!(header.segment_number, 1);
    }

    #[test]
    fn parse_file_header_segment_42() {
        let buf = make_file_header(42);
        let header = EwfFileHeader::parse(&buf).unwrap();
        assert_eq!(header.segment_number, 42);
    }

    #[test]
    fn parse_file_header_rejects_invalid_signature() {
        let buf = [0u8; 13];
        let result = EwfFileHeader::parse(&buf);
        assert!(matches!(result, Err(EwfError::InvalidSignature)));
    }

    #[test]
    fn parse_file_header_rejects_short_buffer() {
        let buf = [0u8; 5];
        let result = EwfFileHeader::parse(&buf);
        assert!(matches!(result, Err(EwfError::BufferTooShort { .. })));
    }

    // -- SectionDescriptor tests --

    fn make_section_descriptor(section_type: &str, next: u64, section_size: u64) -> [u8; 76] {
        let mut buf = [0u8; SECTION_DESCRIPTOR_SIZE];
        // Type field: 16 bytes, NUL-padded
        let type_bytes = section_type.as_bytes();
        buf[..type_bytes.len()].copy_from_slice(type_bytes);
        // Next: u64 LE at offset 16
        buf[16..24].copy_from_slice(&next.to_le_bytes());
        // SectionSize: u64 LE at offset 24
        buf[24..32].copy_from_slice(&section_size.to_le_bytes());
        // Checksum at offset 72 (skip for now, not validated)
        buf
    }

    #[test]
    fn parse_section_descriptor_volume() {
        let buf = make_section_descriptor("volume", 1000, 170);
        let desc = SectionDescriptor::parse(&buf, 13).unwrap();
        assert_eq!(desc.section_type, "volume");
        assert_eq!(desc.next, 1000);
        assert_eq!(desc.section_size, 170);
        assert_eq!(desc.offset, 13);
    }

    #[test]
    fn parse_section_descriptor_table() {
        let buf = make_section_descriptor("table", 50000, 4096);
        let desc = SectionDescriptor::parse(&buf, 200).unwrap();
        assert_eq!(desc.section_type, "table");
        assert_eq!(desc.next, 50000);
        assert_eq!(desc.section_size, 4096);
    }

    #[test]
    fn parse_section_descriptor_done() {
        let buf = make_section_descriptor("done", 0, 76);
        let desc = SectionDescriptor::parse(&buf, 9999).unwrap();
        assert_eq!(desc.section_type, "done");
        assert_eq!(desc.next, 0);
    }

    #[test]
    fn parse_section_descriptor_rejects_short_buffer() {
        let buf = [0u8; 10];
        let result = SectionDescriptor::parse(&buf, 0);
        assert!(matches!(result, Err(EwfError::BufferTooShort { .. })));
    }

    // -- EwfVolume tests --

    fn make_volume_data(
        chunk_count: u32,
        sectors_per_chunk: u32,
        bytes_per_sector: u32,
        sector_count: u64,
    ) -> [u8; 94] {
        let mut buf = [0u8; 94];
        // media_type at offset 0 (skip)
        buf[4..8].copy_from_slice(&chunk_count.to_le_bytes());
        buf[8..12].copy_from_slice(&sectors_per_chunk.to_le_bytes());
        buf[12..16].copy_from_slice(&bytes_per_sector.to_le_bytes());
        buf[16..24].copy_from_slice(&sector_count.to_le_bytes());
        buf
    }

    #[test]
    fn parse_volume_typical() {
        let buf = make_volume_data(1000, 64, 512, 64000);
        let vol = EwfVolume::parse(&buf).unwrap();
        assert_eq!(vol.chunk_count, 1000);
        assert_eq!(vol.sectors_per_chunk, 64);
        assert_eq!(vol.bytes_per_sector, 512);
        assert_eq!(vol.sector_count, 64000);
        assert_eq!(vol.chunk_size(), 32768); // 64 * 512
        assert_eq!(vol.total_size(), 512 * 64000);
    }

    #[test]
    fn parse_volume_rejects_short_buffer() {
        let buf = [0u8; 10];
        let result = EwfVolume::parse(&buf);
        assert!(matches!(result, Err(EwfError::BufferTooShort { .. })));
    }

    // -- TableEntry tests --

    #[test]
    fn parse_table_entry_compressed() {
        // bit 31 set, offset = 0x1000
        let val: u32 = 0x8000_1000;
        let buf = val.to_le_bytes();
        let entry = TableEntry::parse(&buf).unwrap();
        assert!(entry.compressed);
        assert_eq!(entry.chunk_offset, 0x1000);
    }

    #[test]
    fn parse_table_entry_uncompressed() {
        let val: u32 = 0x0000_2000;
        let buf = val.to_le_bytes();
        let entry = TableEntry::parse(&buf).unwrap();
        assert!(!entry.compressed);
        assert_eq!(entry.chunk_offset, 0x2000);
    }

    #[test]
    fn parse_table_entry_rejects_short_buffer() {
        let buf = [0u8; 2];
        let result = TableEntry::parse(&buf);
        assert!(matches!(result, Err(EwfError::BufferTooShort { .. })));
    }

    // -- EwfReader synthetic E01 tests --

    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Build a minimal single-segment E01 file with known data.
    ///
    /// Layout:
    ///   [0..13)     File header (segment 1)
    ///   [13..89)    Section descriptor: "volume", next -> table_desc_offset
    ///   [89..183)   Volume data (94 bytes)
    ///   [183..259)  Section descriptor: "table", next -> sectors_desc_offset
    ///   [259..283)  Table header (24 bytes): 1 entry, base_offset = sectors_data_offset
    ///   [283..287)  Table entry (4 bytes): compressed bit + offset 0
    ///   [287..363)  Section descriptor: "sectors"
    ///   [363..363+N) Sectors data (zlib-compressed chunk)
    ///   [363+N..)   Section descriptor: "done", next = 0
    fn build_synthetic_e01(data: &[u8]) -> NamedTempFile {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;

        let chunk_size: u32 = 32768; // 64 sectors * 512 bytes
        let sectors_per_chunk: u32 = 64;
        let bytes_per_sector: u32 = 512;
        // Pad data to chunk_size
        let mut padded = data.to_vec();
        padded.resize(chunk_size as usize, 0);

        // Compress the chunk
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&padded).unwrap();
        let compressed = encoder.finish().unwrap();

        let sector_count = (chunk_size / bytes_per_sector) as u64;

        // Calculate offsets
        let vol_desc_offset: u64 = FILE_HEADER_SIZE as u64; // 13
        let vol_data_offset: u64 = vol_desc_offset + SECTION_DESCRIPTOR_SIZE as u64; // 89
        let tbl_desc_offset: u64 = vol_data_offset + 94; // 183
        let tbl_hdr_offset: u64 = tbl_desc_offset + SECTION_DESCRIPTOR_SIZE as u64; // 259
        let tbl_entries_offset: u64 = tbl_hdr_offset + 24; // 283
        let sectors_desc_offset: u64 = tbl_entries_offset + 4; // 287
        let sectors_data_offset: u64 = sectors_desc_offset + SECTION_DESCRIPTOR_SIZE as u64; // 363
        let done_desc_offset: u64 = sectors_data_offset + compressed.len() as u64;

        let mut file_data = Vec::new();

        // 1. File header (13 bytes)
        file_data.extend_from_slice(&EVF_SIGNATURE);
        file_data.push(0x01); // Fields_start
        file_data.extend_from_slice(&1u16.to_le_bytes()); // Segment 1
        file_data.extend_from_slice(&0u16.to_le_bytes()); // Fields_end

        // 2. Volume section descriptor (76 bytes)
        let mut vol_desc = [0u8; SECTION_DESCRIPTOR_SIZE];
        vol_desc[..6].copy_from_slice(b"volume");
        vol_desc[16..24].copy_from_slice(&tbl_desc_offset.to_le_bytes()); // next
        vol_desc[24..32].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u64 + 94).to_le_bytes()); // section_size
        file_data.extend_from_slice(&vol_desc);

        // 3. Volume data (94 bytes)
        let mut vol_data = [0u8; 94];
        // media_type = 1 (fixed) at offset 0
        vol_data[0..4].copy_from_slice(&1u32.to_le_bytes());
        vol_data[4..8].copy_from_slice(&1u32.to_le_bytes()); // chunk_count = 1
        vol_data[8..12].copy_from_slice(&sectors_per_chunk.to_le_bytes());
        vol_data[12..16].copy_from_slice(&bytes_per_sector.to_le_bytes());
        vol_data[16..24].copy_from_slice(&sector_count.to_le_bytes());
        file_data.extend_from_slice(&vol_data);

        // 4. Table section descriptor (76 bytes)
        let mut tbl_desc = [0u8; SECTION_DESCRIPTOR_SIZE];
        tbl_desc[..5].copy_from_slice(b"table");
        tbl_desc[16..24].copy_from_slice(&sectors_desc_offset.to_le_bytes()); // next
        let tbl_section_size = SECTION_DESCRIPTOR_SIZE as u64 + 24 + 4;
        tbl_desc[24..32].copy_from_slice(&tbl_section_size.to_le_bytes());
        file_data.extend_from_slice(&tbl_desc);

        // 5. Table header (24 bytes)
        let mut tbl_hdr = [0u8; 24];
        tbl_hdr[0..8].copy_from_slice(&1u64.to_le_bytes()); // 1 entry
        tbl_hdr[8..16].copy_from_slice(&sectors_data_offset.to_le_bytes()); // base_offset
        file_data.extend_from_slice(&tbl_hdr);

        // 6. Table entry (4 bytes): compressed, chunk_offset = 0
        let entry: u32 = 0x8000_0000; // compressed bit set, offset = 0
        file_data.extend_from_slice(&entry.to_le_bytes());

        // 7. Sectors section descriptor (76 bytes)
        let mut sec_desc = [0u8; SECTION_DESCRIPTOR_SIZE];
        sec_desc[..7].copy_from_slice(b"sectors");
        sec_desc[16..24].copy_from_slice(&done_desc_offset.to_le_bytes()); // next
        let sec_section_size = SECTION_DESCRIPTOR_SIZE as u64 + compressed.len() as u64;
        sec_desc[24..32].copy_from_slice(&sec_section_size.to_le_bytes());
        file_data.extend_from_slice(&sec_desc);

        // 8. Compressed chunk data
        file_data.extend_from_slice(&compressed);

        // 9. Done section descriptor (76 bytes)
        let mut done_desc = [0u8; SECTION_DESCRIPTOR_SIZE];
        done_desc[..4].copy_from_slice(b"done");
        // next = 0 (end of chain)
        done_desc[24..32].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u64).to_le_bytes());
        file_data.extend_from_slice(&done_desc);

        let mut tmp = tempfile::Builder::new()
            .suffix(".E01")
            .tempfile()
            .unwrap();
        tmp.write_all(&file_data).unwrap();
        tmp.flush().unwrap();
        tmp
    }

    #[test]
    fn ewf_reader_opens_synthetic_e01() {
        let data = b"Hello, forensic world!";
        let tmp = build_synthetic_e01(data);
        let reader = EwfReader::open(tmp.path()).unwrap();
        assert_eq!(reader.chunk_size(), 32768);
        assert_eq!(reader.chunk_count(), 1);
        assert!(reader.total_size() > 0);
    }

    #[test]
    fn ewf_reader_reads_first_bytes() {
        let data = b"DEADBEEF_CAFEBABE_1234567890";
        let tmp = build_synthetic_e01(data);
        let mut reader = EwfReader::open(tmp.path()).unwrap();
        let mut buf = vec![0u8; data.len()];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, data);
    }

    #[test]
    fn ewf_reader_seek_and_read() {
        let mut test_data = vec![0u8; 1024];
        // Write a known pattern at offset 512
        test_data[512..520].copy_from_slice(b"SEEKTEST");
        let tmp = build_synthetic_e01(&test_data);
        let mut reader = EwfReader::open(tmp.path()).unwrap();

        // Seek to offset 512
        reader.seek(SeekFrom::Start(512)).unwrap();
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"SEEKTEST");
    }

    #[test]
    fn ewf_reader_seek_from_end() {
        let data = b"test";
        let tmp = build_synthetic_e01(data);
        let mut reader = EwfReader::open(tmp.path()).unwrap();
        let size = reader.total_size();

        // Seek to 4 bytes before end, then read should get zeros (padded area)
        let pos = reader.seek(SeekFrom::End(-4)).unwrap();
        assert_eq!(pos, size - 4);
    }

    #[test]
    fn ewf_reader_read_returns_zero_at_eof() {
        let data = b"short";
        let tmp = build_synthetic_e01(data);
        let mut reader = EwfReader::open(tmp.path()).unwrap();
        // Seek past end
        reader.seek(SeekFrom::Start(reader.total_size())).unwrap();
        let mut buf = [0u8; 10];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    // -- Enhancement: table2 support --

    /// Build a synthetic E01 that uses "table2" instead of "table" for the chunk table.
    /// Some EnCase versions write both; our reader must handle either.
    fn build_synthetic_e01_with_table2(data: &[u8]) -> NamedTempFile {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;

        let chunk_size: u32 = 32768;
        let sectors_per_chunk: u32 = 64;
        let bytes_per_sector: u32 = 512;
        let mut padded = data.to_vec();
        padded.resize(chunk_size as usize, 0);

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&padded).unwrap();
        let compressed = encoder.finish().unwrap();

        let sector_count = (chunk_size / bytes_per_sector) as u64;

        let vol_desc_offset: u64 = FILE_HEADER_SIZE as u64;
        let vol_data_offset: u64 = vol_desc_offset + SECTION_DESCRIPTOR_SIZE as u64;
        let tbl_desc_offset: u64 = vol_data_offset + 94;
        let tbl_hdr_offset: u64 = tbl_desc_offset + SECTION_DESCRIPTOR_SIZE as u64;
        let tbl_entries_offset: u64 = tbl_hdr_offset + 24;
        let sectors_desc_offset: u64 = tbl_entries_offset + 4;
        let sectors_data_offset: u64 = sectors_desc_offset + SECTION_DESCRIPTOR_SIZE as u64;
        let done_desc_offset: u64 = sectors_data_offset + compressed.len() as u64;

        let mut file_data = Vec::new();

        // File header
        file_data.extend_from_slice(&EVF_SIGNATURE);
        file_data.push(0x01);
        file_data.extend_from_slice(&1u16.to_le_bytes());
        file_data.extend_from_slice(&0u16.to_le_bytes());

        // Volume descriptor
        let mut vol_desc = [0u8; SECTION_DESCRIPTOR_SIZE];
        vol_desc[..6].copy_from_slice(b"volume");
        vol_desc[16..24].copy_from_slice(&tbl_desc_offset.to_le_bytes());
        vol_desc[24..32].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u64 + 94).to_le_bytes());
        file_data.extend_from_slice(&vol_desc);

        // Volume data
        let mut vol_data = [0u8; 94];
        vol_data[0..4].copy_from_slice(&1u32.to_le_bytes());
        vol_data[4..8].copy_from_slice(&1u32.to_le_bytes());
        vol_data[8..12].copy_from_slice(&sectors_per_chunk.to_le_bytes());
        vol_data[12..16].copy_from_slice(&bytes_per_sector.to_le_bytes());
        vol_data[16..24].copy_from_slice(&sector_count.to_le_bytes());
        file_data.extend_from_slice(&vol_data);

        // Table descriptor -- uses "table2" instead of "table"
        let mut tbl_desc = [0u8; SECTION_DESCRIPTOR_SIZE];
        tbl_desc[..6].copy_from_slice(b"table2");
        tbl_desc[16..24].copy_from_slice(&sectors_desc_offset.to_le_bytes());
        let tbl_section_size = SECTION_DESCRIPTOR_SIZE as u64 + 24 + 4;
        tbl_desc[24..32].copy_from_slice(&tbl_section_size.to_le_bytes());
        file_data.extend_from_slice(&tbl_desc);

        // Table header
        let mut tbl_hdr = [0u8; 24];
        tbl_hdr[0..8].copy_from_slice(&1u64.to_le_bytes());
        tbl_hdr[8..16].copy_from_slice(&sectors_data_offset.to_le_bytes());
        file_data.extend_from_slice(&tbl_hdr);

        // Table entry
        let entry: u32 = 0x8000_0000;
        file_data.extend_from_slice(&entry.to_le_bytes());

        // Sectors descriptor
        let mut sec_desc = [0u8; SECTION_DESCRIPTOR_SIZE];
        sec_desc[..7].copy_from_slice(b"sectors");
        sec_desc[16..24].copy_from_slice(&done_desc_offset.to_le_bytes());
        let sec_section_size = SECTION_DESCRIPTOR_SIZE as u64 + compressed.len() as u64;
        sec_desc[24..32].copy_from_slice(&sec_section_size.to_le_bytes());
        file_data.extend_from_slice(&sec_desc);

        // Compressed chunk data
        file_data.extend_from_slice(&compressed);

        // Done descriptor
        let mut done_desc = [0u8; SECTION_DESCRIPTOR_SIZE];
        done_desc[..4].copy_from_slice(b"done");
        done_desc[24..32].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u64).to_le_bytes());
        file_data.extend_from_slice(&done_desc);

        let mut tmp = tempfile::Builder::new()
            .suffix(".E01")
            .tempfile()
            .unwrap();
        tmp.write_all(&file_data).unwrap();
        tmp.flush().unwrap();
        tmp
    }

    #[test]
    fn ewf_reader_handles_table2_sections() {
        let data = b"table2 section test data!";
        let tmp = build_synthetic_e01_with_table2(data);
        let mut reader = EwfReader::open(tmp.path()).unwrap();
        assert_eq!(reader.chunk_count(), 1);
        let mut buf = vec![0u8; data.len()];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, data);
    }

    #[test]
    fn ewf_reader_skips_duplicate_table2() {
        // Build a synthetic E01 with BOTH "table" and "table2" sections
        // (same chunk data). Reader should not double-count chunks.
        use flate2::write::ZlibEncoder;
        use flate2::Compression;

        let chunk_size: u32 = 32768;
        let sectors_per_chunk: u32 = 64;
        let bytes_per_sector: u32 = 512;
        let mut padded = b"dedup test".to_vec();
        padded.resize(chunk_size as usize, 0);

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&padded).unwrap();
        let compressed = encoder.finish().unwrap();
        let sector_count = (chunk_size / bytes_per_sector) as u64;

        // Layout: header | vol_desc | vol_data | tbl_desc("table") | tbl_hdr | entry |
        //         tbl2_desc("table2") | tbl2_hdr | entry2 | sec_desc | data | done_desc
        let vol_desc_off: u64 = 13;
        let vol_data_off: u64 = vol_desc_off + 76;
        let tbl_desc_off: u64 = vol_data_off + 94;
        let tbl_hdr_off: u64 = tbl_desc_off + 76;
        let tbl_entry_off: u64 = tbl_hdr_off + 24;
        let tbl2_desc_off: u64 = tbl_entry_off + 4;
        let tbl2_hdr_off: u64 = tbl2_desc_off + 76;
        let tbl2_entry_off: u64 = tbl2_hdr_off + 24;
        let sec_desc_off: u64 = tbl2_entry_off + 4;
        let sec_data_off: u64 = sec_desc_off + 76;
        let done_desc_off: u64 = sec_data_off + compressed.len() as u64;

        let mut d = Vec::new();

        // File header
        d.extend_from_slice(&EVF_SIGNATURE);
        d.push(0x01);
        d.extend_from_slice(&1u16.to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes());

        // Volume descriptor -> next = tbl_desc
        let mut vd = [0u8; 76];
        vd[..6].copy_from_slice(b"volume");
        vd[16..24].copy_from_slice(&tbl_desc_off.to_le_bytes());
        vd[24..32].copy_from_slice(&(76u64 + 94).to_le_bytes());
        d.extend_from_slice(&vd);

        // Volume data
        let mut vdata = [0u8; 94];
        vdata[0..4].copy_from_slice(&1u32.to_le_bytes());
        vdata[4..8].copy_from_slice(&1u32.to_le_bytes()); // 1 chunk
        vdata[8..12].copy_from_slice(&sectors_per_chunk.to_le_bytes());
        vdata[12..16].copy_from_slice(&bytes_per_sector.to_le_bytes());
        vdata[16..24].copy_from_slice(&sector_count.to_le_bytes());
        d.extend_from_slice(&vdata);

        // Table descriptor "table" -> next = tbl2_desc
        let mut td = [0u8; 76];
        td[..5].copy_from_slice(b"table");
        td[16..24].copy_from_slice(&tbl2_desc_off.to_le_bytes());
        td[24..32].copy_from_slice(&(76u64 + 24 + 4).to_le_bytes());
        d.extend_from_slice(&td);

        // Table header: 1 entry, base = sec_data_off
        let mut th = [0u8; 24];
        th[0..8].copy_from_slice(&1u64.to_le_bytes());
        th[8..16].copy_from_slice(&sec_data_off.to_le_bytes());
        d.extend_from_slice(&th);

        // Table entry: compressed, offset 0
        d.extend_from_slice(&0x8000_0000u32.to_le_bytes());

        // Table2 descriptor "table2" -> next = sec_desc
        let mut td2 = [0u8; 76];
        td2[..6].copy_from_slice(b"table2");
        td2[16..24].copy_from_slice(&sec_desc_off.to_le_bytes());
        td2[24..32].copy_from_slice(&(76u64 + 24 + 4).to_le_bytes());
        d.extend_from_slice(&td2);

        // Table2 header (identical)
        d.extend_from_slice(&th);

        // Table2 entry (identical)
        d.extend_from_slice(&0x8000_0000u32.to_le_bytes());

        // Sectors descriptor
        let mut sd = [0u8; 76];
        sd[..7].copy_from_slice(b"sectors");
        sd[16..24].copy_from_slice(&done_desc_off.to_le_bytes());
        sd[24..32].copy_from_slice(&(76u64 + compressed.len() as u64).to_le_bytes());
        d.extend_from_slice(&sd);

        // Compressed data
        d.extend_from_slice(&compressed);

        // Done
        let mut dd = [0u8; 76];
        dd[..4].copy_from_slice(b"done");
        dd[24..32].copy_from_slice(&76u64.to_le_bytes());
        d.extend_from_slice(&dd);

        let mut tmp = tempfile::Builder::new().suffix(".E01").tempfile().unwrap();
        tmp.write_all(&d).unwrap();
        tmp.flush().unwrap();

        let reader = EwfReader::open(tmp.path()).unwrap();
        // Volume says 1 chunk. Even though both table and table2 exist,
        // we should have exactly 1 chunk, not 2.
        assert_eq!(reader.chunk_count(), 1, "table2 caused duplicate chunks");
    }

    // -- Enhancement: configurable LRU cache size --

    #[test]
    fn ewf_reader_open_with_cache_size() {
        let data = b"cache size test";
        let tmp = build_synthetic_e01(data);
        // Should compile and work with a custom cache size
        let reader = EwfReader::open_with_cache_size(tmp.path(), 10).unwrap();
        assert_eq!(reader.chunk_count(), 1);
    }

    /// Smoke test against real E01 image (requires test-data/).
    #[test]
    #[ignore]
    fn ewf_reader_opens_real_e01() {
        let path = std::path::Path::new(
            "../usnjrnl-forensic/test-data/20200918_0417_DESKTOP-SDN1RPT.E01",
        );
        if !path.exists() {
            panic!("Test image not found at {}", path.display());
        }
        let mut reader = EwfReader::open(path).unwrap();
        assert!(reader.total_size() > 0);
        eprintln!("Image size: {} bytes ({:.2} GB)", reader.total_size(),
            reader.total_size() as f64 / 1_073_741_824.0);
        eprintln!("Chunk size: {} bytes", reader.chunk_size());
        eprintln!("Chunk count: {}", reader.chunk_count());

        // Read first sector (MBR/GPT protective MBR)
        let mut sector = [0u8; 512];
        reader.read_exact(&mut sector).unwrap();
        // MBR signature at bytes 510-511
        assert_eq!(sector[510], 0x55);
        assert_eq!(sector[511], 0xAA);
        eprintln!("MBR signature verified: 0x55AA");
    }
}
