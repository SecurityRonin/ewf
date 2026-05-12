use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use flate2::read::ZlibDecoder;
use lru::LruCache;

use crate::error::{EwfError, Result};
use crate::ewf2;
use crate::parse::{parse_error2_data, parse_header_text};
use crate::sections::{
    Chunk, EwfFileHeader, EwfVolume, SectionDescriptor, TableEntry, DEFAULT_LRU_SIZE,
    FILE_HEADER_SIZE, SECTION_DESCRIPTOR_SIZE,
};
#[cfg(feature = "verify")]
use crate::types::VerifyResult;
use crate::types::{AcquisitionError, EwfMetadata, StoredHashes};

// ---------------------------------------------------------------------------
// Segment file discovery
// ---------------------------------------------------------------------------

/// Discover all segment files for an EWF image (E01, L01, Ex01, or Lx01).
///
/// Detects the extension prefix from the input path:
/// - 3-char (v1): `.E01`..`.EZZ`, `.L01`..`.LZZ`
/// - 4-char (v2): `.Ex01`..`.EzZZ`, `.Lx01`..`.LzZZ`
///
/// Returns paths sorted by expected segment order.
fn discover_segments(first: &Path) -> Result<Vec<PathBuf>> {
    let stem = first
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| EwfError::NoSegments(first.display().to_string()))?;
    let parent = first.parent().unwrap_or_else(|| Path::new("."));

    let ext = first.extension().and_then(|e| e.to_str()).unwrap_or("E01");

    let escaped_stem = glob::Pattern::escape(stem);
    let parent_str = parent.display();
    let mut paths: Vec<PathBuf> = Vec::new();

    if ext.len() == 4 {
        // EWF2: 4-char extensions like Ex01, Lx01
        let prefix = ext.chars().next().unwrap().to_ascii_uppercase();
        let lc = prefix.to_ascii_lowercase();
        for pattern in &[
            format!("{parent_str}/{escaped_stem}.[{prefix}{lc}][x-z][0-9][0-9]"),
            format!("{parent_str}/{escaped_stem}.[{prefix}{lc}][x-z][A-Za-z][A-Za-z]"),
        ] {
            if let Ok(entries) = glob::glob(pattern) {
                paths.extend(entries.filter_map(std::result::Result::ok));
            }
        }
    } else {
        // EWF v1: 3-char extensions like E01, L01
        let prefix = ext.chars().next().unwrap().to_ascii_uppercase();
        let lc = prefix.to_ascii_lowercase();
        for pattern in &[
            format!("{parent_str}/{escaped_stem}.[{prefix}{lc}][0-9][0-9]"),
            format!("{parent_str}/{escaped_stem}.[{prefix}{lc}][A-Za-z][A-Za-z]"),
        ] {
            if let Ok(entries) = glob::glob(pattern) {
                paths.extend(entries.filter_map(std::result::Result::ok));
            }
        }
    }

    if paths.is_empty() {
        return Err(EwfError::NoSegments(first.display().to_string()));
    }

    // Sort by extension for natural segment order
    paths.sort_by(|a, b| {
        let ext_a = a.extension().and_then(|e| e.to_str()).unwrap_or("");
        let ext_b = b.extension().and_then(|e| e.to_str()).unwrap_or("");
        ext_a.to_ascii_uppercase().cmp(&ext_b.to_ascii_uppercase())
    });

    Ok(paths)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Maximum section data size we'll read into memory (`DoS` guard).
const MAX_SECTION_DATA_SIZE: u64 = 1_000_000;

/// Maximum table entries we'll allocate for (`DoS` guard).
/// 4M entries × 32 KB chunks = 128 TB image — far beyond any real forensic image.
const MAX_TABLE_ENTRIES: usize = 4_000_000;

/// Maximum chunk size in bytes. EWF typically uses 32 KB; 128 MB is a generous cap.
const MAX_CHUNK_SIZE: u64 = 128 * 1024 * 1024;

/// Maximum chunk count from the volume header. Reuses the table entry cap.
const MAX_CHUNK_COUNT: usize = MAX_TABLE_ENTRIES;

/// Default EWF2 chunk size when `device_info` is absent or unparseable.
const DEFAULT_V2_CHUNK_SIZE: u64 = 32768;

/// Validate that segment numbers are sequential (1, 2, 3, ...) and reorder
/// file handles to match. Shared by both v1 and v2 reader paths.
pub(crate) fn validate_and_reorder_segments(
    segments: Vec<File>,
    segment_numbers: Vec<u32>,
) -> Result<Vec<File>> {
    let mut indexed: Vec<(usize, u32)> = segment_numbers.into_iter().enumerate().collect();
    indexed.sort_by_key(|&(_, seg)| seg);

    // Validate sequential segment numbers (1, 2, 3, ...)
    for (expected_pos, &(_, seg_num)) in indexed.iter().enumerate() {
        let expected = (expected_pos + 1) as u32;
        if seg_num != expected {
            return Err(EwfError::SegmentGap {
                expected,
                got: seg_num,
            });
        }
    }

    // Reorder file handles to match segment order
    let mut slots: Vec<Option<File>> = segments.into_iter().map(Some).collect();
    let mut ordered = Vec::with_capacity(slots.len());
    for &(idx, _) in &indexed {
        ordered.push(slots[idx].take().unwrap());
    }
    Ok(ordered)
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
    // Note: LruCache does not implement Debug, so we cannot derive Debug.
    // We provide a manual impl below.
    /// Opened segment file handles.
    segments: Vec<File>,
    /// Flat chunk table: chunk[i] covers logical bytes [i*`chunk_size`, (i+1)*`chunk_size`).
    chunks: Vec<Chunk>,
    /// Chunk size in bytes (typically 32 KB).
    chunk_size: u64,
    /// Total logical image size in bytes.
    total_size: u64,
    /// Current read position (for Read + Seek).
    position: u64,
    /// LRU cache: `chunk_id` -> decompressed chunk data.
    cache: LruCache<usize, Vec<u8>>,
    /// MD5 from hash/digest section (16 bytes), if present.
    stored_md5: Option<[u8; 16]>,
    /// SHA-1 from digest section (20 bytes), if present.
    stored_sha1: Option<[u8; 20]>,
    /// Case and acquisition metadata from header sections.
    metadata: EwfMetadata,
    /// Sectors with read errors during acquisition (from error2 section).
    acquisition_errors: Vec<AcquisitionError>,
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

        // Peek at the first 8 bytes to determine format version
        {
            let mut probe = File::open(&paths[0])?;
            let mut sig = [0u8; 8];
            probe.read_exact(&mut sig)?;
            if sig == ewf2::EVF2_SIGNATURE || sig == ewf2::LEF2_SIGNATURE {
                return Self::open_segments_v2(paths, cache_size);
            }
        }

        // EWF v1 path
        // Open all segment files and parse file headers
        let mut segments = Vec::with_capacity(paths.len());
        let mut headers = Vec::with_capacity(paths.len());
        for path in paths {
            let mut f = File::open(path)?;
            let mut hdr_buf = [0u8; FILE_HEADER_SIZE];
            f.read_exact(&mut hdr_buf)?;
            headers.push(EwfFileHeader::parse(&hdr_buf)?);
            segments.push(f);
        }

        let segment_numbers: Vec<u32> = headers
            .iter()
            .map(|h| u32::from(h.segment_number))
            .collect();
        let mut ordered_segments = validate_and_reorder_segments(segments, segment_numbers)?;

        // Walk section descriptors in each segment
        let mut chunk_size: u64 = 0;
        let mut total_size: u64 = 0;
        let mut chunks: Vec<Chunk> = Vec::new();
        let mut stored_md5: Option<[u8; 16]> = None;
        let mut stored_sha1: Option<[u8; 20]> = None;
        let mut metadata = EwfMetadata::default();
        let mut acquisition_errors: Vec<AcquisitionError> = Vec::new();

        for (seg_idx, file) in ordered_segments.iter_mut().enumerate() {
            let mut desc_offset: u64 = FILE_HEADER_SIZE as u64;
            let mut descriptors = Vec::new();

            let file_len = file.seek(SeekFrom::End(0))?;
            while let Some(chain_end) = desc_offset.checked_add(SECTION_DESCRIPTOR_SIZE as u64) {
                // checked_add handles u64::MAX overflow — loop ends if offset wraps.
                if chain_end > file_len {
                    log::debug!("truncated chain at {desc_offset}, EOF {file_len}");
                    break;
                }

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

            // Prefer "table" over "table2"
            let has_table = descriptors.iter().any(|d| d.section_type == "table");
            let table_type = if has_table { "table" } else { "table2" };

            // Find sectors section end boundary for last-chunk back-fill.
            // Use saturating_add: a crafted section_size = u64::MAX would overflow otherwise.
            let sectors_data_end: Option<u64> = descriptors
                .iter()
                .find(|d| d.section_type == "sectors")
                .map(|d| d.offset.saturating_add(d.section_size));

            for desc in &descriptors {
                match desc.section_type.as_str() {
                    "volume" | "disk" => {
                        let mut vol_buf = [0u8; 94];
                        file.seek(SeekFrom::Start(
                            desc.offset + SECTION_DESCRIPTOR_SIZE as u64,
                        ))?;
                        file.read_exact(&mut vol_buf)?;
                        let vol = EwfVolume::parse(&vol_buf)?;
                        let cs = vol.chunk_size();
                        if cs > MAX_CHUNK_SIZE {
                            return Err(EwfError::InvalidChunkSize(
                                cs.min(u64::from(u32::MAX)) as u32
                            ));
                        }
                        if vol.chunk_count as usize > MAX_CHUNK_COUNT {
                            return Err(EwfError::Parse(format!(
                                "volume chunk_count {} exceeds maximum {MAX_CHUNK_COUNT}",
                                vol.chunk_count
                            )));
                        }
                        chunk_size = cs;
                        total_size = vol.total_size();
                        if total_size == 0 {
                            total_size = chunk_size * u64::from(vol.chunk_count);
                        }
                        chunks.reserve(vol.chunk_count as usize);
                    }
                    t if t == table_type => {
                        let desc_offset = desc.offset;
                        file.seek(SeekFrom::Start(
                            desc_offset + SECTION_DESCRIPTOR_SIZE as u64,
                        ))?;
                        let mut tbl_hdr = [0u8; 24];
                        file.read_exact(&mut tbl_hdr)?;

                        let entry_count =
                            u32::from_le_bytes(tbl_hdr[0..4].try_into().unwrap()) as usize;
                        if entry_count > MAX_TABLE_ENTRIES {
                            return Err(EwfError::Parse(format!(
                                "table entry count {entry_count} exceeds maximum {MAX_TABLE_ENTRIES}"
                            )));
                        }
                        let base_offset = u64::from_le_bytes(tbl_hdr[8..16].try_into().unwrap());

                        let entries_offset = desc_offset + SECTION_DESCRIPTOR_SIZE as u64 + 24;
                        file.seek(SeekFrom::Start(entries_offset))?;
                        let mut entries_buf = vec![0u8; entry_count * 4];
                        file.read_exact(&mut entries_buf)?;

                        let mut prev_offset: Option<u64> = None;
                        for i in 0..entry_count {
                            let entry = TableEntry::parse(&entries_buf[i * 4..(i + 1) * 4])?;
                            let abs_offset = u64::from(entry.chunk_offset) + base_offset;

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
                                size: chunk_size,
                            });

                            prev_offset = Some(abs_offset);
                        }

                        // Back-fill last compressed chunk from sectors boundary
                        if let Some(end) = sectors_data_end {
                            if let Some(last) = chunks.last_mut() {
                                if last.compressed && last.size == chunk_size {
                                    let actual = end.saturating_sub(last.offset);
                                    if actual > 0 && actual < chunk_size {
                                        last.size = actual;
                                    }
                                }
                            }
                        }
                    }
                    "hash" => {
                        let data_offset = desc.offset + SECTION_DESCRIPTOR_SIZE as u64;
                        file.seek(SeekFrom::Start(data_offset))?;
                        let mut hash_buf = [0u8; 16];
                        file.read_exact(&mut hash_buf)?;
                        if stored_md5.is_none() {
                            stored_md5 = Some(hash_buf);
                        }
                        log::debug!("parsed hash section: MD5 = {hash_buf:02x?}");
                    }
                    "digest" => {
                        let data_offset = desc.offset + SECTION_DESCRIPTOR_SIZE as u64;
                        file.seek(SeekFrom::Start(data_offset))?;
                        let mut digest_buf = [0u8; 36];
                        file.read_exact(&mut digest_buf)?;
                        let mut md5 = [0u8; 16];
                        let mut sha1 = [0u8; 20];
                        md5.copy_from_slice(&digest_buf[0..16]);
                        sha1.copy_from_slice(&digest_buf[16..36]);
                        stored_md5 = Some(md5);
                        stored_sha1 = Some(sha1);
                        log::debug!("parsed digest section: MD5 = {md5:02x?}, SHA-1 = {sha1:02x?}");
                    }
                    "header" if metadata.case_number.is_none() && metadata.os_version.is_none() => {
                        let data_offset = desc.offset + SECTION_DESCRIPTOR_SIZE as u64;
                        let data_size = desc
                            .section_size
                            .saturating_sub(SECTION_DESCRIPTOR_SIZE as u64);
                        if data_size > 0 && data_size < MAX_SECTION_DATA_SIZE {
                            file.seek(SeekFrom::Start(data_offset))?;
                            let mut compressed = vec![0u8; data_size as usize];
                            file.read_exact(&mut compressed)?;
                            if let Ok(decompressed) = std::io::Read::bytes(std::io::BufReader::new(
                                flate2::read::ZlibDecoder::new(&compressed[..]),
                            ))
                            .collect::<std::result::Result<Vec<u8>, _>>()
                            {
                                let text = String::from_utf8_lossy(&decompressed);
                                parse_header_text(&text, &mut metadata);
                            }
                        }
                    }
                    "error2" => {
                        let data_offset = desc.offset + SECTION_DESCRIPTOR_SIZE as u64;
                        let data_size = desc
                            .section_size
                            .saturating_sub(SECTION_DESCRIPTOR_SIZE as u64);
                        if data_size > 0 && data_size < MAX_SECTION_DATA_SIZE {
                            file.seek(SeekFrom::Start(data_offset))?;
                            let mut buf = vec![0u8; data_size as usize];
                            file.read_exact(&mut buf)?;
                            acquisition_errors = parse_error2_data(&buf);
                            log::debug!(
                                "parsed error2 section: {} entries",
                                acquisition_errors.len()
                            );
                        }
                    }
                    _ => {}
                }
            }
        }

        if chunk_size == 0 {
            return Err(EwfError::MissingVolume);
        }

        let cache = LruCache::new(std::num::NonZeroUsize::new(cache_size.max(1)).unwrap());

        Ok(Self {
            segments: ordered_segments,
            chunks,
            chunk_size,
            total_size,
            position: 0,
            cache,
            stored_md5,
            stored_sha1,
            metadata,
            acquisition_errors,
        })
    }

    /// Open EWF2 (Ex01/Lx01) segments.
    fn open_segments_v2(paths: &[PathBuf], cache_size: usize) -> Result<Self> {
        // Open all segment files and parse v2 headers
        let mut segments = Vec::with_capacity(paths.len());
        let mut v2_headers = Vec::with_capacity(paths.len());
        for path in paths {
            let mut f = File::open(path)?;
            let mut hdr_buf = [0u8; ewf2::FILE_HEADER_SIZE];
            f.read_exact(&mut hdr_buf)?;
            v2_headers.push(ewf2::Ewf2FileHeader::parse(&hdr_buf)?);
            segments.push(f);
        }

        let mut ordered_segments = validate_and_reorder_segments(
            segments,
            v2_headers.iter().map(|h| h.segment_number).collect(),
        )?;

        let mut chunk_size: u64 = 0;
        let mut total_size: u64 = 0;
        let mut chunks: Vec<Chunk> = Vec::new();
        let mut stored_md5: Option<[u8; 16]> = None;
        let mut stored_sha1: Option<[u8; 20]> = None;
        let mut metadata = EwfMetadata::default();
        let acquisition_errors: Vec<AcquisitionError> = Vec::new();

        for (seg_idx, file) in ordered_segments.iter_mut().enumerate() {
            let file_len = file.seek(SeekFrom::End(0))?;
            // First section descriptor starts right after the 32-byte header
            let mut desc_offset: u64 = ewf2::FILE_HEADER_SIZE as u64;

            loop {
                if desc_offset + ewf2::SECTION_DESCRIPTOR_SIZE as u64 > file_len {
                    break;
                }

                file.seek(SeekFrom::Start(desc_offset))?;
                let mut desc_buf = [0u8; ewf2::SECTION_DESCRIPTOR_SIZE];
                file.read_exact(&mut desc_buf)?;
                let desc = ewf2::Ewf2SectionDescriptor::parse(&desc_buf, desc_offset)?;

                if desc.is_encrypted() {
                    return Err(EwfError::EncryptedNotSupported);
                }

                match desc.section_type {
                    ewf2::Ewf2SectionType::CaseData => {
                        // Parse case metadata (UTF-16LE tab-separated)
                        if desc.data_size > 0
                            && desc.data_size < MAX_SECTION_DATA_SIZE
                            && metadata.case_number.is_none()
                        {
                            let data_offset = desc_offset + u64::from(desc.descriptor_size);
                            file.seek(SeekFrom::Start(data_offset))?;
                            let mut raw = vec![0u8; desc.data_size as usize];
                            file.read_exact(&mut raw)?;
                            parse_ewf2_case_data(&raw, &mut metadata);
                            log::debug!("parsed v2 case_data: case={:?}", metadata.case_number);
                        }
                    }
                    ewf2::Ewf2SectionType::DeviceInfo => {
                        // Parse device_info for media geometry
                        if desc.data_size > 0
                            && desc.data_size < MAX_SECTION_DATA_SIZE
                            && chunk_size == 0
                        {
                            let data_offset = desc_offset + u64::from(desc.descriptor_size);
                            file.seek(SeekFrom::Start(data_offset))?;
                            let mut raw = vec![0u8; desc.data_size as usize];
                            file.read_exact(&mut raw)?;
                            parse_ewf2_device_info(&raw, &mut chunk_size, &mut total_size);
                            log::debug!("parsed v2 device_info: chunk_size={chunk_size}, total_size={total_size}");
                        }
                    }
                    ewf2::Ewf2SectionType::SectorTable => {
                        let data_offset = desc_offset + u64::from(desc.descriptor_size);
                        file.seek(SeekFrom::Start(data_offset))?;
                        let mut tbl_hdr_buf = [0u8; 20];
                        file.read_exact(&mut tbl_hdr_buf)?;
                        let tbl_hdr = ewf2::Ewf2TableHeader::parse(&tbl_hdr_buf)?;

                        let entry_count = tbl_hdr.entry_count as usize;
                        if entry_count > MAX_TABLE_ENTRIES {
                            return Err(EwfError::Parse(format!(
                                "table entry count {entry_count} exceeds maximum {MAX_TABLE_ENTRIES}"
                            )));
                        }
                        let entries_offset = data_offset + 20;
                        file.seek(SeekFrom::Start(entries_offset))?;
                        let mut entries_buf = vec![0u8; entry_count * ewf2::TABLE_ENTRY_SIZE];
                        file.read_exact(&mut entries_buf)?;

                        log::debug!(
                            "parsed v2 sector_table: first_chunk={}, entries={entry_count}",
                            tbl_hdr.first_chunk
                        );

                        for i in 0..entry_count {
                            let start = i * ewf2::TABLE_ENTRY_SIZE;
                            let end = start + ewf2::TABLE_ENTRY_SIZE;
                            let entry = ewf2::Ewf2TableEntry::parse(&entries_buf[start..end])?;

                            chunks.push(Chunk {
                                segment_idx: seg_idx,
                                compressed: entry.is_compressed(),
                                offset: entry.chunk_data_offset,
                                size: u64::from(entry.chunk_data_size),
                            });
                        }
                    }
                    ewf2::Ewf2SectionType::Md5Hash => {
                        if desc.data_size >= 16 {
                            let data_offset = desc_offset + u64::from(desc.descriptor_size);
                            file.seek(SeekFrom::Start(data_offset))?;
                            let mut hash = [0u8; 16];
                            file.read_exact(&mut hash)?;
                            stored_md5 = Some(hash);
                            log::debug!("parsed v2 md5_hash section: {hash:02x?}");
                        }
                    }
                    ewf2::Ewf2SectionType::Sha1Hash => {
                        if desc.data_size >= 20 {
                            let data_offset = desc_offset + u64::from(desc.descriptor_size);
                            file.seek(SeekFrom::Start(data_offset))?;
                            let mut hash = [0u8; 20];
                            file.read_exact(&mut hash)?;
                            stored_sha1 = Some(hash);
                            log::debug!("parsed v2 sha1_hash section: {hash:02x?}");
                        }
                    }
                    ewf2::Ewf2SectionType::Done | ewf2::Ewf2SectionType::Next => {
                        break;
                    }
                    _ => {}
                }

                // Advance to next section: descriptor_size + data_size + padding_size
                let advance =
                    u64::from(desc.descriptor_size) + desc.data_size + u64::from(desc.padding_size);
                if advance == 0 {
                    break;
                }
                desc_offset += advance;
            }
        }

        // Default chunk_size if device_info didn't provide it
        if chunk_size == 0 {
            chunk_size = DEFAULT_V2_CHUNK_SIZE;
        }
        if total_size == 0 {
            total_size = chunks.len() as u64 * chunk_size;
        }

        let cache = LruCache::new(std::num::NonZeroUsize::new(cache_size.max(1)).unwrap());

        Ok(Self {
            segments: ordered_segments,
            chunks,
            chunk_size,
            total_size,
            position: 0,
            cache,
            stored_md5,
            stored_sha1,
            metadata,
            acquisition_errors,
        })
    }

    /// Total logical size of the disk image in bytes.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Chunk size in bytes (typically 32768).
    #[must_use]
    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }

    /// Number of chunks in the image.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Access raw chunk metadata (for testing/diagnostics).
    #[cfg(test)]
    pub(crate) fn chunk_meta(&self, idx: usize) -> &Chunk {
        &self.chunks[idx]
    }

    /// Returns the integrity hashes stored within the EWF image by the acquisition tool.
    ///
    /// The `hash` section (`EnCase` 1+) stores an MD5 of the acquired media.
    /// The `digest` section (`EnCase` 6.12+) stores both MD5 and SHA-1.
    /// If neither section is present (e.g. some FTK Imager images), both fields will be `None`.
    #[must_use]
    pub fn stored_hashes(&self) -> StoredHashes {
        StoredHashes {
            md5: self.stored_md5,
            sha1: self.stored_sha1,
        }
    }

    /// Returns case and acquisition metadata from the EWF header sections.
    #[must_use]
    pub fn metadata(&self) -> &EwfMetadata {
        &self.metadata
    }

    /// Returns sectors that had read errors during acquisition.
    ///
    /// Empty for clean acquisitions. Populated from the `error2` section when present.
    #[must_use]
    pub fn acquisition_errors(&self) -> &[AcquisitionError] {
        &self.acquisition_errors
    }

    /// Verify image integrity by streaming all media data through MD5 (and SHA-1 if
    /// a stored SHA-1 exists) and comparing against the hashes stored in the image.
    ///
    /// Returns a [`VerifyResult`] with the computed hashes and match status.
    /// If the image has no stored hashes, the computed hashes are still returned
    /// but the match fields will be `None`.
    ///
    /// Requires the `verify` feature (enabled by default).
    ///
    /// # Example
    ///
    /// ```no_run
    /// let mut reader = ewf::EwfReader::open("image.E01").unwrap();
    /// let result = reader.verify().unwrap();
    /// if let Some(true) = result.md5_match {
    ///     println!("Image integrity verified (MD5 match)");
    /// }
    /// ```
    #[cfg(feature = "verify")]
    pub fn verify(&mut self) -> Result<VerifyResult> {
        use md5::Digest;

        let has_sha1 = self.stored_sha1.is_some();

        let mut md5_hasher = md5::Md5::new();
        let mut sha1_hasher = if has_sha1 {
            Some(sha1::Sha1::new())
        } else {
            None
        };

        self.position = 0;
        let mut buf = vec![0u8; self.chunk_size as usize];
        let mut remaining = self.total_size;

        while remaining > 0 {
            let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
            let n = io::Read::read(self, &mut buf[..to_read])?;
            if n == 0 {
                break;
            }
            md5_hasher.update(&buf[..n]);
            if let Some(ref mut h) = sha1_hasher {
                h.update(&buf[..n]);
            }
            remaining -= n as u64;
        }

        let computed_md5: [u8; 16] = md5_hasher.finalize().into();
        let computed_sha1: Option<[u8; 20]> = sha1_hasher.map(|h| h.finalize().into());

        let md5_match = self.stored_md5.map(|stored| stored == computed_md5);
        let sha1_match = match (self.stored_sha1, computed_sha1) {
            (Some(stored), Some(computed)) => Some(stored == computed),
            _ => None,
        };

        Ok(VerifyResult {
            computed_md5,
            computed_sha1,
            md5_match,
            sha1_match,
        })
    }

    /// Read and decompress a single chunk by its index.
    fn read_chunk(&mut self, chunk_id: usize) -> Result<Vec<u8>> {
        if let Some(cached) = self.cache.get(&chunk_id) {
            return Ok(cached.clone());
        }

        let mut page = vec![0u8; self.chunk_size as usize];
        let chunk = self.chunks[chunk_id].clone();
        let file = &mut self.segments[chunk.segment_idx];

        if chunk.compressed {
            let mut compressed = vec![0u8; chunk.size as usize];
            file.seek(SeekFrom::Start(chunk.offset))?;
            let mut total_read = 0;
            while total_read < compressed.len() {
                let n = file.read(&mut compressed[total_read..])?;
                if n == 0 {
                    break;
                }
                total_read += n;
            }
            let compressed = &compressed[..total_read];

            let mut decoder = ZlibDecoder::new(compressed);
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
        } else {
            file.seek(SeekFrom::Start(chunk.offset))?;
            let to_read = std::cmp::min(chunk.size as usize, page.len());
            file.read_exact(&mut page[..to_read])?;
        }

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

            let to_read = in_chunk.min(remaining_image).min(remaining_buf as u64) as usize;

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
        let n = self.read_at(buf, self.position).map_err(io::Error::other)?;
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

/// Parse EWF2 `device_info` section data (UTF-16LE tab-separated text) to extract
/// `bytes_per_sector`, `sectors_per_chunk`, and `total_sectors` for media geometry.
///
/// Format:
///   Line 1: version ("2")
///   Line 2: section name ("main")
///   Line 3: field names (tab-separated, e.g. "b\tsc\tts")
///   Line 4: field values (tab-separated)
pub(crate) fn parse_ewf2_device_info(raw: &[u8], chunk_size: &mut u64, total_size: &mut u64) {
    // Decode UTF-16LE to String
    if raw.len() < 2 {
        return;
    }
    let u16_iter = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    let text: String = char::decode_utf16(u16_iter)
        .filter_map(std::result::Result::ok)
        .collect();

    let lines: Vec<&str> = text.lines().collect();
    if lines.len() < 4 {
        return;
    }

    let names: Vec<&str> = lines[2].split('\t').collect();
    let values: Vec<&str> = lines[3].split('\t').collect();

    let mut bytes_per_sector: u64 = 512;
    let mut sectors_per_chunk: u64 = 64;
    let mut total_sectors: u64 = 0;

    for (i, &name) in names.iter().enumerate() {
        if let Some(&val_str) = values.get(i) {
            match name {
                "b" => {
                    if let Ok(v) = val_str.parse::<u64>() {
                        bytes_per_sector = v;
                    }
                }
                "sc" => {
                    if let Ok(v) = val_str.parse::<u64>() {
                        sectors_per_chunk = v;
                    }
                }
                "ts" => {
                    if let Ok(v) = val_str.parse::<u64>() {
                        total_sectors = v;
                    }
                }
                _ => {}
            }
        }
    }

    let computed_chunk_size = bytes_per_sector * sectors_per_chunk;
    if computed_chunk_size > 0 {
        *chunk_size = computed_chunk_size;
    }
    if total_sectors > 0 && bytes_per_sector > 0 {
        *total_size = bytes_per_sector * total_sectors;
    }
}

/// Parse EWF2 `case_data` section (UTF-16LE tab-separated) to extract case metadata.
///
/// Field codes: `cn`=`case_number`, `en`=`evidence_number`, `ex`=examiner,
/// `de`=description, `nt`=notes, `av`=`acquiry_software`, `ov`=`os_version`,
/// `ad`=`acquiry_date`, `sd`=`system_date`.
pub(crate) fn parse_ewf2_case_data(raw: &[u8], metadata: &mut EwfMetadata) {
    if raw.len() < 2 {
        return;
    }
    let u16_iter = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    let text: String = char::decode_utf16(u16_iter)
        .filter_map(std::result::Result::ok)
        .collect();

    let lines: Vec<&str> = text.lines().collect();
    if lines.len() < 4 {
        return;
    }

    let names: Vec<&str> = lines[2].split('\t').collect();
    let values: Vec<&str> = lines[3].split('\t').collect();

    for (i, &name) in names.iter().enumerate() {
        if let Some(&val) = values.get(i) {
            if val.is_empty() {
                continue;
            }
            match name {
                "cn" => metadata.case_number = Some(val.to_string()),
                "en" => metadata.evidence_number = Some(val.to_string()),
                "ex" => metadata.examiner = Some(val.to_string()),
                "de" => metadata.description = Some(val.to_string()),
                "nt" => metadata.notes = Some(val.to_string()),
                "av" => metadata.acquiry_software = Some(val.to_string()),
                "ov" => metadata.os_version = Some(val.to_string()),
                "ad" => metadata.acquiry_date = Some(val.to_string()),
                "sd" => metadata.system_date = Some(val.to_string()),
                _ => {}
            }
        }
    }
}

impl std::fmt::Debug for EwfReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EwfReader")
            .field("chunk_size", &self.chunk_size)
            .field("total_size", &self.total_size)
            .field("position", &self.position)
            .field("chunk_count", &self.chunks.len())
            .field("segment_count", &self.segments.len())
            .field("cache", &self.cache)
            .field("stored_md5", &self.stored_md5)
            .field("stored_sha1", &self.stored_sha1)
            .field("metadata", &self.metadata)
            .field("acquisition_errors", &self.acquisition_errors)
            .finish()
    }
}
