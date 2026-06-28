//! Chunk-table storage for the EWF v1 reader.
//!
//! Two strategies live behind one [`ChunkTable`] enum so the reader holds a
//! single field and routes every chunk lookup through it:
//!
//! - [`ChunkTable::Eager`] — the classic flat `Vec<Chunk>`, every table entry
//!   parsed up front during `open()`. Zero per-read overhead; the table itself
//!   costs `chunk_count * size_of::<Chunk>()` resident bytes (≈1 GB for a 2 TB
//!   image).
//! - [`ChunkTable::Lazy`] — a small per-table-section index plus an LRU cache of
//!   parsed sections. `open_lazy()` reads only each table section's 24-byte
//!   header (entry count + base offset), deferring the per-entry parse until a
//!   chunk in that section is first touched.
//!
//! Both strategies MUST yield byte-identical [`Chunk`] metadata. To guarantee
//! that, the per-section entry-parsing logic lives in exactly one place —
//! [`parse_table_section`] — and is called from BOTH the eager `open()` and the
//! lazy `get()` cache-miss path.

use std::num::NonZeroUsize;
use std::sync::Mutex;

use lru::LruCache;

use crate::error::Result;
use crate::sections::{Chunk, TableEntry, SECTION_DESCRIPTOR_SIZE};
use crate::segment_source::SegmentSource;

/// Number of parsed table sections the lazy cache keeps resident. Real images
/// split their chunks into ~16 K-entry sections, so 8 sections covers a 4 MB
/// working set of decoded entries — generous for sequential and most random
/// access patterns while bounding lazy resident memory.
pub(crate) const DEFAULT_SECTION_CACHE: usize = 8;

/// Parse one table section's entry buffer into its chunks, reproducing the
/// EXACT eager per-section size logic so eager and lazy are byte-identical.
///
/// `entries` is the raw `entry_count * 4` bytes that follow the 24-byte table
/// header. `base_offset` is the section's table base; `seg_idx` the owning
/// segment; `chunk_size` the image chunk size; `sectors_data_end` the end
/// offset of the segment's first `sectors` section (for the last-chunk
/// back-fill), or `None` when the segment has no `sectors` section.
///
/// The two size rules, verbatim from the original inline loop:
/// 1. **Within-section back-fill** — `prev_offset` resets per section; when
///    pushing chunk *i*, chunk *i-1*'s size is set to `abs_offset_i - prev`
///    IFF chunk *i-1* is compressed and the delta is > 0.
/// 2. **Last-chunk back-fill** — after the loop, the section's final chunk gets
///    its size from `sectors_data_end - offset` IFF it is compressed, still has
///    `size == chunk_size`, and `0 < (end - offset) < chunk_size`.
pub(crate) fn parse_table_section(
    entries: &[u8],
    entry_count: usize,
    base_offset: u64,
    seg_idx: usize,
    chunk_size: u64,
    sectors_data_end: Option<u64>,
) -> Result<Vec<Chunk>> {
    let mut chunks: Vec<Chunk> = Vec::with_capacity(entry_count);
    let mut prev_offset: Option<u64> = None;

    for i in 0..entry_count {
        let entry = TableEntry::parse(&entries[i * 4..(i + 1) * 4])?;
        let abs_offset = u64::from(entry.chunk_offset) + base_offset;

        if let Some(po) = prev_offset {
            if let Some(prev_chunk) = chunks.last_mut() {
                if prev_chunk.compressed() {
                    let sz = abs_offset.saturating_sub(po);
                    if sz > 0 {
                        prev_chunk.set_size(sz);
                    }
                }
            }
        }

        chunks.push(Chunk::new(
            seg_idx,
            entry.compressed,
            abs_offset,
            chunk_size,
        ));

        prev_offset = Some(abs_offset);
    }

    if let Some(end) = sectors_data_end {
        if let Some(last) = chunks.last_mut() {
            if last.compressed() && last.size() == chunk_size {
                let actual = end.saturating_sub(last.offset());
                if actual > 0 && actual < chunk_size {
                    last.set_size(actual);
                }
            }
        }
    }

    Ok(chunks)
}

/// Lazy index entry: everything needed to re-parse one table section on demand,
/// without holding its per-chunk entries in memory.
#[derive(Debug, Clone)]
pub(crate) struct SectionMeta {
    /// Global chunk id of this section's first chunk.
    pub(crate) first_chunk_id: usize,
    /// Number of table entries (chunks) in this section.
    pub(crate) entry_count: usize,
    /// Absolute file offset of the section's entry bytes (after the 24-B header).
    pub(crate) entries_file_offset: u64,
    /// Table base offset added to each entry's packed offset.
    pub(crate) base_offset: u64,
    /// Segment file index that holds this section.
    pub(crate) segment_idx: usize,
    /// End offset of the owning segment's first `sectors` section, for the
    /// last-chunk back-fill. `None` when that segment has no `sectors` section.
    pub(crate) sectors_data_end: Option<u64>,
}

/// On-demand chunk table: a compact section index + an LRU of parsed sections.
pub(crate) struct LazyChunkTable {
    /// Per-table-section index, ordered by `first_chunk_id` (ascending), so a
    /// chunk id is located by binary search.
    index: Vec<SectionMeta>,
    /// Total chunk count across all sections.
    len: usize,
    /// Image chunk size (bytes), needed to re-parse a section's entries.
    chunk_size: u64,
    /// LRU cache: section index in `self.index` -> its parsed chunks.
    cache: Mutex<LruCache<usize, Vec<Chunk>>>,
}

impl LazyChunkTable {
    pub(crate) fn new(index: Vec<SectionMeta>, chunk_size: u64, section_cache_cap: usize) -> Self {
        let len = index.last().map_or(0, |m| m.first_chunk_id + m.entry_count);
        let cap = NonZeroUsize::new(section_cache_cap.max(1)).unwrap_or(NonZeroUsize::MIN);
        Self {
            index,
            len,
            chunk_size,
            cache: Mutex::new(LruCache::new(cap)),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Binary-search the section index for the section containing `chunk_id`.
    /// Returns the section's position in `self.index`.
    fn section_for(&self, chunk_id: usize) -> Option<usize> {
        // partition_point: first section whose first_chunk_id > chunk_id; the
        // section we want is the one just before it.
        let after = self.index.partition_point(|m| m.first_chunk_id <= chunk_id);
        if after == 0 {
            return None;
        }
        let pos = after - 1;
        let meta = &self.index[pos];
        if chunk_id < meta.first_chunk_id + meta.entry_count {
            Some(pos)
        } else {
            None
        }
    }

    /// Return an owned [`Chunk`] for `chunk_id`, parsing (and caching) its table
    /// section on a cache miss. `segments` is the reader's ordered segment
    /// sources (loose file, in-archive sub-range, or in-RAM buffer).
    pub(crate) fn get(&self, chunk_id: usize, segments: &[SegmentSource]) -> Result<Chunk> {
        let pos = self.section_for(chunk_id).ok_or_else(|| {
            crate::error::EwfError::Parse(format!(
                "chunk id {chunk_id} out of range (len {})",
                self.len
            ))
        })?;
        let meta = &self.index[pos];
        let local = chunk_id - meta.first_chunk_id;

        // Fast path: section already parsed and cached.
        {
            let mut cache = self
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(section) = cache.get(&pos) {
                return Ok(section[local].clone());
            }
        }

        // Cache miss: read this section's entry bytes and parse via the shared
        // routine, so the result is byte-identical to the eager table.
        let src = segments.get(meta.segment_idx).ok_or_else(|| {
            crate::error::EwfError::Parse(format!(
                "lazy table section references missing segment {}",
                meta.segment_idx
            ))
        })?;
        let mut entries_buf = vec![0u8; meta.entry_count * 4];
        let n = src.read_at(&mut entries_buf, meta.entries_file_offset)?;
        if n < entries_buf.len() {
            return Err(crate::error::EwfError::Parse(format!(
                "short read for lazy table section at {:#x}: got {n} of {} bytes",
                meta.entries_file_offset,
                entries_buf.len()
            )));
        }

        let section = parse_table_section(
            &entries_buf,
            meta.entry_count,
            meta.base_offset,
            meta.segment_idx,
            self.chunk_size,
            meta.sectors_data_end,
        )?;

        let chunk = section[local].clone();

        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.put(pos, section);

        Ok(chunk)
    }

    /// Resident bytes: the section index plus the currently-cached parsed
    /// sections (entries × `size_of::<Chunk>`). Used by the benchmark.
    pub(crate) fn resident_table_bytes(&self) -> usize {
        let index_bytes = self.index.len() * std::mem::size_of::<SectionMeta>();
        let cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cached_chunks: usize = cache.iter().map(|(_, v)| v.len()).sum();
        index_bytes + cached_chunks * std::mem::size_of::<Chunk>()
    }
}

/// The reader's chunk-table store: eager (flat vec) or lazy (paged index).
pub(crate) enum ChunkTable {
    Eager(Vec<Chunk>),
    Lazy(LazyChunkTable),
}

impl ChunkTable {
    pub(crate) fn len(&self) -> usize {
        match self {
            ChunkTable::Eager(v) => v.len(),
            ChunkTable::Lazy(l) => l.len(),
        }
    }

    /// Owned [`Chunk`] for `chunk_id`. Eager clones from the vec; lazy parses /
    /// serves from its section cache.
    pub(crate) fn get(&self, chunk_id: usize, segments: &[SegmentSource]) -> Result<Chunk> {
        match self {
            ChunkTable::Eager(v) => v.get(chunk_id).cloned().ok_or_else(|| {
                crate::error::EwfError::Parse(format!(
                    "chunk id {chunk_id} out of range (len {})",
                    v.len()
                ))
            }),
            ChunkTable::Lazy(l) => l.get(chunk_id, segments),
        }
    }

    /// Resident table bytes: eager = `chunks * size_of::<Chunk>`; lazy = index +
    /// cached sections. This is the benchmark's headline memory figure.
    pub(crate) fn resident_table_bytes(&self) -> usize {
        match self {
            ChunkTable::Eager(v) => v.len() * std::mem::size_of::<Chunk>(),
            ChunkTable::Lazy(l) => l.resident_table_bytes(),
        }
    }
}

/// Section descriptor data the lazy index builder needs from `open()`'s
/// descriptor walk: the table section's file offset and the segment's
/// `sectors`-section end (shared across all table sections in that segment).
pub(crate) struct TableSectionRef {
    /// Absolute file offset of the `table`/`table2` section descriptor.
    pub(crate) desc_offset: u64,
    /// End offset of the segment's first `sectors` section (back-fill bound).
    pub(crate) sectors_data_end: Option<u64>,
}

impl TableSectionRef {
    /// Build a [`SectionMeta`] by reading ONLY this table section's 24-byte
    /// header (entry count + base offset) — never the per-entry bytes.
    ///
    /// `first_chunk_id` is the running global chunk count before this section.
    /// Returns the meta and the section's entry count (so the caller can advance
    /// `first_chunk_id`).
    pub(crate) fn read_header(
        &self,
        src: &SegmentSource,
        seg_idx: usize,
        first_chunk_id: usize,
        max_table_entries: usize,
    ) -> Result<SectionMeta> {
        let hdr_offset = self.desc_offset + SECTION_DESCRIPTOR_SIZE as u64;
        let mut tbl_hdr = [0u8; 24];
        let n = src.read_at(&mut tbl_hdr, hdr_offset)?;
        if n < 24 {
            return Err(crate::error::EwfError::Parse(format!(
                "short read for lazy table header at {hdr_offset:#x}: got {n} of 24 bytes"
            )));
        }
        let entry_count =
            u32::from_le_bytes([tbl_hdr[0], tbl_hdr[1], tbl_hdr[2], tbl_hdr[3]]) as usize;
        if entry_count > max_table_entries {
            return Err(crate::error::EwfError::Parse(format!(
                "table entry count {entry_count} exceeds maximum {max_table_entries}"
            )));
        }
        let base_offset = u64::from_le_bytes(tbl_hdr[8..16].try_into().unwrap_or([0u8; 8]));

        Ok(SectionMeta {
            first_chunk_id,
            entry_count,
            entries_file_offset: hdr_offset + 24,
            base_offset,
            segment_idx: seg_idx,
            sectors_data_end: self.sectors_data_end,
        })
    }
}
