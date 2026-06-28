//! Pluggable backing store for one EWF segment.
//!
//! The reader historically held a `Vec<File>` — one loose file per `.E01`/`.E02`
//! segment. [`SegmentSource`] generalizes that to three positioned-read backings
//! WITHOUT a boxed trait, so the hot read path stays vtable-free (a `match` the
//! compiler can inline, not a dynamic dispatch):
//!
//! - [`SegmentSource::File`] — a loose segment file (today's path), read with the
//!   OS positioned-read primitive.
//! - [`SegmentSource::Sub`] — a contiguous sub-range of a larger file (a STORED,
//!   i.e. uncompressed, zip entry sits at a fixed offset inside the archive):
//!   `read_at(buf, off)` preads at `base + off`, clamped to `len`.
//! - [`SegmentSource::Mem`] — an in-RAM buffer (a DEFLATED zip entry inflated to
//!   memory once): `read_at` copies from the slice.
//!
//! All three expose the same cursor-free, thread-safe positioned-read API
//! (`read_at` + `len`), so the same `&[SegmentSource]` can mix loose files,
//! in-archive sub-ranges, and inflated buffers — the enabler for reading E01
//! segments straight out of a `.zip` without spilling to temp disk.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;

use crate::reader::pread;

/// A positioned, cursor-free reader over one EWF segment's bytes.
///
/// `read_at(buf, offset)` fills `buf` from logical `offset` within the segment
/// and returns the byte count (short only at end of segment) — never touching a
/// shared cursor, so it is safe to call concurrently through `&self` from many
/// threads, exactly like the underlying `pread`.
pub enum SegmentSource {
    /// A loose segment file: positioned reads go straight to the OS handle.
    File(File),
    /// A contiguous sub-range `[base, base+len)` of a larger shared file.
    Sub {
        /// The backing file (shared; positioned reads carry their own offset).
        file: Arc<File>,
        /// Absolute file offset where this segment's bytes begin.
        base: u64,
        /// Length of this segment in bytes.
        len: u64,
    },
    /// An in-RAM segment (e.g. an inflated zip entry).
    Mem(Arc<[u8]>),
}

impl SegmentSource {
    /// Construct a [`SegmentSource::Sub`] over `[base, base+len)` of `file`.
    #[must_use]
    pub fn sub(file: Arc<File>, base: u64, len: u64) -> Self {
        SegmentSource::Sub { file, base, len }
    }

    /// Construct an in-RAM [`SegmentSource::Mem`] from owned bytes.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Arc<[u8]>>) -> Self {
        SegmentSource::Mem(bytes.into())
    }

    /// Total length of this segment in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        match self {
            SegmentSource::File(f) => f.metadata().map_or(0, |m| m.len()),
            SegmentSource::Sub { len, .. } => *len,
            SegmentSource::Mem(b) => b.len() as u64,
        }
    }

    /// Whether the segment is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Fill `buf` from logical `offset` within this segment, returning the bytes
    /// read (short only at the segment's end). Cursor-free and thread-safe.
    ///
    /// # Errors
    /// Propagates the underlying I/O error for [`SegmentSource::File`] /
    /// [`SegmentSource::Sub`]; [`SegmentSource::Mem`] never fails.
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        match self {
            SegmentSource::File(f) => pread(f, buf, offset),
            SegmentSource::Sub { file, base, len } => {
                // Clamp the request to this segment's window so a Sub never reads
                // past its end into a neighbouring entry. A read starting beyond
                // the window yields 0 (clean EOF), mirroring File/Mem behaviour.
                let avail = len.saturating_sub(offset);
                if avail == 0 {
                    return Ok(0);
                }
                let want = (buf.len() as u64).min(avail) as usize;
                pread(file, &mut buf[..want], base + offset)
            }
            SegmentSource::Mem(bytes) => {
                let off = offset.min(bytes.len() as u64) as usize;
                let src = &bytes[off..];
                let n = src.len().min(buf.len());
                buf[..n].copy_from_slice(&src[..n]);
                Ok(n)
            }
        }
    }
}

impl std::fmt::Debug for SegmentSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SegmentSource::File(_) => f.debug_struct("File").field("len", &self.len()).finish(),
            SegmentSource::Sub { base, len, .. } => f
                .debug_struct("Sub")
                .field("base", base)
                .field("len", len)
                .finish(),
            SegmentSource::Mem(b) => f.debug_struct("Mem").field("len", &b.len()).finish(),
        }
    }
}

/// A `Read + Seek` cursor layered over a [`SegmentSource`]'s positioned reads.
///
/// The OPEN / index pass walks section descriptors with a mutable cursor
/// (`seek` then `read_exact`). Wrapping a `&SegmentSource` in this adapter lets
/// that existing parsing code run unchanged over any of the three backings —
/// the position lives here, the byte fetch delegates to `read_at`.
pub(crate) struct SegmentCursor<'a> {
    src: &'a SegmentSource,
    pos: u64,
}

impl<'a> SegmentCursor<'a> {
    pub(crate) fn new(src: &'a SegmentSource) -> Self {
        Self { src, pos: 0 }
    }

    /// The underlying segment's length (for `metadata().len()`-style queries the
    /// open path used to make against a `File`).
    pub(crate) fn segment_len(&self) -> u64 {
        self.src.len()
    }
}

impl Read for SegmentCursor<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.src.read_at(buf, self.pos)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SegmentCursor<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos: i64 = match pos {
            SeekFrom::Start(p) => p as i64,
            SeekFrom::End(p) => self.src.len() as i64 + p,
            SeekFrom::Current(p) => self.pos as i64 + p,
        };
        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek to negative position",
            ));
        }
        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}
