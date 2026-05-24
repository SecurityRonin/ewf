# EWF Implementation Notes

Developer notes capturing format quirks, spec contradictions, and empirically verified
behaviour. Intended for future contributors and as a basis for upstream spec clarifications.

References:
- *libewf project documentation* (Joachim Metz, 2006–2023)
- EWF (Expert Witness Format) v1 format specification (derived from EnCase)
- EWF2 (Ex01/Lx01) specification (Guidance Software / OpenText)

---

## 1. `table` vs `table2` deduplication

Many EWF images contain **both** a `table` and a `table2` section in each segment.
`table2` is a redundant copy of `table` intended for recovery from partial corruption.

**Rule:** prefer `table` when present; use `table2` only if `table` is absent.

```rust
let has_table   = descriptors.iter().any(|d| d.section_type == "table");
let table_type  = if has_table { "table" } else { "table2" };
```

**Common pitfall:** processing both sections and appending chunks from each. This doubles
every chunk in the chunk list, yielding a virtual image twice the correct size with
every sector appearing twice.

---

## 2. "volume" vs "disk" section — both describe geometry

Different acquisition tools use different section type names for the volume/geometry
record:

| Tool | Section name |
|------|-------------|
| EnCase | `disk` |
| FTK Imager | `volume` |
| Some others | `volume` |

Both have identical binary layouts. Our parser handles both:

```rust
"volume" | "disk" => { /* parse EwfVolume */ }
```

Handling only `disk` (the name in the original libewf documentation) causes FTK
Imager images to silently fail with `EwfError::MissingVolume`.

---

## 3. Last compressed chunk size inference

The `table` section stores one 4-byte entry per chunk. The entry encodes:
- Bit 31: `compressed` flag
- Bits 0–30: `chunk_offset` relative to `base_offset` (absolute file offset of chunk data)

For compressed chunks, the **on-disk size** is not stored. It must be inferred from
the start offset of the **next** chunk:

```
size_of_chunk[i] = offset_of_chunk[i+1] - offset_of_chunk[i]
```

This is computed during table parsing via a "previous offset" carry:

```rust
if let Some(po) = prev_offset {
    if prev_chunk.compressed {
        let sz = abs_offset.saturating_sub(po);
        if sz > 0 { prev_chunk.size = sz; }
    }
}
```

**Last chunk special case:** there is no `i+1` entry. The size must be inferred from
the end of the `sectors` section. Each segment includes a `sectors` section whose
`section_size` field gives the total bytes of sector data including all chunk headers.
The end of the last chunk = `sectors_data_end`:

```rust
let actual = sectors_data_end.saturating_sub(last.offset);
if actual > 0 && actual < chunk_size { last.size = actual; }
```

Without this back-fill, the last compressed chunk in each segment is read with
`size = chunk_size` (the uncompressed size), reading too many bytes past the
actual compressed data — yielding a corrupt decompression or `UnexpectedEof`.

---

## 4. EWF2 `device_info` fallback

EWF2 (Ex01/Lx01) stores geometry in a `device_info` section encoded as **UTF-16LE
tab-separated text** with a specific header format:

```
Line 1: "2"                    ← version
Line 2: "main"                  ← section name
Line 3: "b\tsc\tts"            ← field names: bytes_per_sector, sectors_per_chunk, total_sectors
Line 4: "512\t64\t2097152"     ← field values
```

If `device_info` is absent or unparseable (e.g. a nonstandard EWF2 writer), the
chunk size defaults to **32,768 bytes** (64 sectors × 512 bytes/sector) and total
size is derived from `chunk_count * chunk_size`:

```rust
const DEFAULT_V2_CHUNK_SIZE: u64 = 32768;
if chunk_size == 0 { chunk_size = DEFAULT_V2_CHUNK_SIZE; }
if total_size == 0 { total_size = chunks.len() as u64 * chunk_size; }
```

This is the same default that libewf uses. Do not return an error if `device_info`
is missing — many early EWF2 tools omit it.

---

## 5. EWF1 header section: zlib-compressed UTF-16LE

The `header` section payload is:
1. Compressed with **zlib** (RFC 1950, with 2-byte header + Adler-32 trailer)
2. Decoded as **UTF-16LE** with BOM

The `header2` section (if present) is the same content, second copy.

Decompressing without a size cap is dangerous — a crafted EWF can embed a deflate bomb
that expands a small compressed header into gigabytes. Cap at 10 MiB:

```rust
let mut limited = std::io::Read::take(
    ZlibDecoder::new(&compressed[..]),
    MAX_DECOMPRESSED_SIZE,  // 10 MB
);
```

---

## 6. EWF2 `table` section: `table_entry_size` varies

EWF2 table entries are **8 bytes** each (vs. 4 bytes in EWF1). The table header
includes a `first_chunk` field (the global chunk index of the first entry in this
table), allowing a segment to contain a subset of the image's chunks rather than
all chunks from offset 0.

EWF1 table entries have no such first-chunk offset — the table always covers chunks
in order, with each segment's table picking up where the previous segment ended.

---

## 7. Encrypted EWF2 (not supported)

EWF2 supports AES-256-CBC encrypted chunks indicated by a flag in the section
descriptor. This implementation rejects encrypted images immediately:

```rust
if desc.is_encrypted() {
    return Err(EwfError::EncryptedNotSupported);
}
```

Processing encrypted chunks without decryption returns garbage data with no error.

---

## 8. Segment file ordering and gap detection

Segment files must form a contiguous numbered sequence starting at 1. The reader
validates this after sorting by segment number:

```rust
for (pos, seg_num) in indexed.iter() {
    let expected = (pos + 1) as u32;
    if seg_num != &expected {
        return Err(EwfError::SegmentGap { expected, got: *seg_num });
    }
}
```

A missing segment (e.g. `.E02` present, `.E01` missing) must be a hard error. Silently
skipping gaps yields a reader that maps chunks to wrong logical byte offsets for all
subsequent segments.

---

## Upstream PR candidates

| Project | File | Suggested change |
|---------|------|-----------------|
| libewf | `libewf/libewf_section_descriptor.c` | Document that `table` and `table2` are mirrors; note the "prefer table" rule |
| libewf | EWF format specification | Clarify that `volume` and `disk` section names are equivalent with a note on which tools produce which |
| libewf | EWF format specification | Add a worked example for last-chunk size inference from `sectors` boundary |
