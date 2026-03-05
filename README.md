# ewf

[![Crates.io](https://img.shields.io/crates/v/ewf.svg)](https://crates.io/crates/ewf)
[![docs.rs](https://img.shields.io/docsrs/ewf)](https://docs.rs/ewf)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/ewf/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/ewf/actions)

Pure Rust reader for Expert Witness Format (E01/EWF) forensic disk images. Zero GPL dependencies.

## Quick start

```rust
use std::io::{Read, Seek, SeekFrom};

let mut reader = ewf::EwfReader::open("disk.E01")?;

// Read the first sector
let mut mbr = [0u8; 512];
reader.read_exact(&mut mbr)?;

// Seek anywhere — O(1) via flat chunk index
reader.seek(SeekFrom::Start(1_048_576))?;
```

`EwfReader` implements `Read + Seek`, so it plugs directly into crates like [`ntfs`](https://crates.io/crates/ntfs), [`fatfs`](https://crates.io/crates/fatfs), or anything expecting a seekable stream.

## Install

```toml
[dependencies]
ewf = "0.1"
```

## Features

- **E01 v1 format** — reads images from EnCase, FTK Imager, Guymager, ewfacquire, etc.
- **Multi-segment** — auto-discovers `.E01` → `.E02` → ... → `.E99` → `.EAA` → `.EZZ`
- **zlib decompression** with LRU caching (configurable, default 100 chunks ≈ 3.2 MB)
- **O(1) seeking** — flat chunk table indexed by `offset / chunk_size`
- **table + table2 resilience** — handles both section types, deduplicates correctly
- **MIT licensed** — no GPL, safe for proprietary DFIR tooling

## Usage

### Open with auto-discovery

```rust
// Finds all .E01/.E02/... segments automatically
let mut reader = ewf::EwfReader::open("case001.E01")?;
println!("Image size: {} bytes", reader.total_size());
```

### Tune cache for large images

```rust
// 1000 chunks ≈ 32 MB cache — useful for sequential scans
let mut reader = ewf::EwfReader::open_with_cache_size("case001.E01", 1000)?;
```

### Explicit segment paths

```rust
use std::path::PathBuf;

let segments = vec![
    PathBuf::from("case001.E01"),
    PathBuf::from("case001.E02"),
];
let mut reader = ewf::EwfReader::open_segments(&segments)?;
```

### With the ntfs crate

```rust
use ewf::EwfReader;
use ntfs::Ntfs;

let mut reader = EwfReader::open("disk.E01")?;
// Seek to NTFS partition offset, then:
let ntfs = Ntfs::new(&mut reader)?;
```

## Format support

| Format | Status |
|--------|--------|
| E01 (EWF v1) | Supported |
| E01 multi-segment | Supported |
| Ex01 (EWF v2) | Not yet |
| L01/Lx01 (logical) | Not yet |
| S01 (SMART) | Not yet |

## How it works

EWF stores disk data as zlib-compressed 32 KB chunks across one or more segment files. Each segment contains a linked list of section descriptors pointing to volume geometry, chunk offset tables, and compressed data.

```
.E01 file layout:
┌─────────────┐
│ File Header  │  13 bytes: EVF signature + segment number
├─────────────┤
│ Section      │  76 bytes each, linked list:
│ Descriptors  │  volume → table → sectors → done
├─────────────┤
│ Volume       │  Chunk geometry (sectors/chunk, bytes/sector)
├─────────────┤
│ Table        │  Chunk offset array (4 bytes per entry)
├─────────────┤
│ Sectors      │  Compressed chunk data
├─────────────┤
│ done         │  End of chain
└─────────────┘
```

`EwfReader::open()` walks each segment's section chain, builds a flat `Vec<Chunk>` index, then serves `Read + Seek` by mapping any byte offset to its chunk in O(1).

## Validation

Byte-level comparison against libewf confirms identical output across 3 public forensic images (complete, truncated, and in-progress downloads). See [docs/VALIDATION.md](docs/VALIDATION.md) for full results.

## Acknowledgments

Architecture informed by [Velocidex/go-ewf](https://github.com/Velocidex/go-ewf) (Apache-2.0).

## License

MIT

## Sponsor

If this crate is useful to your DFIR work:

[![Sponsor](https://img.shields.io/badge/sponsor-♥-ea4aaa)](https://github.com/sponsors/h4x0r)
