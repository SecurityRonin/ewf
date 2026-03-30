# ewf

[![Crates.io](https://img.shields.io/crates/v/ewf.svg)](https://crates.io/crates/ewf)
[![docs.rs](https://img.shields.io/docsrs/ewf)](https://docs.rs/ewf)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/ewf/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/ewf/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

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

- **EWF v1 format** — reads images from EnCase, FTK Imager, Guymager, ewfacquire, etc.
- **EWF v2 format (Ex01/Lx01)** — reads EnCase 7+ images with format auto-detection
- **L01 logical evidence files** — opens `.L01`/`.l01` files (same container, logical acquisition)
- **Multi-segment** — auto-discovers `.E01` through `.EZZ` (v1) and `.Ex01` through `.EzZZ` (v2)
- **zlib decompression** with LRU caching (configurable, default 100 chunks ~ 3.2 MB)
- **O(1) seeking** — flat chunk table indexed by `offset / chunk_size`
- **Hash verification** — `verify()` streams all media data through MD5/SHA-1 and compares against stored hashes
- **Stored hashes** — reads MD5 and SHA-1 from hash/digest sections (v1) and Md5Hash/Sha1Hash sections (v2)
- **Case metadata** — parses case number, examiner, description, notes, acquisition dates from header (v1) and CaseData (v2) sections
- **Acquisition errors** — extracts read-error entries from error2 sections
- **table + table2 resilience** — handles both section types, deduplicates correctly
- **DoS-safe** — guards against malformed images with absurd table entry counts
- **MIT licensed** — no GPL, safe for proprietary DFIR tooling

## Usage

### Open with auto-discovery

```rust
// Finds all .E01/.E02/... segments automatically
let mut reader = ewf::EwfReader::open("case001.E01")?;
println!("Image size: {} bytes", reader.total_size());
```

### Verify image integrity

```rust
let mut reader = ewf::EwfReader::open("case001.E01")?;
let result = reader.verify()?;
if let Some(true) = result.md5_match {
    println!("MD5 verified: {:02x?}", result.computed_md5);
}
```

### Read case metadata

```rust
let reader = ewf::EwfReader::open("case001.E01")?;
let meta = reader.metadata();
println!("Case: {:?}", meta.case_number);
println!("Examiner: {:?}", meta.examiner);
println!("Software: {:?}", meta.acquiry_software);
```

### Check stored hashes

```rust
let reader = ewf::EwfReader::open("case001.E01")?;
let hashes = reader.stored_hashes();
if let Some(md5) = hashes.md5 {
    println!("Stored MD5: {:02x?}", md5);
}
```

### Tune cache for large images

```rust
// 1000 chunks ~ 32 MB cache — useful for sequential scans
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

## Feature flags

| Flag | Default | Description |
|------|---------|-------------|
| `verify` | Yes | Enables `verify()` method (adds `md-5` and `sha-1` dependencies) |

To disable hash verification and reduce dependencies:

```toml
[dependencies]
ewf = { version = "0.1", default-features = false }
```

## Format support

| Format | Status |
|--------|--------|
| E01 (EWF v1) | Supported |
| E01 multi-segment (.E01-.EZZ) | Supported |
| Ex01 (EWF v2) | Supported |
| L01 (logical evidence, v1) | Supported |
| Lx01 (logical evidence, v2) | Supported |
| S01 (SMART) | Not yet |

## MCP server

The workspace includes `ewf-mcp`, an [MCP](https://modelcontextprotocol.io/) server for AI-assisted forensic image inspection. It exposes six tools over JSON-RPC stdio:

| Tool | Description |
|------|-------------|
| `ewf_info` | Image metadata, geometry, stored hashes, acquisition errors |
| `ewf_verify` | Full-media hash verification (MD5 + SHA-1) |
| `ewf_read` | Read hex bytes at any offset |
| `ewf_list_sections` | List all section descriptors across segments |
| `ewf_search` | Byte-pattern search with hex input |
| `ewf_extract` | Extract byte range to file |

### Run the MCP server

```bash
cargo build --release -p ewf-mcp
./target/release/ewf-mcp
```

### Claude Desktop configuration

```json
{
  "mcpServers": {
    "ewf": {
      "command": "/path/to/ewf-mcp"
    }
  }
}
```

## Validation

Full-media MD5 comparison against libewf and The Sleuth Kit confirms bit-identical output across 6 public forensic images (303+ GiB of media). Test images sourced from [Digital Corpora](https://digitalcorpora.org/) and [The Evidence Locker](https://theevidencelocker.github.io/) (Kevin Pagano). Three small images are committed as test fixtures and run in CI. See [docs/VALIDATION.md](docs/VALIDATION.md) for results, image sources, and reproduction steps.

## Acknowledgments

Architecture informed by [Velocidex/go-ewf](https://github.com/Velocidex/go-ewf) (Apache-2.0).

## License

MIT
