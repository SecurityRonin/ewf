//! Benchmark: eager vs lazy EWF v1 chunk table.
//!
//! Builds a synthetic single-segment E01 with MANY chunks split across MANY
//! `table` sections (like a real image), then compares the eager and lazy
//! readers on:
//!   - `open()` time,
//!   - `resident_table_bytes()` (the headline memory figure),
//!   - sequential full-read throughput (MB/s),
//!   - random-read throughput (10k random 64 KiB reads).
//!
//! The chunks are zeroed 32 KiB pages — zeros compress to ~tiny, so a 1,000,000
//! chunk image (≈30 GiB logical) is only tens of MiB on disk. Run with:
//!   `cargo run -p ewf --release --example bench_table`
//! Override chunk count / section size via argv: `bench_table 1000000 16384`.

use std::io::Write;
use std::time::Instant;

use ewf::EwfReader;
use flate2::write::ZlibEncoder;
use flate2::Compression;

const FILE_HEADER_SIZE: usize = 13;
const SECTION_DESCRIPTOR_SIZE: usize = 76;
const EVF_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];

const CHUNK_SIZE: u32 = 32768;
const SECTORS_PER_CHUNK: u32 = 64;
const BYTES_PER_SECTOR: u32 = 512;

/// Build a synthetic E01 with `total_chunks` zero-chunks, split into table
/// sections of `entries_per_section` each. Returns the file path (kept alive by
/// the returned `NamedTempFile`).
fn build_many_chunk_e01(
    total_chunks: usize,
    entries_per_section: usize,
) -> tempfile::NamedTempFile {
    // One shared compressed 32 KiB zero-chunk; every table entry points at the
    // same on-disk blob (its size is well-defined because the next entry sits at
    // the next blob, and the eager/lazy back-fill is identical regardless).
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(&vec![0u8; CHUNK_SIZE as usize]).unwrap();
    let blob = enc.finish().unwrap();
    let blob_len = blob.len() as u64;

    let sector_count = u64::from(CHUNK_SIZE / BYTES_PER_SECTOR) * total_chunks as u64;

    let mut file = Vec::new();

    // 1. File header (13 B), segment 1.
    file.extend_from_slice(&EVF_SIGNATURE);
    file.push(0x01);
    file.extend_from_slice(&1u16.to_le_bytes());
    file.extend_from_slice(&0u16.to_le_bytes());

    // 2. Volume descriptor + data. `next` points at the first table descriptor.
    let vol_desc_off = FILE_HEADER_SIZE as u64;
    let vol_data_off = vol_desc_off + SECTION_DESCRIPTOR_SIZE as u64;
    let first_tbl_desc_off = vol_data_off + 94;

    let mut vol_desc = [0u8; SECTION_DESCRIPTOR_SIZE];
    vol_desc[..6].copy_from_slice(b"volume");
    vol_desc[16..24].copy_from_slice(&first_tbl_desc_off.to_le_bytes());
    vol_desc[24..32].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u64 + 94).to_le_bytes());
    file.extend_from_slice(&vol_desc);

    let mut vol_data = [0u8; 94];
    vol_data[0..4].copy_from_slice(&1u32.to_le_bytes()); // media_type = fixed
    vol_data[4..8].copy_from_slice(&(total_chunks as u32).to_le_bytes());
    vol_data[8..12].copy_from_slice(&SECTORS_PER_CHUNK.to_le_bytes());
    vol_data[12..16].copy_from_slice(&BYTES_PER_SECTOR.to_le_bytes());
    vol_data[16..24].copy_from_slice(&sector_count.to_le_bytes());
    file.extend_from_slice(&vol_data);

    // 3. The shared sectors data goes AFTER all table sections. We must know its
    //    absolute offset to set every table's base_offset, so compute the layout
    //    first: a run of (table-desc + table-hdr + entries) blocks, then ONE
    //    sectors descriptor, then the blob, then `done`.
    let n_sections = total_chunks.div_ceil(entries_per_section);
    let mut section_sizes = Vec::with_capacity(n_sections);
    let mut remaining = total_chunks;
    for _ in 0..n_sections {
        let n = remaining.min(entries_per_section);
        section_sizes.push(n);
        remaining -= n;
    }

    // Bytes consumed by all table sections (descriptor + 24-B header + entries).
    let mut tables_bytes = 0u64;
    for &n in &section_sizes {
        tables_bytes += SECTION_DESCRIPTOR_SIZE as u64 + 24 + (n as u64) * 4;
    }

    let sectors_desc_off = first_tbl_desc_off + tables_bytes;
    let sectors_data_off = sectors_desc_off + SECTION_DESCRIPTOR_SIZE as u64;
    // Every entry points at the single shared blob at sectors_data_off.
    // base_offset = sectors_data_off, chunk_offset = 0 for all entries.
    let done_desc_off = sectors_data_off + blob_len;

    // 4. Emit each table section. Each table descriptor's `next` points at the
    //    following table descriptor (or, for the last one, the sectors desc).
    let mut cursor = first_tbl_desc_off;
    for (si, &n) in section_sizes.iter().enumerate() {
        let this_section_bytes = SECTION_DESCRIPTOR_SIZE as u64 + 24 + (n as u64) * 4;
        let next_off = if si + 1 < section_sizes.len() {
            cursor + this_section_bytes
        } else {
            sectors_desc_off
        };

        let mut tbl_desc = [0u8; SECTION_DESCRIPTOR_SIZE];
        tbl_desc[..5].copy_from_slice(b"table");
        tbl_desc[16..24].copy_from_slice(&next_off.to_le_bytes());
        tbl_desc[24..32].copy_from_slice(&this_section_bytes.to_le_bytes());
        file.extend_from_slice(&tbl_desc);

        // Table header: u32 entry_count + 4 pad + u64 base_offset.
        let mut hdr = [0u8; 24];
        hdr[0..4].copy_from_slice(&(n as u32).to_le_bytes());
        hdr[8..16].copy_from_slice(&sectors_data_off.to_le_bytes());
        file.extend_from_slice(&hdr);

        // Entries: all compressed, chunk_offset = 0 (point at the shared blob).
        let entry: u32 = 0x8000_0000;
        let entry_bytes = entry.to_le_bytes();
        for _ in 0..n {
            file.extend_from_slice(&entry_bytes);
        }

        cursor += this_section_bytes;
    }

    // 5. Sectors descriptor + shared blob.
    let mut sec_desc = [0u8; SECTION_DESCRIPTOR_SIZE];
    sec_desc[..7].copy_from_slice(b"sectors");
    sec_desc[16..24].copy_from_slice(&done_desc_off.to_le_bytes());
    sec_desc[24..32].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u64 + blob_len).to_le_bytes());
    file.extend_from_slice(&sec_desc);
    file.extend_from_slice(&blob);

    // 6. Done.
    let mut done = [0u8; SECTION_DESCRIPTOR_SIZE];
    done[..4].copy_from_slice(b"done");
    done[24..32].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u64).to_le_bytes());
    file.extend_from_slice(&done);

    let mut tmp = tempfile::Builder::new().suffix(".E01").tempfile().unwrap();
    tmp.write_all(&file).unwrap();
    tmp.flush().unwrap();
    tmp
}

struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

fn seq_throughput(reader: &EwfReader) -> (f64, u64) {
    let size = reader.total_size();
    let step = 1024 * 1024usize;
    let mut buf = vec![0u8; step];
    let t = Instant::now();
    let mut off = 0u64;
    let mut total = 0u64;
    while off < size {
        let want = step.min((size - off) as usize);
        let n = reader.read_at(&mut buf[..want], off).unwrap();
        if n == 0 {
            break;
        }
        total += n as u64;
        off += n as u64;
    }
    let secs = t.elapsed().as_secs_f64();
    (total as f64 / 1_000_000.0 / secs, total)
}

fn random_throughput(reader: &EwfReader, n_reads: usize, read_len: usize) -> f64 {
    let size = reader.total_size();
    let mut rng = Rng(0x1234_5678_9abc_def0);
    let mut buf = vec![0u8; read_len];
    let t = Instant::now();
    let mut total = 0u64;
    for _ in 0..n_reads {
        let off = if size > read_len as u64 {
            rng.next_u64() % (size - read_len as u64)
        } else {
            0
        };
        let n = reader.read_at(&mut buf, off).unwrap();
        total += n as u64;
    }
    let secs = t.elapsed().as_secs_f64();
    total as f64 / 1_000_000.0 / secs
}

fn main() {
    let mut args = std::env::args().skip(1);
    let total_chunks: usize = args
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000);
    let entries_per_section: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(16_384);

    println!(
        "Building synthetic E01: {total_chunks} chunks ({} MiB logical), {entries_per_section} entries/section, {} sections ...",
        total_chunks as u64 * u64::from(CHUNK_SIZE) / (1024 * 1024),
        total_chunks.div_ceil(entries_per_section)
    );
    let tmp = build_many_chunk_e01(total_chunks, entries_per_section);
    let on_disk = std::fs::metadata(tmp.path()).unwrap().len();
    println!("On-disk image size: {} KiB\n", on_disk / 1024);

    // --- open() timing ---
    let t = Instant::now();
    let eager = EwfReader::open(tmp.path()).unwrap();
    let eager_open = t.elapsed();

    let t = Instant::now();
    let lazy = EwfReader::open_lazy(tmp.path()).unwrap();
    let lazy_open = t.elapsed();

    assert_eq!(eager.chunk_count(), lazy.chunk_count());
    assert_eq!(eager.chunk_count(), total_chunks);

    // --- resident table bytes (measured BEFORE any reads, so lazy cache empty) ---
    let eager_resident = eager.resident_table_bytes();
    let lazy_resident_cold = lazy.resident_table_bytes();

    // --- sequential throughput ---
    let (eager_seq, _) = seq_throughput(&eager);
    let (lazy_seq, _) = seq_throughput(&lazy);

    // resident AFTER a full sequential sweep (lazy cache warmed to its cap).
    let lazy_resident_warm = lazy.resident_table_bytes();

    // --- random throughput: 10k random 64 KiB reads ---
    let eager_rnd = random_throughput(&eager, 10_000, 64 * 1024);
    let lazy_rnd = random_throughput(&lazy, 10_000, 64 * 1024);

    let chunk_struct = 16usize; // size_of::<Chunk> (packed to 16 B)
    println!("=== EAGER vs LAZY chunk table ({total_chunks} chunks) ===\n");
    println!("{:<28} {:>18} {:>18}", "metric", "EAGER", "LAZY");
    println!("{}", "-".repeat(66));
    println!(
        "{:<28} {:>18} {:>18}",
        "open() time",
        format!("{:.2?}", eager_open),
        format!("{:.2?}", lazy_open)
    );
    println!(
        "{:<28} {:>18} {:>18}",
        "resident table (cold)",
        fmt_bytes(eager_resident),
        fmt_bytes(lazy_resident_cold)
    );
    println!(
        "{:<28} {:>18} {:>18}",
        "resident table (warm)",
        fmt_bytes(eager_resident),
        fmt_bytes(lazy_resident_warm)
    );
    println!(
        "{:<28} {:>18} {:>18}",
        "sequential read",
        format!("{eager_seq:.0} MB/s"),
        format!("{lazy_seq:.0} MB/s")
    );
    println!(
        "{:<28} {:>18} {:>18}",
        "random read (10k×64KiB)",
        format!("{eager_rnd:.0} MB/s"),
        format!("{lazy_rnd:.0} MB/s")
    );
    println!("\nsize_of::<Chunk> = {chunk_struct} B; eager table = chunk_count × 16 B.");
    println!(
        "Resident memory reduction (cold): {:.1}×",
        eager_resident as f64 / lazy_resident_cold.max(1) as f64
    );
}

fn fmt_bytes(b: usize) -> String {
    if b >= 1024 * 1024 {
        format!("{:.1} MiB", b as f64 / (1024.0 * 1024.0))
    } else if b >= 1024 {
        format!("{:.1} KiB", b as f64 / 1024.0)
    } else {
        format!("{b} B")
    }
}
