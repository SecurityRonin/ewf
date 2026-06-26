# Task: Parallel chunk-decompression (intra-image) + multi-source ingest (inter-image)

Status: **partially DONE** (2026-06-27). The reader concurrency *enabler* and the
issen inter-image ingest parallelism are implemented with strict TDD; the remaining
piece is a parallel *consumer* in ewf (parallel verify/hash) to cash in the intra-image
win for full-image ops. Research done 2026-06-27.

## Done so far (strict TDD, separate RED/GREEN commits)

- **Intra-image enabler — `EwfReader` is now `Sync` with positioned reads** (ewf repo):
  `read_at(&self)` serves cursor-free positioned reads (`pread`/`seek_read`, no mmap, keeps
  `forbid(unsafe)`); chunk cache is `Mutex<LruCache>` updated through `&self`, decompression
  happens *outside* the lock so distinct chunks decompress in parallel. RED `b1d8be8`
  (8-thread disjoint + 16-thread hot-chunk differential vs serial) → GREEN `37c2963`.
  Validated: full ewf suite + the `ewfexport` differential oracle stays byte-correct.
- **Inter-image — parallel multi-source ingest** (issen repo): `parse_sources_parallel`
  (capped, order-preserving rayon map) RED `94b3f7d` (order + `Barrier(2)` concurrency proof
  + clamp) → GREEN `d9c0ac5`; wired into `ingest::run` as phase A (serial store setup +
  resume) / phase B (parallel parse, cap = cores-2) / phase C (serial in-order commit) —
  commit `a38cf95`. Determinism holds because cross-source events differ in
  `evidence_source_id` → `record_hash`, so the `ORDER BY timestamp_ns, record_hash, id` sort
  is run-order-independent. Validated: real DC01 E01 still ingests 1,072,067 events; issen-cli
  lib 150/150; integration suite byte-identical to HEAD (the 36 fails are pre-existing).

## Still TODO

1. **Parallel consumer in ewf** — rayon over the chunk range inside `verify()` / a `par_read`,
   so `ewf verify` and full-image hashers actually use the now-`Sync` reader (the intra-image
   benchmark below). This is the remaining intra-image payoff.
2. **issen-ewf wrapper** — drop its `Mutex<EwfReader>`, delegate to `read_at(&self)`; gated on
   **publishing ewf 0.2.2** (issen depends on the registry `ewf = "0.2"`, where `read_at` is
   still private). Bump + publish ewf 0.2.2, then `cargo update -p ewf` in issen.

Build the remainder with **strict TDD** + before/after benchmark on a real E01.

## Why (and why NOT for issen's ingest)

A single multi-segment forensic image **is** parallelizable — but the unit is the **chunk**, not the segment:

- EWF/E01 compresses each **chunk** (~32 KB / 64 sectors) **independently** with zlib, and a `table`/`table2` index maps logical offset → (segment file, file-offset, compressed size). So any chunk decompresses on its own → random access *and* parallel decompression. EWF's zlib scheme is documented as **CPU-intensive** for full-image reads. AFF4 was designed around exactly this (chunks → "bevies" + index segments). Sources: libewf spec (Joachim Metz); DFRWS AFF4 papers (Cohen, Schatz); LoC EWF format FDD; forensics.wiki/aff4.
- VMDK (streamOptimized grains), QCOW2 (clusters via L1/L2) are the same story; VHDX blocks are **uncompressed** (no decompress to parallelize, only concurrent memcpy).

**Profiled reality (issen):** issen's *triage* ingest is **not** decompression-bound — a `sample(1)` profile of a DC01 E01 ingest showed the hot path is ~100% DuckDB statement execution (fixed separately by the Appender change: 194 s → 17 s). Decompression did not appear. So this refactor is a **fleet** win for **full-image ops** — `blazehash` hashing for chain-of-custody, `ewf verify`, carving, `dd`-export — NOT an issen-ingest win.

## Reader state (audited 2026-06-27)

| Format | offset table | indep-compressed units | random-access seek | reader Send+Sync | blocker |
|---|---|---|---|---|---|
| EWF (`~/src/ewf`) | ✅ chunk table | ✅ zlib/chunk | ✅ O(1), LRU cache | ❌ `Mutex<EwfReader>` (issen-ewf wrapper) | single Mutex serializes every `read_at` |
| VMDK (`~/src/vmdk`) | ✅ GD+GT | ✅ zlib/grain | ✅ | ❌ single `&mut File` cursor | `Read` impl `&mut self` |
| QCOW2 (`~/src/qcow2`) | ✅ L1+L2 | ✅ deflate/cluster | ✅ | ❌ single `&mut File` cursor | `Read` impl `&mut self` |
| VHDX (`~/src/vhdx`) | ✅ BAT | ❌ uncompressed | ✅ | (stateless data Vec) | no decompression to gain |

The chunk *locations* are stateless (computed from the table), so parallelization is architecturally clean once the single-cursor/Mutex is removed.

## Design

**Intra-image** — make the reader serve **positioned reads** concurrently:
1. Replace the single `&mut File` cursor / `Mutex<reader>` with **positioned reads** — `std::os::unix::fs::FileExt::read_at` (pread, no cursor mutation) and/or `mmap` the segment files (read-only, `Sync`), and/or per-thread file handles.
2. Make the `DataSource`/reader **`Sync`** so multiple threads call `read_at(offset, buf)` independently, each decompressing its own chunk; a thread-safe (or per-thread) chunk cache.
3. Either (a) parallelize a *single large read* across chunks internally (rayon over the chunk range), or (b) just remove the Mutex so the **existing** `parse_into_jobs_parallel` (issen) and full-image hashers get concurrent decompression for free. (b) is the lower-risk, higher-leverage first step.

**Inter-image** (issen) — parallelize the `for src in &sources` loop in `issen/crates/issen-cli/src/commands/ingest.rs` (cap = `available_parallelism() - 2`, one indicatif bar per image, **commits serialized** through the single-writer DuckDB via `Arc<Mutex<TimelineStore>>`; parsing lock-free). Note: now that ingest is 17 s (Appender fix), this is a smaller win than originally thought — sequence it after the intra-image work.

## Strict-TDD plan

- **RED**: a concurrency test that spawns N threads each `read_at` a different offset of a fixture E01 and asserts the bytes match the serial reader (differential oracle) — fails today because the reader is `!Sync` / Mutex-serialized.
- **GREEN**: positioned-read refactor; the test compiles + passes (reader is `Sync`, concurrent reads byte-identical to serial).
- **Correctness**: differential vs the current serial reader on the in-repo corpus (every chunk read byte-identical) — never trust a synthetic round-trip alone.
- **Benchmark (Doer-Checker)**: `ewf verify` (full decompress) on a real multi-GB E01, serial vs N-thread, on a 14-core box — record the speedup. Expect near-linear up to memory-bandwidth limits.
- Keep `forbid(unsafe)` (mmap needs a justified `#[allow(unsafe_code)]` like ewf-forensic's existing mmap sites).

## Pointers
- issen Appender fix that made decompression *not* the bottleneck: issen `crates/issen-timeline/src/ingest.rs` `commit_parse_job_body` (commit 54db737).
- ewf reader: `~/src/ewf/ewf/src/reader.rs` (+ `lib.rs`, `ewf2.rs`); issen wrapper `~/src/issen/crates/issen-ewf`.
