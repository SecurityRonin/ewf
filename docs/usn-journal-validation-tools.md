# USN Journal Parsing Tools for Validation Comparison

Research conducted 2026-03-05. Tools listed below can parse extracted `$UsnJrnl:$J` files offline (not just live Windows) unless noted otherwise.

---

## Tier 1: Best candidates for validation (offline, cross-platform, path resolution)

### 1. usnrs (Airbus CERT)
- **URL:** https://github.com/airbus-cert/usnrs
- **Language:** Rust
- **Offline $J parsing:** YES - designed specifically for extracted $J files
- **Path resolution:** YES - accepts MFT file via `-m` flag to reconstruct full paths; includes checks for reallocated MFT entries
- **Last commit:** 2025-09-26 (actively maintained)
- **Output formats:** USN-Journal-Parser-compatible format, body file (mactime v3.X)
- **Record versions:** V2 only
- **macOS install:**
  ```bash
  git clone https://github.com/airbus-cert/usnrs.git
  cd usnrs
  cargo build --release
  # Binary at target/release/usnrs-cli
  ```
- **Usage:**
  ```bash
  usnrs-cli -j extracted_J_file                    # basic parse
  usnrs-cli -j extracted_J_file -m extracted_MFT   # with path resolution
  usnrs-cli -j extracted_J_file -b                  # body file output
  ```
- **VERDICT:** Excellent validation candidate. Rust, cross-platform, active, has MFT path resolution.

### 2. dfir_ntfs (Maxim Suhanov)
- **URL:** https://github.com/msuhanov/dfir_ntfs
- **Language:** Python 3
- **Offline $J parsing:** YES - parses extracted $MFT, $UsnJrnl:$J, $LogFile files
- **Path resolution:** YES - `ntfs_parser` tool resolves "File path (from $MFT)" column in CSV output
- **Last commit:** 2025-10-31 (actively maintained)
- **Output:** CSV with columns: USN value, Source, Reason, MFT ref, Parent MFT ref, Timestamp, File name, File path
- **Record versions:** V2 and V3
- **License:** GPL v3
- **macOS install:**
  ```bash
  pip3 install https://github.com/msuhanov/dfir_ntfs/archive/1.1.20.tar.gz
  ```
- **Usage:**
  ```bash
  ntfs_parser --usn extracted_J_file --mft extracted_MFT -o output.csv
  ```
- **VERDICT:** Excellent validation candidate. Python, cross-platform, actively maintained, comprehensive parser with $LogFile support.

### 3. RustyUsn (Matthew Seyer / forensicmatt)
- **URL:** https://github.com/forensicmatt/RustyUsn
- **Language:** Rust
- **Offline $J parsing:** YES - reads extracted $J files; if source is a directory, recurses looking for `$J` files
- **Path resolution:** YES - accepts `-m` MFT file for folder mapping
- **Last commit:** 2020-01-08 (dormant since 2020)
- **Output:** JSONL
- **Record versions:** V2, V3 (64-bit refs only, not 128-bit)
- **macOS install:**
  ```bash
  git clone https://github.com/forensicmatt/RustyUsn.git
  cd RustyUsn
  cargo build --release
  # Binary at target/release/rusty_usn
  ```
- **Usage:**
  ```bash
  rusty_usn -s extracted_J_file                    # basic parse
  rusty_usn -s extracted_J_file -m extracted_MFT   # with path resolution
  ```
- **Notes:** Also supports parsing carved USN records from unallocated space (via blkls output). Dormant but functional.
- **VERDICT:** Good validation candidate. Rust/JSONL output makes diff comparison easy. Not maintained but stable.

### 4. mftmactime (kero99)
- **URL:** https://github.com/kero99/mftmactime
- **Language:** Python (uses Omer BenAmram's MFT Rust libraries)
- **Offline $J parsing:** YES - accepts individual triage files or RAW forensic images
- **Path resolution:** YES - combined MFT+USN timeline output
- **Last commit:** 2023-05-10 (semi-maintained)
- **Output:** mactime/body file format, CSV
- **macOS install:**
  ```bash
  pip install mft argparse tqdm pytz pytsk3 yara-python
  git clone https://github.com/kero99/mftmactime.git
  # Note: pytsk3 can be tricky to compile on macOS
  ```
- **Usage:**
  ```bash
  python mftmactime.py -f extracted_MFT -j extracted_J_file -o timeline.csv -n
  ```
- **VERDICT:** Good for timeline-focused validation. Combines MFT+USN into unified mactime output.

---

## Tier 2: Usable for validation (offline, but limited features or platform constraints)

### 5. usn_analytics (4n6ist / Forensicist)
- **URL:** https://github.com/4n6ist/usn_analytics
- **Website:** https://www.kazamiya.net/en/usn_analytics
- **Language:** C++
- **Offline $J parsing:** YES - pure parser mode with `-r` flag
- **Path resolution:** NO (parser only)
- **Last commit:** 2018-01-24 (dormant)
- **Pre-built binaries:** Windows, Linux, macOS (x64) available on project website
- **macOS install:**
  ```bash
  git clone https://github.com/4n6ist/usn_analytics.git
  cd usn_analytics
  # Edit Makefile for macOS (no static builds on macOS)
  make
  ```
  Or download pre-built macOS binary from https://www.kazamiya.net/en/usn_analytics
- **Usage:**
  ```bash
  usn_analytics -r extracted_J_file -u    # -u for UTC timestamps
  ```
- **VERDICT:** Simple parser, pre-built macOS binary available. Good for quick sanity checks.

### 6. ntfs-linker (Stroz Friedberg)
- **URL:** https://github.com/strozfriedberg/ntfs-linker
- **Language:** C++
- **Offline $J parsing:** YES - processes $MFT + $LogFile + $UsnJrnl together
- **Path resolution:** YES - full path linking via MFT correlation
- **Last commit:** 2016-03-03 (abandoned since 2016)
- **Output:** TSV (events.txt, log.txt, usn.txt) + SQLite database
- **Dependencies:** SQLite, Boost, libtsk, libewf, libbfio, libcerror, libvshadow
- **macOS install:**
  ```bash
  git clone https://github.com/strozfriedberg/ntfs-linker.git
  cd ntfs-linker
  # Requires: brew install boost sqlite libtsk libewf
  # Also needs libvshadow, libbfio, libcerror (manual build)
  autoreconf -i && ./configure && make
  # WARNING: Heavy dependency chain, may need significant effort on modern macOS
  ```
- **VERDICT:** Conceptually the most powerful (MFT+LogFile+USN linking), but abandoned since 2016. Building on modern macOS will likely require significant effort. Use as reference implementation only.

### 7. ntfstool (thewhiteninja)
- **URL:** https://github.com/thewhiteninja/ntfstool
- **Language:** C++
- **Offline $J parsing:** YES - can analyze USN journal with custom rules
- **Path resolution:** Limited (MFT parsing available separately)
- **Last commit:** 2023-07-23
- **Output:** CSV, JSON
- **macOS install:**
  ```bash
  git clone https://github.com/thewhiteninja/ntfstool.git
  cd ntfstool
  # C++ build with CMake
  mkdir build && cd build && cmake .. && make
  ```
- **VERDICT:** Broad NTFS tool (MFT, Bitlocker, EFS, USN). USN analysis includes rule-based detection. Less focused than dedicated USN parsers.

### 8. JParser (LYLC)
- **URL:** https://github.com/LYLC/JParser
- **Language:** Swift 4
- **Offline $J parsing:** YES
- **Path resolution:** NO
- **Last commit:** 2018-08-11 (dormant)
- **Platforms:** macOS, Linux (Ubuntu)
- **macOS install:** Build with Swift toolchain
- **VERDICT:** Native macOS support via Swift, but abandoned since 2018, no path resolution, V2 only.

---

## Tier 3: Not suitable for offline validation (live Windows only or GUI-only)

### 9. UsnJrnl2Csv (jschicht)
- **URL:** https://github.com/jschicht/UsnJrnl2Csv
- **Language:** AutoIt (Windows GUI)
- **Offline $J parsing:** YES - but Windows-only GUI application
- **Path resolution:** NO
- **Record versions:** V2 and V3 (not V4)
- **Has scan/carve mode:** YES - brute-force mode for damaged/carved data
- **macOS:** NOT available (AutoIt = Windows only)
- **VERDICT:** Windows only. Useful if you have a Windows VM. Good carving mode.

### 10. Journal-Trace (RitzySixx)
- **URL:** https://github.com/RitzySixx/Journal-Trace
- **Language:** Python (PyInstaller, Windows GUI)
- **Offline $J parsing:** NO - reads live NTFS drives only
- **Path resolution:** YES (MFT-based path caching on live system)
- **macOS:** NOT usable (live Windows NTFS access required)
- **VERDICT:** Not suitable. Live Windows only.

### 11. wangfu91/UsnParser and usn-journal-rs
- **URL:** https://github.com/wangfu91/UsnParser
- **Language:** C# (.NET 8) / Rust (usn-journal-rs)
- **Offline $J parsing:** NO - Windows API-based (FSCTL calls)
- **macOS:** NOT usable
- **VERDICT:** Not suitable. Live Windows only.

---

## Tier 4: Commercial / Closed-source

### 12. TZWorks jp (Windows Journal Parser)
- **URL:** https://tzworks.com/prototype_page.php?proto_id=5
- **Language:** Closed-source native binary
- **Offline $J parsing:** YES - accepts extracted $J files, dd images, or live volumes
- **Path resolution:** YES - accepts `-mft` flag pointing to exported $MFT file
- **Platforms:** Windows, Linux, macOS (pre-compiled binaries)
- **Unallocated carving:** YES - `-include_unalloc_clusters` scans unallocated space
- **Output:** Multiple parsable formats
- **macOS install:** Download macOS binary from https://www.tzworks.com/download_links.php
- **License:** Commercial (free for personal/academic use with limitations)
- **VERDICT:** Excellent tool if license permits. Pre-built macOS binary, path resolution, unallocated carving. But closed-source limits validation transparency.

### 13. DFIR ORC USNInfo (ANSSI)
- **URL:** https://dfir-orc.github.io/USNInfo.html
- **Source:** https://github.com/DFIR-ORC/dfir-orc
- **Language:** C++ (Windows)
- **Offline $J parsing:** MFT parser supports offline mode, but USNInfo itself uses FSCTL_READ_USN_JOURNAL (live only)
- **macOS:** NOT available (Windows focused)
- **VERDICT:** Not suitable for offline macOS use. The MFT parser is offline-capable but USN parsing is live-only.

---

## Recommended Validation Strategy

For validating your ewf USN parser output on macOS, use these tools in priority order:

1. **usnrs** (Rust, Airbus CERT) - Best overall: active, cross-platform, has path resolution, body file output
2. **dfir_ntfs** (Python, msuhanov) - Second-best: active, comprehensive, CSV output with full paths
3. **RustyUsn** (Rust, forensicmatt) - JSONL output, good for programmatic comparison
4. **usn_analytics** (C++, 4n6ist) - Quick sanity check with pre-built macOS binary
5. **TZWorks jp** (commercial) - If license permits, excellent reference with unallocated carving

### Validation approach:
```bash
# Extract $J and $MFT from evidence (e.g., using icat from Sleuthkit)
icat -o $OFFSET image.E01 $USN_INODE > extracted_J
icat -o $OFFSET image.E01 0 > extracted_MFT

# Parse with multiple tools and diff results:
usnrs-cli -j extracted_J -m extracted_MFT > usnrs_output.txt
ntfs_parser --usn extracted_J --mft extracted_MFT -o dfir_ntfs_output.csv
rusty_usn -s extracted_J -m extracted_MFT > rustyusn_output.jsonl

# Compare record counts, timestamps, filenames, reason codes
wc -l usnrs_output.txt dfir_ntfs_output.csv rustyusn_output.jsonl
```
