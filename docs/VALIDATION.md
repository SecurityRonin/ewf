# Validation Report

Full-media MD5 comparison of the `ewf` crate against **libewf** (via ewfexport/pyewf) and **The Sleuth Kit** (via img_cat) using publicly available forensic disk images.

Every byte of decompressed media is hashed and compared — not sampled.

## Test Environment

| Component | Version |
|-----------|---------|
| ewf crate | 0.1.0 |
| libewf (ewfexport) | 20231119 |
| Sleuth Kit (img_cat) | 4.12.1 |
| Rust | 1.88.0 |
| Platform | macOS Darwin 24.6.0 (aarch64) |

## Test Images

### 1. Szechuan Sauce (DESKTOP-SDN1RPT)

| Property | Value |
|----------|-------|
| Challenge | [The Stolen Szechuan Sauce](https://dfirmadness.com/the-stolen-szechuan-sauce/) (James Smith) |
| Catalog | [CFREDS — HackTheBox / SzechuanSauce](https://cfreds.nist.gov/all/HackTheBox/SzechuanSauce) |
| Download | [The Evidence Locker](https://theevidencelocker.github.io/) (Kevin Pagano) |
| Filename | `20200918_0417_DESKTOP-SDN1RPT.E01` through `.E04` |
| Format | EWF v1, multi-segment (E01-E04) |
| Segments | 4 (2.0 GB + 2.0 GB + 2.0 GB + 403 MB) |
| Media size | 16,106,127,360 bytes (15.0 GiB) |
| Sectors/chunk | 64 |
| Acquisition | FTK Imager, 2020-09-18 |

**Full-media MD5:** `bcd3aef20406df00585341f0c743a1ce` — identical across libewf, Sleuth Kit, and ewf crate.

### 2. MaxPowers C Drive

| Property | Value |
|----------|-------|
| Challenge | [MUS CTF 2018](https://www.youracclaim.com/org/magnet-forensics/badge/magnet-user-summit-ctf-2018) (David Cowen & Matt Seyer) |
| Catalog | [CFREDS — AcademicChallenges / MaxPowers](https://cfreds.nist.gov/all/AcademicChallenges/MaxPowers) |
| Download | [The Evidence Locker](https://theevidencelocker.github.io/) (Kevin Pagano) — hosted on Dropbox |
| URL | `https://www.dropbox.com/scl/fo/oqal4blnfi5vj4miof355/AP223ojh3w70febB3gAsKkM/MaxPowersCDrive.E01?rlkey=ogpdttfz3xzk8005r95gedgiw&e=1&dl=1` |
| Filename | `MaxPowersCDrive.E01` |
| E01 file size | 31,577,797,290 bytes (29.4 GB) |
| E01 MD5 | `BED3B3DDECE20D136A56AA653F0DE608` |
| Format | linen 5, single segment |
| Media size | 53,687,091,200 bytes (50.0 GiB) |
| Sectors/chunk | 64 |
| Acquisition | linen 7.0.4.4 via f-response, 2018-05-05 |

**Full-media MD5:** `10c1fbc9c01d969789ada1c67211b89f` — identical across libewf, Sleuth Kit, and ewf crate.

### 3. PC-MUS-001

| Property | Value |
|----------|-------|
| Challenge | [MVS CTF 2023](https://www.magnetforensics.com/blog/announcing-the-mvs-2023-ctf-winners-and-a-new-ctf-challenge/) (Magnet Forensics) |
| Catalog | [CFREDS — AcademicChallenges / PC-MUS-001](https://cfreds.nist.gov/all/AcademicChallenges/PC-MUS-001) |
| Download | [The Evidence Locker](https://theevidencelocker.github.io/) (Kevin Pagano) — hosted on Google Cloud Storage |
| URL | `https://storage.googleapis.com/mvs-2023/PC-MUS-001.E01` |
| Filename | `PC-MUS-001.E01` |
| E01 file size | 52,629,766,482 bytes (49.0 GB) |
| E01 MD5 | `8CF0C007391F4A72DDC12A570A115B46` |
| Format | EnCase 6, single segment |
| Media size | 256,060,514,304 bytes (238.5 GiB) |
| Sectors/chunk | 64 |
| Acquisition | EnCase 20190306, 2023-01-07 |
| Section features | Both `table` and `table2` sections present (EnCase 6 redundancy) |

**Full-media MD5:** `522df9db8289f4f8132cf47b14d20fb8` — identical across libewf, Sleuth Kit, and ewf crate.

## How to Reproduce

### Download test images

```bash
# Szechuan Sauce (4 segments, ~6.4 GB total)
# Download from The Evidence Locker: https://theevidencelocker.github.io/

# MaxPowers C Drive (single segment, 29.4 GB)
curl -L -o MaxPowersCDrive.E01 \
  "https://www.dropbox.com/scl/fo/oqal4blnfi5vj4miof355/AP223ojh3w70febB3gAsKkM/MaxPowersCDrive.E01?rlkey=ogpdttfz3xzk8005r95gedgiw&e=1&dl=1"
md5 MaxPowersCDrive.E01  # expect BED3B3DDECE20D136A56AA653F0DE608

# PC-MUS-001 (single segment, 49 GB)
curl -L -o PC-MUS-001.E01 \
  "https://storage.googleapis.com/mvs-2023/PC-MUS-001.E01"
md5 PC-MUS-001.E01  # expect 8CF0C007391F4A72DDC12A570A115B46
```

### Generate reference hashes

```bash
# Full-media MD5 via Sleuth Kit
img_cat image.E01 | md5

# Full-media MD5 via libewf
ewfexport -t - -f raw -u image.E01 2>/dev/null | md5
```

### Run validation tests

```bash
cargo test --tests
```

## Summary

| Image | Format | Media Size | Full-media MD5 | ewf = libewf = TSK |
|-------|--------|------------|----------------|---------------------|
| Szechuan Sauce | EWF v1, 4 segments | 15.0 GiB | `bcd3aef...` | Yes |
| MaxPowers | linen 5, 1 segment | 50.0 GiB | `10c1fbc...` | Yes |
| PC-MUS-001 | EnCase 6, 1 segment | 238.5 GiB | `522df9d...` | Yes |

The `ewf` crate produces bit-identical output to both libewf and The Sleuth Kit across all 303 GiB of tested media.
