//! End-to-end tests using small public E01 images from Digital Corpora (DFTT project).
//!
//! Test fixtures in `tests/data/` are committed to the repo (~1.2 MB total).
//! Raw media MD5 hashes verified against both libewf (ewfexport) and The Sleuth Kit (img_cat).

use md5::{Digest, Md5};
use std::io::{Read, Seek, SeekFrom};

const DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");

fn full_media_md5(reader: &mut ewf::EwfReader) -> String {
    let mut hasher = Md5::new();
    let mut buf = vec![0u8; 1024 * 1024]; // 1 MB buffer
    reader.seek(SeekFrom::Start(0)).unwrap();
    loop {
        let n = reader.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    format!("{:x}", hasher.finalize())
}

// ---------- exfat1.E01 (EnCase 6, deflate best-compression, exFAT) ----------

#[test]
fn exfat1_media_size() {
    let path = format!("{DATA_DIR}/exfat1.E01");
    let reader = ewf::EwfReader::open(&path).unwrap();
    assert_eq!(reader.total_size(), 100_020_736);
}

#[test]
fn exfat1_full_media_md5() {
    let path = format!("{DATA_DIR}/exfat1.E01");
    let mut reader = ewf::EwfReader::open(&path).unwrap();
    assert_eq!(
        full_media_md5(&mut reader),
        "0777ee90c27ed5ff5868af2015bed635",
        "Full-media MD5 mismatch vs libewf/Sleuth Kit"
    );
}

#[test]
fn exfat1_seek_and_read_consistency() {
    let path = format!("{DATA_DIR}/exfat1.E01");
    let mut reader = ewf::EwfReader::open(&path).unwrap();

    // Read first 512 bytes sequentially
    let mut sequential = [0u8; 512];
    reader.seek(SeekFrom::Start(0)).unwrap();
    reader.read_exact(&mut sequential).unwrap();

    // Read same bytes via seek
    let mut seeked = [0u8; 512];
    reader.seek(SeekFrom::Start(0)).unwrap();
    reader.read_exact(&mut seeked).unwrap();

    assert_eq!(sequential, seeked);

    // Read at a chunk boundary (32 KB = 32768)
    let mut at_boundary = [0u8; 512];
    reader.seek(SeekFrom::Start(32768)).unwrap();
    reader.read_exact(&mut at_boundary).unwrap();

    // Read same region again
    let mut at_boundary2 = [0u8; 512];
    reader.seek(SeekFrom::Start(32768)).unwrap();
    reader.read_exact(&mut at_boundary2).unwrap();

    assert_eq!(at_boundary, at_boundary2);
}

// ---------- imageformat_mmls_1.E01 (FTK Imager, no compression, NTFS) ----------

#[test]
fn mmls1_media_size() {
    let path = format!("{DATA_DIR}/imageformat_mmls_1.E01");
    let reader = ewf::EwfReader::open(&path).unwrap();
    assert_eq!(reader.total_size(), 62_915_072);
}

#[test]
fn mmls1_full_media_md5() {
    let path = format!("{DATA_DIR}/imageformat_mmls_1.E01");
    let mut reader = ewf::EwfReader::open(&path).unwrap();
    assert_eq!(
        full_media_md5(&mut reader),
        "8ec671e301095c258224aad701740503",
        "Full-media MD5 mismatch vs libewf/Sleuth Kit"
    );
}

#[test]
fn mmls1_mbr_signature() {
    let path = format!("{DATA_DIR}/imageformat_mmls_1.E01");
    let mut reader = ewf::EwfReader::open(&path).unwrap();
    let mut mbr = [0u8; 512];
    reader.read_exact(&mut mbr).unwrap();
    assert_eq!(mbr[510], 0x55);
    assert_eq!(mbr[511], 0xAA);
}

#[test]
fn mmls1_seek_from_end() {
    let path = format!("{DATA_DIR}/imageformat_mmls_1.E01");
    let mut reader = ewf::EwfReader::open(&path).unwrap();

    // Seek to last 512 bytes
    reader.seek(SeekFrom::End(-512)).unwrap();
    let mut last_sector = [0u8; 512];
    reader.read_exact(&mut last_sector).unwrap();

    // Verify position is at end
    let pos = reader.stream_position().unwrap();
    assert_eq!(pos, 62_915_072);
}

// ---------- nps-2010-emails.E01 (EnCase 6, deflate best, 10 MiB) ----------

#[test]
fn emails_media_size() {
    let path = format!("{DATA_DIR}/nps-2010-emails.E01");
    let reader = ewf::EwfReader::open(&path).unwrap();
    assert_eq!(reader.total_size(), 10_485_760);
}

#[test]
fn emails_full_media_md5() {
    let path = format!("{DATA_DIR}/nps-2010-emails.E01");
    let mut reader = ewf::EwfReader::open(&path).unwrap();
    assert_eq!(
        full_media_md5(&mut reader),
        "7dae50cec8163697415e69fd72387c01",
        "Full-media MD5 mismatch vs libewf/Sleuth Kit"
    );
}

#[test]
fn emails_sequential_equals_random_access() {
    let path = format!("{DATA_DIR}/nps-2010-emails.E01");
    let mut reader = ewf::EwfReader::open(&path).unwrap();

    // Read 4 chunks sequentially from offset 0
    let mut sequential = vec![0u8; 32768 * 4];
    reader.seek(SeekFrom::Start(0)).unwrap();
    reader.read_exact(&mut sequential).unwrap();

    // Read same 4 chunks in reverse order via seeking
    let mut random_access = vec![0u8; 32768 * 4];
    for i in (0..4).rev() {
        let offset = i * 32768;
        reader.seek(SeekFrom::Start(offset as u64)).unwrap();
        reader
            .read_exact(&mut random_access[offset..offset + 32768])
            .unwrap();
    }

    assert_eq!(sequential, random_access);
}
