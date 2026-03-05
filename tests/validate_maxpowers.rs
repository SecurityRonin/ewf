use std::io::{Read, Seek, SeekFrom};

#[test]
fn validate_maxpowers() {
    let path = "../usnjrnl-forensic/test-data/MaxPowersCDrive.E01";
    if !std::path::Path::new(path).exists() {
        return;
    }

    let mut reader = ewf::EwfReader::open(path).unwrap();

    assert_eq!(
        reader.total_size(),
        53687091200,
        "Total size must match ewfinfo"
    );

    // MBR
    let mut mbr = [0u8; 512];
    reader.read_exact(&mut mbr).unwrap();
    assert_eq!(mbr[510], 0x55);
    assert_eq!(mbr[511], 0xAA);

    // NTFS partition at LBA 1026048
    let p1_type = mbr[0x1C2];
    let p1_lba = u32::from_le_bytes([mbr[0x1C6], mbr[0x1C7], mbr[0x1C8], mbr[0x1C9]]);
    assert_eq!(p1_type, 0x07, "Partition 1 should be NTFS (0x07)");
    assert_eq!(p1_lba, 1026048, "Partition 1 LBA must match mmls");

    // NTFS boot sector
    let ntfs_offset = p1_lba as u64 * 512;
    reader.seek(SeekFrom::Start(ntfs_offset)).unwrap();
    let mut ntfs_boot = [0u8; 512];
    reader.read_exact(&mut ntfs_boot).unwrap();
    let oem_id = std::str::from_utf8(&ntfs_boot[3..11]).unwrap_or("<invalid>");
    assert!(
        oem_id.starts_with("NTFS"),
        "NTFS boot sector must have NTFS OEM ID"
    );
}

/// Full-media MD5: read every byte through EwfReader, hash it, compare against
/// the hash produced by libewf (pyewf) and The Sleuth Kit (img_cat).
///
/// libewf full-media MD5: 10c1fbc9c01d969789ada1c67211b89f
/// Sleuth Kit full-media MD5: 10c1fbc9c01d969789ada1c67211b89f
#[test]
fn maxpowers_full_media_md5() {
    use md5::{Digest, Md5};

    let path = "../usnjrnl-forensic/test-data/MaxPowersCDrive.E01";
    if !std::path::Path::new(path).exists() {
        return;
    }

    let mut reader = ewf::EwfReader::open(path).unwrap();
    reader.seek(SeekFrom::Start(0)).unwrap();

    let mut hasher = Md5::new();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut total = 0u64;

    loop {
        let n = reader.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }

    let hash = format!("{:x}", hasher.finalize());
    eprintln!("MaxPowers full-media MD5: {hash}");
    eprintln!("Bytes hashed: {total} / {}", reader.total_size());

    assert_eq!(total, reader.total_size(), "Did not read entire media");
    assert_eq!(
        hash, "10c1fbc9c01d969789ada1c67211b89f",
        "Full-media MD5 mismatch vs libewf/Sleuth Kit"
    );
}
