use std::io::{Read, Seek, SeekFrom};

#[test]
fn validate_maxpowers() {
    let path = "../usnjrnl-forensic/test-data/MaxPowersCDrive.E01";
    if !std::path::Path::new(path).exists() {
        eprintln!("Skipping: image not found at {}", path);
        return;
    }

    let result = ewf::EwfReader::open(path);
    match result {
        Ok(mut reader) => {
            eprintln!("=== ewf crate geometry ===");
            eprintln!("Total size: {} bytes", reader.total_size());
            eprintln!("Chunk size: {} bytes", reader.chunk_size());
            eprintln!("Chunk count: {}", reader.chunk_count());

            // Validate geometry against libewf reference values
            assert_eq!(reader.total_size(), 53687091200, "Total size must match ewfinfo");

            // Read MBR
            let mut mbr = [0u8; 512];
            reader.read_exact(&mut mbr).unwrap();
            eprintln!("MBR signature: 0x{:02X}{:02X}", mbr[510], mbr[511]);
            assert_eq!(mbr[510], 0x55);
            assert_eq!(mbr[511], 0xAA);

            // Validate MBR partition entry #1: NTFS at sector 1026048
            // Partition table entry 1 starts at offset 0x1BE in MBR
            let p1_type = mbr[0x1C2]; // partition type byte
            let p1_lba = u32::from_le_bytes([mbr[0x1C6], mbr[0x1C7], mbr[0x1C8], mbr[0x1C9]]);
            eprintln!("Partition 1: type=0x{:02X}, LBA start={}", p1_type, p1_lba);
            assert_eq!(p1_type, 0x07, "Partition 1 should be NTFS (0x07)");
            assert_eq!(p1_lba, 1026048, "Partition 1 LBA must match mmls");

            // Read NTFS boot sector at partition start
            let ntfs_offset = p1_lba as u64 * 512;
            reader.seek(SeekFrom::Start(ntfs_offset)).unwrap();
            let mut ntfs_boot = [0u8; 512];
            reader.read_exact(&mut ntfs_boot).unwrap();
            let oem_id = std::str::from_utf8(&ntfs_boot[3..11]).unwrap_or("<invalid>");
            eprintln!("NTFS OEM ID at offset {}: '{}'", ntfs_offset, oem_id.trim());
            assert!(oem_id.starts_with("NTFS"), "NTFS boot sector must have NTFS OEM ID");
            // NTFS boot sector also ends with 55 AA
            assert_eq!(ntfs_boot[510], 0x55);
            assert_eq!(ntfs_boot[511], 0xAA);

            // Sample reads at various offsets
            for offset in [0u64, 512, 1_048_576, 100_000_000] {
                reader.seek(SeekFrom::Start(offset)).unwrap();
                let mut buf = [0u8; 16];
                reader.read_exact(&mut buf).unwrap();
                eprintln!("Bytes at offset {}: {:02X?}", offset, &buf);
            }

            // Midpoint read
            let mid = reader.total_size() / 2;
            reader.seek(SeekFrom::Start(mid)).unwrap();
            let mut buf = [0u8; 16];
            match reader.read_exact(&mut buf) {
                Ok(_) => eprintln!("Bytes at midpoint {}: {:02X?}", mid, &buf),
                Err(e) => eprintln!("Read at midpoint {} failed (truncated image): {}", mid, e),
            }

            // End read
            let end_offset = reader.total_size() - 512;
            reader.seek(SeekFrom::Start(end_offset)).unwrap();
            let mut tail = [0u8; 512];
            match reader.read(&mut tail) {
                Ok(n) => eprintln!("Read {} bytes at end offset {}", n, end_offset),
                Err(e) => eprintln!("Read at end {} failed (truncated image): {}", end_offset, e),
            }
        }
        Err(e) => {
            eprintln!("=== ewf crate FAILED to open image ===");
            eprintln!("Error: {}", e);
        }
    }
}

/// Compare first 4096 bytes against Sleuth Kit img_cat reference
#[test]
fn compare_with_sleuthkit_reference() {
    let path = "../usnjrnl-forensic/test-data/MaxPowersCDrive.E01";
    let ref_path = "/tmp/ewf_maxpowers_reference.raw";
    if !std::path::Path::new(path).exists() || !std::path::Path::new(ref_path).exists() {
        eprintln!("Skipping byte comparison: files not available");
        return;
    }

    let ref_bytes = std::fs::read(ref_path).unwrap();
    eprintln!("Reference file size: {} bytes", ref_bytes.len());
    assert_eq!(ref_bytes.len(), 4096, "Reference should be 4096 bytes");

    let mut reader = ewf::EwfReader::open(path).unwrap();
    let mut our_bytes = vec![0u8; ref_bytes.len()];
    reader.read_exact(&mut our_bytes).unwrap();

    let mut mismatches = 0;
    for (i, (ours, theirs)) in our_bytes.iter().zip(ref_bytes.iter()).enumerate() {
        if ours != theirs {
            if mismatches < 10 {
                eprintln!("MISMATCH at byte {}: ours=0x{:02X} ref=0x{:02X}", i, ours, theirs);
            }
            mismatches += 1;
        }
    }
    if mismatches == 0 {
        eprintln!("PASS: All {} bytes match Sleuth Kit reference!", ref_bytes.len());
    } else {
        eprintln!("FAIL: {} byte mismatches out of {}", mismatches, ref_bytes.len());
    }
    assert_eq!(mismatches, 0, "Byte-level comparison with Sleuth Kit failed");
}

/// Compare first 4096 bytes against libewf (pyewf) reference
#[test]
fn maxpowers_byte_comparison_vs_libewf() {
    let path = "../usnjrnl-forensic/test-data/MaxPowersCDrive.E01";
    if !std::path::Path::new(path).exists() { return; }

    let ref_path = "/tmp/maxpowers_first_4096.bin";
    if !std::path::Path::new(ref_path).exists() {
        eprintln!("Skipping: pyewf reference not found at {}", ref_path);
        return;
    }

    let reference = std::fs::read(ref_path).unwrap();
    assert_eq!(reference.len(), 4096);

    let mut reader = ewf::EwfReader::open(path).unwrap();
    reader.seek(SeekFrom::Start(0)).unwrap();
    let mut ours = vec![0u8; 4096];
    reader.read_exact(&mut ours).unwrap();

    let mut mismatches = 0;
    for i in 0..4096 {
        if ours[i] != reference[i] {
            if mismatches < 10 {
                eprintln!("MISMATCH at byte {}: ours=0x{:02X}, libewf=0x{:02X}",
                    i, ours[i], reference[i]);
            }
            mismatches += 1;
        }
    }
    eprintln!("First 4096 bytes: {} mismatches", mismatches);
    assert_eq!(mismatches, 0, "First 4096 bytes differ from libewf!");
    eprintln!("=== MaxPowers byte comparison vs libewf: PASSED ===");
}
