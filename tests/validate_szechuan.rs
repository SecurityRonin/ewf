use std::io::{Read, Seek, SeekFrom};

#[test]
fn validate_szechuan_sauce() {
    let path = "../usnjrnl-forensic/test-data/20200918_0417_DESKTOP-SDN1RPT.E01";
    if !std::path::Path::new(path).exists() { return; }

    let mut reader = ewf::EwfReader::open(path).unwrap();

    // Basic geometry
    eprintln!("=== ewf crate geometry ===");
    eprintln!("Total size: {} bytes", reader.total_size());
    eprintln!("Chunk size: {} bytes", reader.chunk_size());
    eprintln!("Chunk count: {}", reader.chunk_count());

    // Read MBR (first 512 bytes)
    let mut mbr = [0u8; 512];
    reader.read_exact(&mut mbr).unwrap();
    eprintln!("MBR signature: 0x{:02X}{:02X}", mbr[510], mbr[511]);

    // Read GPT header at LBA 1
    reader.seek(SeekFrom::Start(512)).unwrap();
    let mut gpt = [0u8; 92];
    reader.read_exact(&mut gpt).unwrap();
    let gpt_sig = std::str::from_utf8(&gpt[0..8]).unwrap_or("???");
    eprintln!("GPT signature: {:?}", gpt_sig);

    // Offset 0 (MBR)
    reader.seek(SeekFrom::Start(0)).unwrap();
    let mut buf = [0u8; 32];
    reader.read_exact(&mut buf).unwrap();
    eprintln!("Bytes at offset 0: {:02X?}", &buf[..16]);

    // Read at 1MB boundary (tests chunk boundary crossing)
    reader.seek(SeekFrom::Start(1_048_576)).unwrap();
    reader.read_exact(&mut buf).unwrap();
    eprintln!("Bytes at offset 1MB: {:02X?}", &buf[..16]);

    // Read last 512 bytes of image
    let end_offset = reader.total_size() - 512;
    reader.seek(SeekFrom::Start(end_offset)).unwrap();
    let mut tail = [0u8; 512];
    let n = reader.read(&mut tail).unwrap();
    eprintln!("Read {} bytes at offset {} (last 512 bytes)", n, end_offset);
    eprintln!("Last bytes: {:02X?}", &tail[..16]);

    // Verify total size matches expectation from libewf
    assert_eq!(reader.total_size(), 16106127360, "Image size mismatch vs libewf");
}

#[test]
fn byte_level_comparison_vs_libewf() {
    let path = "../usnjrnl-forensic/test-data/20200918_0417_DESKTOP-SDN1RPT.E01";
    if !std::path::Path::new(path).exists() { return; }

    // Reference files extracted by pyewf (libewf Python bindings)
    let first_ref_path = "/tmp/ewf_first_4096.bin";
    let last_ref_path = "/tmp/ewf_last_4096.bin";
    if !std::path::Path::new(first_ref_path).exists() {
        eprintln!("Skipping byte comparison: reference files not found at /tmp/ewf_*.bin");
        return;
    }

    let first_ref = std::fs::read(first_ref_path).unwrap();
    let last_ref = std::fs::read(last_ref_path).unwrap();
    assert_eq!(first_ref.len(), 4096, "Reference first block should be 4096 bytes");
    assert_eq!(last_ref.len(), 4096, "Reference last block should be 4096 bytes");

    let mut reader = ewf::EwfReader::open(path).unwrap();

    // Compare first 4096 bytes
    reader.seek(SeekFrom::Start(0)).unwrap();
    let mut our_first = vec![0u8; 4096];
    reader.read_exact(&mut our_first).unwrap();

    let mut mismatches_first = 0;
    for i in 0..4096 {
        if our_first[i] != first_ref[i] {
            if mismatches_first < 10 {
                eprintln!("MISMATCH at byte {}: ours=0x{:02X}, libewf=0x{:02X}", i, our_first[i], first_ref[i]);
            }
            mismatches_first += 1;
        }
    }
    eprintln!("First 4096 bytes: {} mismatches out of 4096", mismatches_first);
    assert_eq!(mismatches_first, 0, "First 4096 bytes differ from libewf reference!");

    // Compare last 4096 bytes
    let end_offset = reader.total_size() - 4096;
    reader.seek(SeekFrom::Start(end_offset)).unwrap();
    let mut our_last = vec![0u8; 4096];
    reader.read_exact(&mut our_last).unwrap();

    let mut mismatches_last = 0;
    for i in 0..4096 {
        if our_last[i] != last_ref[i] {
            if mismatches_last < 10 {
                eprintln!("MISMATCH at byte {}: ours=0x{:02X}, libewf=0x{:02X}", end_offset as usize + i, our_last[i], last_ref[i]);
            }
            mismatches_last += 1;
        }
    }
    eprintln!("Last 4096 bytes: {} mismatches out of 4096", mismatches_last);
    assert_eq!(mismatches_last, 0, "Last 4096 bytes differ from libewf reference!");

    eprintln!("=== BYTE-LEVEL COMPARISON: PASSED ===");
    eprintln!("First 4096 bytes: IDENTICAL to libewf");
    eprintln!("Last 4096 bytes: IDENTICAL to libewf");
}
