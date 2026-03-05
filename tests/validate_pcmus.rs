use std::io::{Read, Seek, SeekFrom};

#[test]
fn validate_pcmus() {
    let path = "../usnjrnl-forensic/test-data/PC-MUS-001.E01";
    if !std::path::Path::new(path).exists() { return; }

    // This image may be incomplete (still downloading or truncated acquisition).
    // Our reader should handle it gracefully.
    let mut reader = ewf::EwfReader::open(path).unwrap();

    eprintln!("=== ewf crate geometry ===");
    eprintln!("Total size: {} bytes", reader.total_size());
    eprintln!("Chunk size: {} bytes", reader.chunk_size());
    eprintln!("Chunk count: {}", reader.chunk_count());

    // Read MBR
    let mut mbr = [0u8; 512];
    reader.read_exact(&mut mbr).unwrap();
    eprintln!("MBR signature: 0x{:02X}{:02X}", mbr[510], mbr[511]);

    // Sample reads at safe offsets
    for offset in [0u64, 512, 1_048_576, 100_000_000] {
        reader.seek(SeekFrom::Start(offset)).unwrap();
        let mut buf = [0u8; 16];
        reader.read_exact(&mut buf).unwrap();
        eprintln!("Bytes at offset {}: {:02X?}", offset, &buf);
    }
}

/// Compare first 4096 bytes against libewf (pyewf) reference
#[test]
fn pcmus_byte_comparison_vs_libewf() {
    let path = "../usnjrnl-forensic/test-data/PC-MUS-001.E01";
    if !std::path::Path::new(path).exists() { return; }

    let ref_path = "/tmp/pcmus_first_4096.bin";
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
    eprintln!("=== PC-MUS byte comparison vs libewf: PASSED ===");
}
