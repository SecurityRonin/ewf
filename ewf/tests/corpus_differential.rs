/// Byte-level differential tests: EwfReader bytes must match `ewfexport -f raw -u` output.
///
/// These tests skip automatically if libewf's `ewfexport` is not installed,
/// so they run in CI only on machines where libewf is available.
/// They verify correctness against an independent authoritative reference rather
/// than against the library's own MD5 hashes (which share the same blind spots).
use ewf::EwfReader;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const EWFEXPORT: &str = "/usr/local/bin/ewfexport";
const DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");

fn ewf_matches_ewfexport(e01_name: &str) {
    if !Path::new(EWFEXPORT).exists() {
        return;
    }
    let e01 = format!("{DATA_DIR}/{e01_name}");
    if !Path::new(&e01).exists() {
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let raw_stem = tmp.path().join("reference");
    let raw_path = tmp.path().join("reference.raw");

    let ok = std::process::Command::new(EWFEXPORT)
        .args([
            "-f", "raw",
            "-u",
            "-t", raw_stem.to_str().unwrap(),
            &e01,
        ])
        .status()
        .expect("spawn ewfexport")
        .success();
    assert!(ok, "ewfexport failed for {e01_name}");
    assert!(raw_path.exists(), "ewfexport did not produce {}", raw_path.display());

    let ref_data = std::fs::read(&raw_path).expect("read reference raw");
    let mut reader = EwfReader::open(&e01).expect("open EwfReader");
    let ewf_size = reader.total_size() as usize;

    assert_eq!(
        ewf_size,
        ref_data.len(),
        "EwfReader::total_size() must match ewfexport raw size for {e01_name}"
    );

    // Sample every 1 MiB + near-end 512 bytes.
    let step = 1024 * 1024usize;
    let mut offset = 0usize;
    while offset < ewf_size {
        let len = 512.min(ewf_size - offset);
        let mut buf = vec![0u8; len];
        reader.seek(SeekFrom::Start(offset as u64)).expect("seek");
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(
            buf,
            ref_data[offset..offset + len],
            "byte mismatch at offset {offset:#x} in {e01_name}"
        );
        offset += step;
    }

    if ewf_size >= 512 {
        let end = ewf_size - 512;
        let mut buf = vec![0u8; 512];
        reader.seek(SeekFrom::Start(end as u64)).expect("seek near-end");
        reader.read_exact(&mut buf).expect("read near-end");
        assert_eq!(
            buf,
            ref_data[end..end + 512],
            "byte mismatch near end of {e01_name}"
        );
    }
}

#[test]
fn corpus_exfat1_matches_ewfexport_raw() {
    ewf_matches_ewfexport("exfat1.E01");
}

#[test]
fn corpus_imageformat_mmls_1_matches_ewfexport_raw() {
    ewf_matches_ewfexport("imageformat_mmls_1.E01");
}

#[test]
fn corpus_nps_2010_emails_matches_ewfexport_raw() {
    ewf_matches_ewfexport("nps-2010-emails.E01");
}
