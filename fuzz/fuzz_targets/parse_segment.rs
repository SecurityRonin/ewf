#![no_main]

use ewf::EwfReader;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let path = dir.path().join("fuzz.E01");
    if std::fs::write(&path, data).is_err() {
        return;
    }
    let _ = EwfReader::open(&path);
});
