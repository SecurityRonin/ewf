#![no_main]

use ewf::EwfFileHeader;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = EwfFileHeader::parse(data);
});
