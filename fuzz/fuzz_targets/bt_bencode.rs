#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_bittorrent::fuzzing::bt_bencode(data));
