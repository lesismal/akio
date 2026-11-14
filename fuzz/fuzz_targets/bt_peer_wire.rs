#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_bittorrent::fuzzing::bt_peer_wire(data));
