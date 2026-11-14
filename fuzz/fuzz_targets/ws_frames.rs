#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_ws::fuzzing::ws_frames(data));
