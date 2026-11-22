#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_ws::fuzzing::ws_frames(data));
