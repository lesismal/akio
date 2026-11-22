#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_webrtc::fuzzing::webrtc_sdp(data));
