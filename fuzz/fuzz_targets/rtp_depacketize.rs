#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_media::fuzzing::rtsp::rtp_depacketize(data));
