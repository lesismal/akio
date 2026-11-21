#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_media::fuzzing::hls::h265_sample_encryption(data));
