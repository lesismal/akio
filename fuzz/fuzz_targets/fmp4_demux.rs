#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_media::fuzzing::fmp4::fmp4_demux(data));
