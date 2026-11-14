#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| flash_media::fuzzing::rtmp::flv_demux(data));
