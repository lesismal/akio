#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_media::fuzzing::rtmp::flv_demux(data));
