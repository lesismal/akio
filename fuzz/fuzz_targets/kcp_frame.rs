#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_kcp::fuzzing::kcp_frame(data));
