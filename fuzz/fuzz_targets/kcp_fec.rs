#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_kcp::fuzzing::kcp_fec(data));
