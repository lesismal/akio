#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| flash_kcp::fuzzing::kcp_input(data));
