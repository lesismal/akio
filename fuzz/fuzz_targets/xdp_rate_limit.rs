#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_ebpf::fuzzing::xdp_rate_limit(data));
