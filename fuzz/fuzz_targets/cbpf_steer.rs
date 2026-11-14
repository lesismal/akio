#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| flash_ebpf::fuzzing::cbpf_steer(data));
