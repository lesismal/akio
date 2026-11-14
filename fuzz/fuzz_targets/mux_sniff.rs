#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_mux::fuzzing::mux_sniff(data));
