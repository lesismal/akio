#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_mux::fuzzing::mux_sniff(data));
