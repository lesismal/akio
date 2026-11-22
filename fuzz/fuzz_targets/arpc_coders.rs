#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_arpc::fuzzing::arpc_coders(data));
