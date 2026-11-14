#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_arpc::fuzzing::arpc_decoder(data));
