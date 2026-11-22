#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_socks::fuzzing::socks_client(data));
