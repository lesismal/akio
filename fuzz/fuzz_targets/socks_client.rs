#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_socks::fuzzing::socks_client(data));
