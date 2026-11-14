#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| flash_socks::fuzzing::socks_request(data));
