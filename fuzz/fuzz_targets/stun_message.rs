#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| flash_turn::fuzzing::stun_message(data));
