#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_turn::fuzzing::turn_dtls(data));
