#![no_main]
//! only-tls: record decryption under fixed keys of every suite never panics, and sealed
//! records open to the same bytes (`only_tls::fuzzing::record`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_tls::fuzzing::record(data));
