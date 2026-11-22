#![no_main]
//! akio-tls: record decryption under fixed keys of every suite never panics, and sealed
//! records open to the same bytes (`akio_tls::fuzzing::record`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_tls::fuzzing::record(data));
