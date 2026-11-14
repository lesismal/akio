#![no_main]
//! only-tls: arbitrary server bytes fed to a client connection (dual-version and TLS 1.2-only)
//! never panic (`only_tls::fuzzing::client`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_tls::fuzzing::client(data));
