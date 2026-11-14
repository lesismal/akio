#![no_main]
//! only-tls: arbitrary client bytes fed to a server connection (TLS 1.3 / 1.2, client
//! authentication, forced HelloRetryRequest) never panic (`only_tls::fuzzing::server`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_tls::fuzzing::server(data));
