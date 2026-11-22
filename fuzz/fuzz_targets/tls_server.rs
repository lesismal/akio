#![no_main]
//! akio-tls: arbitrary client bytes fed to a server connection (TLS 1.3 / 1.2, client
//! authentication, forced HelloRetryRequest) never panic (`akio_tls::fuzzing::server`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_tls::fuzzing::server(data));
