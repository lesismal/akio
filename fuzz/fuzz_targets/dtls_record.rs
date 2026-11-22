#![no_main]
//! akio-dtls: arbitrary datagrams through the record splitter, the handshake fragment parser
//! and every handshake message parser never panic; parsed hellos and ServerKeyExchanges
//! re-encode identically (`akio_dtls::fuzzing::record`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_dtls::fuzzing::record(data));
