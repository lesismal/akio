#![no_main]
//! only-dtls: arbitrary datagrams through the record splitter, the handshake fragment parser
//! and every handshake message parser never panic; parsed hellos and ServerKeyExchanges
//! re-encode identically (`only_dtls::fuzzing::record`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_dtls::fuzzing::record(data));
