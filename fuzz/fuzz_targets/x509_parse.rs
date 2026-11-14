#![no_main]
//! only-x509: certificate, PEM, SPKI and private-key parsing never panics; parsed certificates
//! round-trip (DER and PEM) and survive self-verification (`only_x509::fuzzing::parse`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_x509::fuzzing::parse(data));
