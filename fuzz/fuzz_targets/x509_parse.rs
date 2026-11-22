#![no_main]
//! akio-x509: certificate, PEM, SPKI and private-key parsing never panics; parsed certificates
//! round-trip (DER and PEM) and survive self-verification (`akio_x509::fuzzing::parse`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_x509::fuzzing::parse(data));
