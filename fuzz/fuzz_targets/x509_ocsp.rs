#![no_main]
//! akio-x509: OCSP response parsing and validation (RFC 6960) never panics
//! (`akio_x509::fuzzing::ocsp`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_x509::fuzzing::ocsp(data));
