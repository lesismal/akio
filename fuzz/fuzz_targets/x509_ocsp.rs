#![no_main]
//! only-x509: OCSP response parsing and validation (RFC 6960) never panics
//! (`only_x509::fuzzing::ocsp`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_x509::fuzzing::ocsp(data));
