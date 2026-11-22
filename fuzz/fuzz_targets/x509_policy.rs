#![no_main]
//! akio-x509: certificate policy processing (RFC 5280 §6.1, the policy graph of RFC 9618) over
//! arbitrary paths never panics and stays polynomial (`akio_x509::fuzzing::policy`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_x509::fuzzing::policy(data));
