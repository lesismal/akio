#![no_main]
//! akio-x509: PKCS#10 certificate signing request parsing (RFC 2986) never panics; parsed
//! requests round-trip (DER and PEM) and their signature check runs
//! (`akio_x509::fuzzing::csr`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_x509::fuzzing::csr(data));
