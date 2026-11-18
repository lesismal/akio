#![no_main]
//! only-x509: CRL parsing (RFC 5280 section 5) never panics; parsed CRLs round-trip (DER and
//! PEM) and status lookups run (`only_x509::fuzzing::crl`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_x509::fuzzing::crl(data));
