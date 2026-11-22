#![no_main]
//! akio-sctp: arbitrary bytes as SCTP packets (raw and with the CRC-32C fixed up) into a fresh
//! association, one waiting for its COOKIE ECHO and established pairs with open data channels,
//! one on I-DATA / I-FORWARD-TSN (RFC 8260) and one on DATA / FORWARD TSN, never panic
//! (`akio_sctp::fuzzing::packet`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_sctp::fuzzing::packet(data));
