#![no_main]
//! only-sctp: arbitrary bytes as SCTP packets (raw and with the CRC-32C fixed up) into a fresh
//! association, one waiting for its COOKIE ECHO and an established pair with open data
//! channels never panic (`only_sctp::fuzzing::packet`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_sctp::fuzzing::packet(data));
