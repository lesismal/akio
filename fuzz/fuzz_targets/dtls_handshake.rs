#![no_main]
//! only-dtls: arbitrary datagrams (2-byte length prefixes) fed to client and server state
//! machines mid-handshake (with and without cookies, interleaved with timer expiries) and to
//! both ends of a completed handshake never panic (`only_dtls::fuzzing::handshake`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_dtls::fuzzing::handshake(data));
