#![no_main]
//! akio-dtls: arbitrary datagrams (2-byte length prefixes) fed to client and server state
//! machines mid-handshake (with and without cookies, interleaved with timer expiries) and to
//! both ends of a completed handshake never panic (`akio_dtls::fuzzing::handshake`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_dtls::fuzzing::handshake(data));
