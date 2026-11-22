#![no_main]
//! akio-dtls: arbitrary DTLS 1.3 post-handshake messages (NewConnectionId,
//! RequestConnectionId, post-handshake authentication, KeyUpdate, NewSessionTicket) processed
//! by connected ends while their own post-handshake flights run, and arbitrary early data and
//! datagrams at a server accepting 0-RTT, never panic (`akio_dtls::fuzzing::post_handshake`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_dtls::fuzzing::post_handshake(data));
