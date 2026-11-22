#![no_main]
//! akio-quic: arbitrary datagrams through the packet header parser (long, short, Version
//! Negotiation, Retry, coalesced packets), header protection removal and Initial packet
//! decryption in both directions, then the frame parser (`akio_quic::fuzzing::packet`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_quic::fuzzing::packet(data));
