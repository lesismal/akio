#![no_main]
//! only-quic: arbitrary datagrams through the packet header parser (long, short, Version
//! Negotiation, Retry, coalesced packets), header protection removal and Initial packet
//! decryption in both directions, then the frame parser (`only_quic::fuzzing::packet`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_quic::fuzzing::packet(data));
