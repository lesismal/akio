#![no_main]
//! only-quic: arbitrary bytes through the frame parser (every RFC 9000 frame and DATAGRAM) and
//! the transport parameter decoder; ACK frames and parameters re-encode to what they decoded
//! from (`only_quic::fuzzing::frames`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_quic::fuzzing::frames(data));
