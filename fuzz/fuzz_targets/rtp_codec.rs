#![no_main]
//! only-rtp: arbitrary bytes as RTP payloads through every depacketizer and frame assembler
//! never panic, and as a media frame through every packetizer round-trip back to the
//! (normalized) frame (`only_rtp::codec::fuzz::rtp_codec`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_rtp::codec::fuzz::rtp_codec(data));
