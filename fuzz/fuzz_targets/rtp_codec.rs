#![no_main]
//! akio-rtp: arbitrary bytes as RTP payloads through every depacketizer and frame assembler
//! never panic, and as a media frame through every packetizer round-trip back to the
//! (normalized) frame (`akio_rtp::codec::fuzz::rtp_codec`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_rtp::codec::fuzz::rtp_codec(data));
