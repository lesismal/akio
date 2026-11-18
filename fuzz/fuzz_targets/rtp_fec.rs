#![no_main]
//! only-rtp: arbitrary bytes as ULPFEC / FlexFEC headers, RED payloads and a stream of media
//! and FEC packets for the decoder never panic; headers and RED re-write consistently and an
//! encoder -> lossy decoder round trip rebuilds packets byte for byte
//! (`only_rtp::fuzzing::rtp_fec`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_rtp::fuzzing::rtp_fec(data));
