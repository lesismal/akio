#![no_main]
//! only-srtp: MKIs and re-keying, RFC 6904 header extension encryption, cryptex (RFC 9335) and
//! key derivation rates, for every profile picked by the first byte: arbitrary bytes through
//! `unprotect_rtp` / `unprotect_rtcp` never panic, and inputs that parse as RTP / RTCP protect
//! and unprotect back to themselves (`only_srtp::fuzzing::srtp_features`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_srtp::fuzzing::srtp_features(data));
