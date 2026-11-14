#![no_main]
//! only-srtp: arbitrary bytes through `unprotect_rtp` / `unprotect_rtcp` of every profile never
//! panic, and inputs that parse as RTP / RTCP protect and unprotect back to themselves
//! (`only_srtp::fuzzing::srtp_unprotect`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_srtp::fuzzing::srtp_unprotect(data));
