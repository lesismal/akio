#![no_main]
//! akio-srtp: arbitrary bytes through `unprotect_rtp` / `unprotect_rtcp` of every profile never
//! panic, and inputs that parse as RTP / RTCP protect and unprotect back to themselves
//! (`akio_srtp::fuzzing::srtp_unprotect`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_srtp::fuzzing::srtp_unprotect(data));
