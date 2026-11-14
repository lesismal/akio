#![no_main]
//! only-ice: arbitrary datagrams into full (controlling, controlled) and lite ICE agents with
//! remote credentials set, plus `Candidate::parse` on UTF-8 input, never panic
//! (`only_ice::fuzzing::stun`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_ice::fuzzing::stun(data));
