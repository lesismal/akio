#![no_main]
//! akio-ice: arbitrary datagrams into full (controlling, controlled) and lite ICE agents of one
//! and of two components with remote credentials set, plus `Candidate::parse` on UTF-8 input,
//! never panic (`akio_ice::fuzzing::stun`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_ice::fuzzing::stun(data));
