#![no_main]
//! akio-tls: a macOS trust-settings export (`security trust-settings-export`, an XML property
//! list) read into verdicts never panics and parses the same way twice
//! (`akio_tls::fuzzing::trust_plist`, ADR-059).

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_tls::fuzzing::trust_plist(data));
