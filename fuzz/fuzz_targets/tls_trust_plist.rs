#![no_main]
//! only-tls: a macOS trust-settings export (`security trust-settings-export`, an XML property
//! list) read into verdicts never panics and parses the same way twice
//! (`only_tls::fuzzing::trust_plist`, ADR-059).

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_tls::fuzzing::trust_plist(data));
