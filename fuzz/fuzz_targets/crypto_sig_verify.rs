#![no_main]
//! Ed25519 and ECDSA P-256/P-384 verification (DER and fixed-width signatures) and SEC1 point
//! decoding against ring, on valid, mutated and arbitrary signatures and keys. The logic is
//! shared with the stable replay test `crates/only-crypto/tests/sig_diff.rs`.

#[path = "../../crates/only-crypto/tests/common/sigdiff.rs"]
mod sigdiff;

libfuzzer_sys::fuzz_target!(|data: &[u8]| sigdiff::check(data));
