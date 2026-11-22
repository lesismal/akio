#![no_main]
//! Ed448 sign/verify round trips and strict decoding, X448 agreement, DSA key checks and
//! verification, SPKI / PKCS#8 parsing of the new key types, and SHAKE256 streaming. The logic
//! is shared with the stable replay test `crates/akio-crypto/tests/ed448_dsa.rs`.

#[path = "../../crates/akio-crypto/tests/common/ed448_dsa.rs"]
mod ed448_dsa;

libfuzzer_sys::fuzz_target!(|data: &[u8]| ed448_dsa::check(data));
