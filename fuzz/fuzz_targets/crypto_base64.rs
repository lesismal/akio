#![no_main]
//! akio-crypto's base64 against the `base64` crate's `general_purpose` engines: the same
//! encodings, and the same verdict and output when decoding arbitrary bytes.

use base64::Engine as _;
use base64::engine::general_purpose as gp;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&sel, input)) = data.split_first() else {
        return;
    };
    let (ours, theirs) = match sel % 4 {
        0 => (akio_crypto::base64::STANDARD, gp::STANDARD),
        1 => (akio_crypto::base64::STANDARD_NO_PAD, gp::STANDARD_NO_PAD),
        2 => (akio_crypto::base64::URL_SAFE, gp::URL_SAFE),
        _ => (akio_crypto::base64::URL_SAFE_NO_PAD, gp::URL_SAFE_NO_PAD),
    };
    assert_eq!(ours.encode(input), theirs.encode(input));
    assert_eq!(ours.decode(input).ok(), theirs.decode(input).ok());
});
