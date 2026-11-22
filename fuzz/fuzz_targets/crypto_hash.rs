#![no_main]
//! akio-crypto's hashes, HMAC and CRC-32 against the crates they replaced (CRC-32C against its
//! bitwise definition), with the input split at an arbitrary point for the streaming interface.

use akio_crypto::hash::{Md5, Sha1, Sha224, Sha256, Sha384, Sha512};
use akio_crypto::mac::Hmac;
use sha2::Digest as _;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let split = data.first().map_or(0, |&b| usize::from(b)).min(data.len());
    let (a, b) = data.split_at(split);

    macro_rules! check {
        ($ours:ty, $theirs:ty) => {{
            let mut h = <$ours>::new();
            h.update(a);
            h.update(b);
            assert_eq!(h.finalize()[..], <$theirs>::digest(data)[..]);
        }};
    }
    check!(Sha1, sha1::Sha1);
    check!(Sha224, sha2::Sha224);
    check!(Sha256, sha2::Sha256);
    check!(Sha384, sha2::Sha384);
    check!(Sha512, sha2::Sha512);
    check!(Md5, md5::Md5);

    let mut c = akio_crypto::crc::Crc32::new();
    c.update(a);
    c.update(b);
    assert_eq!(c.finalize(), crc32fast::hash(data));
    // CRC-32C (instruction paths when present) against the bitwise definition.
    let mut r = !0u32;
    for &x in data {
        r ^= u32::from(x);
        for _ in 0..8 {
            r = if r & 1 != 0 { (r >> 1) ^ 0x82f6_3b78 } else { r >> 1 };
        }
    }
    let mut c = akio_crypto::crc::Crc32c::new();
    c.update(a);
    c.update(b);
    assert_eq!(c.finalize(), !r);

    // HMAC: the first part is the key (any length, including longer than a block).
    use hmac::Mac as _;
    let mut m = <hmac::Hmac<sha1::Sha1> as hmac::Mac>::new_from_slice(a).unwrap();
    m.update(b);
    assert_eq!(Hmac::<Sha1>::mac(a, b)[..], m.finalize().into_bytes()[..]);
    let mut m = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(a).unwrap();
    m.update(b);
    assert_eq!(Hmac::<Sha256>::mac(a, b)[..], m.finalize().into_bytes()[..]);
});
