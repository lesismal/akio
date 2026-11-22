//! Key derivation: HKDF (RFC 5869) and PBKDF2 with HMAC (RFC 8018, section 5.2).
//!
//! ```
//! use akio_crypto::hash::{Sha1, Sha256};
//! use akio_crypto::kdf;
//!
//! let mut key = [0u8; 32];
//! kdf::pbkdf2_hmac::<Sha1>(b"passphrase", b"kcp-go", 4096, &mut key);
//!
//! let mut okm = [0u8; 42];
//! kdf::hkdf::<Sha256>(b"salt", b"input key material", b"info", &mut okm).unwrap();
//! ```

use crate::Error;
use crate::hash::Hash;
use crate::mac::Hmac;

/// HKDF-Extract: the pseudorandom key `HMAC(salt, ikm)`. An empty `salt` stands for
/// `OUTPUT_LEN` zero bytes, which gives the same result.
#[must_use]
pub fn hkdf_extract<H: Hash>(salt: &[u8], ikm: &[u8]) -> H::Output {
    Hmac::<H>::mac(salt, ikm)
}

/// HKDF-Expand: fills `okm` from the pseudorandom key `prk` and `info`.
///
/// Fails with [`Error::InvalidLength`] if `okm` is longer than `255 * OUTPUT_LEN` bytes or
/// `prk` is shorter than `OUTPUT_LEN` bytes.
pub fn hkdf_expand<H: Hash>(prk: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), Error> {
    if okm.len() > 255 * H::OUTPUT_LEN || prk.len() < H::OUTPUT_LEN {
        return Err(Error::InvalidLength);
    }
    let base = Hmac::<H>::new(prk);
    let mut prev: Option<H::Output> = None;
    for (i, chunk) in okm.chunks_mut(H::OUTPUT_LEN).enumerate() {
        let mut m = base.clone();
        if let Some(p) = &prev {
            m.update(p.as_ref());
        }
        m.update(info);
        // At most 255 chunks (checked above).
        m.update(&[(i + 1) as u8]);
        let t = m.finalize();
        chunk.copy_from_slice(&t.as_ref()[..chunk.len()]);
        prev = Some(t);
    }
    Ok(())
}

/// HKDF extract-then-expand in one call.
///
/// Fails with [`Error::InvalidLength`] if `okm` is longer than `255 * OUTPUT_LEN` bytes.
pub fn hkdf<H: Hash>(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), Error> {
    let prk = hkdf_extract::<H>(salt, ikm);
    hkdf_expand::<H>(prk.as_ref(), info, okm)
}

/// PBKDF2 with HMAC-`H`: fills `out` from `password`, `salt` and `rounds` iterations (`0` is
/// treated as `1`).
pub fn pbkdf2_hmac<H: Hash>(password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) {
    let prf = Hmac::<H>::new(password);
    for (i, chunk) in out.chunks_mut(H::OUTPUT_LEN).enumerate() {
        let mut m = prf.clone();
        m.update(salt);
        m.update(&(i as u32 + 1).to_be_bytes());
        let mut u = m.finalize();
        let mut t = u;
        for _ in 1..rounds {
            u = prf.clone().chain(u.as_ref()).finalize();
            for (t, u) in t.as_mut().iter_mut().zip(u.as_ref()) {
                *t ^= u;
            }
        }
        chunk.copy_from_slice(&t.as_ref()[..chunk.len()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Sha1, Sha256, hex};

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 5869 appendix A, test cases 1-3 (SHA-256) and 4, 7 (SHA-1).
    #[test]
    fn rfc5869() {
        let cases: [(bool, &str, &str, &str, &str, &str); 5] = [
            (
                true,
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "000102030405060708090a0b0c",
                "f0f1f2f3f4f5f6f7f8f9",
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            ),
            (
                true,
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
            ),
            (
                true,
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "",
                "",
                "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
            ),
            (
                false,
                "0b0b0b0b0b0b0b0b0b0b0b",
                "000102030405060708090a0b0c",
                "f0f1f2f3f4f5f6f7f8f9",
                "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243",
                "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896",
            ),
            (
                false,
                "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
                "",
                "",
                "2adccada18779e7c2077ad2eb19d3f3e731385dd",
                "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48",
            ),
        ];
        for (sha256, ikm, salt, info, prk, okm) in cases {
            let (ikm, salt, info) = (unhex(ikm), unhex(salt), unhex(info));
            let mut out = vec![0u8; okm.len() / 2];
            if sha256 {
                assert_eq!(hex(&hkdf_extract::<Sha256>(&salt, &ikm)), prk);
                hkdf::<Sha256>(&salt, &ikm, &info, &mut out).unwrap();
            } else {
                assert_eq!(hex(&hkdf_extract::<Sha1>(&salt, &ikm)), prk);
                hkdf::<Sha1>(&salt, &ikm, &info, &mut out).unwrap();
            }
            assert_eq!(hex(&out), okm);
        }
        let mut too_long = vec![0u8; 255 * 32 + 1];
        assert_eq!(
            hkdf::<Sha256>(b"", b"k", b"", &mut too_long),
            Err(Error::InvalidLength)
        );
        assert!(hkdf::<Sha256>(b"", b"k", b"", &mut too_long[..255 * 32]).is_ok());
    }

    /// RFC 6070 (PBKDF2-HMAC-SHA1) and the SHA-256 vectors widely used for it (RFC 7914
    /// section 11).
    #[test]
    fn rfc6070() {
        let cases: [(&[u8], &[u8], u32, &str); 5] = [
            (
                b"password",
                b"salt",
                1,
                "0c60c80f961f0e71f3a9b524af6012062fe037a6",
            ),
            (
                b"password",
                b"salt",
                2,
                "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
            ),
            (
                b"password",
                b"salt",
                4096,
                "4b007901b765489abead49d926f721d065a429c1",
            ),
            (
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
            ),
            (
                b"pass\0word",
                b"sa\0lt",
                4096,
                "56fa6aa75548099dcc37d7f03425e0c3",
            ),
        ];
        for (pw, salt, rounds, want) in cases {
            let mut out = vec![0u8; want.len() / 2];
            pbkdf2_hmac::<Sha1>(pw, salt, rounds, &mut out);
            assert_eq!(hex(&out), want);
        }
        let mut out = [0u8; 64];
        pbkdf2_hmac::<Sha256>(b"passwd", b"salt", 1, &mut out);
        assert_eq!(
            hex(&out),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        );
    }
}
