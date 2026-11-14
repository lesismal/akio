//! HMAC (RFC 2104, FIPS 198-1) over any [`Hash`].
//!
//! ```
//! use only_crypto::hash::Sha1;
//! use only_crypto::mac::Hmac;
//!
//! let mut m = Hmac::<Sha1>::new(b"key");
//! m.update(b"The quick brown fox jumps over the lazy dog");
//! let tag = m.finalize();
//! assert!(Hmac::<Sha1>::new(b"key").chain(b"The quick brown fox jumps over the lazy dog").verify(&tag));
//! ```

use crate::hash::Hash;

/// The largest block size of the hashes in this crate (SHA-384 / SHA-512).
const MAX_BLOCK: usize = 128;

/// An HMAC computation keyed with any key length (longer keys are hashed first, as the
/// standard says). Cloning a keyed `Hmac` reuses the key schedule, which PBKDF2 relies on.
#[derive(Clone)]
pub struct Hmac<H: Hash> {
    inner: H,
    outer: H,
}

impl<H: Hash> std::fmt::Debug for Hmac<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hmac").finish_non_exhaustive()
    }
}

impl<H: Hash> Hmac<H> {
    /// Starts an HMAC with `key`.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        assert!(
            H::BLOCK_LEN <= MAX_BLOCK,
            "hash block size above {MAX_BLOCK}"
        );
        let mut k = [0u8; MAX_BLOCK];
        if key.len() > H::BLOCK_LEN {
            let d = H::digest(key);
            k[..H::OUTPUT_LEN].copy_from_slice(d.as_ref());
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let k = &mut k[..H::BLOCK_LEN];
        let mut inner = H::default();
        let mut outer = H::default();
        for b in k.iter_mut() {
            *b ^= 0x36;
        }
        inner.update(k);
        for b in k.iter_mut() {
            *b ^= 0x36 ^ 0x5c;
        }
        outer.update(k);
        Hmac { inner, outer }
    }

    /// Absorbs `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Absorbs `data`, builder style.
    #[must_use]
    pub fn chain(mut self, data: &[u8]) -> Self {
        self.update(data);
        self
    }

    /// Finishes and returns the tag.
    #[must_use]
    pub fn finalize(self) -> H::Output {
        let Hmac { inner, mut outer } = self;
        outer.update(inner.finalize().as_ref());
        outer.finalize()
    }

    /// Finishes and compares the tag with `tag` in constant time. A truncated `tag` (at least
    /// half the digest and 10 bytes, RFC 2104 section 5) is compared against the tag's prefix;
    /// anything shorter never verifies.
    #[must_use]
    pub fn verify(self, tag: &[u8]) -> bool {
        let full = self.finalize();
        let full = full.as_ref();
        if tag.len() > full.len() || tag.len() < (full.len() / 2).max(10) {
            return false;
        }
        crate::ct_eq(&full[..tag.len()], tag)
    }

    /// The HMAC of `data` under `key` in one call.
    #[must_use]
    pub fn mac(key: &[u8], data: &[u8]) -> H::Output {
        Self::new(key).chain(data).finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Md5, Sha1, Sha224, Sha256, Sha384, Sha512, hex};

    /// RFC 4231 test cases 1-4, 6, 7 (5 truncates the output and is checked separately).
    #[test]
    fn rfc4231() {
        let long_key = [0xaau8; 131];
        let cases: [(&[u8], &[u8], [&str; 4]); 6] = [
                    (
                        &[0x0b; 20],
                        b"Hi There",
                        [
                            "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
                            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
                            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
                        ],
                    ),
                    (
                        b"Jefe",
                        b"what do ya want for nothing?",
                        [
                            "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
                            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
                            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
                        ],
                    ),
                    (
                        &[0xaa; 20],
                        &[0xdd; 50],
                        [
                            "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea",
                            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
                            "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
                            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
                        ],
                    ),
                    (
                        &[
                            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                            21, 22, 23, 24, 25,
                        ],
                        &[0xcd; 50],
                        [
                            "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a",
                            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
                            "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
                            "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
                        ],
                    ),
                    (
                        &long_key,
                        b"Test Using Larger Than Block-Size Key - Hash Key First",
                        [
                            "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e",
                            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
                            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
                            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
                        ],
                    ),
                    (
                        &long_key,
                        b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
                        [
                            "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1",
                            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
                            "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
                            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
                        ],
                    ),
                ];
        for (key, data, want) in cases {
            assert_eq!(hex(&Hmac::<Sha224>::mac(key, data)), want[0]);
            assert_eq!(hex(&Hmac::<Sha256>::mac(key, data)), want[1]);
            assert_eq!(hex(&Hmac::<Sha384>::mac(key, data)), want[2]);
            assert_eq!(hex(&Hmac::<Sha512>::mac(key, data)), want[3]);
        }
        // Test case 5: truncated to 128 bits.
        let t = Hmac::<Sha256>::mac(&[0x0c; 20], b"Test With Truncation");
        assert_eq!(hex(&t[..16]), "a3b6167473100ee06e0c796c2955552b");
        assert!(
            Hmac::<Sha256>::new(&[0x0c; 20])
                .chain(b"Test With Truncation")
                .verify(&t[..16])
        );
    }

    /// RFC 2202 (HMAC-MD5 and HMAC-SHA1).
    #[test]
    fn rfc2202() {
        assert_eq!(
            hex(&Hmac::<Sha1>::mac(&[0x0b; 20], b"Hi There")),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        assert_eq!(
            hex(&Hmac::<Sha1>::mac(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
        assert_eq!(
            hex(&Hmac::<Sha1>::mac(
                &[0xaa; 80],
                b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
            )),
            "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
        );
        assert_eq!(
            hex(&Hmac::<Md5>::mac(&[0x0b; 16], b"Hi There")),
            "9294727a3638bb1c13f48ef8158bfc9d"
        );
        assert_eq!(
            hex(&Hmac::<Md5>::mac(b"Jefe", b"what do ya want for nothing?")),
            "750c783e6ab0b503eaa86e310a5db738"
        );
    }

    #[test]
    fn verify_rejects() {
        let t = Hmac::<Sha1>::mac(b"k", b"m");
        assert!(Hmac::<Sha1>::new(b"k").chain(b"m").verify(&t));
        assert!(!Hmac::<Sha1>::new(b"k").chain(b"n").verify(&t));
        assert!(!Hmac::<Sha1>::new(b"k").chain(b"m").verify(&t[..4]));
        let mut bad = t;
        bad[19] ^= 1;
        assert!(!Hmac::<Sha1>::new(b"k").chain(b"m").verify(&bad));
    }
}
