//! Cipher suites, their hash and AEAD, HKDF-Expand-Label (RFC 8446 section 7.1) and the
//! TLS 1.2 PRF (RFC 5246 section 5).

use only_crypto::chacha::ChaCha20Poly1305;
use only_crypto::gcm::AesGcm;
use only_crypto::hash::{Sha256, Sha384};
use only_crypto::kdf;
use only_crypto::mac::Hmac;

/// The hash of a cipher suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
}

impl HashAlg {
    /// Output length in bytes.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
        }
    }

    /// The digest of `data`.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => Sha256::digest(data).to_vec(),
            HashAlg::Sha384 => Sha384::digest(data).to_vec(),
        }
    }

    /// HMAC of `data` under `key`.
    pub fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => Hmac::<Sha256>::mac(key, data).to_vec(),
            HashAlg::Sha384 => Hmac::<Sha384>::mac(key, data).to_vec(),
        }
    }

    /// HKDF-Extract.
    pub fn extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => kdf::hkdf_extract::<Sha256>(salt, ikm).to_vec(),
            HashAlg::Sha384 => kdf::hkdf_extract::<Sha384>(salt, ikm).to_vec(),
        }
    }

    /// HKDF-Expand to `len` bytes (at most 255 hash lengths).
    pub fn expand(self, prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let r = match self {
            HashAlg::Sha256 => kdf::hkdf_expand::<Sha256>(prk, info, &mut out),
            HashAlg::Sha384 => kdf::hkdf_expand::<Sha384>(prk, info, &mut out),
        };
        debug_assert!(r.is_ok(), "HKDF output length is bounded by the callers");
        out
    }

    /// HKDF-Expand-Label(secret, label, context, len) with the `"tls13 "` prefix.
    pub fn expand_label(self, secret: &[u8], label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
        let mut info = Vec::with_capacity(4 + 6 + label.len() + context.len());
        info.extend_from_slice(&(len as u16).to_be_bytes());
        info.push((6 + label.len()) as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label);
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        self.expand(secret, &info, len)
    }

    /// Derive-Secret(secret, label, transcript hash).
    pub fn derive_secret(self, secret: &[u8], label: &[u8], hash: &[u8]) -> Vec<u8> {
        self.expand_label(secret, label, hash, self.len())
    }

    /// The TLS 1.2 PRF: P_hash(secret, label + seed) to `len` bytes.
    pub fn prf(self, secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
        let mut ls = Vec::with_capacity(label.len() + seed.len());
        ls.extend_from_slice(label);
        ls.extend_from_slice(seed);
        let mut out = Vec::with_capacity(len + self.len());
        let mut a = self.hmac(secret, &ls);
        while out.len() < len {
            let mut input = a.clone();
            input.extend_from_slice(&ls);
            out.extend_from_slice(&self.hmac(secret, &input));
            a = self.hmac(secret, &a);
        }
        out.truncate(len);
        out
    }

    pub(crate) fn context(self) -> HashCtx {
        match self {
            HashAlg::Sha256 => HashCtx::Sha256(Sha256::new()),
            HashAlg::Sha384 => HashCtx::Sha384(Sha384::new()),
        }
    }
}

/// A running hash.
#[derive(Clone, Debug)]
pub(crate) enum HashCtx {
    Sha256(Sha256),
    Sha384(Sha384),
}

impl HashCtx {
    pub(crate) fn update(&mut self, data: &[u8]) {
        match self {
            HashCtx::Sha256(h) => h.update(data),
            HashCtx::Sha384(h) => h.update(data),
        }
    }

    /// The digest so far (the context keeps running).
    pub(crate) fn current(&self) -> Vec<u8> {
        match self {
            HashCtx::Sha256(h) => h.clone().finalize().to_vec(),
            HashCtx::Sha384(h) => h.clone().finalize().to_vec(),
        }
    }
}

/// The AEAD of a cipher suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadAlg {
    /// AES-128-GCM.
    Aes128Gcm,
    /// AES-256-GCM.
    Aes256Gcm,
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305,
}

impl AeadAlg {
    /// Key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            AeadAlg::Aes128Gcm => 16,
            AeadAlg::Aes256Gcm | AeadAlg::ChaCha20Poly1305 => 32,
        }
    }

    /// The implicit (fixed) IV length of TLS 1.2: 4 for GCM, 12 for ChaCha20-Poly1305.
    pub(crate) fn fixed_iv_len_12(self) -> usize {
        match self {
            AeadAlg::Aes128Gcm | AeadAlg::Aes256Gcm => 4,
            AeadAlg::ChaCha20Poly1305 => 12,
        }
    }

    pub(crate) fn key(self, key: &[u8]) -> Aead {
        match self {
            AeadAlg::Aes128Gcm | AeadAlg::Aes256Gcm => {
                Aead::Gcm(Box::new(AesGcm::new(key).unwrap_or_else(|_| {
                    unreachable!("key lengths come from key_len")
                })))
            }
            AeadAlg::ChaCha20Poly1305 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                Aead::ChaCha(Box::new(ChaCha20Poly1305::new(&k)))
            }
        }
    }
}

/// An AEAD key.
#[derive(Clone)]
pub(crate) enum Aead {
    Gcm(Box<AesGcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

pub(crate) const TAG_LEN: usize = 16;

impl Aead {
    /// Encrypts `buf` in place, returning the tag (the record layer uses
    /// [`seal_append`](Self::seal_append)).
    #[cfg(test)]
    pub(crate) fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        match self {
            Aead::Gcm(k) => k.encrypt_in_place_detached(nonce, aad, buf),
            Aead::ChaCha(k) => k.encrypt_in_place_detached(nonce, aad, buf),
        }
    }

    /// Appends the ciphertext of `src` followed by `trailer` to `out`, returning the tag: one
    /// pass over the data straight into `out`'s spare capacity (no copy of the plaintext and no
    /// zero-fill of the space first).
    pub(crate) fn seal_append(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        src: &[u8],
        trailer: &[u8],
        out: &mut Vec<u8>,
    ) -> [u8; 16] {
        match self {
            Aead::Gcm(k) => k.encrypt_append(nonce, aad, src, trailer, out),
            Aead::ChaCha(k) => k.encrypt_append(nonce, aad, src, trailer, out),
        }
    }

    /// Verifies `src` (ciphertext without the tag) and appends its plaintext to `out`; nothing
    /// is appended after a failure.
    pub(crate) fn open_append(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        src: &[u8],
        tag: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), ()> {
        let r = match self {
            Aead::Gcm(k) => k.decrypt_append(nonce, aad, src, tag, out),
            Aead::ChaCha(k) => k.decrypt_append(nonce, aad, src, tag, out),
        };
        r.map_err(|_| ())
    }

    /// Decrypts `buf` (ciphertext without the tag) in place.
    pub(crate) fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8],
    ) -> Result<(), ()> {
        let r = match self {
            Aead::Gcm(k) => k.decrypt_in_place_detached(nonce, aad, buf, tag),
            Aead::ChaCha(k) => k.decrypt_in_place_detached(nonce, aad, buf, tag),
        };
        r.map_err(|_| ())
    }
}

/// Key exchange and authentication of a TLS 1.2 suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth12 {
    /// ECDHE with an ECDSA (or Ed25519) certificate.
    Ecdsa,
    /// ECDHE with an RSA certificate.
    Rsa,
}

/// A cipher suite.
#[derive(Debug, PartialEq, Eq)]
pub struct Suite {
    /// The IANA code.
    pub id: u16,
    /// The name, as in the IANA registry.
    pub name: &'static str,
    /// `None` for TLS 1.3 suites.
    pub tls12: Option<Auth12>,
    /// The AEAD.
    pub aead: AeadAlg,
    /// The hash (HKDF / PRF / transcript).
    pub hash: HashAlg,
}

impl Suite {
    /// Whether this is a TLS 1.3 suite.
    pub fn is_tls13(&self) -> bool {
        self.tls12.is_none()
    }
}

macro_rules! suite {
    ($n:ident, $id:expr, $name:expr, $v:expr, $a:ident, $h:ident) => {
        #[allow(missing_docs)]
        pub static $n: Suite = Suite {
            id: $id,
            name: $name,
            tls12: $v,
            aead: AeadAlg::$a,
            hash: HashAlg::$h,
        };
    };
}

suite!(
    TLS13_AES_128_GCM_SHA256,
    0x1301,
    "TLS13_AES_128_GCM_SHA256",
    None,
    Aes128Gcm,
    Sha256
);
suite!(
    TLS13_AES_256_GCM_SHA384,
    0x1302,
    "TLS13_AES_256_GCM_SHA384",
    None,
    Aes256Gcm,
    Sha384
);
suite!(
    TLS13_CHACHA20_POLY1305_SHA256,
    0x1303,
    "TLS13_CHACHA20_POLY1305_SHA256",
    None,
    ChaCha20Poly1305,
    Sha256
);
suite!(
    ECDHE_ECDSA_AES128_GCM_SHA256,
    0xc02b,
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    Some(Auth12::Ecdsa),
    Aes128Gcm,
    Sha256
);
suite!(
    ECDHE_ECDSA_AES256_GCM_SHA384,
    0xc02c,
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    Some(Auth12::Ecdsa),
    Aes256Gcm,
    Sha384
);
suite!(
    ECDHE_RSA_AES128_GCM_SHA256,
    0xc02f,
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    Some(Auth12::Rsa),
    Aes128Gcm,
    Sha256
);
suite!(
    ECDHE_RSA_AES256_GCM_SHA384,
    0xc030,
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    Some(Auth12::Rsa),
    Aes256Gcm,
    Sha384
);
suite!(
    ECDHE_RSA_CHACHA20_POLY1305,
    0xcca8,
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    Some(Auth12::Rsa),
    ChaCha20Poly1305,
    Sha256
);
suite!(
    ECDHE_ECDSA_CHACHA20_POLY1305,
    0xcca9,
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    Some(Auth12::Ecdsa),
    ChaCha20Poly1305,
    Sha256
);

/// Every suite, in default preference order.
pub static ALL: &[&Suite] = &[
    &TLS13_AES_128_GCM_SHA256,
    &TLS13_AES_256_GCM_SHA384,
    &TLS13_CHACHA20_POLY1305_SHA256,
    &ECDHE_ECDSA_AES128_GCM_SHA256,
    &ECDHE_ECDSA_AES256_GCM_SHA384,
    &ECDHE_ECDSA_CHACHA20_POLY1305,
    &ECDHE_RSA_AES128_GCM_SHA256,
    &ECDHE_RSA_AES256_GCM_SHA384,
    &ECDHE_RSA_CHACHA20_POLY1305,
];

/// The suite with this code.
pub fn by_id(id: u16) -> Option<&'static Suite> {
    ALL.iter().copied().find(|s| s.id == id)
}

/// The suite with this IANA name (or `TLS13_*` / `TLS_*` short forms as above).
pub fn by_name(name: &str) -> Option<&'static Suite> {
    ALL.iter().copied().find(|s| s.name == name)
}

/// TLS_EMPTY_RENEGOTIATION_INFO_SCSV (RFC 5746).
pub(crate) const EMPTY_RENEGOTIATION_INFO_SCSV: u16 = 0x00ff;
/// TLS_FALLBACK_SCSV (RFC 7507).
pub(crate) const FALLBACK_SCSV: u16 = 0x5600;

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn prf_sha256_vector() {
        // The widely used P_SHA256 test vector (IETF TLS mailing list, "TLS 1.2 PRF test
        // vectors").
        let secret = unhex("9b be 43 6b a9 40 f0 17 b1 76 52 84 9a 71 db 35");
        let seed = unhex("a0 ba 9f 93 6c da 31 18 27 a6 f7 96 ff d5 19 8c");
        let out = HashAlg::Sha256.prf(&secret, b"test label", &seed, 100);
        assert_eq!(
            out,
            unhex(
                "e3 f2 29 ba 72 7b e1 7b 8d 12 26 20 55 7c d4 53 c2 aa b2 1d 07 c3 d4 95 32 9b 52 d4 e6 1e db 5a
                 6b 30 17 91 e9 0d 35 c9 c9 a4 6b 4e 14 ba f9 af 0f a0 22 f7 07 7d ef 17 ab fd 37 97 c0 56 4b ab
                 4f bc 91 66 6e 9d ef 9b 97 fc e3 4f 79 67 89 ba a4 80 82 d1 22 ee 42 c5 a7 2e 5a 51 10 ff f7 01
                 87 34 7b 66"
            )
        );
    }

    #[test]
    fn prf_sha384_vector() {
        let secret = unhex("b8 0b 73 3d 6c ee fc dc 71 56 6e a4 8e 55 67 df");
        let seed = unhex("cd 66 5c f6 a8 44 7d d6 ff 8b 27 55 5e db 74 65");
        let out = HashAlg::Sha384.prf(&secret, b"test label", &seed, 148);
        assert_eq!(
            &out[..16],
            &unhex("7b 0c 18 e9 ce d4 10 ed 18 04 f2 cf a3 4a 33 6a")[..]
        );
        assert_eq!(out.len(), 148);
    }

    #[test]
    fn suites_lookup() {
        assert_eq!(by_id(0x1301).unwrap().name, "TLS13_AES_128_GCM_SHA256");
        assert!(by_id(0x0035).is_none());
        assert_eq!(
            by_name("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256").unwrap().id,
            0xc02f
        );
        for s in ALL {
            assert_eq!(
                s.aead
                    .key(&vec![0; s.aead.key_len()])
                    .seal(&[0; 12], b"", &mut [])
                    .len(),
                16
            );
        }
    }

    #[test]
    fn aead_roundtrip() {
        for a in [
            AeadAlg::Aes128Gcm,
            AeadAlg::Aes256Gcm,
            AeadAlg::ChaCha20Poly1305,
        ] {
            let k = a.key(&vec![7; a.key_len()]);
            let mut b = b"hello".to_vec();
            let tag = k.seal(&[1; 12], b"aad", &mut b);
            assert!(k.open(&[1; 12], b"aad", &mut b.clone(), &[0; 16]).is_err());
            k.open(&[1; 12], b"aad", &mut b, &tag).unwrap();
            assert_eq!(b, b"hello");
        }
    }
}
