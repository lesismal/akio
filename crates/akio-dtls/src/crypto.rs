//! Cipher suites, the TLS 1.2 PRF, record protection, ECDHE and signature schemes.

use akio_crypto::aes::Aes;
use akio_crypto::chacha::{ChaCha20, ChaCha20Poly1305};
use akio_crypto::gcm::AesGcm;
use akio_crypto::hash::{Hash, Sha256, Sha384};
use akio_crypto::mac::Hmac;
use akio_crypto::pkey::{PrivateKey, PublicKey, SignatureAlgorithm};
use akio_crypto::{p256, p384, x25519};

use crate::record::Header;
use crate::{AlertDescription, Error};

/// A DTLS cipher suite: the DTLS 1.2 ECDHE suites with an AEAD (the WebRTC baseline is
/// [`CipherSuite::EcdheEcdsaAes128GcmSha256`]), the DTLS 1.2 PSK and ECDHE-PSK suites
/// (RFC 4279 / RFC 5487 / RFC 7905 / RFC 8442) and the DTLS 1.3 suites (RFC 9147).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CipherSuite {
    /// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (0xC02B).
    EcdheEcdsaAes128GcmSha256,
    /// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (0xC02C).
    EcdheEcdsaAes256GcmSha384,
    /// `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` (0xCCA9).
    EcdheEcdsaChacha20Poly1305Sha256,
    /// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (0xC02F).
    EcdheRsaAes128GcmSha256,
    /// `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (0xC030).
    EcdheRsaAes256GcmSha384,
    /// `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` (0xCCA8).
    EcdheRsaChacha20Poly1305Sha256,
    /// DTLS 1.2 `TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256` (0xD001, RFC 8442).
    EcdhePskAes128GcmSha256,
    /// DTLS 1.2 `TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384` (0xD002, RFC 8442).
    EcdhePskAes256GcmSha384,
    /// DTLS 1.2 `TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256` (0xCCAC, RFC 7905).
    EcdhePskChacha20Poly1305Sha256,
    /// DTLS 1.2 `TLS_PSK_WITH_AES_128_GCM_SHA256` (0x00A8, RFC 5487): no forward secrecy.
    PskAes128GcmSha256,
    /// DTLS 1.2 `TLS_PSK_WITH_AES_256_GCM_SHA384` (0x00A9, RFC 5487): no forward secrecy.
    PskAes256GcmSha384,
    /// DTLS 1.2 `TLS_PSK_WITH_CHACHA20_POLY1305_SHA256` (0xCCAB, RFC 7905): no forward secrecy.
    PskChacha20Poly1305Sha256,
    /// DTLS 1.3 `TLS_AES_128_GCM_SHA256` (0x1301).
    Tls13Aes128GcmSha256,
    /// DTLS 1.3 `TLS_AES_256_GCM_SHA384` (0x1302).
    Tls13Aes256GcmSha384,
    /// DTLS 1.3 `TLS_CHACHA20_POLY1305_SHA256` (0x1303).
    Tls13Chacha20Poly1305Sha256,
}

/// The PRF / transcript hash of a cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrfHash {
    Sha256,
    Sha384,
}

impl PrfHash {
    pub(crate) fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            PrfHash::Sha256 => Sha256::digest(data).to_vec(),
            PrfHash::Sha384 => Sha384::digest(data).to_vec(),
        }
    }

    /// The digest length.
    pub(crate) fn len(self) -> usize {
        match self {
            PrfHash::Sha256 => 32,
            PrfHash::Sha384 => 48,
        }
    }

    pub(crate) fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            PrfHash::Sha256 => Hmac::<Sha256>::mac(key, data).to_vec(),
            PrfHash::Sha384 => Hmac::<Sha384>::mac(key, data).to_vec(),
        }
    }
}

impl CipherSuite {
    /// Every DTLS 1.2 certificate (ECDHE-ECDSA / ECDHE-RSA) suite, in the default preference
    /// order (ECDSA first, AES-128-GCM first).
    pub const ALL: [CipherSuite; 6] = [
        CipherSuite::EcdheEcdsaAes128GcmSha256,
        CipherSuite::EcdheEcdsaAes256GcmSha384,
        CipherSuite::EcdheEcdsaChacha20Poly1305Sha256,
        CipherSuite::EcdheRsaAes128GcmSha256,
        CipherSuite::EcdheRsaAes256GcmSha384,
        CipherSuite::EcdheRsaChacha20Poly1305Sha256,
    ];

    /// The DTLS 1.2 pre-shared key suites, ECDHE-PSK (forward secret) first. Offered only with
    /// a [`Psk`](crate::Psk) configured.
    pub const PSK: [CipherSuite; 6] = [
        CipherSuite::EcdhePskAes128GcmSha256,
        CipherSuite::EcdhePskAes256GcmSha384,
        CipherSuite::EcdhePskChacha20Poly1305Sha256,
        CipherSuite::PskAes128GcmSha256,
        CipherSuite::PskAes256GcmSha384,
        CipherSuite::PskChacha20Poly1305Sha256,
    ];

    /// The DTLS 1.3 suites, in the default preference order.
    pub const TLS13: [CipherSuite; 3] = [
        CipherSuite::Tls13Aes128GcmSha256,
        CipherSuite::Tls13Aes256GcmSha384,
        CipherSuite::Tls13Chacha20Poly1305Sha256,
    ];

    /// The IANA code point.
    #[must_use]
    pub fn id(self) -> u16 {
        match self {
            CipherSuite::EcdheEcdsaAes128GcmSha256 => 0xc02b,
            CipherSuite::EcdheEcdsaAes256GcmSha384 => 0xc02c,
            CipherSuite::EcdheEcdsaChacha20Poly1305Sha256 => 0xcca9,
            CipherSuite::EcdheRsaAes128GcmSha256 => 0xc02f,
            CipherSuite::EcdheRsaAes256GcmSha384 => 0xc030,
            CipherSuite::EcdheRsaChacha20Poly1305Sha256 => 0xcca8,
            CipherSuite::EcdhePskAes128GcmSha256 => 0xd001,
            CipherSuite::EcdhePskAes256GcmSha384 => 0xd002,
            CipherSuite::EcdhePskChacha20Poly1305Sha256 => 0xccac,
            CipherSuite::PskAes128GcmSha256 => 0x00a8,
            CipherSuite::PskAes256GcmSha384 => 0x00a9,
            CipherSuite::PskChacha20Poly1305Sha256 => 0xccab,
            CipherSuite::Tls13Aes128GcmSha256 => 0x1301,
            CipherSuite::Tls13Aes256GcmSha384 => 0x1302,
            CipherSuite::Tls13Chacha20Poly1305Sha256 => 0x1303,
        }
    }

    /// The suite for a code point, if supported.
    #[must_use]
    pub fn from_id(id: u16) -> Option<CipherSuite> {
        CipherSuite::ALL
            .into_iter()
            .chain(CipherSuite::PSK)
            .chain(CipherSuite::TLS13)
            .find(|s| s.id() == id)
    }

    /// Whether the suite authenticates with an ECDSA (or Ed25519) certificate rather than RSA
    /// (false for PSK and DTLS 1.3 suites, which do not fix the certificate type).
    #[must_use]
    pub fn is_ecdsa(self) -> bool {
        matches!(
            self,
            CipherSuite::EcdheEcdsaAes128GcmSha256
                | CipherSuite::EcdheEcdsaAes256GcmSha384
                | CipherSuite::EcdheEcdsaChacha20Poly1305Sha256
        )
    }

    /// Whether this is a DTLS 1.3 suite.
    #[must_use]
    pub fn is_tls13(self) -> bool {
        CipherSuite::TLS13.contains(&self)
    }

    /// Whether this is a DTLS 1.2 pre-shared key suite (PSK or ECDHE-PSK).
    #[must_use]
    pub fn is_psk(self) -> bool {
        CipherSuite::PSK.contains(&self)
    }

    /// DTLS 1.2 ECDHE-PSK (the PSK suites with forward secrecy).
    pub(crate) fn is_ecdhe_psk(self) -> bool {
        matches!(
            self,
            CipherSuite::EcdhePskAes128GcmSha256
                | CipherSuite::EcdhePskAes256GcmSha384
                | CipherSuite::EcdhePskChacha20Poly1305Sha256
        )
    }

    pub(crate) fn prf_hash(self) -> PrfHash {
        match self {
            CipherSuite::EcdheEcdsaAes256GcmSha384
            | CipherSuite::EcdheRsaAes256GcmSha384
            | CipherSuite::EcdhePskAes256GcmSha384
            | CipherSuite::PskAes256GcmSha384
            | CipherSuite::Tls13Aes256GcmSha384 => PrfHash::Sha384,
            _ => PrfHash::Sha256,
        }
    }

    pub(crate) fn is_chacha(self) -> bool {
        matches!(
            self,
            CipherSuite::EcdheEcdsaChacha20Poly1305Sha256
                | CipherSuite::EcdheRsaChacha20Poly1305Sha256
                | CipherSuite::EcdhePskChacha20Poly1305Sha256
                | CipherSuite::PskChacha20Poly1305Sha256
                | CipherSuite::Tls13Chacha20Poly1305Sha256
        )
    }

    pub(crate) fn key_len(self) -> usize {
        match self {
            CipherSuite::EcdheEcdsaAes128GcmSha256
            | CipherSuite::EcdheRsaAes128GcmSha256
            | CipherSuite::EcdhePskAes128GcmSha256
            | CipherSuite::PskAes128GcmSha256
            | CipherSuite::Tls13Aes128GcmSha256 => 16,
            _ => 32,
        }
    }

    /// The implicit IV length: the 4-byte GCM salt or the 12-byte ChaCha20-Poly1305 IV in
    /// DTLS 1.2; always 12 in DTLS 1.3.
    pub(crate) fn fixed_iv_len(self) -> usize {
        if self.is_chacha() || self.is_tls13() {
            12
        } else {
            4
        }
    }

    /// Bytes added to each protected record: explicit nonce plus tag (DTLS 1.2), or tag plus
    /// the inner content type (DTLS 1.3).
    pub(crate) fn overhead(self) -> usize {
        if self.is_tls13() {
            16 + 1
        } else if self.is_chacha() {
            16
        } else {
            8 + 16
        }
    }

    /// Whether `key` can authenticate this suite (DTLS 1.3 suites take any key; PSK suites
    /// none).
    pub(crate) fn fits_key(self, key: &PrivateKey) -> bool {
        if self.is_tls13() {
            return true;
        }
        if self.is_psk() {
            return false;
        }
        match key {
            PrivateKey::Rsa(_) => !self.is_ecdsa(),
            _ => self.is_ecdsa(),
        }
    }
}

impl std::fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CipherSuite::EcdheEcdsaAes128GcmSha256 => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            CipherSuite::EcdheEcdsaAes256GcmSha384 => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            CipherSuite::EcdheEcdsaChacha20Poly1305Sha256 => {
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
            }
            CipherSuite::EcdheRsaAes128GcmSha256 => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            CipherSuite::EcdheRsaAes256GcmSha384 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            CipherSuite::EcdheRsaChacha20Poly1305Sha256 => {
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
            }
            CipherSuite::EcdhePskAes128GcmSha256 => "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
            CipherSuite::EcdhePskAes256GcmSha384 => "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
            CipherSuite::EcdhePskChacha20Poly1305Sha256 => {
                "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"
            }
            CipherSuite::PskAes128GcmSha256 => "TLS_PSK_WITH_AES_128_GCM_SHA256",
            CipherSuite::PskAes256GcmSha384 => "TLS_PSK_WITH_AES_256_GCM_SHA384",
            CipherSuite::PskChacha20Poly1305Sha256 => "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
            CipherSuite::Tls13Aes128GcmSha256 => "TLS_AES_128_GCM_SHA256",
            CipherSuite::Tls13Aes256GcmSha384 => "TLS_AES_256_GCM_SHA384",
            CipherSuite::Tls13Chacha20Poly1305Sha256 => "TLS_CHACHA20_POLY1305_SHA256",
        })
    }
}

/// `P_hash` of RFC 5246 §5 with `seed = label || seed`.
fn p_hash<H: Hash>(secret: &[u8], label: &[u8], seed: &[u8], out: &mut [u8]) {
    let mut a = Hmac::<H>::new(secret).chain(label).chain(seed).finalize();
    let mut pos = 0;
    while pos < out.len() {
        let block = Hmac::<H>::new(secret)
            .chain(a.as_ref())
            .chain(label)
            .chain(seed)
            .finalize();
        let n = (out.len() - pos).min(block.as_ref().len());
        out[pos..pos + n].copy_from_slice(&block.as_ref()[..n]);
        pos += n;
        a = Hmac::<H>::mac(secret, a.as_ref());
    }
}

/// The TLS 1.2 PRF.
pub(crate) fn prf(hash: PrfHash, secret: &[u8], label: &[u8], seed: &[u8], out: &mut [u8]) {
    match hash {
        PrfHash::Sha256 => p_hash::<Sha256>(secret, label, seed, out),
        PrfHash::Sha384 => p_hash::<Sha384>(secret, label, seed, out),
    }
}

/// One direction's AEAD state for an epoch.
#[derive(Clone)]
pub(crate) struct RecordProtection {
    aead: Aead,
    iv: [u8; 12],
}

#[derive(Clone)]
enum Aead {
    Gcm(Box<AesGcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

impl std::fmt::Debug for RecordProtection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordProtection").finish_non_exhaustive()
    }
}

impl RecordProtection {
    pub(crate) fn new(suite: CipherSuite, key: &[u8], iv: &[u8]) -> Result<Self, Error> {
        let mut fixed = [0u8; 12];
        fixed[..iv.len()].copy_from_slice(iv);
        let aead = if suite.is_chacha() {
            let k: [u8; 32] = key
                .try_into()
                .map_err(|_| Error::Crypto(akio_crypto::Error::InvalidLength))?;
            Aead::ChaCha(Box::new(ChaCha20Poly1305::new(&k)))
        } else {
            Aead::Gcm(Box::new(AesGcm::new(key)?))
        };
        Ok(RecordProtection { aead, iv: fixed })
    }

    fn nonce(&self, epoch_seq: u64) -> [u8; 12] {
        let mut n = self.iv;
        match self.aead {
            // RFC 5288: salt(4) || explicit nonce(8); the explicit part is epoch || seq.
            Aead::Gcm(_) => n[4..].copy_from_slice(&epoch_seq.to_be_bytes()),
            // RFC 7905: IV xor (0^32 || epoch || seq).
            Aead::ChaCha(_) => {
                for (b, s) in n[4..].iter_mut().zip(epoch_seq.to_be_bytes()) {
                    *b ^= s;
                }
            }
        }
        n
    }

    fn aad(h: &Header, len: usize) -> [u8; 13] {
        let mut a = [0u8; 13];
        a[..8].copy_from_slice(&h.epoch_seq().to_be_bytes());
        a[8] = h.content_type;
        a[9..11].copy_from_slice(&h.version.to_be_bytes());
        a[11..].copy_from_slice(&(len as u16).to_be_bytes());
        a
    }

    /// The RFC 9146 §5 additional data of a `tls12_cid` record whose inner plaintext is `len`
    /// bytes.
    pub(crate) fn cid_aad(h: &Header, cid: &[u8], len: usize) -> Vec<u8> {
        let mut a = Vec::with_capacity(23 + cid.len());
        a.extend_from_slice(&[0xff; 8]);
        a.push(crate::record::CT_TLS12_CID);
        a.push(cid.len() as u8);
        a.push(crate::record::CT_TLS12_CID);
        a.extend_from_slice(&h.version.to_be_bytes());
        a.extend_from_slice(&h.epoch_seq().to_be_bytes());
        a.extend_from_slice(cid);
        a.extend_from_slice(&(len as u16).to_be_bytes());
        a
    }

    /// The protected fragment for `plaintext` under header `h`.
    pub(crate) fn seal(&self, h: &Header, plaintext: &[u8]) -> Vec<u8> {
        self.seal_aad(h, &Self::aad(h, plaintext.len()), plaintext)
    }

    /// The protected fragment for `plaintext` under header `h` with additional data `aad`.
    pub(crate) fn seal_aad(&self, h: &Header, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let nonce = self.nonce(h.epoch_seq());
        match &self.aead {
            Aead::Gcm(g) => {
                let mut out = Vec::with_capacity(8 + plaintext.len() + 16);
                out.extend_from_slice(&nonce[4..]);
                out.extend_from_slice(&g.encrypt(&nonce, aad, plaintext));
                out
            }
            Aead::ChaCha(c) => c.encrypt(&nonce, aad, plaintext),
        }
    }

    /// The plaintext of a protected fragment, or `None` if it does not authenticate.
    pub(crate) fn open(&self, h: &Header, fragment: &[u8]) -> Option<Vec<u8>> {
        self.open_aad(h, fragment, |n| Self::aad(h, n))
    }

    /// The plaintext of a protected fragment; `aad` builds the additional data from the
    /// plaintext length.
    pub(crate) fn open_aad<A: AsRef<[u8]>>(
        &self,
        h: &Header,
        fragment: &[u8],
        aad: impl Fn(usize) -> A,
    ) -> Option<Vec<u8>> {
        match &self.aead {
            Aead::Gcm(g) => {
                if fragment.len() < 8 + 16 {
                    return None;
                }
                let mut nonce = self.iv;
                nonce[4..].copy_from_slice(&fragment[..8]);
                let ct = &fragment[8..];
                g.decrypt(&nonce, aad(ct.len() - 16).as_ref(), ct).ok()
            }
            Aead::ChaCha(c) => {
                if fragment.len() < 16 {
                    return None;
                }
                let nonce = self.nonce(h.epoch_seq());
                c.decrypt(&nonce, aad(fragment.len() - 16).as_ref(), fragment)
                    .ok()
            }
        }
    }
}

/// One direction's DTLS 1.3 protection for an epoch (RFC 9147 §4): the AEAD with the
/// TLS 1.3 per-record nonce and the record number encryption key (§4.2.3).
#[derive(Clone)]
pub(crate) struct Protection13 {
    aead: Aead,
    iv: [u8; 12],
    sn: SnCipher,
}

#[derive(Clone)]
enum SnCipher {
    Aes(Box<Aes>),
    ChaCha([u8; 32]),
}

impl std::fmt::Debug for Protection13 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Protection13").finish_non_exhaustive()
    }
}

impl Protection13 {
    /// Keys from `write_key`, `write_iv` (12 bytes) and `sn_key`.
    pub(crate) fn new(
        suite: CipherSuite,
        key: &[u8],
        iv: &[u8],
        sn_key: &[u8],
    ) -> Result<Protection13, Error> {
        let bad = || Error::Crypto(akio_crypto::Error::InvalidLength);
        let iv: [u8; 12] = iv.try_into().map_err(|_| bad())?;
        let (aead, sn) = if suite.is_chacha() {
            let k: [u8; 32] = key.try_into().map_err(|_| bad())?;
            let s: [u8; 32] = sn_key.try_into().map_err(|_| bad())?;
            (
                Aead::ChaCha(Box::new(ChaCha20Poly1305::new(&k))),
                SnCipher::ChaCha(s),
            )
        } else {
            (
                Aead::Gcm(Box::new(AesGcm::new(key)?)),
                SnCipher::Aes(Box::new(Aes::new(sn_key)?)),
            )
        };
        Ok(Protection13 { aead, iv, sn })
    }

    fn nonce(&self, seq: u64) -> [u8; 12] {
        let mut n = self.iv;
        for (b, s) in n[4..].iter_mut().zip(seq.to_be_bytes()) {
            *b ^= s;
        }
        n
    }

    /// Ciphertext and tag of `plaintext` (the DTLSInnerPlaintext) for record `seq`.
    pub(crate) fn seal(&self, seq: u64, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let nonce = self.nonce(seq);
        match &self.aead {
            Aead::Gcm(g) => g.encrypt(&nonce, aad, plaintext),
            Aead::ChaCha(c) => c.encrypt(&nonce, aad, plaintext),
        }
    }

    /// The inner plaintext of record `seq`, or `None` if it does not authenticate.
    pub(crate) fn open(&self, seq: u64, aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        if ciphertext.len() < 16 {
            return None;
        }
        let nonce = self.nonce(seq);
        match &self.aead {
            Aead::Gcm(g) => g.decrypt(&nonce, aad, ciphertext).ok(),
            Aead::ChaCha(c) => c.decrypt(&nonce, aad, ciphertext).ok(),
        }
    }

    /// The record number mask from the first 16 bytes of the ciphertext (RFC 9147 §4.2.3):
    /// AES-ECB of the sample, or the ChaCha20 keystream with the sample's first 4 bytes as the
    /// (little-endian) counter and the other 12 as the nonce.
    pub(crate) fn mask(&self, sample: &[u8; 16]) -> [u8; 2] {
        match &self.sn {
            SnCipher::Aes(a) => {
                let mut b = *sample;
                a.encrypt_block(&mut b);
                [b[0], b[1]]
            }
            SnCipher::ChaCha(k) => {
                let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&sample[4..]);
                let mut m = [0u8; 2];
                ChaCha20::new(k, &nonce, counter).apply_keystream(&mut m);
                m
            }
        }
    }
}

/// Supported ECDHE groups (RFC 8422 / RFC 7748 code points).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NamedGroup {
    X25519,
    Secp256r1,
    Secp384r1,
}

impl NamedGroup {
    /// Our preference order.
    pub(crate) const ALL: [NamedGroup; 3] = [
        NamedGroup::X25519,
        NamedGroup::Secp256r1,
        NamedGroup::Secp384r1,
    ];

    pub(crate) fn id(self) -> u16 {
        match self {
            NamedGroup::X25519 => 29,
            NamedGroup::Secp256r1 => 23,
            NamedGroup::Secp384r1 => 24,
        }
    }

    pub(crate) fn from_id(id: u16) -> Option<NamedGroup> {
        NamedGroup::ALL.into_iter().find(|g| g.id() == id)
    }
}

/// An ephemeral ECDHE key.
pub(crate) enum KeyShare {
    X25519(x25519::PrivateKey),
    P256(p256::SecretKey),
    P384(p384::SecretKey),
}

impl std::fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyShare(..)")
    }
}

impl KeyShare {
    pub(crate) fn generate(group: NamedGroup) -> Result<KeyShare, Error> {
        Ok(match group {
            NamedGroup::X25519 => KeyShare::X25519(x25519::PrivateKey::generate()?),
            NamedGroup::Secp256r1 => KeyShare::P256(p256::SecretKey::generate()?),
            NamedGroup::Secp384r1 => KeyShare::P384(p384::SecretKey::generate()?),
        })
    }

    /// The public value as sent on the wire (uncompressed SEC1 points).
    pub(crate) fn public(&self) -> Vec<u8> {
        match self {
            KeyShare::X25519(k) => k.public_key().to_vec(),
            KeyShare::P256(k) => k.public_key().to_uncompressed(),
            KeyShare::P384(k) => k.public_key().to_uncompressed(),
        }
    }

    /// The premaster secret with the peer's public value.
    pub(crate) fn agree(&self, peer: &[u8]) -> Result<Vec<u8>, Error> {
        let bad = || {
            Error::protocol(
                AlertDescription::IllegalParameter,
                "invalid ECDHE public key",
            )
        };
        Ok(match self {
            KeyShare::X25519(k) => {
                let p: [u8; 32] = peer.try_into().map_err(|_| bad())?;
                k.diffie_hellman(&p).map_err(|_| bad())?.to_vec()
            }
            KeyShare::P256(k) => {
                if peer.first() != Some(&4) {
                    return Err(bad());
                }
                let p = p256::PublicKey::from_sec1(peer).map_err(|_| bad())?;
                k.diffie_hellman(&p).to_vec()
            }
            KeyShare::P384(k) => {
                if peer.first() != Some(&4) {
                    return Err(bad());
                }
                let p = p384::PublicKey::from_sec1(peer).map_err(|_| bad())?;
                k.diffie_hellman(&p).to_vec()
            }
        })
    }
}

/// TLS 1.2 SignatureAndHashAlgorithm code points we sign and verify with (no SHA-1).
pub(crate) const SIGNATURE_SCHEMES: [u16; 10] = [
    0x0403, // ecdsa_secp256r1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0603, // ecdsa_secp521r1_sha512 (any curve with SHA-512 in TLS 1.2)
    0x0807, // ed25519
    0x0804, // rsa_pss_rsae_sha256
    0x0805, // rsa_pss_rsae_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0401, // rsa_pkcs1_sha256
    0x0501, // rsa_pkcs1_sha384
    0x0601, // rsa_pkcs1_sha512
];

pub(crate) fn scheme_algorithm(scheme: u16) -> Option<SignatureAlgorithm> {
    Some(match scheme {
        0x0403 => SignatureAlgorithm::EcdsaSha256,
        0x0503 => SignatureAlgorithm::EcdsaSha384,
        0x0603 => SignatureAlgorithm::EcdsaSha512,
        0x0807 => SignatureAlgorithm::Ed25519,
        0x0804 => SignatureAlgorithm::RsaPssSha256,
        0x0805 => SignatureAlgorithm::RsaPssSha384,
        0x0806 => SignatureAlgorithm::RsaPssSha512,
        0x0401 => SignatureAlgorithm::RsaPkcs1Sha256,
        0x0501 => SignatureAlgorithm::RsaPkcs1Sha384,
        0x0601 => SignatureAlgorithm::RsaPkcs1Sha512,
        _ => return None,
    })
}

/// Our schemes for `key`, preferred first.
fn schemes_for(key: &PrivateKey) -> &'static [u16] {
    match key {
        PrivateKey::P256(_) => &[0x0403, 0x0503, 0x0603],
        PrivateKey::P384(_) => &[0x0503, 0x0403, 0x0603],
        PrivateKey::Ed25519(_) => &[0x0807],
        _ => &[0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601],
    }
}

/// The scheme to sign with: our first preference for `key` that the peer offered. A peer that
/// sent no list (TLS 1.2 default, SHA-1) gets our first preference.
pub(crate) fn choose_scheme(key: &PrivateKey, peer: Option<&[u16]>) -> Option<u16> {
    let ours = schemes_for(key);
    match peer {
        None => ours.first().copied(),
        Some(p) => ours.iter().copied().find(|s| p.contains(s)),
    }
}

/// DTLS 1.3 CertificateVerify schemes (RFC 8446 §4.2.3: no PKCS#1 v1.5, ECDSA bound to its
/// curve).
pub(crate) const SIGNATURE_SCHEMES_13: [u16; 7] =
    [0x0403, 0x0503, 0x0603, 0x0807, 0x0804, 0x0805, 0x0806];

/// The DTLS 1.3 scheme to sign with for `key`, if the peer offered one.
pub(crate) fn choose_scheme13(key: &PrivateKey, peer: &[u16]) -> Option<u16> {
    let ours: &[u16] = match key {
        PrivateKey::P256(_) => &[0x0403],
        PrivateKey::P384(_) => &[0x0503],
        PrivateKey::Ed25519(_) => &[0x0807],
        PrivateKey::Rsa(_) => &[0x0804, 0x0805, 0x0806],
        _ => &[],
    };
    ours.iter().copied().find(|s| peer.contains(s))
}

/// The content a DTLS 1.3 CertificateVerify signs (RFC 8446 §4.4.3; the context strings are
/// TLS 1.3's, RFC 9147 keeps them).
pub(crate) fn certificate_verify_input(server: bool, transcript_hash: &[u8]) -> Vec<u8> {
    let mut m = vec![0x20u8; 64];
    m.extend_from_slice(if server {
        b"TLS 1.3, server CertificateVerify"
    } else {
        b"TLS 1.3, client CertificateVerify"
    });
    m.push(0);
    m.extend_from_slice(transcript_hash);
    m
}

/// Verifies a DTLS 1.3 CertificateVerify signature.
pub(crate) fn verify_signature13(
    key: &PublicKey,
    scheme: u16,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), Error> {
    if !SIGNATURE_SCHEMES_13.contains(&scheme) {
        return Err(Error::protocol(
            AlertDescription::IllegalParameter,
            "signature scheme not allowed in DTLS 1.3",
        ));
    }
    verify_signature(key, scheme, msg, sig)
}

/// Verifies a TLS 1.2 `digitally-signed` value.
pub(crate) fn verify_signature(
    key: &PublicKey,
    scheme: u16,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), Error> {
    if !SIGNATURE_SCHEMES.contains(&scheme) {
        return Err(Error::protocol(
            AlertDescription::IllegalParameter,
            "signature scheme not offered",
        ));
    }
    let alg = scheme_algorithm(scheme).ok_or_else(|| {
        Error::protocol(
            AlertDescription::IllegalParameter,
            "unknown signature scheme",
        )
    })?;
    key.verify(alg, msg, sig).map_err(|_| {
        Error::protocol(
            AlertDescription::DecryptError,
            "signature verification failed",
        )
    })
}

/// Signs `msg` with `scheme`.
pub(crate) fn sign(key: &PrivateKey, scheme: u16, msg: &[u8]) -> Result<Vec<u8>, Error> {
    let alg = scheme_algorithm(scheme).ok_or(Error::Config("unsupported signature scheme"))?;
    Ok(key.sign(alg, msg)?)
}

/// Whether the leaf public key fits the suite's authentication algorithm.
pub(crate) fn public_key_fits(suite: CipherSuite, key: &PublicKey) -> bool {
    match key {
        PublicKey::Rsa(_) => !suite.is_ecdsa(),
        _ => suite.is_ecdsa(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The widely used TLS 1.2 PRF test vector (SHA-256), from the IETF TLS mailing list
    /// (also in Go's crypto/tls prf_test.go).
    #[test]
    fn prf_sha256_vector() {
        let secret = hex("9bbe436ba940f017b17652849a71db35");
        let seed = hex("a0ba9f936cda311827a6f796ffd5198c");
        let mut out = [0u8; 100];
        prf(PrfHash::Sha256, &secret, b"test label", &seed, &mut out);
        assert_eq!(
            out.to_vec(),
            hex(concat!(
                "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af",
                "0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701",
                "87347b66"
            ))
        );
    }

    #[test]
    fn prf_sha384_vector() {
        let secret = hex("b80b733d6ceefcdc71566ea48e5567df");
        let seed = hex("cd665cf6a8447dd6ff8b27555edb7465");
        let mut out = [0u8; 148];
        prf(PrfHash::Sha384, &secret, b"test label", &seed, &mut out);
        assert_eq!(
            out.to_vec(),
            hex(concat!(
                "7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cde9ca0faa60be9fe34f82b1233c9146a0",
                "e534cb400fed2700884f9dc236f80edd8bfa961144c9e8d792eca722a7b32fc3d416d473ebc2c5fd4abfdad05d918425",
                "9b5bf8cd4d90fa0d31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee691c8f3a26854308d5eaa3be85e099070",
                "3d73e56f"
            ))
        );
    }

    #[test]
    fn suites_roundtrip() {
        for s in CipherSuite::ALL
            .into_iter()
            .chain(CipherSuite::PSK)
            .chain(CipherSuite::TLS13)
        {
            assert_eq!(CipherSuite::from_id(s.id()), Some(s));
            assert!(!s.to_string().is_empty());
            assert_eq!(s.is_tls13(), s.id() >> 8 == 0x13);
        }
        assert_eq!(CipherSuite::from_id(0x1304), None);
    }

    #[test]
    fn record_protection_roundtrip() {
        for s in CipherSuite::ALL {
            let key = vec![7u8; s.key_len()];
            let iv = vec![9u8; s.fixed_iv_len()];
            let p = RecordProtection::new(s, &key, &iv).unwrap();
            let h = Header {
                content_type: 23,
                version: 0xfefd,
                epoch: 1,
                seq: 42,
            };
            let ct = p.seal(&h, b"hello");
            assert_eq!(ct.len(), 5 + s.overhead());
            assert_eq!(p.open(&h, &ct).unwrap(), b"hello");
            let mut h2 = h;
            h2.seq = 43;
            assert!(p.open(&h2, &ct).is_none());
            let mut bad = ct.clone();
            *bad.last_mut().unwrap() ^= 1;
            assert!(p.open(&h, &bad).is_none());
            assert!(p.open(&h, &ct[..3]).is_none());
        }
    }

    #[test]
    fn ecdhe_agrees() {
        for g in NamedGroup::ALL {
            let a = KeyShare::generate(g).unwrap();
            let b = KeyShare::generate(g).unwrap();
            assert_eq!(a.agree(&b.public()).unwrap(), b.agree(&a.public()).unwrap());
            assert!(a.agree(&[1, 2, 3]).is_err());
            assert_eq!(NamedGroup::from_id(g.id()), Some(g));
        }
    }
}
