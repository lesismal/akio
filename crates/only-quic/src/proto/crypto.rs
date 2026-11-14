//! Packet protection (RFC 9001 section 5): AEAD keys per direction, header protection with AES
//! or ChaCha20, Initial keys, the Retry integrity tag, 1-RTT key updates (section 6), and the
//! sealed address-validation tokens.

use only_crypto::aes::Aes;
use only_crypto::chacha::{ChaCha20, ChaCha20Poly1305};
use only_crypto::gcm::AesGcm;
use only_crypto::rand::ChaChaRng;
use only_tls::quic::{AeadAlg, HashAlg, Suite};

/// AEAD tag length (all QUIC v1 suites).
pub const TAG_LEN: usize = 16;

#[derive(Clone)]
enum Aead {
    Gcm(Box<AesGcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

/// The AEAD key and IV of one direction of one packet number space.
#[derive(Clone)]
pub struct PacketKey {
    aead: Aead,
    iv: [u8; 12],
}

impl PacketKey {
    pub fn new(alg: AeadAlg, key: &[u8], iv: &[u8]) -> PacketKey {
        let aead = match alg {
            AeadAlg::Aes128Gcm | AeadAlg::Aes256Gcm => Aead::Gcm(Box::new(
                AesGcm::new(key).unwrap_or_else(|_| unreachable!("key length from the suite")),
            )),
            AeadAlg::ChaCha20Poly1305 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                Aead::ChaCha(Box::new(ChaCha20Poly1305::new(&k)))
            }
        };
        let mut v = [0u8; 12];
        v.copy_from_slice(iv);
        PacketKey { aead, iv: v }
    }

    fn nonce(&self, pn: u64) -> [u8; 12] {
        let mut n = self.iv;
        for (i, b) in pn.to_be_bytes().iter().enumerate() {
            n[4 + i] ^= b;
        }
        n
    }

    /// Encrypts `payload` in place; returns the tag to append.
    pub fn seal(&self, pn: u64, header: &[u8], payload: &mut [u8]) -> [u8; TAG_LEN] {
        let n = self.nonce(pn);
        match &self.aead {
            Aead::Gcm(k) => k.encrypt_in_place_detached(&n, header, payload),
            Aead::ChaCha(k) => k.encrypt_in_place_detached(&n, header, payload),
        }
    }

    /// Decrypts `payload` (ciphertext without the tag) in place.
    pub fn open(&self, pn: u64, header: &[u8], payload: &mut [u8], tag: &[u8]) -> bool {
        let n = self.nonce(pn);
        match &self.aead {
            Aead::Gcm(k) => k.decrypt_in_place_detached(&n, header, payload, tag).is_ok(),
            Aead::ChaCha(k) => k.decrypt_in_place_detached(&n, header, payload, tag).is_ok(),
        }
    }
}

/// A header protection key.
#[derive(Clone)]
pub enum HeaderKey {
    Aes(Box<Aes>),
    ChaCha([u8; 32]),
}

impl HeaderKey {
    pub fn new(alg: AeadAlg, key: &[u8]) -> HeaderKey {
        match alg {
            AeadAlg::Aes128Gcm | AeadAlg::Aes256Gcm => HeaderKey::Aes(Box::new(
                Aes::new(key).unwrap_or_else(|_| unreachable!("key length from the suite")),
            )),
            AeadAlg::ChaCha20Poly1305 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                HeaderKey::ChaCha(k)
            }
        }
    }

    /// The 5-byte mask for a 16-byte ciphertext sample (RFC 9001 sections 5.4.3 and 5.4.4).
    pub fn mask(&self, sample: &[u8; 16]) -> [u8; 5] {
        match self {
            HeaderKey::Aes(k) => {
                let mut b = *sample;
                k.encrypt_block(&mut b);
                [b[0], b[1], b[2], b[3], b[4]]
            }
            HeaderKey::ChaCha(k) => {
                let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&sample[4..]);
                let mut m = [0u8; 5];
                ChaCha20::new(k, &nonce, counter).apply_keystream(&mut m);
                m
            }
        }
    }
}

/// Packet and header protection of one direction.
#[derive(Clone)]
pub struct DirKeys {
    pub packet: PacketKey,
    pub header: HeaderKey,
}

impl DirKeys {
    /// The keys of a TLS traffic secret.
    pub fn from_secret(suite: &Suite, secret: &[u8]) -> DirKeys {
        let (k, iv, hp) = only_tls::quic::packet_keys(suite, secret);
        DirKeys {
            packet: PacketKey::new(suite.aead, &k, &iv),
            header: HeaderKey::new(suite.aead, &hp),
        }
    }
}

/// Both directions of a packet number space.
#[derive(Clone)]
pub struct Keys {
    pub local: DirKeys,
    pub remote: DirKeys,
}

fn initial_dir(secret: &[u8]) -> DirKeys {
    let h = HashAlg::Sha256;
    let k = only_tls::quic::hkdf_expand_label(h, secret, b"quic key", &[], 16);
    let iv = only_tls::quic::hkdf_expand_label(h, secret, b"quic iv", &[], 12);
    let hp = only_tls::quic::hkdf_expand_label(h, secret, b"quic hp", &[], 16);
    DirKeys {
        packet: PacketKey::new(AeadAlg::Aes128Gcm, &k, &iv),
        header: HeaderKey::new(AeadAlg::Aes128Gcm, &hp),
    }
}

/// The Initial keys for the client's first destination connection ID.
pub fn initial_keys(dcid: &[u8], client: bool) -> Keys {
    let (c, s) = only_tls::quic::initial_secrets(&only_tls::quic::V1_INITIAL_SALT, dcid);
    let (c, s) = (initial_dir(&c), initial_dir(&s));
    if client {
        Keys {
            local: c,
            remote: s,
        }
    } else {
        Keys {
            local: s,
            remote: c,
        }
    }
}

/// The 1-RTT keys with what a key update needs (RFC 9001 section 6).
pub struct OneRtt {
    pub suite: &'static Suite,
    pub local_secret: Vec<u8>,
    pub remote_secret: Vec<u8>,
    /// Header protection keys never change.
    pub local_hp: HeaderKey,
    pub remote_hp: HeaderKey,
    pub local: PacketKey,
    pub remote: PacketKey,
    /// The key phase bit of the current keys.
    pub phase: bool,
    /// The remote keys of the next phase, derived ahead so a peer's update is detected cheaply.
    pub next_remote: PacketKey,
    /// The previous phase's remote keys, for late packets, until the given time.
    pub prev_remote: Option<(PacketKey, std::time::Instant)>,
}

impl OneRtt {
    pub fn new(suite: &'static Suite, local_secret: Vec<u8>, remote_secret: Vec<u8>) -> OneRtt {
        let l = DirKeys::from_secret(suite, &local_secret);
        let r = DirKeys::from_secret(suite, &remote_secret);
        let next = only_tls::quic::next_secret(suite, &remote_secret);
        let next_remote = DirKeys::from_secret(suite, &next).packet;
        OneRtt {
            suite,
            local_secret,
            remote_secret,
            local_hp: l.header,
            remote_hp: r.header,
            local: l.packet,
            remote: r.packet,
            phase: false,
            next_remote,
            prev_remote: None,
        }
    }

    /// Moves both directions to the next phase; the old remote key stays usable until
    /// `keep_until`.
    pub fn update(&mut self, keep_until: std::time::Instant) {
        let s = self.suite;
        self.local_secret = only_tls::quic::next_secret(s, &self.local_secret);
        self.local = DirKeys::from_secret(s, &self.local_secret).packet;
        self.remote_secret = only_tls::quic::next_secret(s, &self.remote_secret);
        let next_secret = only_tls::quic::next_secret(s, &self.remote_secret);
        let next = DirKeys::from_secret(s, &next_secret).packet;
        let cur = std::mem::replace(&mut self.next_remote, next);
        let old = std::mem::replace(&mut self.remote, cur);
        self.prev_remote = Some((old, keep_until));
        self.phase = !self.phase;
    }
}

const RETRY_KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_NONCE: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

/// The Retry integrity tag (RFC 9001 section 5.8) of a Retry packet without its tag, sent in
/// answer to an Initial with destination `odcid`.
pub fn retry_tag(odcid: &[u8], retry_without_tag: &[u8]) -> [u8; TAG_LEN] {
    let mut aad = Vec::with_capacity(1 + odcid.len() + retry_without_tag.len());
    aad.push(odcid.len() as u8);
    aad.extend_from_slice(odcid);
    aad.extend_from_slice(retry_without_tag);
    let k = AesGcm::new(&RETRY_KEY).unwrap_or_else(|_| unreachable!("16-byte key"));
    k.encrypt_in_place_detached(&RETRY_NONCE, &aad, &mut [])
}

/// Seals and opens address-validation tokens (Retry and NEW_TOKEN) with an endpoint key.
pub struct TokenKey(AesGcm);

impl TokenKey {
    pub fn new(key: &[u8; 16]) -> TokenKey {
        TokenKey(AesGcm::new(key).unwrap_or_else(|_| unreachable!("16-byte key")))
    }

    /// `kind` byte, a random nonce, then `plain` encrypted with `kind` as associated data.
    pub fn seal(&self, rng: &mut ChaChaRng, kind: u8, plain: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce);
        let mut out = Vec::with_capacity(1 + 12 + plain.len() + TAG_LEN);
        out.push(kind);
        out.extend_from_slice(&nonce);
        let at = out.len();
        out.extend_from_slice(plain);
        let tag = self.0.encrypt_in_place_detached(&nonce, &[kind], &mut out[at..]);
        out.extend_from_slice(&tag);
        out
    }

    /// The kind and plaintext of a token sealed by this key.
    pub fn open(&self, token: &[u8]) -> Option<(u8, Vec<u8>)> {
        if token.len() < 1 + 12 + TAG_LEN {
            return None;
        }
        let kind = token[0];
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&token[1..13]);
        let (ct, tag) = token[13..].split_at(token.len() - 13 - TAG_LEN);
        let mut plain = ct.to_vec();
        self.0
            .decrypt_in_place_detached(&nonce, &[kind], &mut plain, tag)
            .ok()?;
        Some((kind, plain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc9001_header_protection_samples() {
        // A.2: the client Initial's sample and mask.
        let k = initial_keys(&unhex("8394c8f03e515708"), true);
        let sample: [u8; 16] = unhex("d1b1c98dd7689fb8ec11d242b123dc9b").try_into().unwrap();
        assert_eq!(k.local.header.mask(&sample).to_vec(), unhex("437b9aec36"));
        // A.3: the server Initial's.
        let sample: [u8; 16] = unhex("2cd0991cd25b0aac406a5816b6394100").try_into().unwrap();
        assert_eq!(k.remote.header.mask(&sample).to_vec(), unhex("2ec0d8356a"));
        // A.5: ChaCha20 header protection.
        let hp = unhex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
        let hk = HeaderKey::new(AeadAlg::ChaCha20Poly1305, &hp);
        let sample: [u8; 16] = unhex("5e5cd55c41f69080575d7999c25a5bfb").try_into().unwrap();
        assert_eq!(hk.mask(&sample).to_vec(), unhex("aefefe7d03"));
    }

    #[test]
    fn retry_integrity_tag_vector() {
        // RFC 9001 A.4.
        let pkt = unhex(
            "ff000000010008f067a5502a4262b574 6f6b656e04a265ba2eff4d829058fb3f 0f2496ba",
        );
        let (body, tag) = pkt.split_at(pkt.len() - 16);
        assert_eq!(retry_tag(&unhex("8394c8f03e515708"), body).to_vec(), tag);
    }

    #[test]
    fn tokens_seal_and_open() {
        let k = TokenKey::new(&[9; 16]);
        let mut rng = ChaChaRng::from_seed([1; 32]);
        let t = k.seal(&mut rng, 2, b"hello");
        assert_eq!(k.open(&t), Some((2, b"hello".to_vec())));
        let mut bad = t.clone();
        bad[0] = 3;
        assert_eq!(k.open(&bad), None);
        assert_eq!(k.open(&t[..20]), None);
        assert_eq!(TokenKey::new(&[8; 16]).open(&t), None);
    }

    #[test]
    fn key_update_moves_both_directions() {
        static S: Suite = Suite {
            id: 0x1303,
            name: "TLS_CHACHA20_POLY1305_SHA256",
            tls12: None,
            aead: AeadAlg::ChaCha20Poly1305,
            hash: HashAlg::Sha256,
        };
        let s = &S;
        let a = OneRtt::new(s, vec![1; 32], vec![2; 32]);
        let mut b = OneRtt::new(s, vec![2; 32], vec![1; 32]);
        let now = std::time::Instant::now();
        // b updates; a's precomputed next remote key opens what b now seals.
        b.update(now);
        assert!(b.phase);
        let mut p = b"payload".to_vec();
        let tag = b.local.seal(5, b"hdr", &mut p);
        assert!(a.next_remote.open(5, b"hdr", &mut p, &tag));
        assert_eq!(p, b"payload");
        assert!(b.prev_remote.is_some());
    }
}
