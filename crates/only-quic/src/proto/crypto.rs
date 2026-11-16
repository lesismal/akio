//! Packet protection (RFC 9001 section 5): AEAD keys per direction, header protection with AES
//! or ChaCha20, Initial keys, the Retry integrity tag, 1-RTT key updates (section 6), and the
//! sealed address-validation tokens. QUIC version 2 (RFC 9369) differs in its Initial salt, its
//! HKDF labels and its Retry integrity key; everything takes the version.

use only_crypto::aes::Aes;
use only_crypto::chacha::{ChaCha20, ChaCha20Poly1305};
use only_crypto::gcm::AesGcm;
use only_crypto::rand::ChaChaRng;
use only_tls::quic::{AeadAlg, HashAlg, Suite};

use super::packet::VERSION_2;

/// The HKDF labels of a version: key, IV, header protection, key update.
fn labels(version: u32) -> [&'static [u8]; 4] {
    if version == VERSION_2 {
        [b"quicv2 key", b"quicv2 iv", b"quicv2 hp", b"quicv2 ku"]
    } else {
        [b"quic key", b"quic iv", b"quic hp", b"quic ku"]
    }
}

/// The next 1-RTT secret of a key update.
fn next_secret(suite: &Suite, secret: &[u8], version: u32) -> Vec<u8> {
    let h = suite.hash;
    only_tls::quic::hkdf_expand_label(h, secret, labels(version)[3], &[], h.len())
}

/// QUIC version 2's Initial salt (RFC 9369 section 3.3.1).
const V2_INITIAL_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

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
            Aead::Gcm(k) => k
                .decrypt_in_place_detached(&n, header, payload, tag)
                .is_ok(),
            Aead::ChaCha(k) => k
                .decrypt_in_place_detached(&n, header, payload, tag)
                .is_ok(),
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
    /// The keys of a TLS traffic secret, with the labels of `version`.
    pub fn from_secret(suite: &Suite, secret: &[u8], version: u32) -> DirKeys {
        let [lk, liv, lhp, _] = labels(version);
        let (h, kl) = (suite.hash, suite.aead.key_len());
        let k = only_tls::quic::hkdf_expand_label(h, secret, lk, &[], kl);
        let iv = only_tls::quic::hkdf_expand_label(h, secret, liv, &[], 12);
        let hp = only_tls::quic::hkdf_expand_label(h, secret, lhp, &[], kl);
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

fn initial_dir(secret: &[u8], version: u32) -> DirKeys {
    let h = HashAlg::Sha256;
    let [lk, liv, lhp, _] = labels(version);
    let k = only_tls::quic::hkdf_expand_label(h, secret, lk, &[], 16);
    let iv = only_tls::quic::hkdf_expand_label(h, secret, liv, &[], 12);
    let hp = only_tls::quic::hkdf_expand_label(h, secret, lhp, &[], 16);
    DirKeys {
        packet: PacketKey::new(AeadAlg::Aes128Gcm, &k, &iv),
        header: HeaderKey::new(AeadAlg::Aes128Gcm, &hp),
    }
}

/// The Initial keys of `version` for the client's first destination connection ID.
pub fn initial_keys(dcid: &[u8], client: bool, version: u32) -> Keys {
    let salt: &[u8] = if version == VERSION_2 {
        &V2_INITIAL_SALT
    } else {
        &only_tls::quic::V1_INITIAL_SALT
    };
    let (c, s) = only_tls::quic::initial_secrets(salt, dcid);
    let (c, s) = (initial_dir(&c, version), initial_dir(&s, version));
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
    /// The QUIC version (its key update label).
    version: u32,
}

impl OneRtt {
    pub fn new(
        suite: &'static Suite,
        local_secret: Vec<u8>,
        remote_secret: Vec<u8>,
        version: u32,
    ) -> OneRtt {
        let l = DirKeys::from_secret(suite, &local_secret, version);
        let r = DirKeys::from_secret(suite, &remote_secret, version);
        let next = next_secret(suite, &remote_secret, version);
        let next_remote = DirKeys::from_secret(suite, &next, version).packet;
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
            version,
        }
    }

    /// Sets the remote direction (a server answering 0-RTT writes 1-RTT packets before it has
    /// the client's 1-RTT secret).
    pub fn set_remote(&mut self, remote_secret: Vec<u8>) {
        let (s, v) = (self.suite, self.version);
        let r = DirKeys::from_secret(s, &remote_secret, v);
        let next = next_secret(s, &remote_secret, v);
        self.next_remote = DirKeys::from_secret(s, &next, v).packet;
        self.remote_hp = r.header;
        self.remote = r.packet;
        self.remote_secret = remote_secret;
    }

    /// Moves both directions to the next phase; the old remote key stays usable until
    /// `keep_until`.
    pub fn update(&mut self, keep_until: std::time::Instant) {
        let (s, v) = (self.suite, self.version);
        self.local_secret = next_secret(s, &self.local_secret, v);
        self.local = DirKeys::from_secret(s, &self.local_secret, v).packet;
        self.remote_secret = next_secret(s, &self.remote_secret, v);
        let following = next_secret(s, &self.remote_secret, v);
        let next = DirKeys::from_secret(s, &following, v).packet;
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

const RETRY_KEY_V2: [u8; 16] = [
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
];
const RETRY_NONCE_V2: [u8; 12] = [
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
];

/// The Retry integrity tag (RFC 9001 section 5.8, RFC 9369 section 3.3.3) of a Retry packet of
/// `version` without its tag, sent in answer to an Initial with destination `odcid`.
pub fn retry_tag(version: u32, odcid: &[u8], retry_without_tag: &[u8]) -> [u8; TAG_LEN] {
    let (key, nonce) = if version == VERSION_2 {
        (&RETRY_KEY_V2, &RETRY_NONCE_V2)
    } else {
        (&RETRY_KEY, &RETRY_NONCE)
    };
    let mut aad = Vec::with_capacity(1 + odcid.len() + retry_without_tag.len());
    aad.push(odcid.len() as u8);
    aad.extend_from_slice(odcid);
    aad.extend_from_slice(retry_without_tag);
    let k = AesGcm::new(key).unwrap_or_else(|_| unreachable!("16-byte key"));
    k.encrypt_in_place_detached(nonce, &aad, &mut [])
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
        let tag = self
            .0
            .encrypt_in_place_detached(&nonce, &[kind], &mut out[at..]);
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
        let k = initial_keys(&unhex("8394c8f03e515708"), true, 1);
        let sample: [u8; 16] = unhex("d1b1c98dd7689fb8ec11d242b123dc9b")
            .try_into()
            .unwrap();
        assert_eq!(k.local.header.mask(&sample).to_vec(), unhex("437b9aec36"));
        // A.3: the server Initial's.
        let sample: [u8; 16] = unhex("2cd0991cd25b0aac406a5816b6394100")
            .try_into()
            .unwrap();
        assert_eq!(k.remote.header.mask(&sample).to_vec(), unhex("2ec0d8356a"));
        // A.5: ChaCha20 header protection.
        let hp = unhex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
        let hk = HeaderKey::new(AeadAlg::ChaCha20Poly1305, &hp);
        let sample: [u8; 16] = unhex("5e5cd55c41f69080575d7999c25a5bfb")
            .try_into()
            .unwrap();
        assert_eq!(hk.mask(&sample).to_vec(), unhex("aefefe7d03"));
    }

    #[test]
    fn retry_integrity_tag_vector() {
        // RFC 9001 A.4.
        let pkt =
            unhex("ff000000010008f067a5502a4262b574 6f6b656e04a265ba2eff4d829058fb3f 0f2496ba");
        let (body, tag) = pkt.split_at(pkt.len() - 16);
        assert_eq!(retry_tag(1, &unhex("8394c8f03e515708"), body).to_vec(), tag);
        // RFC 9369 A.4: version 2.
        let pkt =
            unhex("cf6b3343cf0008f067a5502a4262b574 6f6b656ec8646ce8bfe33952d9555436 65dcc7b6");
        let (body, tag) = pkt.split_at(pkt.len() - 16);
        assert_eq!(
            retry_tag(VERSION_2, &unhex("8394c8f03e515708"), body).to_vec(),
            tag
        );
    }

    #[test]
    fn rfc9369_v2_keys() {
        // A.1: the Initial keys (sealing with the client's and opening with the server's view
        // proves the key and IV; the header protection key is checked through its mask).
        let dcid = unhex("8394c8f03e515708");
        let c = initial_keys(&dcid, true, VERSION_2);
        let want = initial_dir(
            &unhex("14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b"),
            VERSION_2,
        );
        let sample = [7u8; 16];
        assert_eq!(c.local.header.mask(&sample), want.header.mask(&sample));
        let hp = HeaderKey::new(
            AeadAlg::Aes128Gcm,
            &unhex("45b95e15235d6f45a6b19cbcb0294ba9"),
        );
        assert_eq!(c.local.header.mask(&sample), hp.mask(&sample));
        let shp = HeaderKey::new(
            AeadAlg::Aes128Gcm,
            &unhex("edf6d05c83121201b436e16877593c3a"),
        );
        assert_eq!(c.remote.header.mask(&sample), shp.mask(&sample));
        let ck = PacketKey::new(
            AeadAlg::Aes128Gcm,
            &unhex("8b1a0bc121284290a29e0971b5cd045d"),
            &unhex("91f73e2351d8fa91660e909f"),
        );
        let mut p = b"hello".to_vec();
        let tag = ck.seal(3, b"h", &mut p);
        let s = initial_keys(&dcid, false, VERSION_2);
        assert!(s.remote.packet.open(3, b"h", &mut p, &tag));
        assert_eq!(p, b"hello");
        // A.5: ChaCha20 with the v2 labels, packet 654360564.
        static S: Suite = Suite {
            id: 0x1303,
            name: "TLS_CHACHA20_POLY1305_SHA256",
            tls12: None,
            aead: AeadAlg::ChaCha20Poly1305,
            hash: HashAlg::Sha256,
        };
        let secret = unhex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
        let k = DirKeys::from_secret(&S, &secret, VERSION_2);
        let mut buf = Vec::new();
        let b = super::super::packet::PacketBuilder::short(
            &mut buf,
            &super::super::cid::ConnectionId::default(),
            false,
            654_360_564,
            3,
        );
        assert_eq!(buf, unhex("4200bff4"));
        buf.push(0x01);
        b.finish(&mut buf, &k.packet, &k.header);
        assert_eq!(buf, unhex("5558b1c60ae7b6b932bc27d786f4bc2bb20f2162ba"));
        assert_eq!(
            next_secret(&S, &secret, VERSION_2),
            unhex("c69374c49e3d2a9466fa689e49d476db5d0dfbc87d32ceeaa6343fd0ae4c7d88")
        );
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
        let a = OneRtt::new(s, vec![1; 32], vec![2; 32], 1);
        let mut b = OneRtt::new(s, vec![2; 32], vec![1; 32], 1);
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
