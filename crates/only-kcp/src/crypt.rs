//! kcp-go's packet encryption: CFB block ciphers (AES) and its XOR table behind a random nonce
//! and a CRC32, "none" (nonce + CRC, clear), and AES-GCM.

use only_crypto::aes::Aes;
use only_crypto::crc::crc32;
use only_crypto::gcm::AesGcm;
use only_crypto::hash::Sha1;

pub(crate) const NONCE: usize = 16;
pub(crate) const CRC: usize = 4;
pub(crate) const HEADER: usize = NONCE + CRC;
const MAX_PACKET: usize = 1472;
const IV: [u8; 16] = [
    167, 115, 79, 156, 18, 172, 27, 1, 164, 21, 242, 193, 252, 120, 230, 107,
];
const SALT_XOR: &[u8] = b"sH3CIVoF#rWLtJo6";

enum Kind {
    None,
    Aes(Box<Aes>),
    Xor(Vec<u8>),
    Gcm(Box<AesGcm>),
}

/// A packet encryption scheme, as kcp-go names them.
pub struct Crypt(Kind);

impl std::fmt::Debug for Crypt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Crypt").finish_non_exhaustive()
    }
}

impl Crypt {
    /// `name` as kcptun spells it: `none`, `xor`, `aes` (32-byte key), `aes-128` (16),
    /// `aes-192` (24), `aes-128-gcm` (16). The key is already derived (kcptun uses
    /// PBKDF2-SHA1 of the passphrase with salt `kcp-go`, 4096 rounds, 32 bytes).
    ///
    /// Fails with `InvalidInput` for an unknown `name` or a short key.
    pub fn new(name: &str, key: &[u8]) -> std::io::Result<Crypt> {
        let need = |n: usize| {
            key.get(..n).ok_or_else(|| {
                crate::invalid_input(format!("crypt {name} needs a key of {n} bytes"))
            })
        };
        let bad = |e: only_crypto::Error| crate::invalid_input(e.to_string());
        Ok(Crypt(match name {
            "none" => Kind::None,
            "xor" => {
                let mut tbl = vec![0u8; MAX_PACKET];
                only_crypto::kdf::pbkdf2_hmac::<Sha1>(key, SALT_XOR, 32, &mut tbl);
                Kind::Xor(tbl)
            }
            "aes" => Kind::Aes(Box::new(Aes::new(need(32)?).map_err(bad)?)),
            "aes-192" => Kind::Aes(Box::new(Aes::new(need(24)?).map_err(bad)?)),
            "aes-128" => Kind::Aes(Box::new(Aes::new(need(16)?).map_err(bad)?)),
            "aes-128-gcm" => Kind::Gcm(Box::new(AesGcm::new(need(16)?).map_err(bad)?)),
            other => {
                return Err(crate::invalid_input(format!(
                    "crypt {other:?} is not supported"
                )));
            }
        }))
    }

    /// Bytes reserved before the payload.
    pub fn header(&self) -> usize {
        match self.0 {
            Kind::Gcm(_) => 12,
            _ => HEADER,
        }
    }

    /// Bytes the scheme appends after the payload (the AEAD tag).
    pub fn trailer(&self) -> usize {
        match self.0 {
            Kind::Gcm(_) => 16,
            _ => 0,
        }
    }

    /// Encrypts `b` in place (`header()` bytes reserved at its start) and returns the datagram.
    pub fn seal(&self, mut b: Vec<u8>) -> Vec<u8> {
        match &self.0 {
            Kind::Gcm(g) => {
                random(&mut b[..12]);
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&b[..12]);
                let tag = g.encrypt_in_place_detached(&nonce, b"", &mut b[12..]);
                b.extend_from_slice(&tag);
                b
            }
            kind => {
                random(&mut b[..NONCE]);
                let crc = crc32(&b[HEADER..]);
                b[NONCE..HEADER].copy_from_slice(&crc.to_le_bytes());
                match kind {
                    Kind::Aes(c) => cfb_encrypt(c, &mut b),
                    Kind::Xor(t) => b.iter_mut().zip(t).for_each(|(x, k)| *x ^= k),
                    _ => {}
                }
                b
            }
        }
    }

    /// Decrypts a datagram, returning what follows the crypt header, or `None` if it fails its
    /// check.
    pub fn open(&self, mut b: Vec<u8>) -> Option<Vec<u8>> {
        match &self.0 {
            Kind::Gcm(g) => {
                if b.len() < 12 + 16 {
                    return None;
                }
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&b[..12]);
                let mut body = b.split_off(12);
                g.decrypt_in_place(&nonce, b"", &mut body).ok()?;
                Some(body)
            }
            kind => {
                if b.len() < HEADER {
                    return None;
                }
                match kind {
                    Kind::Aes(c) => cfb_decrypt(c, &mut b),
                    Kind::Xor(t) => b.iter_mut().zip(t).for_each(|(x, k)| *x ^= k),
                    _ => {}
                }
                let crc = u32::from_le_bytes([b[NONCE], b[NONCE + 1], b[NONCE + 2], b[NONCE + 3]]);
                if crc32(&b[HEADER..]) != crc {
                    return None;
                }
                Some(b.split_off(HEADER))
            }
        }
    }
}

/// The nonce: OS randomness (a nonce only has to be unpredictable and, for GCM, unique). On the
/// never-expected failure of the OS generator a counter at least keeps nonces from repeating
/// within this process (the code on the RustCrypto crates sent zeros then).
fn random(b: &mut [u8]) {
    if only_crypto::rand::fill_random(b).is_err() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(1);
        let n = N.fetch_add(1, Ordering::Relaxed).to_le_bytes();
        for (x, y) in b.iter_mut().zip(n.iter().cycle()) {
            *x ^= y;
        }
    }
}

/// kcp-go's CFB: keystream from the encrypted IV, each full ciphertext block encrypted into the
/// next, a final partial block takes what it needs.
fn cfb_encrypt(c: &Aes, b: &mut [u8]) {
    let mut tbl = IV;
    c.encrypt_block(&mut tbl);
    let mut chunks = b.chunks_mut(16);
    for ch in &mut chunks {
        for (x, k) in ch.iter_mut().zip(tbl.iter()) {
            *x ^= k;
        }
        if ch.len() == 16 {
            tbl.copy_from_slice(ch);
            c.encrypt_block(&mut tbl);
        }
    }
}

/// CFB decryption: every keystream block is the encryption of a known ciphertext block (or the
/// IV), so the blocks are encrypted four at a time.
fn cfb_decrypt(c: &Aes, b: &mut [u8]) {
    let mut ks = [[0u8; 16]; 4];
    let mut prev = IV;
    for group in b.chunks_mut(64) {
        let mut n = 0;
        for (i, ch) in group.chunks(16).enumerate() {
            ks[i] = prev;
            if ch.len() == 16 {
                prev.copy_from_slice(ch);
            }
            n = i + 1;
        }
        c.encrypt_blocks(&mut ks[..n]);
        for (ch, k) in group.chunks_mut(16).zip(&ks) {
            for (x, k) in ch.iter_mut().zip(k) {
                *x ^= k;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_every_crypt() {
        for (name, key) in [
            ("none", &[][..]),
            ("xor", b"pass"),
            ("aes", &[7u8; 32]),
            ("aes-128", &[1u8; 16]),
            ("aes-192", &[2u8; 24]),
            ("aes-128-gcm", &[3u8; 16]),
        ] {
            let c = Crypt::new(name, key).unwrap();
            for len in [0usize, 1, 15, 16, 17, 100, 1400] {
                let mut b = vec![0u8; c.header()];
                let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
                b.extend_from_slice(&payload);
                let sealed = c.seal(b);
                assert_eq!(
                    c.open(sealed.clone()).as_deref(),
                    Some(&payload[..]),
                    "{name} {len}"
                );
                let mut bad = sealed;
                if let Some(x) = bad.last_mut() {
                    *x ^= 1;
                    if len > 0 || name == "aes-128-gcm" {
                        assert!(c.open(bad).is_none(), "{name} tamper");
                    }
                }
            }
        }
        assert!(Crypt::new("salsa20", b"k").is_err());
        assert!(Crypt::new("aes", &[1; 8]).is_err());
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Datagrams sealed by the implementation on the RustCrypto crates (before only-crypto):
    /// the wire format must not change.
    #[test]
    fn golden_datagrams() {
        let payload: Vec<u8> = (0..45u8).collect();
        for (name, key, sealed) in [
            (
                "none",
                &[][..],
                "61ae74e2a4cddef6efe5a297adeb7ca0c5f3bcd7000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c",
            ),
            (
                "xor",
                b"pass",
                "593bc4003b848af10853e1e4c7c9087c4f868cdc4fef2ef6122b7e63981ecf96006e5b32cc87c8ca1425088b4c2bb6445aab7f64ef8b42d7dc404213eb30bea14e",
            ),
            (
                "aes",
                &[7u8; 32],
                "ffb0eab454a7c60e99be59cf332941ff3460dc97f5d02f53756b89dba1413c2fe779a53116560b119c4e7b984e779a45a44572a4633b4dbb47136ad56255804983",
            ),
            (
                "aes-128",
                &[1u8; 16],
                "d1ea33f93eafcf28eeba1fe6420e096e3abef8b45b3492d36636ff303a411ca2ed2f528f0253a9062cc232deec17fd9be03de3c995901f61678b73203af62be0cf",
            ),
            (
                "aes-192",
                &[2u8; 24],
                "473fa3fafed5e049f608a0c69280772729d4747ba4806fe0c7db8a8d987566ba326f7c0401c3bd32ea515c2ffe6c7945cf5e5e760371423105421c225fea814b56",
            ),
            (
                "aes-128-gcm",
                &[3u8; 16],
                "feb40e1743b3b3a01f655dabe679137e4c5023ff23d9a6baa8cd55721ce685b47baa68a61ef313107096d71cab97f88a76698446e32183c8a5bad29b542c086bde9c2d95177c4fcd89",
            ),
        ] {
            let c = Crypt::new(name, key).unwrap();
            assert_eq!(
                c.open(unhex(sealed)).as_deref(),
                Some(&payload[..]),
                "{name}"
            );
        }
    }
}
