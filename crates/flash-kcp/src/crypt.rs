//! kcp-go's packet encryption: CFB block ciphers (AES) and its XOR table behind a random nonce
//! and a CRC32, "none" (nonce + CRC, clear), and AES-GCM.

use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes_gcm::{Aes128Gcm, aead::AeadInPlace};

pub(crate) const NONCE: usize = 16;
pub(crate) const CRC: usize = 4;
pub(crate) const HEADER: usize = NONCE + CRC;
const MAX_PACKET: usize = 1472;
const IV: [u8; 16] = [
    167, 115, 79, 156, 18, 172, 27, 1, 164, 21, 242, 193, 252, 120, 230, 107,
];
const SALT_XOR: &[u8] = b"sH3CIVoF#rWLtJo6";

enum AesAny {
    A128(aes::Aes128),
    A192(aes::Aes192),
    A256(aes::Aes256),
}

impl AesAny {
    fn encrypt(&self, b: &mut [u8; 16]) {
        let g = GenericArray::from_mut_slice(b);
        match self {
            AesAny::A128(c) => c.encrypt_block(g),
            AesAny::A192(c) => c.encrypt_block(g),
            AesAny::A256(c) => c.encrypt_block(g),
        }
    }
}

enum Kind {
    None,
    Aes(Box<AesAny>),
    Xor(Vec<u8>),
    Gcm(Box<Aes128Gcm>),
}

/// A packet encryption scheme, as kcp-go names them.
pub struct Crypt(Kind);

impl Crypt {
    /// `name` as kcptun spells it: `none`, `xor`, `aes` (32-byte key), `aes-128` (16),
    /// `aes-192` (24), `aes-128-gcm` (16). The key is already derived (kcptun uses
    /// PBKDF2-SHA1 of the passphrase with salt `kcp-go`, 4096 rounds, 32 bytes).
    pub fn new(name: &str, key: &[u8]) -> Result<Crypt, String> {
        let need = |n: usize| {
            key.get(..n)
                .ok_or_else(|| format!("crypt {name} needs a key of {n} bytes"))
        };
        Ok(Crypt(match name {
            "none" => Kind::None,
            "xor" => {
                let mut tbl = vec![0u8; MAX_PACKET];
                pbkdf2::pbkdf2_hmac::<sha1::Sha1>(key, SALT_XOR, 32, &mut tbl);
                Kind::Xor(tbl)
            }
            "aes" => Kind::Aes(Box::new(AesAny::A256(
                aes::Aes256::new_from_slice(need(32)?).map_err(|e| e.to_string())?,
            ))),
            "aes-192" => Kind::Aes(Box::new(AesAny::A192(
                aes::Aes192::new_from_slice(need(24)?).map_err(|e| e.to_string())?,
            ))),
            "aes-128" => Kind::Aes(Box::new(AesAny::A128(
                aes::Aes128::new_from_slice(need(16)?).map_err(|e| e.to_string())?,
            ))),
            "aes-128-gcm" => Kind::Gcm(Box::new(
                Aes128Gcm::new_from_slice(need(16)?).map_err(|e| e.to_string())?,
            )),
            other => return Err(format!("crypt {other:?} is not supported")),
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
                let _ = getrandom::getrandom(&mut b[..12]);
                let nonce = *aes_gcm::Nonce::from_slice(&b[..12]);
                let mut body = b.split_off(12);
                let _ = g.encrypt_in_place(&nonce, b"", &mut body);
                b.extend_from_slice(&body);
                b
            }
            kind => {
                let _ = getrandom::getrandom(&mut b[..NONCE]);
                let crc = crc32fast::hash(&b[HEADER..]);
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
                let nonce = *aes_gcm::Nonce::from_slice(&b[..12]);
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
                if crc32fast::hash(&b[HEADER..]) != crc {
                    return None;
                }
                Some(b.split_off(HEADER))
            }
        }
    }
}

/// kcp-go's CFB: keystream from the encrypted IV, each full ciphertext block encrypted into the
/// next, a final partial block takes what it needs.
fn cfb_encrypt(c: &AesAny, b: &mut [u8]) {
    let mut tbl = IV;
    c.encrypt(&mut tbl);
    let mut chunks = b.chunks_mut(16);
    for ch in &mut chunks {
        for (x, k) in ch.iter_mut().zip(tbl.iter()) {
            *x ^= k;
        }
        if ch.len() == 16 {
            tbl.copy_from_slice(ch);
            c.encrypt(&mut tbl);
        }
    }
}

fn cfb_decrypt(c: &AesAny, b: &mut [u8]) {
    let mut tbl = IV;
    c.encrypt(&mut tbl);
    for ch in b.chunks_mut(16) {
        let mut next = [0u8; 16];
        if ch.len() == 16 {
            next.copy_from_slice(ch);
            c.encrypt(&mut next);
        }
        for (x, k) in ch.iter_mut().zip(tbl.iter()) {
            *x ^= k;
        }
        tbl = next;
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
}
