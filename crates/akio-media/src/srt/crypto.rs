//! SRT encryption (section 6): keying material messages, the RFC 3394 key wrap under a
//! PBKDF2-HMAC-SHA1 key encrypting key, and AES-CTR payload encryption.

use super::packet::{KK_EVEN, KK_ODD};

pub(crate) const KM_HEADER_SIZE: usize = 16;
const KM_SALT_SIZE: usize = 16;
const KM_SIGN: u16 = 0x2029;
const KM_CIPHER_CTR: u8 = 2;
const KM_SE: u8 = 2;
const PBKDF2_ITER: u32 = 2048;

pub(crate) const KM_STATE_BADSECRET: u32 = 4;

/// AES with any of the three key sizes.
#[derive(Clone, Debug)]
pub(crate) struct Aes(akio_crypto::aes::Aes);

impl Aes {
    pub(crate) fn new(key: &[u8]) -> Option<Aes> {
        akio_crypto::aes::Aes::new(key).ok().map(Aes)
    }

    fn encrypt(&self, b: &mut [u8; 16]) {
        self.0.encrypt_block(b);
    }

    fn decrypt(&self, b: &mut [u8; 16]) {
        self.0.decrypt_block(b);
    }

    /// XORs `data` with the CTR keystream starting at counter block `iv` (128-bit big-endian
    /// increment).
    fn ctr(&self, iv: [u8; 16], data: &mut [u8]) {
        self.0.apply_ctr(&iv, data);
    }
}

/// The keys of a connection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct KeyMaterial {
    pub(crate) salt: [u8; KM_SALT_SIZE],
    pub(crate) key_len: usize,
    pub(crate) even: Option<Vec<u8>>,
    pub(crate) odd: Option<Vec<u8>>,
    /// The key encrypting key derived from the passphrase.
    pub(crate) kek: Vec<u8>,
}

/// Why keying material was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KmError {
    Malformed,
    BadSecret,
}

pub(crate) fn random(buf: &mut [u8]) {
    if akio_crypto::rand::fill_random(buf).is_err() {
        // No OS randomness: still produce distinct values (not secure, never expected).
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (t >> ((i % 16) * 8)) as u8 ^ (i as u8).wrapping_mul(151);
        }
    }
}

pub(crate) fn derive_kek(passphrase: &str, salt: &[u8; KM_SALT_SIZE], key_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; key_len];
    akio_crypto::kdf::pbkdf2_hmac::<akio_crypto::hash::Sha1>(
        passphrase.as_bytes(),
        &salt[KM_SALT_SIZE - 8..],
        PBKDF2_ITER,
        &mut out,
    );
    out
}

impl KeyMaterial {
    /// Fresh random salt and even key.
    pub(crate) fn generate(key_len: usize, passphrase: &str) -> KeyMaterial {
        let mut km = KeyMaterial {
            key_len,
            even: Some(vec![0; key_len]),
            ..KeyMaterial::default()
        };
        random(&mut km.salt);
        if let Some(k) = km.even.as_mut() {
            random(k);
        }
        km.kek = derive_kek(passphrase, &km.salt, key_len);
        km
    }

    /// The KMREQ / KMRSP message.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut kk = 0;
        let mut keys = Vec::new();
        if let Some(e) = &self.even {
            kk |= KK_EVEN;
            keys.extend_from_slice(e);
        }
        if let Some(o) = &self.odd {
            kk |= KK_ODD;
            keys.extend_from_slice(o);
        }
        let wrapped = key_wrap(&self.kek, &keys).unwrap_or_default();
        let mut b = vec![0x12];
        b.extend_from_slice(&KM_SIGN.to_be_bytes());
        b.push(kk);
        b.extend_from_slice(&[0, 0, 0, 0]); // KEKI
        b.extend_from_slice(&[
            KM_CIPHER_CTR,
            0,
            KM_SE,
            0,
            0,
            0,
            (KM_SALT_SIZE / 4) as u8,
            (self.key_len / 4) as u8,
        ]);
        b.extend_from_slice(&self.salt);
        b.extend_from_slice(&wrapped);
        b
    }

    /// Parses a KM message, deriving the KEK with `kek(salt, key_len)`.
    pub(crate) fn decode(
        b: &[u8],
        kek: impl FnOnce(&[u8; KM_SALT_SIZE], usize) -> Vec<u8>,
    ) -> Result<KeyMaterial, KmError> {
        if b.len() < KM_HEADER_SIZE + KM_SALT_SIZE
            || b[0] != 0x12
            || u16::from_be_bytes([b[1], b[2]]) != KM_SIGN
        {
            return Err(KmError::Malformed);
        }
        let kk = b[3] & 3;
        if kk == 0 || b[8] != KM_CIPHER_CTR || usize::from(b[14]) * 4 != KM_SALT_SIZE {
            return Err(KmError::Malformed);
        }
        let key_len = usize::from(b[15]) * 4;
        if !matches!(key_len, 16 | 24 | 32) {
            return Err(KmError::Malformed);
        }
        let mut salt = [0u8; KM_SALT_SIZE];
        salt.copy_from_slice(&b[KM_HEADER_SIZE..KM_HEADER_SIZE + KM_SALT_SIZE]);
        let n = if kk == KK_EVEN | KK_ODD { 2 } else { 1 };
        let wrapped = b
            .get(KM_HEADER_SIZE + KM_SALT_SIZE..KM_HEADER_SIZE + KM_SALT_SIZE + 8 + n * key_len)
            .ok_or(KmError::Malformed)?;
        let k = kek(&salt, key_len);
        let keys = key_unwrap(&k, wrapped)?;
        let mut km = KeyMaterial {
            salt,
            key_len,
            kek: k,
            ..KeyMaterial::default()
        };
        let mut rest = &keys[..];
        if kk & KK_EVEN != 0 {
            km.even = Some(rest[..key_len].to_vec());
            rest = &rest[key_len..];
        }
        if kk & KK_ODD != 0 {
            km.odd = Some(rest[..key_len].to_vec());
        }
        Ok(km)
    }
}

const WRAP_IV: [u8; 8] = [0xa6; 8];

pub(crate) fn key_wrap(kek: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let aes = Aes::new(kek)?;
    if key.len() % 8 != 0 || key.is_empty() {
        return None;
    }
    let n = key.len() / 8;
    let mut a = WRAP_IV;
    let mut r = key.to_vec();
    for j in 0..6 {
        for i in 1..=n {
            let mut buf = [0u8; 16];
            buf[..8].copy_from_slice(&a);
            buf[8..].copy_from_slice(&r[8 * (i - 1)..8 * i]);
            aes.encrypt(&mut buf);
            let t = (n * j + i) as u64;
            let v = u64::from_be_bytes(buf[..8].try_into().unwrap_or([0; 8])) ^ t;
            a = v.to_be_bytes();
            r[8 * (i - 1)..8 * i].copy_from_slice(&buf[8..]);
        }
    }
    let mut out = a.to_vec();
    out.extend_from_slice(&r);
    Some(out)
}

pub(crate) fn key_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, KmError> {
    if wrapped.len() < 24 || wrapped.len() % 8 != 0 {
        return Err(KmError::Malformed);
    }
    let aes = Aes::new(kek).ok_or(KmError::Malformed)?;
    let n = wrapped.len() / 8 - 1;
    let mut a = u64::from_be_bytes(wrapped[..8].try_into().map_err(|_| KmError::Malformed)?);
    let mut r = wrapped[8..].to_vec();
    for j in (0..6).rev() {
        for i in (1..=n).rev() {
            let t = (n * j + i) as u64;
            let mut buf = [0u8; 16];
            buf[..8].copy_from_slice(&(a ^ t).to_be_bytes());
            buf[8..].copy_from_slice(&r[8 * (i - 1)..8 * i]);
            aes.decrypt(&mut buf);
            a = u64::from_be_bytes(buf[..8].try_into().map_err(|_| KmError::Malformed)?);
            r[8 * (i - 1)..8 * i].copy_from_slice(&buf[8..]);
        }
    }
    // Constant time comparison of the integrity check value.
    let diff = a
        .to_be_bytes()
        .iter()
        .zip(WRAP_IV)
        .fold(0u8, |d, (x, y)| d | (x ^ y));
    if diff != 0 {
        return Err(KmError::BadSecret);
    }
    Ok(r)
}

/// Encrypts and decrypts payloads with the even and odd keys.
#[derive(Debug, Clone)]
pub(crate) struct Cryptor {
    salt: [u8; KM_SALT_SIZE],
    even: Option<Aes>,
    odd: Option<Aes>,
}

impl Cryptor {
    pub(crate) fn new(km: &KeyMaterial) -> Option<Cryptor> {
        let even = match &km.even {
            Some(k) => Some(Aes::new(k)?),
            None => None,
        };
        let odd = match &km.odd {
            Some(k) => Some(Aes::new(k)?),
            None => None,
        };
        Some(Cryptor {
            salt: km.salt,
            even,
            odd,
        })
    }

    /// XORs `data` (the payload of packet `seq`) with key `kk`; `false` without that key.
    pub(crate) fn xor(&self, kk: u8, seq: u32, data: &mut [u8]) -> bool {
        let Some(aes) = (if kk == KK_ODD { &self.odd } else { &self.even }) else {
            return false;
        };
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(&self.salt[..14]);
        for (i, b) in seq.to_be_bytes().iter().enumerate() {
            iv[10 + i] ^= b;
        }
        aes.ctr(iv, data);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3394_vector() {
        // RFC 3394 4.1: 128-bit key data with a 128-bit KEK.
        let kek: Vec<u8> = (0u8..16).collect();
        let key = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let w = key_wrap(&kek, &key).unwrap();
        assert_eq!(
            w,
            [
                0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47, 0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a,
                0x7b, 0x82, 0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5
            ]
        );
        assert_eq!(key_unwrap(&kek, &w).unwrap(), key);
        let mut bad = w;
        bad[3] ^= 1;
        assert_eq!(key_unwrap(&kek, &bad), Err(KmError::BadSecret));
    }

    #[test]
    fn km_round_trip_and_ctr() {
        for len in [16, 24, 32] {
            let km = KeyMaterial::generate(len, "0123456789secret");
            let msg = km.encode();
            let back =
                KeyMaterial::decode(&msg, |s, l| derive_kek("0123456789secret", s, l)).unwrap();
            assert_eq!(back, km);
            let wrong = KeyMaterial::decode(&msg, |s, l| derive_kek("wrong passphrase", s, l));
            assert_eq!(wrong, Err(KmError::BadSecret));
            let c = Cryptor::new(&km).unwrap();
            let mut data = vec![7u8; 1316];
            assert!(c.xor(KK_EVEN, 42, &mut data));
            assert_ne!(data, vec![7u8; 1316]);
            assert!(!c.xor(KK_ODD, 42, &mut data));
            assert!(Cryptor::new(&back).unwrap().xor(KK_EVEN, 42, &mut data));
            assert_eq!(data, vec![7u8; 1316]);
        }
        assert_eq!(
            KeyMaterial::decode(&[0; 10], |_, _| vec![]),
            Err(KmError::Malformed)
        );
    }
}
