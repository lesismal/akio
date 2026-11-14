//! AES-128, AES-192 and AES-256 (FIPS 197) in constant time, and CTR mode (NIST SP 800-38A).
//!
//! On x86_64 with AES-NI and on aarch64 with the ARMv8 AES instructions (detected at run time),
//! the CPU's instructions do the work. Elsewhere the block cipher is the fixsliced software AES of
//! Adomnicai and Peyrin ("Fixslicing AES-like ciphers", TCHES 2021), adapted from the RustCrypto
//! `aes` crate's `soft` backend: the S-box is a Boolean circuit over bitsliced state, so there are
//! no secret-dependent memory accesses or branches. It processes four blocks at once;
//! [`Aes::encrypt_blocks`] and CTR use that, a single block costs as much as four. Both paths are
//! constant time. On the hardware path CTR mode keeps eight blocks in flight.
//!
//! ```
//! use only_crypto::aes::Aes;
//!
//! // FIPS 197 appendix C.1.
//! let aes = Aes::new(&(0u8..16).collect::<Vec<_>>()).unwrap();
//! let mut b = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
//!     0xdd, 0xee, 0xff];
//! aes.encrypt_block(&mut b);
//! assert_eq!(b[..4], [0x69, 0xc4, 0xe0, 0xd8]);
//! aes.decrypt_block(&mut b);
//! assert_eq!(b[..4], [0x00, 0x11, 0x22, 0x33]);
//! ```

#[allow(
    clippy::unreadable_literal,
    clippy::many_single_char_names,
    clippy::needless_range_loop,
    clippy::similar_names,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]
mod fixslice;
mod hw;

use fixslice::BatchBlocks;

use crate::Error;

#[derive(Clone)]
enum Keys {
    A128([u64; 88]),
    A192([u64; 104]),
    A256([u64; 120]),
    /// The CPU's AES instructions (`hw`), with the key length.
    Hw(Box<hw::Keys>, usize),
}

/// An AES key schedule for a 16-, 24- or 32-byte key (AES-128, AES-192, AES-256).
#[derive(Clone)]
pub struct Aes(Keys);

impl std::fmt::Debug for Aes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aes")
            .field("key_len", &self.key_len())
            .finish_non_exhaustive()
    }
}

impl Aes {
    /// The key schedule of `key`; fails with [`Error::InvalidLength`] unless it has 16, 24 or 32
    /// bytes.
    pub fn new(key: &[u8]) -> Result<Aes, Error> {
        match key.len() {
            16 => key.try_into().map(Aes::new128),
            24 => key.try_into().map(Aes::new192),
            32 => key.try_into().map(Aes::new256),
            _ => return Err(Error::InvalidLength),
        }
        .map_err(|_| Error::InvalidLength)
    }

    /// The CPU's AES instructions for `key` when it has them.
    fn hw(key: &[u8]) -> Option<Aes> {
        hw::Keys::new(key).map(|k| Aes(Keys::Hw(Box::new(k), key.len())))
    }

    /// AES-128 with a 16-byte key.
    #[must_use]
    pub fn new128(key: &[u8; 16]) -> Aes {
        Self::hw(key).unwrap_or_else(|| Aes(Keys::A128(fixslice::aes128_key_schedule(key))))
    }

    /// AES-192 with a 24-byte key.
    #[must_use]
    pub fn new192(key: &[u8; 24]) -> Aes {
        Self::hw(key).unwrap_or_else(|| Aes(Keys::A192(fixslice::aes192_key_schedule(key))))
    }

    /// AES-256 with a 32-byte key.
    #[must_use]
    pub fn new256(key: &[u8; 32]) -> Aes {
        Self::hw(key).unwrap_or_else(|| Aes(Keys::A256(fixslice::aes256_key_schedule(key))))
    }

    /// The portable fixsliced implementation even when the CPU has AES instructions (for tests
    /// and benchmarks).
    #[doc(hidden)]
    pub fn new_portable(key: &[u8]) -> Result<Aes, Error> {
        Ok(Aes(match key.len() {
            16 => Keys::A128(fixslice::aes128_key_schedule(
                key.try_into().map_err(|_| Error::InvalidLength)?,
            )),
            24 => Keys::A192(fixslice::aes192_key_schedule(
                key.try_into().map_err(|_| Error::InvalidLength)?,
            )),
            32 => Keys::A256(fixslice::aes256_key_schedule(
                key.try_into().map_err(|_| Error::InvalidLength)?,
            )),
            _ => return Err(Error::InvalidLength),
        }))
    }

    /// Whether this key schedule uses the CPU's AES instructions (AES-NI, ARMv8 AES) rather than
    /// the portable implementation.
    #[doc(hidden)]
    #[must_use]
    pub fn is_hardware(&self) -> bool {
        matches!(self.0, Keys::Hw(..))
    }

    /// The round keys of the hardware path (`None` on the portable path): only constructed when
    /// the CPU has AES instructions.
    pub(crate) fn hw_round_keys(&self) -> Option<(&[[u8; 16]; 15], usize)> {
        match &self.0 {
            Keys::Hw(k, _) => Some(k.enc_keys()),
            _ => None,
        }
    }

    /// The key length in bytes: 16, 24 or 32.
    #[must_use]
    pub fn key_len(&self) -> usize {
        match self.0 {
            Keys::A128(_) => 16,
            Keys::A192(_) => 24,
            Keys::A256(_) => 32,
            Keys::Hw(_, n) => n,
        }
    }

    #[inline]
    fn enc4(&self, b: &BatchBlocks) -> BatchBlocks {
        match &self.0 {
            Keys::A128(k) => fixslice::aes128_encrypt(k, b),
            Keys::A192(k) => fixslice::aes192_encrypt(k, b),
            Keys::A256(k) => fixslice::aes256_encrypt(k, b),
            Keys::Hw(k, _) => {
                let mut b = *b;
                k.encrypt4(&mut b);
                b
            }
        }
    }

    #[inline]
    fn dec4(&self, b: &BatchBlocks) -> BatchBlocks {
        match &self.0 {
            Keys::A128(k) => fixslice::aes128_decrypt(k, b),
            Keys::A192(k) => fixslice::aes192_decrypt(k, b),
            Keys::A256(k) => fixslice::aes256_decrypt(k, b),
            Keys::Hw(k, _) => {
                let mut b = *b;
                k.decrypt4(&mut b);
                b
            }
        }
    }

    /// Encrypts one block in place.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        match &self.0 {
            Keys::Hw(k, _) => k.encrypt1(block),
            _ => *block = self.enc4(&[*block, [0; 16], [0; 16], [0; 16]])[0],
        }
    }

    /// Decrypts one block in place.
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        match &self.0 {
            Keys::Hw(k, _) => k.decrypt1(block),
            _ => *block = self.dec4(&[*block, [0; 16], [0; 16], [0; 16]])[0],
        }
    }

    /// Encrypts blocks in place (ECB), four at a time.
    pub fn encrypt_blocks(&self, blocks: &mut [[u8; 16]]) {
        self.each4(blocks, Aes::enc4);
    }

    /// Decrypts blocks in place (ECB), four at a time.
    pub fn decrypt_blocks(&self, blocks: &mut [[u8; 16]]) {
        self.each4(blocks, Aes::dec4);
    }

    fn each4(&self, blocks: &mut [[u8; 16]], f: fn(&Aes, &BatchBlocks) -> BatchBlocks) {
        let mut chunks = blocks.chunks_exact_mut(4);
        for c in &mut chunks {
            let out = f(self, &[c[0], c[1], c[2], c[3]]);
            c.copy_from_slice(&out);
        }
        let rest = chunks.into_remainder();
        if !rest.is_empty() {
            let mut b = [[0u8; 16]; 4];
            b[..rest.len()].copy_from_slice(rest);
            let out = f(self, &b);
            rest.copy_from_slice(&out[..rest.len()]);
        }
    }

    /// XORs `data` with the CTR keystream that starts at the counter block `counter` and
    /// increments the whole block as a 128-bit big-endian integer (SP 800-38A; SRTP AES-CM,
    /// SRT). Encryption and decryption are the same operation.
    pub fn apply_ctr(&self, counter: &[u8; 16], data: &mut [u8]) {
        let c = u128::from_be_bytes(*counter);
        self.ctr_with(data, |i| c.wrapping_add(i).to_be_bytes());
    }

    /// CTR with a 32-bit big-endian counter in the last four bytes (GCM's `inc32`).
    pub(crate) fn apply_ctr32(&self, counter: &[u8; 16], data: &mut [u8]) {
        let base = *counter;
        let c = u32::from_be_bytes([base[12], base[13], base[14], base[15]]);
        self.ctr_with(data, |i| {
            let mut b = base;
            b[12..].copy_from_slice(&c.wrapping_add(i as u32).to_be_bytes());
            b
        });
    }

    #[inline]
    fn ctr_with(&self, data: &mut [u8], block: impl Fn(u128) -> [u8; 16]) {
        if let Keys::Hw(k, _) = &self.0 {
            let mut i: u128 = 0;
            k.ctr(data, || {
                let b = block(i);
                i += 1;
                b
            });
            return;
        }
        let mut i: u128 = 0;
        for chunk in data.chunks_mut(64) {
            let ks = self.enc4(&[block(i), block(i + 1), block(i + 2), block(i + 3)]);
            i += 4;
            for (d, k) in chunk.iter_mut().zip(ks.iter().flatten()) {
                *d ^= k;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// FIPS 197 appendix C.
    #[test]
    fn fips197() {
        let pt: [u8; 16] = unhex("00112233445566778899aabbccddeeff")
            .try_into()
            .unwrap();
        for (key, ct) in [
            (
                "000102030405060708090a0b0c0d0e0f",
                "69c4e0d86a7b0430d8cdb78070b4c55a",
            ),
            (
                "000102030405060708090a0b0c0d0e0f1011121314151617",
                "dda97ca4864cdfe06eaf70a0ec0d7191",
            ),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "8ea2b7ca516745bfeafc49904b496089",
            ),
        ] {
            for aes in [
                Aes::new(&unhex(key)).unwrap(),
                Aes::new_portable(&unhex(key)).unwrap(),
            ] {
                let mut b = pt;
                aes.encrypt_block(&mut b);
                assert_eq!(b.to_vec(), unhex(ct));
                aes.decrypt_block(&mut b);
                assert_eq!(b, pt);
                let mut many = [pt; 7];
                aes.encrypt_blocks(&mut many);
                assert!(many.iter().all(|b| b.to_vec() == unhex(ct)));
                aes.decrypt_blocks(&mut many);
                assert_eq!(many, [pt; 7]);
            }
        }
        assert_eq!(Aes::new(&[0; 15]).unwrap_err(), Error::InvalidLength);
    }

    /// The hardware path (when this CPU has one) and the portable one agree.
    #[test]
    fn hardware_matches_portable() {
        let mut rng = crate::rand::ChaChaRng::from_seed([5; 32]);
        for i in 0..300 {
            let mut key = vec![0u8; [16, 24, 32][i % 3]];
            rng.fill(&mut key);
            let hw = Aes::new(&key).unwrap();
            let sw = Aes::new_portable(&key).unwrap();
            assert!(!sw.is_hardware());
            assert_eq!(hw.key_len(), sw.key_len());
            let mut blocks = [[0u8; 16]; 6];
            for b in &mut blocks {
                rng.fill(b);
            }
            let (mut a, mut b) = (blocks, blocks);
            hw.encrypt_blocks(&mut a);
            sw.encrypt_blocks(&mut b);
            assert_eq!(a, b);
            let mut c = blocks[0];
            hw.encrypt_block(&mut c);
            assert_eq!(c, a[0]);
            hw.decrypt_blocks(&mut a);
            sw.decrypt_blocks(&mut b);
            assert_eq!(a, blocks);
            assert_eq!(b, blocks);
            hw.decrypt_block(&mut c);
            assert_eq!(c, blocks[0]);
        }
        println!(
            "hardware AES: {}",
            Aes::new(&[0; 16]).unwrap().is_hardware()
        );
    }

    /// Hardware CTR (eight blocks per step) and portable CTR agree for every length.
    #[test]
    fn ctr_hardware_matches_portable() {
        let mut rng = crate::rand::ChaChaRng::from_seed([6; 32]);
        for i in 0..200 {
            let mut key = vec![0u8; [16, 24, 32][i % 3]];
            rng.fill(&mut key);
            let hw = Aes::new(&key).unwrap();
            let sw = Aes::new_portable(&key).unwrap();
            let mut ctr = [0u8; 16];
            rng.fill(&mut ctr);
            if i % 5 == 0 {
                ctr[8..].fill(0xff); // carries across the 64-bit and 32-bit boundaries
            }
            let mut data = vec![0u8; (i * 29) % 600];
            rng.fill(&mut data);
            let (mut a, mut b) = (data.clone(), data.clone());
            hw.apply_ctr(&ctr, &mut a);
            sw.apply_ctr(&ctr, &mut b);
            assert_eq!(a, b);
            let (mut a, mut b) = (data.clone(), data);
            hw.apply_ctr32(&ctr, &mut a);
            sw.apply_ctr32(&ctr, &mut b);
            assert_eq!(a, b);
        }
    }

    /// SP 800-38A F.5.1 (CTR-AES128.Encrypt).
    #[test]
    fn sp800_38a_ctr() {
        let aes = Aes::new(&unhex("2b7e151628aed2a6abf7158809cf4f3c")).unwrap();
        let ctr: [u8; 16] = unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
            .try_into()
            .unwrap();
        let mut data = unhex(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        );
        aes.apply_ctr(&ctr, &mut data);
        assert_eq!(
            data,
            unhex(
                "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff\
                 5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"
            )
        );
        // The counter wraps around the whole block.
        let mut a = [0u8; 40];
        aes.apply_ctr(&[0xff; 16], &mut a);
        let mut b = [0u8; 16];
        aes.encrypt_block(&mut b);
        assert_eq!(a[16..32], b);
    }
}
