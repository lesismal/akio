//! ChaCha20, Poly1305 and the ChaCha20-Poly1305 AEAD (RFC 8439). All three are constant time by
//! construction (additions, rotations and XORs; Poly1305 uses 26-bit limbs and
//! multiplications only).
//!
//! ```
//! use only_crypto::chacha::ChaCha20Poly1305;
//!
//! let aead = ChaCha20Poly1305::new(&[7u8; 32]);
//! let nonce = [1u8; 12];
//! let sealed = aead.encrypt(&nonce, b"header", b"secret");
//! assert_eq!(aead.decrypt(&nonce, b"header", &sealed).unwrap(), b"secret");
//! ```

use crate::Error;

/// The key length in bytes.
pub const KEY_LEN: usize = 32;
/// The nonce length in bytes.
pub const NONCE_LEN: usize = 12;
/// The Poly1305 tag length in bytes.
pub const TAG_LEN: usize = 16;

#[inline(always)]
fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[inline(always)]
fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// The ChaCha20 block function (RFC 8439 section 2.3).
pub(crate) fn block(input: &[u32; 16]) -> [u8; 64] {
    let mut s = *input;
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for ((o, s), i) in out.chunks_exact_mut(4).zip(s).zip(input) {
        o.copy_from_slice(&s.wrapping_add(*i).to_le_bytes());
    }
    out
}

/// The ChaCha20 stream cipher with a 96-bit nonce and a 32-bit block counter (RFC 8439).
#[derive(Clone)]
pub struct ChaCha20 {
    state: [u32; 16],
    keystream: [u8; 64],
    /// Bytes of `keystream` already used (64: none left).
    used: usize,
    /// The counter wrapped: every keystream block has been used.
    exhausted: bool,
}

impl std::fmt::Debug for ChaCha20 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChaCha20").finish_non_exhaustive()
    }
}

impl ChaCha20 {
    /// A keystream for `key` and `nonce`, starting at block `counter`.
    #[must_use]
    pub fn new(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], counter: u32) -> Self {
        let mut state = [0u32; 16];
        state[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
        for (s, k) in state[4..12].iter_mut().zip(key.chunks_exact(4)) {
            *s = le32(k);
        }
        state[12] = counter;
        for (s, n) in state[13..].iter_mut().zip(nonce.chunks_exact(4)) {
            *s = le32(n);
        }
        ChaCha20 {
            state,
            keystream: [0; 64],
            used: 64,
            exhausted: false,
        }
    }

    fn next_block(&mut self) -> [u8; 64] {
        assert!(
            !self.exhausted,
            "ChaCha20 keystream exhausted (counter wrapped)"
        );
        let b = block(&self.state);
        self.state[12] = self.state[12].wrapping_add(1);
        self.exhausted = self.state[12] == 0;
        b
    }

    /// XORs `data` with the next bytes of the keystream. Encryption and decryption are the same
    /// operation; calls continue where the previous one stopped.
    ///
    /// # Panics
    ///
    /// When the 32-bit block counter would wrap (256 GiB from counter 0).
    pub fn apply_keystream(&mut self, mut data: &mut [u8]) {
        if self.used < 64 {
            let n = (64 - self.used).min(data.len());
            for (d, k) in data[..n].iter_mut().zip(&self.keystream[self.used..]) {
                *d ^= k;
            }
            self.used += n;
            data = &mut data[n..];
        }
        let mut chunks = data.chunks_exact_mut(64);
        for c in &mut chunks {
            let ks = self.next_block();
            for (d, k) in c.iter_mut().zip(ks) {
                *d ^= k;
            }
        }
        let rest = chunks.into_remainder();
        if !rest.is_empty() {
            self.keystream = self.next_block();
            for (d, k) in rest.iter_mut().zip(self.keystream) {
                *d ^= k;
            }
            self.used = rest.len();
        }
    }
}

/// The Poly1305 one-time authenticator (RFC 8439 section 2.5). A key must never authenticate two
/// messages.
#[derive(Clone)]
pub struct Poly1305 {
    r: [u32; 5],
    s: [u32; 4],
    h: [u32; 5],
    buf: [u8; 16],
    pos: usize,
}

impl std::fmt::Debug for Poly1305 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Poly1305").finish_non_exhaustive()
    }
}

const M26: u32 = 0x3ff_ffff;

impl Poly1305 {
    /// A Poly1305 instance keyed with the one-time key `key` (`r` then `s`).
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        Poly1305 {
            r: [
                le32(&key[0..]) & 0x3ff_ffff,
                (le32(&key[3..]) >> 2) & 0x3ff_ff03,
                (le32(&key[6..]) >> 4) & 0x3ff_c0ff,
                (le32(&key[9..]) >> 6) & 0x3f0_3fff,
                (le32(&key[12..]) >> 8) & 0x00f_ffff,
            ],
            s: [
                le32(&key[16..]),
                le32(&key[20..]),
                le32(&key[24..]),
                le32(&key[28..]),
            ],
            h: [0; 5],
            buf: [0; 16],
            pos: 0,
        }
    }

    /// Processes one 16-byte block; `hibit` is `1 << 24` for a full block, `0` for the final
    /// partial block (which carries its own `0x01` terminator).
    #[inline]
    fn block(&mut self, m: &[u8], hibit: u32) {
        let [r0, r1, r2, r3, r4] = self.r.map(u64::from);
        let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);
        let h = &mut self.h;
        let h0 = u64::from(h[0] + (le32(&m[0..]) & M26));
        let h1 = u64::from(h[1] + ((le32(&m[3..]) >> 2) & M26));
        let h2 = u64::from(h[2] + ((le32(&m[6..]) >> 4) & M26));
        let h3 = u64::from(h[3] + ((le32(&m[9..]) >> 6) & M26));
        let h4 = u64::from(h[4] + ((le32(&m[12..]) >> 8) | hibit));

        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        let mut c = d0 >> 26;
        h[0] = (d0 as u32) & M26;
        d1 += c;
        c = d1 >> 26;
        h[1] = (d1 as u32) & M26;
        d2 += c;
        c = d2 >> 26;
        h[2] = (d2 as u32) & M26;
        d3 += c;
        c = d3 >> 26;
        h[3] = (d3 as u32) & M26;
        d4 += c;
        c = d4 >> 26;
        h[4] = (d4 as u32) & M26;
        h[0] += (c as u32) * 5;
        let c = h[0] >> 26;
        h[0] &= M26;
        h[1] += c;
    }

    /// Absorbs `data`.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.pos > 0 {
            let n = (16 - self.pos).min(data.len());
            self.buf[self.pos..self.pos + n].copy_from_slice(&data[..n]);
            self.pos += n;
            data = &data[n..];
            if self.pos < 16 {
                return;
            }
            let b = self.buf;
            self.block(&b, 1 << 24);
            self.pos = 0;
        }
        let mut chunks = data.chunks_exact(16);
        for b in &mut chunks {
            self.block(b, 1 << 24);
        }
        let rest = chunks.remainder();
        self.buf[..rest.len()].copy_from_slice(rest);
        self.pos = rest.len();
    }

    /// Pads what was absorbed so far with zeros to a 16-byte boundary (the AEAD construction).
    fn pad16(&mut self) {
        if self.pos > 0 {
            self.buf[self.pos..].fill(0);
            let b = self.buf;
            self.block(&b, 1 << 24);
            self.pos = 0;
        }
    }

    /// Finishes and returns the tag.
    #[must_use]
    pub fn finalize(mut self) -> [u8; TAG_LEN] {
        if self.pos > 0 {
            self.buf[self.pos] = 1;
            self.buf[self.pos + 1..].fill(0);
            let b = self.buf;
            self.block(&b, 0);
        }
        let [mut h0, mut h1, mut h2, mut h3, mut h4] = self.h;
        let mut c = h1 >> 26;
        h1 &= M26;
        h2 += c;
        c = h2 >> 26;
        h2 &= M26;
        h3 += c;
        c = h3 >> 26;
        h3 &= M26;
        h4 += c;
        c = h4 >> 26;
        h4 &= M26;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= M26;
        h1 += c;

        // g = h + 5 - 2^130; use g if it did not go negative.
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= M26;
        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= M26;
        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= M26;
        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= M26;
        let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        let mask = (g4 >> 31).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        let g4 = g4 & mask;
        let nmask = !mask;
        h0 = (h0 & nmask) | g0;
        h1 = (h1 & nmask) | g1;
        h2 = (h2 & nmask) | g2;
        h3 = (h3 & nmask) | g3;
        h4 = (h4 & nmask) | g4;

        let w0 = h0 | (h1 << 26);
        let w1 = (h1 >> 6) | (h2 << 20);
        let w2 = (h2 >> 12) | (h3 << 14);
        let w3 = (h3 >> 18) | (h4 << 8);

        let mut out = [0u8; 16];
        let mut f = u64::from(w0) + u64::from(self.s[0]);
        out[0..4].copy_from_slice(&(f as u32).to_le_bytes());
        f = u64::from(w1) + u64::from(self.s[1]) + (f >> 32);
        out[4..8].copy_from_slice(&(f as u32).to_le_bytes());
        f = u64::from(w2) + u64::from(self.s[2]) + (f >> 32);
        out[8..12].copy_from_slice(&(f as u32).to_le_bytes());
        f = u64::from(w3) + u64::from(self.s[3]) + (f >> 32);
        out[12..16].copy_from_slice(&(f as u32).to_le_bytes());
        out
    }

    /// The tag of `data` under the one-time key `key`.
    #[must_use]
    pub fn mac(key: &[u8; 32], data: &[u8]) -> [u8; TAG_LEN] {
        let mut p = Poly1305::new(key);
        p.update(data);
        p.finalize()
    }
}

/// The longest plaintext of one ChaCha20-Poly1305 message: 2^32 - 1 blocks of 64 bytes.
const MAX_LEN: u64 = ((1 << 32) - 1) * 64;

/// The ChaCha20-Poly1305 AEAD (RFC 8439 section 2.8).
#[derive(Clone)]
pub struct ChaCha20Poly1305 {
    key: [u8; KEY_LEN],
}

impl std::fmt::Debug for ChaCha20Poly1305 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChaCha20Poly1305").finish_non_exhaustive()
    }
}

impl ChaCha20Poly1305 {
    /// An AEAD key.
    #[must_use]
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        ChaCha20Poly1305 { key: *key }
    }

    /// The cipher at block 1 and the Poly1305 instance keyed from block 0.
    fn start(&self, nonce: &[u8; NONCE_LEN]) -> (ChaCha20, Poly1305) {
        let mut c = ChaCha20::new(&self.key, nonce, 0);
        let mut otk = [0u8; 64];
        c.apply_keystream(&mut otk);
        let mut k = [0u8; 32];
        k.copy_from_slice(&otk[..32]);
        (c, Poly1305::new(&k))
    }

    fn tag(mut p: Poly1305, aad: &[u8], ct: &[u8]) -> [u8; TAG_LEN] {
        p.update(aad);
        p.pad16();
        p.update(ct);
        p.pad16();
        p.update(&(aad.len() as u64).to_le_bytes());
        p.update(&(ct.len() as u64).to_le_bytes());
        p.finalize()
    }

    /// Encrypts `buf` in place and returns the tag.
    ///
    /// # Panics
    ///
    /// If `buf` is longer than the construction allows (256 GiB).
    pub fn encrypt_in_place_detached(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
    ) -> [u8; TAG_LEN] {
        assert!(
            buf.len() as u64 <= MAX_LEN,
            "ChaCha20-Poly1305: plaintext too long"
        );
        let (mut c, p) = self.start(nonce);
        c.apply_keystream(buf);
        Self::tag(p, aad, buf)
    }

    /// Verifies `tag` and decrypts `buf` in place. On failure ([`Error::Verification`], or
    /// [`Error::InvalidLength`] for a tag that is not 16 bytes) `buf` is left as it was.
    pub fn decrypt_in_place_detached(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        if tag.len() != TAG_LEN {
            return Err(Error::InvalidLength);
        }
        if buf.len() as u64 > MAX_LEN {
            return Err(Error::Verification);
        }
        let (mut c, p) = self.start(nonce);
        if !crate::ct_eq(&Self::tag(p, aad, buf), tag) {
            return Err(Error::Verification);
        }
        c.apply_keystream(buf);
        Ok(())
    }

    /// Encrypts `buf` in place and appends the tag.
    pub fn encrypt_in_place(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut Vec<u8>) {
        let tag = self.encrypt_in_place_detached(nonce, aad, buf);
        buf.extend_from_slice(&tag);
    }

    /// Verifies and decrypts `buf` (ciphertext followed by the tag) in place, removing the tag.
    /// On failure `buf` is left as it was.
    pub fn decrypt_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let n = buf.len().checked_sub(TAG_LEN).ok_or(Error::Verification)?;
        let (ct, tag) = buf.split_at_mut(n);
        let tag: [u8; TAG_LEN] = (&*tag).try_into().map_err(|_| Error::Verification)?;
        self.decrypt_in_place_detached(nonce, aad, ct, &tag)?;
        buf.truncate(n);
        Ok(())
    }

    /// Returns the ciphertext of `plaintext` followed by the tag.
    #[must_use]
    pub fn encrypt(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(plaintext.len() + TAG_LEN);
        v.extend_from_slice(plaintext);
        self.encrypt_in_place(nonce, aad, &mut v);
        v
    }

    /// Verifies and decrypts `ciphertext` (followed by the tag).
    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut v = ciphertext.to_vec();
        self.decrypt_in_place(nonce, aad, &mut v)?;
        Ok(v)
    }
}

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

    /// RFC 8439 section 2.4.2.
    #[test]
    fn chacha20_rfc8439() {
        let key: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
        let nonce = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let mut data = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        let mut c = ChaCha20::new(&key, &nonce, 1);
        // Split across calls to exercise the keystream buffer.
        let (a, b) = data.split_at_mut(7);
        c.apply_keystream(a);
        c.apply_keystream(b);
        assert_eq!(
            data,
            unhex(
                "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b
                 f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8
                 07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736
                 5af90bbf74a35be6b40b8eedf2785e42874d"
            )
        );
    }

    /// RFC 8439 section 2.5.2.
    #[test]
    fn poly1305_rfc8439() {
        let key: [u8; 32] =
            unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
                .try_into()
                .unwrap();
        let tag = Poly1305::mac(&key, b"Cryptographic Forum Research Group");
        assert_eq!(tag.to_vec(), unhex("a8061dc1305136c6c22b8baf0c0127a9"));
        let mut p = Poly1305::new(&key);
        for b in b"Cryptographic Forum Research Group".chunks(5) {
            p.update(b);
        }
        assert_eq!(p.finalize(), tag);
    }

    /// RFC 8439 section 2.8.2.
    #[test]
    fn aead_rfc8439() {
        let key: [u8; 32] =
            unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .try_into()
                .unwrap();
        let nonce: [u8; 12] = unhex("070000004041424344454647").try_into().unwrap();
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aead = ChaCha20Poly1305::new(&key);
        let sealed = aead.encrypt(&nonce, &aad, pt);
        let (ct, tag) = sealed.split_at(pt.len());
        assert_eq!(
            ct,
            unhex(
                "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6
                 3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36
                 92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc
                 3ff4def08e4b7a9de576d26586cec64b6116"
            )
        );
        assert_eq!(tag, unhex("1ae10b594f09e26a7e902ecbd0600691"));
        assert_eq!(aead.decrypt(&nonce, &aad, &sealed).unwrap(), pt);
        let mut bad = sealed.clone();
        bad[0] ^= 1;
        assert_eq!(aead.decrypt(&nonce, &aad, &bad), Err(Error::Verification));
    }
}
