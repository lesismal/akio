//! ChaCha20, Poly1305 and the ChaCha20-Poly1305 AEAD (RFC 8439). All three are constant time by
//! construction (additions, rotations and XORs; Poly1305 uses 44-bit limbs and
//! multiplications only).
//!
//! ChaCha20 computes several blocks at once: eight with AVX2 on x86_64 (detected at run time, see
//! `hw`), else four in a lane-parallel layout that compilers map onto 128-bit vectors (SSE2,
//! NEON).
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

mod hw;

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

/// Four consecutive blocks (counters `input[12]` to `input[12] + 3`, which must not wrap), lane
/// parallel: word `j` of the four blocks sits in `s[j]`, so each step of a quarter round is one
/// 4-lane vector operation.
fn blocks4(input: &[u32; 16], out: &mut [u8; 256]) {
    let mut s = [[0u32; 4]; 16];
    for (s, i) in s.iter_mut().zip(input) {
        *s = [*i; 4];
    }
    for (l, c) in s[12].iter_mut().enumerate() {
        *c = input[12].wrapping_add(l as u32);
    }
    let init = s;
    #[inline(always)]
    fn add(s: &mut [[u32; 4]; 16], x: usize, y: usize) {
        let t = s[y];
        for (a, b) in s[x].iter_mut().zip(t) {
            *a = a.wrapping_add(b);
        }
    }
    #[inline(always)]
    fn xor_rot(s: &mut [[u32; 4]; 16], x: usize, y: usize, r: u32) {
        let t = s[y];
        for (a, b) in s[x].iter_mut().zip(t) {
            *a = (*a ^ b).rotate_left(r);
        }
    }
    #[inline(always)]
    fn quarter4(s: &mut [[u32; 4]; 16], a: usize, b: usize, c: usize, d: usize) {
        add(s, a, b);
        xor_rot(s, d, a, 16);
        add(s, c, d);
        xor_rot(s, b, c, 12);
        add(s, a, b);
        xor_rot(s, d, a, 8);
        add(s, c, d);
        xor_rot(s, b, c, 7);
    }
    for _ in 0..10 {
        quarter4(&mut s, 0, 4, 8, 12);
        quarter4(&mut s, 1, 5, 9, 13);
        quarter4(&mut s, 2, 6, 10, 14);
        quarter4(&mut s, 3, 7, 11, 15);
        quarter4(&mut s, 0, 5, 10, 15);
        quarter4(&mut s, 1, 6, 11, 12);
        quarter4(&mut s, 2, 7, 8, 13);
        quarter4(&mut s, 3, 4, 9, 14);
    }
    for (j, (w, i)) in s.iter().zip(&init).enumerate() {
        for l in 0..4 {
            let o = 64 * l + 4 * j;
            out[o..o + 4].copy_from_slice(&w[l].wrapping_add(i[l]).to_le_bytes());
        }
    }
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
        // Eight blocks at a time on AVX2, four at a time otherwise, while the counter cannot
        // wrap inside the group (the single-block path below handles the wrap and exhaustion).
        let mut done = 0;
        if !self.exhausted && hw::enabled() {
            for c in data.chunks_exact_mut(512) {
                let c: &mut [u8; 512] = c.try_into().unwrap_or_else(|_| unreachable!());
                if self.state[12] > u32::MAX - 8 || !hw::xor8(&self.state, c) {
                    break;
                }
                self.state[12] += 8;
                done += 512;
            }
        }
        let data = &mut data[done..];
        let mut done = 0;
        if !self.exhausted {
            for c in data.chunks_exact_mut(256) {
                if self.state[12] > u32::MAX - 4 {
                    break;
                }
                let mut ks = [0u8; 256];
                blocks4(&self.state, &mut ks);
                self.state[12] += 4;
                for (d, k) in c.iter_mut().zip(ks) {
                    *d ^= k;
                }
                done += 256;
            }
        }
        let data = &mut data[done..];
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
    /// `r` in 44/44/42-bit limbs.
    r: [u64; 3],
    /// `s` as two 64-bit words.
    s: [u64; 2],
    /// The accumulator in 44/44/42-bit limbs (partially reduced).
    h: [u64; 3],
    buf: [u8; 16],
    pos: usize,
}

impl std::fmt::Debug for Poly1305 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Poly1305").finish_non_exhaustive()
    }
}

const M44: u64 = 0xfff_ffff_ffff;
const M42: u64 = 0x3ff_ffff_ffff;

#[inline(always)]
fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// `h + m` for a 16-byte block `m` with the high bit `hibit` (`1 << 40` for a full block), in
/// 44/44/42-bit limbs.
#[inline(always)]
fn add_block(h: [u64; 3], m: &[u8], hibit: u64) -> [u64; 3] {
    let t0 = le64(&m[0..]);
    let t1 = le64(&m[8..]);
    [
        h[0] + (t0 & M44),
        h[1] + (((t0 >> 44) | (t1 << 20)) & M44),
        h[2] + (((t1 >> 24) & M42) | hibit),
    ]
}

/// Carries the product limbs `d` back to 44/44/42 bits (partially reduced: `h0` may exceed 2⁴⁴
/// slightly), folding the top through `2¹³⁰ ≡ 5`.
#[inline(always)]
fn carry(d: [u128; 3]) -> [u64; 3] {
    let [d0, mut d1, mut d2] = d;
    let mut c = (d0 >> 44) as u64;
    let mut h0 = d0 as u64 & M44;
    d1 += u128::from(c);
    c = (d1 >> 44) as u64;
    let mut h1 = d1 as u64 & M44;
    d2 += u128::from(c);
    c = (d2 >> 42) as u64;
    let h2 = d2 as u64 & M42;
    h0 += c * 5;
    c = h0 >> 44;
    h0 &= M44;
    h1 += c;
    [h0, h1, h2]
}

impl Poly1305 {
    /// A Poly1305 instance keyed with the one-time key `key` (`r` then `s`).
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        // poly1305-donna-64: r clamped and split into 44/44/42-bit limbs.
        let t0 = le64(&key[0..]);
        let t1 = le64(&key[8..]);
        Poly1305 {
            r: [
                t0 & 0xffc_0fff_ffff,
                ((t0 >> 44) | (t1 << 20)) & 0xfff_ffc0_ffff,
                (t1 >> 24) & 0x00f_ffff_fc0f,
            ],
            s: [le64(&key[16..]), le64(&key[24..])],
            h: [0; 3],
            buf: [0; 16],
            pos: 0,
        }
    }

    /// Processes one 16-byte block; `hibit` is `1 << 40` for a full block, `0` for the final
    /// partial block (which carries its own `0x01` terminator).
    #[inline]
    fn block(&mut self, m: &[u8], hibit: u64) {
        let a = add_block(self.h, m, hibit);
        let r = self.r;
        let (s1, s2) = (r[1] * 20, r[2] * 20);
        let mm = |a: u64, b: u64| u128::from(a) * u128::from(b);
        // r1·20 and r2·20 fold the 2^130 ≡ 5 reduction into the products.
        self.h = carry([
            mm(a[0], r[0]) + mm(a[1], s2) + mm(a[2], s1),
            mm(a[0], r[1]) + mm(a[1], r[0]) + mm(a[2], s2),
            mm(a[0], r[2]) + mm(a[1], r[1]) + mm(a[2], r[0]),
        ]);
    }

    /// Two full blocks: `h = (h + m₁)·r² + m₂·r`, one carry chain for both (the two products
    /// are independent, which roughly doubles the throughput of the dependent chain).
    #[inline]
    fn blocks2(&mut self, m: &[u8], r2: &[u64; 3]) {
        let a = add_block(self.h, &m[..16], 1 << 40);
        let b = add_block([0; 3], &m[16..32], 1 << 40);
        let r = self.r;
        let (s1, s2) = (r[1] * 20, r[2] * 20);
        let (t1, t2) = (r2[1] * 20, r2[2] * 20);
        let mm = |a: u64, b: u64| u128::from(a) * u128::from(b);
        self.h = carry([
            mm(a[0], r2[0])
                + mm(a[1], t2)
                + mm(a[2], t1)
                + mm(b[0], r[0])
                + mm(b[1], s2)
                + mm(b[2], s1),
            mm(a[0], r2[1])
                + mm(a[1], r2[0])
                + mm(a[2], t2)
                + mm(b[0], r[1])
                + mm(b[1], r[0])
                + mm(b[2], s2),
            mm(a[0], r2[2])
                + mm(a[1], r2[1])
                + mm(a[2], r2[0])
                + mm(b[0], r[2])
                + mm(b[1], r[1])
                + mm(b[2], r[0]),
        ]);
    }

    /// `r²` (partially reduced limbs, below 2⁴⁵).
    fn r_squared(&self) -> [u64; 3] {
        let r = self.r;
        let (s1, s2) = (r[1] * 20, r[2] * 20);
        let mm = |a: u64, b: u64| u128::from(a) * u128::from(b);
        carry([
            mm(r[0], r[0]) + mm(r[1], s2) + mm(r[2], s1),
            mm(r[0], r[1]) + mm(r[1], r[0]) + mm(r[2], s2),
            mm(r[0], r[2]) + mm(r[1], r[1]) + mm(r[2], r[0]),
        ])
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
            self.block(&b, 1 << 40);
            self.pos = 0;
        }
        if data.len() >= 64 {
            let r2 = self.r_squared();
            let mut pairs = data.chunks_exact(32);
            for b in &mut pairs {
                self.blocks2(b, &r2);
            }
            data = pairs.remainder();
        }
        let mut chunks = data.chunks_exact(16);
        for b in &mut chunks {
            self.block(b, 1 << 40);
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
            self.block(&b, 1 << 40);
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
        let [mut h0, mut h1, mut h2] = self.h;
        // Full carry (twice: the first pass may leave h1 at 2^44).
        let mut c;
        for _ in 0..2 {
            c = h1 >> 44;
            h1 &= M44;
            h2 += c;
            c = h2 >> 42;
            h2 &= M42;
            h0 += c * 5;
            c = h0 >> 44;
            h0 &= M44;
            h1 += c;
        }
        c = h1 >> 44;
        h1 &= M44;
        h2 += c;

        // g = h + 5 - 2^130; use g if it did not go negative (constant-time select).
        let mut g0 = h0 + 5;
        c = g0 >> 44;
        g0 &= M44;
        let mut g1 = h1 + c;
        c = g1 >> 44;
        g1 &= M44;
        let g2 = (h2 + c).wrapping_sub(1 << 42);
        let mask = (g2 >> 63).wrapping_sub(1); // all ones if g2 did not underflow
        let nmask = !mask;
        h0 = (h0 & nmask) | (g0 & mask);
        h1 = (h1 & nmask) | (g1 & mask);
        h2 = (h2 & nmask) | (g2 & mask);

        // h + s mod 2^128.
        let [s0, s1] = self.s;
        h0 += s0 & M44;
        c = h0 >> 44;
        h0 &= M44;
        h1 += (((s0 >> 44) | (s1 << 20)) & M44) + c;
        c = h1 >> 44;
        h1 &= M44;
        h2 = (h2 + ((s1 >> 24) & M42) + c) & M42;
        let w0 = h0 | (h1 << 44);
        let w1 = (h1 >> 20) | (h2 << 24);

        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&w0.to_le_bytes());
        out[8..].copy_from_slice(&w1.to_le_bytes());
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

    /// The multi-block keystream paths match block-at-a-time generation, across counter values
    /// near the wrap-around and all lengths.
    #[test]
    fn multiblock_matches_single() {
        let key = [0x42u8; 32];
        let nonce = [7u8; 12];
        for (counter, len) in [
            (0u32, 3000usize),
            (5, 1),
            (9, 513),
            (u32::MAX - 20, 64 * 21),
        ] {
            let mut a = vec![0u8; len];
            ChaCha20::new(&key, &nonce, counter).apply_keystream(&mut a);
            let mut c = ChaCha20::new(&key, &nonce, counter);
            let mut b = Vec::new();
            while b.len() < len {
                b.extend_from_slice(&c.next_block());
            }
            b.truncate(len);
            assert_eq!(a, b, "counter {counter} len {len}");
        }
        // Portable 4-block function against the single-block one.
        let mut st = ChaCha20::new(&key, &nonce, 77).state;
        let mut four = [0u8; 256];
        blocks4(&st, &mut four);
        for i in 0..4 {
            assert_eq!(four[64 * i..64 * i + 64], block(&st));
            st[12] += 1;
        }
    }

    /// Poly1305 edge cases (RFC 8439 appendix A.3, tests 5-7 and 11: carries around 2^130 - 5).
    #[test]
    fn poly1305_edges() {
        let mut key = [0u8; 32];
        key[0] = 2;
        // Test 5: r = 2, s = 0, m = 2^128 - 1 → tag 03 00..
        assert_eq!(Poly1305::mac(&key, &[0xff; 16])[0], 3);
        // Test 6: r = 2, s = 2^128 - 1 (all ones), m = 2 → tag 03 00..
        let mut k6 = key;
        k6[16..].fill(0xff);
        let mut m6 = [0u8; 16];
        m6[0] = 2;
        let mut want = [0u8; 16];
        want[0] = 3;
        assert_eq!(Poly1305::mac(&k6, &m6), want);
        // Test 7: r = 1, m = ff..ff | f0 ff..ff | 11 00..00 → tag 05 00..
        let mut k7 = [0u8; 32];
        k7[0] = 1;
        let mut m7 = vec![0xffu8; 16];
        m7.extend_from_slice(&[0xf0; 1]);
        m7.extend_from_slice(&[0xff; 15]);
        m7.push(0x11);
        m7.extend_from_slice(&[0; 15]);
        let mut want = [0u8; 16];
        want[0] = 5;
        assert_eq!(Poly1305::mac(&k7, &m7), want);
    }

    /// The two-block path matches one block at a time.
    #[test]
    fn poly1305_pairs() {
        let mut rng = crate::rand::ChaChaRng::from_seed([13; 32]);
        for len in [0usize, 15, 16, 31, 32, 63, 64, 65, 100, 1000] {
            let mut key = [0u8; 32];
            rng.fill(&mut key);
            let mut msg = vec![0u8; len];
            rng.fill(&mut msg);
            let mut one = Poly1305::new(&key);
            for b in msg.chunks(16) {
                one.update(b);
            }
            assert_eq!(Poly1305::mac(&key, &msg), one.finalize(), "len {len}");
        }
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
