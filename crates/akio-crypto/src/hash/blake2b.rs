//! BLAKE2b (RFC 7693): digests of 1 to 64 bytes, keyed (a MAC) or not. Argon2 (RFC 9106) is
//! built on it; [`Blake2b512`] is the 64-byte variant behind the [`Hash`](super::Hash) trait.
//!
//! Constant time by construction: 64-bit additions, rotations and XORs, no table indexed by the
//! data or the key.

use crate::Error;

const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// BLAKE2b with a digest of 1 to [`MAX_OUTPUT_LEN`](Self::MAX_OUTPUT_LEN) bytes, chosen when it
/// is made, and an optional key of up to [`MAX_KEY_LEN`](Self::MAX_KEY_LEN) bytes.
///
/// ```
/// use akio_crypto::hash::Blake2b;
///
/// let mut h = Blake2b::new(32).unwrap();
/// h.update(b"ab");
/// h.update(b"c");
/// let mut d = [0u8; 32];
/// h.finalize_into(&mut d).unwrap();
/// let mut one = [0u8; 32];
/// Blake2b::digest(&mut one, b"abc").unwrap();
/// assert_eq!(d, one);
/// ```
#[derive(Clone)]
pub struct Blake2b {
    h: [u64; 8],
    /// Bytes compressed so far (RFC 7693's `t`).
    t: u128,
    buf: [u8; 128],
    /// Bytes in `buf`. A full block stays buffered until more input comes, since the last block
    /// is compressed with the final flag.
    pos: usize,
    out_len: usize,
}

impl std::fmt::Debug for Blake2b {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Blake2b")
            .field("out_len", &self.out_len)
            .finish_non_exhaustive()
    }
}

impl Blake2b {
    /// The block size in bytes.
    pub const BLOCK_LEN: usize = 128;
    /// The longest digest, in bytes.
    pub const MAX_OUTPUT_LEN: usize = 64;
    /// The longest key, in bytes.
    pub const MAX_KEY_LEN: usize = 64;

    /// An unkeyed hasher whose digest is `out_len` bytes.
    ///
    /// Fails with [`Error::InvalidLength`] unless `out_len` is 1 to 64.
    pub fn new(out_len: usize) -> Result<Self, Error> {
        Self::new_keyed(&[], out_len)
    }

    /// A keyed hasher (BLAKE2b as a MAC) whose digest is `out_len` bytes.
    ///
    /// Fails with [`Error::InvalidLength`] unless `out_len` is 1 to 64 and `key` at most 64
    /// bytes.
    pub fn new_keyed(key: &[u8], out_len: usize) -> Result<Self, Error> {
        if out_len == 0 || out_len > Self::MAX_OUTPUT_LEN || key.len() > Self::MAX_KEY_LEN {
            return Err(Error::InvalidLength);
        }
        let mut h = IV;
        h[0] ^= 0x0101_0000 ^ ((key.len() as u64) << 8) ^ out_len as u64;
        let mut s = Blake2b {
            h,
            t: 0,
            buf: [0; 128],
            pos: 0,
            out_len,
        };
        if !key.is_empty() {
            s.buf[..key.len()].copy_from_slice(key);
            s.pos = Self::BLOCK_LEN;
        }
        Ok(s)
    }

    /// An unkeyed hasher of `out_len` bytes, `out_len` already known to be 1 to 64.
    pub(crate) fn with_len(out_len: usize) -> Self {
        debug_assert!((1..=Self::MAX_OUTPUT_LEN).contains(&out_len));
        Self::new(out_len.clamp(1, Self::MAX_OUTPUT_LEN)).unwrap_or_else(|_| unreachable!())
    }

    /// The digest length this hasher was made with.
    #[must_use]
    pub fn output_len(&self) -> usize {
        self.out_len
    }

    /// Absorbs `data`.
    pub fn update(&mut self, mut data: &[u8]) {
        if data.is_empty() {
            return;
        }
        // Fill the buffer; compress it only once more input is known to follow.
        let n = (Self::BLOCK_LEN - self.pos).min(data.len());
        self.buf[self.pos..self.pos + n].copy_from_slice(&data[..n]);
        self.pos += n;
        data = &data[n..];
        if data.is_empty() {
            return;
        }
        let block = self.buf;
        self.t += Self::BLOCK_LEN as u128;
        compress(&mut self.h, &block, self.t, false);
        // Whole blocks straight from `data`, keeping the last (possibly whole) one buffered.
        while data.len() > Self::BLOCK_LEN {
            let (b, rest) = data.split_at(Self::BLOCK_LEN);
            self.t += Self::BLOCK_LEN as u128;
            compress(
                &mut self.h,
                b.try_into().unwrap_or_else(|_| unreachable!()),
                self.t,
                false,
            );
            data = rest;
        }
        self.buf[..data.len()].copy_from_slice(data);
        self.pos = data.len();
    }

    /// Finishes the hash into `out`, which must be exactly [`output_len`](Self::output_len)
    /// bytes long ([`Error::InvalidLength`] otherwise).
    pub fn finalize_into(mut self, out: &mut [u8]) -> Result<(), Error> {
        if out.len() != self.out_len {
            return Err(Error::InvalidLength);
        }
        self.t += self.pos as u128;
        self.buf[self.pos..].fill(0);
        let block = self.buf;
        compress(&mut self.h, &block, self.t, true);
        let mut full = [0u8; 64];
        for (c, w) in full.chunks_exact_mut(8).zip(self.h) {
            c.copy_from_slice(&w.to_le_bytes());
        }
        out.copy_from_slice(&full[..self.out_len]);
        Ok(())
    }

    /// The unkeyed digest of `data` in one call, `out.len()` bytes long (1 to 64;
    /// [`Error::InvalidLength`] otherwise).
    pub fn digest(out: &mut [u8], data: &[u8]) -> Result<(), Error> {
        let mut h = Self::new(out.len())?;
        h.update(data);
        h.finalize_into(out)
    }
}

/// BLAKE2b-512: unkeyed BLAKE2b with a 64-byte digest, behind the [`Hash`](super::Hash) trait
/// (so it works with [`Hmac`](crate::mac::Hmac) and HKDF).
#[derive(Clone)]
pub struct Blake2b512(Blake2b);

impl Blake2b512 {
    /// A fresh hasher.
    #[must_use]
    pub fn new() -> Self {
        Blake2b512(Blake2b::with_len(64))
    }

    /// Absorbs `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Finishes the hash and returns the digest.
    #[must_use]
    pub fn finalize(self) -> [u8; 64] {
        let mut out = [0u8; 64];
        self.0
            .finalize_into(&mut out)
            .unwrap_or_else(|_| unreachable!());
        out
    }
}

super::impl_hash!(Blake2b512, 128, 64);

#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// RFC 7693's F: compresses `block` into `h`, `t` bytes counted so far, `last` for the final
/// block.
fn compress(h: &mut [u64; 8], block: &[u8; 128], t: u128, last: bool) {
    let mut m = [0u64; 16];
    for (w, b) in m.iter_mut().zip(block.chunks_exact(8)) {
        *w = u64::from_le_bytes(b.try_into().unwrap_or_else(|_| unreachable!()));
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    for s in &SIGMA {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

#[cfg(test)]
mod tests {
    use super::super::hex;
    use super::*;

    #[test]
    fn rfc7693_abc() {
        // RFC 7693, appendix A.
        assert_eq!(
            hex(&Blake2b512::digest(b"abc")),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }

    #[test]
    fn empty_and_lengths() {
        // The BLAKE2 reference's unkeyed 512-bit digest of the empty string.
        assert_eq!(
            hex(&Blake2b512::digest(b"")),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
             d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
        assert_eq!(Blake2b::new(0).err(), Some(Error::InvalidLength));
        assert_eq!(Blake2b::new(65).err(), Some(Error::InvalidLength));
        assert_eq!(
            Blake2b::new_keyed(&[0; 65], 32).err(),
            Some(Error::InvalidLength)
        );
        let h = Blake2b::new(20).unwrap();
        assert_eq!(h.output_len(), 20);
        assert_eq!(
            h.finalize_into(&mut [0u8; 21]).err(),
            Some(Error::InvalidLength)
        );
    }

    #[test]
    fn streamed_matches_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        for len in [0, 1, 127, 128, 129, 255, 256, 257, 1000] {
            let mut one = [0u8; 48];
            Blake2b::digest(&mut one, &data[..len]).unwrap();
            for step in [1, 7, 64, 128, 129] {
                let mut h = Blake2b::new(48).unwrap();
                for c in data[..len].chunks(step) {
                    h.update(c);
                }
                let mut d = [0u8; 48];
                h.finalize_into(&mut d).unwrap();
                assert_eq!(d, one, "len {len} step {step}");
            }
        }
    }
}
