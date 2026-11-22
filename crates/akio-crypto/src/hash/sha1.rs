//! SHA-1 (FIPS 180-4, section 6.1).

use super::{Buffer, blocks, impl_hash};

const H0: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

/// SHA-1: 20-byte digests. Broken for collision resistance; use it only where a protocol
/// requires it.
#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    buf: Buffer<64>,
}

impl Sha1 {
    /// A fresh hasher.
    #[must_use]
    pub const fn new() -> Self {
        Sha1 {
            state: H0,
            buf: Buffer::new(),
        }
    }

    /// Absorbs `data`.
    pub fn update(&mut self, data: &[u8]) {
        let state = &mut self.state;
        self.buf.update(data, |d| compress_blocks(state, d));
    }

    /// Finishes the hash and returns the digest.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 20] {
        let state = &mut self.state;
        self.buf.finish(8, true, |d| compress_blocks(state, d));
        let mut out = [0u8; 20];
        for (o, s) in out.chunks_exact_mut(4).zip(self.state) {
            o.copy_from_slice(&s.to_be_bytes());
        }
        out
    }
}

impl_hash!(Sha1, 64, 20);

/// Compresses whole 64-byte blocks: the SHA instructions when the CPU has them, else
/// [`compress`].
#[inline]
fn compress_blocks(state: &mut [u32; 5], data: &[u8]) {
    if super::hw::enabled() && super::hw::sha1(state, data) {
        return;
    }
    blocks(data).for_each(|b| compress(state, b));
}

#[inline(always)]
fn schedule(w: &mut [u32; 16], i: usize) -> u32 {
    let t = w[(i + 13) & 15] ^ w[(i + 8) & 15] ^ w[(i + 2) & 15] ^ w[i & 15];
    let t = t.rotate_left(1);
    w[i & 15] = t;
    t
}

fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 16];
    for (w, b) in w.iter_mut().zip(block.chunks_exact(4)) {
        *w = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *state;
    macro_rules! round {
        ($f:expr, $k:expr, $wi:expr) => {{
            let t = a
                .rotate_left(5)
                .wrapping_add($f)
                .wrapping_add(e)
                .wrapping_add($k)
                .wrapping_add($wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }};
    }
    for x in w {
        round!(d ^ (b & (c ^ d)), 0x5a82_7999, x);
    }
    for i in 16..20 {
        let x = schedule(&mut w, i);
        round!(d ^ (b & (c ^ d)), 0x5a82_7999, x);
    }
    for i in 20..40 {
        let x = schedule(&mut w, i);
        round!(b ^ c ^ d, 0x6ed9_eba1, x);
    }
    for i in 40..60 {
        let x = schedule(&mut w, i);
        round!((b & c) | (d & (b | c)), 0x8f1b_bcdc, x);
    }
    for i in 60..80 {
        let x = schedule(&mut w, i);
        round!(b ^ c ^ d, 0xca62_c1d6, x);
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e]) {
        *s = s.wrapping_add(v);
    }
}

#[cfg(test)]
mod tests {
    use super::super::hex;
    use super::*;

    /// The SHA instructions (when present) and the portable compression agree.
    #[test]
    fn hardware_matches_portable() {
        let mut rng = crate::rand::ChaChaRng::from_seed([3; 32]);
        let mut data = vec![0u8; 64 * 9];
        for _ in 0..50 {
            rng.fill(&mut data);
            let mut a = H0;
            let mut b = H0;
            compress_blocks(&mut a, &data);
            blocks(&data).for_each(|blk| compress(&mut b, blk));
            assert_eq!(a, b);
        }
    }

    #[test]
    fn vectors() {
        assert_eq!(
            hex(&Sha1::digest(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            hex(&Sha1::digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&Sha1::digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        let mut h = Sha1::new();
        for _ in 0..1000 {
            h.update(&[b'a'; 1000]);
        }
        assert_eq!(
            hex(&h.finalize()),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }
}
