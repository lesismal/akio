//! ChaCha20, Poly1305 and the ChaCha20-Poly1305 AEAD (RFC 8439). All three are constant time by
//! construction (additions, rotations and XORs; Poly1305 uses 44-bit limbs and
//! multiplications only).
//!
//! ChaCha20 computes several blocks at once: sixteen (zmm) or four (xmm) with AVX-512 on x86_64,
//! eight with AVX2 (detected at run time, see `hw`), else four in a lane-parallel layout that
//! compilers map onto 128-bit vectors (SSE2, NEON). Poly1305 absorbs eight blocks per step with
//! AVX-512 IFMA (runs of 256 bytes and more), else two per step in scalar code.
//!
//! ```
//! use akio_crypto::chacha::ChaCha20Poly1305;
//!
//! let aead = ChaCha20Poly1305::new(&[7u8; 32]);
//! let nonce = [1u8; 12];
//! let sealed = aead.encrypt(&nonce, b"header", b"secret");
//! assert_eq!(aead.decrypt(&nonce, b"header", &sealed).unwrap(), b"secret");
//! ```

use std::mem::MaybeUninit;

use crate::Error;
use crate::fill::{self, Fill};

mod hw;

/// The key length in bytes.
pub const KEY_LEN: usize = 32;
/// The nonce length in bytes.
pub const NONCE_LEN: usize = 12;
/// The Poly1305 tag length in bytes.
pub const TAG_LEN: usize = 16;

/// The widest implementation a key may use; the default allows all, the others exist for
/// differential tests and benchmarks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    /// The portable code (also what `AKIO_CRYPTO_PORTABLE` forces).
    Portable,
    /// ChaCha20 on AVX2 (eight blocks), Poly1305 on AVX2 (four blocks, radix 2²⁶).
    Avx2,
    /// ChaCha20 on AVX-512 (sixteen or four blocks), Poly1305 on AVX-512 IFMA when present.
    Wide,
}

impl Level {
    /// The widest level this CPU allows now (the portable switch included), at most `cap`.
    #[inline]
    fn current(cap: Level) -> Level {
        let best = if hw::wide_enabled() {
            Level::Wide
        } else if hw::enabled() {
            Level::Avx2
        } else {
            Level::Portable
        };
        best.min(cap)
    }
}

/// The shortest run of whole Poly1305 blocks handed to the IFMA kernel: below it, computing the
/// eight powers of `r` costs more than the kernel saves.
const IFMA_MIN: usize = 256;

/// The shortest run of whole Poly1305 blocks handed to the AVX2 kernel (without IFMA): below it
/// the powers of `r` cost more than the kernel saves.
const AVX2_MIN: usize = 512;

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
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        self.apply(Level::current(Level::Wide), data);
    }

    /// [`apply_keystream`](Self::apply_keystream) with the implementations of `lvl` at most.
    fn apply(&mut self, lvl: Level, mut data: &mut [u8]) {
        if self.used < 64 {
            let n = (64 - self.used).min(data.len());
            for (d, k) in data[..n].iter_mut().zip(&self.keystream[self.used..]) {
                *d ^= k;
            }
            self.used += n;
            data = &mut data[n..];
        }
        // Whole blocks on AVX-512 up to (not including) the last counter value; then eight
        // blocks at a time on AVX2, four at a time otherwise, while the counter cannot wrap
        // inside the group (the single-block path below handles the wrap and exhaustion).
        if !self.exhausted && lvl == Level::Wide {
            let n = (data.len() / 64).min((u32::MAX - self.state[12]) as usize);
            if n > 0 && hw::xor_wide(&self.state, &mut data[..64 * n]) {
                self.state[12] += n as u32;
                data = &mut data[64 * n..];
            }
        }
        let mut done = 0;
        if !self.exhausted && lvl >= Level::Avx2 {
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
        // A rest shorter than eight blocks: one more vector call into a buffer (it costs about
        // as much as one block of the portable code), the last partial block kept for later.
        if !self.exhausted
            && lvl >= Level::Avx2
            && !data.is_empty()
            && data.len() < 512
            && self.state[12] <= u32::MAX - 8
        {
            let mut ks = [0u8; 512];
            let nb = data.len().div_ceil(64);
            let ok = if lvl == Level::Wide {
                hw::xor_wide(&self.state, &mut ks[..64 * nb])
            } else {
                hw::xor8(&self.state, &mut ks)
            };
            if ok {
                for (d, k) in data.iter_mut().zip(&ks) {
                    *d ^= k;
                }
                let rest = data.len() % 64;
                if rest > 0 {
                    self.keystream.copy_from_slice(&ks[64 * (nb - 1)..64 * nb]);
                    self.used = rest;
                }
                self.state[12] += nb as u32;
                return;
            }
        }
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
    /// `r` (clamped) as two 64-bit words.
    r: [u64; 2],
    /// `s` as two 64-bit words.
    s: [u64; 2],
    /// The accumulator as two 64-bit words and the bits above 2¹²⁸ (partially reduced: below
    /// 2¹³⁰ plus a little).
    h: [u64; 3],
    buf: [u8; 16],
    pos: usize,
    /// The widest kernels it may use: IFMA with [`Level::Wide`], AVX2 from [`Level::Avx2`]
    /// (each recomputes its powers of `r` per call: the struct stays small, and the AEAD makes
    /// one long call).
    lvl: Level,
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

/// Carries the product limbs `d` back to 44/44/42 bits (partially reduced: `h1` may exceed 2⁴⁴
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

/// `a·b` modulo `2¹³⁰ - 5` in 44/44/42-bit limbs (partially reduced).
#[inline(always)]
fn mul44(a: [u64; 3], b: [u64; 3]) -> [u64; 3] {
    let (s1, s2) = (b[1] * 20, b[2] * 20);
    let mm = |a: u64, b: u64| u128::from(a) * u128::from(b);
    carry([
        mm(a[0], b[0]) + mm(a[1], s2) + mm(a[2], s1),
        mm(a[0], b[1]) + mm(a[1], b[0]) + mm(a[2], s2),
        mm(a[0], b[2]) + mm(a[1], b[1]) + mm(a[2], b[0]),
    ])
}

/// A value below 2¹³⁴ in 64/64/rest words as 44/44/rest-bit limbs.
#[inline(always)]
fn to44(h: [u64; 3]) -> [u64; 3] {
    [
        h[0] & M44,
        ((h[0] >> 44) | (h[1] << 20)) & M44,
        (h[1] >> 24) | (h[2] << 40),
    ]
}

/// 44/44/42-bit limbs (partially reduced, each below 2⁶³) as a value in 64/64/rest words, with
/// the bits from 2¹³⁰ folded back once (the result is below 2¹³⁰ plus a little).
fn from44(l: [u64; 3]) -> [u64; 3] {
    let [l0, l1, l2] = carry(l.map(u128::from));
    // l0 < 2⁴⁴, l1 < 2⁴⁴ plus a carry, l2 < 2⁴²: the low 128 bits may carry once more.
    let (v, c) = (u128::from(l0) + (u128::from(l1) << 44))
        .overflowing_add(u128::from(l2 & ((1 << 40) - 1)) << 88);
    [v as u64, (v >> 64) as u64, (l2 >> 40) + u64::from(c)]
}

/// A value in 64/64/rest words (below 2¹³⁴) as five 26-bit limbs (the top one takes the rest).
#[inline]
fn to26(h: [u64; 3]) -> [u64; 5] {
    const M: u64 = 0x3ff_ffff;
    [
        h[0] & M,
        (h[0] >> 26) & M,
        ((h[0] >> 52) | (h[1] << 12)) & M,
        (h[1] >> 14) & M,
        (h[1] >> 40) | (h[2] << 24),
    ]
}

/// Five limbs of about 26 bits (each below 2⁶⁰) back to 64/64/rest words, carried and with the
/// bits from 2¹³⁰ folded back once.
#[inline]
fn from26(t: [u64; 5]) -> [u64; 3] {
    const M: u64 = 0x3ff_ffff;
    let [mut t0, mut t1, mut t2, mut t3, mut t4] = t;
    t1 += t0 >> 26;
    t0 &= M;
    t2 += t1 >> 26;
    t1 &= M;
    t3 += t2 >> 26;
    t2 &= M;
    t4 += t3 >> 26;
    t3 &= M;
    t0 += (t4 >> 26) * 5;
    t4 &= M;
    // Once more from t0 (the fold can carry all the way up): t0..t3 < 2²⁶ afterwards and
    // t4 at most 2²⁶, so the low 128 bits below do not overflow.
    t1 += t0 >> 26;
    t0 &= M;
    t2 += t1 >> 26;
    t1 &= M;
    t3 += t2 >> 26;
    t2 &= M;
    t4 += t3 >> 26;
    t3 &= M;
    let v = u128::from(t0)
        + (u128::from(t1) << 26)
        + (u128::from(t2) << 52)
        + (u128::from(t3) << 78)
        + (u128::from(t4 & 0xff_ffff) << 104);
    [v as u64, (v >> 64) as u64, t4 >> 24]
}

impl Poly1305 {
    /// A Poly1305 instance keyed with the one-time key `key` (`r` then `s`).
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        Self::with_level(key, Level::Wide)
    }

    /// A Poly1305 instance that uses the IFMA kernel only with `lvl` [`Level::Wide`].
    fn with_level(key: &[u8], lvl: Level) -> Self {
        Self::from_words(
            [
                le64(&key[0..]),
                le64(&key[8..]),
                le64(&key[16..]),
                le64(&key[24..]),
            ],
            lvl,
        )
    }

    /// [`with_level`](Self::with_level) of the key given as four little-endian words.
    #[inline]
    fn from_words(k: [u64; 4], lvl: Level) -> Self {
        Poly1305 {
            r: [k[0] & 0x0fff_fffc_0fff_ffff, k[1] & 0x0fff_fffc_0fff_fffc],
            s: [k[2], k[3]],
            h: [0; 3],
            buf: [0; 16],
            pos: 0,
            lvl,
        }
    }

    /// `r⁸ … r¹` in the layout of [`hw::Powers`] (limbs below 2⁴⁵, `20·r1` and `20·r2` below
    /// 2⁵⁰).
    fn powers(r: [u64; 3]) -> hw::Powers {
        let r2 = mul44(r, r);
        let r3 = mul44(r2, r);
        let r4 = mul44(r2, r2);
        let p = [
            mul44(r4, r4),
            mul44(r4, r3),
            mul44(r4, r2),
            mul44(r4, r),
            r4,
            r3,
            r2,
            r,
        ];
        let mut pw = [0u64; 40];
        for (i, p) in p.iter().enumerate() {
            pw[i] = p[0];
            pw[8 + i] = p[1];
            pw[16 + i] = p[2];
            pw[24 + i] = 20 * p[1];
            pw[32 + i] = 20 * p[2];
        }
        pw
    }

    /// Absorbs the 16-byte blocks of `data` (a multiple of 16 bytes), each with the bit 2¹²⁸
    /// set when `hibit` is 1 (full blocks) or not (the final partial block, padded with its own
    /// `0x01`), in radix 2⁶⁴ (poly1305-donna-64 / OpenSSL): `h = (h + m)·r`, with
    /// `s1 = r1 + r1/4` folding the products above 2¹³⁰ (`r1` is a multiple of 4).
    #[inline]
    fn blocks64(&mut self, data: &[u8], hibit: u64) {
        for m in data.chunks_exact(16) {
            self.block64(le64(&m[0..]), le64(&m[8..]), hibit);
        }
    }

    /// Absorbs one block given as two little-endian words (see [`blocks64`](Self::blocks64)).
    #[inline(always)]
    fn block64(&mut self, m0: u64, m1: u64, hibit: u64) {
        let [r0, r1] = self.r;
        let s1 = r1 + (r1 >> 2);
        let [mut h0, mut h1, mut h2] = self.h;
        let mm = |a: u64, b: u64| u128::from(a) * u128::from(b);
        let t = u128::from(h0) + u128::from(m0);
        h0 = t as u64;
        let t = u128::from(h1) + u128::from(m1) + (t >> 64);
        h1 = t as u64;
        h2 += (t >> 64) as u64 + hibit;
        let d0 = mm(h0, r0) + mm(h1, s1);
        let d1 = mm(h0, r1) + mm(h1, r0) + u128::from(h2 * s1) + (d0 >> 64);
        let d2 = h2 * r0 + (d1 >> 64) as u64;
        // d2 holds the bits from 2¹²⁸: keep two, fold the rest times 5 into h0.
        let c = (d2 & !3) + (d2 >> 2);
        let t = u128::from(d0 as u64) + u128::from(c);
        h0 = t as u64;
        let t = u128::from(d1 as u64) + (t >> 64);
        h1 = t as u64;
        h2 = (d2 & 3) + (t >> 64) as u64;
        self.h = [h0, h1, h2];
    }

    /// Absorbs `data` padded with zeros to whole 16-byte blocks (the AEAD's padding; nothing
    /// may be buffered), the last partial block assembled from fixed-size loads (no `memcpy`
    /// call for these few bytes).
    fn absorb_padded(&mut self, data: &[u8], pw: Option<&hw::Powers>) {
        debug_assert_eq!(self.pos, 0);
        let whole = data.len() / 16 * 16;
        // Below both vector thresholds straight to the scalar loop (no dispatch, no frame for
        // the IFMA powers).
        if whole >= IFMA_MIN.min(AVX2_MIN) {
            self.full_blocks(&data[..whole], pw);
        } else {
            self.blocks64(&data[..whole], 1);
        }
        let rest = &data[whole..];
        if !rest.is_empty() {
            // The zero-padded block as two words, from pieces of 8, 4, 2 and 1 bytes shifted
            // into place in registers (a piece never straddles the words: after an 8-byte piece
            // the rest is at most 7 bytes). Assembled in a stack buffer instead, the second word
            // was read back across several narrower stores, which cannot be forwarded: the load
            // waited for them to commit, and when opening that is after the ChaCha20 call still
            // in flight retires.
            let mut w = [0u64; 2];
            let mut o = 0;
            for n in [8, 4, 2, 1] {
                if rest.len() & n != 0 {
                    let p = &rest[o..o + n];
                    let v = match n {
                        8 => le64(p),
                        4 => u64::from(u32::from_le_bytes([p[0], p[1], p[2], p[3]])),
                        2 => u64::from(u16::from_le_bytes([p[0], p[1]])),
                        _ => u64::from(p[0]),
                    };
                    w[o / 8] |= v << (8 * (o % 8));
                    o += n;
                }
            }
            self.block64(w[0], w[1], 1);
        }
    }

    /// Whether `len` bytes of whole blocks go through the IFMA kernel.
    fn uses_ifma(&self, len: usize) -> bool {
        self.lvl == Level::Wide && len >= IFMA_MIN && hw::ifma_enabled()
    }

    /// The powers of `r` for the IFMA kernel.
    fn ifma_powers(&self) -> hw::Powers {
        Self::powers(to44([self.r[0], self.r[1], 0]))
    }

    /// Absorbs the whole 16-byte blocks of `data` (a multiple of 16 bytes), with the powers of
    /// `r` for the IFMA kernel when the caller computed them already.
    fn full_blocks(&mut self, mut data: &[u8], pw: Option<&hw::Powers>) {
        if self.uses_ifma(data.len()) {
            let n = data.len() / hw::POLY_CHUNK * hw::POLY_CHUNK;
            let mut h = to44(self.h);
            let own;
            let pw = match pw {
                Some(pw) => pw,
                None => {
                    own = self.ifma_powers();
                    &own
                }
            };
            if hw::poly_blocks(&mut h, pw, &data[..n]) {
                // Back to radix 2⁶⁴ (carried so that each limb is in range).
                let [l0, mut l1, mut l2] = carry(h.map(u128::from));
                l2 += l1 >> 44;
                l1 &= M44;
                self.h = [l0 | (l1 << 44), (l1 >> 20) | (l2 << 24), l2 >> 40];
                data = &data[n..];
            }
        } else if self.lvl >= Level::Avx2 && data.len() >= AVX2_MIN && hw::enabled() {
            let n = data.len() / hw::POLY_AVX2_CHUNK * hw::POLY_AVX2_CHUNK;
            let mut h = to26(self.h);
            if hw::poly_avx2(&mut h, &self.avx2_powers(), &data[..n]) {
                self.h = from26(h);
                data = &data[n..];
            }
        }
        self.blocks64(data, 1);
    }

    /// The powers of `r` for the AVX2 kernel (see [`hw::Avx2Powers`]).
    fn avx2_powers(&self) -> hw::Avx2Powers {
        let r = to44([self.r[0], self.r[1], 0]);
        let r2 = mul44(r, r);
        let r3 = mul44(r2, r);
        let r4 = mul44(r2, r2);
        let limbs = |p: [u64; 3]| {
            let t = to26(from44(p));
            [
                t[0],
                t[1],
                t[2],
                t[3],
                t[4],
                5 * t[1],
                5 * t[2],
                5 * t[3],
                5 * t[4],
            ]
        };
        let (p1, p2, p3, p4) = (limbs(r), limbs(r2), limbs(r3), limbs(r4));
        let mut last = [[0u64; 4]; 9];
        for (i, l) in last.iter_mut().enumerate() {
            // The lanes hold blocks 0, 2, 1, 3 of the last group.
            *l = [p4[i], p2[i], p3[i], p1[i]];
        }
        hw::Avx2Powers { r4: p4, last }
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
            self.blocks64(&b, 1);
            self.pos = 0;
        }
        let whole = data.len() / 16 * 16;
        self.full_blocks(&data[..whole], None);
        let rest = &data[whole..];
        self.buf[..rest.len()].copy_from_slice(rest);
        self.pos = rest.len();
    }

    /// Finishes and returns the tag.
    #[must_use]
    pub fn finalize(mut self) -> [u8; TAG_LEN] {
        if self.pos > 0 {
            self.buf[self.pos] = 1;
            self.buf[self.pos + 1..].fill(0);
            let b = self.buf;
            self.blocks64(&b, 0);
        }
        let [mut h0, mut h1, mut h2] = self.h;
        // Fold the bits from 2¹³⁰ once more: h < 2¹³⁰ + 2⁶⁴ afterwards.
        let c = (h2 & !3) + (h2 >> 2);
        h2 &= 3;
        let t = u128::from(h0) + u128::from(c);
        h0 = t as u64;
        let t = u128::from(h1) + (t >> 64);
        h1 = t as u64;
        h2 += (t >> 64) as u64;

        // g = h + 5 - 2^130; use g if it did not go negative (constant-time select).
        let t = u128::from(h0) + 5;
        let g0 = t as u64;
        let t = u128::from(h1) + (t >> 64);
        let g1 = t as u64;
        let g2 = h2 + (t >> 64) as u64;
        let mask = 0u64.wrapping_sub(g2 >> 2); // all ones if h + 5 >= 2^130
        h0 = (h0 & !mask) | (g0 & mask);
        h1 = (h1 & !mask) | (g1 & mask);

        // h + s mod 2^128.
        let t = u128::from(h0) + u128::from(self.s[0]);
        let w0 = t as u64;
        let w1 = h1.wrapping_add(self.s[1]).wrapping_add((t >> 64) as u64);

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
    /// The widest implementation this key may use.
    cap: Level,
}

impl std::fmt::Debug for ChaCha20Poly1305 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChaCha20Poly1305").finish_non_exhaustive()
    }
}

/// The first keystream blocks of a message: `n` blocks from block 0 (the Poly1305 key) in `ks`
/// (in the caller's [`HeadBuf`]).
struct Head<'a> {
    ks: &'a [u8],
    n: usize,
    /// The first 32 bytes of `ks` (the Poly1305 key) as little-endian words.
    key: [u64; 4],
}

/// Storage for a [`Head`], owned by the caller so that the keystream is written in place and
/// never moved (a returned array was a 256-byte `memcpy`, 13% of a 64-byte seal): four blocks
/// written straight by the AVX-512 row kernel, or up to eight in a zeroed buffer.
struct HeadBuf {
    row: MaybeUninit<[u8; 256]>,
    buf: MaybeUninit<[u8; 512]>,
}

impl HeadBuf {
    fn new() -> Self {
        HeadBuf {
            row: MaybeUninit::uninit(),
            buf: MaybeUninit::uninit(),
        }
    }
}

impl ChaCha20Poly1305 {
    /// An AEAD key.
    #[must_use]
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        ChaCha20Poly1305 {
            key: *key,
            cap: Level::Wide,
        }
    }

    /// A key that uses at most ChaCha20 on AVX2 and scalar Poly1305 (never the AVX-512 / IFMA
    /// kernels), for differential tests and benchmarks.
    #[doc(hidden)]
    #[must_use]
    pub fn new_avx2(key: &[u8; KEY_LEN]) -> Self {
        ChaCha20Poly1305 {
            key: *key,
            cap: Level::Avx2,
        }
    }

    /// A key that uses only the portable code, for differential tests and benchmarks.
    #[doc(hidden)]
    #[must_use]
    pub fn new_portable(key: &[u8; KEY_LEN]) -> Self {
        ChaCha20Poly1305 {
            key: *key,
            cap: Level::Portable,
        }
    }

    /// The level for this call, the cipher state at block 0 and the first keystream blocks
    /// (block 0 keys Poly1305, the others cover the first bytes of a message of `len` bytes):
    /// four or eight from one AVX-512 call (see [`hw::wide_cost`]); eight from one AVX2 call for
    /// messages of more than two blocks; else the blocks the message needs (at most four), one
    /// at a time.
    // Inlined so that the key words stay in registers: a returned `Head` would carry them
    // through memory (word stores read back by wider loads, which cannot be forwarded and stall
    // the start of the tag).
    #[inline(always)]
    fn start<'a>(
        &self,
        nonce: &[u8; NONCE_LEN],
        len: usize,
        hb: &'a mut HeadBuf,
    ) -> (Level, [u32; 16], Head<'a>) {
        let lvl = Level::current(self.cap);
        let st = ChaCha20::new(&self.key, nonce, 0).state;
        // Four blocks (one row group) or eight (one ymm group), whichever leaves the cheaper
        // rest (a public length only).
        let wide = if len > 192
            && hw::wide_cost(512) + hw::wide_cost(len.saturating_sub(448))
                < hw::wide_cost(256) + hw::wide_cost(len - 192)
        {
            8
        } else {
            4
        };
        if lvl == Level::Wide && wide == 4 {
            if let Some((ks, key)) = hw::keystream_row(&st, &mut hb.row) {
                return (lvl, st, Head { ks, n: 4, key });
            }
        }
        let ks = hb.buf.write([0u8; 512]);
        let n = if lvl == Level::Wide && hw::xor_wide(&st, &mut ks[..64 * wide]) {
            wide
        } else if lvl >= Level::Avx2 && len > 128 && hw::xor8(&st, ks) {
            8
        } else {
            let n = 1 + len.min(192).div_ceil(64);
            let mut s = st;
            for b in ks.chunks_exact_mut(64).take(n) {
                b.copy_from_slice(&block(&s));
                s[12] += 1;
            }
            n
        };
        (
            lvl,
            st,
            Head {
                key: [
                    le64(&ks[0..]),
                    le64(&ks[8..]),
                    le64(&ks[16..]),
                    le64(&ks[24..]),
                ],
                ks: &ks[..],
                n,
            },
        )
    }

    /// XORs the keystream from block 1 into the message, written to `out`: without `src` the
    /// message is `out` (initialised), worked on in place; with `src` (nothing written to `out`
    /// from the front yet) it is `src` followed by the initialised bytes of `out` after
    /// `src.len()`. `head` holds the first blocks. `out` is full afterwards.
    fn crypt(lvl: Level, st: &[u32; 16], head: &Head<'_>, src: Option<&[u8]>, out: &mut Fill<'_>) {
        let hb = 64 * (head.n - 1);
        let ks = &head.ks[64..64 * head.n];
        let len = out.len();
        let mut st = *st;
        st[12] = head.n as u32;
        // Bytes of `out` written from `src` (the rest is processed in place below).
        let mut at = 0;
        if let Some(s) = src {
            assert!(s.len() <= len && out.pos() == 0);
            at = s.len().min(hb);
            out.push_xor(&s[..at], ks);
            // On AVX-512 the whole blocks of `src` after the head (all of it when `src` is all
            // of the rest) go straight into `out` (the counter cannot wrap within a message).
            if lvl == Level::Wide && s.len() > hb {
                let rest = &s[hb..];
                let n = if s.len() == len {
                    rest.len()
                } else {
                    rest.len() / 64 * 64
                };
                if n > 0 {
                    if !hw::xor_wide_into(&st, &rest[..n], out) {
                        unreachable!("Level::Wide only with AVX-512");
                    }
                    st[12] += (n / 64) as u32;
                    at = hb + n;
                }
            }
            out.push(&s[at..]);
        }
        let buf = out.filled();
        let h = len.min(hb);
        if at < h {
            for (d, k) in buf[at..h].iter_mut().zip(&ks[at..]) {
                *d ^= k;
            }
        }
        let from = at.max(hb);
        if from >= len {
            return;
        }
        let dst = &mut buf[from..];
        if lvl == Level::Wide {
            if hw::xor_wide(&st, dst) {
                return;
            }
            unreachable!("Level::Wide only with AVX-512");
        }
        let mut c = ChaCha20 {
            state: st,
            keystream: [0; 64],
            used: 64,
            exhausted: false,
        };
        c.apply(lvl, dst);
    }

    /// The tag of `aad` and `ct` (`pw`: the IFMA powers of `p`'s `r`, when computed already).
    fn tag(mut p: Poly1305, aad: &[u8], ct: &[u8], pw: Option<&hw::Powers>) -> [u8; TAG_LEN] {
        p.absorb_padded(aad, None);
        p.absorb_padded(ct, pw);
        p.block64(aad.len() as u64, ct.len() as u64, 1);
        p.finalize()
    }

    /// Seals `src` followed by the initialised rest of `out` (or `out` in place) into `out`.
    fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        src: Option<&[u8]>,
        out: &mut Fill<'_>,
    ) -> [u8; TAG_LEN] {
        assert!(
            out.len() as u64 <= MAX_LEN,
            "ChaCha20-Poly1305: plaintext too long"
        );
        let len = out.len();
        let mut hb = HeadBuf::new();
        let (lvl, st, head) = self.start(nonce, len, &mut hb);
        let p = Poly1305::from_words(head.key, lvl);
        // The powers of `r` for the IFMA kernel first: their scalar multiplications overlap the
        // vector work of the cipher.
        let pw = p.uses_ifma(len / 16 * 16).then(|| p.ifma_powers());
        Self::crypt(lvl, &st, &head, src, out);
        Self::tag(p, aad, out.filled(), pw.as_ref())
    }

    /// Verifies the tag over the ciphertext `src` (or `out` in place) and decrypts it into `out`;
    /// `false` (and `out` untouched) on a mismatch.
    fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        src: Option<&[u8]>,
        out: &mut Fill<'_>,
        tag: &[u8],
    ) -> bool {
        let mut hb = HeadBuf::new();
        let (lvl, st, head) = self.start(nonce, out.len(), &mut hb);
        let ct: &[u8] = match src {
            Some(s) => s,
            None => out.filled(),
        };
        let t = Self::tag(Poly1305::from_words(head.key, lvl), aad, ct, None);
        if !crate::ct_eq(&t, tag) {
            return false;
        }
        Self::crypt(lvl, &st, &head, src, out);
        true
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
        self.seal(nonce, aad, None, &mut Fill::init(buf))
    }

    /// Encrypts `src` followed by `dst[src.len()..]` (plaintext already in place) into `dst` and
    /// returns the tag: [`encrypt_in_place_detached`](Self::encrypt_in_place_detached) of that
    /// plaintext without copying `src` into `dst` first.
    ///
    /// # Panics
    ///
    /// If `src` is longer than `dst`, or `dst` longer than the construction allows.
    #[doc(hidden)]
    pub fn encrypt_detached_from(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        src: &[u8],
        dst: &mut [u8],
    ) -> [u8; TAG_LEN] {
        assert!(
            src.len() <= dst.len(),
            "ChaCha20-Poly1305: output too short"
        );
        self.seal(nonce, aad, Some(src), &mut Fill::init(dst))
    }

    /// Appends the ciphertext of `src` followed by `trailer` to `out` and returns the tag:
    /// [`encrypt_detached_from`](Self::encrypt_detached_from) into `out`'s spare capacity, which
    /// is not zero-filled first (every byte is written before `out` grows). For the TLS record
    /// layer (`trailer`: the TLS 1.3 inner content type).
    ///
    /// # Panics
    ///
    /// If the plaintext is longer than the construction allows (`out` unchanged).
    #[doc(hidden)]
    pub fn encrypt_append(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        src: &[u8],
        trailer: &[u8],
        out: &mut Vec<u8>,
    ) -> [u8; TAG_LEN] {
        let n = src.len().saturating_add(trailer.len());
        assert!(n as u64 <= MAX_LEN, "ChaCha20-Poly1305: plaintext too long");
        fill::append(out, n, |f| {
            f.push_back(trailer);
            (self.seal(nonce, aad, Some(src), f), true)
        })
    }

    /// Verifies `tag` over the ciphertext `src` and decrypts it into `dst` (of the same length)
    /// without copying it into `dst` first. On failure `dst` is zeroed.
    ///
    /// # Panics
    ///
    /// If `src` and `dst` differ in length.
    #[doc(hidden)]
    pub fn decrypt_detached_from(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        src: &[u8],
        tag: &[u8],
        dst: &mut [u8],
    ) -> Result<(), Error> {
        assert_eq!(src.len(), dst.len(), "ChaCha20-Poly1305: output length");
        if tag.len() != TAG_LEN {
            return Err(Error::InvalidLength);
        }
        if src.len() as u64 > MAX_LEN
            || !self.open(nonce, aad, Some(src), &mut Fill::init(dst), tag)
        {
            dst.fill(0);
            return Err(Error::Verification);
        }
        Ok(())
    }

    /// Verifies `tag` over the ciphertext `src` and appends its plaintext to `out`:
    /// [`decrypt_detached_from`](Self::decrypt_detached_from) into `out`'s spare capacity, which
    /// is not zero-filled first. On failure `out` is left as it was (the tag is checked before
    /// anything is decrypted). For the TLS record layer.
    #[doc(hidden)]
    pub fn decrypt_append(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        src: &[u8],
        tag: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        if tag.len() != TAG_LEN {
            return Err(Error::InvalidLength);
        }
        if src.len() as u64 > MAX_LEN {
            return Err(Error::Verification);
        }
        let ok = fill::append(out, src.len(), |f| {
            let ok = self.open(nonce, aad, Some(src), f, tag);
            (ok, ok)
        });
        if ok { Ok(()) } else { Err(Error::Verification) }
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
        if buf.len() as u64 > MAX_LEN || !self.open(nonce, aad, None, &mut Fill::init(buf), tag) {
            return Err(Error::Verification);
        }
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

    /// Message lengths for the differential tests: every length up to 600, then sizes around the
    /// kernel widths and records.
    fn lengths() -> impl Iterator<Item = usize> {
        (0..=600).chain([
            767, 768, 1023, 1024, 1025, 1200, 1216, 1400, 2047, 2048, 4113, 16384, 16385, 16401,
            65536, 65539,
        ])
    }

    /// The AVX-512 / IFMA path (`new`), the AVX2 path and the portable code produce the same
    /// ciphertexts and tags, in place and out of place, from misaligned buffers, and open each
    /// other's messages (on CPUs without the wider instructions the paths coincide).
    #[test]
    fn aead_paths_agree() {
        println!("hardware: [{}]", crate::hardware_features());
        let mut rng = crate::rand::ChaChaRng::from_seed([21; 32]);
        let mut key = [0u8; 32];
        rng.fill(&mut key);
        let keys = [
            ChaCha20Poly1305::new(&key),
            ChaCha20Poly1305::new_avx2(&key),
            ChaCha20Poly1305::new_portable(&key),
        ];
        let nonce = [9u8; 12];
        for (i, len) in lengths().enumerate() {
            let aad = vec![0x17u8; [0, 5, 13, 16, 17, 300][i % 6]];
            let mut msg = vec![0u8; len + 3];
            rng.fill(&mut msg);
            // Misaligned by 0..=2 bytes.
            let off = i % 3;
            let pt = &msg[off..off + len];
            let want = keys[2].encrypt(&nonce, &aad, pt);
            for k in &keys {
                assert_eq!(k.encrypt(&nonce, &aad, pt), want, "len {len}");
                assert_eq!(k.decrypt(&nonce, &aad, &want).unwrap(), pt, "len {len}");
                // Out of place, the plaintext split between `src` and `dst`.
                for split in [0, len / 3, len.saturating_sub(1), len] {
                    let mut dst = vec![0u8; len + 1];
                    dst[1 + split..].copy_from_slice(&pt[split..]);
                    let tag = k.encrypt_detached_from(&nonce, &aad, &pt[..split], &mut dst[1..]);
                    assert_eq!(dst[1..], want[..len], "len {len} split {split}");
                    assert_eq!(tag[..], want[len..], "len {len} split {split}");
                }
                let mut back = vec![0u8; len + 2];
                k.decrypt_detached_from(&nonce, &aad, &want[..len], &want[len..], &mut back[2..])
                    .unwrap();
                assert_eq!(&back[2..], pt);
                // A forged tag: rejected, `dst` zeroed (out of place) or untouched (in place).
                let mut bad = want.clone();
                bad[len] ^= 0x80;
                let mut back = vec![0xaau8; len];
                assert_eq!(
                    k.decrypt_detached_from(&nonce, &aad, &bad[..len], &bad[len..], &mut back),
                    Err(Error::Verification)
                );
                assert!(back.iter().all(|&b| b == 0));
                let mut inplace = bad[..len].to_vec();
                assert_eq!(
                    k.decrypt_in_place_detached(&nonce, &aad, &mut inplace, &bad[len..]),
                    Err(Error::Verification)
                );
                assert_eq!(inplace, bad[..len]);
                append_agrees(k, &nonce, &aad, pt, &want, &format!("len {len}"));
            }
        }
    }

    /// `encrypt_append` / `decrypt_append` agree with `sealed` (ciphertext and tag of `pt`):
    /// after bytes already in the vector, with the spare capacity exact, larger or grown by the
    /// call, and the plaintext split between `src` and a trailer (none, the last byte as the
    /// TLS 1.3 record layer has it, a third); a failed open leaves the vector as it was.
    fn append_agrees(
        k: &ChaCha20Poly1305,
        nonce: &[u8; 12],
        aad: &[u8],
        pt: &[u8],
        sealed: &[u8],
        what: &str,
    ) {
        let len = pt.len();
        let (ct, tag) = sealed.split_at(len);
        for (j, trailer) in [0, len.min(1), len / 3].into_iter().enumerate() {
            let split = len - trailer;
            let head = (len + j) % 4;
            let mut out: Vec<u8> = (1..=head as u8).collect();
            match j {
                0 => out.reserve_exact(len),
                1 => out.reserve(len + 100),
                _ => {}
            }
            let t = k.encrypt_append(nonce, aad, &pt[..split], &pt[split..], &mut out);
            assert_eq!(out.len(), head + len, "append len: {what}");
            assert!(out[..head].iter().copied().eq(1..=head as u8), "{what}");
            assert!(out[head..] == ct[..], "append: {what}, trailer {trailer}");
            assert_eq!(t[..], tag[..], "append tag: {what}, trailer {trailer}");
            let before = out.clone();
            let mut bad = t;
            bad[(len + j) % 16] ^= 0x10;
            assert_eq!(
                k.decrypt_append(nonce, aad, ct, &bad, &mut out),
                Err(Error::Verification)
            );
            assert!(out == before, "failed open appends nothing: {what}");
            assert_eq!(
                k.decrypt_append(nonce, aad, ct, &tag[..15], &mut out),
                Err(Error::InvalidLength)
            );
            assert!(out == before);
            k.decrypt_append(nonce, aad, ct, tag, &mut out).unwrap();
            assert!(out[..head + len] == before[..], "{what}");
            assert!(out[head + len..] == pt[..], "append opened: {what}");
        }
    }

    /// The append paths on the portable code alone, at small sizes and around the head and
    /// block sizes: the test that runs under Miri (`cargo miri test -p akio-crypto --lib --
    /// append`), which checks that every byte they write into a vector's spare capacity is
    /// written before it is read or exposed.
    #[test]
    fn append_portable() {
        let mut rng = crate::rand::ChaChaRng::from_seed([22; 32]);
        let mut key = [0u8; 32];
        rng.fill(&mut key);
        let k = ChaCha20Poly1305::new_portable(&key);
        let lens: Vec<usize> = if cfg!(miri) {
            vec![0, 1, 63, 64, 65, 128, 191, 192, 193, 300, 513]
        } else {
            (0..=600).chain([1000, 4096, 16385]).collect()
        };
        for len in lens {
            let mut nonce = [0u8; 12];
            rng.fill(&mut nonce);
            let aad = vec![0x5au8; len % 19];
            let mut pt = vec![0u8; len];
            rng.fill(&mut pt);
            let sealed = k.encrypt(&nonce, &aad, &pt);
            append_agrees(&k, &nonce, &aad, &pt, &sealed, &format!("len {len}"));
        }
    }

    /// The ChaCha20 stream on the widest path against block-at-a-time generation, at counters
    /// near the wrap-around, from misaligned buffers and split across calls.
    #[test]
    fn chacha20_wide_matches_single() {
        let key = [0x5au8; 32];
        let nonce = [3u8; 12];
        for counter in [0u32, 1, 15, u32::MAX - 1100, u32::MAX - 20, u32::MAX - 1] {
            let max = (u64::from(u32::MAX - counter) + 1) * 64;
            for len in [
                1usize, 63, 64, 65, 255, 256, 257, 1000, 1024, 1088, 3000, 4096,
            ] {
                if len as u64 > max {
                    continue;
                }
                let mut c = ChaCha20::new(&key, &nonce, counter);
                let mut want = Vec::new();
                while want.len() < len {
                    want.extend_from_slice(&c.next_block());
                }
                want.truncate(len);
                let mut buf = vec![0u8; len + 1];
                let mut c = ChaCha20::new(&key, &nonce, counter);
                let (a, b) = buf[1..].split_at_mut(len.min(70));
                c.apply(Level::Wide, a);
                c.apply(Level::Wide, b);
                assert_eq!(buf[1..], want, "counter {counter} len {len}");
            }
        }
    }

    /// Poly1305 with the IFMA kernel against the scalar code: carries stressed with all-ones
    /// messages and the largest clamped `r`, `s` at both extremes, whole and split updates.
    #[test]
    fn wide_tail_stays_in_bounds() {
        // The last group of the AVX-512 kernels is read and written under byte masks: every
        // length up to a few groups, with canary bytes after the message, against the
        // block-at-a-time keystream.
        let key = [0x11u8; 32];
        let nonce = [9u8; 12];
        let mut c = ChaCha20::new(&key, &nonce, 7);
        let mut want = Vec::new();
        while want.len() < 2200 {
            want.extend_from_slice(&c.next_block());
        }
        for len in 1..2200 {
            let mut buf = vec![0xeeu8; len + 80];
            ChaCha20::new(&key, &nonce, 7).apply(Level::Wide, &mut buf[..len]);
            for (i, &b) in buf[..len].iter().enumerate() {
                assert_eq!(b, want[i] ^ 0xee, "len {len} byte {i}");
            }
            assert!(
                buf[len..].iter().all(|&b| b == 0xee),
                "len {len}: wrote past the end"
            );
        }
    }

    #[test]
    fn poly1305_wide_matches_scalar() {
        let mut rng = crate::rand::ChaChaRng::from_seed([5; 32]);
        let mut keys = vec![[0xffu8; 32], [0u8; 32]];
        let mut k = [0xffu8; 32];
        k[16..].fill(0);
        keys.push(k);
        let mut k = [0u8; 32];
        k[0] = 1;
        k[16..].fill(0xff);
        keys.push(k);
        for _ in 0..4 {
            let mut k = [0u8; 32];
            rng.fill(&mut k);
            keys.push(k);
        }
        for key in &keys {
            for len in [
                128usize, 255, 256, 257, 320, 383, 384, 448, 511, 512, 576, 1000, 1024, 1040, 4096,
                16400,
            ] {
                for fill in [None, Some(0xffu8), Some(0)] {
                    let mut msg = vec![0u8; len];
                    match fill {
                        Some(b) => msg.fill(b),
                        None => rng.fill(&mut msg),
                    }
                    let mut scalar = Poly1305::with_level(key, Level::Portable);
                    scalar.update(&msg);
                    let want = scalar.finalize();
                    for lvl in [Level::Avx2, Level::Wide] {
                        let mut wide = Poly1305::with_level(key, lvl);
                        wide.update(&msg);
                        assert_eq!(wide.finalize(), want, "{lvl:?} len {len}");
                        // Split updates (each long enough for the kernels).
                        let mut wide = Poly1305::with_level(key, lvl);
                        for c in msg.chunks(300) {
                            wide.update(c);
                        }
                        assert_eq!(wide.finalize(), want, "{lvl:?} len {len} split");
                    }
                }
            }
        }
    }
}
