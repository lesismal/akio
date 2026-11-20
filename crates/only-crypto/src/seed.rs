//! SEED (RFC 4269), the Korean 128-bit block cipher, with the modes SRTP runs it in (RFC 5669):
//! CTR, CCM (RFC 3610) and GCM (NIST SP 800-38D).
//!
//! Constant time, with no S-box tables: SEED's S-boxes are an inversion in GF(2⁸) (modulo
//! x⁸ + x⁶ + x⁵ + x + 1) followed by an affine map (`S0(x) = A0·x²⁴⁷ ⊕ 0xA9`,
//! `S1(x) = A1·x²⁵¹ ⊕ 0x38`, and `x²⁴⁷ = (x⁻¹)⁸`, `x²⁵¹ = (x⁻¹)⁴` are linear in `x⁻¹`). The
//! inversion is the Boyar-Peralta circuit of the fixsliced AES behind an isomorphism of the two
//! fields, over bitsliced state: the G function runs on sixteen 32-bit words at once (sixteen
//! blocks, or the 32 G calls of the key schedule in two passes) without secret-dependent memory
//! accesses or branches; CTR, GCM and ECB keep sixteen blocks in flight. A single block (CCM's
//! CBC-MAC, [`Seed::encrypt_block`]) runs the same circuit on one word, its four bytes as four
//! lanes, at about 40 % of the cost of a sixteen-block pass. There is no SEED instruction to
//! detect, so this is the only path.
//!
//! ```
//! use only_crypto::seed::Seed;
//!
//! // RFC 4269 Appendix B.1.
//! let seed = Seed::new(&[0; 16]);
//! let mut b: [u8; 16] = core::array::from_fn(|i| i as u8);
//! seed.encrypt_block(&mut b);
//! assert_eq!(b[..4], [0x5e, 0xba, 0xc6, 0xe0]);
//! seed.decrypt_block(&mut b);
//! assert_eq!(b[..4], [0, 1, 2, 3]);
//! ```

use crate::Error;
use crate::aes::{Aes, bitsliced_sub_bytes};
use crate::gcm::{be_pair, portable_ghash};

/// The block length in bytes.
pub const BLOCK_LEN: usize = 16;
/// The key length in bytes.
pub const KEY_LEN: usize = 16;

/// Blocks (or G inputs) processed together.
const LANES: usize = 16;

/// Key schedule constants `KC1 … KC16` (RFC 4269 §2.3).
const KC: [u32; 16] = [
    0x9e37_79b9,
    0x3c6e_f373,
    0x78dd_e6e6,
    0xf1bb_cdcc,
    0xe377_9b99,
    0xc6ef_3733,
    0x8dde_6e67,
    0x1bbc_dccf,
    0x3779_b99e,
    0x6ef3_733c,
    0xdde6_e678,
    0xbbcd_ccf1,
    0x779b_99e3,
    0xef37_33c6,
    0xde6e_678d,
    0xbcdc_cf1b,
];

/// A SEED key schedule (the 32 round subkeys `Ki0`, `Ki1`).
#[derive(Clone)]
pub struct Seed {
    rk: [u32; 32],
}

impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Seed").finish_non_exhaustive()
    }
}

impl Seed {
    /// The key schedule of a 128-bit key.
    #[must_use]
    pub fn new(key: &[u8; KEY_LEN]) -> Seed {
        let mut k01 = u64::from_be_bytes(key[..8].try_into().expect("8 bytes"));
        let mut k23 = u64::from_be_bytes(key[8..].try_into().expect("8 bytes"));
        let mut rk = [0u32; 32];
        for (i, kc) in KC.iter().enumerate() {
            let (k0, k1, k2, k3) = (
                (k01 >> 32) as u32,
                k01 as u32,
                (k23 >> 32) as u32,
                k23 as u32,
            );
            rk[2 * i] = k0.wrapping_add(k2).wrapping_sub(*kc);
            rk[2 * i + 1] = k1.wrapping_sub(k3).wrapping_add(*kc);
            // Rounds are numbered from 1: odd rounds rotate Key0 || Key1, even ones Key2 || Key3.
            if i % 2 == 0 {
                k01 = k01.rotate_right(8);
            } else {
                k23 = k23.rotate_left(8);
            }
        }
        // The G inputs do not depend on G outputs: all 32 go through in two passes.
        let (a, b) = rk.split_at_mut(LANES);
        g16(a.try_into().expect("16 words"));
        g16(b.try_into().expect("16 words"));
        Seed { rk }
    }

    /// The key schedule of `key`, which must be 16 bytes ([`Error::InvalidLength`] otherwise).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] for a key of another length.
    pub fn from_slice(key: &[u8]) -> Result<Seed, Error> {
        let key: &[u8; KEY_LEN] = key.try_into().map_err(|_| Error::InvalidLength)?;
        Ok(Seed::new(key))
    }

    /// Encrypts one block in place.
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        self.crypt(std::slice::from_mut(block), false);
    }

    /// Decrypts one block in place.
    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        self.crypt(std::slice::from_mut(block), true);
    }

    /// Encrypts blocks in place (ECB), sixteen at a time.
    pub fn encrypt_blocks(&self, blocks: &mut [[u8; BLOCK_LEN]]) {
        for c in blocks.chunks_mut(LANES) {
            self.crypt(c, false);
        }
    }

    /// Decrypts blocks in place (ECB), sixteen at a time.
    pub fn decrypt_blocks(&self, blocks: &mut [[u8; BLOCK_LEN]]) {
        for c in blocks.chunks_mut(LANES) {
            self.crypt(c, true);
        }
    }

    /// XORs `data` with the CTR keystream that starts at the counter block `counter` and
    /// increments the whole block as a 128-bit big-endian integer (SP 800-38A; SRTP SEED-CTR,
    /// RFC 5669 §2.1). Encryption and decryption are the same operation.
    pub fn apply_ctr(&self, counter: &[u8; BLOCK_LEN], data: &mut [u8]) {
        let c = u128::from_be_bytes(*counter);
        self.ctr(data, None, |i| c.wrapping_add(i).to_be_bytes());
    }

    /// XORs `data` with the encryptions of `ctr(0)`, `ctr(1)`, …; `lead`, when given, is
    /// encrypted in place in the first batch (GCM's `E(J0)`, CCM's `S0`), so a short message
    /// takes one batch in all.
    fn ctr(
        &self,
        data: &mut [u8],
        mut lead: Option<&mut [u8; BLOCK_LEN]>,
        ctr: impl Fn(u128) -> [u8; BLOCK_LEN],
    ) {
        let mut next = 0u128;
        let mut rest = data;
        loop {
            let mut ks = [[0u8; BLOCK_LEN]; LANES];
            let first = usize::from(lead.is_some());
            if let Some(l) = &lead {
                ks[0] = **l;
            }
            let room = (LANES - first) * BLOCK_LEN;
            let take = rest.len().min(room);
            let n = take.div_ceil(BLOCK_LEN);
            for (j, b) in ks[first..first + n].iter_mut().enumerate() {
                *b = ctr(next + j as u128);
            }
            if first + n == 0 {
                return;
            }
            self.crypt(&mut ks[..first + n], false);
            if let Some(l) = lead.take() {
                *l = ks[0];
            }
            let (chunk, tail) = rest.split_at_mut(take);
            for (d, k) in chunk.iter_mut().zip(ks[first..].as_flattened()) {
                *d ^= k;
            }
            next += n as u128;
            rest = tail;
            if rest.is_empty() {
                return;
            }
        }
    }

    /// The sixteen rounds over up to [`LANES`] blocks.
    fn crypt(&self, blocks: &mut [[u8; BLOCK_LEN]], decrypt: bool) {
        debug_assert!(blocks.len() <= LANES);
        if let [b] = blocks {
            self.crypt1(b, decrypt);
            return;
        }
        let (mut l0, mut l1, mut r0, mut r1) =
            ([0u32; LANES], [0u32; LANES], [0u32; LANES], [0u32; LANES]);
        for (j, b) in blocks.iter().enumerate() {
            l0[j] = be32(b, 0);
            l1[j] = be32(b, 4);
            r0[j] = be32(b, 8);
            r1[j] = be32(b, 12);
        }
        for round in 0..16 {
            let k = if decrypt { 15 - round } else { round };
            let (f0, f1) = f16(&r0, &r1, self.rk[2 * k], self.rk[2 * k + 1]);
            for j in 0..LANES {
                l0[j] ^= f0[j];
                l1[j] ^= f1[j];
            }
            // The last round does not swap.
            if round < 15 {
                std::mem::swap(&mut l0, &mut r0);
                std::mem::swap(&mut l1, &mut r1);
            }
        }
        for (j, b) in blocks.iter_mut().enumerate() {
            b[..4].copy_from_slice(&l0[j].to_be_bytes());
            b[4..8].copy_from_slice(&l1[j].to_be_bytes());
            b[8..12].copy_from_slice(&r0[j].to_be_bytes());
            b[12..].copy_from_slice(&r1[j].to_be_bytes());
        }
    }
}

impl Seed {
    /// The sixteen rounds over one block, with the one-word G ([`g1`]): a CBC-MAC step costs
    /// less than a sixteen-block batch.
    fn crypt1(&self, b: &mut [u8; BLOCK_LEN], decrypt: bool) {
        let (mut l0, mut l1, mut r0, mut r1) = (be32(b, 0), be32(b, 4), be32(b, 8), be32(b, 12));
        for round in 0..16 {
            let k = if decrypt { 15 - round } else { round };
            let c = r0 ^ self.rk[2 * k];
            let a = g1(c ^ r1 ^ self.rk[2 * k + 1]);
            let bb = g1(a.wrapping_add(c));
            let f1 = g1(bb.wrapping_add(a));
            l0 ^= f1.wrapping_add(bb);
            l1 ^= f1;
            if round < 15 {
                std::mem::swap(&mut l0, &mut r0);
                std::mem::swap(&mut l1, &mut r1);
            }
        }
        b[..4].copy_from_slice(&l0.to_be_bytes());
        b[4..8].copy_from_slice(&l1.to_be_bytes());
        b[8..12].copy_from_slice(&r0.to_be_bytes());
        b[12..].copy_from_slice(&r1.to_be_bytes());
    }
}

fn be32(b: &[u8; BLOCK_LEN], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// The round function F (RFC 4269 §2.1) on sixteen right halves `(R0, R1)` under one subkey.
#[inline(always)]
fn f16(r0: &[u32; LANES], r1: &[u32; LANES], k0: u32, k1: u32) -> ([u32; LANES], [u32; LANES]) {
    let mut c = [0u32; LANES];
    let mut x = [0u32; LANES];
    for j in 0..LANES {
        c[j] = r0[j] ^ k0;
        x[j] = c[j] ^ r1[j] ^ k1;
    }
    g16(&mut x);
    let a = x;
    for j in 0..LANES {
        x[j] = a[j].wrapping_add(c[j]);
    }
    g16(&mut x);
    let b = x;
    for j in 0..LANES {
        x[j] = b[j].wrapping_add(a[j]);
    }
    g16(&mut x);
    let mut y0 = [0u32; LANES];
    for j in 0..LANES {
        y0[j] = x[j].wrapping_add(b[j]);
    }
    (y0, x)
}

/// Lanes holding bytes `X0` and `X2` of a G input (S-box `S0`); the others hold `X1`, `X3`
/// (`S1`). Byte `p` of word `k` of the packed input sits at lane `8p + k` (see [`transpose`]).
const S0_LANES: u64 = 0x00ff_00ff_00ff_00ff;

/// The S-boxes' constants, per bit plane: 0xA9 on `S0` lanes, 0x38 on `S1` lanes.
const SBOX_CONST: [u64; 8] = {
    let mut c = [0u64; 8];
    let mut i = 0;
    while i < 8 {
        if (0xa9 >> i) & 1 == 1 {
            c[i] |= S0_LANES;
        }
        if (0x38 >> i) & 1 == 1 {
            c[i] |= !S0_LANES;
        }
        i += 1;
    }
    c
};

/// The function G (RFC 4269 §2.2) on sixteen words.
#[inline(always)]
fn g16(x: &mut [u32; LANES]) {
    let mut w = [0u64; 8];
    for (k, w) in w.iter_mut().enumerate() {
        *w = u64::from(x[2 * k]) | (u64::from(x[2 * k + 1]) << 32);
    }
    transpose(&mut w);
    let mut s = to_aes_field(&w);
    bitsliced_sub_bytes(&mut s);
    let (a, b) = (s0_out(&s), s1_out(&s));
    for i in 0..8 {
        w[i] = ((a[i] & S0_LANES) | (b[i] & !S0_LANES)) ^ SBOX_CONST[i];
    }
    transpose(&mut w);
    for (k, w) in w.iter().enumerate() {
        x[2 * k] = mix(*w as u32);
        x[2 * k + 1] = mix((*w >> 32) as u32);
    }
}

/// Transposes the 8×8 bit matrix in `x` (bit `c` of byte `r` to bit `r` of byte `c`).
#[inline(always)]
fn transpose8(x: u64) -> u64 {
    let x = (x & 0xaa55_aa55_aa55_aa55)
        | ((x & 0x00aa_00aa_00aa_00aa) << 7)
        | ((x >> 7) & 0x00aa_00aa_00aa_00aa);
    let x = (x & 0xcccc_3333_cccc_3333)
        | ((x & 0x0000_cccc_0000_cccc) << 14)
        | ((x >> 14) & 0x0000_cccc_0000_cccc);
    (x & 0xf0f0_f0f0_0f0f_0f0f)
        | ((x & 0x0000_0000_f0f0_f0f0) << 28)
        | ((x >> 28) & 0x0000_0000_f0f0_f0f0)
}

/// [`SBOX_CONST`] for [`g1`]: bit `p` of each plane is byte `Xp`.
const SBOX_CONST1: [u64; 8] = {
    let mut c = [0u64; 8];
    let mut i = 0;
    while i < 8 {
        c[i] = (((0xa9 >> i) & 1) * 0x55) | (((0x38 >> i) & 1) * 0xaa);
        i += 1;
    }
    c
};

/// The function G on one word: the same circuit with the four bytes as four lanes.
#[inline(always)]
fn g1(x: u32) -> u32 {
    let t = transpose8(u64::from(x));
    let w: [u64; 8] = std::array::from_fn(|b| (t >> (8 * b)) & 0xff);
    let mut s = to_aes_field(&w);
    bitsliced_sub_bytes(&mut s);
    let (a, c) = (s0_out(&s), s1_out(&s));
    let mut r = 0u64;
    for b in 0..8 {
        r |= ((((a[b] & 0x55) | (c[b] & 0xaa)) ^ SBOX_CONST1[b]) & 0x0f) << (8 * b);
    }
    mix(transpose8(r) as u32)
}

/// G's permutation layer on the S-box outputs `Y3 || Y2 || Y1 || Y0`:
/// `Zj = ⊕i Yi & m(i+j mod 4)`, that is `⊕r rotr(Y, 8r) & mask_r`.
#[inline(always)]
fn mix(y: u32) -> u32 {
    (y & 0xcffc_cffc)
        ^ (y.rotate_right(8) & 0x3ff3_3ff3)
        ^ (y.rotate_right(16) & 0xfccf_fccf)
        ^ (y.rotate_right(24) & 0xf33f_f33f)
}

#[inline(always)]
fn swapmove(a: &mut u64, b: &mut u64, n: u32, m: u64) {
    let t = ((*a >> n) ^ *b) & m;
    *b ^= t;
    *a ^= t << n;
}

/// Transposes eight words as eight 8×8 bit matrices: afterwards word `b` holds bit `b` of every
/// byte, bit `b` of byte `p` of word `k` landing at bit `8p + k`. Its own inverse.
#[inline(always)]
fn transpose(w: &mut [u64; 8]) {
    for (n, m) in [
        (1, 0x5555_5555_5555_5555),
        (2, 0x3333_3333_3333_3333),
        (4, 0x0f0f_0f0f_0f0f_0f0f),
    ] {
        for i in 0..8 {
            if i & n == 0 {
                let (lo, hi) = w.split_at_mut(i + n);
                swapmove(&mut lo[i], &mut hi[0], n as u32, m);
            }
        }
    }
}

// The linear maps around the AES S-box circuit (derived and checked against the RFC 4269
// tables for every input, see the tests): `to_aes_field` is the field isomorphism φ from
// GF(2⁸)/(x⁸+x⁶+x⁵+x+1) to AES's GF(2⁸)/(x⁸+x⁴+x³+x+1) sending x to 0x19; `s0_out` and
// `s1_out` are `A0·F³·φ⁻¹·M⁻¹` and `A1·F²·φ⁻¹·M⁻¹` (F the squaring, M the AES affine map's
// linear part that the circuit applies), so that `S0(x) = s0_out(circuit(φ(x))) ⊕ 0xA9` and
// `S1(x) = s1_out(circuit(φ(x))) ⊕ 0x38`.

#[inline(always)]
fn to_aes_field(x: &[u64; 8]) -> [u64; 8] {
    [
        x[0] ^ x[1] ^ x[3],
        x[2] ^ x[3] ^ x[6] ^ x[7],
        x[4] ^ x[5] ^ x[7],
        x[1] ^ x[2] ^ x[3] ^ x[5],
        x[1] ^ x[2] ^ x[4],
        x[3] ^ x[4],
        x[2] ^ x[3] ^ x[4] ^ x[5],
        x[4] ^ x[5] ^ x[6],
    ]
}

#[inline(always)]
fn s0_out(x: &[u64; 8]) -> [u64; 8] {
    [
        x[2] ^ x[4] ^ x[5] ^ x[6],
        x[2] ^ x[4] ^ x[6] ^ x[7],
        x[0] ^ x[1] ^ x[4] ^ x[6],
        x[0] ^ x[2] ^ x[4] ^ x[5] ^ x[6] ^ x[7],
        x[0] ^ x[2] ^ x[3] ^ x[4] ^ x[6],
        x[0] ^ x[1] ^ x[3] ^ x[5] ^ x[6],
        x[0] ^ x[4] ^ x[5] ^ x[6],
        x[1] ^ x[3] ^ x[6] ^ x[7],
    ]
}

#[inline(always)]
fn s1_out(x: &[u64; 8]) -> [u64; 8] {
    [
        x[1] ^ x[3],
        x[1] ^ x[4] ^ x[5] ^ x[6] ^ x[7],
        x[0] ^ x[2] ^ x[3] ^ x[4] ^ x[6],
        x[0] ^ x[1] ^ x[3] ^ x[4] ^ x[5] ^ x[6],
        x[3] ^ x[6] ^ x[7],
        x[3] ^ x[4] ^ x[5] ^ x[6],
        x[1] ^ x[2] ^ x[3] ^ x[6],
        x[3],
    ]
}

/// The GCM nonce length in bytes.
pub const GCM_NONCE_LEN: usize = 12;

/// SEED-GCM (NIST SP 800-38D with SEED; RFC 5669 §2.3): 96-bit nonces, tags of 16 bytes or
/// truncated (SRTP uses 12). GHASH is the portable constant-time one of [`crate::gcm`].
#[derive(Clone)]
pub struct SeedGcm {
    seed: Seed,
    h: (u64, u64),
}

impl std::fmt::Debug for SeedGcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeedGcm").finish_non_exhaustive()
    }
}

impl SeedGcm {
    /// A SEED-GCM key.
    #[must_use]
    pub fn new(key: &[u8; KEY_LEN]) -> SeedGcm {
        let seed = Seed::new(key);
        let mut h = [0u8; BLOCK_LEN];
        seed.encrypt_block(&mut h);
        SeedGcm {
            seed,
            h: be_pair(&h),
        }
    }

    /// CTR over `buf` from `inc32(J0)`, with `E(J0)` from the first batch.
    fn ctr(&self, nonce: &[u8; GCM_NONCE_LEN], buf: &mut [u8]) -> [u8; BLOCK_LEN] {
        let mut j0 = [0u8; BLOCK_LEN];
        j0[..GCM_NONCE_LEN].copy_from_slice(nonce);
        j0[15] = 1;
        let base = j0;
        self.seed.ctr(buf, Some(&mut j0), |i| {
            let mut b = base;
            let c = 2u32.wrapping_add(i as u32);
            b[12..].copy_from_slice(&c.to_be_bytes());
            b
        });
        j0
    }

    fn tag(&self, ek0: &[u8; BLOCK_LEN], aad: &[u8], ct: &[u8]) -> [u8; BLOCK_LEN] {
        let mut t = portable_ghash(self.h, aad, ct);
        for (t, k) in t.iter_mut().zip(ek0) {
            *t ^= k;
        }
        t
    }

    /// Encrypts `buf` in place and returns the full 16-byte tag (truncate it for shorter tags).
    ///
    /// # Panics
    ///
    /// If `buf` is longer than GCM allows (about 64 GiB).
    pub fn encrypt_in_place_detached(
        &self,
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
    ) -> [u8; BLOCK_LEN] {
        assert!(
            buf.len() as u64 <= ((1 << 32) - 2) * 16,
            "GCM message too long"
        );
        let ek0 = self.ctr(nonce, buf);
        self.tag(&ek0, aad, buf)
    }

    /// Verifies `tag` (16 bytes, or truncated to 15, 14, 13, 12, 8 or 4) over `aad` and the
    /// ciphertext `buf`, then decrypts `buf` in place. On failure `buf` is left as it was.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] for another tag length, [`Error::Verification`] when the tag
    /// does not match.
    pub fn decrypt_in_place_detached(
        &self,
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        if !matches!(tag.len(), 4 | 8 | 12..=16) {
            return Err(Error::InvalidLength);
        }
        if buf.len() as u64 > ((1 << 32) - 2) * 16 {
            return Err(Error::Verification);
        }
        let mut j0 = [0u8; BLOCK_LEN];
        j0[..GCM_NONCE_LEN].copy_from_slice(nonce);
        j0[15] = 1;
        // Short messages: one batch for E(J0) and the keystream, applied only once the tag
        // verified.
        if buf.len() <= (LANES - 1) * BLOCK_LEN {
            let mut ks = [0u8; (LANES - 1) * BLOCK_LEN];
            let ks = &mut ks[..buf.len()];
            let ek0 = self.ctr(nonce, ks);
            if !crate::ct_eq(&self.tag(&ek0, aad, buf)[..tag.len()], tag) {
                return Err(Error::Verification);
            }
            for (d, k) in buf.iter_mut().zip(ks.iter()) {
                *d ^= k;
            }
            return Ok(());
        }
        self.seed.encrypt_block(&mut j0);
        if !crate::ct_eq(&self.tag(&j0, aad, buf)[..tag.len()], tag) {
            return Err(Error::Verification);
        }
        self.ctr(nonce, buf);
        Ok(())
    }
}

/// SEED-CCM (RFC 3610 with SEED; RFC 5669 §2.2): nonces of 7 to 13 bytes (SRTP: 12), tags of
/// 4 to 16 bytes, even (SRTP: 10). The CBC-MAC runs one block at a time.
#[derive(Clone)]
pub struct SeedCcm {
    seed: Seed,
}

impl std::fmt::Debug for SeedCcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeedCcm").finish_non_exhaustive()
    }
}

impl SeedCcm {
    /// A SEED-CCM key.
    #[must_use]
    pub fn new(key: &[u8; KEY_LEN]) -> SeedCcm {
        SeedCcm {
            seed: Seed::new(key),
        }
    }

    /// Encrypts `buf` in place and writes the tag into `tag` (its length is the tag length).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] for a nonce or tag length CCM does not allow, or a message too
    /// long for the nonce length (2^(8·(15 - nonce length)) bytes); nothing is changed then.
    pub fn encrypt_in_place_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), Error> {
        ccm_seal(&self.seed, nonce, aad, buf, tag)
    }

    /// Decrypts `buf` in place and verifies `tag`. On failure `buf` is zeroed (CCM
    /// authenticates the plaintext, so it is decrypted first; none of it is released).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] as for encryption, [`Error::Verification`] when the tag does
    /// not match.
    pub fn decrypt_in_place_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        ccm_open(&self.seed, nonce, aad, buf, tag)
    }
}

/// A 128-bit block cipher for the CCM construction (SEED; AES for the RFC 3610 vectors).
pub(crate) trait Block128 {
    /// Encrypts one block in place.
    fn encrypt1(&self, b: &mut [u8; BLOCK_LEN]);
    /// XORs `data` with the encryptions of the counter blocks from `a1` on (a 128-bit
    /// increment), and encrypts `a0` in place.
    fn ctr_with_lead(&self, a0: &mut [u8; BLOCK_LEN], a1: u128, data: &mut [u8]);
}

impl Block128 for Seed {
    fn encrypt1(&self, b: &mut [u8; BLOCK_LEN]) {
        self.encrypt_block(b);
    }

    fn ctr_with_lead(&self, a0: &mut [u8; BLOCK_LEN], a1: u128, data: &mut [u8]) {
        self.ctr(data, Some(a0), |i| a1.wrapping_add(i).to_be_bytes());
    }
}

impl Block128 for Aes {
    fn encrypt1(&self, b: &mut [u8; BLOCK_LEN]) {
        self.encrypt_block(b);
    }

    fn ctr_with_lead(&self, a0: &mut [u8; BLOCK_LEN], a1: u128, data: &mut [u8]) {
        self.encrypt_block(a0);
        self.apply_ctr(&a1.to_be_bytes(), data);
    }
}

/// The CCM parameters checked: `L` (the length field size) for `nonce`, `tag` and a message of
/// `len` bytes.
fn ccm_params(nonce: &[u8], tag_len: usize, len: usize) -> Result<usize, Error> {
    if !(7..=13).contains(&nonce.len()) || !(4..=16).contains(&tag_len) || tag_len % 2 != 0 {
        return Err(Error::InvalidLength);
    }
    let l = 15 - nonce.len();
    if l < 8 && (len as u64) >> (8 * l) != 0 {
        return Err(Error::InvalidLength);
    }
    Ok(l)
}

/// `A0`, the first counter block (RFC 3610 §2.3); `Ai` is `A0 + i`.
fn ccm_a0(nonce: &[u8], l: usize) -> [u8; BLOCK_LEN] {
    let mut a = [0u8; BLOCK_LEN];
    a[0] = (l - 1) as u8;
    a[1..=nonce.len()].copy_from_slice(nonce);
    a
}

/// The CBC-MAC `T` over `aad` and the plaintext `msg` (RFC 3610 §2.2), all 16 bytes.
fn ccm_mac<C: Block128>(
    c: &C,
    nonce: &[u8],
    l: usize,
    tag_len: usize,
    aad: &[u8],
    msg: &[u8],
) -> [u8; BLOCK_LEN] {
    let mut x = [0u8; BLOCK_LEN];
    x[0] = (u8::from(!aad.is_empty()) << 6) | ((((tag_len - 2) / 2) as u8) << 3) | (l - 1) as u8;
    x[1..=nonce.len()].copy_from_slice(nonce);
    let len = (msg.len() as u64).to_be_bytes();
    x[16 - l..].copy_from_slice(&len[8 - l..]);
    c.encrypt1(&mut x);
    let absorb = |data: &[u8], x: &mut [u8; BLOCK_LEN]| {
        for chunk in data.chunks(BLOCK_LEN) {
            for (x, d) in x.iter_mut().zip(chunk) {
                *x ^= d;
            }
            c.encrypt1(x);
        }
    };
    if !aad.is_empty() {
        // The encoded length l(a), then the AAD, padded with zeros as one string.
        let n = aad.len() as u64;
        let mut first = [0u8; BLOCK_LEN];
        let enc: &[u8] = if n < 0xff00 {
            &n.to_be_bytes()[6..]
        } else if n >> 32 == 0 {
            first[..2].copy_from_slice(&[0xff, 0xfe]);
            &n.to_be_bytes()[4..]
        } else {
            first[..2].copy_from_slice(&[0xff, 0xff]);
            &n.to_be_bytes()[..]
        };
        let at = if n < 0xff00 { 0 } else { 2 };
        first[at..at + enc.len()].copy_from_slice(enc);
        let head = at + enc.len();
        let take = aad.len().min(BLOCK_LEN - head);
        first[head..head + take].copy_from_slice(&aad[..take]);
        absorb(&first, &mut x);
        absorb(&aad[take..], &mut x);
    }
    absorb(msg, &mut x);
    x
}

pub(crate) fn ccm_seal<C: Block128>(
    c: &C,
    nonce: &[u8],
    aad: &[u8],
    buf: &mut [u8],
    tag: &mut [u8],
) -> Result<(), Error> {
    let l = ccm_params(nonce, tag.len(), buf.len())?;
    let t = ccm_mac(c, nonce, l, tag.len(), aad, buf);
    let mut s0 = ccm_a0(nonce, l);
    let a1 = u128::from_be_bytes(s0) + 1;
    c.ctr_with_lead(&mut s0, a1, buf);
    for ((o, t), s) in tag.iter_mut().zip(t).zip(s0) {
        *o = t ^ s;
    }
    Ok(())
}

pub(crate) fn ccm_open<C: Block128>(
    c: &C,
    nonce: &[u8],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8],
) -> Result<(), Error> {
    let l = ccm_params(nonce, tag.len(), buf.len())?;
    let mut s0 = ccm_a0(nonce, l);
    let a1 = u128::from_be_bytes(s0) + 1;
    c.ctr_with_lead(&mut s0, a1, buf);
    let mut want = ccm_mac(c, nonce, l, tag.len(), aad, buf);
    for (w, s) in want.iter_mut().zip(s0) {
        *w ^= s;
    }
    if crate::ct_eq(&want[..tag.len()], tag) {
        Ok(())
    } else {
        buf.fill(0);
        Err(Error::Verification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(char::is_ascii_hexdigit).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn arr(s: &str) -> [u8; 16] {
        hex(s).try_into().unwrap()
    }

    /// RFC 4269 Appendix A.1.
    const S0: [u8; 256] = [
        0xa9, 0x85, 0xd6, 0xd3, 0x54, 0x1d, 0xac, 0x25, 0x5d, 0x43, 0x18, 0x1e, 0x51, 0xfc, 0xca,
        0x63, 0x28, 0x44, 0x20, 0x9d, 0xe0, 0xe2, 0xc8, 0x17, 0xa5, 0x8f, 0x03, 0x7b, 0xbb, 0x13,
        0xd2, 0xee, 0x70, 0x8c, 0x3f, 0xa8, 0x32, 0xdd, 0xf6, 0x74, 0xec, 0x95, 0x0b, 0x57, 0x5c,
        0x5b, 0xbd, 0x01, 0x24, 0x1c, 0x73, 0x98, 0x10, 0xcc, 0xf2, 0xd9, 0x2c, 0xe7, 0x72, 0x83,
        0x9b, 0xd1, 0x86, 0xc9, 0x60, 0x50, 0xa3, 0xeb, 0x0d, 0xb6, 0x9e, 0x4f, 0xb7, 0x5a, 0xc6,
        0x78, 0xa6, 0x12, 0xaf, 0xd5, 0x61, 0xc3, 0xb4, 0x41, 0x52, 0x7d, 0x8d, 0x08, 0x1f, 0x99,
        0x00, 0x19, 0x04, 0x53, 0xf7, 0xe1, 0xfd, 0x76, 0x2f, 0x27, 0xb0, 0x8b, 0x0e, 0xab, 0xa2,
        0x6e, 0x93, 0x4d, 0x69, 0x7c, 0x09, 0x0a, 0xbf, 0xef, 0xf3, 0xc5, 0x87, 0x14, 0xfe, 0x64,
        0xde, 0x2e, 0x4b, 0x1a, 0x06, 0x21, 0x6b, 0x66, 0x02, 0xf5, 0x92, 0x8a, 0x0c, 0xb3, 0x7e,
        0xd0, 0x7a, 0x47, 0x96, 0xe5, 0x26, 0x80, 0xad, 0xdf, 0xa1, 0x30, 0x37, 0xae, 0x36, 0x15,
        0x22, 0x38, 0xf4, 0xa7, 0x45, 0x4c, 0x81, 0xe9, 0x84, 0x97, 0x35, 0xcb, 0xce, 0x3c, 0x71,
        0x11, 0xc7, 0x89, 0x75, 0xfb, 0xda, 0xf8, 0x94, 0x59, 0x82, 0xc4, 0xff, 0x49, 0x39, 0x67,
        0xc0, 0xcf, 0xd7, 0xb8, 0x0f, 0x8e, 0x42, 0x23, 0x91, 0x6c, 0xdb, 0xa4, 0x34, 0xf1, 0x48,
        0xc2, 0x6f, 0x3d, 0x2d, 0x40, 0xbe, 0x3e, 0xbc, 0xc1, 0xaa, 0xba, 0x4e, 0x55, 0x3b, 0xdc,
        0x68, 0x7f, 0x9c, 0xd8, 0x4a, 0x56, 0x77, 0xa0, 0xed, 0x46, 0xb5, 0x2b, 0x65, 0xfa, 0xe3,
        0xb9, 0xb1, 0x9f, 0x5e, 0xf9, 0xe6, 0xb2, 0x31, 0xea, 0x6d, 0x5f, 0xe4, 0xf0, 0xcd, 0x88,
        0x16, 0x3a, 0x58, 0xd4, 0x62, 0x29, 0x07, 0x33, 0xe8, 0x1b, 0x05, 0x79, 0x90, 0x6a, 0x2a,
        0x9a,
    ];

    /// RFC 4269 Appendix A.1.
    const S1: [u8; 256] = [
        0x38, 0xe8, 0x2d, 0xa6, 0xcf, 0xde, 0xb3, 0xb8, 0xaf, 0x60, 0x55, 0xc7, 0x44, 0x6f, 0x6b,
        0x5b, 0xc3, 0x62, 0x33, 0xb5, 0x29, 0xa0, 0xe2, 0xa7, 0xd3, 0x91, 0x11, 0x06, 0x1c, 0xbc,
        0x36, 0x4b, 0xef, 0x88, 0x6c, 0xa8, 0x17, 0xc4, 0x16, 0xf4, 0xc2, 0x45, 0xe1, 0xd6, 0x3f,
        0x3d, 0x8e, 0x98, 0x28, 0x4e, 0xf6, 0x3e, 0xa5, 0xf9, 0x0d, 0xdf, 0xd8, 0x2b, 0x66, 0x7a,
        0x27, 0x2f, 0xf1, 0x72, 0x42, 0xd4, 0x41, 0xc0, 0x73, 0x67, 0xac, 0x8b, 0xf7, 0xad, 0x80,
        0x1f, 0xca, 0x2c, 0xaa, 0x34, 0xd2, 0x0b, 0xee, 0xe9, 0x5d, 0x94, 0x18, 0xf8, 0x57, 0xae,
        0x08, 0xc5, 0x13, 0xcd, 0x86, 0xb9, 0xff, 0x7d, 0xc1, 0x31, 0xf5, 0x8a, 0x6a, 0xb1, 0xd1,
        0x20, 0xd7, 0x02, 0x22, 0x04, 0x68, 0x71, 0x07, 0xdb, 0x9d, 0x99, 0x61, 0xbe, 0xe6, 0x59,
        0xdd, 0x51, 0x90, 0xdc, 0x9a, 0xa3, 0xab, 0xd0, 0x81, 0x0f, 0x47, 0x1a, 0xe3, 0xec, 0x8d,
        0xbf, 0x96, 0x7b, 0x5c, 0xa2, 0xa1, 0x63, 0x23, 0x4d, 0xc8, 0x9e, 0x9c, 0x3a, 0x0c, 0x2e,
        0xba, 0x6e, 0x9f, 0x5a, 0xf2, 0x92, 0xf3, 0x49, 0x78, 0xcc, 0x15, 0xfb, 0x70, 0x75, 0x7f,
        0x35, 0x10, 0x03, 0x64, 0x6d, 0xc6, 0x74, 0xd5, 0xb4, 0xea, 0x09, 0x76, 0x19, 0xfe, 0x40,
        0x12, 0xe0, 0xbd, 0x05, 0xfa, 0x01, 0xf0, 0x2a, 0x5e, 0xa9, 0x56, 0x43, 0x85, 0x14, 0x89,
        0x9b, 0xb0, 0xe5, 0x48, 0x79, 0x97, 0xfc, 0x1e, 0x82, 0x21, 0x8c, 0x1b, 0x5f, 0x77, 0x54,
        0xb2, 0x1d, 0x25, 0x4f, 0x00, 0x46, 0xed, 0x58, 0x52, 0xeb, 0x7e, 0xda, 0xc9, 0xfd, 0x30,
        0x95, 0x65, 0x3c, 0xb6, 0xe4, 0xbb, 0x7c, 0x0e, 0x50, 0x39, 0x26, 0x32, 0x84, 0x69, 0x93,
        0x37, 0xe7, 0x24, 0xa4, 0xcb, 0x53, 0x0a, 0x87, 0xd9, 0x4c, 0x83, 0x8f, 0xce, 0x3b, 0x4a,
        0xb7,
    ];

    /// G from the RFC tables (the SS-box form of RFC 4269 §2.2).
    fn g_ref(x: u32) -> u32 {
        let b = x.to_le_bytes();
        let y = [
            S0[b[0] as usize],
            S1[b[1] as usize],
            S0[b[2] as usize],
            S1[b[3] as usize],
        ];
        let m = [0xfcu8, 0xf3, 0xcf, 0x3f];
        let mut z = [0u8; 4];
        for (j, z) in z.iter_mut().enumerate() {
            for (i, y) in y.iter().enumerate() {
                *z ^= y & m[(i + j) % 4];
            }
        }
        u32::from_le_bytes(z)
    }

    #[test]
    #[allow(clippy::needless_range_loop)]
    fn transpose_layout() {
        let mut w = [0u64; 8];
        for k in 0..8 {
            for p in 0..8 {
                w[k] |= u64::from((k * 8 + p) as u8 ^ 0x5a) << (8 * p);
            }
        }
        let orig = w;
        transpose(&mut w);
        for b in 0..8 {
            for k in 0..8 {
                for p in 0..8 {
                    assert_eq!((w[b] >> (8 * p + k)) & 1, (orig[k] >> (8 * p + b)) & 1);
                }
            }
        }
        transpose(&mut w);
        assert_eq!(w, orig);
    }

    /// The circuit against the RFC 4269 tables, every input in every lane position.
    #[test]
    fn g_matches_tables() {
        for base in (0..256u32).step_by(4) {
            let mut x = [0u32; LANES];
            for (j, x) in x.iter_mut().enumerate() {
                let v = (base + j as u32) & 0xff;
                *x = v
                    | (((v + 1) & 0xff) << 8)
                    | (((v + 2) & 0xff) << 16)
                    | (((v + 3) & 0xff) << 24);
                *x = x.rotate_left(8 * (j as u32 % 4));
            }
            let want: Vec<u32> = x.iter().map(|&x| g_ref(x)).collect();
            let one: Vec<u32> = x.iter().map(|&x| g1(x)).collect();
            assert_eq!(one, want);
            g16(&mut x);
            assert_eq!(x.to_vec(), want);
        }
    }

    /// RFC 4269 Appendix B.1-B.4, both ways, singly and in batches with other blocks.
    #[test]
    fn rfc4269_vectors() {
        let v = [
            (
                "00000000000000000000000000000000",
                "000102030405060708090A0B0C0D0E0F",
                "5EBAC6E0054E166819AFF1CC6D346CDB",
            ),
            (
                "000102030405060708090A0B0C0D0E0F",
                "00000000000000000000000000000000",
                "C11F22F20140505084483597E4370F43",
            ),
            (
                "4706480851E61BE85D74BFB3FD956185",
                "83A2F8A288641FB9A4E9A5CC2F131C7D",
                "EE54D13EBCAE706D226BC3142CD40D4A",
            ),
            (
                "28DBC3BC49FFD87DCFA509B11D422BE7",
                "B41E6BE2EBA84A148E2EED84593C5EC7",
                "9B9B7BFCD1813CB95D0B3618F40F5122",
            ),
        ];
        for (k, p, c) in v {
            let s = Seed::new(&arr(k));
            let mut b = arr(p);
            s.encrypt_block(&mut b);
            assert_eq!(b, arr(c));
            s.decrypt_block(&mut b);
            assert_eq!(b, arr(p));
            let mut many = vec![arr(p); 37];
            many[5] = [0x11; 16];
            s.encrypt_blocks(&mut many);
            assert_eq!(many[0], arr(c));
            assert_eq!(many[36], arr(c));
            s.decrypt_blocks(&mut many);
            assert_eq!(many[36], arr(p));
            assert_eq!(many[5], [0x11; 16]);
        }
        // B.4 round keys.
        let s = Seed::new(&arr("28DBC3BC49FFD87DCFA509B11D422BE7"));
        assert_eq!(
            &s.rk[..4],
            &[0xb2b1_1b63, 0x2ee9_e2d1, 0x1196_7260, 0x71a6_2f24]
        );
        assert_eq!(&s.rk[30..], &[0xc97d_7eed, 0x9072_4a6e]);
        assert!(Seed::from_slice(&[0; 15]).is_err());
        assert!(format!("{s:?}").starts_with("Seed"));
    }

    /// SEED-ECB against OpenSSL 3.0.13 (`openssl enc -provider legacy -seed-ecb -nopad`): key
    /// bytes `7j + 16i`, three-block plaintexts of bytes `13j + 5i + 1`.
    #[test]
    fn openssl_ecb() {
        for (i, want) in [
            "9996d9e12017163ce559d47172a63aba7a7d5931d70901d1edcb1435694ec263
             87897ee4bbe62f5a2ac2c98834a57114",
            "a4e32d48d76900d73a75c4348df70b7270878c69331a6e10742e7f744f391bf0
             27677a9a348b7983cceb31aa0adc87a3",
            "42efe3e6ac8ec91483c74279b3a93a50f89367778c8f41b9673fee9d8f59a598
             36fe7d9122c5ce30af916a3fb97d28a4",
        ]
        .into_iter()
        .enumerate()
        {
            let key: [u8; 16] = core::array::from_fn(|j| (j * 7 + i * 16) as u8);
            let mut blocks: Vec<[u8; 16]> = (0..3)
                .map(|b| core::array::from_fn(|j| ((16 * b + j) * 13 + i * 5 + 1) as u8))
                .collect();
            Seed::new(&key).encrypt_blocks(&mut blocks);
            assert_eq!(blocks.as_flattened(), hex(want));
        }
    }

    #[test]
    fn ctr_matches_blocks() {
        let s = Seed::new(&[7; 16]);
        let ctr0 = arr("fffffffffffffffffffffffffffffffe");
        for len in [0, 1, 15, 16, 17, 239, 240, 241, 256, 257, 1000] {
            let mut data = vec![0u8; len];
            s.apply_ctr(&ctr0, &mut data);
            let mut want = Vec::new();
            for i in 0..len.div_ceil(16) as u128 {
                let mut b = u128::from_be_bytes(ctr0).wrapping_add(i).to_be_bytes();
                s.encrypt_block(&mut b);
                want.extend_from_slice(&b);
            }
            assert_eq!(data, want[..len]);
        }
    }

    const RFC5669_PAYLOAD: &str = "f57af5fd4ae19562976ec57a5a7ad55a5af5c5e5c5fdf5c55ad57a4a7272d572
        62e9729566ed66e97ac54a4a5a7ad5e15ae5fdd5fd5ac5d56ae56ad5c572d54a
        e54ac55a956afd6aed5a4ac562957a9516991691d572fd14e97ae962ed7a9f4a
        955af572e162f57a956666e17ae1f54a95f566d54a66e16e4afd6a9f7ae1c5c5
        5ae5d56afde916c5e94a6ec56695e14afde1148416e94ad57ac5146ed59d1cc5";

    /// RFC 5669 Appendix A.1: the SEED-CTR keystream.
    #[test]
    fn rfc5669_ctr() {
        let s = Seed::new(&arr("0c5ffd37a11edc42c325287fc0604f2e"));
        let mut p = hex(RFC5669_PAYLOAD);
        s.apply_ctr(&arr("cd3a7c42e69915ed7a2a263985640000"), &mut p);
        assert_eq!(
            p,
            hex(
                "df5a89291e7e383e9beff765e691a73749c9e33139ad3001cd8da73ad07f69a2
                805a70358b5c7c8c60ed359f95cf5e08f713c53ff7b808250d79a19ccb8d1073
                4e3cb72ed1f0a4e85b002b248049ab0763dbe571bec52cf9153fdf2019e421ef
                779cd6f4bd1c8211da8c272e2fce43934b9eabb87362510f254149f992599036
                f5e43102327db1ac5e78adc4f66546ed7abfb5a4db320fb7b9c52a61bc554e44"
            )
        );
    }

    /// RFC 5669 Appendix A.2: SEED-CCM, 12-byte nonce, 10-byte tag.
    #[test]
    fn rfc5669_ccm() {
        let c = SeedCcm::new(&arr("974bee725d44fc3992267b284c3c6750"));
        let nonce = hex("000020e8f5eb00000000315e");
        let aad = hex("8008315ebf2e6fe020e8f5eb");
        let plain = hex(RFC5669_PAYLOAD);
        let mut buf = plain.clone();
        let mut tag = [0u8; 10];
        c.encrypt_in_place_detached(&nonce, &aad, &mut buf, &mut tag)
            .unwrap();
        assert_eq!(
            buf,
            hex(
                "486843a881df215a8574650ddabf5dbb2650f06f51252bccaeb4012899d6d71e
                30c64dad5ead5d8ba65ffe9d79aaf30dc9e6334490c07e7533d704114a9006ec
                b3b3bff59ecf585485bc0bd286ed434cfd684d19a1ad514ca5f37b71d93288c0
                7cf4d5e9b83db8becc8c692a7279b6a9ac62ba970fc54f46dcc926d434c0b5ad
                8678fbf0e7a03037924dae342ef64fa65b8eaea260fecb477a57e3919c5dab82"
            )
        );
        assert_eq!(tag.to_vec(), hex("b0a8274cf6a8bb6cc466"));
        let ct = buf.clone();
        c.decrypt_in_place_detached(&nonce, &aad, &mut buf, &tag)
            .unwrap();
        assert_eq!(buf, plain);
        let mut bad = ct.clone();
        bad[100] ^= 1;
        assert_eq!(
            c.decrypt_in_place_detached(&nonce, &aad, &mut bad, &tag),
            Err(Error::Verification)
        );
        assert!(bad.iter().all(|&b| b == 0));
        let mut buf = ct;
        assert_eq!(
            c.decrypt_in_place_detached(&nonce, b"other", &mut buf, &tag),
            Err(Error::Verification)
        );
        assert_eq!(
            c.encrypt_in_place_detached(&nonce[..6], &aad, &mut buf, &mut tag),
            Err(Error::InvalidLength)
        );
        assert_eq!(
            c.encrypt_in_place_detached(&nonce, &aad, &mut buf, &mut [0; 5]),
            Err(Error::InvalidLength)
        );
        assert_eq!(
            c.encrypt_in_place_detached(&[0; 13], &aad, &mut vec![0; 1 << 16], &mut tag),
            Err(Error::InvalidLength)
        );
    }

    /// RFC 3610 packet vectors #1 and #19 (AES): the CCM construction itself.
    #[test]
    fn rfc3610_ccm_with_aes() {
        for (key, nonce, input, out, m) in [
            (
                "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
                "00000003020100A0A1A2A3A4A5",
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E",
                "0001020304050607588C979A61C663D2F066D0C2C0F989806D5F6B61DAC38417E8D12CFDF926E0",
                8,
            ),
            (
                "D7828D13B2B0BDC325A76236DF93CC6B",
                "0042FFF8F1951C3C9696766CFA",
                "D85BC7E69F944FB88A19B950BCF71A018E5E6701C91787659809D67DBEDD18",
                "D85BC7E69F944FB8BC218DAA947427B6DB386A99AC1AEF23ADE0B52939CB6A637CF9BEC2408897C6BA",
                10,
            ),
        ] {
            let aes = Aes::new(&hex(key)).unwrap();
            let input = hex(input);
            let (aad, msg) = input.split_at(8);
            let mut buf = msg.to_vec();
            let mut tag = vec![0u8; m];
            ccm_seal(&aes, &hex(nonce), aad, &mut buf, &mut tag).unwrap();
            buf.extend_from_slice(&tag);
            assert_eq!([aad, &buf].concat(), hex(out));
            let mut ct = buf[..msg.len()].to_vec();
            ccm_open(&aes, &hex(nonce), aad, &mut ct, &tag).unwrap();
            assert_eq!(ct, msg);
        }
    }

    /// RFC 5669 Appendix A.3: SEED-GCM, 12-byte tag.
    #[test]
    fn rfc5669_gcm() {
        let g = SeedGcm::new(&arr("e91e5e75da65554a48181f3846349562"));
        let nonce: [u8; 12] = hex("000020e8f5eb00000000315e").try_into().unwrap();
        let aad = hex("8008315ebf2e6fe020e8f5eb");
        let plain = hex(RFC5669_PAYLOAD);
        let mut buf = plain.clone();
        let tag = g.encrypt_in_place_detached(&nonce, &aad, &mut buf);
        assert_eq!(
            buf,
            hex(
                "8a5363682c6b1bbf13c0b09cf747a5512543cb2f129b8bd0e92dfadf735cda8f
                88c4bbf90288f5e58d20c4f1bb0d58446ea009103ee57ba99cdeabaaa18d4a9a
                05ddb46e7e5290a5a2284fe50b1f6fe9ad3f1348c354181e85b24f1a552a1193
                cf0e13eed5ab95ae854fb4f5b0edb2d3ee5eb238c8f4bfb136b2eb6cd7876042
                0680ce1879100014f140a15e07e70133ed9cbb6d57b75d574acb0087eefbac99"
            )
        );
        assert_eq!(tag[..12].to_vec(), hex("36cd9ae602be3ee2cd8d5d9d"));
        let ct = buf.clone();
        g.decrypt_in_place_detached(&nonce, &aad, &mut buf, &tag[..12])
            .unwrap();
        assert_eq!(buf, plain);
        let mut bad = ct.clone();
        assert_eq!(
            g.decrypt_in_place_detached(&nonce, &aad, &mut bad, &tag[..11]),
            Err(Error::InvalidLength)
        );
        bad[0] ^= 1;
        assert_eq!(
            g.decrypt_in_place_detached(&nonce, &aad, &mut bad, &tag[..12]),
            Err(Error::Verification)
        );
        bad[0] ^= 1;
        assert_eq!(bad, ct);
        // Long messages (past one batch) and the empty one round-trip.
        for len in [0, 1, 240, 241, 1000] {
            let mut m = vec![0x42u8; len];
            let t = g.encrypt_in_place_detached(&nonce, b"a", &mut m);
            g.decrypt_in_place_detached(&nonce, b"a", &mut m, &t)
                .unwrap();
            assert_eq!(m, vec![0x42u8; len]);
        }
    }
}
