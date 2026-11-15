//! AES-GCM (NIST SP 800-38D) with 96-bit nonces and 128-bit tags.
//!
//! On x86_64 with VAES, VPCLMULQDQ and AVX-512 (detected at run time) the CTR keystream and
//! GHASH run in one pass over 512-bit vectors, sixteen blocks per loop iteration and per GHASH
//! reduction, and the whole message, its last partial group under byte masks and the tag
//! included, is one call (`hw::vaes`). With VAES and VPCLMULQDQ but no AVX-512 the same pass runs
//! on 256-bit vectors for whole 256-byte groups; the rest of such a message and other CPUs use
//! the 128-bit path below.
//!
//! GHASH multiplies in GF(2^128) on the CPU's carry-less multiplication (PCLMULQDQ on x86_64,
//! PMULL on aarch64; detected at run time, eight blocks per reduction, see `hw`), else with
//! BearSSL's constant-time `ctmul64` method (Thomas Pornin, MIT): carry-less 64x64
//! multiplications built from integer multiplications with the carries masked out, combined
//! Karatsuba style. No tables, no secret-dependent branches on either path. The CTR keystream
//! comes from [`Aes`] (eight blocks in flight on AES instructions).
//!
//! ```
//! use only_crypto::gcm::AesGcm;
//!
//! let gcm = AesGcm::new(&[7u8; 16]).unwrap();
//! let nonce = [1u8; 12];
//! let sealed = gcm.encrypt(&nonce, b"header", b"secret");
//! assert_eq!(sealed.len(), 6 + 16);
//! assert_eq!(gcm.decrypt(&nonce, b"header", &sealed).unwrap(), b"secret");
//! assert!(gcm.decrypt(&nonce, b"other header", &sealed).is_err());
//! ```

mod hw;

use crate::Error;
use crate::aes::Aes;

/// The nonce length in bytes.
pub const NONCE_LEN: usize = 12;
/// The tag length in bytes.
pub const TAG_LEN: usize = 16;

/// The longest plaintext one nonce may encrypt: 2^32 - 2 blocks (SP 800-38D section 5.2.1.1).
const MAX_LEN: u64 = ((1 << 32) - 2) * 16;

/// An AES-GCM key: AES-128-GCM, AES-192-GCM or AES-256-GCM by the key length.
#[derive(Clone)]
pub struct AesGcm {
    aes: Aes,
    h: (u64, u64),
    /// `H¹ … H⁸` (and `H¹ … H¹⁶` for the wide kernel) for the carry-less multiplication
    /// instructions, when the CPU has them.
    powers: Option<hw::Powers>,
}

impl std::fmt::Debug for AesGcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesGcm")
            .field("key_len", &self.aes.key_len())
            .finish_non_exhaustive()
    }
}

impl AesGcm {
    /// An AES-GCM key from 16, 24 or 32 bytes; anything else fails with
    /// [`Error::InvalidLength`].
    pub fn new(key: &[u8]) -> Result<AesGcm, Error> {
        Ok(Self::with_cipher(Aes::new(key)?))
    }

    /// AES-GCM over an existing AES key schedule ([`Aes::new128`] and friends make one without a
    /// fallible length check).
    #[must_use]
    pub fn with_cipher(aes: Aes) -> AesGcm {
        let mut h = [0u8; 16];
        aes.encrypt_block(&mut h);
        let h = be_pair(&h);
        AesGcm {
            aes,
            h,
            powers: hw::Powers::new([h.0, h.1], hw::Mode::Best),
        }
    }

    /// The same key on the 128-bit carry-less multiplication and AES paths even when the CPU
    /// has VAES (the wide kernels), for tests and benchmarks.
    #[doc(hidden)]
    #[must_use]
    pub fn with_cipher_narrow(aes: Aes) -> AesGcm {
        let mut g = Self::with_cipher(aes);
        g.powers = hw::Powers::new([g.h.0, g.h.1], hw::Mode::Narrow);
        g
    }

    /// The same key on the VAES-AVX2 kernel even when the CPU has AVX-512 (the 128-bit path
    /// without VAES), for tests and benchmarks: the kernel of CPUs with VAES but no AVX-512.
    #[doc(hidden)]
    #[must_use]
    pub fn with_cipher_avx2(aes: Aes) -> AesGcm {
        let mut g = Self::with_cipher(aes);
        g.powers = hw::Powers::new([g.h.0, g.h.1], hw::Mode::Avx2);
        g
    }

    /// Whether AES-GCM runs on a wide VAES / VPCLMULQDQ kernel (x86_64; AVX-512 or AVX2).
    #[doc(hidden)]
    #[must_use]
    pub fn is_wide(&self) -> bool {
        self.powers
            .as_ref()
            .is_some_and(|p| p.kernel().starts_with("vaes"))
    }

    /// The kernel AES-GCM runs on, for diagnostics and benchmark labels: `"vaes-avx512"`,
    /// `"vaes-avx2"`, `"clmul"` (AES-NI / ARMv8 AES with 128-bit carry-less multiplication) or
    /// `"portable"` (portable GHASH).
    #[doc(hidden)]
    #[must_use]
    pub fn kernel(&self) -> &'static str {
        self.powers.as_ref().map_or("portable", hw::Powers::kernel)
    }

    /// The same key on the portable GHASH (and the AES path `aes` already has), for tests and
    /// benchmarks.
    #[doc(hidden)]
    #[must_use]
    pub fn with_cipher_portable(aes: Aes) -> AesGcm {
        let mut g = Self::with_cipher(aes);
        g.powers = None;
        g
    }

    /// Whether GHASH runs on carry-less multiplication instructions.
    #[doc(hidden)]
    #[must_use]
    pub fn is_hardware(&self) -> bool {
        self.powers.is_some()
    }

    fn tag(&self, j0: &[u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
        let mut g = Ghash::new(self.h, self.powers.as_ref());
        g.update_padded(aad);
        g.update_padded(ct);
        self.finish_tag(g, j0, aad.len(), ct.len())
    }

    /// Absorbs the length block and masks the GHASH result with `E(J0)`.
    fn finish_tag(
        &self,
        mut g: Ghash<'_>,
        j0: &[u8; 16],
        aad_len: usize,
        ct_len: usize,
    ) -> [u8; 16] {
        let mut len = [0u8; 16];
        len[..8].copy_from_slice(&((aad_len as u64) << 3).to_be_bytes());
        len[8..].copy_from_slice(&((ct_len as u64) << 3).to_be_bytes());
        g.update_padded(&len);
        let mut s = g.finish();
        let mut ek = *j0;
        self.aes.encrypt_block(&mut ek);
        for (s, k) in s.iter_mut().zip(ek) {
            *s ^= k;
        }
        s
    }

    /// Encrypts `buf` in place and returns the tag.
    ///
    /// # Panics
    ///
    /// If `buf` is longer than GCM allows (about 64 GiB).
    pub fn encrypt_in_place_detached(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
    ) -> [u8; TAG_LEN] {
        assert!(buf.len() as u64 <= MAX_LEN, "AES-GCM: plaintext too long");
        let j0 = j0(nonce);
        if let Some(t) = self.fused(&j0, aad, None, buf, false) {
            return t;
        }
        self.aes.apply_ctr32(&inc32(j0), buf);
        self.tag(&j0, aad, buf)
    }

    /// Encrypts `src` followed by `dst[src.len()..]` (plaintext already in place) into `dst` and
    /// returns the tag: [`encrypt_in_place_detached`](Self::encrypt_in_place_detached) of that
    /// plaintext without copying `src` into `dst` first (the wide kernel reads `src` and writes
    /// `dst` in the same pass). For the TLS record layer.
    ///
    /// # Panics
    ///
    /// If `src` is longer than `dst`, or `dst` longer than GCM allows.
    #[doc(hidden)]
    pub fn encrypt_detached_from(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        src: &[u8],
        dst: &mut [u8],
    ) -> [u8; TAG_LEN] {
        assert!(src.len() <= dst.len(), "AES-GCM: output too short");
        assert!(dst.len() as u64 <= MAX_LEN, "AES-GCM: plaintext too long");
        let j0 = j0(nonce);
        if let Some(t) = self.fused(&j0, aad, Some(src), dst, false) {
            return t;
        }
        dst[..src.len()].copy_from_slice(src);
        self.aes.apply_ctr32(&inc32(j0), dst);
        self.tag(&j0, aad, dst)
    }

    /// Verifies `tag` over the ciphertext `src` and decrypts it into `dst` (of the same length)
    /// without copying it into `dst` first. On failure `dst` is zeroed. For the TLS record layer.
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
        assert_eq!(src.len(), dst.len(), "AES-GCM: output length");
        if tag.len() != TAG_LEN {
            return Err(Error::InvalidLength);
        }
        if src.len() as u64 > MAX_LEN {
            return Err(Error::Verification);
        }
        let j0 = j0(nonce);
        if let Some(t) = self.fused(&j0, aad, Some(src), dst, true) {
            if crate::ct_eq(&t, tag) {
                return Ok(());
            }
            dst.fill(0);
            return Err(Error::Verification);
        }
        if !crate::ct_eq(&self.tag(&j0, aad, src), tag) {
            dst.fill(0);
            return Err(Error::Verification);
        }
        dst.copy_from_slice(src);
        self.aes.apply_ctr32(&inc32(j0), dst);
        Ok(())
    }

    /// Encryption (`open == false`) or decryption with the tag computed in the same pass, on AES
    /// and carry-less multiplication instructions; `None` (nothing done) without them. Returns
    /// the tag (over the ciphertext either way). With `src`, the input is `src` followed by
    /// `buf[src.len()..]` and the output goes to `buf` (see `hw::Powers::crypt`).
    fn fused(
        &self,
        j0: &[u8; 16],
        aad: &[u8],
        src: Option<&[u8]>,
        buf: &mut [u8],
        open: bool,
    ) -> Option<[u8; 16]> {
        let p = self.powers.as_ref()?;
        let rk = self.aes.hw_round_keys()?;
        let (aad_len, ct_len) = (aad.len(), buf.len());
        let mut y = [0u64; 2];
        // The AVX-512 kernel does everything in one call (an AAD over 256 bytes hashed first).
        if p.whole_message() {
            let (wide_aad, wide_y) = if aad_len <= WIDE_AAD {
                (aad, y)
            } else {
                let mut g = Ghash::new(self.h, Some(p));
                g.update_padded(aad);
                (&[][..], [g.y0, g.y1])
            };
            return p.crypt_all(rk, j0, wide_y, wide_aad, aad_len, src, buf, open);
        }
        // A short message hashes a short AAD together with its blocks (one GHASH call).
        let joined = ct_len < 128 && aad_len <= SHORT_AAD;
        if !joined {
            let mut g = Ghash::new(self.h, Some(p));
            g.update_padded(aad);
            y = [g.y0, g.y1];
        }
        let ctr = inc32(*j0);
        let done = p.crypt(rk, &ctr, &mut y, src, buf, open);
        let mut c = ctr;
        let n = u32::from_be_bytes([c[12], c[13], c[14], c[15]]).wrapping_add((done / 16) as u32);
        c[12..].copy_from_slice(&n.to_be_bytes());
        let aad = if joined { aad } else { &[] };
        let tail = Tail {
            j0,
            ctr: c,
            aad,
            aad_len,
            ct_len,
            open,
        };
        Some(self.finish_short(p, y, &tail, &mut buf[done..]))
    }

    /// The last (fewer than 128) bytes `rest` of a fused seal or open, and the tag: the counter
    /// blocks of `rest` and `J0` go through AES in one call, and `tail.aad` (when joined), the
    /// ciphertext of `rest` and the length block are hashed in one call.
    fn finish_short(
        &self,
        p: &hw::Powers,
        mut y: [u64; 2],
        tail: &Tail<'_>,
        rest: &mut [u8],
    ) -> [u8; 16] {
        debug_assert!(rest.len() < 128 && tail.aad.len() <= SHORT_AAD);
        let nb = rest.len().div_ceil(16);
        let mut ctrs = [*tail.j0; 8];
        let mut c = u32::from_be_bytes([tail.ctr[12], tail.ctr[13], tail.ctr[14], tail.ctr[15]]);
        for b in ctrs.iter_mut().take(nb) {
            b[..12].copy_from_slice(&tail.ctr[..12]);
            b[12..].copy_from_slice(&c.to_be_bytes());
            c = c.wrapping_add(1);
        }
        // `ks` is `rest` followed by zeros: after the XOR it holds the processed `rest` and,
        // when `nb < 8`, `E(J0)` in block `nb`.
        let mut ks = [0u8; 128];
        ks[..rest.len()].copy_from_slice(rest);
        let mut hb = [0u8; 16 * (SHORT_AAD / 16 + 9)];
        hb[..tail.aad.len()].copy_from_slice(tail.aad);
        let at = tail.aad.len().div_ceil(16) * 16;
        if tail.open {
            hb[at..at + rest.len()].copy_from_slice(rest);
        }
        if !self.aes.hw_xor8(&ctrs, &mut ks) {
            unreachable!("the fused path runs only on hardware AES");
        }
        rest.copy_from_slice(&ks[..rest.len()]);
        if !tail.open {
            hb[at..at + rest.len()].copy_from_slice(rest);
        }
        let at = at + nb * 16;
        hb[at..at + 8].copy_from_slice(&((tail.aad_len as u64) << 3).to_be_bytes());
        hb[at + 8..at + 16].copy_from_slice(&((tail.ct_len as u64) << 3).to_be_bytes());
        p.update(&mut y, &hb[..at + 16]);
        let ek: [u8; 16] = if nb < 8 {
            ks[nb * 16..nb * 16 + 16]
                .try_into()
                .unwrap_or_else(|_| unreachable!())
        } else {
            let mut e = *tail.j0;
            self.aes.encrypt_block(&mut e);
            e
        };
        let mut s = [0u8; 16];
        s[..8].copy_from_slice(&y[1].to_be_bytes());
        s[8..].copy_from_slice(&y[0].to_be_bytes());
        for (s, k) in s.iter_mut().zip(ek) {
            *s ^= k;
        }
        s
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
        let j0 = j0(nonce);
        if let Some(t) = self.fused(&j0, aad, None, buf, true) {
            if crate::ct_eq(&t, tag) {
                return Ok(());
            }
            // Decrypted in the same pass: CTR again restores the ciphertext.
            self.aes.apply_ctr32(&inc32(j0), buf);
            return Err(Error::Verification);
        }
        if !crate::ct_eq(&self.tag(&j0, aad, buf), tag) {
            return Err(Error::Verification);
        }
        self.aes.apply_ctr32(&inc32(j0), buf);
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

/// The longest AAD hashed in the same GHASH call as a short message's blocks (TLS record
/// headers, QUIC packet headers).
const SHORT_AAD: usize = 64;

/// The longest AAD the AVX-512 kernel hashes itself (one masked sixteen-block group).
const WIDE_AAD: usize = 256;

/// What [`AesGcm::finish_short`] needs besides the data: `J0`, the counter block of the first
/// remaining byte, the AAD when it is hashed with the tail (else empty), the AAD and ciphertext
/// lengths and the direction.
struct Tail<'a> {
    j0: &'a [u8; 16],
    ctr: [u8; 16],
    aad: &'a [u8],
    aad_len: usize,
    ct_len: usize,
    open: bool,
}

fn j0(nonce: &[u8; NONCE_LEN]) -> [u8; 16] {
    let mut j = [0u8; 16];
    j[..12].copy_from_slice(nonce);
    j[15] = 1;
    j
}

fn inc32(mut j: [u8; 16]) -> [u8; 16] {
    let c = u32::from_be_bytes([j[12], j[13], j[14], j[15]]).wrapping_add(1);
    j[12..].copy_from_slice(&c.to_be_bytes());
    j
}

/// A 16-byte block as (low, high) 64-bit halves: `high` is the first eight bytes, big-endian.
fn be_pair(b: &[u8]) -> (u64, u64) {
    let hi = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    let lo = u64::from_be_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
    (lo, hi)
}

/// Carry-less multiplication of the low 64 bits, constant time: each operand is split into four
/// interleaved bit groups with three-bit holes, so the integer products' carries land in the
/// holes and are masked away (BearSSL `bmul64`).
#[inline(always)]
fn bmul64(x: u64, y: u64) -> u64 {
    const M0: u64 = 0x1111_1111_1111_1111;
    const M1: u64 = 0x2222_2222_2222_2222;
    const M2: u64 = 0x4444_4444_4444_4444;
    const M3: u64 = 0x8888_8888_8888_8888;
    let (x0, x1, x2, x3) = (x & M0, x & M1, x & M2, x & M3);
    let (y0, y1, y2, y3) = (y & M0, y & M1, y & M2, y & M3);
    let z0 = x0.wrapping_mul(y0) ^ x1.wrapping_mul(y3) ^ x2.wrapping_mul(y2) ^ x3.wrapping_mul(y1);
    let z1 = x0.wrapping_mul(y1) ^ x1.wrapping_mul(y0) ^ x2.wrapping_mul(y3) ^ x3.wrapping_mul(y2);
    let z2 = x0.wrapping_mul(y2) ^ x1.wrapping_mul(y1) ^ x2.wrapping_mul(y0) ^ x3.wrapping_mul(y3);
    let z3 = x0.wrapping_mul(y3) ^ x1.wrapping_mul(y2) ^ x2.wrapping_mul(y1) ^ x3.wrapping_mul(y0);
    (z0 & M0) | (z1 & M1) | (z2 & M2) | (z3 & M3)
}

/// `a·b` in GHASH's field, both as `[lo, hi]` (the layout of [`be_pair`]), constant time
/// (BearSSL `ctmul64`, as [`Ghash`] does per block).
fn gf_mul(a: [u64; 2], b: [u64; 2]) -> [u64; 2] {
    let mut g = Ghash::new((b[0], b[1]), None);
    let mut blk = [0u8; 16];
    blk[..8].copy_from_slice(&a[1].to_be_bytes());
    blk[8..].copy_from_slice(&a[0].to_be_bytes());
    g.block(&blk);
    [g.y0, g.y1]
}

/// GHASH state (BearSSL `br_ghash_ctmul64`), or the hardware path when `hw` is set.
struct Ghash<'a> {
    hw: Option<&'a hw::Powers>,
    h0: u64,
    h1: u64,
    h0r: u64,
    h1r: u64,
    h2: u64,
    h2r: u64,
    y0: u64,
    y1: u64,
}

impl<'a> Ghash<'a> {
    fn new((h0, h1): (u64, u64), hw: Option<&'a hw::Powers>) -> Ghash<'a> {
        let h0r = h0.reverse_bits();
        let h1r = h1.reverse_bits();
        Ghash {
            hw,
            h0,
            h1,
            h0r,
            h1r,
            h2: h0 ^ h1,
            h2r: h0r ^ h1r,
            y0: 0,
            y1: 0,
        }
    }

    /// Absorbs `data` as 16-byte blocks, the last one padded with zeros.
    fn update_padded(&mut self, data: &[u8]) {
        let whole = data.len() & !15;
        let rest = &data[whole..];
        if let Some(p) = self.hw {
            let mut y = [self.y0, self.y1];
            p.update(&mut y, &data[..whole]);
            if !rest.is_empty() {
                let mut b = [0u8; 16];
                b[..rest.len()].copy_from_slice(rest);
                p.update(&mut y, &b);
            }
            [self.y0, self.y1] = y;
            return;
        }
        for b in data[..whole].chunks_exact(16) {
            self.block(b);
        }
        if !rest.is_empty() {
            let mut b = [0u8; 16];
            b[..rest.len()].copy_from_slice(rest);
            self.block(&b);
        }
    }

    #[inline]
    fn block(&mut self, b: &[u8]) {
        let (x0, x1) = be_pair(b);
        let y0 = self.y0 ^ x0;
        let y1 = self.y1 ^ x1;
        let y0r = y0.reverse_bits();
        let y1r = y1.reverse_bits();
        let y2 = y0 ^ y1;
        let y2r = y0r ^ y1r;

        let z0 = bmul64(y0, self.h0);
        let z1 = bmul64(y1, self.h1);
        let mut z2 = bmul64(y2, self.h2);
        let mut z0h = bmul64(y0r, self.h0r);
        let mut z1h = bmul64(y1r, self.h1r);
        let mut z2h = bmul64(y2r, self.h2r);
        z2 ^= z0 ^ z1;
        z2h ^= z0h ^ z1h;
        z0h = z0h.reverse_bits() >> 1;
        z1h = z1h.reverse_bits() >> 1;
        z2h = z2h.reverse_bits() >> 1;

        let mut v0 = z0;
        let mut v1 = z0h ^ z2;
        let mut v2 = z1 ^ z2h;
        let mut v3 = z1h;

        v3 = (v3 << 1) | (v2 >> 63);
        v2 = (v2 << 1) | (v1 >> 63);
        v1 = (v1 << 1) | (v0 >> 63);
        v0 <<= 1;

        v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
        v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
        v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
        v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);

        self.y0 = v2;
        self.y1 = v3;
    }

    fn finish(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.y1.to_be_bytes());
        out[8..].copy_from_slice(&self.y0.to_be_bytes());
        out
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

    /// The test cases of the original GCM specification (McGrew and Viega), 2-4 and 14-16.
    #[test]
    fn gcm_spec_vectors() {
        let k128 = "feffe9928665731c6d6a8f9467308308";
        let k256 = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
        let iv = "cafebabefacedbaddecaf888";
        let p = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                 1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
        let a = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        let cases = [
            (
                "00000000000000000000000000000000",
                "000000000000000000000000",
                "00000000000000000000000000000000",
                "",
                "0388dace60b6a392f328c2b971b2fe78",
                "ab6e47d42cec13bdf53a67b21257bddf",
            ),
            (
                k128,
                iv,
                p,
                "",
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                 21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
                "4d5c2af327cd64a62cf35abd2ba6fab4",
            ),
            (
                k128,
                iv,
                &p[..120],
                a,
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                 21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
                "5bc94fbc3221a5db94fae95ae7121a47",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "000000000000000000000000",
                "00000000000000000000000000000000",
                "",
                "cea7403d4d606b6e074ec5d3baf39d18",
                "d0d1c8a799996bf0265b98b5d48ab919",
            ),
            (
                k256,
                iv,
                p,
                "",
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                 8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
                "b094dac5d93471bdec1a502270e3cc6c",
            ),
            (
                k256,
                iv,
                &p[..120],
                a,
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                 8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
                "76fc6ece0f4e1768cddf8853bb2d551b",
            ),
        ];
        for (key, iv, p, a, c, t) in cases {
            let p = unhex(&p.replace(' ', ""));
            let c = unhex(&c.replace(' ', ""));
            let gcm = AesGcm::new(&unhex(key)).unwrap();
            let nonce: [u8; 12] = unhex(iv).try_into().unwrap();
            let mut buf = p.clone();
            let tag = gcm.encrypt_in_place_detached(&nonce, &unhex(a), &mut buf);
            assert_eq!(buf, c);
            assert_eq!(tag.to_vec(), unhex(t));
            gcm.decrypt_in_place_detached(&nonce, &unhex(a), &mut buf, &tag)
                .unwrap();
            assert_eq!(buf, p);
        }
    }

    /// The hardware GHASH / AES paths (when this CPU has them) and the portable ones agree, for
    /// every length class (whole 8-block groups, remainders, partial blocks) of AAD and data.
    #[test]
    fn hardware_matches_portable() {
        let mut rng = crate::rand::ChaChaRng::from_seed([9; 32]);
        for i in 0..300 {
            let mut key = vec![0u8; [16, 24, 32][i % 3]];
            rng.fill(&mut key);
            let hw = AesGcm::new(&key).unwrap();
            let sw = AesGcm::with_cipher_portable(Aes::new_portable(&key).unwrap());
            assert!(!sw.is_hardware());
            let mut nonce = [0u8; 12];
            rng.fill(&mut nonce);
            let mut pt = vec![0u8; (i * 37) % 700];
            rng.fill(&mut pt);
            let mut aad = vec![0u8; (i * 13) % 300];
            rng.fill(&mut aad);
            let (mut a, mut b) = (pt.clone(), pt.clone());
            let ta = hw.encrypt_in_place_detached(&nonce, &aad, &mut a);
            let tb = sw.encrypt_in_place_detached(&nonce, &aad, &mut b);
            assert_eq!(a, b, "case {i}");
            assert_eq!(ta, tb, "case {i}");
            // A bad tag leaves the ciphertext as it was (the fused path decrypts and restores).
            let mut bad = tb;
            bad[0] ^= 1;
            assert!(
                hw.decrypt_in_place_detached(&nonce, &aad, &mut a, &bad)
                    .is_err()
            );
            assert_eq!(a, b);
            hw.decrypt_in_place_detached(&nonce, &aad, &mut a, &tb)
                .unwrap();
            assert_eq!(a, pt);
            sw.decrypt_in_place_detached(&nonce, &aad, &mut b, &ta)
                .unwrap();
            assert_eq!(b, pt);
        }
        // GF(2^128) multiplication: H^8 by repeated multiplication matches the hardware powers'
        // use (checked above); also 1·x = x (1 is the block 0x80 00 .. 00).
        let one = [0, 1u64 << 63];
        let x = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210];
        assert_eq!(gf_mul(one, x), x);
        assert_eq!(gf_mul(x, one), x);
        println!(
            "hardware GHASH: {}",
            AesGcm::new(&[0; 16]).unwrap().is_hardware()
        );
    }

    /// Seals and opens `len` bytes at offset `off` of a buffer (misaligned when `off > 0`) with
    /// each key; all must agree with the first, and a bad tag must leave the ciphertext as it
    /// was.
    fn agree(keys: &[&AesGcm], len: usize, off: usize, rng: &mut crate::rand::ChaChaRng) {
        agree_aad(keys, len, len % 41, off, rng);
    }

    /// [`agree`] with `aad_len` bytes of AAD.
    fn agree_aad(
        keys: &[&AesGcm],
        len: usize,
        aad_len: usize,
        off: usize,
        rng: &mut crate::rand::ChaChaRng,
    ) {
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce);
        let mut aad = vec![0u8; aad_len];
        rng.fill(&mut aad);
        let mut pt = vec![0u8; len];
        rng.fill(&mut pt);
        let mut first: Option<(Vec<u8>, [u8; 16])> = None;
        for (i, k) in keys.iter().enumerate() {
            let mut buf = vec![0u8; len + off];
            buf[off..].copy_from_slice(&pt);
            let tag = k.encrypt_in_place_detached(&nonce, &aad, &mut buf[off..]);
            let ct = buf[off..].to_vec();
            match &first {
                None => first = Some((ct.clone(), tag)),
                Some((c, t)) => {
                    assert!(
                        *c == ct,
                        "ciphertext differs: key {i}, len {len}, off {off}"
                    );
                    assert_eq!(*t, tag, "tag differs: key {i}, len {len}, off {off}");
                }
            }
            let mut bad = tag;
            bad[15] ^= 0x40;
            assert!(
                k.decrypt_in_place_detached(&nonce, &aad, &mut buf[off..], &bad)
                    .is_err()
            );
            assert!(buf[off..] == ct[..], "restored: key {i}, len {len}");
            k.decrypt_in_place_detached(&nonce, &aad, &mut buf[off..], &tag)
                .unwrap();
            assert!(
                buf[off..] == pt[..],
                "opened: key {i}, len {len}, off {off}"
            );

            // Out of place: the first `split` bytes from a separate (misaligned) buffer, the
            // rest already in the output (all of it from `src`, all but the last byte as the
            // TLS 1.3 record layer has it, two thirds); then decryption into a separate buffer.
            for split in [len, len.saturating_sub(1), len - len / 3] {
                let mut src = vec![0u8; split + 1];
                src[1..].copy_from_slice(&pt[..split]);
                let mut dst = vec![0u8; len + off];
                dst[off + split..].copy_from_slice(&pt[split..]);
                let t2 = k.encrypt_detached_from(&nonce, &aad, &src[1..], &mut dst[off..]);
                assert!(
                    dst[off..] == ct[..],
                    "from: key {i}, len {len}, split {split}, off {off}"
                );
                assert_eq!(t2, tag, "from tag: key {i}, len {len}, split {split}");
            }
            let mut out = vec![0x77u8; len + 2];
            assert!(
                k.decrypt_detached_from(&nonce, &aad, &ct, &bad, &mut out[2..])
                    .is_err()
            );
            assert!(
                out[2..].iter().all(|b| *b == 0),
                "zeroed: key {i}, len {len}"
            );
            k.decrypt_detached_from(&nonce, &aad, &ct, &tag, &mut out[2..])
                .unwrap();
            assert!(out[2..] == pt[..], "from opened: key {i}, len {len}");
        }
    }

    /// The wide kernel (VAES + VPCLMULQDQ + AVX-512, when this CPU has it), the 128-bit hardware
    /// path and the portable code agree at every length 0..=600, at large sizes around the
    /// 256-byte groups, with misaligned buffers, for AES-128, AES-192 and AES-256.
    #[test]
    fn wide_narrow_portable_agree() {
        let mut rng = crate::rand::ChaChaRng::from_seed([5; 32]);
        for klen in [16, 24, 32] {
            let mut key = vec![0u8; klen];
            rng.fill(&mut key);
            let wide = AesGcm::new(&key).unwrap();
            let avx2 = AesGcm::with_cipher_avx2(Aes::new(&key).unwrap());
            let narrow = AesGcm::with_cipher_narrow(Aes::new(&key).unwrap());
            let sw = AesGcm::with_cipher_portable(Aes::new_portable(&key).unwrap());
            assert!(!narrow.is_wide() && !sw.is_wide());
            assert_ne!(avx2.kernel(), "vaes-avx512");
            println!(
                "AES-{} GCM kernels: {} {} {} {}",
                klen * 8,
                wide.kernel(),
                avx2.kernel(),
                narrow.kernel(),
                sw.kernel()
            );
            let keys = [&wide, &avx2, &narrow, &sw];
            for len in 0..=600 {
                agree(&keys, len, len % 5, &mut rng);
            }
            for len in [
                767, 768, 769, 1023, 1024, 1025, 1400, 1500, 4096, 4111, 16383, 16384, 16385,
                16401, 65536, 65791,
            ] {
                for off in [0, 3] {
                    agree(&keys, len, off, &mut rng);
                }
            }
            // Every AAD length the AVX-512 kernel hashes itself and past it (hashed first).
            for aad_len in (0..=300).chain([511, 512, 513, 1000]) {
                for len in [0, 1, 15, 16, 200, 256, 300] {
                    agree_aad(&keys, len, aad_len, aad_len % 3, &mut rng);
                }
            }
        }
    }

    /// Large messages against ring (an independent implementation, dev-dependency).
    #[test]
    fn matches_ring() {
        use ring::aead::{AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
        let mut rng = crate::rand::ChaChaRng::from_seed([6; 32]);
        for (klen, alg) in [(16, &AES_128_GCM), (32, &AES_256_GCM)] {
            let mut key = vec![0u8; klen];
            rng.fill(&mut key);
            let ours = AesGcm::new(&key).unwrap();
            let theirs = LessSafeKey::new(UnboundKey::new(alg, &key).unwrap());
            for len in [
                0,
                1,
                255,
                256,
                257,
                511,
                1024,
                1400,
                4097,
                16384,
                16385,
                65536 + 300,
            ] {
                let mut nonce = [0u8; 12];
                rng.fill(&mut nonce);
                let mut aad = vec![0u8; len % 23];
                rng.fill(&mut aad);
                let mut a = vec![0u8; len];
                rng.fill(&mut a);
                let mut b = a.clone();
                let ta = ours.encrypt_in_place_detached(&nonce, &aad, &mut a);
                let tb = theirs
                    .seal_in_place_separate_tag(
                        Nonce::assume_unique_for_key(nonce),
                        Aad::from(&aad),
                        &mut b,
                    )
                    .unwrap();
                assert!(a == b, "ciphertext, len {len}");
                assert_eq!(ta[..], tb.as_ref()[..], "tag, len {len}");
            }
        }
    }

    /// The fused kernels directly, with the 32-bit counter wrapping inside a group: the wide
    /// kernel against the 128-bit one and plain CTR.
    #[test]
    fn counter_wraps() {
        let mut rng = crate::rand::ChaChaRng::from_seed([7; 32]);
        for klen in [16, 24, 32] {
            let mut key = vec![0u8; klen];
            rng.fill(&mut key);
            let g = AesGcm::new(&key).unwrap();
            let (Some(p), Some(rk)) = (g.powers.as_ref(), g.aes.hw_round_keys()) else {
                return;
            };
            let narrow = hw::Powers::new([g.h.0, g.h.1], hw::Mode::Narrow).unwrap();
            let avx2 = hw::Powers::new([g.h.0, g.h.1], hw::Mode::Avx2).unwrap();
            for start in [0xffff_fff0u32, 0xffff_ffff, 0xffff_ff00, 7] {
                let mut ctr = [0x3cu8; 16];
                ctr[12..].copy_from_slice(&start.to_be_bytes());
                let mut data = vec![0u8; 1024 + 256 + 128 + 48];
                rng.fill(&mut data);
                for open in [false, true] {
                    let (mut d1, mut d2, mut d4) = (data.clone(), data.clone(), data.clone());
                    let (mut y1, mut y2, mut y4) = ([1u64, 2], [1u64, 2], [1u64, 2]);
                    let n1 = p.crypt(rk, &ctr, &mut y1, None, &mut d1, open);
                    let n2 = narrow.crypt(rk, &ctr, &mut y2, None, &mut d2, open);
                    let n4 = avx2.crypt(rk, &ctr, &mut y4, None, &mut d4, open);
                    assert_eq!((n1, n2, n4), (1024 + 256 + 128, 1024 + 256 + 128, 1408));
                    assert!(d1 == d2 && d4 == d2);
                    assert_eq!(y1, y2);
                    assert_eq!(y4, y2);
                    let mut d3 = data.clone();
                    g.aes.apply_ctr32(&ctr, &mut d3[..n1]);
                    assert!(d1[..n1] == d3[..n1]);
                    assert!(d1[n1..] == data[n1..]);
                }
            }
        }
    }

    #[test]
    fn rejects_forgeries() {
        let gcm = AesGcm::new(&[1; 32]).unwrap();
        let n = [2; 12];
        let sealed = gcm.encrypt(&n, b"a", b"hello world");
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 0x80;
            assert_eq!(gcm.decrypt(&n, b"a", &bad), Err(Error::Verification));
        }
        assert!(gcm.decrypt(&n, b"a", &sealed[..15]).is_err());
        let mut buf = sealed[..11].to_vec();
        assert_eq!(
            gcm.decrypt_in_place_detached(&n, b"a", &mut buf, &[0; 15]),
            Err(Error::InvalidLength)
        );
    }
}
