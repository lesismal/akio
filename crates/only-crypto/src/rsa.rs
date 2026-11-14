//! RSA signatures: PKCS#1 v1.5 and PSS (RFC 8017) with SHA-256/384/512 (and SHA-1 for legacy
//! verification), moduli of 2048 to 8192 bits.
//!
//! Private-key operations use the CRT with constant-time Montgomery exponentiation (fixed
//! 4-bit windows over the full exponent length), base blinding (a random `r`, `rᵉ` and `r⁻¹`
//! kept per key and squared after each use), and check the result against the public key
//! before releasing it (fault attacks). Verification is variable time (public data) and
//! compares the full encoded message, so BER variations of the DigestInfo never verify.
//!
//! Key generation is not provided; load keys with [`PrivateKey::from_pkcs1_der`] or through
//! [`pkey`](crate::pkey).

use std::sync::Mutex;

use crate::Error;
use crate::bignum::{self, Mont};
use crate::hash::{Hash, Sha1, Sha256, Sha384, Sha512};

/// The smallest accepted modulus in bits.
pub const MIN_BITS: usize = 2048;
/// The largest accepted modulus in bits.
pub const MAX_BITS: usize = 8192;

/// The hash function of an RSA signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HashAlg {
    /// SHA-1: legacy, for verifying old signatures only.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl HashAlg {
    /// The digest length in bytes.
    #[must_use]
    pub fn output_len(self) -> usize {
        match self {
            HashAlg::Sha1 => 20,
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }

    /// The digest of `data`.
    #[must_use]
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        self.digest_parts(&[data])
    }

    fn digest_parts(self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<H: Hash>(parts: &[&[u8]]) -> Vec<u8> {
            let mut h = H::default();
            for p in parts {
                h.update(p);
            }
            h.finalize().as_ref().to_vec()
        }
        match self {
            HashAlg::Sha1 => run::<Sha1>(parts),
            HashAlg::Sha256 => run::<Sha256>(parts),
            HashAlg::Sha384 => run::<Sha384>(parts),
            HashAlg::Sha512 => run::<Sha512>(parts),
        }
    }

    /// The DER `DigestInfo` prefix of PKCS#1 v1.5 (RFC 8017 §9.2 note 1).
    fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            HashAlg::Sha1 => &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                0x14,
            ],
            HashAlg::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            HashAlg::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            HashAlg::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }

    /// MGF1 (RFC 8017 B.2.1) of `seed`, XORed into `out`.
    fn mgf1_xor(self, seed: &[u8], out: &mut [u8]) {
        for (counter, chunk) in (0u32..).zip(out.chunks_mut(self.output_len())) {
            let m = self.digest_parts(&[seed, &counter.to_be_bytes()]);
            for (o, x) in chunk.iter_mut().zip(m) {
                *o ^= x;
            }
        }
    }
}

/// An RSA public key `(n, e)`.
#[derive(Clone)]
pub struct PublicKey {
    n: Mont,
    /// The modulus length in bytes.
    len: usize,
    bits: usize,
    e: u64,
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("rsa::PublicKey")
            .field("bits", &self.bits)
            .field("e", &self.e)
            .finish_non_exhaustive()
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, o: &Self) -> bool {
        self.n.m == o.n.m && self.e == o.e
    }
}
impl Eq for PublicKey {}

impl PublicKey {
    /// From the big-endian modulus and exponent. The modulus must have 2048 to 8192 bits and
    /// be odd; the exponent odd, at least 3 and below 2³³ (as ring and BoringSSL require).
    pub fn from_components(n: &[u8], e: &[u8]) -> Result<PublicKey, Error> {
        let k = n.len().div_ceil(8).max(1);
        let nl = bignum::from_be(n, k).ok_or(Error::InvalidKey)?;
        let bits = bignum::bit_len_vartime(&nl);
        if !(MIN_BITS..=MAX_BITS).contains(&bits) {
            return Err(Error::InvalidKey);
        }
        let nl = bignum::resize(&nl, bits.div_ceil(64));
        let el = bignum::from_be(e, 1).ok_or(Error::InvalidKey)?;
        let e = el[0];
        if e < 3 || e & 1 == 0 || e >= 1 << 33 {
            return Err(Error::InvalidKey);
        }
        let n = Mont::new(&nl).ok_or(Error::InvalidKey)?;
        Ok(PublicKey {
            n,
            len: bits.div_ceil(8),
            bits,
            e,
        })
    }

    /// From the PKCS#1 `RSAPublicKey` DER (`SEQUENCE { n, e }`).
    pub fn from_pkcs1_der(der: &[u8]) -> Result<PublicKey, Error> {
        let mut r = crate::der::Reader::new(der);
        let mut s = r.sequence()?;
        let n = s.read_uint()?;
        let e = s.read_uint()?;
        s.finish()?;
        r.finish()?;
        Self::from_components(n, e)
    }

    /// The PKCS#1 `RSAPublicKey` DER.
    #[must_use]
    pub fn to_pkcs1_der(&self) -> Vec<u8> {
        let mut w = crate::der::Writer::new();
        w.sequence(|w| {
            w.uint(&self.modulus());
            w.small_uint(self.e);
        });
        w.into_vec()
    }

    /// The modulus, big-endian, without leading zeros.
    #[must_use]
    pub fn modulus(&self) -> Vec<u8> {
        bignum::to_be(&self.n.m, self.len)
    }

    /// The public exponent.
    #[must_use]
    pub fn exponent(&self) -> u64 {
        self.e
    }

    /// The modulus size in bits.
    #[must_use]
    pub fn bits(&self) -> usize {
        self.bits
    }

    /// The signature length in bytes (the modulus length).
    #[must_use]
    pub fn signature_len(&self) -> usize {
        self.len
    }

    /// `s^e mod n` as `len` bytes; fails unless `s` has exactly the modulus length and is
    /// below `n`.
    fn public_op(&self, sig: &[u8]) -> Result<Vec<u8>, Error> {
        if sig.len() != self.len {
            return Err(Error::Verification);
        }
        let k = self.n.limbs();
        let s = bignum::from_be(sig, k).ok_or(Error::Verification)?;
        if !bignum::lt_vartime(&s, &self.n.m) {
            return Err(Error::Verification);
        }
        let m = self
            .n
            .out_of_mont(&self.n.pow_vartime(&self.n.to_mont(&s), &[self.e]));
        Ok(bignum::to_be(&m, self.len))
    }

    /// Verifies a PKCS#1 v1.5 signature (RSASSA-PKCS1-v1_5) on `msg`.
    pub fn verify_pkcs1v15(&self, hash: HashAlg, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        self.verify_pkcs1v15_prehash(hash, &hash.digest(msg), sig)
    }

    /// Verifies a PKCS#1 v1.5 signature on a precomputed digest.
    pub fn verify_pkcs1v15_prehash(
        &self,
        hash: HashAlg,
        digest: &[u8],
        sig: &[u8],
    ) -> Result<(), Error> {
        let em = self.public_op(sig)?;
        let want = pkcs1v15_encode(hash, digest, self.len)?;
        if crate::ct_eq(&em, &want) {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }

    /// Verifies an RSASSA-PSS signature on `msg` with MGF1 over the same hash and a salt of
    /// `salt_len` bytes (TLS 1.3 and X.509 use the hash length).
    pub fn verify_pss(
        &self,
        hash: HashAlg,
        msg: &[u8],
        sig: &[u8],
        salt_len: usize,
    ) -> Result<(), Error> {
        self.verify_pss_prehash(hash, &hash.digest(msg), sig, salt_len)
    }

    /// Verifies an RSASSA-PSS signature on a precomputed digest (RFC 8017 §9.1.2).
    pub fn verify_pss_prehash(
        &self,
        hash: HashAlg,
        m_hash: &[u8],
        sig: &[u8],
        salt_len: usize,
    ) -> Result<(), Error> {
        let em_full = self.public_op(sig)?;
        let em_bits = self.bits - 1;
        let em_len = em_bits.div_ceil(8);
        // When emBits is a multiple of 8, the leading byte of the k-byte result must be 0.
        let em = if em_len < em_full.len() {
            if em_full[0] != 0 {
                return Err(Error::Verification);
            }
            &em_full[1..]
        } else {
            &em_full[..]
        };
        let h_len = hash.output_len();
        if m_hash.len() != h_len || em_len < h_len + salt_len + 2 || em[em_len - 1] != 0xbc {
            return Err(Error::Verification);
        }
        let (masked_db, rest) = em.split_at(em_len - h_len - 1);
        let h = &rest[..h_len];
        let top_bits = 8 * em_len - em_bits;
        if top_bits > 0 && masked_db[0] >> (8 - top_bits) != 0 {
            return Err(Error::Verification);
        }
        let mut db = masked_db.to_vec();
        hash.mgf1_xor(h, &mut db);
        if top_bits > 0 {
            db[0] &= 0xff >> top_bits;
        }
        let ps_len = em_len - h_len - salt_len - 2;
        if db[..ps_len].iter().any(|&b| b != 0) || db[ps_len] != 1 {
            return Err(Error::Verification);
        }
        let salt = &db[ps_len + 1..];
        let h2 = hash.digest_parts(&[&[0u8; 8], m_hash, salt]);
        if crate::ct_eq(h, &h2) {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }
}

/// `00 01 FF.. 00 DigestInfo` of length `k`.
fn pkcs1v15_encode(hash: HashAlg, digest: &[u8], k: usize) -> Result<Vec<u8>, Error> {
    let prefix = hash.digest_info_prefix();
    if digest.len() != hash.output_len() {
        return Err(Error::InvalidLength);
    }
    let t_len = prefix.len() + digest.len();
    if k < t_len + 11 {
        return Err(Error::InvalidLength);
    }
    let mut em = vec![0xffu8; k];
    em[0] = 0;
    em[1] = 1;
    em[k - t_len - 1] = 0;
    em[k - t_len..k - digest.len()].copy_from_slice(prefix);
    em[k - digest.len()..].copy_from_slice(digest);
    Ok(em)
}

/// The blinding pair `(rᵉ, r⁻¹)` mod n, both in Montgomery form.
#[derive(Clone)]
struct Blinding {
    r_e: Vec<u64>,
    r_inv: Vec<u64>,
}

/// An RSA private key with its CRT parameters.
pub struct PrivateKey {
    public: PublicKey,
    d: Vec<u64>,
    p: Mont,
    q: Mont,
    dp: Vec<u64>,
    dq: Vec<u64>,
    /// `q⁻¹ mod p`, Montgomery form mod p.
    qinv: Vec<u64>,
    blinding: Mutex<Option<Blinding>>,
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        PrivateKey {
            public: self.public.clone(),
            d: self.d.clone(),
            p: self.p.clone(),
            q: self.q.clone(),
            dp: self.dp.clone(),
            dq: self.dq.clone(),
            qinv: self.qinv.clone(),
            blinding: Mutex::new(None),
        }
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("rsa::PrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl PrivateKey {
    /// From the PKCS#1 `RSAPrivateKey` DER (two-prime, version 0).
    pub fn from_pkcs1_der(der: &[u8]) -> Result<PrivateKey, Error> {
        let mut r = crate::der::Reader::new(der);
        let mut s = r.sequence()?;
        if s.read_small_uint()? != 0 {
            return Err(Error::Unsupported); // multi-prime
        }
        let n = s.read_uint()?;
        let e = s.read_uint()?;
        let d = s.read_uint()?;
        let p = s.read_uint()?;
        let q = s.read_uint()?;
        let dp = s.read_uint()?;
        let dq = s.read_uint()?;
        let qi = s.read_uint()?;
        s.finish()?;
        r.finish()?;
        Self::from_components(n, e, d, p, q, dp, dq, qi)
    }

    /// From the big-endian components. Checks `n = p·q`, the sizes, `dp, dq` below `p - 1`,
    /// `q - 1`, `qinv < p` and `qinv·q ≡ 1 (mod p)`, and that a test signature verifies.
    #[allow(clippy::too_many_arguments, clippy::many_single_char_names)]
    pub fn from_components(
        n: &[u8],
        e: &[u8],
        d: &[u8],
        p: &[u8],
        q: &[u8],
        dp: &[u8],
        dq: &[u8],
        qinv: &[u8],
    ) -> Result<PrivateKey, Error> {
        let public = PublicKey::from_components(n, e)?;
        let k = public.n.limbs();
        let kp = p.len().div_ceil(8).max(1);
        let kq = q.len().div_ceil(8).max(1);
        let pl = bignum::from_be(p, kp).ok_or(Error::InvalidKey)?;
        let ql = bignum::from_be(q, kq).ok_or(Error::InvalidKey)?;
        // Trim leading zero limbs (the limb counts of p and q are public).
        let pl = bignum::resize(&pl, bignum::bit_len_vartime(&pl).div_ceil(64).max(1));
        let ql = bignum::resize(&ql, bignum::bit_len_vartime(&ql).div_ceil(64).max(1));
        let (kp, kq) = (pl.len(), ql.len());
        if kp + kq < k {
            return Err(Error::InvalidKey);
        }
        // n = p·q.
        let pq = bignum::mul_plain(&pl, &ql);
        if pq[k..].iter().any(|&x| x != 0) || pq[..k] != public.n.m[..] {
            return Err(Error::InvalidKey);
        }
        let pm = Mont::new(&pl).ok_or(Error::InvalidKey)?;
        let qm = Mont::new(&ql).ok_or(Error::InvalidKey)?;
        let dpl = bignum::from_be(dp, kp).ok_or(Error::InvalidKey)?;
        let dql = bignum::from_be(dq, kq).ok_or(Error::InvalidKey)?;
        let qil = bignum::from_be(qinv, kp).ok_or(Error::InvalidKey)?;
        if !bignum::lt_vartime(&dpl, &pl)
            || !bignum::lt_vartime(&dql, &ql)
            || !bignum::lt_vartime(&qil, &pl)
        {
            return Err(Error::InvalidKey);
        }
        let qinv = pm.to_mont(&qil);
        // qinv·q ≡ 1 (mod p): mul(qinv·R, q) = qinv·q (normal form).
        let one = pm.mul(&qinv, &pm.reduce_any(&ql));
        let mut want = vec![0u64; kp];
        want[0] = 1;
        if one != want {
            return Err(Error::InvalidKey);
        }
        let dl = bignum::from_be(d, k).ok_or(Error::InvalidKey)?;
        let key = PrivateKey {
            public,
            d: dl,
            p: pm,
            q: qm,
            dp: dpl,
            dq: dql,
            qinv,
            blinding: Mutex::new(None),
        };
        // A consistency check of e, dp, dq: sign a fixed message and verify it.
        let probe = key.sign_pkcs1v15(HashAlg::Sha256, b"only-crypto rsa key check")?;
        key.public
            .verify_pkcs1v15(HashAlg::Sha256, b"only-crypto rsa key check", &probe)
            .map_err(|_| Error::InvalidKey)?;
        Ok(key)
    }

    /// The public key.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The PKCS#1 `RSAPrivateKey` DER.
    #[must_use]
    pub fn to_pkcs1_der(&self) -> Vec<u8> {
        let (lp, lq) = (self.p.limbs() * 8, self.q.limbs() * 8);
        let qinv = self.p.out_of_mont(&self.qinv);
        let mut w = crate::der::Writer::new();
        w.sequence(|w| {
            w.small_uint(0);
            w.uint(&self.public.modulus());
            w.small_uint(self.public.e);
            w.uint(&bignum::to_be(&self.d, self.public.len));
            w.uint(&bignum::to_be(&self.p.m, lp));
            w.uint(&bignum::to_be(&self.q.m, lq));
            w.uint(&bignum::to_be(&self.dp, lp));
            w.uint(&bignum::to_be(&self.dq, lq));
            w.uint(&bignum::to_be(&qinv, lp));
        });
        w.into_vec()
    }

    /// A fresh blinding pair: random `r`, `rᵉ` and `r⁻¹ = CRT(r^(p-2) mod p, r^(q-2) mod q)`
    /// (inversion by Fermat in each prime field: constant time).
    fn new_blinding(&self) -> Result<Blinding, Error> {
        let n = &self.public.n;
        let k = n.limbs();
        loop {
            let mut bytes = vec![0u8; 8 * k];
            crate::rand::fill_random(&mut bytes).map_err(|_| Error::Random)?;
            let r = n.reduce(&bignum::from_be(&bytes, k).ok_or(Error::Random)?);
            let inv_mod = |m: &Mont| {
                let mut e = m.m.clone();
                let mut two = vec![0u64; e.len()];
                two[0] = 2;
                crate::ct::sub_limbs(&mut e, &m.m, &two);
                let rm = m.to_mont(&m.reduce_any(&r));
                m.out_of_mont(&m.pow(&rm, &e))
            };
            let r_inv = self.crt_combine(&inv_mod(&self.p), &inv_mod(&self.q));
            let r_m = n.to_mont(&r);
            let r_inv_m = n.to_mont(&r_inv);
            let check = n.out_of_mont(&n.mul(&r_m, &r_inv_m));
            let mut one = vec![0u64; k];
            one[0] = 1;
            if check != one {
                continue; // r shares a factor with n (negligible) or r = 0
            }
            let r_e = n.pow_vartime(&r_m, &[self.public.e]);
            return Ok(Blinding {
                r_e,
                r_inv: r_inv_m,
            });
        }
    }

    /// `m2 + q·(qinv·(m1 - m2) mod p)` for `m1` mod p and `m2` mod q (normal form).
    fn crt_combine(&self, m1: &[u64], m2: &[u64]) -> Vec<u64> {
        let k = self.public.n.limbs();
        let m2p = self.p.reduce_any(m2);
        let diff = self.p.sub(m1, &m2p);
        let h = self.p.mul(&self.qinv, &diff);
        let mut m = bignum::mul_plain(&h, &self.q.m);
        let mut carry = 0u64;
        for (i, limb) in m.iter_mut().enumerate() {
            let add = if i < m2.len() { m2[i] } else { 0 };
            let (s, c1) = limb.overflowing_add(add);
            let (s, c2) = s.overflowing_add(carry);
            *limb = s;
            carry = u64::from(c1 | c2);
        }
        bignum::resize(&m, k)
    }

    /// The raw private operation `c^d mod n` with blinding and a check of the result.
    fn private_op(&self, c: &[u8]) -> Result<Vec<u8>, Error> {
        let n = &self.public.n;
        let k = n.limbs();
        let cl = bignum::from_be(c, k).ok_or(Error::InvalidLength)?;
        let bl = {
            let mut g = self.blinding.lock().unwrap_or_else(|e| e.into_inner());
            let b = match g.take() {
                Some(b) => b,
                None => self.new_blinding()?,
            };
            *g = Some(Blinding {
                r_e: n.mul(&b.r_e, &b.r_e),
                r_inv: n.mul(&b.r_inv, &b.r_inv),
            });
            b
        };
        // c·rᵉ (normal form).
        let cb = n.mul(&n.to_mont(&cl), &bl.r_e);
        let cb = n.out_of_mont(&cb);
        let m1 = {
            let cp = self.p.to_mont(&self.p.reduce_any(&cb));
            self.p.out_of_mont(&self.p.pow(&cp, &self.dp))
        };
        let m2 = {
            let cq = self.q.to_mont(&self.q.reduce_any(&cb));
            self.q.out_of_mont(&self.q.pow(&cq, &self.dq))
        };
        let mb = self.crt_combine(&m1, &m2);
        let m = n.out_of_mont(&n.mul(&n.to_mont(&mb), &bl.r_inv));
        // Fault check: mᵉ = c.
        let back = n.out_of_mont(&n.pow_vartime(&n.to_mont(&m), &[self.public.e]));
        if back != cl {
            return Err(Error::Verification);
        }
        Ok(bignum::to_be(&m, self.public.len))
    }

    /// A PKCS#1 v1.5 signature of `msg`.
    pub fn sign_pkcs1v15(&self, hash: HashAlg, msg: &[u8]) -> Result<Vec<u8>, Error> {
        self.sign_pkcs1v15_prehash(hash, &hash.digest(msg))
    }

    /// A PKCS#1 v1.5 signature of a precomputed digest.
    pub fn sign_pkcs1v15_prehash(&self, hash: HashAlg, digest: &[u8]) -> Result<Vec<u8>, Error> {
        let em = pkcs1v15_encode(hash, digest, self.public.len)?;
        self.private_op(&em)
    }

    /// An RSASSA-PSS signature of `msg` with MGF1 over the same hash and a random salt as
    /// long as the digest.
    pub fn sign_pss(&self, hash: HashAlg, msg: &[u8]) -> Result<Vec<u8>, Error> {
        self.sign_pss_prehash(hash, &hash.digest(msg))
    }

    /// An RSASSA-PSS signature of a precomputed digest (RFC 8017 §9.1.1).
    pub fn sign_pss_prehash(&self, hash: HashAlg, m_hash: &[u8]) -> Result<Vec<u8>, Error> {
        let h_len = hash.output_len();
        if m_hash.len() != h_len {
            return Err(Error::InvalidLength);
        }
        let em_bits = self.public.bits - 1;
        let em_len = em_bits.div_ceil(8);
        let s_len = h_len;
        if em_len < h_len + s_len + 2 {
            return Err(Error::InvalidLength);
        }
        let mut salt = vec![0u8; s_len];
        crate::rand::fill_random(&mut salt).map_err(|_| Error::Random)?;
        let h = hash.digest_parts(&[&[0u8; 8], m_hash, &salt]);
        let db_len = em_len - h_len - 1;
        let mut db = vec![0u8; db_len];
        db[db_len - s_len - 1] = 1;
        db[db_len - s_len..].copy_from_slice(&salt);
        hash.mgf1_xor(&h, &mut db);
        let top_bits = 8 * em_len - em_bits;
        db[0] &= 0xff >> top_bits;
        let mut em = Vec::with_capacity(self.public.len);
        if em_len < self.public.len {
            em.push(0);
        }
        em.extend_from_slice(&db);
        em.extend_from_slice(&h);
        em.push(0xbc);
        self.private_op(&em)
    }
}
