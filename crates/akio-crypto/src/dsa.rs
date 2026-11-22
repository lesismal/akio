//! DSA signature verification (FIPS 186-4 §4.7), for legacy certificates and CRLs (RFC 3279):
//! no key generation or signing. Everything here is public data, so it runs in variable time.
//!
//! Domain parameters must have one of the FIPS 186-4 sizes `(L, N)` = (1024, 160),
//! (2048, 224), (2048, 256) or (3072, 256), and a key is checked once when it is built:
//! `1 < g < p`, `1 < y < p`, `g^q = y^q = 1 (mod p)` and `p`, `q` odd (the primality of `p` and
//! `q` is not tested). Signatures are DER `Dss-Sig-Value`s with `0 < r, s < q`. Certificates
//! reach this module through [`pkey::PublicKey::Dsa`](crate::pkey::PublicKey::Dsa).

use crate::Error;
use crate::bignum::{self, Mont};
use crate::der::{Reader, Writer};
use crate::rsa::HashAlg;

/// A DSA public key `y` with its domain parameters `(p, q, g)`.
#[derive(Clone)]
pub struct PublicKey {
    p: Mont,
    q: Mont,
    /// `g` and `y` in Montgomery form modulo `p`.
    g: Vec<u64>,
    y: Vec<u64>,
    /// The big-endian encodings, as given (without leading zeros).
    raw: [Vec<u8>; 4],
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "dsa::PublicKey({}/{} bits)",
            self.p_bits(),
            self.q_bits()
        )
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, o: &Self) -> bool {
        self.raw == o.raw
    }
}
impl Eq for PublicKey {}

fn strip(b: &[u8]) -> &[u8] {
    let n = b.iter().take_while(|&&x| x == 0).count();
    &b[n..]
}

impl PublicKey {
    /// From big-endian `p`, `q`, `g` and `y`. Fails with [`Error::InvalidKey`] for sizes other
    /// than FIPS 186-4's or parameters that fail the checks in the module documentation.
    pub fn from_components(p: &[u8], q: &[u8], g: &[u8], y: &[u8]) -> Result<PublicKey, Error> {
        let (p, q, g, y) = (strip(p), strip(q), strip(g), strip(y));
        let p_bits = bit_len(p);
        let q_bits = bit_len(q);
        if !matches!(
            (p_bits, q_bits),
            (1024, 160) | (2048, 224 | 256) | (3072, 256)
        ) {
            return Err(Error::InvalidKey);
        }
        let pk = p.len().div_ceil(8);
        let qk = q.len().div_ceil(8);
        let pl = bignum::from_be(p, pk).ok_or(Error::InvalidKey)?;
        let ql = bignum::from_be(q, qk).ok_or(Error::InvalidKey)?;
        let pm = Mont::new_public(&pl).ok_or(Error::InvalidKey)?;
        let qm = Mont::new_public(&ql).ok_or(Error::InvalidKey)?;
        let gl = bignum::from_be(g, pk).ok_or(Error::InvalidKey)?;
        let yl = bignum::from_be(y, pk).ok_or(Error::InvalidKey)?;
        let mut one = vec![0u64; pk];
        one[0] = 1;
        for v in [&gl, &yl] {
            // 1 < v < p
            if !bignum::lt_vartime(&one, v) || !bignum::lt_vartime(v, &pl) {
                return Err(Error::InvalidKey);
            }
        }
        let gm = pm.to_mont(&gl);
        let ym = pm.to_mont(&yl);
        for v in [&gm, &ym] {
            if pm.pow_vartime(v, &ql) != pm.one() {
                return Err(Error::InvalidKey);
            }
        }
        Ok(PublicKey {
            p: pm,
            q: qm,
            g: gm,
            y: ym,
            raw: [p.to_vec(), q.to_vec(), g.to_vec(), y.to_vec()],
        })
    }

    /// From the DER `Dss-Parms` (`SEQUENCE { p, q, g }`, the SubjectPublicKeyInfo parameters)
    /// and the DER `INTEGER` `y` (the key bits).
    pub fn from_der(params: &[u8], key: &[u8]) -> Result<PublicKey, Error> {
        let mut r = Reader::new(params);
        let mut s = r.sequence()?;
        let p = s.read_uint()?;
        let q = s.read_uint()?;
        let g = s.read_uint()?;
        s.finish()?;
        r.finish()?;
        let mut r = Reader::new(key);
        let y = r.read_uint()?;
        r.finish()?;
        Self::from_components(p, q, g, y)
    }

    /// The DER `Dss-Parms`.
    #[must_use]
    pub fn params_der(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.sequence(|w| {
            w.uint(&self.raw[0]);
            w.uint(&self.raw[1]);
            w.uint(&self.raw[2]);
        });
        w.into_vec()
    }

    /// The DER `INTEGER` `y`.
    #[must_use]
    pub fn key_der(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.uint(&self.raw[3]);
        w.into_vec()
    }

    /// The size of `p` in bits (`L`).
    #[must_use]
    pub fn p_bits(&self) -> usize {
        bit_len(&self.raw[0])
    }

    /// The size of `q` in bits (`N`).
    #[must_use]
    pub fn q_bits(&self) -> usize {
        bit_len(&self.raw[1])
    }

    /// Verifies the DER signature `sig` on `msg` hashed with `hash`.
    pub fn verify(&self, hash: HashAlg, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        self.verify_prehash(&hash.digest(msg), sig)
    }

    /// Verifies the DER signature `sig` on a digest (its leftmost `N` bits are used, FIPS 186-4
    /// §4.6). Fails with [`Error::Verification`].
    pub fn verify_prehash(&self, digest: &[u8], sig: &[u8]) -> Result<(), Error> {
        let (r, s) = parse_sig(sig).ok_or(Error::Verification)?;
        let qk = self.q.limbs();
        let r = bignum::from_be(r, qk).ok_or(Error::Verification)?;
        let s = bignum::from_be(s, qk).ok_or(Error::Verification)?;
        let zero = vec![0u64; qk];
        for v in [&r, &s] {
            if *v == zero || !bignum::lt_vartime(v, &self.q.m) {
                return Err(Error::Verification);
            }
        }
        let n = self.q_bits().div_ceil(8);
        let z = &digest[..digest.len().min(n)];
        // N is a multiple of 8 for the allowed sizes, so the leftmost N bits are whole bytes.
        let z = bignum::from_be(z, qk).ok_or(Error::Verification)?;
        let z = self.q.reduce_any(&z);
        let q2: Vec<u64> = {
            let mut e = self.q.m.clone();
            // q - 2 (q is odd and > 2)
            let (v, b) = e[0].overflowing_sub(2);
            e[0] = v;
            let mut i = 1;
            let mut borrow = b;
            while borrow {
                let (v, b) = e[i].overflowing_sub(1);
                e[i] = v;
                borrow = b;
                i += 1;
            }
            e
        };
        let w = self.q.pow_vartime(&self.q.to_mont(&s), &q2);
        let u1 = self.q.out_of_mont(&self.q.mul(&self.q.to_mont(&z), &w));
        let u2 = self.q.out_of_mont(&self.q.mul(&self.q.to_mont(&r), &w));
        let a = self.p.pow_vartime(&self.g, &u1);
        let b = self.p.pow_vartime(&self.y, &u2);
        let v = self.p.out_of_mont(&self.p.mul(&a, &b));
        let v = bignum::rem_vartime(&v, &self.q.m);
        if v == r {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }
}

fn bit_len(be: &[u8]) -> usize {
    let b = strip(be);
    match b.first() {
        None => 0,
        Some(&x) => 8 * b.len() - x.leading_zeros() as usize,
    }
}

/// `(r, s)` of a DER `Dss-Sig-Value`.
fn parse_sig(sig: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut rd = Reader::new(sig);
    let mut s = rd.sequence().ok()?;
    let r = s.read_uint().ok()?;
    let ss = s.read_uint().ok()?;
    s.finish().ok()?;
    rd.finish().ok()?;
    Some((r, ss))
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

    fn sig_der(r: &[u8], s: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.sequence(|w| {
            w.uint(r);
            w.uint(s);
        });
        w.into_vec()
    }

    struct Vector {
        name: String,
        hash: HashAlg,
        p: Vec<u8>,
        q: Vec<u8>,
        g: Vec<u8>,
        y: Vec<u8>,
        msg: Vec<u8>,
        r: Vec<u8>,
        s: Vec<u8>,
        ok: bool,
    }

    /// The vectors of `tests/data/dsa_sigver.rsp` (NIST CAVP format).
    fn vectors() -> Vec<Vector> {
        let text = include_str!("../tests/data/dsa_sigver.rsp");
        let (mut hash, mut p, mut q, mut g) = (HashAlg::Sha1, vec![], vec![], vec![]);
        let (mut msg, mut y, mut r, mut s) = (vec![], vec![], vec![], vec![]);
        let mut group = String::new();
        let mut out = Vec::new();
        for line in text.lines() {
            if let Some(m) = line.strip_prefix("[mod = ") {
                group = m.trim_end_matches(']').to_string();
                hash = match group.rsplit(' ').next() {
                    Some("SHA-1") => HashAlg::Sha1,
                    Some("SHA-224") => HashAlg::Sha224,
                    Some("SHA-256") => HashAlg::Sha256,
                    Some("SHA-384") => HashAlg::Sha384,
                    _ => HashAlg::Sha512,
                };
                continue;
            }
            let Some((k, v)) = line.split_once(" = ") else {
                continue;
            };
            match k {
                "P" => p = unhex(v),
                "Q" => q = unhex(v),
                "G" => g = unhex(v),
                "Msg" => msg = unhex(v),
                "Y" => y = unhex(v),
                "R" => r = unhex(v),
                "S" => s = unhex(v),
                "Result" => out.push(Vector {
                    name: format!("{group} #{}", out.len()),
                    hash,
                    p: p.clone(),
                    q: q.clone(),
                    g: g.clone(),
                    y: y.clone(),
                    msg: msg.clone(),
                    r: r.clone(),
                    s: s.clone(),
                    ok: v.starts_with('P'),
                }),
                _ => {}
            }
        }
        out
    }

    /// FIPS 186-4 SigVer vectors: each valid one must verify, each marked invalid must fail
    /// (at key construction when the key itself was altered).
    #[test]
    fn cavp_sigver() {
        let vs = vectors();
        assert_eq!(vs.len(), 100);
        for v in &vs {
            let key = match PublicKey::from_components(&v.p, &v.q, &v.g, &v.y) {
                Ok(k) => k,
                Err(e) => {
                    assert!(!v.ok, "{}: key rejected: {e:?}", v.name);
                    continue;
                }
            };
            let res = key.verify(v.hash, &v.msg, &sig_der(&v.r, &v.s));
            assert_eq!(res.is_ok(), v.ok, "{}", v.name);
        }
    }

    #[test]
    fn rejects() {
        let vs = vectors();
        let v = &vs[0];
        let key = PublicKey::from_components(&v.p, &v.q, &v.g, &v.y).unwrap();
        let back = PublicKey::from_der(&key.params_der(), &key.key_der()).unwrap();
        assert_eq!(back, key);
        let q = v.q.clone();
        // r = 0, r = q, trailing data, BER.
        assert!(key.verify(v.hash, b"", &sig_der(&[], &v.s)).is_err());
        assert!(key.verify(v.hash, b"", &sig_der(&q, &v.s)).is_err());
        let mut d = sig_der(&v.r, &v.s);
        d.push(0);
        assert!(key.verify(v.hash, &v.msg, &d).is_err());
        // g = 1 and wrong sizes.
        assert!(PublicKey::from_components(&v.p, &q, &[1], &v.y).is_err());
        assert!(PublicKey::from_components(&v.p[1..], &q, &v.g, &v.y).is_err());
    }
}
