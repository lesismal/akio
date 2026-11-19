//! Algorithm-agnostic public and private keys: encoding (SubjectPublicKeyInfo, PKCS#8, SEC1,
//! PKCS#1, PEM) and signatures by [`SignatureAlgorithm`], as TLS and X.509 use them.
//!
//! ```
//! use only_crypto::pkey::{PrivateKey, PublicKey, SignatureAlgorithm};
//!
//! let key = PrivateKey::P256(only_crypto::p256::SecretKey::generate().unwrap());
//! let pem = key.to_pkcs8_pem();
//! let key = PrivateKey::from_pem(pem.as_bytes()).unwrap();
//! let spki = key.public_key().to_spki_der();
//! let sig = key.sign(SignatureAlgorithm::EcdsaSha256, b"msg").unwrap();
//! PublicKey::from_spki_der(&spki)
//!     .unwrap()
//!     .verify(SignatureAlgorithm::EcdsaSha256, b"msg", &sig)
//!     .unwrap();
//! ```

use crate::der::{Reader, Writer, oid, tag};
use crate::hash::{Sha256, Sha384, Sha512};
use crate::rsa::HashAlg;
use crate::{Error, dsa, ed448, ed25519, p256, p384, pem, rsa};

/// A signature algorithm as TLS signature schemes and X.509 `AlgorithmIdentifier`s name them.
/// ECDSA signatures are DER `ECDSA-Sig-Value`s; the curve comes from the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// ECDSA with SHA-256 (`ecdsa-with-SHA256`; TLS `ecdsa_secp256r1_sha256` with a P-256 key).
    EcdsaSha256,
    /// ECDSA with SHA-384.
    EcdsaSha384,
    /// ECDSA with SHA-512.
    EcdsaSha512,
    /// Ed25519 (RFC 8032).
    Ed25519,
    /// Ed448 (RFC 8032, pure, empty context).
    Ed448,
    /// DSA with SHA-1: legacy, verification only (RFC 3279).
    DsaSha1,
    /// DSA with SHA-224: verification only (RFC 5758).
    DsaSha224,
    /// DSA with SHA-256: verification only (RFC 5758).
    DsaSha256,
    /// RSASSA-PKCS1-v1_5 with SHA-1: legacy, verification of old certificates only.
    RsaPkcs1Sha1,
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RsaPkcs1Sha256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    RsaPkcs1Sha384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    RsaPkcs1Sha512,
    /// RSASSA-PSS with SHA-256, MGF1-SHA-256, 32-byte salt.
    RsaPssSha256,
    /// RSASSA-PSS with SHA-384, MGF1-SHA-384, 48-byte salt.
    RsaPssSha384,
    /// RSASSA-PSS with SHA-512, MGF1-SHA-512, 64-byte salt.
    RsaPssSha512,
}

impl SignatureAlgorithm {
    /// From an X.509 / PKCS `AlgorithmIdentifier` (the DER SEQUENCE). RSA-PSS parameters must
    /// be the hash-length-salt, same-hash-MGF1 combinations TLS 1.3 allows.
    pub fn from_algorithm_identifier(der: &[u8]) -> Result<SignatureAlgorithm, Error> {
        let mut r = Reader::new(der);
        let mut s = r.sequence()?;
        let alg = s.read_oid()?;
        let params = s.remaining();
        r.finish()?;
        let no_params = params.is_empty();
        let null_params = params == [tag::NULL, 0];
        use SignatureAlgorithm as A;
        let a = match alg {
            x if x == oid::ECDSA_WITH_SHA256 && no_params => A::EcdsaSha256,
            x if x == oid::ECDSA_WITH_SHA384 && no_params => A::EcdsaSha384,
            x if x == oid::ECDSA_WITH_SHA512 && no_params => A::EcdsaSha512,
            x if x == oid::ED25519 && no_params => A::Ed25519,
            x if x == oid::ED448 && no_params => A::Ed448,
            x if x == oid::DSA_WITH_SHA1 && no_params => A::DsaSha1,
            x if x == oid::DSA_WITH_SHA224 && no_params => A::DsaSha224,
            x if x == oid::DSA_WITH_SHA256 && no_params => A::DsaSha256,
            x if x == oid::SHA1_WITH_RSA && (null_params || no_params) => A::RsaPkcs1Sha1,
            x if x == oid::SHA256_WITH_RSA && (null_params || no_params) => A::RsaPkcs1Sha256,
            x if x == oid::SHA384_WITH_RSA && (null_params || no_params) => A::RsaPkcs1Sha384,
            x if x == oid::SHA512_WITH_RSA && (null_params || no_params) => A::RsaPkcs1Sha512,
            x if x == oid::RSASSA_PSS => {
                let a = [A::RsaPssSha256, A::RsaPssSha384, A::RsaPssSha512]
                    .into_iter()
                    .find(|a| a.pss_params().as_deref() == Some(params));
                a.ok_or(Error::Unsupported)?
            }
            _ => return Err(Error::Unsupported),
        };
        Ok(a)
    }

    /// The DER `AlgorithmIdentifier` X.509 uses for this algorithm.
    #[must_use]
    pub fn to_algorithm_identifier(self) -> Vec<u8> {
        use SignatureAlgorithm as A;
        let mut w = Writer::new();
        w.sequence(|w| match self {
            A::EcdsaSha256 => w.oid(oid::ECDSA_WITH_SHA256),
            A::EcdsaSha384 => w.oid(oid::ECDSA_WITH_SHA384),
            A::EcdsaSha512 => w.oid(oid::ECDSA_WITH_SHA512),
            A::Ed25519 => w.oid(oid::ED25519),
            A::Ed448 => w.oid(oid::ED448),
            A::DsaSha1 => w.oid(oid::DSA_WITH_SHA1),
            A::DsaSha224 => w.oid(oid::DSA_WITH_SHA224),
            A::DsaSha256 => w.oid(oid::DSA_WITH_SHA256),
            A::RsaPkcs1Sha1 | A::RsaPkcs1Sha256 | A::RsaPkcs1Sha384 | A::RsaPkcs1Sha512 => {
                w.oid(match self {
                    A::RsaPkcs1Sha1 => oid::SHA1_WITH_RSA,
                    A::RsaPkcs1Sha256 => oid::SHA256_WITH_RSA,
                    A::RsaPkcs1Sha384 => oid::SHA384_WITH_RSA,
                    _ => oid::SHA512_WITH_RSA,
                });
                w.null();
            }
            A::RsaPssSha256 | A::RsaPssSha384 | A::RsaPssSha512 => {
                w.oid(oid::RSASSA_PSS);
                w.raw(&self.pss_params().unwrap_or_default());
            }
        });
        w.into_vec()
    }

    /// The DER `RSASSA-PSS-params` (RFC 4055) for the PSS variants.
    fn pss_params(self) -> Option<Vec<u8>> {
        let (h, salt) = match self {
            SignatureAlgorithm::RsaPssSha256 => (oid::SHA256, 32),
            SignatureAlgorithm::RsaPssSha384 => (oid::SHA384, 48),
            SignatureAlgorithm::RsaPssSha512 => (oid::SHA512, 64),
            _ => return None,
        };
        let hash_alg = |w: &mut Writer| {
            w.sequence(|w| {
                w.oid(h);
                w.null();
            });
        };
        let mut w = Writer::new();
        w.sequence(|w| {
            w.nested(tag::explicit(0), hash_alg);
            w.nested(tag::explicit(1), |w| {
                w.sequence(|w| {
                    w.oid(oid::MGF1);
                    hash_alg(w);
                });
            });
            w.nested(tag::explicit(2), |w| w.small_uint(salt));
        });
        Some(w.into_vec())
    }

    fn rsa(self) -> Option<(HashAlg, bool)> {
        use SignatureAlgorithm as A;
        Some(match self {
            A::RsaPkcs1Sha1 => (HashAlg::Sha1, false),
            A::RsaPkcs1Sha256 => (HashAlg::Sha256, false),
            A::RsaPkcs1Sha384 => (HashAlg::Sha384, false),
            A::RsaPkcs1Sha512 => (HashAlg::Sha512, false),
            A::RsaPssSha256 => (HashAlg::Sha256, true),
            A::RsaPssSha384 => (HashAlg::Sha384, true),
            A::RsaPssSha512 => (HashAlg::Sha512, true),
            _ => return None,
        })
    }

    fn dsa(self) -> Option<HashAlg> {
        Some(match self {
            SignatureAlgorithm::DsaSha1 => HashAlg::Sha1,
            SignatureAlgorithm::DsaSha224 => HashAlg::Sha224,
            SignatureAlgorithm::DsaSha256 => HashAlg::Sha256,
            _ => return None,
        })
    }
}

/// A public key of any supported type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PublicKey {
    /// Ed25519.
    Ed25519(ed25519::VerifyingKey),
    /// Ed448.
    Ed448(ed448::VerifyingKey),
    /// ECDSA / ECDH on P-256.
    P256(p256::PublicKey),
    /// ECDSA / ECDH on P-384.
    P384(p384::PublicKey),
    /// RSA.
    Rsa(rsa::PublicKey),
    /// DSA (verification only).
    Dsa(dsa::PublicKey),
}

/// Reads an `AlgorithmIdentifier` into `(oid, parameters)`.
fn read_alg_id<'a>(r: &mut Reader<'a>) -> Result<(&'a [u8], &'a [u8]), Error> {
    let mut s = r.sequence()?;
    let o = s.read_oid()?;
    Ok((o, s.remaining()))
}

/// The named curve OID in EC parameters (explicit parameters are not supported).
fn named_curve(params: &[u8]) -> Result<&[u8], Error> {
    let mut r = Reader::new(params);
    if r.peek_tag() != Some(tag::OID) {
        return Err(Error::Unsupported);
    }
    let c = r.read_oid()?;
    r.finish()?;
    Ok(c)
}

impl PublicKey {
    /// From a DER `SubjectPublicKeyInfo`.
    pub fn from_spki_der(der: &[u8]) -> Result<PublicKey, Error> {
        let mut r = Reader::new(der);
        let mut s = r.sequence()?;
        let (alg, params) = read_alg_id(&mut s)?;
        let key = s.read_bit_string()?;
        s.finish()?;
        r.finish()?;
        Self::from_algorithm_and_key(alg, params, key)
    }

    /// From the parts of a `SubjectPublicKeyInfo`: algorithm OID, raw parameters, key bits.
    pub fn from_algorithm_and_key(
        alg: &[u8],
        params: &[u8],
        key: &[u8],
    ) -> Result<PublicKey, Error> {
        match alg {
            x if x == oid::EC_PUBLIC_KEY => match named_curve(params)? {
                c if c == oid::SECP256R1 => p256::PublicKey::from_sec1(key).map(PublicKey::P256),
                c if c == oid::SECP384R1 => p384::PublicKey::from_sec1(key).map(PublicKey::P384),
                _ => Err(Error::Unsupported),
            },
            x if x == oid::ED25519 => {
                if !params.is_empty() {
                    return Err(Error::Encoding);
                }
                ed25519::VerifyingKey::from_bytes(key).map(PublicKey::Ed25519)
            }
            x if x == oid::ED448 => {
                if !params.is_empty() {
                    return Err(Error::Encoding);
                }
                ed448::VerifyingKey::from_bytes(key).map(PublicKey::Ed448)
            }
            // Absent parameters (inherited from the issuer, RFC 3279 §2.3.2) are not supported.
            x if x == oid::DSA => dsa::PublicKey::from_der(params, key).map(PublicKey::Dsa),
            x if x == oid::RSA_ENCRYPTION => {
                if params != [tag::NULL, 0] {
                    return Err(Error::Encoding);
                }
                rsa::PublicKey::from_pkcs1_der(key).map(PublicKey::Rsa)
            }
            _ => Err(Error::Unsupported),
        }
    }

    /// The DER `SubjectPublicKeyInfo`.
    #[must_use]
    pub fn to_spki_der(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.sequence(|w| {
            w.sequence(|w| match self {
                PublicKey::Ed25519(_) => w.oid(oid::ED25519),
                PublicKey::Ed448(_) => w.oid(oid::ED448),
                PublicKey::Dsa(k) => {
                    w.oid(oid::DSA);
                    w.raw(&k.params_der());
                }
                PublicKey::P256(_) => {
                    w.oid(oid::EC_PUBLIC_KEY);
                    w.oid(oid::SECP256R1);
                }
                PublicKey::P384(_) => {
                    w.oid(oid::EC_PUBLIC_KEY);
                    w.oid(oid::SECP384R1);
                }
                PublicKey::Rsa(_) => {
                    w.oid(oid::RSA_ENCRYPTION);
                    w.null();
                }
            });
            w.bit_string(&self.raw_key());
        });
        w.into_vec()
    }

    /// The key bits of the `SubjectPublicKeyInfo`: the 32-byte Ed25519 or 57-byte Ed448 key,
    /// the uncompressed SEC1 point, the PKCS#1 `RSAPublicKey`, or the DSA `INTEGER` `y`.
    #[must_use]
    pub fn raw_key(&self) -> Vec<u8> {
        match self {
            PublicKey::Ed25519(k) => k.as_bytes().to_vec(),
            PublicKey::Ed448(k) => k.as_bytes().to_vec(),
            PublicKey::Dsa(k) => k.key_der(),
            PublicKey::P256(k) => k.to_uncompressed(),
            PublicKey::P384(k) => k.to_uncompressed(),
            PublicKey::Rsa(k) => k.to_pkcs1_der(),
        }
    }

    /// Verifies `sig` on `msg`. Fails with [`Error::Unsupported`] if the algorithm does not
    /// fit the key type and [`Error::Verification`] if the signature is invalid.
    pub fn verify(&self, alg: SignatureAlgorithm, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        use SignatureAlgorithm as A;
        macro_rules! ecdsa {
            ($k:expr, $m:ident) => {{
                let s = $m::Signature::from_der(sig).map_err(|_| Error::Verification)?;
                match alg {
                    A::EcdsaSha256 => $k.verify_with::<Sha256>(msg, &s),
                    A::EcdsaSha384 => $k.verify_with::<Sha384>(msg, &s),
                    A::EcdsaSha512 => $k.verify_with::<Sha512>(msg, &s),
                    _ => Err(Error::Unsupported),
                }
            }};
        }
        match self {
            PublicKey::Ed25519(k) if alg == A::Ed25519 => k.verify(msg, sig),
            PublicKey::Ed448(k) if alg == A::Ed448 => k.verify(msg, sig),
            PublicKey::Dsa(k) => match alg.dsa() {
                Some(h) => k.verify(h, msg, sig),
                None => Err(Error::Unsupported),
            },
            PublicKey::P256(k)
                if matches!(alg, A::EcdsaSha256 | A::EcdsaSha384 | A::EcdsaSha512) =>
            {
                ecdsa!(k, p256)
            }
            PublicKey::P384(k)
                if matches!(alg, A::EcdsaSha256 | A::EcdsaSha384 | A::EcdsaSha512) =>
            {
                ecdsa!(k, p384)
            }
            PublicKey::Rsa(k) => match alg.rsa() {
                Some((h, false)) => k.verify_pkcs1v15(h, msg, sig),
                Some((h, true)) => k.verify_pss(h, msg, sig, h.output_len()),
                None => Err(Error::Unsupported),
            },
            _ => Err(Error::Unsupported),
        }
    }
}

/// A private key of any supported type.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)] // Ed25519 keys cache their expansion; RSA is boxed
#[non_exhaustive]
pub enum PrivateKey {
    /// Ed25519.
    Ed25519(ed25519::SigningKey),
    /// Ed448.
    Ed448(ed448::SigningKey),
    /// P-256.
    P256(p256::SecretKey),
    /// P-384.
    P384(p384::SecretKey),
    /// RSA.
    Rsa(Box<rsa::PrivateKey>),
}

/// `(curve OID, private scalar, public point if present)` of a SEC1 key.
type Sec1<'a> = (&'a [u8], &'a [u8], Option<&'a [u8]>);

/// Reads a SEC1 `ECPrivateKey` (RFC 5915); `curve` is the curve OID from the PKCS#8 wrapper if
/// any. Returns `(curve OID, scalar bytes, public point if present)`.
fn read_sec1<'a>(der: &'a [u8], curve: Option<&'a [u8]>) -> Result<Sec1<'a>, Error> {
    let mut r = Reader::new(der);
    let mut s = r.sequence()?;
    if s.read_small_uint()? != 1 {
        return Err(Error::Encoding);
    }
    let d = s.read_octet_string()?;
    let params = s.read_optional(tag::explicit(0))?;
    let public = match s.read_optional(tag::explicit(1))? {
        Some(p) => {
            let mut pr = Reader::new(p);
            let bits = pr.read_bit_string()?;
            pr.finish()?;
            Some(bits)
        }
        None => None,
    };
    s.finish()?;
    r.finish()?;
    let named = match params {
        Some(p) => Some(named_curve(p)?),
        None => None,
    };
    let c = match (curve, named) {
        (Some(a), Some(b)) if a != b => return Err(Error::Encoding),
        (Some(a), _) => a,
        (None, Some(b)) => b,
        (None, None) => return Err(Error::Encoding),
    };
    Ok((c, d, public))
}

/// Left-pads a scalar to `n` bytes (some encoders drop leading zeros).
fn pad(d: &[u8], n: usize) -> Result<Vec<u8>, Error> {
    if d.len() > n {
        return Err(Error::InvalidKey);
    }
    let mut v = vec![0u8; n - d.len()];
    v.extend_from_slice(d);
    Ok(v)
}

impl PrivateKey {
    fn from_ec(curve: &[u8], d: &[u8], public: Option<&[u8]>) -> Result<PrivateKey, Error> {
        let k = match curve {
            c if c == oid::SECP256R1 => {
                PrivateKey::P256(p256::SecretKey::from_bytes(&pad(d, 32)?)?)
            }
            c if c == oid::SECP384R1 => {
                PrivateKey::P384(p384::SecretKey::from_bytes(&pad(d, 48)?)?)
            }
            _ => return Err(Error::Unsupported),
        };
        if let Some(p) = public {
            let ours = k.public_key().raw_key();
            let theirs = match &k {
                PrivateKey::P256(_) => p256::PublicKey::from_sec1(p)?.to_uncompressed(),
                _ => p384::PublicKey::from_sec1(p)?.to_uncompressed(),
            };
            if ours != theirs {
                return Err(Error::InvalidKey);
            }
        }
        Ok(k)
    }

    /// From a DER PKCS#8 `PrivateKeyInfo` / `OneAsymmetricKey` (RFC 5208, 5958): Ed25519,
    /// Ed448, EC (P-256, P-384) or RSA. Unencrypted only.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<PrivateKey, Error> {
        let mut r = Reader::new(der);
        let mut s = r.sequence()?;
        let version = s.read_small_uint()?;
        if version > 1 {
            return Err(Error::Encoding);
        }
        let (alg, params) = read_alg_id(&mut s)?;
        let key = s.read_octet_string()?;
        let _attributes = s.read_optional(tag::explicit(0))?;
        let public = s.read_optional(tag::implicit(1))?;
        s.finish()?;
        r.finish()?;
        if version == 0 && public.is_some() {
            return Err(Error::Encoding);
        }
        match alg {
            x if x == oid::ED25519 => {
                if !params.is_empty() {
                    return Err(Error::Encoding);
                }
                let mut kr = Reader::new(key);
                let seed: [u8; 32] = kr
                    .read_octet_string()?
                    .try_into()
                    .map_err(|_| Error::InvalidKey)?;
                kr.finish()?;
                let k = ed25519::SigningKey::from_seed(&seed);
                if let Some(p) = public {
                    // [1] IMPLICIT BIT STRING: unused-bits byte 0, then the key.
                    if p.first() != Some(&0) || p[1..] != k.verifying_key().as_bytes()[..] {
                        return Err(Error::InvalidKey);
                    }
                }
                Ok(PrivateKey::Ed25519(k))
            }
            x if x == oid::ED448 => {
                if !params.is_empty() {
                    return Err(Error::Encoding);
                }
                let mut kr = Reader::new(key);
                let seed: [u8; 57] = kr
                    .read_octet_string()?
                    .try_into()
                    .map_err(|_| Error::InvalidKey)?;
                kr.finish()?;
                let k = ed448::SigningKey::from_seed(&seed);
                if let Some(p) = public {
                    if p.first() != Some(&0) || p[1..] != k.verifying_key().as_bytes()[..] {
                        return Err(Error::InvalidKey);
                    }
                }
                Ok(PrivateKey::Ed448(k))
            }
            x if x == oid::EC_PUBLIC_KEY => {
                let curve = named_curve(params)?;
                let (c, d, p) = read_sec1(key, Some(curve))?;
                Self::from_ec(c, d, p)
            }
            x if x == oid::RSA_ENCRYPTION => {
                if params != [tag::NULL, 0] {
                    return Err(Error::Encoding);
                }
                Ok(PrivateKey::Rsa(Box::new(rsa::PrivateKey::from_pkcs1_der(
                    key,
                )?)))
            }
            _ => Err(Error::Unsupported),
        }
    }

    /// From a DER SEC1 `ECPrivateKey` (`EC PRIVATE KEY`), which must name its curve.
    pub fn from_sec1_der(der: &[u8]) -> Result<PrivateKey, Error> {
        let (c, d, p) = read_sec1(der, None)?;
        Self::from_ec(c, d, p)
    }

    /// From a DER PKCS#1 `RSAPrivateKey` (`RSA PRIVATE KEY`).
    pub fn from_pkcs1_der(der: &[u8]) -> Result<PrivateKey, Error> {
        Ok(PrivateKey::Rsa(Box::new(rsa::PrivateKey::from_pkcs1_der(
            der,
        )?)))
    }

    /// From DER in any of PKCS#8, SEC1 or PKCS#1.
    pub fn from_der(der: &[u8]) -> Result<PrivateKey, Error> {
        Self::from_pkcs8_der(der)
            .or_else(|_| Self::from_sec1_der(der))
            .or_else(|_| Self::from_pkcs1_der(der))
    }

    /// From the first `PRIVATE KEY`, `EC PRIVATE KEY` or `RSA PRIVATE KEY` PEM block.
    pub fn from_pem(text: &[u8]) -> Result<PrivateKey, Error> {
        for (label, der) in pem::decode(text)? {
            match label.as_str() {
                "PRIVATE KEY" => return Self::from_pkcs8_der(&der),
                "EC PRIVATE KEY" => return Self::from_sec1_der(&der),
                "RSA PRIVATE KEY" => return Self::from_pkcs1_der(&der),
                _ => {}
            }
        }
        Err(Error::Encoding)
    }

    /// The DER PKCS#8 encoding (version 1, no attributes; EC keys include the public key).
    #[must_use]
    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.sequence(|w| {
            w.small_uint(0);
            match self {
                PrivateKey::Ed25519(k) => {
                    w.sequence(|w| w.oid(oid::ED25519));
                    w.nested(tag::OCTET_STRING, |w| w.octet_string(k.seed()));
                }
                PrivateKey::Ed448(k) => {
                    w.sequence(|w| w.oid(oid::ED448));
                    w.nested(tag::OCTET_STRING, |w| w.octet_string(k.seed()));
                }
                PrivateKey::P256(_) | PrivateKey::P384(_) => {
                    let curve = if matches!(self, PrivateKey::P256(_)) {
                        oid::SECP256R1
                    } else {
                        oid::SECP384R1
                    };
                    w.sequence(|w| {
                        w.oid(oid::EC_PUBLIC_KEY);
                        w.oid(curve);
                    });
                    w.octet_string(&self.ec_private_key(false));
                }
                PrivateKey::Rsa(k) => {
                    w.sequence(|w| {
                        w.oid(oid::RSA_ENCRYPTION);
                        w.null();
                    });
                    w.octet_string(&k.to_pkcs1_der());
                }
            }
        });
        w.into_vec()
    }

    /// SEC1 `ECPrivateKey` (with the curve parameters if `with_params`).
    fn ec_private_key(&self, with_params: bool) -> Vec<u8> {
        let (d, curve) = match self {
            PrivateKey::P256(k) => (k.to_bytes().to_vec(), oid::SECP256R1),
            PrivateKey::P384(k) => (k.to_bytes().to_vec(), oid::SECP384R1),
            _ => return Vec::new(),
        };
        let public = self.public_key().raw_key();
        let mut w = Writer::new();
        w.sequence(|w| {
            w.small_uint(1);
            w.octet_string(&d);
            if with_params {
                w.nested(tag::explicit(0), |w| w.oid(curve));
            }
            w.nested(tag::explicit(1), |w| w.bit_string(&public));
        });
        w.into_vec()
    }

    /// The SEC1 `ECPrivateKey` DER with named-curve parameters, for EC keys.
    #[must_use]
    pub fn to_sec1_der(&self) -> Option<Vec<u8>> {
        matches!(self, PrivateKey::P256(_) | PrivateKey::P384(_)).then(|| self.ec_private_key(true))
    }

    /// The PKCS#8 encoding as a `PRIVATE KEY` PEM block.
    #[must_use]
    pub fn to_pkcs8_pem(&self) -> String {
        pem::encode("PRIVATE KEY", &self.to_pkcs8_der())
    }

    /// The public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        match self {
            PrivateKey::Ed25519(k) => PublicKey::Ed25519(k.verifying_key()),
            PrivateKey::Ed448(k) => PublicKey::Ed448(k.verifying_key()),
            PrivateKey::P256(k) => PublicKey::P256(k.public_key()),
            PrivateKey::P384(k) => PublicKey::P384(k.public_key()),
            PrivateKey::Rsa(k) => PublicKey::Rsa(k.public_key().clone()),
        }
    }

    /// The algorithm certificates signed with this key use by default: ECDSA with the curve's
    /// hash, Ed25519, Ed448, RSA PKCS#1 v1.5 with SHA-256.
    #[must_use]
    pub fn default_signature_algorithm(&self) -> SignatureAlgorithm {
        match self {
            PrivateKey::Ed25519(_) => SignatureAlgorithm::Ed25519,
            PrivateKey::Ed448(_) => SignatureAlgorithm::Ed448,
            PrivateKey::P256(_) => SignatureAlgorithm::EcdsaSha256,
            PrivateKey::P384(_) => SignatureAlgorithm::EcdsaSha384,
            PrivateKey::Rsa(_) => SignatureAlgorithm::RsaPkcs1Sha256,
        }
    }

    /// Signs `msg` (ECDSA signatures in DER). Fails with [`Error::Unsupported`] if the
    /// algorithm does not fit the key type (or is SHA-1).
    pub fn sign(&self, alg: SignatureAlgorithm, msg: &[u8]) -> Result<Vec<u8>, Error> {
        use SignatureAlgorithm as A;
        macro_rules! ecdsa {
            ($k:expr) => {
                match alg {
                    A::EcdsaSha256 => Ok($k.sign_with::<Sha256>(msg).to_der()),
                    A::EcdsaSha384 => Ok($k.sign_with::<Sha384>(msg).to_der()),
                    A::EcdsaSha512 => Ok($k.sign_with::<Sha512>(msg).to_der()),
                    _ => Err(Error::Unsupported),
                }
            };
        }
        match self {
            PrivateKey::Ed25519(k) if alg == A::Ed25519 => Ok(k.sign(msg).to_vec()),
            PrivateKey::Ed448(k) if alg == A::Ed448 => Ok(k.sign(msg).to_vec()),
            PrivateKey::P256(k) => ecdsa!(k),
            PrivateKey::P384(k) => ecdsa!(k),
            PrivateKey::Rsa(k) => match alg.rsa() {
                Some((HashAlg::Sha1, _)) | None => Err(Error::Unsupported),
                Some((h, false)) => k.sign_pkcs1v15(h, msg),
                Some((h, true)) => k.sign_pss(h, msg),
            },
            _ => Err(Error::Unsupported),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips() {
        for key in [
            PrivateKey::Ed25519(ed25519::SigningKey::from_seed(&[3; 32])),
            PrivateKey::Ed448(ed448::SigningKey::from_seed(&[3; 57])),
            PrivateKey::P256(p256::SecretKey::generate().unwrap()),
            PrivateKey::P384(p384::SecretKey::generate().unwrap()),
        ] {
            let der = key.to_pkcs8_der();
            let back = PrivateKey::from_der(&der).unwrap();
            assert_eq!(back.to_pkcs8_der(), der);
            if let Some(sec1) = key.to_sec1_der() {
                assert_eq!(
                    PrivateKey::from_sec1_der(&sec1).unwrap().to_pkcs8_der(),
                    der
                );
            }
            let pk = key.public_key();
            let spki = pk.to_spki_der();
            assert_eq!(PublicKey::from_spki_der(&spki).unwrap(), pk);
            let alg = key.default_signature_algorithm();
            let sig = key.sign(alg, b"m").unwrap();
            pk.verify(alg, b"m", &sig).unwrap();
            assert_eq!(pk.verify(alg, b"n", &sig), Err(Error::Verification));
            let ai = alg.to_algorithm_identifier();
            assert_eq!(
                SignatureAlgorithm::from_algorithm_identifier(&ai).unwrap(),
                alg
            );
        }
        for alg in [
            SignatureAlgorithm::RsaPssSha256,
            SignatureAlgorithm::RsaPssSha384,
            SignatureAlgorithm::RsaPssSha512,
            SignatureAlgorithm::RsaPkcs1Sha256,
        ] {
            let ai = alg.to_algorithm_identifier();
            assert_eq!(
                SignatureAlgorithm::from_algorithm_identifier(&ai).unwrap(),
                alg
            );
        }
    }
}
