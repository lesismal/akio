//! Certificate generation for tests and development servers: self-signed or CA-signed,
//! signed with any [`PrivateKey`] (ECDSA P-256 is the default for generated keys).

use akio_crypto::der::{Writer, tag};
use akio_crypto::hash::Sha1;
use akio_crypto::pkey::{PrivateKey, PublicKey};

use crate::Error;
use crate::cert::{Certificate, Extension, KeyUsage, NameConstraints, ext};
use crate::name::{GeneralName, Name, attr};
use crate::time::write_time;

/// Whether the certificate is a CA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsCa {
    /// An end entity (no basicConstraints extension).
    No,
    /// A CA with an optional pathLenConstraint.
    Ca(Option<u32>),
}

/// What to put in a certificate.
#[derive(Debug, Clone)]
pub struct CertificateParams {
    /// The subject name.
    pub subject: Name,
    /// subjectAltName entries (DNS names and IP addresses usually).
    pub subject_alt_names: Vec<GeneralName>,
    /// notBefore, Unix seconds.
    pub not_before: i64,
    /// notAfter, Unix seconds.
    pub not_after: i64,
    /// The serial number (positive, big-endian); random 16 bytes if `None`.
    pub serial: Option<Vec<u8>>,
    /// CA or end entity.
    pub is_ca: IsCa,
    /// keyUsage (critical) if set.
    pub key_usage: Option<KeyUsage>,
    /// extKeyUsage purposes (OID content bytes, e.g. [`ext::SERVER_AUTH`]); omitted if empty.
    pub extended_key_usage: Vec<Vec<u8>>,
    /// nameConstraints (critical) for a CA.
    pub name_constraints: Option<NameConstraints>,
    /// Further extensions, appended as given.
    pub custom_extensions: Vec<Extension>,
}

impl CertificateParams {
    /// An end-entity certificate for these host names / IP addresses (each parsed with
    /// [`GeneralName::from_host`]), valid from one hour ago for one year, with the first name
    /// as the subject common name.
    #[must_use]
    pub fn new<S: AsRef<str>>(names: impl IntoIterator<Item = S>) -> CertificateParams {
        let sans: Vec<GeneralName> = names
            .into_iter()
            .map(|n| GeneralName::from_host(n.as_ref()))
            .collect();
        let cn = match sans.first() {
            Some(GeneralName::Dns(d)) => d.clone(),
            _ => "akio self-signed".to_string(),
        };
        let now = crate::time::now();
        CertificateParams {
            subject: Name::from_attributes([(attr::COMMON_NAME, cn.as_str())]),
            subject_alt_names: sans,
            not_before: now - 3600,
            not_after: now + 365 * 86_400,
            serial: None,
            is_ca: IsCa::No,
            key_usage: None,
            extended_key_usage: Vec::new(),
            name_constraints: None,
            custom_extensions: Vec::new(),
        }
    }

    /// A CA certificate with this common name, keyCertSign/cRLSign/digitalSignature, valid
    /// from one hour ago for ten years.
    #[must_use]
    pub fn ca(common_name: &str) -> CertificateParams {
        let mut p = CertificateParams::new(std::iter::empty::<&str>());
        p.subject = Name::from_attributes([(attr::COMMON_NAME, common_name)]);
        p.is_ca = IsCa::Ca(None);
        p.key_usage = Some(
            KeyUsage::KEY_CERT_SIGN
                .union(KeyUsage::CRL_SIGN)
                .union(KeyUsage::DIGITAL_SIGNATURE),
        );
        p.not_after = p.not_before + 3600 + 10 * 365 * 86_400;
        p
    }

    /// A self-signed certificate for `key`.
    pub fn self_signed(&self, key: &PrivateKey) -> Result<Certificate, Error> {
        let public = key.public_key();
        self.build(&public, &self.subject, None, key)
    }

    /// A certificate for `subject_key`, issued by `issuer` (whose private key is
    /// `issuer_key`).
    pub fn signed_by(
        &self,
        subject_key: &PublicKey,
        issuer: &Certificate,
        issuer_key: &PrivateKey,
    ) -> Result<Certificate, Error> {
        let aki = issuer
            .subject_key_id()
            .map_or_else(|| key_id(&issuer_key.public_key()), <[u8]>::to_vec);
        self.build(subject_key, issuer.subject(), Some(aki), issuer_key)
    }

    fn build(
        &self,
        subject_key: &PublicKey,
        issuer: &Name,
        aki: Option<Vec<u8>>,
        signer: &PrivateKey,
    ) -> Result<Certificate, Error> {
        let alg = signer.default_signature_algorithm();
        let alg_id = alg.to_algorithm_identifier();
        let serial = match &self.serial {
            Some(s) => s.clone(),
            None => {
                let mut s = vec![0u8; 16];
                akio_crypto::rand::fill_random(&mut s)
                    .map_err(|_| Error::Crypto(akio_crypto::Error::Random))?;
                s[0] &= 0x7f;
                s[0] |= 0x01; // positive and 16 bytes long
                s
            }
        };
        let ski = key_id(subject_key);
        let mut w = Writer::new();
        w.sequence(|w| {
            w.nested(tag::explicit(0), |w| w.small_uint(2));
            w.uint(&serial);
            w.raw(&alg_id);
            w.raw(issuer.as_der());
            w.sequence(|w| {
                write_time(w, self.not_before);
                write_time(w, self.not_after);
            });
            w.raw(self.subject.as_der());
            w.raw(&subject_key.to_spki_der());
            w.nested(tag::explicit(3), |w| {
                w.sequence(|w| self.extensions(w, &ski, aki.as_deref()));
            });
        });
        let tbs = w.into_vec();
        let sig = signer.sign(alg, &tbs).map_err(Error::Crypto)?;
        let mut w = Writer::new();
        w.sequence(|w| {
            w.raw(&tbs);
            w.raw(&alg_id);
            w.bit_string(&sig);
        });
        Certificate::from_der(w.into_vec())
    }

    fn extensions(&self, w: &mut Writer, ski: &[u8], aki: Option<&[u8]>) {
        let extension = |w: &mut Writer, oid: &[u8], critical: bool, f: &dyn Fn(&mut Writer)| {
            w.sequence(|w| {
                w.oid(oid);
                if critical {
                    w.bool(true);
                }
                let mut v = Writer::new();
                f(&mut v);
                w.octet_string(v.as_bytes());
            });
        };
        if let IsCa::Ca(path_len) = self.is_ca {
            extension(w, ext::BASIC_CONSTRAINTS, true, &|w| {
                w.sequence(|w| {
                    w.bool(true);
                    if let Some(n) = path_len {
                        w.small_uint(u64::from(n));
                    }
                });
            });
        }
        if let Some(ku) = self.key_usage.filter(|k| k.0 != 0) {
            extension(w, ext::KEY_USAGE, true, &|w| {
                // Named bit list: bit i is bit (7 - i % 8) of byte i / 8, trailing zeros cut.
                let nbits = 16 - ku.0.leading_zeros() as usize;
                let mut bytes = vec![0u8; nbits.div_ceil(8)];
                for i in 0..nbits {
                    if ku.0 & (1 << i) != 0 {
                        bytes[i / 8] |= 0x80 >> (i % 8);
                    }
                }
                w.bit_string_bits(&bytes, nbits);
            });
        }
        if !self.extended_key_usage.is_empty() {
            extension(w, ext::EXT_KEY_USAGE, false, &|w| {
                w.sequence(|w| {
                    for e in &self.extended_key_usage {
                        w.oid(e);
                    }
                });
            });
        }
        if !self.subject_alt_names.is_empty() {
            // Critical when the subject is empty (RFC 5280 §4.2.1.6).
            extension(w, ext::SUBJECT_ALT_NAME, self.subject.is_empty(), &|w| {
                w.sequence(|w| {
                    for n in &self.subject_alt_names {
                        n.write(w);
                    }
                });
            });
        }
        if let Some(nc) = &self.name_constraints {
            extension(w, ext::NAME_CONSTRAINTS, true, &|w| {
                w.sequence(|w| {
                    for (t, list) in [
                        (tag::explicit(0), &nc.permitted),
                        (tag::explicit(1), &nc.excluded),
                    ] {
                        if !list.is_empty() {
                            w.nested(t, |w| {
                                for s in list {
                                    w.sequence(|w| s.0.write(w));
                                }
                            });
                        }
                    }
                });
            });
        }
        extension(w, ext::SUBJECT_KEY_ID, false, &|w| w.octet_string(ski));
        if let Some(aki) = aki {
            extension(w, ext::AUTHORITY_KEY_ID, false, &|w| {
                w.sequence(|w| w.tlv(tag::implicit(0), aki));
            });
        }
        for e in &self.custom_extensions {
            extension(w, &e.oid, e.critical, &|w| w.raw(&e.value));
        }
    }
}

/// The key identifier of RFC 5280 §4.2.1.2 method 1: SHA-1 of the subjectPublicKey bits.
fn key_id(k: &PublicKey) -> Vec<u8> {
    Sha1::digest(&k.raw_key()).to_vec()
}

/// A new ECDSA P-256 key and a self-signed end-entity certificate for these names (like
/// rcgen's `generate_simple_self_signed`).
pub fn generate_simple_self_signed<S: AsRef<str>>(
    names: impl IntoIterator<Item = S>,
) -> Result<(Certificate, PrivateKey), Error> {
    let key = PrivateKey::P256(akio_crypto::p256::SecretKey::generate().map_err(Error::Crypto)?);
    let cert = CertificateParams::new(names).self_signed(&key)?;
    Ok((cert, key))
}
