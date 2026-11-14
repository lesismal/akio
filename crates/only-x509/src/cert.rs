//! Certificate parsing (RFC 5280 §4).

use only_crypto::der::{Reader, tag};
use only_crypto::pkey::{PublicKey, SignatureAlgorithm};

use crate::Error;
use crate::name::{GeneralName, Name};
use crate::time::read_time;

/// Extension and key-purpose OIDs.
pub mod ext {
    /// subjectKeyIdentifier, 2.5.29.14.
    pub const SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1d, 0x0e];
    /// keyUsage, 2.5.29.15.
    pub const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
    /// subjectAltName, 2.5.29.17.
    pub const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
    /// issuerAltName, 2.5.29.18.
    pub const ISSUER_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x12];
    /// basicConstraints, 2.5.29.19.
    pub const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
    /// nameConstraints, 2.5.29.30.
    pub const NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
    /// cRLDistributionPoints, 2.5.29.31.
    pub const CRL_DISTRIBUTION_POINTS: &[u8] = &[0x55, 0x1d, 0x1f];
    /// certificatePolicies, 2.5.29.32.
    pub const CERTIFICATE_POLICIES: &[u8] = &[0x55, 0x1d, 0x20];
    /// authorityKeyIdentifier, 2.5.29.35.
    pub const AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1d, 0x23];
    /// extKeyUsage, 2.5.29.37.
    pub const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
    /// anyExtendedKeyUsage, 2.5.29.37.0.
    pub const ANY_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
    /// id-kp-serverAuth, 1.3.6.1.5.5.7.3.1.
    pub const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
    /// id-kp-clientAuth, 1.3.6.1.5.5.7.3.2.
    pub const CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
}

/// The keyUsage bits (RFC 5280 §4.2.1.3), bit `i` for named bit `i`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyUsage(pub u16);

impl KeyUsage {
    /// digitalSignature.
    pub const DIGITAL_SIGNATURE: KeyUsage = KeyUsage(1 << 0);
    /// nonRepudiation / contentCommitment.
    pub const CONTENT_COMMITMENT: KeyUsage = KeyUsage(1 << 1);
    /// keyEncipherment.
    pub const KEY_ENCIPHERMENT: KeyUsage = KeyUsage(1 << 2);
    /// dataEncipherment.
    pub const DATA_ENCIPHERMENT: KeyUsage = KeyUsage(1 << 3);
    /// keyAgreement.
    pub const KEY_AGREEMENT: KeyUsage = KeyUsage(1 << 4);
    /// keyCertSign.
    pub const KEY_CERT_SIGN: KeyUsage = KeyUsage(1 << 5);
    /// cRLSign.
    pub const CRL_SIGN: KeyUsage = KeyUsage(1 << 6);

    /// Whether every bit of `other` is set.
    #[must_use]
    pub fn contains(self, other: KeyUsage) -> bool {
        self.0 & other.0 == other.0
    }

    /// The union.
    #[must_use]
    pub fn union(self, other: KeyUsage) -> KeyUsage {
        KeyUsage(self.0 | other.0)
    }
}

/// basicConstraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasicConstraints {
    /// Whether the subject is a CA.
    pub ca: bool,
    /// The maximum number of intermediate CA certificates that may follow this one.
    pub path_len: Option<u32>,
}

/// One `GeneralSubtree` of a name constraint (minimum/maximum are not used by RFC 5280
/// profiles and are rejected if present).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralSubtree(pub GeneralName);

/// nameConstraints (RFC 5280 §4.2.1.10).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NameConstraints {
    /// permittedSubtrees.
    pub permitted: Vec<GeneralSubtree>,
    /// excludedSubtrees.
    pub excluded: Vec<GeneralSubtree>,
}

/// A raw extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// The extension OID (content bytes).
    pub oid: Vec<u8>,
    /// The critical flag.
    pub critical: bool,
    /// The extnValue contents (the DER of the extension's value).
    pub value: Vec<u8>,
}

/// A parsed X.509 certificate. Parsing is strict DER and checks the structure and the
/// extensions this crate understands; unsupported key or signature algorithms do not stop
/// parsing (they fail verification).
#[derive(Debug, Clone)]
pub struct Certificate {
    der: Vec<u8>,
    tbs: (usize, usize),
    spki: (usize, usize),
    version: u8,
    serial: Vec<u8>,
    signature_algorithm: Result<SignatureAlgorithm, only_crypto::Error>,
    issuer: Name,
    subject: Name,
    not_before: i64,
    not_after: i64,
    extensions: Vec<Extension>,
    subject_alt_names: Vec<GeneralName>,
    basic_constraints: Option<BasicConstraints>,
    key_usage: Option<KeyUsage>,
    ext_key_usage: Option<Vec<Vec<u8>>>,
    name_constraints: Option<NameConstraints>,
    subject_key_id: Option<Vec<u8>>,
    authority_key_id: Option<Vec<u8>>,
    unsupported_critical: Option<Vec<u8>>,
    signature: Vec<u8>,
}

impl PartialEq for Certificate {
    fn eq(&self, o: &Self) -> bool {
        self.der == o.der
    }
}
impl Eq for Certificate {}

/// The offset range of `inner` inside `outer`.
fn range(outer: &[u8], inner: &[u8]) -> (usize, usize) {
    let start = inner.as_ptr() as usize - outer.as_ptr() as usize;
    (start, start + inner.len())
}

impl Certificate {
    /// Parses a DER certificate.
    pub fn from_der(der: impl Into<Vec<u8>>) -> Result<Certificate, Error> {
        let der = der.into();
        let p = Parsed::parse(&der)?;
        let tbs = range(&der, p.tbs);
        let spki = range(&der, p.spki);
        Ok(Certificate {
            tbs,
            spki,
            version: p.version,
            serial: p.serial.to_vec(),
            signature_algorithm: SignatureAlgorithm::from_algorithm_identifier(p.sig_alg),
            issuer: p.issuer,
            subject: p.subject,
            not_before: p.not_before,
            not_after: p.not_after,
            extensions: p.extensions,
            subject_alt_names: p.san,
            basic_constraints: p.bc,
            key_usage: p.ku,
            ext_key_usage: p.eku,
            name_constraints: p.nc,
            subject_key_id: p.ski,
            authority_key_id: p.aki,
            unsupported_critical: p.unsupported_critical,
            signature: p.signature.to_vec(),
            der,
        })
    }

    /// Every `CERTIFICATE` block of a PEM text.
    pub fn from_pem(text: &[u8]) -> Result<Vec<Certificate>, Error> {
        only_crypto::pem::decode_label(text, "CERTIFICATE")?
            .into_iter()
            .map(Certificate::from_der)
            .collect()
    }

    /// The DER encoding.
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// The PEM encoding.
    #[must_use]
    pub fn to_pem(&self) -> String {
        only_crypto::pem::encode("CERTIFICATE", &self.der)
    }

    /// The DER `TBSCertificate` (the signed part).
    #[must_use]
    pub fn tbs_der(&self) -> &[u8] {
        &self.der[self.tbs.0..self.tbs.1]
    }

    /// The DER `SubjectPublicKeyInfo`.
    #[must_use]
    pub fn spki_der(&self) -> &[u8] {
        &self.der[self.spki.0..self.spki.1]
    }

    /// The subject public key; fails for key types `only-crypto` does not support.
    pub fn public_key(&self) -> Result<PublicKey, Error> {
        PublicKey::from_spki_der(self.spki_der()).map_err(Error::Crypto)
    }

    /// The version: 1, 2 or 3.
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// The serial number's INTEGER contents (two's complement, big-endian).
    #[must_use]
    pub fn serial(&self) -> &[u8] {
        &self.serial
    }

    /// The signature algorithm (an error for unsupported algorithms).
    pub fn signature_algorithm(&self) -> Result<SignatureAlgorithm, Error> {
        self.signature_algorithm.map_err(Error::Crypto)
    }

    /// The signature value.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The issuer name.
    #[must_use]
    pub fn issuer(&self) -> &Name {
        &self.issuer
    }

    /// The subject name.
    #[must_use]
    pub fn subject(&self) -> &Name {
        &self.subject
    }

    /// notBefore, Unix seconds.
    #[must_use]
    pub fn not_before(&self) -> i64 {
        self.not_before
    }

    /// notAfter, Unix seconds.
    #[must_use]
    pub fn not_after(&self) -> i64 {
        self.not_after
    }

    /// All extensions, in order.
    #[must_use]
    pub fn extensions(&self) -> &[Extension] {
        &self.extensions
    }

    /// The subjectAltName entries.
    #[must_use]
    pub fn subject_alt_names(&self) -> &[GeneralName] {
        &self.subject_alt_names
    }

    /// basicConstraints, if present.
    #[must_use]
    pub fn basic_constraints(&self) -> Option<BasicConstraints> {
        self.basic_constraints
    }

    /// Whether basicConstraints marks the subject as a CA.
    #[must_use]
    pub fn is_ca(&self) -> bool {
        self.basic_constraints.is_some_and(|b| b.ca)
    }

    /// keyUsage, if present.
    #[must_use]
    pub fn key_usage(&self) -> Option<KeyUsage> {
        self.key_usage
    }

    /// extKeyUsage purposes (OID content bytes), if present.
    #[must_use]
    pub fn ext_key_usage(&self) -> Option<&[Vec<u8>]> {
        self.ext_key_usage.as_deref()
    }

    /// nameConstraints, if present.
    #[must_use]
    pub fn name_constraints(&self) -> Option<&NameConstraints> {
        self.name_constraints.as_ref()
    }

    /// subjectKeyIdentifier, if present.
    #[must_use]
    pub fn subject_key_id(&self) -> Option<&[u8]> {
        self.subject_key_id.as_deref()
    }

    /// The keyIdentifier of authorityKeyIdentifier, if present.
    #[must_use]
    pub fn authority_key_id(&self) -> Option<&[u8]> {
        self.authority_key_id.as_deref()
    }

    /// The OID of the first critical extension this crate does not process, if any (such a
    /// certificate fails verification, RFC 5280 §4.2).
    #[must_use]
    pub fn unsupported_critical_extension(&self) -> Option<&[u8]> {
        self.unsupported_critical.as_deref()
    }

    /// Whether `issuer` signed this certificate (its key verifies the signature).
    pub fn verify_signed_by(&self, issuer: &PublicKey) -> Result<(), Error> {
        let alg = self.signature_algorithm()?;
        issuer
            .verify(alg, self.tbs_der(), &self.signature)
            .map_err(|e| match e {
                only_crypto::Error::Verification => Error::BadSignature,
                e => Error::Crypto(e),
            })
    }
}

/// The borrowed parse result.
struct Parsed<'a> {
    tbs: &'a [u8],
    sig_alg: &'a [u8],
    signature: &'a [u8],
    version: u8,
    serial: &'a [u8],
    issuer: Name,
    subject: Name,
    not_before: i64,
    not_after: i64,
    spki: &'a [u8],
    extensions: Vec<Extension>,
    san: Vec<GeneralName>,
    bc: Option<BasicConstraints>,
    ku: Option<KeyUsage>,
    eku: Option<Vec<Vec<u8>>>,
    nc: Option<NameConstraints>,
    ski: Option<Vec<u8>>,
    aki: Option<Vec<u8>>,
    unsupported_critical: Option<Vec<u8>>,
}

impl<'a> Parsed<'a> {
    fn parse(der: &'a [u8]) -> Result<Parsed<'a>, Error> {
        let mut r = Reader::new(der);
        let mut cert = r.sequence()?;
        r.finish()?;
        let tbs = cert.read_element(tag::SEQUENCE)?;
        let sig_alg = cert.read_element(tag::SEQUENCE)?;
        let signature = cert.read_bit_string()?;
        cert.finish()?;

        let mut t = Reader::new(tbs).sequence()?;
        let version = match t.read_optional(tag::explicit(0))? {
            Some(v) => {
                let mut vr = Reader::new(v);
                let n = vr.read_small_uint()?;
                vr.finish()?;
                match n {
                    1 => 2,
                    2 => 3,
                    _ => return Err(Error::UnsupportedVersion), // v1 must be omitted in DER
                }
            }
            None => 1,
        };
        let serial = t.read_integer()?;
        if serial.len() > 21 {
            return Err(Error::Encoding);
        }
        let inner_alg = t.read_element(tag::SEQUENCE)?;
        if inner_alg != sig_alg {
            return Err(Error::SignatureAlgorithmMismatch);
        }
        let issuer = Name::from_der(t.read_element(tag::SEQUENCE)?)?;
        let mut validity = t.sequence()?;
        let not_before = read_time(&mut validity)?;
        let not_after = read_time(&mut validity)?;
        validity.finish()?;
        let subject = Name::from_der(t.read_element(tag::SEQUENCE)?)?;
        let spki = t.read_element(tag::SEQUENCE)?;
        // issuerUniqueID [1], subjectUniqueID [2]: IMPLICIT BIT STRING, ignored.
        if version >= 2 {
            let _ = t.read_optional(tag::implicit(1))?;
            let _ = t.read_optional(tag::implicit(2))?;
        }
        let mut p = Parsed {
            tbs,
            sig_alg,
            signature,
            version,
            serial,
            issuer,
            subject,
            not_before,
            not_after,
            spki,
            extensions: Vec::new(),
            san: Vec::new(),
            bc: None,
            ku: None,
            eku: None,
            nc: None,
            ski: None,
            aki: None,
            unsupported_critical: None,
        };
        if version == 3 {
            if let Some(exts) = t.read_optional(tag::explicit(3))? {
                let mut er = Reader::new(exts);
                let mut seq = er.sequence()?;
                er.finish()?;
                if seq.is_empty() {
                    return Err(Error::Encoding);
                }
                while !seq.is_empty() {
                    let mut e = seq.sequence()?;
                    let oid = e.read_oid()?;
                    let critical = if e.peek_tag() == Some(tag::BOOLEAN) {
                        if !e.read_bool()? {
                            return Err(Error::Encoding); // DEFAULT FALSE must be omitted
                        }
                        true
                    } else {
                        false
                    };
                    let value = e.read_octet_string()?;
                    e.finish()?;
                    if p.extensions.iter().any(|x| x.oid == oid) {
                        return Err(Error::DuplicateExtension);
                    }
                    p.extension(oid, critical, value)?;
                    p.extensions.push(Extension {
                        oid: oid.to_vec(),
                        critical,
                        value: value.to_vec(),
                    });
                }
            }
        }
        t.finish()?;
        Ok(p)
    }

    fn extension(&mut self, oid: &[u8], critical: bool, v: &[u8]) -> Result<(), Error> {
        let mut r = Reader::new(v);
        match oid {
            ext::SUBJECT_ALT_NAME => {
                let mut s = r.sequence()?;
                if s.is_empty() {
                    return Err(Error::Encoding);
                }
                while !s.is_empty() {
                    self.san.push(GeneralName::read(&mut s)?);
                }
            }
            ext::BASIC_CONSTRAINTS => {
                let mut s = r.sequence()?;
                let ca = if s.peek_tag() == Some(tag::BOOLEAN) {
                    if !s.read_bool()? {
                        return Err(Error::Encoding);
                    }
                    true
                } else {
                    false
                };
                let path_len = if s.is_empty() {
                    None
                } else {
                    Some(u32::try_from(s.read_small_uint()?).map_err(|_| Error::Encoding)?)
                };
                s.finish()?;
                self.bc = Some(BasicConstraints { ca, path_len });
            }
            ext::KEY_USAGE => {
                let (unused, bits) = r.read_bit_string_bits()?;
                // DER wants trailing zero bits removed, but common encoders (rcgen, some CAs)
                // emit them; accepted, as rustls-webpki and Go do.
                let _ = unused;
                if bits.is_empty() || bits.len() > 2 {
                    return Err(Error::Encoding);
                }
                let mut v = 0u16;
                for (i, b) in bits.iter().enumerate() {
                    for j in 0..8 {
                        if b & (0x80 >> j) != 0 {
                            v |= 1 << (8 * i + j);
                        }
                    }
                }
                self.ku = Some(KeyUsage(v));
            }
            ext::EXT_KEY_USAGE => {
                let mut s = r.sequence()?;
                let mut v = Vec::new();
                if s.is_empty() {
                    return Err(Error::Encoding);
                }
                while !s.is_empty() {
                    v.push(s.read_oid()?.to_vec());
                }
                self.eku = Some(v);
            }
            ext::NAME_CONSTRAINTS => {
                let mut s = r.sequence()?;
                let mut nc = NameConstraints::default();
                for (t, list) in [
                    (tag::explicit(0), &mut nc.permitted),
                    (tag::explicit(1), &mut nc.excluded),
                ] {
                    if let Some(c) = s.read_optional(t)? {
                        let mut sr = Reader::new(c);
                        if sr.is_empty() {
                            return Err(Error::Encoding);
                        }
                        while !sr.is_empty() {
                            let mut st = sr.sequence()?;
                            let base = GeneralName::read(&mut st)?;
                            if !st.is_empty() {
                                return Err(Error::Encoding); // minimum / maximum
                            }
                            list.push(GeneralSubtree(base));
                        }
                    }
                }
                s.finish()?;
                if nc.permitted.is_empty() && nc.excluded.is_empty() {
                    return Err(Error::Encoding);
                }
                self.nc = Some(nc);
            }
            ext::SUBJECT_KEY_ID => self.ski = Some(r.read_octet_string()?.to_vec()),
            ext::AUTHORITY_KEY_ID => {
                let mut s = r.sequence()?;
                self.aki = s.read_optional(tag::implicit(0))?.map(<[u8]>::to_vec);
                // authorityCertIssuer [1], authorityCertSerialNumber [2]: ignored.
                return Ok(());
            }
            // Understood and deliberately not acted on (no policy processing, no CRLs).
            ext::CERTIFICATE_POLICIES | ext::CRL_DISTRIBUTION_POINTS | ext::ISSUER_ALT_NAME => {
                return Ok(());
            }
            _ => {
                if critical && self.unsupported_critical.is_none() {
                    self.unsupported_critical = Some(oid.to_vec());
                }
                return Ok(());
            }
        }
        r.finish()?;
        Ok(())
    }
}
