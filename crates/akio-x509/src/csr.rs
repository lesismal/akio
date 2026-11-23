//! Certificate signing requests (PKCS#10, RFC 2986): made for a key, as an ACME client sends
//! them to finalize an order (RFC 8555 §7.4), and parsed and checked, as a CA or a test server
//! receives them.

use akio_crypto::der::{Reader, Writer, tag};
use akio_crypto::pkey::{PrivateKey, PublicKey, SignatureAlgorithm};

use crate::Error;
use crate::cert::{Extension, ext, read_extension_list};
use crate::name::{GeneralName, Name, attr};

/// The largest DER request [`CertificateRequest::from_der`] parses: requests are a few
/// hundred bytes; this leaves room for long SAN lists and RSA-8192 keys while bounding what a
/// peer can make the parser walk.
pub const MAX_REQUEST_LEN: usize = 64 * 1024;

/// The most attributes a request may carry.
pub const MAX_ATTRIBUTES: usize = 32;

/// PKCS#9 `extensionRequest` (1.2.840.113549.1.9.14).
const EXTENSION_REQUEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e];

/// What to put in a request.
#[derive(Debug, Clone)]
pub struct CsrParams {
    /// The subject name (may be empty: ACME takes the names from subjectAltName).
    pub subject: Name,
    /// subjectAltName entries (DNS names and IP addresses usually).
    pub subject_alt_names: Vec<GeneralName>,
    /// extKeyUsage purposes (OID content bytes, e.g. [`ext::SERVER_AUTH`]); omitted if empty.
    pub extended_key_usage: Vec<Vec<u8>>,
    /// Further requested extensions, appended as given (for example the TLS Feature
    /// extension, RFC 7633, for OCSP must-staple).
    pub custom_extensions: Vec<Extension>,
}

impl CsrParams {
    /// A request for these host names / IP addresses (each parsed with
    /// [`GeneralName::from_host`]), with the first DNS name as the subject common name, as
    /// most CAs expect.
    #[must_use]
    pub fn new<S: AsRef<str>>(names: impl IntoIterator<Item = S>) -> CsrParams {
        let sans: Vec<GeneralName> = names
            .into_iter()
            .map(|n| GeneralName::from_host(n.as_ref()))
            .collect();
        let subject = match sans.iter().find_map(|n| match n {
            GeneralName::Dns(d) => Some(d.clone()),
            _ => None,
        }) {
            Some(cn) => Name::from_attributes([(attr::COMMON_NAME, cn.as_str())]),
            None => Name::from_attributes(std::iter::empty::<(&[u8], &str)>()),
        };
        CsrParams {
            subject,
            subject_alt_names: sans,
            extended_key_usage: Vec::new(),
            custom_extensions: Vec::new(),
        }
    }

    /// The request for `key`'s public key, signed by `key` with its default signature
    /// algorithm.
    pub fn sign(&self, key: &PrivateKey) -> Result<CertificateRequest, Error> {
        let alg = key.default_signature_algorithm();
        let alg_id = alg.to_algorithm_identifier();
        let exts = self.extensions();
        let mut w = Writer::new();
        w.sequence(|w| {
            w.small_uint(0); // version v1
            w.raw(self.subject.as_der());
            w.raw(&key.public_key().to_spki_der());
            // attributes [0] IMPLICIT SET OF Attribute
            w.nested(tag::explicit(0), |w| {
                if !exts.is_empty() {
                    w.sequence(|w| {
                        w.oid(EXTENSION_REQUEST);
                        w.nested(tag::SET, |w| {
                            w.sequence(|w| {
                                for e in &exts {
                                    w.sequence(|w| {
                                        w.oid(&e.oid);
                                        if e.critical {
                                            w.bool(true);
                                        }
                                        w.octet_string(&e.value);
                                    });
                                }
                            });
                        });
                    });
                }
            });
        });
        let info = w.into_vec();
        let sig = key.sign(alg, &info).map_err(Error::Crypto)?;
        let mut w = Writer::new();
        w.sequence(|w| {
            w.raw(&info);
            w.raw(&alg_id);
            w.bit_string(&sig);
        });
        CertificateRequest::from_der(w.into_vec())
    }

    fn extensions(&self) -> Vec<Extension> {
        let mut out = Vec::new();
        if !self.subject_alt_names.is_empty() {
            let mut v = Writer::new();
            v.sequence(|w| {
                for n in &self.subject_alt_names {
                    n.write(w);
                }
            });
            out.push(Extension {
                oid: ext::SUBJECT_ALT_NAME.to_vec(),
                // Critical when the subject is empty (RFC 5280 §4.2.1.6).
                critical: self.subject.is_empty(),
                value: v.into_vec(),
            });
        }
        if !self.extended_key_usage.is_empty() {
            let mut v = Writer::new();
            v.sequence(|w| {
                for e in &self.extended_key_usage {
                    w.oid(e);
                }
            });
            out.push(Extension {
                oid: ext::EXT_KEY_USAGE.to_vec(),
                critical: false,
                value: v.into_vec(),
            });
        }
        out.extend(self.custom_extensions.iter().cloned());
        out
    }
}

/// A parsed PKCS#10 certificate signing request. Parsing is strict DER and checks the
/// structure; [`verify_signature`](Self::verify_signature) checks the proof of possession.
#[derive(Debug, Clone)]
pub struct CertificateRequest {
    der: Vec<u8>,
    info: (usize, usize),
    spki: (usize, usize),
    subject: Name,
    signature_algorithm: Result<SignatureAlgorithm, akio_crypto::Error>,
    signature: Vec<u8>,
    extensions: Vec<Extension>,
    subject_alt_names: Vec<GeneralName>,
    attributes: Vec<(Vec<u8>, Vec<u8>)>,
}

impl PartialEq for CertificateRequest {
    fn eq(&self, o: &Self) -> bool {
        self.der == o.der
    }
}
impl Eq for CertificateRequest {}

/// The offset range of `inner` inside `outer`.
fn range(outer: &[u8], inner: &[u8]) -> (usize, usize) {
    let start = inner.as_ptr() as usize - outer.as_ptr() as usize;
    (start, start + inner.len())
}

impl CertificateRequest {
    /// Parses a DER request (at most [`MAX_REQUEST_LEN`] bytes).
    pub fn from_der(der: impl Into<Vec<u8>>) -> Result<CertificateRequest, Error> {
        let der = der.into();
        if der.len() > MAX_REQUEST_LEN {
            return Err(Error::Encoding);
        }
        let mut r = Reader::new(&der);
        let mut req = r.sequence()?;
        r.finish()?;
        let info = req.read_element(tag::SEQUENCE)?;
        let sig_alg = req.read_element(tag::SEQUENCE)?;
        let signature = req.read_bit_string()?;
        req.finish()?;

        let mut t = Reader::new(info).sequence()?;
        if t.read_small_uint()? != 0 {
            return Err(Error::UnsupportedVersion);
        }
        let subject = Name::from_der(t.read_element(tag::SEQUENCE)?)?;
        let spki = t.read_element(tag::SEQUENCE)?;
        let mut extensions = Vec::new();
        let mut subject_alt_names = Vec::new();
        let mut attributes = Vec::new();
        let mut seen_ext_req = false;
        // RFC 2986 makes `attributes` mandatory (possibly empty); a few encoders omit an empty
        // one, which is accepted.
        if let Some(attrs) = t.read_optional(tag::explicit(0))? {
            let mut a = Reader::new(attrs);
            while !a.is_empty() {
                if attributes.len() + usize::from(seen_ext_req) >= MAX_ATTRIBUTES {
                    return Err(Error::Encoding);
                }
                let mut at = a.sequence()?;
                let oid = at.read_oid()?;
                let values = at.read(tag::SET)?;
                at.finish()?;
                if oid == EXTENSION_REQUEST {
                    if seen_ext_req {
                        return Err(Error::DuplicateExtension);
                    }
                    seen_ext_req = true;
                    let mut vs = Reader::new(values);
                    let mut seq = vs.sequence()?;
                    vs.finish()?; // exactly one value
                    // An empty list is what OpenSSL writes when no extension is requested.
                    if !seq.is_empty() {
                        extensions = read_extension_list(&mut seq)?;
                    }
                    if let Some(e) = extensions.iter().find(|e| e.oid == ext::SUBJECT_ALT_NAME) {
                        let mut er = Reader::new(&e.value);
                        let s = er.sequence()?;
                        er.finish()?;
                        subject_alt_names = crate::cert::read_general_names(s)?;
                    }
                } else {
                    if attributes
                        .iter()
                        .any(|(o, _): &(Vec<u8>, Vec<u8>)| o == oid)
                    {
                        return Err(Error::Encoding);
                    }
                    attributes.push((oid.to_vec(), values.to_vec()));
                }
            }
        }
        t.finish()?;
        Ok(CertificateRequest {
            info: range(&der, info),
            spki: range(&der, spki),
            subject,
            signature_algorithm: SignatureAlgorithm::from_algorithm_identifier(sig_alg),
            signature: signature.to_vec(),
            extensions,
            subject_alt_names,
            attributes,
            der,
        })
    }

    /// The single `CERTIFICATE REQUEST` (or legacy `NEW CERTIFICATE REQUEST`) block of a PEM
    /// text.
    pub fn from_pem(text: &[u8]) -> Result<CertificateRequest, Error> {
        let mut blocks = akio_crypto::pem::decode_label(text, "CERTIFICATE REQUEST")?;
        if blocks.is_empty() {
            blocks = akio_crypto::pem::decode_label(text, "NEW CERTIFICATE REQUEST")?;
        }
        if blocks.len() != 1 {
            return Err(Error::Encoding);
        }
        CertificateRequest::from_der(blocks.remove(0))
    }

    /// The DER encoding (what RFC 8555's `finalize` sends, base64url-encoded).
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// The PEM encoding.
    #[must_use]
    pub fn to_pem(&self) -> String {
        akio_crypto::pem::encode("CERTIFICATE REQUEST", &self.der)
    }

    /// The DER `CertificationRequestInfo` (the signed part).
    #[must_use]
    pub fn info_der(&self) -> &[u8] {
        &self.der[self.info.0..self.info.1]
    }

    /// The subject name.
    #[must_use]
    pub fn subject(&self) -> &Name {
        &self.subject
    }

    /// The DER `SubjectPublicKeyInfo`.
    #[must_use]
    pub fn spki_der(&self) -> &[u8] {
        &self.der[self.spki.0..self.spki.1]
    }

    /// The public key; fails for key types `akio-crypto` does not support.
    pub fn public_key(&self) -> Result<PublicKey, Error> {
        PublicKey::from_spki_der(self.spki_der()).map_err(Error::Crypto)
    }

    /// The signature algorithm; fails for algorithms `akio-crypto` does not support.
    pub fn signature_algorithm(&self) -> Result<SignatureAlgorithm, Error> {
        self.signature_algorithm.map_err(Error::Crypto)
    }

    /// The signature bytes.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The requested extensions (the `extensionRequest` attribute), as given.
    #[must_use]
    pub fn extensions(&self) -> &[Extension] {
        &self.extensions
    }

    /// The requested subjectAltName entries.
    #[must_use]
    pub fn subject_alt_names(&self) -> &[GeneralName] {
        &self.subject_alt_names
    }

    /// Attributes other than `extensionRequest`: each OID (content bytes) with the contents of
    /// its value SET, unparsed (for example PKCS#9 `challengePassword`).
    #[must_use]
    pub fn attributes(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.attributes
    }

    /// Whether the request is signed by the key it carries (proof of possession).
    pub fn verify_signature(&self) -> Result<(), Error> {
        let alg = self.signature_algorithm()?;
        self.public_key()?
            .verify(alg, self.info_der(), &self.signature)
            .map_err(|e| match e {
                akio_crypto::Error::Verification => Error::BadSignature,
                e => Error::Crypto(e),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p256() -> PrivateKey {
        PrivateKey::P256(akio_crypto::p256::SecretKey::generate().unwrap())
    }

    #[test]
    fn round_trip_names_and_signature() {
        let key = p256();
        let csr = CsrParams::new(["example.com", "www.example.com", "192.0.2.1"])
            .sign(&key)
            .unwrap();
        assert_eq!(csr.subject().common_name().as_deref(), Some("example.com"));
        assert_eq!(
            csr.subject_alt_names(),
            &[
                GeneralName::from_host("example.com"),
                GeneralName::from_host("www.example.com"),
                GeneralName::from_host("192.0.2.1"),
            ]
        );
        assert_eq!(csr.public_key().unwrap(), key.public_key());
        csr.verify_signature().unwrap();
        let again = CertificateRequest::from_pem(csr.to_pem().as_bytes()).unwrap();
        assert_eq!(again, csr);
        assert!(csr.attributes().is_empty());
    }

    #[test]
    fn other_key_types() {
        let keys = [
            PrivateKey::P384(akio_crypto::p384::SecretKey::generate().unwrap()),
            PrivateKey::Ed25519(akio_crypto::ed25519::SigningKey::generate().unwrap()),
        ];
        for key in keys {
            let csr = CsrParams::new(["a.test"]).sign(&key).unwrap();
            csr.verify_signature().unwrap();
            assert_eq!(csr.public_key().unwrap(), key.public_key());
        }
    }

    #[test]
    fn empty_subject_makes_san_critical() {
        let mut p = CsrParams::new(["a.test"]);
        p.subject = Name::from_attributes(std::iter::empty::<(&[u8], &str)>());
        let csr = p.sign(&p256()).unwrap();
        assert!(csr.subject().is_empty());
        let san = csr
            .extensions()
            .iter()
            .find(|e| e.oid == ext::SUBJECT_ALT_NAME)
            .unwrap();
        assert!(san.critical);
    }

    #[test]
    fn ip_only_has_no_common_name() {
        let csr = CsrParams::new(["2001:db8::1"]).sign(&p256()).unwrap();
        assert!(csr.subject().is_empty());
        csr.verify_signature().unwrap();
    }

    #[test]
    fn eku_and_custom_extension() {
        let mut p = CsrParams::new(["a.test"]);
        p.extended_key_usage.push(ext::SERVER_AUTH.to_vec());
        // TLS Feature (1.3.6.1.5.5.7.1.24), status_request: OCSP must-staple.
        p.custom_extensions.push(Extension {
            oid: vec![0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18],
            critical: false,
            value: vec![0x30, 0x03, 0x02, 0x01, 0x05],
        });
        let csr = p.sign(&p256()).unwrap();
        let oids: Vec<&[u8]> = csr.extensions().iter().map(|e| e.oid.as_slice()).collect();
        assert_eq!(oids.len(), 3);
        assert!(oids.contains(&ext::EXT_KEY_USAGE));
    }

    #[test]
    fn no_names_no_attributes() {
        let p = CsrParams::new(std::iter::empty::<&str>());
        let csr = p.sign(&p256()).unwrap();
        assert!(csr.extensions().is_empty());
        csr.verify_signature().unwrap();
    }

    #[test]
    fn tampered_info_fails_signature() {
        let csr = CsrParams::new(["a.test"]).sign(&p256()).unwrap();
        let mut der = csr.as_der().to_vec();
        // Flip a byte of the common name "a.test" inside the signed part.
        let pos = der.windows(6).position(|w| w == b"a.test").unwrap();
        der[pos] = b'b';
        let bad = CertificateRequest::from_der(der).unwrap();
        assert_eq!(bad.verify_signature(), Err(Error::BadSignature));
    }

    #[test]
    fn rejects_bad_structure() {
        let csr = CsrParams::new(["a.test"]).sign(&p256()).unwrap();
        let der = csr.as_der();
        // Truncated, trailing garbage, oversized.
        assert!(CertificateRequest::from_der(&der[..der.len() - 1]).is_err());
        let mut long = der.to_vec();
        long.push(0);
        assert!(CertificateRequest::from_der(long).is_err());
        assert!(CertificateRequest::from_der(vec![0x30; MAX_REQUEST_LEN + 1]).is_err());
        assert!(CertificateRequest::from_der(Vec::new()).is_err());
        // Version 1 instead of 0: re-sign is not needed, parsing refuses first.
        let mut v = der.to_vec();
        let info_start = csr.info.0;
        // SEQUENCE header of info, then INTEGER 02 01 00.
        let ver = v[info_start..]
            .windows(3)
            .position(|w| w == [0x02, 0x01, 0x00])
            .unwrap();
        v[info_start + ver + 2] = 1;
        assert_eq!(
            CertificateRequest::from_der(v).err(),
            Some(Error::UnsupportedVersion)
        );
    }

    #[test]
    fn pem_needs_exactly_one_block() {
        let a = CsrParams::new(["a.test"]).sign(&p256()).unwrap();
        let two = format!("{}{}", a.to_pem(), a.to_pem());
        assert!(CertificateRequest::from_pem(two.as_bytes()).is_err());
        assert!(CertificateRequest::from_pem(b"").is_err());
        let legacy = akio_crypto::pem::encode("NEW CERTIFICATE REQUEST", a.as_der());
        assert_eq!(CertificateRequest::from_pem(legacy.as_bytes()).unwrap(), a);
    }
}
