//! OCSP (RFC 6960): response parsing and validation (the issuer or a delegated responder with
//! id-kp-OCSPSigning, CertID matching, nonce, thisUpdate / nextUpdate with clock skew), and
//! request encoding. Sending requests is up to the application (HTTP POST of
//! [`OcspRequest::to_der`] to a URL of [`Certificate::ocsp_urls`], or a stapled response).

use only_crypto::der::{Reader, Writer, oid, tag};
use only_crypto::hash::{Sha1, Sha256, Sha384, Sha512};
use only_crypto::pkey::{PrivateKey, PublicKey, SignatureAlgorithm};

use crate::Error;
use crate::cert::{Certificate, Extension, KeyUsage, ext, read_extensions};
use crate::name::Name;
use crate::revocation::{DEFAULT_CLOCK_SKEW, RevocationReason, RevocationStatus, is_current};
use crate::time::{read_generalized_time, write_generalized_time};

/// id-pkix-ocsp-basic, 1.3.6.1.5.5.7.48.1.1.
const OCSP_BASIC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
/// id-pkix-ocsp-nonce, 1.3.6.1.5.5.7.48.1.2.
const OCSP_NONCE: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];
/// ENUMERATED.
const ENUMERATED: u8 = 0x0a;

/// `OCSPResponseStatus` (RFC 6960 §4.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OcspResponseStatus {
    /// successful (0): the response has a body.
    Successful,
    /// malformedRequest (1).
    MalformedRequest,
    /// internalError (2).
    InternalError,
    /// tryLater (3).
    TryLater,
    /// sigRequired (5).
    SigRequired,
    /// unauthorized (6).
    Unauthorized,
}

impl OcspResponseStatus {
    fn from_code(c: u8) -> Result<OcspResponseStatus, Error> {
        use OcspResponseStatus as S;
        Ok(match c {
            0 => S::Successful,
            1 => S::MalformedRequest,
            2 => S::InternalError,
            3 => S::TryLater,
            5 => S::SigRequired,
            6 => S::Unauthorized,
            _ => return Err(Error::Encoding),
        })
    }
}

impl std::fmt::Display for OcspResponseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use OcspResponseStatus as S;
        f.write_str(match self {
            S::Successful => "successful",
            S::MalformedRequest => "malformedRequest",
            S::InternalError => "internalError",
            S::TryLater => "tryLater",
            S::SigRequired => "sigRequired",
            S::Unauthorized => "unauthorized",
        })
    }
}

/// The hash of a [`CertId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CertIdHash {
    /// SHA-1 (what responders and stapling servers use by default).
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl CertIdHash {
    fn from_oid(o: &[u8]) -> Option<CertIdHash> {
        Some(match o {
            oid::SHA1 => CertIdHash::Sha1,
            oid::SHA256 => CertIdHash::Sha256,
            oid::SHA384 => CertIdHash::Sha384,
            oid::SHA512 => CertIdHash::Sha512,
            _ => return None,
        })
    }

    fn oid(self) -> &'static [u8] {
        match self {
            CertIdHash::Sha1 => oid::SHA1,
            CertIdHash::Sha256 => oid::SHA256,
            CertIdHash::Sha384 => oid::SHA384,
            CertIdHash::Sha512 => oid::SHA512,
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            CertIdHash::Sha1 => Sha1::digest(data).to_vec(),
            CertIdHash::Sha256 => Sha256::digest(data).to_vec(),
            CertIdHash::Sha384 => Sha384::digest(data).to_vec(),
            CertIdHash::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// A `CertID` (RFC 6960 §4.1.1): which certificate a request or single response is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertId {
    /// The hash algorithm (`None`: one this crate does not support; such a CertID matches
    /// nothing).
    pub hash: Option<CertIdHash>,
    /// The hash of the issuer's name (DER).
    pub issuer_name_hash: Vec<u8>,
    /// The hash of the issuer's public key (the subjectPublicKey BIT STRING value).
    pub issuer_key_hash: Vec<u8>,
    /// The serial number's INTEGER contents.
    pub serial: Vec<u8>,
}

/// The subjectPublicKey bits of a certificate.
fn key_bits(c: &Certificate) -> Result<Vec<u8>, Error> {
    let mut r = Reader::new(c.spki_der());
    let mut s = r.sequence()?;
    let _ = s.read_element(tag::SEQUENCE)?;
    Ok(s.read_bit_string()?.to_vec())
}

impl CertId {
    /// The CertID of `cert`, issued by `issuer`.
    pub fn new(
        cert: &Certificate,
        issuer: &Certificate,
        hash: CertIdHash,
    ) -> Result<CertId, Error> {
        Ok(CertId {
            hash: Some(hash),
            issuer_name_hash: hash.digest(issuer.subject().as_der()),
            issuer_key_hash: hash.digest(&key_bits(issuer)?),
            serial: cert.serial().to_vec(),
        })
    }

    /// Whether this CertID names `cert`, issued by `issuer`.
    #[must_use]
    pub fn matches(&self, cert: &Certificate, issuer: &Certificate) -> bool {
        let Some(h) = self.hash else {
            return false;
        };
        self.serial == cert.serial()
            && cert.issuer().as_der() == issuer.subject().as_der()
            && self.issuer_name_hash == h.digest(issuer.subject().as_der())
            && key_bits(issuer).is_ok_and(|k| self.issuer_key_hash == h.digest(&k))
    }

    fn read(r: &mut Reader<'_>) -> Result<CertId, Error> {
        let mut s = r.sequence()?;
        let mut alg = s.sequence()?;
        let hash = CertIdHash::from_oid(alg.read_oid()?);
        if !alg.is_empty() {
            alg.read_null()?;
        }
        alg.finish()?;
        let issuer_name_hash = s.read_octet_string()?.to_vec();
        let issuer_key_hash = s.read_octet_string()?.to_vec();
        let serial = s.read_integer()?;
        if serial.len() > 21 {
            return Err(Error::Encoding);
        }
        s.finish()?;
        Ok(CertId {
            hash,
            issuer_name_hash,
            issuer_key_hash,
            serial: serial.to_vec(),
        })
    }

    fn write(&self, w: &mut Writer) {
        w.sequence(|w| {
            w.sequence(|w| {
                w.oid(self.hash.unwrap_or(CertIdHash::Sha1).oid());
                w.null();
            });
            w.octet_string(&self.issuer_name_hash);
            w.octet_string(&self.issuer_key_hash);
            w.tlv(tag::INTEGER, &self.serial);
        });
    }
}

/// `ResponderID` (RFC 6960 §4.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponderId {
    /// byName: the responder certificate's subject.
    ByName(Name),
    /// byKey: SHA-1 of the responder's subjectPublicKey bits.
    ByKey(Vec<u8>),
}

impl ResponderId {
    fn matches(&self, c: &Certificate) -> bool {
        match self {
            ResponderId::ByName(n) => n.as_der() == c.subject().as_der(),
            ResponderId::ByKey(h) => key_bits(c).is_ok_and(|k| Sha1::digest(&k)[..] == h[..]),
        }
    }
}

/// One `SingleResponse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleResponse {
    /// The certificate it is about.
    pub cert_id: CertId,
    /// good, revoked (with time and reason) or unknown.
    pub status: RevocationStatus,
    /// thisUpdate, Unix seconds.
    pub this_update: i64,
    /// nextUpdate, Unix seconds, if present.
    pub next_update: Option<i64>,
    /// The OID of the first critical singleExtension this crate does not process.
    pub unsupported_critical: Option<Vec<u8>>,
}

/// A `BasicOCSPResponse`.
#[derive(Debug, Clone)]
pub struct BasicOcspResponse {
    tbs: Vec<u8>,
    responder_id: ResponderId,
    produced_at: i64,
    responses: Vec<SingleResponse>,
    extensions: Vec<Extension>,
    nonce: Option<Vec<u8>>,
    unsupported_critical: Option<Vec<u8>>,
    signature_algorithm: Result<SignatureAlgorithm, only_crypto::Error>,
    signature: Vec<u8>,
    certs: Vec<Certificate>,
}

impl BasicOcspResponse {
    fn parse(der: &[u8]) -> Result<BasicOcspResponse, Error> {
        let mut r = Reader::new(der);
        let mut b = r.sequence()?;
        r.finish()?;
        let tbs = b.read_element(tag::SEQUENCE)?;
        let sig_alg = b.read_element(tag::SEQUENCE)?;
        let signature = b.read_bit_string()?.to_vec();
        let mut certs = Vec::new();
        if let Some(c) = b.read_optional(tag::explicit(0))? {
            let mut cr = Reader::new(c);
            let mut seq = cr.sequence()?;
            cr.finish()?;
            while !seq.is_empty() {
                certs.push(Certificate::from_der(seq.read_element(tag::SEQUENCE)?)?);
            }
        }
        b.finish()?;

        let mut t = Reader::new(tbs).sequence()?;
        if let Some(v) = t.read_optional(tag::explicit(0))? {
            let mut vr = Reader::new(v);
            let _ = vr.read_small_uint()?;
            vr.finish()?;
            return Err(Error::UnsupportedVersion); // only v1, which DER omits
        }
        let (rt, rc, _) = t.read_tlv()?;
        let responder_id = match rt {
            0xa1 => {
                let mut nr = Reader::new(rc);
                let n = Name::from_der(nr.read_element(tag::SEQUENCE)?)?;
                nr.finish()?;
                ResponderId::ByName(n)
            }
            0xa2 => {
                let mut kr = Reader::new(rc);
                let k = kr.read_octet_string()?.to_vec();
                kr.finish()?;
                if k.len() != 20 {
                    return Err(Error::Encoding);
                }
                ResponderId::ByKey(k)
            }
            _ => return Err(Error::Encoding),
        };
        let produced_at = read_generalized_time(&mut t)?;
        let mut responses = Vec::new();
        let mut list = t.sequence()?;
        while !list.is_empty() {
            responses.push(read_single(&mut list)?);
        }
        let mut extensions = Vec::new();
        if let Some(e) = t.read_optional(tag::explicit(1))? {
            extensions = read_extensions(e)?;
        }
        t.finish()?;
        let mut nonce = None;
        let mut unsupported_critical = None;
        for x in &extensions {
            if x.oid == OCSP_NONCE {
                // RFC 8954: an OCTET STRING inside extnValue; older responders put the raw
                // nonce there.
                let mut nr = Reader::new(&x.value);
                nonce = Some(match nr.read_octet_string() {
                    Ok(n) if nr.is_empty() => n.to_vec(),
                    _ => x.value.clone(),
                });
            } else if x.critical && unsupported_critical.is_none() {
                unsupported_critical = Some(x.oid.clone());
            }
        }
        Ok(BasicOcspResponse {
            tbs: tbs.to_vec(),
            responder_id,
            produced_at,
            responses,
            extensions,
            nonce,
            unsupported_critical,
            signature_algorithm: SignatureAlgorithm::from_algorithm_identifier(sig_alg),
            signature,
            certs,
        })
    }

    /// The DER `ResponseData` (the signed part).
    #[must_use]
    pub fn tbs_der(&self) -> &[u8] {
        &self.tbs
    }

    /// responderID.
    #[must_use]
    pub fn responder_id(&self) -> &ResponderId {
        &self.responder_id
    }

    /// producedAt, Unix seconds.
    #[must_use]
    pub fn produced_at(&self) -> i64 {
        self.produced_at
    }

    /// The single responses.
    #[must_use]
    pub fn responses(&self) -> &[SingleResponse] {
        &self.responses
    }

    /// responseExtensions.
    #[must_use]
    pub fn extensions(&self) -> &[Extension] {
        &self.extensions
    }

    /// The nonce extension's value, if present.
    #[must_use]
    pub fn nonce(&self) -> Option<&[u8]> {
        self.nonce.as_deref()
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

    /// The certificates included to help verify the signature (a delegated responder's).
    #[must_use]
    pub fn certs(&self) -> &[Certificate] {
        &self.certs
    }

    /// The key that may sign for `issuer` (RFC 6960 §4.2.2.2): the issuer itself, or an
    /// included certificate matching responderID that `issuer` signed, with id-kp-OCSPSigning,
    /// digitalSignature (if keyUsage is present), valid at `now` ± `skew`.
    fn signer_key(&self, issuer: &Certificate, now: i64, skew: i64) -> Result<PublicKey, Error> {
        if self.responder_id.matches(issuer) {
            return issuer.public_key();
        }
        let mut err = Error::UnauthorizedResponder;
        for c in self.certs.iter().filter(|c| self.responder_id.matches(c)) {
            let ok = c.issuer().as_der() == issuer.subject().as_der()
                && c.ext_key_usage()
                    .is_some_and(|e| e.iter().any(|o| o == ext::OCSP_SIGNING))
                && c.key_usage()
                    .is_none_or(|k| k.contains(KeyUsage::DIGITAL_SIGNATURE))
                && c.unsupported_critical_extension().is_none()
                && c.not_before() <= now.saturating_add(skew)
                && now.saturating_sub(skew) <= c.not_after();
            if !ok {
                continue;
            }
            match issuer.public_key().and_then(|k| c.verify_signed_by(&k)) {
                Ok(()) => return c.public_key(),
                Err(e) => err = e,
            }
        }
        Err(match err {
            Error::BadSignature => Error::UnauthorizedResponder,
            e => e,
        })
    }
}

fn read_single(r: &mut Reader<'_>) -> Result<SingleResponse, Error> {
    let mut s = r.sequence()?;
    let cert_id = CertId::read(&mut s)?;
    let (st, sc, _) = s.read_tlv()?;
    let status = match st {
        0x80 if sc.is_empty() => RevocationStatus::Good,
        0x82 if sc.is_empty() => RevocationStatus::Unknown,
        0xa1 => {
            let mut ri = Reader::new(sc);
            let time = read_generalized_time(&mut ri)?;
            let reason = match ri.read_optional(tag::explicit(0))? {
                Some(c) => {
                    let mut rr = Reader::new(c);
                    let code = rr.read(ENUMERATED)?;
                    rr.finish()?;
                    let [code] = code else {
                        return Err(Error::Encoding);
                    };
                    Some(RevocationReason::from_code(u64::from(*code))?)
                }
                None => None,
            };
            ri.finish()?;
            RevocationStatus::Revoked { time, reason }
        }
        _ => return Err(Error::Encoding),
    };
    let this_update = read_generalized_time(&mut s)?;
    let next_update = match s.read_optional(tag::explicit(0))? {
        Some(c) => {
            let mut nr = Reader::new(c);
            let t = read_generalized_time(&mut nr)?;
            nr.finish()?;
            Some(t)
        }
        None => None,
    };
    let mut unsupported_critical = None;
    if let Some(e) = s.read_optional(tag::explicit(1))? {
        // Known single extensions (CRL references, archive cutoff) carry nothing we act on.
        unsupported_critical = read_extensions(e)?
            .into_iter()
            .find(|x| x.critical)
            .map(|x| x.oid);
    }
    s.finish()?;
    Ok(SingleResponse {
        cert_id,
        status,
        this_update,
        next_update,
        unsupported_critical,
    })
}

/// How [`OcspResponse::verify`] checks a response.
#[derive(Debug, Clone)]
pub struct OcspValidation {
    time: Option<i64>,
    skew: u32,
    nonce: Option<Vec<u8>>,
    max_age: u32,
}

impl Default for OcspValidation {
    fn default() -> Self {
        OcspValidation::new()
    }
}

impl OcspValidation {
    /// Now, [`DEFAULT_CLOCK_SKEW`], no nonce, and a day as the lifetime of a response
    /// without nextUpdate.
    #[must_use]
    pub fn new() -> OcspValidation {
        OcspValidation {
            time: None,
            skew: DEFAULT_CLOCK_SKEW,
            nonce: None,
            max_age: 86_400,
        }
    }

    /// Validates at `unix_seconds` instead of now.
    #[must_use]
    pub fn at_time(mut self, unix_seconds: i64) -> Self {
        self.time = Some(unix_seconds);
        self
    }

    /// The tolerated clock skew in seconds.
    #[must_use]
    pub fn clock_skew(mut self, secs: u32) -> Self {
        self.skew = secs;
        self
    }

    /// Requires the response to echo this nonce (the one sent in the request).
    #[must_use]
    pub fn nonce(mut self, nonce: impl Into<Vec<u8>>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// How long after thisUpdate a single response without nextUpdate stays usable.
    #[must_use]
    pub fn max_age(mut self, secs: u32) -> Self {
        self.max_age = secs;
        self
    }
}

/// A parsed `OCSPResponse`.
#[derive(Debug, Clone)]
pub struct OcspResponse {
    der: Vec<u8>,
    status: OcspResponseStatus,
    basic: Option<BasicOcspResponse>,
}

impl PartialEq for OcspResponse {
    fn eq(&self, o: &Self) -> bool {
        self.der == o.der
    }
}
impl Eq for OcspResponse {}

impl OcspResponse {
    /// Parses a DER response: a successful one must carry a `BasicOCSPResponse`, others none.
    pub fn from_der(der: impl Into<Vec<u8>>) -> Result<OcspResponse, Error> {
        let der = der.into();
        let mut r = Reader::new(&der);
        let mut s = r.sequence()?;
        r.finish()?;
        let code = s.read(ENUMERATED)?;
        let [code] = code else {
            return Err(Error::Encoding);
        };
        let status = OcspResponseStatus::from_code(*code)?;
        let basic = match s.read_optional(tag::explicit(0))? {
            Some(c) => {
                let mut br = Reader::new(c);
                let mut rb = br.sequence()?;
                br.finish()?;
                let typ = rb.read_oid()?;
                let body = rb.read_octet_string()?;
                rb.finish()?;
                if typ != OCSP_BASIC {
                    return Err(Error::Encoding);
                }
                Some(BasicOcspResponse::parse(body)?)
            }
            None => None,
        };
        s.finish()?;
        if (status == OcspResponseStatus::Successful) != basic.is_some() {
            return Err(Error::Encoding);
        }
        Ok(OcspResponse { der, status, basic })
    }

    /// The DER encoding.
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// responseStatus.
    #[must_use]
    pub fn status(&self) -> OcspResponseStatus {
        self.status
    }

    /// The body of a successful response.
    #[must_use]
    pub fn basic(&self) -> Option<&BasicOcspResponse> {
        self.basic.as_ref()
    }

    /// Validates the response for `cert`, issued by `issuer` (both from a verified path), and
    /// returns its status (RFC 6960 §3.2): a successful response signed by `issuer` or by a
    /// delegated responder it certified (id-kp-OCSPSigning), with no unsupported critical
    /// extension, echoing the expected nonce if one is set, and a current single response for
    /// `cert` (thisUpdate not after now + skew; nextUpdate, or thisUpdate + max age, not
    /// before now − skew). Errors mean the response cannot be trusted; `Ok(Unknown)` is the
    /// responder's own answer.
    pub fn verify(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
        v: &OcspValidation,
    ) -> Result<RevocationStatus, Error> {
        let Some(b) = &self.basic else {
            return Err(Error::OcspStatus(self.status));
        };
        let now = v.time.unwrap_or_else(crate::time::now);
        let skew = i64::from(v.skew);
        let key = b.signer_key(issuer, now, skew)?;
        key.verify(b.signature_algorithm()?, &b.tbs, &b.signature)
            .map_err(|e| match e {
                only_crypto::Error::Verification => Error::BadSignature,
                e => Error::Crypto(e),
            })?;
        if let Some(o) = &b.unsupported_critical {
            return Err(Error::UnsupportedCriticalExtension(o.clone()));
        }
        if let Some(want) = &v.nonce {
            if !b
                .nonce
                .as_deref()
                .is_some_and(|got| only_crypto::ct_eq(got, want))
            {
                return Err(Error::NonceMismatch);
            }
        }
        let single = b
            .responses
            .iter()
            .find(|s| s.cert_id.matches(cert, issuer))
            .ok_or(Error::NoMatchingResponse)?;
        if let Some(o) = &single.unsupported_critical {
            return Err(Error::UnsupportedCriticalExtension(o.clone()));
        }
        let next = single
            .next_update
            .unwrap_or_else(|| single.this_update.saturating_add(i64::from(v.max_age)));
        if single.this_update > now.saturating_add(skew) {
            return Err(Error::RevocationInfoNotYetValid);
        }
        if !is_current(single.this_update, next, now, skew) {
            return Err(Error::RevocationInfoExpired);
        }
        Ok(single.status)
    }
}

/// An `OCSPRequest` for one or more certificates, unsigned, optionally with a nonce.
#[derive(Debug, Clone, Default)]
pub struct OcspRequest {
    ids: Vec<CertId>,
    nonce: Option<Vec<u8>>,
}

impl OcspRequest {
    /// A request about `cert`, issued by `issuer`, with a SHA-1 CertID (what responders
    /// universally accept).
    pub fn new(cert: &Certificate, issuer: &Certificate) -> Result<OcspRequest, Error> {
        Ok(OcspRequest {
            ids: vec![CertId::new(cert, issuer, CertIdHash::Sha1)?],
            nonce: None,
        })
    }

    /// Also asks about the certificate `id` names.
    #[must_use]
    pub fn with_cert_id(mut self, id: CertId) -> Self {
        self.ids.push(id);
        self
    }

    /// Adds a nonce extension (RFC 8954: 1 to 32 bytes; check it with
    /// [`OcspValidation::nonce`]).
    #[must_use]
    pub fn nonce(mut self, nonce: impl Into<Vec<u8>>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// The CertIDs.
    #[must_use]
    pub fn cert_ids(&self) -> &[CertId] {
        &self.ids
    }

    /// The DER encoding (`application/ocsp-request`).
    #[must_use]
    pub fn to_der(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.sequence(|w| {
            w.sequence(|w| {
                w.sequence(|w| {
                    for id in &self.ids {
                        w.sequence(|w| id.write(w));
                    }
                });
                if let Some(n) = &self.nonce {
                    w.nested(tag::explicit(2), |w| {
                        w.sequence(|w| nonce_ext(w, n));
                    });
                }
            });
        });
        w.into_vec()
    }
}

fn nonce_ext(w: &mut Writer, n: &[u8]) {
    w.sequence(|w| {
        w.oid(OCSP_NONCE);
        let mut v = Writer::new();
        v.octet_string(n);
        w.octet_string(v.as_bytes());
    });
}

/// What to put in an OCSP response made by [`OcspResponseParams::sign`] (tests, development
/// responders and stapling servers that sign their own responses).
#[derive(Debug, Clone)]
pub struct OcspResponseParams {
    /// The status to report.
    pub status: RevocationStatus,
    /// producedAt and thisUpdate, Unix seconds.
    pub this_update: i64,
    /// nextUpdate, Unix seconds.
    pub next_update: Option<i64>,
    /// A nonce to echo.
    pub nonce: Option<Vec<u8>>,
    /// responderID byKey instead of byName.
    pub responder_by_key: bool,
    /// Include the signer's certificate (needed for a delegated responder).
    pub include_signer: bool,
    /// The CertID hash.
    pub hash: CertIdHash,
}

impl OcspResponseParams {
    /// A response with `status`, produced one minute ago and valid for a day.
    #[must_use]
    pub fn new(status: RevocationStatus) -> OcspResponseParams {
        let now = crate::time::now();
        OcspResponseParams {
            status,
            this_update: now - 60,
            next_update: Some(now + 86_400),
            nonce: None,
            responder_by_key: false,
            include_signer: false,
            hash: CertIdHash::Sha1,
        }
    }

    /// A successful response about `cert` (issued by `issuer`), signed with `signer_key` by
    /// `signer` (the issuer, or a delegated responder certificate).
    pub fn sign(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
        signer: &Certificate,
        signer_key: &PrivateKey,
    ) -> Result<Vec<u8>, Error> {
        let id = CertId::new(cert, issuer, self.hash)?;
        let alg = signer_key.default_signature_algorithm();
        let alg_id = alg.to_algorithm_identifier();
        let mut w = Writer::new();
        let key_hash = Sha1::digest(&key_bits(signer)?);
        w.sequence(|w| {
            if self.responder_by_key {
                w.nested(tag::explicit(2), |w| w.octet_string(&key_hash));
            } else {
                w.nested(tag::explicit(1), |w| w.raw(signer.subject().as_der()));
            }
            write_generalized_time(w, self.this_update);
            w.sequence(|w| {
                w.sequence(|w| {
                    id.write(w);
                    match self.status {
                        RevocationStatus::Good => w.tlv(0x80, &[]),
                        RevocationStatus::Unknown => w.tlv(0x82, &[]),
                        RevocationStatus::Revoked { time, reason } => {
                            w.nested(0xa1, |w| {
                                write_generalized_time(w, time);
                                if let Some(r) = reason {
                                    w.nested(tag::explicit(0), |w| w.tlv(ENUMERATED, &[r.code()]));
                                }
                            });
                        }
                    }
                    write_generalized_time(w, self.this_update);
                    if let Some(n) = self.next_update {
                        w.nested(tag::explicit(0), |w| write_generalized_time(w, n));
                    }
                });
            });
            if let Some(n) = &self.nonce {
                w.nested(tag::explicit(1), |w| w.sequence(|w| nonce_ext(w, n)));
            }
        });
        let tbs = w.into_vec();
        let sig = signer_key.sign(alg, &tbs).map_err(Error::Crypto)?;
        let mut b = Writer::new();
        b.sequence(|w| {
            w.raw(&tbs);
            w.raw(&alg_id);
            w.bit_string(&sig);
            if self.include_signer {
                w.nested(tag::explicit(0), |w| w.sequence(|w| w.raw(signer.as_der())));
            }
        });
        let basic = b.into_vec();
        let mut o = Writer::new();
        o.sequence(|w| {
            w.tlv(ENUMERATED, &[0]);
            w.nested(tag::explicit(0), |w| {
                w.sequence(|w| {
                    w.oid(OCSP_BASIC);
                    w.octet_string(&basic);
                });
            });
        });
        Ok(o.into_vec())
    }
}
