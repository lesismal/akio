//! Certificate revocation lists (RFC 5280 §5): strict DER parsing, signature checks against
//! the issuing CA, and status lookups over a caller-supplied [`CrlSet`] (complete CRLs, delta
//! CRLs, issuingDistributionPoint scopes). Fetching CRLs is up to the application.

use std::cmp::Ordering;
use std::sync::OnceLock;

use only_crypto::der::{Reader, Writer, tag};
use only_crypto::pkey::{PrivateKey, SignatureAlgorithm};

use crate::Error;
use crate::cert::{
    Certificate, Extension, KeyUsage, ext, read_dp_name, read_extension_list, read_extensions,
};
use crate::name::{GeneralName, Name};
use crate::revocation::{ReasonFlags, RevocationReason, RevocationStatus, is_current, uint_cmp};
use crate::time::{read_generalized_time, read_time, write_generalized_time, write_time};

/// One revokedCertificates entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedCertificate {
    /// userCertificate: the serial number's INTEGER contents.
    pub serial: Vec<u8>,
    /// revocationDate, Unix seconds.
    pub revocation_date: i64,
    /// reasonCode, if present.
    pub reason: Option<RevocationReason>,
    /// invalidityDate, Unix seconds, if present.
    pub invalidity_date: Option<i64>,
}

/// issuingDistributionPoint (RFC 5280 §5.2.5): the scope of a CRL.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IssuingDistributionPoint {
    /// distributionPoint as fullName (empty when absent or nameRelativeToCRLIssuer).
    pub full_name: Vec<GeneralName>,
    /// onlyContainsUserCerts: covers end-entity certificates only.
    pub only_user_certs: bool,
    /// onlyContainsCACerts: covers CA certificates only.
    pub only_ca_certs: bool,
    /// onlySomeReasons: covers only these reasons.
    pub only_some_reasons: Option<ReasonFlags>,
    /// indirectCRL: entries may belong to other issuers (not supported for lookups: such a
    /// CRL is never used).
    pub indirect_crl: bool,
    /// onlyContainsAttributeCerts: covers attribute certificates only (never used here).
    pub only_attribute_certs: bool,
}

/// A parsed CRL (`CertificateList`). Parsing checks the structure and the extensions RFC 5280
/// defines; an unknown critical CRL or entry extension (indirect CRLs' certificateIssuer
/// included) is recorded, and such a CRL is never used for status lookups.
#[derive(Debug, Clone)]
pub struct Crl {
    der: Vec<u8>,
    tbs: (usize, usize),
    version: u8,
    signature_algorithm: Result<SignatureAlgorithm, only_crypto::Error>,
    issuer: Name,
    this_update: i64,
    next_update: Option<i64>,
    revoked: Vec<RevokedCertificate>,
    extensions: Vec<Extension>,
    crl_number: Option<Vec<u8>>,
    delta_base: Option<Vec<u8>>,
    idp: Option<IssuingDistributionPoint>,
    authority_key_id: Option<Vec<u8>>,
    unsupported_critical: Option<Vec<u8>>,
    signature: Vec<u8>,
    /// The SPKI of the issuer key that verified the signature, once one has.
    verified: OnceLock<Vec<u8>>,
}

impl PartialEq for Crl {
    fn eq(&self, o: &Self) -> bool {
        self.der == o.der
    }
}
impl Eq for Crl {}

fn range(outer: &[u8], inner: &[u8]) -> (usize, usize) {
    let start = inner.as_ptr() as usize - outer.as_ptr() as usize;
    (start, start + inner.len())
}

fn read_time_opt(r: &mut Reader<'_>) -> Result<Option<i64>, Error> {
    match r.peek_tag() {
        Some(tag::UTC_TIME | tag::GENERALIZED_TIME) => Ok(Some(read_time(r)?)),
        _ => Ok(None),
    }
}

/// A non-negative INTEGER (CRL numbers: at most 20 octets, RFC 5280 §5.2.3).
fn read_crl_number(v: &[u8]) -> Result<Vec<u8>, Error> {
    let mut r = Reader::new(v);
    let n = r.read_uint()?;
    r.finish()?;
    if n.len() > 21 {
        return Err(Error::Encoding);
    }
    Ok(n.to_vec())
}

fn read_implicit_bool(c: &[u8]) -> Result<bool, Error> {
    // DEFAULT FALSE: only TRUE (0xff) may be encoded.
    if c == [0xff] {
        Ok(true)
    } else {
        Err(Error::Encoding)
    }
}

fn read_idp(v: &[u8]) -> Result<IssuingDistributionPoint, Error> {
    let mut r = Reader::new(v);
    let mut s = r.sequence()?;
    r.finish()?;
    let mut idp = IssuingDistributionPoint::default();
    if let Some(c) = s.read_optional(tag::explicit(0))? {
        idp.full_name = read_dp_name(c)?;
    }
    if let Some(c) = s.read_optional(tag::implicit(1))? {
        idp.only_user_certs = read_implicit_bool(c)?;
    }
    if let Some(c) = s.read_optional(tag::implicit(2))? {
        idp.only_ca_certs = read_implicit_bool(c)?;
    }
    if let Some(c) = s.read_optional(tag::implicit(3))? {
        idp.only_some_reasons = Some(ReasonFlags::from_bit_string(c)?);
    }
    if let Some(c) = s.read_optional(tag::implicit(4))? {
        idp.indirect_crl = read_implicit_bool(c)?;
    }
    if let Some(c) = s.read_optional(tag::implicit(5))? {
        idp.only_attribute_certs = read_implicit_bool(c)?;
    }
    s.finish()?;
    // At most one of the "only" flags (RFC 5280 §5.2.5).
    if u8::from(idp.only_user_certs)
        + u8::from(idp.only_ca_certs)
        + u8::from(idp.only_attribute_certs)
        > 1
    {
        return Err(Error::Encoding);
    }
    Ok(idp)
}

impl Crl {
    /// Parses a DER CRL.
    pub fn from_der(der: impl Into<Vec<u8>>) -> Result<Crl, Error> {
        let der = der.into();
        let mut r = Reader::new(&der);
        let mut cl = r.sequence()?;
        r.finish()?;
        let tbs = cl.read_element(tag::SEQUENCE)?;
        let sig_alg = cl.read_element(tag::SEQUENCE)?;
        let signature = cl.read_bit_string()?.to_vec();
        cl.finish()?;

        let mut t = Reader::new(tbs).sequence()?;
        let version = if t.peek_tag() == Some(tag::INTEGER) {
            match t.read_small_uint()? {
                1 => 2,
                _ => return Err(Error::UnsupportedVersion), // v1 must be omitted
            }
        } else {
            1
        };
        if t.read_element(tag::SEQUENCE)? != sig_alg {
            return Err(Error::SignatureAlgorithmMismatch);
        }
        let issuer = Name::from_der(t.read_element(tag::SEQUENCE)?)?;
        let this_update = read_time(&mut t)?;
        let next_update = read_time_opt(&mut t)?;
        let mut unsupported_critical = None;
        let mut revoked = Vec::new();
        if t.peek_tag() == Some(tag::SEQUENCE) {
            let mut list = t.sequence()?;
            while !list.is_empty() {
                let mut e = list.sequence()?;
                let serial = e.read_integer()?;
                if serial.len() > 21 {
                    return Err(Error::Encoding);
                }
                let mut entry = RevokedCertificate {
                    serial: serial.to_vec(),
                    revocation_date: read_time(&mut e)?,
                    reason: None,
                    invalidity_date: None,
                };
                if !e.is_empty() {
                    if version < 2 {
                        return Err(Error::Encoding);
                    }
                    let mut exts = e.sequence()?;
                    for x in read_extension_list(&mut exts)? {
                        let mut v = Reader::new(&x.value);
                        match &x.oid[..] {
                            ext::REASON_CODE => {
                                let c = v.read(0x0a)?; // ENUMERATED
                                v.finish()?;
                                let [code] = c else {
                                    return Err(Error::Encoding);
                                };
                                entry.reason = Some(RevocationReason::from_code(u64::from(*code))?);
                            }
                            ext::INVALIDITY_DATE => {
                                entry.invalidity_date = Some(read_generalized_time(&mut v)?);
                                v.finish()?;
                            }
                            ext::HOLD_INSTRUCTION_CODE => {}
                            _ => {
                                if x.critical && unsupported_critical.is_none() {
                                    unsupported_critical = Some(x.oid.clone());
                                }
                            }
                        }
                    }
                    e.finish()?;
                }
                revoked.push(entry);
            }
        }
        let mut crl = Crl {
            tbs: range(&der, tbs),
            version,
            signature_algorithm: SignatureAlgorithm::from_algorithm_identifier(sig_alg),
            issuer,
            this_update,
            next_update,
            revoked,
            extensions: Vec::new(),
            crl_number: None,
            delta_base: None,
            idp: None,
            authority_key_id: None,
            unsupported_critical,
            signature,
            verified: OnceLock::new(),
            der: Vec::new(),
        };
        if let Some(exts) = t.read_optional(tag::explicit(0))? {
            if version < 2 {
                return Err(Error::Encoding);
            }
            crl.extensions = read_extensions(exts)?;
        }
        t.finish()?;
        for x in &crl.extensions {
            match &x.oid[..] {
                ext::CRL_NUMBER => crl.crl_number = Some(read_crl_number(&x.value)?),
                ext::DELTA_CRL_INDICATOR => crl.delta_base = Some(read_crl_number(&x.value)?),
                ext::ISSUING_DISTRIBUTION_POINT => crl.idp = Some(read_idp(&x.value)?),
                ext::AUTHORITY_KEY_ID => {
                    let mut r = Reader::new(&x.value);
                    let mut s = r.sequence()?;
                    crl.authority_key_id = s.read_optional(tag::implicit(0))?.map(<[u8]>::to_vec);
                }
                ext::ISSUER_ALT_NAME | ext::FRESHEST_CRL | ext::AUTHORITY_INFO_ACCESS => {}
                _ => {
                    if x.critical && crl.unsupported_critical.is_none() {
                        crl.unsupported_critical = Some(x.oid.clone());
                    }
                }
            }
        }
        // Sorted by serial for lookups (a stable sort keeps duplicate entries in order).
        crl.revoked.sort_by(|a, b| uint_cmp(&a.serial, &b.serial));
        crl.der = der;
        Ok(crl)
    }

    /// Every `X509 CRL` block of a PEM text.
    pub fn from_pem(text: &[u8]) -> Result<Vec<Crl>, Error> {
        only_crypto::pem::decode_label(text, "X509 CRL")?
            .into_iter()
            .map(Crl::from_der)
            .collect()
    }

    /// The DER encoding.
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// The PEM encoding (`X509 CRL`).
    #[must_use]
    pub fn to_pem(&self) -> String {
        only_crypto::pem::encode("X509 CRL", &self.der)
    }

    /// The DER `TBSCertList` (the signed part).
    #[must_use]
    pub fn tbs_der(&self) -> &[u8] {
        &self.der[self.tbs.0..self.tbs.1]
    }

    /// The version: 1 or 2.
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// The signature algorithm (an error for unsupported algorithms).
    pub fn signature_algorithm(&self) -> Result<SignatureAlgorithm, Error> {
        self.signature_algorithm.map_err(Error::Crypto)
    }

    /// The issuer name.
    #[must_use]
    pub fn issuer(&self) -> &Name {
        &self.issuer
    }

    /// thisUpdate, Unix seconds.
    #[must_use]
    pub fn this_update(&self) -> i64 {
        self.this_update
    }

    /// nextUpdate, Unix seconds, if present (a CRL without one is never current).
    #[must_use]
    pub fn next_update(&self) -> Option<i64> {
        self.next_update
    }

    /// The revoked certificates, sorted by serial number.
    #[must_use]
    pub fn revoked(&self) -> &[RevokedCertificate] {
        &self.revoked
    }

    /// The entry for `serial` (INTEGER contents, as [`Certificate::serial`]), if listed.
    #[must_use]
    pub fn find(&self, serial: &[u8]) -> Option<&RevokedCertificate> {
        self.revoked
            .binary_search_by(|e| uint_cmp(&e.serial, serial))
            .ok()
            .map(|i| &self.revoked[i])
    }

    /// All CRL extensions, in order.
    #[must_use]
    pub fn extensions(&self) -> &[Extension] {
        &self.extensions
    }

    /// cRLNumber (INTEGER contents), if present.
    #[must_use]
    pub fn crl_number(&self) -> Option<&[u8]> {
        self.crl_number.as_deref()
    }

    /// For a delta CRL, the BaseCRLNumber of its deltaCRLIndicator.
    #[must_use]
    pub fn delta_base(&self) -> Option<&[u8]> {
        self.delta_base.as_deref()
    }

    /// Whether this is a delta CRL.
    #[must_use]
    pub fn is_delta(&self) -> bool {
        self.delta_base.is_some()
    }

    /// issuingDistributionPoint, if present.
    #[must_use]
    pub fn issuing_distribution_point(&self) -> Option<&IssuingDistributionPoint> {
        self.idp.as_ref()
    }

    /// The keyIdentifier of authorityKeyIdentifier, if present.
    #[must_use]
    pub fn authority_key_id(&self) -> Option<&[u8]> {
        self.authority_key_id.as_deref()
    }

    /// The OID of the first critical CRL or entry extension this crate does not process.
    #[must_use]
    pub fn unsupported_critical_extension(&self) -> Option<&[u8]> {
        self.unsupported_critical.as_deref()
    }

    /// The signature value.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Whether the CRL is current at `now` (Unix seconds), give or take `skew` seconds:
    /// thisUpdate not in the future and nextUpdate (required) not in the past.
    #[must_use]
    pub fn is_current(&self, now: i64, skew: u32) -> bool {
        self.next_update
            .is_some_and(|n| is_current(self.this_update, n, now, i64::from(skew)))
    }

    /// Whether `issuer` issued this CRL: its subject is the CRL issuer, its keyUsage (if
    /// any) has cRLSign, and its key verifies the signature. A success is remembered, so
    /// checking a large CRL again against the same issuer costs no signature verification.
    pub fn verify_signed_by(&self, issuer: &Certificate) -> Result<(), Error> {
        if issuer.subject().as_der() != self.issuer.as_der() {
            return Err(Error::UnknownIssuer);
        }
        if issuer
            .key_usage()
            .is_some_and(|ku| !ku.contains(KeyUsage::CRL_SIGN))
        {
            return Err(Error::KeyUsage);
        }
        if self.verified.get().is_some_and(|s| s == issuer.spki_der()) {
            return Ok(());
        }
        let alg = self.signature_algorithm()?;
        issuer
            .public_key()?
            .verify(alg, self.tbs_der(), &self.signature)
            .map_err(|e| match e {
                only_crypto::Error::Verification => Error::BadSignature,
                e => Error::Crypto(e),
            })?;
        let _ = self.verified.set(issuer.spki_der().to_vec());
        Ok(())
    }

    /// Whether this CRL may answer for `cert`: usable (no unsupported critical extension,
    /// not indirect, not attribute-only) and in scope (the issuingDistributionPoint's user/CA
    /// restriction and distribution point name).
    fn covers(&self, cert: &Certificate) -> bool {
        if self.unsupported_critical.is_some() {
            return false;
        }
        let Some(idp) = &self.idp else {
            return true;
        };
        if idp.indirect_crl || idp.only_attribute_certs {
            return false;
        }
        if (idp.only_user_certs && cert.is_ca()) || (idp.only_ca_certs && !cert.is_ca()) {
            return false;
        }
        if idp.full_name.is_empty() {
            return true;
        }
        // RFC 5280 §6.3.3 (b)(2)(i): a name of the IDP must match one of the certificate's
        // distribution points or, without them, the CRL issuer.
        let dps = cert.crl_distribution_points();
        if dps.is_empty() {
            return idp
                .full_name
                .iter()
                .any(|n| matches!(n, GeneralName::DirectoryName(d) if d == &self.issuer));
        }
        dps.iter()
            .any(|dp| dp.full_name.iter().any(|n| idp.full_name.contains(n)))
    }

    /// The reasons this CRL covers.
    fn reasons(&self) -> ReasonFlags {
        self.idp
            .as_ref()
            .and_then(|i| i.only_some_reasons)
            .unwrap_or(ReasonFlags::ALL)
    }
}

/// A caller-supplied set of CRLs (complete and delta), for [`Verifier::crls`](crate::Verifier)
/// or direct [`status`](CrlSet::status) lookups. The application fetches and refreshes them
/// (cRLDistributionPoints give the URLs); signatures are checked on use, against the issuer
/// in the verified path, and remembered per CRL.
#[derive(Debug, Clone, Default)]
pub struct CrlSet {
    crls: Vec<Crl>,
}

impl CrlSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> CrlSet {
        CrlSet::default()
    }

    /// Adds a CRL.
    pub fn add(&mut self, crl: Crl) {
        self.crls.push(crl);
    }

    /// Adds a DER CRL.
    pub fn add_der(&mut self, der: impl Into<Vec<u8>>) -> Result<(), Error> {
        self.crls.push(Crl::from_der(der)?);
        Ok(())
    }

    /// Adds every CRL of a PEM text; returns how many.
    pub fn add_pem(&mut self, text: &[u8]) -> Result<usize, Error> {
        let v = Crl::from_pem(text)?;
        let n = v.len();
        self.crls.extend(v);
        Ok(n)
    }

    /// The CRLs.
    #[must_use]
    pub fn crls(&self) -> &[Crl] {
        &self.crls
    }

    /// The number of CRLs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.crls.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.crls.is_empty()
    }

    /// The status of `cert`, issued by `issuer`, at `now` (Unix seconds) with `skew` seconds
    /// of tolerance (RFC 5280 §6.3, without indirect CRLs):
    ///
    /// - CRLs used: issued by `issuer` (same name, signature by its key, cRLSign), current,
    ///   in scope (issuingDistributionPoint), with no unsupported critical extension.
    /// - Revoked when a complete CRL lists the serial (removeFromCRL entries ignored), or a
    ///   delta CRL based on a used complete CRL lists it; a delta's removeFromCRL lifts a
    ///   certificateHold.
    /// - Good when the used complete CRLs together cover every reason; Unknown otherwise.
    #[must_use]
    pub fn status(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
        now: i64,
        skew: u32,
    ) -> RevocationStatus {
        if cert.issuer().as_der() != issuer.subject().as_der() {
            return RevocationStatus::Unknown;
        }
        let usable = |c: &&Crl| {
            c.issuer.as_der() == issuer.subject().as_der()
                && c.covers(cert)
                && c.is_current(now, skew)
                && c.verify_signed_by(issuer).is_ok()
        };
        let mut covered = ReasonFlags::default();
        let mut found: Option<RevocationStatus> = None;
        let mut newest: Option<&[u8]> = None;
        for c in self.crls.iter().filter(|c| !c.is_delta()).filter(usable) {
            covered = covered.union(c.reasons());
            if let Some(n) = c.crl_number.as_deref() {
                if newest.is_none_or(|m| uint_cmp(n, m) == Ordering::Greater) {
                    newest = Some(n);
                }
            }
            if let Some(e) = c.find(cert.serial()) {
                if e.reason != Some(RevocationReason::RemoveFromCrl) && found.is_none() {
                    found = Some(RevocationStatus::Revoked {
                        time: e.revocation_date,
                        reason: e.reason,
                    });
                }
            }
        }
        if !covered.contains(ReasonFlags::ALL) {
            return found.unwrap_or(RevocationStatus::Unknown);
        }
        // Deltas: the newest one whose base is a CRL we used (base number <= our newest
        // complete CRL's number) and that is newer than it.
        if let Some(base) = newest {
            let delta = self
                .crls
                .iter()
                .filter(|c| c.is_delta())
                .filter(|c| {
                    c.delta_base
                        .as_deref()
                        .is_some_and(|b| uint_cmp(b, base) != Ordering::Greater)
                        && c.crl_number
                            .as_deref()
                            .is_some_and(|n| uint_cmp(n, base) == Ordering::Greater)
                })
                .filter(usable)
                .max_by(|a, b| {
                    uint_cmp(
                        a.crl_number.as_deref().unwrap_or_default(),
                        b.crl_number.as_deref().unwrap_or_default(),
                    )
                });
            if let Some(d) = delta {
                if let Some(e) = d.find(cert.serial()) {
                    if e.reason == Some(RevocationReason::RemoveFromCrl) {
                        if let Some(RevocationStatus::Revoked {
                            reason: Some(RevocationReason::CertificateHold),
                            ..
                        }) = found
                        {
                            found = None;
                        }
                    } else {
                        found = Some(RevocationStatus::Revoked {
                            time: e.revocation_date,
                            reason: e.reason,
                        });
                    }
                }
            }
        }
        found.unwrap_or(RevocationStatus::Good)
    }
}

/// What to put in a CRL made by [`CrlParams::sign`] (tests and development CAs).
#[derive(Debug, Clone)]
pub struct CrlParams {
    /// thisUpdate, Unix seconds.
    pub this_update: i64,
    /// nextUpdate, Unix seconds.
    pub next_update: Option<i64>,
    /// cRLNumber.
    pub crl_number: u64,
    /// For a delta CRL: the BaseCRLNumber (deltaCRLIndicator, critical).
    pub delta_base: Option<u64>,
    /// The entries.
    pub revoked: Vec<RevokedCertificate>,
    /// issuingDistributionPoint (critical), if any.
    pub issuing_distribution_point: Option<IssuingDistributionPoint>,
}

impl CrlParams {
    /// An empty complete CRL number 1, valid from one hour ago for a week.
    #[must_use]
    pub fn new() -> CrlParams {
        let now = crate::time::now();
        CrlParams {
            this_update: now - 3600,
            next_update: Some(now + 7 * 86_400),
            crl_number: 1,
            delta_base: None,
            revoked: Vec::new(),
            issuing_distribution_point: None,
        }
    }

    /// Adds an entry revoking `cert` since one hour ago.
    #[must_use]
    pub fn revoke(mut self, cert: &Certificate, reason: Option<RevocationReason>) -> Self {
        self.revoked.push(RevokedCertificate {
            serial: cert.serial().to_vec(),
            revocation_date: self.this_update,
            reason,
            invalidity_date: None,
        });
        self
    }

    /// A v2 CRL signed by `issuer_key` for `issuer`.
    pub fn sign(&self, issuer: &Certificate, issuer_key: &PrivateKey) -> Result<Crl, Error> {
        let alg = issuer_key.default_signature_algorithm();
        let alg_id = alg.to_algorithm_identifier();
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
        let mut w = Writer::new();
        w.sequence(|w| {
            w.small_uint(1);
            w.raw(&alg_id);
            w.raw(issuer.subject().as_der());
            write_time(w, self.this_update);
            if let Some(n) = self.next_update {
                write_time(w, n);
            }
            if !self.revoked.is_empty() {
                w.sequence(|w| {
                    for e in &self.revoked {
                        w.sequence(|w| {
                            w.uint(&e.serial);
                            write_time(w, e.revocation_date);
                            if e.reason.is_some() || e.invalidity_date.is_some() {
                                w.sequence(|w| {
                                    if let Some(r) = e.reason {
                                        extension(w, ext::REASON_CODE, false, &|w| {
                                            w.tlv(0x0a, &[r.code()]);
                                        });
                                    }
                                    if let Some(t) = e.invalidity_date {
                                        extension(w, ext::INVALIDITY_DATE, false, &|w| {
                                            write_generalized_time(w, t);
                                        });
                                    }
                                });
                            }
                        });
                    }
                });
            }
            w.nested(tag::explicit(0), |w| {
                w.sequence(|w| {
                    if let Some(aki) = issuer.subject_key_id() {
                        extension(w, ext::AUTHORITY_KEY_ID, false, &|w| {
                            w.sequence(|w| w.tlv(tag::implicit(0), aki));
                        });
                    }
                    extension(w, ext::CRL_NUMBER, false, &|w| {
                        w.small_uint(self.crl_number);
                    });
                    if let Some(b) = self.delta_base {
                        extension(w, ext::DELTA_CRL_INDICATOR, true, &|w| w.small_uint(b));
                    }
                    if let Some(idp) = &self.issuing_distribution_point {
                        extension(w, ext::ISSUING_DISTRIBUTION_POINT, true, &|w| {
                            write_idp(w, idp);
                        });
                    }
                });
            });
        });
        let tbs = w.into_vec();
        let sig = issuer_key.sign(alg, &tbs).map_err(Error::Crypto)?;
        let mut w = Writer::new();
        w.sequence(|w| {
            w.raw(&tbs);
            w.raw(&alg_id);
            w.bit_string(&sig);
        });
        Crl::from_der(w.into_vec())
    }
}

impl Default for CrlParams {
    fn default() -> Self {
        CrlParams::new()
    }
}

fn write_idp(w: &mut Writer, idp: &IssuingDistributionPoint) {
    w.sequence(|w| {
        if !idp.full_name.is_empty() {
            w.nested(tag::explicit(0), |w| {
                w.nested(tag::explicit(0), |w| {
                    for n in &idp.full_name {
                        n.write(w);
                    }
                });
            });
        }
        for (n, yes) in [(1, idp.only_user_certs), (2, idp.only_ca_certs)] {
            if yes {
                w.tlv(tag::implicit(n), &[0xff]);
            }
        }
        if let Some(r) = idp.only_some_reasons {
            let (bytes, nbits) = r.to_bits();
            let mut bw = Writer::new();
            bw.bit_string_bits(&bytes, nbits);
            let v = bw.into_vec();
            // Re-tag the BIT STRING as [3] IMPLICIT.
            let mut rr = Reader::new(&v);
            if let Ok((_, c, _)) = rr.read_tlv() {
                w.tlv(tag::implicit(3), c);
            }
        }
        for (n, yes) in [(4, idp.indirect_crl), (5, idp.only_attribute_certs)] {
            if yes {
                w.tlv(tag::implicit(n), &[0xff]);
            }
        }
    });
}
