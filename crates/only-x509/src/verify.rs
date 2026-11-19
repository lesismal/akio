//! Chain building and validation (an RFC 5280 §6 subset with the Web PKI profile choices of
//! rustls-webpki) and server-name matching (RFC 6125).

use std::net::IpAddr;

use crate::Error;
use crate::cert::{Certificate, KeyUsage, ext};
use crate::crl::CrlSet;
use crate::name::{GeneralName, attr};
use crate::policy::{self, PolicyOptions, ValidPolicies};
use crate::revocation::{DEFAULT_CLOCK_SKEW, RevocationStatus};

/// The most intermediates a path may contain.
pub const MAX_INTERMEDIATES: usize = 6;
/// The most signature verifications one path search may perform (a bound on the work an
/// adversarial set of intermediates can cause), CRL signatures and CRL signer paths
/// included.
pub const MAX_SIGNATURE_CHECKS: usize = 100;

/// How deep CRL signer paths are revocation-checked: the path of a CRL signer other than the
/// certificate's issuer is validated (to the same trust anchor) and its own certificates
/// checked against CRLs; the signers of those CRLs are validated without further revocation
/// checks.
const MAX_CRL_SIGNER_DEPTH: u8 = 2;

/// A validated path and the policies it is valid for.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedPath {
    /// The certificates, end entity first, trust anchor last.
    pub chain: Vec<Certificate>,
    /// The user-constrained policy set (RFC 5280 §6.1.6).
    pub policies: ValidPolicies,
}

/// A set of trust anchors (root certificates).
#[derive(Debug, Clone, Default)]
pub struct RootStore {
    roots: Vec<Certificate>,
}

impl RootStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> RootStore {
        RootStore::default()
    }

    /// Adds a root.
    pub fn add(&mut self, cert: Certificate) {
        if !self.roots.contains(&cert) {
            self.roots.push(cert);
        }
    }

    /// Adds every certificate of a PEM text, returning how many were added.
    pub fn add_pem(&mut self, text: &[u8]) -> Result<usize, Error> {
        let certs = Certificate::from_pem(text)?;
        let n = certs.len();
        for c in certs {
            self.add(c);
        }
        Ok(n)
    }

    /// The roots.
    #[must_use]
    pub fn roots(&self) -> &[Certificate] {
        &self.roots
    }

    /// The number of roots.
    #[must_use]
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }
}

/// What the end-entity certificate will be used for (checked against extKeyUsage).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Usage {
    /// TLS server authentication (`id-kp-serverAuth`).
    ServerAuth,
    /// TLS client authentication (`id-kp-clientAuth`).
    ClientAuth,
    /// No extended key usage requirement.
    Any,
}

impl Usage {
    fn oid(self) -> Option<&'static [u8]> {
        match self {
            Usage::ServerAuth => Some(ext::SERVER_AUTH),
            Usage::ClientAuth => Some(ext::CLIENT_AUTH),
            Usage::Any => None,
        }
    }
}

/// A reference identity: a DNS name or an IP address.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServerName {
    /// A DNS name (no trailing dot, ASCII; A-labels for IDNs).
    Dns(String),
    /// An IP address, matched against iPAddress SANs only.
    Ip(IpAddr),
}

impl ServerName {
    /// Parses `s` as an IP address, else validates it as a DNS name (labels of 1–63
    /// letters, digits and hyphens, not starting or ending with a hyphen; a trailing dot is
    /// removed; no wildcards).
    pub fn parse(s: &str) -> Result<ServerName, Error> {
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(ServerName::Ip(ip));
        }
        let s = s.strip_suffix('.').unwrap_or(s);
        if s.is_empty() || s.len() > 253 {
            return Err(Error::InvalidServerName);
        }
        for label in s.split('.') {
            if !valid_label(label) {
                return Err(Error::InvalidServerName);
            }
        }
        Ok(ServerName::Dns(s.to_ascii_lowercase()))
    }
}

fn valid_label(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && !l.starts_with('-')
        && !l.ends_with('-')
        && l.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Whether DNS SAN `pattern` matches `name` (RFC 6125 §6.4): case-insensitive, a wildcard
/// only as the entire leftmost label, matching exactly one label, and only with at least two
/// labels after it (no `*.com`).
#[must_use]
pub fn dns_name_matches(pattern: &str, name: &str) -> bool {
    let pattern = pattern.strip_suffix('.').unwrap_or(pattern);
    let name = name.strip_suffix('.').unwrap_or(name);
    if let Some(rest) = pattern.strip_prefix("*.") {
        if rest.contains('*') || rest.split('.').count() < 2 || !rest.split('.').all(valid_label) {
            return false;
        }
        let Some((first, tail)) = name.split_once('.') else {
            return false;
        };
        return valid_label(first) && tail.eq_ignore_ascii_case(rest);
    }
    if pattern.contains('*') {
        return false;
    }
    pattern.eq_ignore_ascii_case(name)
}

/// Whether a certificate's subjectAltName matches the server name (DNS names against
/// dNSName entries, IP addresses against iPAddress entries; the subject common name is not
/// consulted, as in current browsers and rustls).
pub fn matches_server_name(cert: &Certificate, name: &ServerName) -> bool {
    cert.subject_alt_names().iter().any(|g| match (g, name) {
        (GeneralName::Dns(p), ServerName::Dns(n)) => dns_name_matches(p, n),
        (GeneralName::Ip(a), ServerName::Ip(IpAddr::V4(ip))) => a[..] == ip.octets(),
        (GeneralName::Ip(a), ServerName::Ip(IpAddr::V6(ip))) => a[..] == ip.octets(),
        _ => false,
    })
}

/// Chain verification against a [`RootStore`].
///
/// Rules: every non-root certificate in the path must be within its validity period at the
/// verification time; intermediates must be CAs (basicConstraints `cA`), satisfy their
/// pathLenConstraint, have keyCertSign if they carry keyUsage, and allow the requested usage
/// if they carry extKeyUsage; the end entity must not be a CA, and must allow the usage if it
/// carries extKeyUsage (anyExtendedKeyUsage is accepted); every signature must verify;
/// unknown critical extensions are rejected; name constraints of every CA (DNS, IP and
/// directoryName forms; others fail closed) apply to the end entity's names; the server name,
/// if given, must match a subjectAltName. Trust anchors are only a subject name and key: their
/// own validity and constraints other than name constraints are not checked (as in
/// rustls-webpki). Certificate policies are processed as RFC 5280 §6.1 specifies (policy
/// mappings, requireExplicitPolicy, inhibitPolicyMapping, inhibitAnyPolicy), with the inputs
/// of [`policies`](Self::policies); a self-issued intermediate does not count against
/// pathLenConstraint. Revocation ([`crls`](Self::crls)) is checked once a whole path is found.
#[derive(Debug, Clone)]
pub struct Verifier<'a> {
    roots: &'a RootStore,
    time: Option<i64>,
    usage: Usage,
    crls: Option<&'a CrlSet>,
    crl_signers: &'a [Certificate],
    mode: RevocationMode,
    skew: u32,
    policy: PolicyOptions,
    ca_end_entity: bool,
}

/// What [`Verifier::crls`] does with a certificate no current CRL covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum RevocationMode {
    /// Accept it (only a listed revocation fails the path).
    #[default]
    SoftFail,
    /// Reject it ([`Error::RevocationUnknown`]): every certificate of the path below the
    /// root needs a current CRL from its issuer.
    HardFail,
}

impl<'a> Verifier<'a> {
    /// A verifier for TLS server certificates at the current time.
    #[must_use]
    pub fn new(roots: &'a RootStore) -> Verifier<'a> {
        Verifier {
            roots,
            time: None,
            usage: Usage::ServerAuth,
            crls: None,
            crl_signers: &[],
            mode: RevocationMode::SoftFail,
            skew: DEFAULT_CLOCK_SKEW,
            policy: PolicyOptions::default(),
            ca_end_entity: false,
        }
    }

    /// Whether the end entity may be a CA certificate (default: no, [`Error::CaUsedAsEndEntity`];
    /// RFC 5280 path validation itself allows it, e.g. to validate a CA certificate).
    #[must_use]
    pub fn allow_ca_end_entity(mut self, allow: bool) -> Self {
        self.ca_end_entity = allow;
        self
    }

    /// Checks every certificate of a candidate path below the root against `crls`: a revoked
    /// certificate fails that path ([`Error::Revoked`]; another path may still succeed), and
    /// one no CRL covers is handled by the [`revocation_mode`](Self::revocation_mode). CRLs
    /// are used as [`CrlSet::status`] describes, and also when signed by another key than the
    /// issuer's (a certificate with the CRL issuer's name and cRLSign) or by another issuer
    /// that the certificate's distribution point names as cRLIssuer (an indirect CRL): such a
    /// signer certificate, found among the intermediates, the
    /// [`crl_signers`](Self::crl_signers) and the roots, must itself validate to the same root
    /// (RFC 5280 §6.3.3 (f)), including revocation.
    #[must_use]
    pub fn crls(mut self, crls: &'a CrlSet) -> Self {
        self.crls = Some(crls);
        self
    }

    /// Extra certificates that may sign CRLs or be on a CRL signer's path (not used to
    /// build the certificate's own path).
    #[must_use]
    pub fn crl_signers(mut self, certs: &'a [Certificate]) -> Self {
        self.crl_signers = certs;
        self
    }

    /// The certificate policy inputs (default: any policy, nothing required or inhibited).
    #[must_use]
    pub fn policies(mut self, options: PolicyOptions) -> Self {
        self.policy = options;
        self
    }

    /// What to do with certificates no current CRL covers (default: soft fail).
    #[must_use]
    pub fn revocation_mode(mut self, mode: RevocationMode) -> Self {
        self.mode = mode;
        self
    }

    /// The clock skew tolerated for CRL validity, in seconds (default
    /// [`DEFAULT_CLOCK_SKEW`]).
    #[must_use]
    pub fn clock_skew(mut self, secs: u32) -> Self {
        self.skew = secs;
        self
    }

    /// Verifies at `unix_seconds` instead of now.
    #[must_use]
    pub fn at_time(mut self, unix_seconds: i64) -> Self {
        self.time = Some(unix_seconds);
        self
    }

    /// The usage to require of the end entity (default: [`Usage::ServerAuth`]).
    #[must_use]
    pub fn usage(mut self, usage: Usage) -> Self {
        self.usage = usage;
        self
    }

    /// Builds and validates a path from `leaf` through any of `intermediates` to a root,
    /// returning it (leaf first, root last). `name`, if given, must match the leaf.
    pub fn verify(
        &self,
        leaf: &Certificate,
        intermediates: &[Certificate],
        name: Option<&ServerName>,
    ) -> Result<Vec<Certificate>, Error> {
        self.verify_path(leaf, intermediates, name).map(|p| p.chain)
    }

    /// [`verify`](Self::verify), also returning the policies the path is valid for.
    pub fn verify_path(
        &self,
        leaf: &Certificate,
        intermediates: &[Certificate],
        name: Option<&ServerName>,
    ) -> Result<VerifiedPath, Error> {
        let now = self.time.unwrap_or_else(crate::time::now);
        check_time(leaf, now)?;
        if let Some(oid) = leaf.unsupported_critical_extension() {
            return Err(Error::UnsupportedCriticalExtension(oid.to_vec()));
        }
        if leaf.is_ca() && !self.ca_end_entity {
            return Err(Error::CaUsedAsEndEntity);
        }
        check_eku(leaf, self.usage)?;
        if let Some(n) = name {
            if !matches_server_name(leaf, n) {
                return Err(Error::NameMismatch);
            }
        }
        let mut path = vec![leaf];
        let mut budget = MAX_SIGNATURE_CHECKS;
        let main: Vec<&Certificate> = intermediates.iter().collect();
        let mut signer_pool = main.clone();
        signer_pool.extend(self.crl_signers.iter());
        let mut search = Search {
            v: self,
            now,
            intermediates: &main,
            signer_pool: &signer_pool,
            budget: &mut budget,
            anchor: None,
            usage: self.usage,
            depth: 0,
            policies: None,
        };
        let chain = search.extend(&mut path)?;
        Ok(VerifiedPath {
            chain,
            policies: search.policies.unwrap_or(ValidPolicies::Any),
        })
    }

    /// [`verify`](Self::verify) for a server certificate presented for `server_name`.
    pub fn verify_server(
        &self,
        leaf: &Certificate,
        intermediates: &[Certificate],
        server_name: &str,
    ) -> Result<Vec<Certificate>, Error> {
        let n = ServerName::parse(server_name)?;
        self.clone()
            .usage(Usage::ServerAuth)
            .verify(leaf, intermediates, Some(&n))
    }

    /// [`verify`](Self::verify) for a client certificate (no name check).
    pub fn verify_client(
        &self,
        leaf: &Certificate,
        intermediates: &[Certificate],
    ) -> Result<Vec<Certificate>, Error> {
        self.clone()
            .usage(Usage::ClientAuth)
            .verify(leaf, intermediates, None)
    }
}

fn check_time(c: &Certificate, now: i64) -> Result<(), Error> {
    if now < c.not_before() {
        return Err(Error::NotYetValid);
    }
    if now > c.not_after() {
        return Err(Error::Expired);
    }
    Ok(())
}

fn check_eku(c: &Certificate, usage: Usage) -> Result<(), Error> {
    match (c.ext_key_usage(), usage.oid()) {
        (Some(ekus), Some(want)) => {
            if ekus
                .iter()
                .any(|e| e == want || e == ext::ANY_EXTENDED_KEY_USAGE)
            {
                Ok(())
            } else {
                Err(Error::ExtendedKeyUsage)
            }
        }
        _ => Ok(()),
    }
}

/// Rank of an error for reporting the most relevant failure of a search: anything specific
/// beats "unknown issuer".
fn rank(e: &Error) -> u8 {
    match e {
        Error::UnknownIssuer => 0,
        Error::TooManySignatures | Error::PathTooLong => 1,
        _ => 2,
    }
}

struct Search<'s, 'a> {
    v: &'s Verifier<'a>,
    now: i64,
    intermediates: &'s [&'s Certificate],
    /// Where CRL signers and their issuers are looked for (plus the roots).
    signer_pool: &'s [&'s Certificate],
    budget: &'s mut usize,
    /// Only this root may end the path (CRL signer paths: the same trust anchor).
    anchor: Option<&'s Certificate>,
    usage: Usage,
    /// 0 for the certificate's own path, 1 and more for CRL signer paths.
    depth: u8,
    /// The policies of the path found.
    policies: Option<ValidPolicies>,
}

impl<'s> Search<'s, '_> {
    fn check_signature(&mut self, child: &Certificate, issuer: &Certificate) -> Result<(), Error> {
        self.spend()?;
        child.verify_signed_by(&issuer.public_key()?)
    }

    fn spend(&mut self) -> Result<(), Error> {
        if *self.budget == 0 {
            return Err(Error::TooManySignatures);
        }
        *self.budget -= 1;
        Ok(())
    }

    /// The checks of a complete path `path` + `root`: name constraints of the root, policy
    /// processing (the certificate's own path only), and revocation from the top down.
    fn finish(&mut self, path: &[&Certificate], root: &'s Certificate) -> Result<(), Error> {
        check_name_constraints(root, path)?;
        if self.depth == 0 {
            let below: Vec<&Certificate> = path.iter().rev().copied().collect();
            self.policies = Some(policy::process(&below, &self.v.policy)?);
        }
        if self.v.crls.is_some() && self.depth < MAX_CRL_SIGNER_DEPTH {
            for k in (0..path.len()).rev() {
                let issuer = path.get(k + 1).copied().unwrap_or(root);
                self.check_revocation(path[k], issuer, root)?;
            }
        }
        Ok(())
    }

    fn check_revocation(
        &mut self,
        child: &Certificate,
        issuer: &Certificate,
        root: &'s Certificate,
    ) -> Result<(), Error> {
        let Some(crls) = self.v.crls else {
            return Ok(());
        };
        if child.issuer().as_der() != issuer.subject().as_der() {
            return Err(Error::RevocationUnknown);
        }
        let (now, skew) = (self.now, self.v.skew);
        let mut too_many = false;
        let status = crls.status_with(child, now, skew, &mut |crl| match self
            .crl_signed(crl, issuer, root)
        {
            Ok(b) => b,
            Err(_) => {
                too_many = true;
                false
            }
        });
        if too_many {
            return Err(Error::TooManySignatures);
        }
        match status {
            RevocationStatus::Good => Ok(()),
            RevocationStatus::Revoked { reason, .. } => Err(Error::Revoked(reason)),
            RevocationStatus::Unknown => match self.v.mode {
                RevocationMode::SoftFail => Ok(()),
                RevocationMode::HardFail => Err(Error::RevocationUnknown),
            },
        }
    }

    /// Whether `crl` is authentic for a path ending at `root`: signed by `issuer` (the
    /// certificate's issuer), or by a certificate with the CRL issuer's name and cRLSign that
    /// itself validates to `root`. Fails only when the signature budget runs out.
    fn crl_signed(
        &mut self,
        crl: &crate::Crl,
        issuer: &Certificate,
        root: &'s Certificate,
    ) -> Result<bool, Error> {
        if crl.issuer().as_der() == issuer.subject().as_der() {
            self.spend()?;
            if crl.verify_signed_by(issuer).is_ok() {
                return Ok(true);
            }
        }
        if crl.issuer().as_der() == root.subject().as_der() && root != issuer {
            self.spend()?;
            if crl.verify_signed_by(root).is_ok() {
                return Ok(true);
            }
        }
        let pool = self.signer_pool;
        for &cand in pool {
            if cand.subject().as_der() != crl.issuer().as_der() || cand == issuer || cand == root {
                continue;
            }
            self.spend()?;
            if crl.verify_signed_by(cand).is_err() {
                continue;
            }
            if self.validate_signer(cand, root)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether the CRL signer `cand` has a valid path to `root` (without the end-entity
    /// rules: a CRL signer may be a CA).
    fn validate_signer(
        &mut self,
        cand: &'s Certificate,
        root: &'s Certificate,
    ) -> Result<bool, Error> {
        if check_time(cand, self.now).is_err() || cand.unsupported_critical_extension().is_some() {
            return Ok(false);
        }
        let mut sub = Search {
            v: self.v,
            now: self.now,
            intermediates: self.signer_pool,
            signer_pool: self.signer_pool,
            budget: &mut *self.budget,
            anchor: Some(root),
            usage: Usage::Any,
            depth: self.depth + 1,
            policies: None,
        };
        let mut path = vec![cand];
        match sub.extend(&mut path) {
            Ok(_) => Ok(true),
            Err(e @ Error::TooManySignatures) => Err(e),
            Err(_) => Ok(false),
        }
    }

    /// Extends `path` (whose last element still needs an issuer) to a root.
    fn extend<'c>(&mut self, path: &mut Vec<&'c Certificate>) -> Result<Vec<Certificate>, Error>
    where
        's: 'c,
    {
        let mut best = Error::UnknownIssuer;
        let note = |e: Error, best: &mut Error| {
            if rank(&e) > rank(best) {
                *best = e;
            }
        };
        let child = path[path.len() - 1];
        let roots = self.v.roots.roots();
        for root in roots {
            if root.subject().as_der() != child.issuer().as_der()
                || self.anchor.is_some_and(|a| a != root)
            {
                continue;
            }
            let r = self
                .check_signature(child, root)
                .and_then(|()| self.finish(path, root));
            match r {
                Ok(()) => {
                    let mut out: Vec<Certificate> = path.iter().map(|c| (*c).clone()).collect();
                    out.push(root.clone());
                    return Ok(out);
                }
                Err(e @ Error::TooManySignatures) => return Err(e),
                Err(e) => note(e, &mut best),
            }
        }
        if path.len() > MAX_INTERMEDIATES {
            note(Error::PathTooLong, &mut best);
            return Err(best);
        }
        let intermediates = self.intermediates;
        for &ca in intermediates {
            if ca.subject().as_der() != child.issuer().as_der() || path.contains(&ca) {
                continue;
            }
            // Self-issued intermediates below `ca` do not count against its pathLen.
            let below = path[1..].iter().filter(|c| !c.is_self_issued()).count();
            let r = self
                .check_ca(ca, below)
                .and_then(|()| self.check_signature(child, ca))
                .and_then(|()| check_name_constraints(ca, path));
            if let Err(e) = r {
                if matches!(e, Error::TooManySignatures) {
                    return Err(e);
                }
                note(e, &mut best);
                continue;
            }
            path.push(ca);
            let r = self.extend(path);
            path.pop();
            match r {
                Ok(p) => return Ok(p),
                Err(e @ Error::TooManySignatures) => return Err(e),
                Err(e) => note(e, &mut best),
            }
        }
        Err(best)
    }

    /// Checks an intermediate that has `below` intermediates under it in the path.
    fn check_ca(&self, ca: &Certificate, below: usize) -> Result<(), Error> {
        check_time(ca, self.now)?;
        if let Some(oid) = ca.unsupported_critical_extension() {
            return Err(Error::UnsupportedCriticalExtension(oid.to_vec()));
        }
        let Some(bc) = ca.basic_constraints().filter(|b| b.ca) else {
            return Err(Error::NotCa);
        };
        if bc.path_len.is_some_and(|n| (below as u64) > u64::from(n)) {
            return Err(Error::PathLenExceeded);
        }
        if ca
            .key_usage()
            .is_some_and(|ku| !ku.contains(KeyUsage::KEY_CERT_SIGN))
        {
            return Err(Error::KeyUsage);
        }
        check_eku(ca, self.usage)
    }
}

/// Applies `ca`'s name constraints to every certificate below it in `path` (the end entity's
/// subjectAltNames and subject; intermediates' subjects).
fn check_name_constraints(ca: &Certificate, path: &[&Certificate]) -> Result<(), Error> {
    let Some(nc) = ca.name_constraints() else {
        return Ok(());
    };
    for (i, c) in path.iter().enumerate() {
        // Self-issued intermediates are exempt (RFC 5280 §6.1.3 (b)).
        if i > 0 && c.is_self_issued() {
            continue;
        }
        let mut names: Vec<GeneralName> = Vec::new();
        if !c.subject().is_empty() {
            names.push(GeneralName::DirectoryName(c.subject().clone()));
        }
        if i == 0 {
            names.extend(c.subject_alt_names().iter().cloned());
            // Legacy e-mail addresses in the subject name are rfc822Names too.
            names.extend(
                c.subject()
                    .values(attr::EMAIL_ADDRESS)
                    .map(GeneralName::Email),
            );
        }
        for n in &names {
            // Excluded: a match, or a form of the same type we cannot evaluate.
            if nc
                .excluded
                .iter()
                .any(|s| same_form(&s.0, n) && subtree_match(&s.0, n) != Some(false))
            {
                return Err(Error::NameConstraintViolation);
            }
            let same: Vec<_> = nc.permitted.iter().filter(|s| same_form(&s.0, n)).collect();
            if !same.is_empty() && !same.iter().any(|s| subtree_match(&s.0, n) == Some(true)) {
                return Err(Error::NameConstraintViolation);
            }
        }
    }
    Ok(())
}

fn same_form(a: &GeneralName, b: &GeneralName) -> bool {
    std::mem::discriminant(a) == std::mem::discriminant(b)
}

/// Whether `name` is within `base`: `Some(true/false)` for the forms we evaluate (DNS, IP,
/// directoryName, rfc822Name, URI), `None` for other forms of the same type or names we
/// cannot evaluate (fail closed).
fn subtree_match(base: &GeneralName, name: &GeneralName) -> Option<bool> {
    // A host within a constraint: equal, or (constraint ".example.com") any subdomain.
    let host_in = |b: &str, host: &str| -> bool {
        match b.strip_prefix('.') {
            Some(_) => {
                host.len() > b.len() && host.to_ascii_lowercase().ends_with(&b.to_ascii_lowercase())
            }
            None => host.eq_ignore_ascii_case(b),
        }
    };
    match (base, name) {
        (GeneralName::Email(b), GeneralName::Email(n)) => {
            // A mailbox (local part exact, host case-insensitive), a host, or a domain.
            let (local, host) = n.rsplit_once('@')?;
            Some(match b.rsplit_once('@') {
                Some((bl, bh)) => bl == local && bh.eq_ignore_ascii_case(host),
                None => host_in(b, host),
            })
        }
        (GeneralName::Uri(b), GeneralName::Uri(n)) => {
            // The host of the authority; a URI without one cannot be evaluated.
            let rest = n.split_once("://")?.1;
            let auth = rest.split(['/', '?', '#']).next()?;
            let auth = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
            let host = if auth.starts_with('[') {
                return None;
            } else {
                auth.split(':').next()?
            };
            if host.is_empty() {
                return None;
            }
            Some(host_in(b, host))
        }
        (GeneralName::Dns(b), GeneralName::Dns(n)) => {
            let n = n.strip_prefix("*.").unwrap_or(n).to_ascii_lowercase();
            let b = b.to_ascii_lowercase();
            if b.is_empty() {
                return Some(true);
            }
            if let Some(suffix) = b.strip_prefix('.') {
                return Some(n.ends_with(&format!(".{suffix}")));
            }
            Some(n == b || n.ends_with(&format!(".{b}")))
        }
        (GeneralName::Ip(b), GeneralName::Ip(n)) => {
            if b.len() != 2 * n.len() {
                return Some(false);
            }
            let (addr, mask) = b.split_at(n.len());
            Some(
                addr.iter()
                    .zip(mask)
                    .zip(n.iter())
                    .all(|((a, m), x)| a & m == x & m),
            )
        }
        (GeneralName::DirectoryName(b), GeneralName::DirectoryName(n)) => Some(n.has_prefix(b)),
        (a, b) if same_form(a, b) => None,
        _ => Some(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_matching() {
        assert!(dns_name_matches("example.com", "EXAMPLE.com"));
        assert!(dns_name_matches("example.com.", "example.com"));
        assert!(dns_name_matches("*.example.com", "a.example.com"));
        assert!(!dns_name_matches("*.example.com", "a.b.example.com"));
        assert!(!dns_name_matches("*.example.com", "example.com"));
        assert!(!dns_name_matches("*.com", "example.com"));
        assert!(!dns_name_matches("a*.example.com", "ab.example.com"));
        assert!(!dns_name_matches("*.*.example.com", "a.b.example.com"));
        assert!(!dns_name_matches("a.*.example.com", "a.b.example.com"));
        assert!(ServerName::parse("a..b").is_err());
        assert!(ServerName::parse("-a.b").is_err());
        assert_eq!(
            ServerName::parse("127.0.0.1").unwrap(),
            ServerName::Ip("127.0.0.1".parse().unwrap())
        );
        assert_eq!(
            ServerName::parse("Example.COM.").unwrap(),
            ServerName::Dns("example.com".into())
        );
    }

    #[test]
    fn subtrees() {
        let d = |s: &str| GeneralName::Dns(s.into());
        assert_eq!(
            subtree_match(&d("example.com"), &d("a.example.com")),
            Some(true)
        );
        assert_eq!(
            subtree_match(&d("example.com"), &d("example.com")),
            Some(true)
        );
        assert_eq!(
            subtree_match(&d("example.com"), &d("badexample.com")),
            Some(false)
        );
        assert_eq!(
            subtree_match(&d(".example.com"), &d("example.com")),
            Some(false)
        );
        let ip = GeneralName::Ip(vec![10, 0, 0, 0, 255, 0, 0, 0]);
        assert_eq!(
            subtree_match(&ip, &GeneralName::Ip(vec![10, 1, 2, 3])),
            Some(true)
        );
        assert_eq!(
            subtree_match(&ip, &GeneralName::Ip(vec![11, 1, 2, 3])),
            Some(false)
        );
        assert_eq!(
            subtree_match(
                &GeneralName::Email("a".into()),
                &GeneralName::Email("b".into())
            ),
            None
        );
    }
}
