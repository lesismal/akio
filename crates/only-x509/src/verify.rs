//! Chain building and validation (an RFC 5280 §6 subset with the Web PKI profile choices of
//! rustls-webpki) and server-name matching (RFC 6125).

use std::net::IpAddr;

use crate::Error;
use crate::cert::{Certificate, KeyUsage, ext};
use crate::name::GeneralName;

/// The most intermediates a path may contain.
pub const MAX_INTERMEDIATES: usize = 6;
/// The most signature verifications one path search may perform (a bound on the work an
/// adversarial set of intermediates can cause).
pub const MAX_SIGNATURE_CHECKS: usize = 100;

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
/// rustls-webpki).
#[derive(Debug, Clone)]
pub struct Verifier<'a> {
    roots: &'a RootStore,
    time: Option<i64>,
    usage: Usage,
}

impl<'a> Verifier<'a> {
    /// A verifier for TLS server certificates at the current time.
    #[must_use]
    pub fn new(roots: &'a RootStore) -> Verifier<'a> {
        Verifier {
            roots,
            time: None,
            usage: Usage::ServerAuth,
        }
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
        let now = self.time.unwrap_or_else(crate::time::now);
        check_time(leaf, now)?;
        if let Some(oid) = leaf.unsupported_critical_extension() {
            return Err(Error::UnsupportedCriticalExtension(oid.to_vec()));
        }
        if leaf.is_ca() {
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
        let mut search = Search {
            v: self,
            now,
            intermediates,
            budget: &mut budget,
        };
        let found = search.extend(&mut path)?;
        Ok(found)
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
    intermediates: &'s [Certificate],
    budget: &'s mut usize,
}

impl<'s> Search<'s, '_> {
    fn check_signature(&mut self, child: &Certificate, issuer: &Certificate) -> Result<(), Error> {
        if *self.budget == 0 {
            return Err(Error::TooManySignatures);
        }
        *self.budget -= 1;
        child.verify_signed_by(&issuer.public_key()?)
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
        for root in self.v.roots.roots() {
            if root.subject().as_der() != child.issuer().as_der() {
                continue;
            }
            let r = self
                .check_signature(child, root)
                .and_then(|()| check_name_constraints(root, path));
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
        for ca in intermediates {
            if ca.subject().as_der() != child.issuer().as_der() || path.contains(&ca) {
                continue;
            }
            let r = self
                .check_ca(ca, path.len() - 1)
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
        check_eku(ca, self.v.usage)
    }
}

/// Applies `ca`'s name constraints to every certificate below it in `path` (the end entity's
/// subjectAltNames and subject; intermediates' subjects).
fn check_name_constraints(ca: &Certificate, path: &[&Certificate]) -> Result<(), Error> {
    let Some(nc) = ca.name_constraints() else {
        return Ok(());
    };
    for (i, c) in path.iter().enumerate() {
        let mut names: Vec<GeneralName> = Vec::new();
        if !c.subject().is_empty() {
            names.push(GeneralName::DirectoryName(c.subject().clone()));
        }
        if i == 0 {
            names.extend(c.subject_alt_names().iter().cloned());
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
/// directoryName), `None` for other forms of the same type (fail closed).
fn subtree_match(base: &GeneralName, name: &GeneralName) -> Option<bool> {
    match (base, name) {
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
