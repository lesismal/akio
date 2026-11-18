//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use only_crypto::der::Reader;

use crate::{
    Certificate, Crl, CrlSet, OcspResponse, OcspValidation, RootStore, ServerName, Usage, Verifier,
    matches_server_name,
};

/// The OpenSSL-made CA and leaf of tests/data/revocation, for the revocation targets.
fn revocation_pki() -> (Certificate, Certificate) {
    let ca = Certificate::from_pem(include_bytes!("../tests/data/revocation/ca.pem"));
    let leaf = Certificate::from_pem(include_bytes!("../tests/data/revocation/revoked.pem"));
    match (ca, leaf) {
        (Ok(mut a), Ok(mut b)) if !a.is_empty() && !b.is_empty() => (a.remove(0), b.remove(0)),
        _ => unreachable!("vendored test certificates parse"),
    }
}

/// `x509_crl`: arbitrary bytes as a DER CRL (and a PEM text). Never panics; a parsed CRL
/// re-parses identically, survives a PEM round trip, finds each of its entries, and status
/// lookups (signature check, scope, deltas) run.
pub fn crl(data: &[u8]) {
    let _ = Crl::from_pem(data);
    let Ok(c) = Crl::from_der(data) else {
        return;
    };
    assert!(Crl::from_der(c.as_der()).ok().as_ref() == Some(&c));
    assert!(Crl::from_pem(c.to_pem().as_bytes()).ok().as_deref() == Some(std::slice::from_ref(&c)));
    for e in c.revoked() {
        assert!(c.find(&e.serial).is_some());
    }
    let _ = (
        c.issuer().to_string(),
        c.is_delta(),
        c.issuing_distribution_point(),
    );
    let (ca, leaf) = revocation_pki();
    let _ = c.verify_signed_by(&ca);
    let mut set = CrlSet::new();
    set.add(c.clone());
    set.add(c.clone());
    for t in [c.this_update(), c.next_update().unwrap_or(0)] {
        let _ = set.status(&leaf, &ca, t, 300);
        let _ = set.status(&ca, &ca, t, 300);
    }
}

/// `x509_ocsp`: arbitrary bytes as a DER OCSP response. Never panics; a parsed response
/// re-parses identically, and validation (signer selection, signature, CertID matching,
/// nonce, times) runs against the vendored CA at the response's own times.
pub fn ocsp(data: &[u8]) {
    let Ok(r) = OcspResponse::from_der(data) else {
        return;
    };
    assert!(OcspResponse::from_der(r.as_der()).ok().as_ref() == Some(&r));
    let (ca, leaf) = revocation_pki();
    let mut times = vec![0];
    if let Some(b) = r.basic() {
        times.push(b.produced_at());
        for s in b.responses() {
            let _ = s.cert_id.matches(&leaf, &ca);
            times.push(s.this_update);
            times.extend(s.next_update);
        }
        let _ = (b.nonce(), b.responder_id(), b.certs().len());
    }
    for t in times {
        let v = OcspValidation::new().at_time(t);
        let _ = r.verify(&leaf, &ca, &v);
        let _ = r.verify(&leaf, &ca, &v.nonce(&[0u8; 16][..]));
    }
}

/// Walks arbitrary DER recursively (constructed elements are descended into), with a depth
/// limit; never panics.
fn walk(data: &[u8], depth: usize) {
    if depth > 32 {
        return;
    }
    let mut r = Reader::new(data);
    while let Ok((tag, contents, _)) = r.read_tlv() {
        if tag & 0x20 != 0 {
            walk(contents, depth + 1);
        }
    }
}

/// `x509_parse`: arbitrary bytes as a DER certificate, a PEM text and generic DER. Never
/// panics; a parsed certificate re-parses identically, survives a PEM round trip, and every
/// accessor and a self-verification run without panicking.
pub fn parse(data: &[u8]) {
    walk(data, 0);
    let _ = only_crypto::pem::decode(data);
    let _ = only_crypto::pkey::PublicKey::from_spki_der(data);
    let _ = only_crypto::pkey::PrivateKey::from_der(data);
    let Ok(c) = Certificate::from_der(data) else {
        return;
    };
    let again = Certificate::from_der(c.as_der()).ok();
    assert!(again.as_ref() == Some(&c));
    let pem = Certificate::from_pem(c.to_pem().as_bytes()).ok();
    assert!(pem.as_deref() == Some(std::slice::from_ref(&c)));
    let _ = c.public_key();
    let _ = c.subject().to_string();
    let _ = c.issuer().common_name();
    for name in ["example.com", "a.example.com", "127.0.0.1", "::1"] {
        if let Ok(n) = ServerName::parse(name) {
            let _ = matches_server_name(&c, &n);
        }
    }
    let mut roots = RootStore::new();
    roots.add(c.clone());
    let t = c.not_before().saturating_add(1);
    let v = Verifier::new(&roots).at_time(t).usage(Usage::Any);
    let _ = v.verify(&c, std::slice::from_ref(&c), None);
}

#[cfg(test)]
mod tests {
    fn corpus(target: &str) -> Vec<Vec<u8>> {
        let dir = format!("{}/../../fuzz/corpus/{target}", env!("CARGO_MANIFEST_DIR"));
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        entries
            .filter_map(Result::ok)
            .filter_map(|e| std::fs::read(e.path()).ok())
            .collect()
    }

    fn replay(target: &str, f: fn(&[u8])) {
        let files = corpus(target);
        assert!(!files.is_empty(), "fuzz/corpus/{target} is empty");
        for d in files {
            f(&d);
            for cut in [1, d.len() / 2, d.len().saturating_sub(1)] {
                f(&d[..cut.min(d.len())]);
            }
            for i in (0..d.len()).step_by(31) {
                let mut g = d.clone();
                g[i] ^= 0x41;
                f(&g);
            }
        }
    }

    #[test]
    fn replay_x509_crl() {
        replay("x509_crl", super::crl);
    }

    #[test]
    fn replay_x509_ocsp() {
        replay("x509_ocsp", super::ocsp);
    }

    #[test]
    fn replay_x509_parse() {
        let files = corpus("x509_parse");
        assert!(!files.is_empty(), "fuzz/corpus/x509_parse is empty");
        for f in files {
            super::parse(&f);
            // Truncations and single-byte corruptions of each seed.
            for cut in [1, f.len() / 2, f.len().saturating_sub(1)] {
                super::parse(&f[..cut.min(f.len())]);
            }
            for i in (0..f.len()).step_by(97) {
                let mut g = f.clone();
                g[i] ^= 0x41;
                super::parse(&g);
            }
        }
    }
}
