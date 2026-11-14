//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use only_crypto::der::Reader;

use crate::{Certificate, RootStore, ServerName, Usage, Verifier, matches_server_name};

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
