//! Public-key known-answer tests: Wycheproof (X25519, Ed25519, ECDSA P-256/P-384 in DER and
//! P1363 form, ECDH P-256/P-384 with SPKI and raw points, RSA PKCS#1 v1.5 and PSS verification,
//! RSA PKCS#1 v1.5 signature generation), vendored under `tests/data/`.

mod common;

use common::{Json, unhex, wycheproof};
use only_crypto::hash::{Sha256, Sha384, Sha512};
use only_crypto::pkey::{PrivateKey, PublicKey};
use only_crypto::rsa::HashAlg;
use only_crypto::{ed25519, p256, p384, x25519};

/// "valid" / "acceptable" / "invalid".
fn result(t: &Json) -> &str {
    t.get("result").str()
}

fn size(j: &Json) -> usize {
    match j {
        Json::Str(s) => s.parse().unwrap(),
        _ => j.num(),
    }
}

fn hash_alg(s: &str) -> Option<HashAlg> {
    Some(match s {
        "SHA-1" => HashAlg::Sha1,
        "SHA-256" => HashAlg::Sha256,
        "SHA-384" => HashAlg::Sha384,
        "SHA-512" => HashAlg::Sha512,
        _ => return None,
    })
}

/// Tallies of (checked, valid-ok, rejected) for the summary line.
#[derive(Default, Debug)]
struct Count {
    total: usize,
    accepted: usize,
    rejected: usize,
}

impl Count {
    /// Checks `ok` against the expected result.
    fn check(&mut self, t: &Json, ok: bool, name: &str) {
        self.total += 1;
        match result(t) {
            "valid" => assert!(ok, "{name} tc {:?} should verify", t.get("tcId")),
            "invalid" => assert!(!ok, "{name} tc {:?} should fail", t.get("tcId")),
            _ => {}
        }
        if ok {
            self.accepted += 1;
        } else {
            self.rejected += 1;
        }
    }
}

#[test]
fn wycheproof_x25519() {
    let mut c = Count::default();
    for (_, t) in wycheproof("wycheproof_x25519.json") {
        let k = x25519::PrivateKey::from_bytes(t.get("private").hex().try_into().unwrap());
        let u: [u8; 32] = t.get("public").hex().try_into().unwrap();
        let want = t.get("shared").hex();
        // The raw function always matches (including low-order and non-canonical inputs).
        assert_eq!(x25519::x25519(&k.to_bytes(), &u).to_vec(), want);
        let ok = k.diffie_hellman(&u).is_ok_and(|s| s.to_vec() == want);
        c.check(&t, ok || want != [0; 32], "x25519");
        if want == [0; 32] {
            assert!(k.diffie_hellman(&u).is_err());
        }
    }
    assert!(c.total > 500, "{c:?}");
}

#[test]
fn wycheproof_ed25519() {
    let mut c = Count::default();
    for (g, t) in wycheproof("wycheproof_ed25519.json") {
        let pk = g.get("publicKey").get("pk").hex();
        let ok = ed25519::VerifyingKey::from_bytes(&pk)
            .and_then(|k| k.verify(&t.get("msg").hex(), &t.get("sig").hex()))
            .is_ok();
        c.check(&t, ok, "ed25519");
    }
    assert!(c.total > 140, "{c:?}");
}

fn ecdsa_file(name: &str, p1363: bool) {
    let mut c = Count::default();
    for (g, t) in wycheproof(name) {
        let key = PublicKey::from_spki_der(&g.get("publicKeyDer").hex()).unwrap();
        let msg = t.get("msg").hex();
        let sig = t.get("sig").hex();
        let sha = g.get("sha").str();
        macro_rules! run {
            ($k:expr, $m:ident) => {{
                let s = if p1363 {
                    $m::Signature::from_fixed(&sig)
                } else {
                    $m::Signature::from_der(&sig)
                };
                s.and_then(|s| match sha {
                    "SHA-256" => $k.verify_with::<Sha256>(&msg, &s),
                    "SHA-384" => $k.verify_with::<Sha384>(&msg, &s),
                    "SHA-512" => $k.verify_with::<Sha512>(&msg, &s),
                    _ => unreachable!(),
                })
                .is_ok()
            }};
        }
        let ok = match &key {
            PublicKey::P256(k) => run!(k, p256),
            PublicKey::P384(k) => run!(k, p384),
            _ => unreachable!(),
        };
        c.check(&t, ok, name);
        // The uncompressed point in the group must decode to the same key.
        let raw = g.get("publicKey").get("uncompressed").hex();
        assert_eq!(key.raw_key(), raw);
    }
    assert!(c.total > 200, "{c:?}");
}

#[test]
fn wycheproof_ecdsa() {
    ecdsa_file("wycheproof_ecdsa_secp256r1_sha256.json", false);
    ecdsa_file("wycheproof_ecdsa_secp256r1_sha256_p1363.json", true);
    ecdsa_file("wycheproof_ecdsa_secp384r1_sha384.json", false);
    ecdsa_file("wycheproof_ecdsa_secp384r1_sha512.json", false);
}

/// Private scalars in Wycheproof may carry a sign byte or be short.
fn scalar(hex: &[u8], n: usize) -> Vec<u8> {
    let s: Vec<u8> = hex.iter().copied().skip_while(|&b| b == 0).collect();
    let mut v = vec![0u8; n.saturating_sub(s.len())];
    v.extend_from_slice(&s);
    v
}

fn ecdh_file(name: &str, raw_points: bool) {
    let mut c = Count::default();
    for (g, t) in wycheproof(name) {
        let curve = g.get("curve").str();
        let public = t.get("public").hex();
        let private = t.get("private").hex();
        let want = t.get("shared").hex();
        let shared = match curve {
            "secp256r1" => {
                let d = p256::SecretKey::from_bytes(&scalar(&private, 32)).unwrap();
                let q = if raw_points {
                    p256::PublicKey::from_sec1(&public).ok()
                } else {
                    match PublicKey::from_spki_der(&public) {
                        Ok(PublicKey::P256(q)) => Some(q),
                        _ => None,
                    }
                };
                q.map(|q| d.diffie_hellman(&q).to_vec())
            }
            "secp384r1" => {
                let d = p384::SecretKey::from_bytes(&scalar(&private, 48)).unwrap();
                let q = if raw_points {
                    p384::PublicKey::from_sec1(&public).ok()
                } else {
                    match PublicKey::from_spki_der(&public) {
                        Ok(PublicKey::P384(q)) => Some(q),
                        _ => None,
                    }
                };
                q.map(|q| d.diffie_hellman(&q).to_vec())
            }
            _ => unreachable!(),
        };
        if let Some(s) = &shared {
            if result(&t) != "invalid" {
                assert_eq!(s, &want, "{name} {:?}", t.get("tcId"));
            }
        }
        c.check(&t, shared.is_some_and(|s| s == want), name);
    }
    assert!(c.total > 300, "{c:?}");
}

#[test]
fn wycheproof_ecdh() {
    ecdh_file("wycheproof_ecdh_secp256r1.json", false);
    ecdh_file("wycheproof_ecdh_secp256r1_ecpoint.json", true);
    ecdh_file("wycheproof_ecdh_secp384r1.json", false);
}

fn rsa_verify_file(name: &str, pss: bool) {
    let mut c = Count::default();
    for (g, t) in wycheproof(name) {
        let key = match PublicKey::from_spki_der(&g.get("publicKeyDer").hex()) {
            Ok(PublicKey::Rsa(k)) => k,
            other => {
                // Only keys below the 2048-bit minimum may be refused.
                assert!(size(g.get("keySize")) < 2048, "{name}: {other:?}");
                continue;
            }
        };
        let h = hash_alg(g.get("sha").str()).unwrap();
        let msg = t.get("msg").hex();
        let sig = t.get("sig").hex();
        let ok = if pss {
            assert_eq!(g.get("mgfSha").str(), g.get("sha").str());
            key.verify_pss(h, &msg, &sig, size(g.get("sLen"))).is_ok()
        } else {
            key.verify_pkcs1v15(h, &msg, &sig).is_ok()
        };
        c.check(&t, ok, name);
    }
    assert!(c.total > 100, "{c:?}");
}

#[test]
fn wycheproof_rsa_verify() {
    rsa_verify_file("wycheproof_rsa_signature_2048_sha256.json", false);
    rsa_verify_file("wycheproof_rsa_signature_3072_sha384.json", false);
    rsa_verify_file("wycheproof_rsa_signature_4096_sha512.json", false);
    rsa_verify_file("wycheproof_rsa_pss_2048_sha256_mgf1_32.json", true);
    rsa_verify_file("wycheproof_rsa_pss_4096_sha512_mgf1_64.json", true);
}

#[test]
fn wycheproof_rsa_sign() {
    let mut n = 0;
    for (g, t) in wycheproof("wycheproof_rsa_pkcs1_2048_sig_gen.json") {
        let Some(h) = hash_alg(g.get("sha").str()) else {
            continue; // SHA-224 is not implemented
        };
        let PrivateKey::Rsa(k) = PrivateKey::from_pkcs8_der(&g.get("privateKeyPkcs8").hex())
            .unwrap_or_else(|e| panic!("tc {:?}: {e}", t.get("tcId")))
        else {
            unreachable!()
        };
        let msg = t.get("msg").hex();
        let sig = k.sign_pkcs1v15(h, &msg).unwrap();
        assert_eq!(sig, t.get("sig").hex(), "tc {:?}", t.get("tcId"));
        k.public_key().verify_pkcs1v15(h, &msg, &sig).unwrap();
        // PSS signatures are randomized: check they verify.
        if h != HashAlg::Sha1 {
            let pss = k.sign_pss(h, &msg).unwrap();
            k.public_key()
                .verify_pss(h, &msg, &pss, h.output_len())
                .unwrap();
        }
        let back = PrivateKey::from_pkcs1_der(&k.to_pkcs1_der()).unwrap();
        assert_eq!(back.public_key(), PublicKey::Rsa(k.public_key().clone()));
        n += 1;
    }
    assert!(n > 20);
}

#[test]
fn rfc6979_sample() {
    // RFC 6979 A.2.5 (P-256, SHA-256) and A.2.6 (P-384, SHA-384), message "sample".
    let k = p256::SecretKey::from_bytes(&unhex(
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
    ))
    .unwrap();
    assert_eq!(
        k.sign(b"sample").to_fixed(),
        unhex(concat!(
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
            "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
        ))
    );
    let k = p384::SecretKey::from_bytes(&unhex(concat!(
        "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d8",
        "96d5724e4c70a825f872c9ea60d2edf5"
    )))
    .unwrap();
    assert_eq!(
        k.sign(b"sample").to_fixed(),
        unhex(concat!(
            "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c",
            "81a648152e44acf96e36dd1e80fabe46",
            "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94f",
            "a329c145786e679e7b82c71a38628ac8"
        ))
    );
}
