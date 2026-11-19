//! Public-key known-answer tests: Wycheproof (X25519, Ed25519, ECDSA P-256/P-384/P-521 in DER
//! and P1363 form, ECDH P-256/P-384/P-521 with SPKI and raw points, RSA PKCS#1 v1.5 and PSS verification,
//! RSA PKCS#1 v1.5 signature generation), vendored under `tests/data/`.

mod common;

use common::{Json, data, unhex, wycheproof};
use only_crypto::hash::{Sha256, Sha384, Sha512};
use only_crypto::pkey::{PrivateKey, PssParams, PublicKey, SignatureAlgorithm};
use only_crypto::rsa::HashAlg;
use only_crypto::{ed25519, p256, p384, p521, x25519};

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
            PublicKey::P521(k) => run!(k, p521),
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
    ecdsa_file("wycheproof_ecdsa_secp521r1_sha512.json", false);
    ecdsa_file("wycheproof_ecdsa_secp521r1_sha512_p1363.json", true);
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
            "secp521r1" => {
                let d = p521::SecretKey::from_bytes(&scalar(&private, 66)).unwrap();
                let q = match PublicKey::from_spki_der(&public) {
                    Ok(PublicKey::P521(q)) => Some(q),
                    _ => None,
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
    ecdh_file("wycheproof_ecdh_secp521r1.json", false);
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

#[test]
fn rfc6979_sample_p521() {
    // RFC 6979 A.2.7 (P-521), message "sample", SHA-512 and SHA-256 (a digest shorter than the
    // order); the same values come from OpenSSL's deterministic ECDSA (`nonce-type:1`).
    let k = p521::SecretKey::from_bytes(&unhex(concat!(
        "00fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75",
        "caa896eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b8",
        "3538"
    )))
    .unwrap();
    let sig = k.sign(b"sample");
    assert_eq!(
        sig.to_fixed(),
        unhex(concat!(
            "00c328fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d4c5f",
            "174e25a1ee9017b5d450606add152b534931d7d4e8455cc91f9b15bf05ec36e3",
            "77fa",
            "00617cce7cf5064806c467f678d3b4080d6f1cc50af26ca209417308281b68af",
            "282623eaa63e5b5c0723d8b8c37ff0777b1a20f8ccb1dccc43997f1ee0e44da4",
            "a67a"
        ))
    );
    k.public_key().verify(b"sample", &sig).unwrap();
    let sig = k.sign_with::<Sha256>(b"sample");
    assert_eq!(
        sig.to_fixed(),
        unhex(concat!(
            "01511bb4d675114fe266fc4372b87682baecc01d3cc62cf2303c92b352601265",
            "9d16876e25c7c1e57648f23b73564d67f61c6f14d527d54972810421e7d87589",
            "e1a7",
            "004a171143a83163d6df460aaf61522695f207a58b95c0644d87e52aa1a34791",
            "6e4f7a72930b1bc06dbe22ce3f58264afd23704cbb63b29b931f7de6c9d949a7",
            "ecfc"
        ))
    );
    k.public_key()
        .verify_with::<Sha256>(b"sample", &sig)
        .unwrap();
    // DER and SEC1 round trips through pkey.
    let key = PrivateKey::P521(k);
    let back = PrivateKey::from_pem(key.to_pkcs8_pem().as_bytes()).unwrap();
    assert_eq!(back.public_key(), key.public_key());
    let sec1 = key.to_sec1_der().unwrap();
    assert_eq!(
        PrivateKey::from_sec1_der(&sec1).unwrap().public_key(),
        key.public_key()
    );
    let spki = key.public_key().to_spki_der();
    assert_eq!(PublicKey::from_spki_der(&spki).unwrap(), key.public_key());
    let PublicKey::P521(pk) = key.public_key() else {
        unreachable!()
    };
    assert_eq!(p521::PublicKey::from_sec1(&pk.to_compressed()).unwrap(), pk);
}

/// `id-RSASSA-PSS` keys made by OpenSSL 3 (`genpkey -algorithm RSA-PSS`), one restricted to
/// SHA-256 with a 32-byte minimum salt, one without parameters; signatures by OpenSSL over
/// "sample" (SHA-256, MGF1-SHA-256, 32-byte salt).
#[test]
fn rsa_pss_keys() {
    let openssl_sigs = [
        concat!(
            "b0c80d674b5c962c482422334ef1717734b7c6e03a56eaef39948ab12d3af717",
            "9b78e39247d37644d2d008ccd010a97aae357e6391575541ca6ff896ab3d8621",
            "4e2e0fa12471f0f7786e5250d8683e6f27a77f6cab4e4d1b57d7b0f646b4bf1d",
            "bd855e7667491cbd44dafba4c2c4335ddf9b0a98c236fe98e732e9bce4ecfacb",
            "c7f144018ad6ed6edba0cc5de9072e4b04b2198b0049c68729be2045e53858b1",
            "f198dcb9d3e313c625d48017ce3d9fc87c2dd0d9a3a9d75527201c1febd18158",
            "f7ef05b447be63da30d3c55c58eb7ec02bcf2f56b2dd83f39581b358bf890339",
            "ffc0ad53669ecb916ef5ee8282a8358c6c07ddefbc908e879455c02ed6a24c26",
        ),
        concat!(
            "b771fba72f1f4dc3128cb69b5f554a6a575da89c53d3f958f1a9b2fe9960581b",
            "4976b6848fdab33de30cb7ae64b18ecac7e669913697a6053f5bbe1af0685ed3",
            "fbe5094847c0e37a8073d3200cbff9579f48148573d1b19bce3749a8e70936a1",
            "5fbb7c0e330759c5ed31dd911780f1579e8ba6f5bdf34c868e61ed0ae5201541",
            "1504385c76b0d1875e2c26c30b46282a58bf3d42d9b72c6d6fc9b81626f28b90",
            "119ddd7c59ed52afc7927e62029825109bfb05223d493b141f38c7ab655849bc",
            "c9df988bbfed9a5c8cc2052ca717aedf3af92ac9abd47c69650600debd46938d",
            "759f6c66bd696b7cbcb021f017269cfe05290b08d5ff96b9ea522b1bd6a30c44",
        ),
    ];
    for (i, (file, want)) in [
        (
            "rsa_pss_sha256_test_key.pem",
            Some(PssParams::new(HashAlg::Sha256, 32)),
        ),
        ("rsa_pss_test_key.pem", None),
    ]
    .into_iter()
    .enumerate()
    {
        let pem = data(file);
        let key = PrivateKey::from_pem(pem.as_bytes()).unwrap();
        let PrivateKey::RsaPss(_, params) = &key else {
            panic!("{file}: not an RSA-PSS key")
        };
        assert_eq!(*params, want);
        // Our PKCS#8 encoding is OpenSSL's, byte for byte.
        let der: Vec<u8> = only_crypto::pem::decode(pem.as_bytes()).unwrap()[0]
            .1
            .clone();
        assert_eq!(key.to_pkcs8_der(), der);
        let pk = key.public_key();
        assert!(matches!(pk, PublicKey::RsaPss(_, p) if p == want));
        let spki = pk.to_spki_der();
        assert_eq!(PublicKey::from_spki_der(&spki).unwrap(), pk);
        pk.verify(
            SignatureAlgorithm::RsaPssSha256,
            b"sample",
            &unhex(openssl_sigs[i]),
        )
        .unwrap();
        assert_eq!(
            key.default_signature_algorithm(),
            SignatureAlgorithm::RsaPssSha256
        );
        for alg in [
            SignatureAlgorithm::RsaPssSha256,
            SignatureAlgorithm::RsaPssSha384,
            SignatureAlgorithm::RsaPssSha512,
            SignatureAlgorithm::RsaPkcs1Sha256,
        ] {
            let allowed = match alg {
                SignatureAlgorithm::RsaPssSha256 => true,
                SignatureAlgorithm::RsaPkcs1Sha256 => false,
                _ => want.is_none(),
            };
            match key.sign(alg, b"m") {
                Ok(sig) => {
                    assert!(allowed, "{file} {alg:?}");
                    pk.verify(alg, b"m", &sig).unwrap();
                }
                Err(e) => {
                    assert!(!allowed, "{file} {alg:?}");
                    assert_eq!(e, only_crypto::Error::Unsupported);
                }
            }
        }
        // The same key as rsaEncryption verifies PKCS#1 v1.5; as id-RSASSA-PSS it refuses it.
        let PrivateKey::RsaPss(k, _) = &key else {
            unreachable!()
        };
        let sig = k.sign_pkcs1v15(HashAlg::Sha256, b"m").unwrap();
        assert!(
            pk.verify(SignatureAlgorithm::RsaPkcs1Sha256, b"m", &sig)
                .is_err()
        );
    }
    // Parameters: defaults (SHA-1) and a different MGF1 hash are unsupported; a salt longer
    // than the hash cannot be honoured by our fixed-salt signer.
    assert_eq!(
        PssParams::from_der(&[0x30, 0x00]),
        Err(only_crypto::Error::Unsupported)
    );
    let p = PssParams::new(HashAlg::Sha384, 48);
    assert_eq!(PssParams::from_der(&p.to_der()), Ok(p));
    assert!(p.allows(SignatureAlgorithm::RsaPssSha384));
    assert!(!p.allows(SignatureAlgorithm::RsaPssSha256));
    assert!(!PssParams::new(HashAlg::Sha256, 33).allows(SignatureAlgorithm::RsaPssSha256));
    // MGF1 over SHA-384 with a SHA-256 message hash: the second SHA-256 OID (the MGF1 hash)
    // ends in 02 instead of 01.
    let mut mixed = PssParams::new(HashAlg::Sha256, 32).to_der();
    let sha256 = only_crypto::der::oid::SHA256;
    let at = mixed
        .windows(sha256.len())
        .rposition(|w| w == sha256)
        .unwrap();
    mixed[at + sha256.len() - 1] = 0x02;
    assert_eq!(
        PssParams::from_der(&mixed),
        Err(only_crypto::Error::Unsupported)
    );
}
