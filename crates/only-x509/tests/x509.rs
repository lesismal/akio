//! X.509 tests: real-world chains (vendored public certificates), OpenSSL-made chains and keys
//! (generated in Docker, `tests/data/openssl`), certificates generated here, and constructed
//! negative cases in the spirit of BetterTLS / x509-limbo.

use only_crypto::pkey::{PrivateKey, PublicKey, SignatureAlgorithm};
use only_crypto::{ed25519, p256, p384};
use only_x509::{
    Certificate, CertificateParams, Error, Extension, GeneralName, GeneralSubtree, IsCa, KeyUsage,
    NameConstraints, RootStore, ServerName, Usage, Verifier, ext,
};

fn data(path: &str) -> Vec<u8> {
    let p = format!("{}/tests/data/{path}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn pem_certs(path: &str) -> Vec<Certificate> {
    Certificate::from_pem(&data(path)).unwrap()
}

fn roots(paths: &[&str]) -> RootStore {
    let mut r = RootStore::new();
    for p in paths {
        assert!(r.add_pem(&data(p)).unwrap() >= 1);
    }
    r
}

#[test]
fn real_world_chains() {
    let store = roots(&[
        "real/isrgrootx1.pem",
        "real/isrg-root-x2.pem",
        "real/globalsign-root-ca.pem",
        "real/gts-root-r4.pem",
    ]);
    for (file, host, root_cn) in [
        ("real/www.google.com.pem", "www.google.com", "GTS Root R4"),
        (
            "real/www.cloudflare.com.pem",
            "www.cloudflare.com",
            "GTS Root R4",
        ),
        (
            "real/letsencrypt.org.pem",
            "letsencrypt.org",
            "ISRG Root X2",
        ),
        (
            "real/www.rust-lang.org.pem",
            "www.rust-lang.org",
            "ISRG Root X1",
        ),
    ] {
        let chain = pem_certs(file);
        let leaf = &chain[0];
        // A time inside every certificate's validity.
        let t = chain.iter().map(Certificate::not_before).max().unwrap() + 86_400;
        let v = Verifier::new(&store).at_time(t);
        let path = v
            .verify_server(leaf, &chain[1..], host)
            .unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(
            path.last().unwrap().subject().common_name().as_deref(),
            Some(root_cn),
            "{file}"
        );
        // Re-encoding round trip and accessors.
        for c in &chain {
            assert_eq!(&Certificate::from_der(c.as_der().to_vec()).unwrap(), c);
            assert_eq!(c.version(), 3);
            assert!(c.public_key().is_ok());
            assert!(c.subject_key_id().is_some());
        }
        assert!(
            leaf.ext_key_usage()
                .unwrap()
                .iter()
                .any(|e| e == ext::SERVER_AUTH)
        );
        // Wrong name, expired, not yet valid, missing intermediates, empty store.
        assert_eq!(
            v.verify_server(leaf, &chain[1..], "example.com"),
            Err(Error::NameMismatch)
        );
        assert_eq!(
            Verifier::new(&store)
                .at_time(leaf.not_after() + 1)
                .verify_server(leaf, &chain[1..], host),
            Err(Error::Expired)
        );
        assert_eq!(
            Verifier::new(&store)
                .at_time(leaf.not_before() - 1)
                .verify_server(leaf, &chain[1..], host),
            Err(Error::NotYetValid)
        );
        assert_eq!(v.verify_server(leaf, &[], host), Err(Error::UnknownIssuer));
        let empty = RootStore::new();
        assert_eq!(
            Verifier::new(&empty)
                .at_time(t)
                .verify_server(leaf, &chain[1..], host),
            Err(Error::UnknownIssuer)
        );
        // Client-auth usage is not in these leaves' EKU.
        assert_eq!(
            v.verify_client(leaf, &chain[1..]),
            Err(Error::ExtendedKeyUsage)
        );
        // A corrupted signature fails.
        let mut der = leaf.as_der().to_vec();
        let n = der.len();
        der[n - 5] ^= 1;
        if let Ok(bad) = Certificate::from_der(der) {
            assert!(v.verify_server(&bad, &chain[1..], host).is_err());
        }
    }
    // The roots' self-signatures (RSA PKCS#1 SHA-1 for GlobalSign, SHA-256 for ISRG X1,
    // ECDSA P-384 for X2 and R4) verify.
    for root in store.roots() {
        root.verify_signed_by(&root.public_key().unwrap()).unwrap();
    }
}

#[test]
fn openssl_chain_and_keys() {
    let store = roots(&["openssl/root.pem"]);
    let inter = pem_certs("openssl/inter.pem");
    assert_eq!(
        inter[0].signature_algorithm().unwrap(),
        SignatureAlgorithm::RsaPssSha256
    );
    let t = inter[0].not_before() + 3600;
    let v = Verifier::new(&store).at_time(t);
    for leaf in ["openssl/leaf_ed25519.pem", "openssl/leaf_rsa.pem"] {
        let leaf = &pem_certs(leaf)[0];
        for name in ["openssl.test", "a.wild.openssl.test", "10.1.2.3", "::1"] {
            v.verify_server(leaf, &inter, name)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        for name in [
            "wild.openssl.test",
            "a.b.wild.openssl.test",
            "10.1.2.4",
            "other.test",
        ] {
            assert_eq!(
                v.verify_server(leaf, &inter, name),
                Err(Error::NameMismatch),
                "{name}"
            );
        }
        v.verify_client(leaf, &inter).unwrap();
        assert_eq!(leaf.key_usage(), Some(KeyUsage::DIGITAL_SIGNATURE));
    }
    // pathlen:0 on the intermediate: a CA below it is rejected (constructed below).
    assert_eq!(inter[0].basic_constraints().unwrap().path_len, Some(0));

    // Keys in every format, and OpenSSL's signatures over msg.bin.
    let msg = data("openssl/msg.bin");
    let p256 = PrivateKey::from_pem(&data("openssl/p256.key")).unwrap();
    let p256_sec1 = PrivateKey::from_pem(&data("openssl/p256_sec1.key")).unwrap();
    assert_eq!(p256.to_pkcs8_der(), p256_sec1.to_pkcs8_der());
    p256.public_key()
        .verify(
            SignatureAlgorithm::EcdsaSha256,
            &msg,
            &data("openssl/p256_sha256.sig"),
        )
        .unwrap();
    let inter_key = PrivateKey::from_pem(&data("openssl/inter.key")).unwrap();
    let inter_sec1 = PrivateKey::from_pem(&data("openssl/inter_sec1.key")).unwrap();
    assert_eq!(inter_key.to_pkcs8_der(), inter_sec1.to_pkcs8_der());
    assert_eq!(inter_key.public_key(), inter[0].public_key().unwrap());
    inter_key
        .public_key()
        .verify(
            SignatureAlgorithm::EcdsaSha384,
            &msg,
            &data("openssl/p384_sha384.sig"),
        )
        .unwrap();
    let ed = PrivateKey::from_pem(&data("openssl/leaf_ed25519.key")).unwrap();
    assert_eq!(
        ed.sign(SignatureAlgorithm::Ed25519, &msg).unwrap(),
        data("openssl/ed25519.sig")
    );
    let rsa = PrivateKey::from_pem(&data("openssl/leaf_rsa.key")).unwrap();
    let rsa1 = PrivateKey::from_pem(&data("openssl/leaf_rsa_pkcs1.key")).unwrap();
    assert_eq!(rsa.to_pkcs8_der(), rsa1.to_pkcs8_der());
    assert_eq!(
        rsa.sign(SignatureAlgorithm::RsaPkcs1Sha256, &msg).unwrap(),
        data("openssl/rsa_pkcs1_sha256.sig")
    );
    rsa.public_key()
        .verify(
            SignatureAlgorithm::RsaPssSha512,
            &msg,
            &data("openssl/rsa_pss_sha512.sig"),
        )
        .unwrap();
    let root_key = PrivateKey::from_pem(&data("openssl/root.key")).unwrap();
    assert_eq!(
        root_key.public_key(),
        store.roots()[0].public_key().unwrap()
    );
}

fn p256_key() -> PrivateKey {
    PrivateKey::P256(p256::SecretKey::generate().unwrap())
}

struct Pki {
    root: Certificate,
    root_key: PrivateKey,
    inter: Certificate,
    inter_key: PrivateKey,
}

fn pki() -> Pki {
    let root_key = PrivateKey::P384(p384::SecretKey::generate().unwrap());
    let root = CertificateParams::ca("Test Root")
        .self_signed(&root_key)
        .unwrap();
    let inter_key = PrivateKey::Ed25519(ed25519::SigningKey::generate().unwrap());
    let mut p = CertificateParams::ca("Test Intermediate");
    p.is_ca = IsCa::Ca(Some(0));
    let inter = p
        .signed_by(&inter_key.public_key(), &root, &root_key)
        .unwrap();
    Pki {
        root,
        root_key,
        inter,
        inter_key,
    }
}

fn leaf_params(names: &[&str]) -> CertificateParams {
    let mut p = CertificateParams::new(names.iter().copied());
    p.extended_key_usage = vec![ext::SERVER_AUTH.to_vec()];
    p.key_usage = Some(KeyUsage::DIGITAL_SIGNATURE);
    p
}

#[test]
fn generated_chain() {
    let pki = pki();
    let mut store = RootStore::new();
    store.add(pki.root.clone());
    let v = Verifier::new(&store);
    let key = p256_key();
    let leaf = leaf_params(&["svc.test", "*.svc.test", "192.0.2.7"])
        .signed_by(&key.public_key(), &pki.inter, &pki.inter_key)
        .unwrap();
    let inters = [pki.inter.clone()];
    let path = v.verify_server(&leaf, &inters, "svc.test").unwrap();
    assert_eq!(path.len(), 3);
    v.verify_server(&leaf, &inters, "x.svc.test").unwrap();
    v.verify_server(&leaf, &inters, "192.0.2.7").unwrap();
    assert_eq!(leaf.authority_key_id(), pki.inter.subject_key_id());
    assert_eq!(
        v.verify_client(&leaf, &inters),
        Err(Error::ExtendedKeyUsage)
    );
    assert_eq!(
        v.clone()
            .usage(Usage::Any)
            .verify(&leaf, &inters, None)
            .unwrap()
            .len(),
        3
    );
    // PEM round trip of certificates and keys.
    let again = Certificate::from_pem(leaf.to_pem().as_bytes()).unwrap();
    assert_eq!(again, vec![leaf.clone()]);
    let k2 = PrivateKey::from_pem(key.to_pkcs8_pem().as_bytes()).unwrap();
    assert_eq!(k2.public_key(), leaf.public_key().unwrap());

    // Intermediates are found in any order, among unrelated certificates.
    let other = pki_unrelated();
    let mixed = [other.clone(), pki.inter.clone(), other];
    v.verify_server(&leaf, &mixed, "svc.test").unwrap();

    // pathLen 0 on the intermediate: another CA below it is refused.
    let sub_key = p256_key();
    let sub = CertificateParams::ca("Sub CA")
        .signed_by(&sub_key.public_key(), &pki.inter, &pki.inter_key)
        .unwrap();
    let leaf2 = leaf_params(&["svc.test"])
        .signed_by(&p256_key().public_key(), &sub, &sub_key)
        .unwrap();
    assert_eq!(
        v.verify_server(&leaf2, &[sub, pki.inter.clone()], "svc.test"),
        Err(Error::PathLenExceeded)
    );

    // A leaf signed by a non-CA certificate.
    let ee_key = p256_key();
    let ee = leaf_params(&["ee.test"])
        .signed_by(&ee_key.public_key(), &pki.inter, &pki.inter_key)
        .unwrap();
    let below_ee = leaf_params(&["svc.test"])
        .signed_by(&p256_key().public_key(), &ee, &ee_key)
        .unwrap();
    assert_eq!(
        v.verify_server(&below_ee, &[ee, pki.inter.clone()], "svc.test"),
        Err(Error::NotCa)
    );

    // A CA certificate as the end entity.
    assert_eq!(
        v.clone().usage(Usage::Any).verify(&pki.inter, &[], None),
        Err(Error::CaUsedAsEndEntity)
    );

    // An intermediate without keyCertSign.
    let mut p = CertificateParams::ca("No KeyCertSign");
    p.key_usage = Some(KeyUsage::DIGITAL_SIGNATURE);
    let nk_key = p256_key();
    let nk = p
        .signed_by(&nk_key.public_key(), &pki.root, &pki.root_key)
        .unwrap();
    let leaf3 = leaf_params(&["svc.test"])
        .signed_by(&p256_key().public_key(), &nk, &nk_key)
        .unwrap();
    assert_eq!(
        v.verify_server(&leaf3, &[nk], "svc.test"),
        Err(Error::KeyUsage)
    );

    // An intermediate whose EKU excludes server auth.
    let mut p = CertificateParams::ca("Client CA");
    p.extended_key_usage = vec![ext::CLIENT_AUTH.to_vec()];
    let ck = p256_key();
    let cca = p
        .signed_by(&ck.public_key(), &pki.root, &pki.root_key)
        .unwrap();
    let leaf4 = leaf_params(&["svc.test"])
        .signed_by(&p256_key().public_key(), &cca, &ck)
        .unwrap();
    assert_eq!(
        v.verify_server(&leaf4, &[cca], "svc.test"),
        Err(Error::ExtendedKeyUsage)
    );

    // An expired intermediate.
    let mut p = CertificateParams::ca("Expired CA");
    p.not_before = 1_000_000_000;
    p.not_after = 1_100_000_000;
    let xk = p256_key();
    let xca = p
        .signed_by(&xk.public_key(), &pki.root, &pki.root_key)
        .unwrap();
    let leaf5 = leaf_params(&["svc.test"])
        .signed_by(&p256_key().public_key(), &xca, &xk)
        .unwrap();
    assert_eq!(
        v.verify_server(&leaf5, &[xca], "svc.test"),
        Err(Error::Expired)
    );

    // An unknown critical extension in the leaf.
    let mut p = leaf_params(&["svc.test"]);
    p.custom_extensions.push(Extension {
        oid: vec![0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x99, 0x01],
        critical: true,
        value: vec![0x05, 0x00],
    });
    let leaf6 = p
        .signed_by(&p256_key().public_key(), &pki.inter, &pki.inter_key)
        .unwrap();
    assert!(matches!(
        v.verify_server(&leaf6, &inters, "svc.test"),
        Err(Error::UnsupportedCriticalExtension(_))
    ));
    // The same extension non-critical is fine.
    let mut p = leaf_params(&["svc.test"]);
    p.custom_extensions.push(Extension {
        oid: vec![0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x99, 0x01],
        critical: false,
        value: vec![0x05, 0x00],
    });
    let leaf7 = p
        .signed_by(&p256_key().public_key(), &pki.inter, &pki.inter_key)
        .unwrap();
    v.verify_server(&leaf7, &inters, "svc.test").unwrap();

    // Signed by the wrong key (issuer name matches, signature does not).
    let leaf8 = leaf_params(&["svc.test"])
        .signed_by(
            &p256_key().public_key(),
            &pki.inter,
            &PrivateKey::Ed25519(ed25519::SigningKey::generate().unwrap()),
        )
        .unwrap();
    assert_eq!(
        v.verify_server(&leaf8, &inters, "svc.test"),
        Err(Error::BadSignature)
    );
    // ... or with a key of another type (the algorithm does not fit the issuer key).
    let leaf9 = leaf_params(&["svc.test"])
        .signed_by(&p256_key().public_key(), &pki.inter, &p256_key())
        .unwrap();
    assert_eq!(
        v.verify_server(&leaf9, &inters, "svc.test"),
        Err(Error::Crypto(only_crypto::Error::Unsupported))
    );
}

fn pki_unrelated() -> Certificate {
    let k = p256_key();
    CertificateParams::ca("Unrelated").self_signed(&k).unwrap()
}

#[test]
fn name_constraints() {
    let root_key = p256_key();
    let root = CertificateParams::ca("NC Root")
        .self_signed(&root_key)
        .unwrap();
    let mut store = RootStore::new();
    store.add(root.clone());
    let v = Verifier::new(&store);
    let mut p = CertificateParams::ca("Constrained");
    p.name_constraints = Some(NameConstraints {
        permitted: vec![
            GeneralSubtree(GeneralName::Dns("example.com".into())),
            GeneralSubtree(GeneralName::Ip(vec![10, 0, 0, 0, 255, 0, 0, 0])),
        ],
        excluded: vec![GeneralSubtree(GeneralName::Dns("bad.example.com".into()))],
    });
    let ck = p256_key();
    let ca = p.signed_by(&ck.public_key(), &root, &root_key).unwrap();
    assert!(ca.name_constraints().is_some());
    let leaf = |names: &[&str]| {
        leaf_params(names)
            .signed_by(&p256_key().public_key(), &ca, &ck)
            .unwrap()
    };
    let inters = [ca.clone()];
    v.verify_server(&leaf(&["a.example.com"]), &inters, "a.example.com")
        .unwrap();
    v.verify_server(&leaf(&["example.com", "10.9.8.7"]), &inters, "10.9.8.7")
        .unwrap();
    for names in [
        &["a.example.org"][..],
        &["a.example.com", "evil.test"][..],
        &["x.bad.example.com"][..],
        &["a.example.com", "192.168.1.1"][..],
        &["badexample.com"][..],
    ] {
        assert_eq!(
            v.verify_server(&leaf(names), &inters, names[0]),
            Err(Error::NameConstraintViolation),
            "{names:?}"
        );
    }
}

#[test]
fn self_signed_and_server_names() {
    let (cert, key) = only_x509::generate_simple_self_signed(["localhost", "127.0.0.1"]).unwrap();
    assert!(matches!(key, PrivateKey::P256(_)));
    let mut store = RootStore::new();
    store.add(cert.clone());
    let v = Verifier::new(&store);
    v.verify_server(&cert, &[], "localhost").unwrap();
    v.verify_server(&cert, &[], "127.0.0.1").unwrap();
    v.verify_server(&cert, &[], "LOCALHOST.").unwrap();
    assert_eq!(
        v.verify_server(&cert, &[], "127.0.0.2"),
        Err(Error::NameMismatch)
    );
    assert_eq!(
        v.verify_server(&cert, &[], "bad..name"),
        Err(Error::InvalidServerName)
    );
    assert!(only_x509::matches_server_name(
        &cert,
        &ServerName::parse("localhost").unwrap()
    ));
    // Ed25519 and RSA signers.
    let ed = PrivateKey::Ed25519(ed25519::SigningKey::generate().unwrap());
    let c = CertificateParams::new(["ed.test"])
        .self_signed(&ed)
        .unwrap();
    assert_eq!(
        c.signature_algorithm().unwrap(),
        SignatureAlgorithm::Ed25519
    );
    c.verify_signed_by(&ed.public_key()).unwrap();
    let rsa = PrivateKey::from_pem(&data("openssl/leaf_rsa.key")).unwrap();
    let c = CertificateParams::new(["rsa.test"])
        .self_signed(&rsa)
        .unwrap();
    assert_eq!(
        c.signature_algorithm().unwrap(),
        SignatureAlgorithm::RsaPkcs1Sha256
    );
    c.verify_signed_by(&rsa.public_key()).unwrap();
}

#[test]
fn malformed_certificates() {
    let (cert, _) = only_x509::generate_simple_self_signed(["m.test"]).unwrap();
    let der = cert.as_der();
    // Every truncation fails cleanly.
    for n in 0..der.len() {
        assert!(Certificate::from_der(der[..n].to_vec()).is_err());
    }
    // Trailing data.
    let mut d = der.to_vec();
    d.push(0);
    assert!(Certificate::from_der(d).is_err());
    // A non-minimal outer length (BER) is rejected.
    let mut ber = vec![0x30, 0x83, 0x00];
    ber.extend_from_slice(&der[2..]);
    assert!(Certificate::from_der(ber).is_err());
    // Random single-byte corruptions never panic.
    for i in 0..der.len() {
        let mut d = der.to_vec();
        d[i] ^= 0xa5;
        let _ = Certificate::from_der(d);
    }
}

#[test]
fn spki_and_keys_from_certificates() {
    for c in pem_certs("real/www.google.com.pem")
        .into_iter()
        .chain(pem_certs("real/www.rust-lang.org.pem"))
    {
        let k = c.public_key().unwrap();
        assert_eq!(k.to_spki_der(), c.spki_der());
        assert_eq!(PublicKey::from_spki_der(c.spki_der()).unwrap(), k);
    }
}
