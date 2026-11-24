//! Tests of the configuration types: parsing, builders, errors, and in-memory handshakes between
//! the built configs.

use super::*;
use crate::proto::Connection;

struct Pki {
    cert: Certificate,
    key: PrivateKey,
    cert_pem: String,
    key_pem: String,
}

fn pki(name: &str) -> Pki {
    let (cert, key) = akio_x509::generate_simple_self_signed([name]).unwrap();
    Pki {
        cert: Certificate::from_der(cert.as_der().to_vec()),
        key: PrivateKey::from_pkcs8_der(key.to_pkcs8_der()),
        cert_pem: cert.to_pem(),
        key_pem: key.to_pkcs8_pem(),
    }
}

fn roots(c: &Certificate) -> RootCerts {
    let mut r = RootCerts::empty();
    r.add(c).unwrap();
    r
}

/// Runs a handshake in memory; returns the two ends or the first error.
fn handshake(
    s: &ServerConfig,
    c: &ClientConfig,
    name: &str,
) -> Result<(Connection, Connection), crate::proto::Fatal> {
    let mut sc = crate::__proto::server(s);
    let mut cc = crate::__proto::client(c, name)?;
    let mut c2s = Vec::new();
    let mut plain = Vec::new();
    cc.recv(&[], &mut plain, &mut c2s)?;
    for _ in 0..10 {
        let mut s2c = Vec::new();
        sc.recv(&std::mem::take(&mut c2s), &mut plain, &mut s2c)?;
        cc.recv(&s2c, &mut plain, &mut c2s)?;
        if c2s.is_empty() && !sc.handshaking() && !cc.handshaking() {
            return Ok((sc, cc));
        }
    }
    panic!("handshake did not finish");
}

#[test]
fn pem_inputs_parse_and_bad_ones_fail() {
    let p = pki("localhost");
    let chain = Certificate::from_pem(p.cert_pem.as_bytes()).unwrap();
    assert_eq!(chain, vec![p.cert.clone()]);
    assert_eq!(chain[0].as_der(), p.cert.as_der());
    PrivateKey::from_pem(p.key_pem.as_bytes()).unwrap();
    assert!(Certificate::from_pem(b"nothing here").is_err());
    assert!(PrivateKey::from_pem(p.cert_pem.as_bytes()).is_err());
    assert!(PrivateKey::from_der(vec![1, 2, 3]).is_err());
    // SEC1 and PKCS#1 keys load too.
    let ec = pkey::PrivateKey::from_pkcs8_der(&p.key.0.der).unwrap();
    let sec1 = ec.to_sec1_der().unwrap();
    PrivateKey::from_der(sec1.clone()).unwrap();
    let sec1_pem = akio_crypto::pem::encode("EC PRIVATE KEY", &sec1);
    PrivateKey::from_pem(sec1_pem.as_bytes()).unwrap();
    let mut r = RootCerts::default();
    assert!(r.is_empty());
    assert_eq!(r.add_pem(p.cert_pem.as_bytes()).unwrap(), 1);
    assert_eq!(r.len(), 1);
    assert!(format!("{r:?}").contains("len: 1"));
    assert!(format!("{:?}", p.cert).contains("der_len"));
    // Debug output never shows the key.
    assert_eq!(format!("{:?}", p.key.clone()), "PrivateKey { .. }");
}

#[test]
fn alpn_and_sni_selection() {
    let a = pki("a.test");
    let b = pki("b.test");
    let s = ServerConfig::builder(vec![a.cert.clone()], a.key)
        .sni_cert("B.test", vec![b.cert.clone()], b.key.clone())
        .alpn(["h2", "http/1.1"])
        .tls13_only(true)
        .session_tickets(true)
        .build()
        .unwrap();
    assert_eq!(s.alpn_protocols(), [b"h2".to_vec(), b"http/1.1".to_vec()]);
    assert!(format!("{s:?}").contains("alpn"));
    assert_eq!(s.__parts().sni.len(), 1);
    let c = ClientConfig::builder()
        .roots(roots(&b.cert))
        .alpn([b"http/1.1"])
        .build()
        .unwrap();
    assert_eq!(c.alpn_protocols(), [b"http/1.1".to_vec()]);
    assert!(format!("{c:?}").contains("alpn"));
    assert_eq!(c.__parts().roots.len(), 1);
    let (sc, cc) = handshake(&s, &c, "b.test").unwrap();
    assert_eq!(sc.server_name(), Some("b.test"));
    assert_eq!(cc.alpn(), Some(&b"http/1.1"[..]));
    // Any other name gets the default chain, which b.test's roots do not trust.
    let c = ClientConfig::builder()
        .roots(roots(&b.cert))
        .build()
        .unwrap();
    assert!(handshake(&s, &c, "a.test").is_err());
}

#[test]
fn client_auth_required_and_optional() {
    let srv = pki("localhost");
    let cli = pki("client");
    let required = ServerConfig::builder(vec![srv.cert.clone()], srv.key.clone())
        .client_auth_required(roots(&cli.cert))
        .session_cache(0)
        .build()
        .unwrap();
    let optional = ServerConfig::builder(vec![srv.cert.clone()], srv.key.clone())
        .client_auth_optional(roots(&cli.cert))
        .build()
        .unwrap();
    let anon = ClientConfig::builder()
        .roots(roots(&srv.cert))
        .resumption(false)
        .sni(false)
        .build()
        .unwrap();
    let with_cert = ClientConfig::builder()
        .roots(roots(&srv.cert))
        .client_cert(vec![cli.cert.clone()], cli.key)
        .build()
        .unwrap();
    handshake(&required, &with_cert, "localhost").unwrap();
    handshake(&optional, &with_cert, "localhost").unwrap();
    handshake(&optional, &anon, "localhost").unwrap();
    assert!(handshake(&required, &anon, "localhost").is_err());
    // Client authentication needs roots.
    assert!(
        ServerConfig::builder(vec![srv.cert.clone()], srv.key)
            .client_auth_required(RootCerts::empty())
            .build()
            .is_err()
    );
}

#[test]
fn insecure_client_accepts_unknown_certificates() {
    let srv = pki("localhost");
    let s = ServerConfig::builder(vec![srv.cert.clone()], srv.key)
        .build()
        .unwrap();
    let strict = ClientConfig::builder().build().unwrap();
    assert!(handshake(&s, &strict, "localhost").is_err());
    let insecure = ClientConfig::builder()
        .insecure_skip_verify()
        .tls13_only(true)
        .build()
        .unwrap();
    assert!(insecure.__parts().insecure);
    handshake(&s, &insecure, "localhost").unwrap();
    let insecure12 = ClientConfig::builder()
        .insecure_skip_verify()
        .__tls12_only(true)
        .build()
        .unwrap();
    let (sc, _) = handshake(&s, &insecure12, "localhost").unwrap();
    assert_eq!(sc.version_name(), Some("TLSv1_2"));
}

#[test]
fn bad_keys_and_errors_are_reported() {
    let srv = pki("localhost");
    let e = ServerConfig::builder(
        vec![srv.cert.clone()],
        PrivateKey::from_pkcs8_der(vec![1, 2, 3]),
    )
    .build()
    .unwrap_err();
    assert!(e.to_string().starts_with("tls: private key"), "{e}");
    assert!(format!("{e:?}").contains("private key"));
    assert!(std::error::Error::source(&e).is_some());
    let io: io::Error = e.into();
    assert_eq!(io.kind(), io::ErrorKind::InvalidInput);
    let e = Certificate::from_pem(b"").unwrap_err();
    assert!(std::error::Error::source(&e).is_none());
    assert_eq!(e.to_string(), "tls: no certificate in PEM input");
    let mut r = RootCerts::empty();
    assert!(r.add(&Certificate::from_der(vec![0x30, 0x00])).is_err());
    let e = ClientConfig::builder()
        .client_cert(vec![srv.cert.clone()], PrivateKey::from_pkcs8_der(vec![1]))
        .build()
        .unwrap_err();
    assert!(e.to_string().contains("client certificate"), "{e}");
    // A key that is not the certificate's.
    let other = pki("localhost");
    let e = ServerConfig::builder(vec![srv.cert.clone()], other.key)
        .build()
        .unwrap_err();
    assert!(e.to_string().contains("does not match"), "{e}");
    // The same for a client certificate (A109), and an empty client chain.
    let e = ClientConfig::builder()
        .client_cert(vec![srv.cert.clone()], pki("client").key)
        .build()
        .unwrap_err();
    let msg = e.to_string();
    assert!(msg.contains("client certificate"), "{e}");
    assert!(
        msg.contains("private key does not match the certificate"),
        "{e}"
    );
    assert!(
        ClientConfig::builder()
            .client_cert(vec![], srv.key.clone())
            .build()
            .is_err()
    );
    assert!(
        ServerConfig::builder(vec![], srv.key.clone())
            .build()
            .is_err()
    );
    // Unknown internal suites / groups, or none left.
    let b = || ServerConfig::builder(vec![srv.cert.clone()], srv.key.clone());
    assert!(b().__suites(&[0x0035]).build().is_err());
    assert!(b().__groups(&[0x001a]).build().is_err());
    assert!(b().__groups(&[]).build().is_err());
    // Client OCSP needs client authentication / a client certificate.
    let e = b()
        .client_ocsp_policy(RevocationPolicy::SoftFail)
        .build()
        .unwrap_err();
    assert!(e.to_string().contains("client authentication"), "{e}");
    let e = ClientConfig::builder()
        .client_cert_ocsp_response(vec![0x30, 0x03, 0x0a, 0x01, 0x00])
        .build()
        .unwrap_err();
    assert!(
        e.to_string().contains("without a client certificate"),
        "{e}"
    );
    assert!(b().__suites(&[0x1301]).__tls12_only(true).build().is_err());
    assert!(
        ClientConfig::builder()
            .__suites(&[0xc02b])
            .tls13_only(true)
            .build()
            .is_err()
    );
    assert!(ClientConfig::builder().__groups(&[]).build().is_err());
    assert!(format!("{:?}", ServerConfig::builder(vec![], srv.key)).contains("tls13_only"));
    assert!(format!("{:?}", ClientConfig::builder()).contains("roots"));
}

#[test]
fn system_roots_load() {
    // Every CI host (Linux with ca-certificates, macOS) has a system store.
    let r = RootCerts::system().expect("system roots");
    assert!(r.len() > 10, "{}", r.len());
    // Cached: the second call returns the same set.
    assert_eq!(RootCerts::system().unwrap().len(), r.len());
    ClientConfig::builder().roots(r).build().unwrap();
}
