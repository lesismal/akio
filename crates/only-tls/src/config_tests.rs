//! Tests of the configuration types: in-memory handshakes between the built configs.

use super::*;
use rustls::{ClientConnection, ServerConnection};

struct Pki {
    cert: Certificate,
    key: PrivateKey,
    cert_pem: String,
    key_pem: String,
}

fn pki(name: &str) -> Pki {
    let ck = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
    Pki {
        cert: Certificate::from_der(ck.cert.der().to_vec()),
        key: PrivateKey::from_pkcs8_der(ck.key_pair.serialize_der()),
        cert_pem: ck.cert.pem(),
        key_pem: ck.key_pair.serialize_pem(),
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
) -> Result<(ServerConnection, ClientConnection), rustls::Error> {
    let mut sc = ServerConnection::new(s.__rustls().clone())?;
    let n = rustls::pki_types::ServerName::try_from(name.to_owned()).unwrap();
    let mut cc = ClientConnection::new(c.__rustls().clone(), n)?;
    for _ in 0..10 {
        let mut buf = Vec::new();
        while cc.wants_write() {
            cc.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            sc.read_tls(&mut &buf[..]).unwrap();
            sc.process_new_packets()?;
        }
        buf.clear();
        while sc.wants_write() {
            sc.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            cc.read_tls(&mut &buf[..]).unwrap();
            cc.process_new_packets()?;
        }
        if !sc.is_handshaking() && !cc.is_handshaking() {
            // One more round: in TLS 1.3 the server sees the client's certificate last.
            let mut buf = Vec::new();
            while cc.wants_write() {
                cc.write_tls(&mut buf).unwrap();
            }
            if !buf.is_empty() {
                sc.read_tls(&mut &buf[..]).unwrap();
                sc.process_new_packets()?;
            }
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
    let c = ClientConfig::builder()
        .roots(roots(&b.cert))
        .alpn([b"http/1.1"])
        .build()
        .unwrap();
    assert_eq!(c.alpn_protocols(), [b"http/1.1".to_vec()]);
    assert!(format!("{c:?}").contains("alpn"));
    let (sc, cc) = handshake(&s, &c, "b.test").unwrap();
    assert_eq!(sc.server_name(), Some("b.test"));
    assert_eq!(cc.alpn_protocol(), Some(&b"http/1.1"[..]));
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
    let s = ServerConfig::builder(vec![srv.cert.clone()], srv.key.clone())
        .build()
        .unwrap();
    let strict = ClientConfig::builder().build().unwrap();
    assert!(handshake(&s, &strict, "localhost").is_err());
    let insecure = ClientConfig::builder()
        .insecure_skip_verify()
        .tls13_only(true)
        .build()
        .unwrap();
    handshake(&s, &insecure, "localhost").unwrap();
    let insecure12 = ClientConfig::builder()
        .insecure_skip_verify()
        .build()
        .unwrap();
    let s12 = ServerConfig::builder(vec![srv.cert.clone()], srv.key)
        .build()
        .unwrap();
    handshake(&s12, &insecure12, "localhost").unwrap();
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
    assert!(format!("{:?}", ServerConfig::builder(vec![], srv.key)).contains("tls13_only"));
    assert!(format!("{:?}", ClientConfig::builder()).contains("roots"));
}
