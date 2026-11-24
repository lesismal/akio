//! The client's verified certificate chain on each request (`Request::peer_certificates`,
//! ADR-109): over HTTP/1.1 and HTTP/2 behind akio-tls with client authentication, absent
//! without a certificate and in the clear, and shared by a connection's requests.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

use akio::{
    Backend, Config, Engine, Listener, UringConfig,
    tls::{Certificate, ClientConfig, PrivateKey, RootCerts, ServerConfig, Tls},
};
use akio_http::{
    Context, H2Config, HttpConfig, Router,
    client::ClientRequest,
    h2client::{H2Client, H2Options},
    serve_with,
};
use akio_x509::{CertificateParams, generate_simple_self_signed};

type X509Key = akio_crypto::pkey::PrivateKey;

fn backend() -> Backend {
    match std::env::var("AKIO_TEST_BACKEND").as_deref() {
        Ok("uring") => Backend::IoUring({
            let mut v = UringConfig::default();
            v.strict = true;
            v
        }),
        _ => Backend::Epoll,
    }
}

/// A certificate of `names` signed by `ca`, with its key.
fn issue(names: &[&str], ca: &(akio_x509::Certificate, X509Key)) -> (Vec<Certificate>, PrivateKey) {
    let (throwaway, key) = generate_simple_self_signed(["x"]).unwrap();
    let cert = CertificateParams::new(names.iter().copied())
        .signed_by(&throwaway.public_key().unwrap(), &ca.0, &ca.1)
        .unwrap();
    (
        vec![Certificate::from_der(cert.as_der().to_vec())],
        PrivateKey::from_pkcs8_der(key.to_pkcs8_der()),
    )
}

struct Pki {
    roots: RootCerts,
    server: (Vec<Certificate>, PrivateKey),
    client: (Vec<Certificate>, PrivateKey),
}

fn pki() -> Pki {
    let (_, ca_key) = generate_simple_self_signed(["ca"]).unwrap();
    let ca_cert = CertificateParams::ca("test ca")
        .self_signed(&ca_key)
        .unwrap();
    let mut roots = RootCerts::empty();
    roots
        .add(&Certificate::from_der(ca_cert.as_der().to_vec()))
        .unwrap();
    let ca = (ca_cert, ca_key);
    Pki {
        roots,
        server: issue(&["localhost"], &ca),
        client: issue(&["alice"], &ca),
    }
}

/// Answers with how many certificates the request carries, the leaf's length, and whether the
/// leaf is the one `want` names.
fn app(want: Vec<u8>) -> Router {
    Router::new().get("/who", move |ctx: &mut Context| {
        let body = match &ctx.req().peer_certificates {
            None => "none".to_owned(),
            Some(chain) => format!("certs={} leaf={}", chain.len(), chain[0] == want),
        };
        ctx.text(200, body);
    })
}

/// An engine with a TLS listener asking for client certificates (verified when given), and a
/// plain one.
fn start(p: &Pki) -> Engine {
    let scfg = ServerConfig::builder(p.server.0.clone(), p.server.1.clone())
        .alpn(["h2", "http/1.1"])
        .client_auth_optional(p.roots.clone())
        .build()
        .unwrap();
    let mut cfg = HttpConfig::default();
    cfg.h2 = Some(H2Config::default());
    let want = p.client.0[0].as_der().to_vec();
    let e = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(500);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .threads(1)
                .serve(Tls::server(
                    scfg,
                    serve_with(cfg.clone(), app(want.clone())),
                )),
        )
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .threads(1)
                .serve(serve_with(cfg, app(want))),
        )
        .client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

fn client_config(p: &Pki, cert: bool, alpn: &str) -> ClientConfig {
    let mut b = ClientConfig::builder().roots(p.roots.clone()).alpn([alpn]);
    if cert {
        b = b.client_cert(p.client.0.clone(), p.client.1.clone());
    }
    b.build().unwrap()
}

/// `GET /who` twice on one HTTP/1.1 connection over TLS (or in the clear, with `None`).
fn h1_who(addr: SocketAddr, tls: Option<&ClientConfig>) -> Vec<String> {
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut s: Box<dyn ReadWrite> = match tls {
        Some(cfg) => Box::new(akio::tls::stream::Stream::client(cfg, "localhost", tcp).unwrap()),
        None => Box::new(tcp),
    };
    s.write_all(b"GET /who HTTP/1.1\r\nHost: x\r\n\r\nGET /who HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    s.flush().unwrap();
    let mut all = Vec::new();
    let mut b = [0u8; 4096];
    loop {
        match s.read(&mut b) {
            Ok(0) => break,
            Ok(n) => all.extend_from_slice(&b[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => panic!("read: {e}"),
        }
    }
    let text = String::from_utf8(all).unwrap();
    text.split("HTTP/1.1 200 OK")
        .skip(1)
        .map(|r| r.split("\r\n\r\n").nth(1).unwrap().to_owned())
        .collect()
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

#[test]
fn http1_requests_carry_the_clients_verified_chain() {
    let p = pki();
    let e = start(&p);
    let (tls, plain) = (e.local_addrs()[0], e.local_addrs()[1]);
    let with = client_config(&p, true, "http/1.1");
    assert_eq!(h1_who(tls, Some(&with)), ["certs=1 leaf=true"; 2]);
    // A resumed session has the chain of the session it resumes.
    assert_eq!(h1_who(tls, Some(&with)), ["certs=1 leaf=true"; 2]);
    let without = client_config(&p, false, "http/1.1");
    assert_eq!(h1_who(tls, Some(&without)), ["none"; 2]);
    assert_eq!(h1_who(plain, None), ["none"; 2]);
    e.shutdown();
    e.wait();
}

#[test]
fn h2_requests_carry_the_clients_verified_chain() {
    let p = pki();
    let e = start(&p);
    let addr = e.local_addrs()[0];
    for (cert, want) in [(true, "certs=1 leaf=true"), (false, "none")] {
        let c = H2Client::dial_blocking(
            &e,
            addr,
            Some((client_config(&p, cert, "h2"), "localhost")),
            H2Options::default(),
        )
        .unwrap();
        for _ in 0..2 {
            let r = c
                .send(ClientRequest::get(&format!(
                    "https://localhost:{}/who",
                    addr.port()
                )))
                .wait()
                .unwrap();
            assert_eq!(String::from_utf8(r.body).unwrap(), want, "cert={cert}");
        }
    }
    // HTTP/2 in the clear (prior knowledge).
    let c = H2Client::dial_blocking(&e, e.local_addrs()[1], None, H2Options::default()).unwrap();
    let r = c
        .send(ClientRequest::get(&format!(
            "http://{}/who",
            e.local_addrs()[1]
        )))
        .wait()
        .unwrap();
    assert_eq!(String::from_utf8(r.body).unwrap(), "none");
    e.shutdown();
    e.wait();
}
