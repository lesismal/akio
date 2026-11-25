//! ALPN protocols for the handshake only (ADR-123, `ServerConfigBuilder::handshake_only_alpn`):
//! a client that negotiates `acme-tls/1` (RFC 8737) completes the handshake and is closed then,
//! and an HTTP request it sends is never served; a client that negotiates `http/1.1` on the same
//! listener is served as before.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use akio::{Backend, Config, Engine, Listener, UringConfig, tls::Tls};
use akio_http::{Context, HttpConfig, Router, serve_with};

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

struct Server {
    engine: Engine,
    cert: Vec<u8>,
    served: Arc<AtomicUsize>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.engine.shutdown();
        self.engine.wait();
    }
}

fn start() -> Server {
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = ck.0.as_der().to_vec();
    let scfg = akio::tls::ServerConfig::builder(
        vec![akio::tls::Certificate::from_der(cert.clone())],
        akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
    .alpn(["h2", "http/1.1", "acme-tls/1"])
    .handshake_only_alpn(["acme-tls/1"])
    .build()
    .unwrap();
    let served = Arc::new(AtomicUsize::new(0));
    let n = served.clone();
    let app = Router::new().get("/", move |ctx: &mut Context| {
        n.fetch_add(1, Ordering::SeqCst);
        ctx.text(200, "served");
    });
    let engine = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(500);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .threads(1)
                .serve(Tls::server(scfg, serve_with(HttpConfig::default(), app))),
        )
        .build()
        .unwrap();
    engine.start().unwrap();
    Server {
        engine,
        cert,
        served,
    }
}

fn client(s: &Server, alpn: &str) -> akio::tls::stream::Stream<TcpStream> {
    let mut roots = akio::tls::RootCerts::empty();
    roots
        .add(&akio::tls::Certificate::from_der(s.cert.clone()))
        .unwrap();
    let cfg = akio::tls::ClientConfig::builder()
        .roots(roots)
        .alpn([alpn])
        .build()
        .unwrap();
    let addr: SocketAddr = s.engine.local_addrs()[0];
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    akio::tls::stream::Stream::client(&cfg, "localhost", tcp).unwrap()
}

/// Everything the server sends until it closes (or a read fails).
fn read_to_close(t: &mut akio::tls::stream::Stream<TcpStream>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut b = [0u8; 4096];
    loop {
        match t.read(&mut b) {
            Ok(0) => return out,
            Ok(n) => out.extend_from_slice(&b[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                assert_ne!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock,
                    "the server did not close: {e}"
                );
                return out;
            }
        }
    }
}

#[test]
fn acme_tls_connection_is_closed_after_its_handshake() {
    let s = start();
    let mut t = client(&s, "acme-tls/1");
    t.handshake().unwrap();
    assert_eq!(t.conn().alpn(), Some(&b"acme-tls/1"[..]));
    // The challenge's certificate was the handshake's: nothing more is served.
    let _ = t.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let _ = t.flush();
    let got = read_to_close(&mut t);
    assert!(got.is_empty(), "served {:?}", String::from_utf8_lossy(&got));
    assert_eq!(s.served.load(Ordering::SeqCst), 0);

    // The same listener serves a client that negotiates HTTP.
    let mut t = client(&s, "http/1.1");
    t.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    t.flush().unwrap();
    let got = String::from_utf8(read_to_close(&mut t)).unwrap();
    assert!(got.starts_with("HTTP/1.1 200"), "{got}");
    assert!(got.ends_with("served"), "{got}");
    assert_eq!(s.served.load(Ordering::SeqCst), 1);
}

#[test]
fn acme_tls_connection_that_sends_nothing_is_closed() {
    let s = start();
    let mut t = client(&s, "acme-tls/1");
    t.handshake().unwrap();
    // A CA checking the challenge only handshakes: the server closes, unasked.
    assert!(read_to_close(&mut t).is_empty());
    assert_eq!(s.served.load(Ordering::SeqCst), 0);
}
