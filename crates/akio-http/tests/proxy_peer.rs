//! A request's peer behind akio-mux's PROXY protocol layer (ADR-118): the client a trusted
//! header names, over HTTP/1.1, HTTP/2 with prior knowledge, an `h2c` upgrade and TLS; the
//! socket's peer for a header naming none (`UNKNOWN`, `LOCAL`) and for an untrusted peer.
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
use akio_http::{Context, H2Config, HttpConfig, Router, serve_with};
use akio_mux::proxy::ProxyProtocol;
use akio_x509::generate_simple_self_signed;

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

/// A router answering each request with its peer and `Context::peer`.
fn router() -> Router {
    Router::new().get("/", |ctx: &mut Context| {
        let body = format!("{}|{}", ctx.req().peer, ctx.peer());
        ctx.text(200, body);
    })
}

fn http_config() -> HttpConfig {
    let mut cfg = HttpConfig::default();
    cfg.h2 = Some(H2Config::default());
    cfg
}

/// An engine serving HTTP behind the PROXY layer, which trusts peers for which `trusted` says
/// so; with `tls`, HTTPS behind it.
fn engine(trusted: fn(SocketAddr) -> bool, tls: Option<ServerConfig>) -> (Engine, SocketAddr) {
    let http = serve_with(http_config(), router());
    let pp = match tls {
        Some(cfg) => ProxyProtocol::new(Tls::server(cfg, http)),
        None => ProxyProtocol::new(http),
    }
    .trusted(trusted)
    .header_timeout(Some(Duration::from_secs(5)));
    let e = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(300);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .serve_any(pp),
        )
        .client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    (e, addr)
}

/// Sends `wire`, reads the response until the server closes, and returns its body.
fn exchange(addr: SocketAddr, wire: &[u8]) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(wire).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out).into_owned();
    match text.split_once("\r\n\r\n") {
        Some((_, body)) => body.to_owned(),
        None => panic!("no response: {text:?}"),
    }
}

const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";

fn with(header: &[u8], rest: &[u8]) -> Vec<u8> {
    let mut v = header.to_vec();
    v.extend_from_slice(rest);
    v
}

#[test]
fn http1_peer_is_the_header_source() {
    let (e, addr) = engine(|_| true, None);
    let v1 = b"PROXY TCP4 203.0.113.9 198.51.100.1 5555 80\r\n";
    assert_eq!(
        exchange(addr, &with(v1, GET)),
        "203.0.113.9:5555|203.0.113.9:5555"
    );
    let v2 = akio_mux::proxy::ProxyHeader::proxy(
        "[2001:db8::9]:5555".parse().unwrap(),
        "[2001:db8::1]:80".parse().unwrap(),
    )
    .encode_v2()
    .unwrap();
    assert_eq!(
        exchange(addr, &with(&v2, GET)),
        "[2001:db8::9]:5555|[2001:db8::9]:5555"
    );
    // A header naming no address leaves the socket's peer.
    for none in [
        b"PROXY UNKNOWN\r\n".to_vec(),
        akio_mux::proxy::ProxyHeader::local().encode_v2().unwrap(),
    ] {
        let body = exchange(addr, &with(&none, GET));
        assert!(body.starts_with("127.0.0.1:"), "{body}");
    }
    e.shutdown();
    e.wait();
}

#[test]
fn untrusted_peer_is_its_own() {
    let (e, addr) = engine(|a| !a.ip().is_loopback(), None);
    // The layer is skipped for an untrusted peer: its request is the socket's.
    let body = exchange(addr, GET);
    assert!(body.starts_with("127.0.0.1:"), "{body}");
    e.shutdown();
    e.wait();
}

/// Reads from `s` until `want` shows up or the server stops sending.
fn read_until(s: &mut impl Read, want: &str) -> String {
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while !String::from_utf8_lossy(&got).contains(want) {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8_lossy(&got).into_owned()
}

#[test]
fn h2_peer_is_the_header_source() {
    let (e, addr) = engine(|_| true, None);
    let header = b"PROXY TCP4 203.0.113.7 198.51.100.1 4444 80\r\n";
    // HTTP/2 with prior knowledge: the preface, empty SETTINGS, and a GET of / on stream 1
    // (HPACK: :method GET, :scheme http, :path /, :authority "x").
    let mut wire = header.to_vec();
    wire.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    wire.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    wire.extend_from_slice(&[0, 0, 6, 1, 5, 0, 0, 0, 1, 0x82, 0x86, 0x84, 0x41, 1, b'x']);
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(&wire).unwrap();
    let text = read_until(&mut s, "203.0.113.7:4444|203.0.113.7:4444");
    assert!(
        text.contains("203.0.113.7:4444|203.0.113.7:4444"),
        "{text:?}"
    );
    // The h2c upgrade from HTTP/1.1.
    let upgrade = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, HTTP2-Settings\r\n\
                    Upgrade: h2c\r\nHTTP2-Settings: \r\n\r\n";
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(&with(header, upgrade)).unwrap();
    let text = read_until(&mut s, "203.0.113.7:4444|203.0.113.7:4444");
    assert!(text.starts_with("HTTP/1.1 101"), "{text:?}");
    assert!(
        text.contains("203.0.113.7:4444|203.0.113.7:4444"),
        "{text:?}"
    );
    e.shutdown();
    e.wait();
}

#[test]
fn https_peer_is_the_header_source() {
    let (cert, key) = generate_simple_self_signed(["localhost"]).unwrap();
    let leaf = Certificate::from_der(cert.as_der().to_vec());
    let mut roots = RootCerts::empty();
    roots.add(&leaf).unwrap();
    let scfg = ServerConfig::builder(vec![leaf], PrivateKey::from_pkcs8_der(key.to_pkcs8_der()))
        .alpn(["http/1.1"])
        .build()
        .unwrap();
    let (e, addr) = engine(|_| true, Some(scfg));
    // The header in the clear, then TLS.
    let mut tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    tcp.write_all(b"PROXY TCP4 203.0.113.5 198.51.100.1 3333 443\r\n")
        .unwrap();
    let ccfg = ClientConfig::builder()
        .roots(roots)
        .alpn(["http/1.1"])
        .build()
        .unwrap();
    let mut s = akio::tls::stream::Stream::client(&ccfg, "localhost", tcp).unwrap();
    s.write_all(GET).unwrap();
    s.flush().unwrap();
    let text = read_until(&mut s, "203.0.113.5:3333|203.0.113.5:3333");
    assert!(
        text.contains("203.0.113.5:3333|203.0.113.5:3333"),
        "{text:?}"
    );
    e.shutdown();
    e.wait();
}
