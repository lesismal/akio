//! HTTP/1.1 over TLS 1.3 early data: requests that arrive as 0-RTT carry `Early-Data: 1`
//! (RFC 8470), later ones do not, and the application can answer `425 Too Early`.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use only::{Backend, Engine, Listener, UringConfig, tls::Tls};
use only_http::{Context, Router, serve};

fn backend() -> Backend {
    match std::env::var("ONLY_TEST_BACKEND").as_deref() {
        Ok("uring") => Backend::IoUring({
            let mut v = UringConfig::default();
            v.strict = true;
            v
        }),
        _ => Backend::Epoll,
    }
}

fn app() -> Router {
    Router::new()
        .get("/", |ctx: &mut Context| {
            let e = ctx.header("early-data").unwrap_or("-").to_owned();
            ctx.text(200, format!("early={e}"));
        })
        .post("/pay", |ctx: &mut Context| {
            if ctx.header("early-data") == Some("1") {
                ctx.text(425, "too early");
            } else {
                ctx.text(200, "paid");
            }
        })
}

/// Sends `early` before the handshake (as early data when the ticket allows), `late` after
/// it, and returns everything the server answered.
fn exchange(
    addr: SocketAddr,
    cfg: &only::tls::ClientConfig,
    early: &[u8],
    late: &[u8],
) -> (String, only::tls::EarlyData) {
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut s = only::tls::stream::Stream::client(cfg, "localhost", tcp).unwrap();
    s.write_early(early).unwrap();
    s.handshake().unwrap();
    s.write_all(late).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    (
        String::from_utf8_lossy(&out).into_owned(),
        s.conn().early_data(),
    )
}

#[test]
fn early_requests_are_marked() {
    let ck = only_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = ck.0.as_der().to_vec();
    let scfg = only::tls::ServerConfig::builder(
        vec![only::tls::Certificate::from_der(cert.clone())],
        only::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
    .alpn(["http/1.1"])
    .session_tickets(true)
    .early_data(16384)
    .build()
    .unwrap();
    let engine = Engine::builder()
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .serve(Tls::server(scfg, serve(app()))),
        )
        .build()
        .unwrap();
    engine.start().unwrap();
    let addr = engine.local_addrs()[0];
    let mut roots = only::tls::RootCerts::empty();
    roots.add(&only::tls::Certificate::from_der(cert)).unwrap();
    let ccfg = only::tls::ClientConfig::builder()
        .roots(roots)
        .alpn(["http/1.1"])
        .early_data(true)
        .build()
        .unwrap();
    let get = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    let last = b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    // First connection: no ticket, nothing early.
    let (r, e) = exchange(addr, &ccfg, get, last);
    assert_eq!(e, only::tls::EarlyData::NotAttempted);
    assert_eq!(r.matches("early=-").count(), 2, "{r}");
    // Resumed: the pipelined GET and POST go early, the request after the handshake not.
    let mut early = get.to_vec();
    early.extend_from_slice(b"POST /pay HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\nx");
    let (r, e) = exchange(addr, &ccfg, &early, last);
    assert_eq!(e, only::tls::EarlyData::Accepted);
    let first = r.find("early=1").expect("early GET marked");
    let refused = r.find("HTTP/1.1 425").expect("early POST refused");
    let after = r.find("early=-").expect("later GET not marked");
    assert!(first < refused && refused < after, "{r}");
    engine.shutdown();
    engine.wait();
}
