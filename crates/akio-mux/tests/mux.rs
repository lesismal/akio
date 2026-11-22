//! One port, four protocols.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::TcpStream,
    time::Duration,
};

use akio::{Config, Conn, Engine, Handler, Listener, fn_acceptor, tls::Tls};
use akio_http::{
    Context, Router,
    client::ClientRequest,
    h2client::{H2Client, H2Options},
    serve,
};
use akio_mux::{Mux, Rule};

struct Prefixed(&'static [u8]);
impl Handler for Prefixed {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let mut out = self.0.to_vec();
        out.extend_from_slice(data);
        let _ = c.send(&out);
    }
}

fn read_some(s: &mut TcpStream) -> Vec<u8> {
    let mut b = vec![0u8; 4096];
    let n = s.read(&mut b).unwrap();
    b.truncate(n);
    b
}

#[test]
fn tls_http1_http2_custom_prefix_and_fallback_share_a_port() {
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = ck.0.as_der().to_vec();
    let scfg = akio::tls::ServerConfig::builder(
        vec![akio::tls::Certificate::from_der(cert.clone())],
        akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
    .build()
    .unwrap();
    let mux = Mux::new()
        .route(
            Rule::Tls,
            Tls::server(scfg, fn_acceptor(|_c: &Conn<Prefixed>| Prefixed(b"tls:"))),
        )
        .route(
            Rule::Http,
            serve(Router::new().get("/hi", |ctx: &mut Context| ctx.text(200, "http says hi"))),
        )
        .route(
            Rule::Prefix(b"PING".to_vec()),
            fn_acceptor(|_c: &Conn<Prefixed>| Prefixed(b"PONG:")),
        )
        .fallback(fn_acceptor(|_c: &Conn<Prefixed>| Prefixed(b"raw:")));
    let e = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(300);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .threads(2)
                .serve_any(mux),
        )
        .client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];

    // HTTP/1.1
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"GET /hi HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut all = Vec::new();
    s.read_to_end(&mut all).unwrap();
    assert!(String::from_utf8_lossy(&all).ends_with("http says hi"));

    // HTTP/2 prior knowledge through the same route.
    let c = H2Client::dial_blocking(&e, addr, None, H2Options::default()).unwrap();
    let r = c
        .send(ClientRequest::get(&format!("http://{addr}/hi")))
        .wait()
        .unwrap();
    assert_eq!(r.body, b"http says hi");

    // Custom prefix, one byte at a time (the decision waits for enough bytes).
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    for b in b"PI" {
        s.write_all(&[*b]).unwrap();
        std::thread::sleep(Duration::from_millis(20));
    }
    s.write_all(b"NG!").unwrap();
    assert_eq!(read_some(&mut s), b"PONG:PING!");

    // Fallback.
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"\x01\x02hello").unwrap();
    assert_eq!(read_some(&mut s), b"raw:\x01\x02hello");

    // TLS.
    let mut roots = akio::tls::RootCerts::empty();
    roots.add(&akio::tls::Certificate::from_der(cert)).unwrap();
    let ccfg = akio::tls::ClientConfig::builder()
        .roots(roots)
        .build()
        .unwrap();
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut tls = akio::tls::stream::Stream::client(&ccfg, "localhost", tcp).unwrap();
    tls.write_all(b"secret").unwrap();
    let mut b = [0u8; 10];
    tls.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"tls:secret");

    e.shutdown();
    e.wait();
}

fn mux_engine(timeout: Option<Duration>) -> Engine {
    let mux = Mux::new()
        .route(
            Rule::Prefix(b"PING".to_vec()),
            fn_acceptor(|_c: &Conn<Prefixed>| Prefixed(b"PONG:")),
        )
        .fallback(fn_acceptor(|_c: &Conn<Prefixed>| Prefixed(b"raw:")))
        .sniff_timeout(timeout);
    let backend = if std::env::var("AKIO_TEST_BACKEND").as_deref() == Ok("uring") {
        let mut v = akio::UringConfig::default();
        v.strict = true;
        akio::Backend::IoUring(v)
    } else {
        akio::Backend::Epoll
    };
    let e = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(300);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend)
                .serve_any(mux),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

/// Reads to EOF; how long it took, or `None` if the connection stayed open for `within`.
fn closed_within(s: &mut TcpStream, within: Duration) -> Option<Duration> {
    let t0 = std::time::Instant::now();
    s.set_read_timeout(Some(within)).unwrap();
    let mut b = [0u8; 64];
    loop {
        match s.read(&mut b) {
            Ok(0) => return Some(t0.elapsed()),
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return None;
            }
            Err(_) => return Some(t0.elapsed()),
        }
    }
}

/// A silent client, or one that sends an undecided prefix and stops, is closed at the sniff
/// deadline; one that decides in time is routed and outlives it.
#[test]
fn sniff_deadline() {
    let e = mux_engine(Some(Duration::from_millis(300)));
    let addr = e.local_addrs()[0];
    // Silent.
    let mut s = TcpStream::connect(addr).unwrap();
    let t = closed_within(&mut s, Duration::from_secs(5)).expect("closed");
    assert!(t >= Duration::from_millis(250), "{t:?}");
    // Undecided prefix ("PI" could still be "PING"), then nothing.
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(b"PI").unwrap();
    closed_within(&mut s, Duration::from_secs(5)).expect("closed");
    // Trickled, but decided in time (about 150 ms): served, and the deadline no longer applies.
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    for b in b"PIN" {
        s.write_all(&[*b]).unwrap();
        std::thread::sleep(Duration::from_millis(50));
    }
    s.write_all(b"G").unwrap();
    assert_eq!(read_some(&mut s), b"PONG:PING");
    std::thread::sleep(Duration::from_millis(600));
    s.write_all(b"!").unwrap();
    assert_eq!(read_some(&mut s), b"PONG:!");
    e.shutdown();
    e.wait();

    // Without a timeout, a silent client waits.
    let e = mux_engine(None);
    let mut s = TcpStream::connect(e.local_addrs()[0]).unwrap();
    assert_eq!(closed_within(&mut s, Duration::from_millis(800)), None);
    e.shutdown();
    e.wait();
}
