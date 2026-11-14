//! One port, four protocols.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
    time::Duration,
};

use flash::{
    Config, Conn, Engine, Handler, Listener, fn_acceptor,
    tls::{Tls, rustls},
};
use flash_http::{
    Context, Router,
    client::ClientRequest,
    h2client::{H2Client, H2Options},
    serve,
};
use flash_mux::{Mux, Rule};

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
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert = ck.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        ck.key_pair.serialize_der(),
    ));
    let scfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    let mux = Mux::new()
        .route(
            Rule::Tls,
            Tls::server(
                Arc::new(scfg),
                fn_acceptor(|_c: &Conn<Prefixed>| Prefixed(b"tls:")),
            ),
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
    let c = H2Client::connect_blocking(&e, addr, None, H2Options::default()).unwrap();
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
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let ccfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let conn = rustls::ClientConnection::new(
        Arc::new(ccfg),
        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    tls.write_all(b"secret").unwrap();
    let mut b = [0u8; 10];
    tls.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"tls:secret");

    e.shutdown();
    e.wait();
}
