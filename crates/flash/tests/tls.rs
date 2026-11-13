//! TLS end to end: a rustls client talks to flash servers, and flash dials flash.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use flash::{
    Config, Conn, Engine, Error, Handler, Listener, fn_acceptor,
    tls::{Tls, rustls, tls_info},
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};

struct Pki {
    cert: CertificateDer<'static>,
    key: Vec<u8>,
}

fn pki() -> Pki {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    Pki {
        cert: ck.cert.der().clone(),
        key: ck.key_pair.serialize_der(),
    }
}

fn server_cfg(p: &Pki, alpn: &[&[u8]]) -> Arc<ServerConfig> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(p.key.clone()));
    let mut c = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![p.cert.clone()], key)
        .unwrap();
    c.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Arc::new(c)
}

fn client_cfg(trust: &CertificateDer<'static>, alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(trust.clone()).unwrap();
    let mut c = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Arc::new(c)
}

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn quick() -> Config {
    Config {
        shutdown_timeout: Duration::from_millis(300),
        ..Config::default()
    }
}

fn tls_client(
    addr: SocketAddr,
    cfg: Arc<ClientConfig>,
) -> StreamOwned<ClientConnection, TcpStream> {
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let conn = ClientConnection::new(cfg, ServerName::try_from("localhost").unwrap()).unwrap();
    StreamOwned::new(conn, tcp)
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

struct Echo;
impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
}

fn echo_engine(p: &Pki, alpn: &[&[u8]]) -> Engine {
    let e = Engine::builder()
        .config(quick())
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(2)
                .serve(Tls::server(
                    server_cfg(p, alpn),
                    fn_acceptor(|_c: &Conn<Echo>| Echo),
                )),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

#[test]
fn echo_over_tls_small_and_large() {
    let p = pki();
    let e = echo_engine(&p, &[]);
    let mut c = tls_client(e.local_addrs()[0], client_cfg(&p.cert, &[]));
    c.write_all(b"hello tls").unwrap();
    let mut b = [0u8; 9];
    c.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"hello tls");

    // 3 MiB: many records, backpressure, partial writes. Writer and reader run concurrently.
    let data: Vec<u8> = (0..3 << 20).map(|i| (i * 31 % 251) as u8).collect();
    // One stream cannot be split, so interleave: write in chunks, and read back once a fair
    // amount is outstanding, so neither side stalls on full buffers.
    let mut got = Vec::with_capacity(data.len());
    let mut sent = 0;
    let mut buf = vec![0u8; 64 << 10];
    while got.len() < data.len() {
        if sent < data.len() {
            let n = (data.len() - sent).min(32 << 10);
            c.write_all(&data[sent..sent + n]).unwrap();
            sent += n;
        }
        // Read what has come back so far (blocks until at least one record arrives).
        // Keep the outstanding amount well below the kernel socket buffers (macOS has small
        // ones): a client that stops reading while the server's echo cannot be written, and a
        // server that pauses reading because of that backpressure, would deadlock each other.
        if sent - got.len() >= 64 << 10 || sent == data.len() {
            let n = c.read(&mut buf).unwrap();
            got.extend_from_slice(&buf[..n]);
        }
    }
    assert_eq!(got.len(), data.len());
    assert!(got == data, "payload corrupted");
    stop(&e);
}

#[test]
fn alpn_and_sni_are_visible_to_the_handler() {
    struct Who;
    impl Handler for Who {
        fn on_data(&mut self, c: &Conn<Self>, _d: &[u8]) {
            let i = tls_info(c).expect("tls connection");
            let msg = format!(
                "alpn={} sni={} hs={} v={}",
                String::from_utf8_lossy(&i.alpn.clone().unwrap_or_default()),
                i.server_name.unwrap_or_default(),
                i.handshaking,
                i.version.unwrap_or_default()
            );
            let _ = c.send(msg.as_bytes());
        }
    }
    let p = pki();
    let e = Engine::builder()
        .config(quick())
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve(Tls::server(
                    server_cfg(&p, &[b"h2", b"http/1.1"]),
                    fn_acceptor(|_c: &Conn<Who>| Who),
                )),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let mut c = tls_client(e.local_addrs()[0], client_cfg(&p.cert, &[b"h2"]));
    c.write_all(b"?").unwrap();
    let mut b = vec![0u8; 64];
    let n = c.read(&mut b).unwrap();
    let s = String::from_utf8_lossy(&b[..n]).to_string();
    assert_eq!(s, "alpn=h2 sni=localhost hs=false v=TLSv1_3");
    stop(&e);
}

#[test]
fn plaintext_garbage_and_untrusted_servers_are_rejected() {
    let p = pki();
    let e = echo_engine(&p, &[]);
    let addr = e.local_addrs()[0];

    // A plaintext client gets dropped, not echoed.
    let mut raw = TcpStream::connect(addr).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    raw.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    let mut buf = [0u8; 256];
    let mut total = 0;
    loop {
        match raw.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n, // at most a TLS alert record
        }
    }
    assert!(total < 32, "server answered garbage with {total} bytes");

    // A client that does not trust the certificate refuses to talk.
    let other = pki();
    let mut c = tls_client(addr, client_cfg(&other.cert, &[]));
    assert!(c.write_all(b"x").is_err() || c.read(&mut [0u8; 1]).is_err());
    stop(&e);
}

#[test]
fn spawn_blocking_and_ordered_slots_work_over_tls() {
    struct H;
    impl Handler for H {
        fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
            for &b in data {
                let slot = c.reserve_response().unwrap();
                let delay = (10 - b as u64) * 5;
                c.spawn_blocking(
                    move || {
                        thread::sleep(Duration::from_millis(delay));
                        slot.fill(vec![b'a' + b]);
                    },
                    |_, _, ()| {},
                )
                .unwrap();
            }
        }
    }
    let p = pki();
    let e = Engine::builder()
        .config(quick())
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(2)
                .serve(Tls::server(
                    server_cfg(&p, &[]),
                    fn_acceptor(|_c: &Conn<H>| H),
                )),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let mut c = tls_client(e.local_addrs()[0], client_cfg(&p.cert, &[]));
    c.write_all(&(0..10).collect::<Vec<u8>>()).unwrap();
    let mut got = vec![0u8; 10];
    c.read_exact(&mut got).unwrap();
    assert_eq!(got, b"abcdefghij");
    stop(&e);
}

#[test]
fn flash_dials_flash_over_tls() {
    let p = pki();
    let server = echo_engine(&p, &[]);
    let addr = server.local_addrs()[0];

    struct Client(Arc<Mutex<Vec<u8>>>);
    impl Handler for Client {
        fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
            self.0.lock().unwrap().extend_from_slice(data);
        }
    }
    struct ClientAcceptor(Arc<Mutex<Vec<u8>>>);
    impl flash::Acceptor for ClientAcceptor {
        type Handler = Client;
        fn on_open(&self, c: &Conn<Client>) -> Client {
            // Sent before the handshake finished: must be held back, then delivered.
            c.send(b"ping over tls").unwrap();
            Client(self.0.clone())
        }
    }
    let got = Arc::new(Mutex::new(Vec::new()));
    let client = Engine::builder()
        .config(quick())
        .client_threads(1)
        .build()
        .unwrap();
    client.start().unwrap();
    let acceptor = Tls::client(
        client_cfg(&p.cert, &[]),
        "localhost",
        ClientAcceptor(got.clone()),
    )
    .unwrap();
    client.dial(addr, acceptor, |e| panic!("dial failed: {e}"));
    let t = std::time::Instant::now();
    while got.lock().unwrap().len() < 13 {
        assert!(t.elapsed() < Duration::from_secs(10), "no echo through TLS");
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(&*got.lock().unwrap(), b"ping over tls");
    stop(&client);
    stop(&server);
}

#[test]
fn local_close_after_send_ends_with_close_notify() {
    struct Bye;
    impl Handler for Bye {
        fn on_data(&mut self, c: &Conn<Self>, _d: &[u8]) {
            let _ = c.send(b"bye");
            c.close_after_send();
        }
        fn on_close(&mut self, _c: &Conn<Self>, err: Option<Error>) {
            assert!(err.is_none());
        }
    }
    let p = pki();
    let e = Engine::builder()
        .config(quick())
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve(Tls::server(
                    server_cfg(&p, &[]),
                    fn_acceptor(|_c: &Conn<Bye>| Bye),
                )),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let mut c = tls_client(e.local_addrs()[0], client_cfg(&p.cert, &[]));
    c.write_all(b"x").unwrap();
    let mut all = Vec::new();
    // A clean close_notify makes read_to_end succeed; a bare FIN would be an UnexpectedEof error.
    c.read_to_end(&mut all).expect("close_notify before FIN");
    assert_eq!(all, b"bye");
    stop(&e);
}
