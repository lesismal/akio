//! The engine's graceful shutdown ends what the proxies and the client hold open (a follow-up
//! of akit's A301): SOCKS sessions (tunnels, handshakes, UDP associations), HTTP `CONNECT`
//! tunnels on HTTP/1.1 and on an HTTP/2 stream, and the client's UDP association, so none of
//! them holds `Engine::wait` until a long `shutdown_timeout`. `AKIO_TEST_BACKEND=uring` serves
//! the proxies on io_uring.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};

use akio::{Backend, Config, Engine, EngineRef, Listener, UringConfig};
use akio_http::{
    H2Config, HttpConfig, Method,
    client::ClientRequest,
    h2client::{H2Client, H2Event, H2Options},
    serve_with,
};
use akio_socks::{Destinations, ProxyConfig, Socks, SocksClient, Version, connect_proxy_with};

const WAIT: Duration = Duration::from_secs(10);

/// Far longer than any test may take: an engine that sits it out fails the test.
const LONG: Duration = Duration::from_secs(20);

fn uring() -> bool {
    std::env::var("AKIO_TEST_BACKEND").as_deref() == Ok("uring")
}

fn backend() -> Backend {
    if uring() {
        let mut v = UringConfig::default();
        v.strict = true;
        Backend::IoUring(v)
    } else {
        Backend::Epoll
    }
}

/// A thread-per-connection echo server; each connection's end is reported on `closed`.
fn echo_server(closed: mpsc::Sender<()>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming().flatten() {
            let closed = closed.clone();
            thread::spawn(move || {
                let mut s = s;
                let mut b = vec![0u8; 64 << 10];
                loop {
                    match s.read(&mut b) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&b[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = closed.send(());
            });
        }
    });
    a
}

/// An engine serving `l` with the long shutdown timeout.
fn proxy_engine(l: Listener, er: &EngineRef) -> Arc<Engine> {
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = LONG;
                v
            })
            .listen(l.backend(backend()).threads(2))
            // Client threads are always epoll; on io_uring, upstreams share the listener's.
            .client_threads(if uring() { 0 } else { 2 })
            .udp_client_threads(1)
            .build()
            .unwrap(),
    );
    er.set(&e);
    e.start().unwrap();
    e
}

/// Shuts `e` down and waits for it, which must take far less than its shutdown timeout.
fn stop_promptly(e: &Engine) {
    let t0 = Instant::now();
    e.shutdown();
    e.wait();
    assert!(t0.elapsed() < WAIT, "engine wait took {:?}", t0.elapsed());
}

fn connect(a: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(a).unwrap();
    s.set_read_timeout(Some(WAIT)).unwrap();
    s
}

fn read_n(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut b = vec![0; n];
    s.read_exact(&mut b).unwrap();
    b
}

/// Reads until EOF (or a reset); what came before it.
fn read_to_eof(s: &mut TcpStream) -> Vec<u8> {
    let mut all = Vec::new();
    let mut b = [0u8; 4096];
    loop {
        match s.read(&mut b) {
            Ok(0) => return all,
            Ok(n) => all.extend_from_slice(&b[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                panic!("still open after {WAIT:?}")
            }
            Err(_) => return all,
        }
    }
}

fn ipv4(a: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(v4) = a else {
        unreachable!()
    };
    let mut t = vec![1];
    t.extend_from_slice(&v4.ip().octets());
    t.extend_from_slice(&a.port().to_be_bytes());
    t
}

/// A SOCKS5 greeting without authentication, answered.
fn greet(proxy: SocketAddr) -> TcpStream {
    let mut s = connect(proxy);
    s.write_all(&[5, 1, 0]).unwrap();
    assert_eq!(read_n(&mut s, 2), [5, 0]);
    s
}

/// Sends a SOCKS5 request and reads its reply (an IPv4 address in it): the reply code.
fn request(s: &mut TcpStream, cmd: u8, target: &[u8]) -> u8 {
    let mut req = vec![5, cmd, 0];
    req.extend_from_slice(target);
    s.write_all(&req).unwrap();
    let r = read_n(s, 10);
    assert_eq!(r[3], 1, "{r:?}");
    r[1]
}

/// A SOCKS server's engine shuts down at once with a tunnel (idle after a round trip), a
/// client still negotiating, a BIND waiting for its connection and a UDP association's control
/// connection open: each client sees its connection end, and the tunnel's upstream is closed
/// too.
#[test]
fn socks_sessions_end_at_the_engine_shutdown() {
    let (ctx, closed) = mpsc::channel();
    let echo = echo_server(ctx);
    let er = EngineRef::new();
    let socks = Socks::new(er.clone())
        .destinations(Destinations::Any)
        .bind(true)
        .udp_associate(true);
    let e = proxy_engine(
        Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(socks),
        &er,
    );
    let proxy = e.local_addrs()[0];

    let mut tunnel = greet(proxy);
    assert_eq!(request(&mut tunnel, 1, &ipv4(echo)), 0);
    tunnel.write_all(b"ping").unwrap();
    assert_eq!(read_n(&mut tunnel, 4), b"ping");

    let mut negotiating = greet(proxy);

    let mut binding = greet(proxy);
    assert_eq!(request(&mut binding, 2, &ipv4(echo)), 0);

    let mut control = greet(proxy);
    let unspecified = ipv4("0.0.0.0:0".parse().unwrap());
    assert_eq!(request(&mut control, 3, &unspecified), 0);

    stop_promptly(&e);
    assert!(read_to_eof(&mut tunnel).is_empty());
    assert!(read_to_eof(&mut negotiating).is_empty());
    assert!(read_to_eof(&mut binding).is_empty());
    assert!(read_to_eof(&mut control).is_empty());
    closed.recv_timeout(WAIT).expect("the upstream closed");
}

/// The same for an HTTP `CONNECT` tunnel on HTTP/1.1.
#[test]
fn http_connect_tunnel_ends_at_the_engine_shutdown() {
    let (ctx, closed) = mpsc::channel();
    let echo = echo_server(ctx);
    let er = EngineRef::new();
    let mut cfg = ProxyConfig::default();
    cfg.destinations = Destinations::Any;
    let e = proxy_engine(
        Listener::tcp("127.0.0.1:0".parse().unwrap())
            .serve(akio_http::serve(connect_proxy_with(er.clone(), cfg))),
        &er,
    );
    let mut s = connect(e.local_addrs()[0]);
    s.write_all(format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n").as_bytes())
        .unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut b).unwrap();
        head.push(b[0]);
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
    s.write_all(b"ping").unwrap();
    assert_eq!(read_n(&mut s, 4), b"ping");

    stop_promptly(&e);
    assert!(read_to_eof(&mut s).is_empty());
    closed.recv_timeout(WAIT).expect("the upstream closed");
}

/// The same for a `CONNECT` on an HTTP/2 stream: the proxy's connection goes away once the
/// tunnel's upstream is closed, which ends the stream.
#[test]
fn h2_connect_tunnel_ends_at_the_engine_shutdown() {
    let (ctx, closed) = mpsc::channel();
    let echo = echo_server(ctx);
    let er = EngineRef::new();
    let mut cfg = ProxyConfig::default();
    cfg.destinations = Destinations::Any;
    let mut hc = HttpConfig::default();
    hc.h2 = Some(H2Config::default());
    let e = proxy_engine(
        Listener::tcp("127.0.0.1:0".parse().unwrap())
            .serve(serve_with(hc, connect_proxy_with(er.clone(), cfg))),
        &er,
    );
    let proxy = e.local_addrs()[0];
    let client = Engine::builder().client_threads(1).build().unwrap();
    client.start().unwrap();
    let c = H2Client::dial_blocking(&client, proxy, None, H2Options::default()).unwrap();
    let mut req = ClientRequest::get(&format!("http://{proxy}/"));
    req.method = Method::Connect;
    req.headers.set("host", echo.to_string());
    let (tx, rx) = mpsc::channel();
    let up = c.open(req, move |ev| {
        let _ = tx.send(match ev {
            H2Event::Head { status, .. } => format!("head {status}"),
            H2Event::Data(d) => format!("data {}", String::from_utf8_lossy(d)),
            H2Event::Trailers(_) => "trailers".into(),
            H2Event::End => "end".into(),
            H2Event::Error(e) => format!("error {e}"),
        });
    });
    assert_eq!(rx.recv_timeout(WAIT).unwrap(), "head 200");
    assert!(up.write(b"ping"));
    assert_eq!(rx.recv_timeout(WAIT).unwrap(), "data ping");

    stop_promptly(&e);
    closed.recv_timeout(WAIT).expect("the upstream closed");
    // The stream ends (its last DATA may be empty), or fails with the connection.
    loop {
        match rx.recv_timeout(WAIT).unwrap().as_str() {
            "data " => {}
            "end" => break,
            ev if ev.starts_with("error") => break,
            ev => panic!("{ev}"),
        }
    }
    c.close();
    client.shutdown();
    client.wait();
}

/// The client's UDP association ends at its engine's shutdown: the control connection to the
/// proxy is closed, so it does not hold `Engine::wait`, and the association is over.
#[test]
fn client_udp_association_ends_at_the_engine_shutdown() {
    let er = EngineRef::new();
    let socks = Socks::new(er.clone())
        .destinations(Destinations::Any)
        .udp_associate(true);
    let server = proxy_engine(
        Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(socks),
        &er,
    );
    let proxy = server.local_addrs()[0];
    let ce = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = LONG;
                v
            })
            .client_threads(1)
            .udp_client_threads(1)
            .build()
            .unwrap(),
    );
    ce.start().unwrap();
    let (dtx, drx) = mpsc::channel();
    SocksClient::new(Version::Socks5, proxy).udp_associate(
        &ce,
        |_a, _from, _payload| {},
        move |r| dtx.send(r).unwrap(),
    );
    let assoc = drx.recv_timeout(WAIT).unwrap().unwrap();
    assert!(assoc.is_open());

    stop_promptly(&ce);
    assert!(!assoc.is_open());
    stop_promptly(&server);
}
