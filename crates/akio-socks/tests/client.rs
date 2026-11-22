//! The SOCKS client (engine and blocking) against akio-socks' server, a misbehaving proxy and
//! a hand-written UDP relay; the HTTP and WebSocket clients' `socks5h://` / `socks4a://`
//! proxies; the server's SOCKS4 BIND and UDP fragment reassembly; ADR-059: fragments sent both
//! ways, TLS to the proxy.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

use akio::{Backend, Config, Conn, Engine, EngineRef, Handler, Listener, UringConfig};
use akio_socks::{Dest, ProxyRefused, Socks, SocksClient, Version};

fn echo_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming().flatten() {
            thread::spawn(move || {
                let mut s = s;
                let mut b = vec![0u8; 64 << 10];
                loop {
                    match s.read(&mut b) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if s.write_all(&b[..n]).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    a
}

fn udp_echo() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    let a = s.local_addr().unwrap();
    thread::spawn(move || {
        let mut b = vec![0u8; 65_536];
        while let Ok((n, from)) = s.recv_from(&mut b) {
            let _ = s.send_to(&b[..n], from);
        }
    });
    a
}

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

/// A SOCKS server with BIND and UDP ASSOCIATE on, allowed to reach loopback.
fn server(socks: impl FnOnce(Socks) -> Socks) -> Arc<Engine> {
    let er = EngineRef::new();
    let s = socks(
        Socks::new(er.clone())
            .destinations(akio_socks::Destinations::Any)
            .bind(true)
            .bind_timeout(Duration::from_secs(5))
            .udp_associate(true),
    );
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_millis(300);
                v
            })
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .backend(backend())
                    .threads(2)
                    .serve(s),
            )
            .client_threads(if uring() { 0 } else { 2 })
            .udp_client_threads(1)
            .build()
            .unwrap(),
    );
    er.set(&e);
    e.start().unwrap();
    e
}

/// An engine for the client side.
fn client_engine() -> Arc<Engine> {
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_millis(300);
                v
            })
            .client_threads(1)
            .udp_client_threads(1)
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    e
}

fn stop(e: &Arc<Engine>) {
    e.shutdown();
    e.wait();
}

fn roundtrip(s: &mut TcpStream, n: usize) {
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
    let mut w = s.try_clone().unwrap();
    let d2 = data.clone();
    let t = thread::spawn(move || w.write_all(&d2).unwrap());
    let mut got = vec![0; n];
    s.read_exact(&mut got).unwrap();
    t.join().unwrap();
    assert!(got == data, "relayed bytes differ");
}

fn refusal(e: &std::io::Error) -> ProxyRefused {
    e.get_ref()
        .and_then(|r| r.downcast_ref::<ProxyRefused>())
        .cloned()
        .unwrap_or_else(|| panic!("not a refusal: {e:?}"))
}

#[test]
fn blocking_connect_every_version() {
    let echo = echo_server();
    let e = server(|s| s);
    let proxy = e.local_addrs()[0];
    for v in [Version::Socks5, Version::Socks4, Version::Socks4a] {
        let c = SocksClient::new(v, proxy);
        let mut s = c.dial_blocking(&Dest::Addr(echo)).unwrap();
        roundtrip(&mut s, 256 << 10);
        // A host name: sent to SOCKS5/4a proxies, resolved here for SOCKS4.
        let mut s = c
            .dial_blocking(&Dest::Name("localhost".into(), echo.port()))
            .unwrap_or_else(|e| panic!("{v:?}: {e}"));
        roundtrip(&mut s, 1000);
    }
    stop(&e);
}

#[test]
fn blocking_authentication_and_refusals() {
    let echo = echo_server();
    let e = server(|s| {
        s.auth(|u, p| u == "alice" && p == "s3cret")
            .allow(|r| r.dest().port() != 9)
    });
    let proxy = e.local_addrs()[0];
    let url = format!("socks5://alice:s3cret@{proxy}");
    let c = SocksClient::from_url(&url).unwrap();
    assert!(!format!("{c:?}").contains("s3cret"));
    let mut s = c.dial_blocking(&echo.into()).unwrap();
    roundtrip(&mut s, 1 << 20);
    // Refused by the hook: 403-like, reply 2.
    let to: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let r = refusal(&c.dial_blocking(&to.into()).unwrap_err());
    assert_eq!((r.status(), r.socks_reply()), (403, Some(2)));
    // Wrong password, no credentials: 407.
    let bad = SocksClient::new(Version::Socks5, proxy).auth("alice", "nope");
    let e1 = bad.dial_blocking(&echo.into()).unwrap_err();
    assert_eq!(e1.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(refusal(&e1).status(), 407);
    let none = SocksClient::new(Version::Socks5, proxy);
    assert_eq!(
        refusal(&none.dial_blocking(&echo.into()).unwrap_err()).status(),
        407
    );
    // SOCKS4 is off when authentication is required.
    let v4 = SocksClient::new(Version::Socks4, proxy);
    let r = refusal(&v4.dial_blocking(&echo.into()).unwrap_err());
    assert_eq!(r.socks_reply(), Some(0x5b));
    stop(&e);
}

#[test]
fn handshake_timeout_and_garbage() {
    // A "proxy" that accepts and says nothing, one that answers HTTP.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let silent_addr = silent.local_addr().unwrap();
    let http = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_addr = http.local_addr().unwrap();
    thread::spawn(move || {
        // Accepted and held open, never answered.
        let held: Vec<TcpStream> = silent.incoming().flatten().collect();
        drop(held);
    });
    thread::spawn(move || {
        for mut s in http.incoming().flatten() {
            let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        }
    });
    let to: Dest = "10.0.0.1:80".parse::<SocketAddr>().unwrap().into();
    let c = SocksClient::new(Version::Socks5, silent_addr)
        .handshake_timeout(Some(Duration::from_millis(300)));
    let t0 = std::time::Instant::now();
    let err = c.dial_blocking(&to).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
    assert!(t0.elapsed() >= Duration::from_millis(300));
    let c = SocksClient::new(Version::Socks5, http_addr);
    assert_eq!(
        c.dial_blocking(&to).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );

    // On the engine: the deadline closes the connection and reports to on_error; garbage too.
    let ce = client_engine();
    for (proxy, kind) in [
        (silent_addr, std::io::ErrorKind::TimedOut),
        (http_addr, std::io::ErrorKind::InvalidData),
    ] {
        let (tx, rx) = mpsc::channel();
        let tx = Mutex::new(tx);
        let (etx, erx) = mpsc::channel();
        let c = SocksClient::new(Version::Socks5, proxy)
            .handshake_timeout(Some(Duration::from_millis(300)));
        c.dial(
            &ce,
            to.clone(),
            akio::fn_acceptor(move |_c: &Conn<Collect>| Collect {
                got: Vec::new(),
                done: Some(tx.lock().unwrap().clone()),
            }),
            move |e| etx.send(e.kind()).unwrap(),
        );
        assert_eq!(erx.recv_timeout(Duration::from_secs(5)).unwrap(), kind);
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    stop(&ce);
}

/// Collects what the tunnel delivers; reports it (and the close error) when closed.
struct Collect {
    got: Vec<u8>,
    done: Option<mpsc::Sender<(Vec<u8>, Option<String>)>>,
}

impl Handler for Collect {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        self.got.extend_from_slice(data);
        if self.got.ends_with(b"\n") {
            c.close();
        }
    }
    fn on_close(&mut self, _c: &Conn<Self>, err: Option<akio::Error>) {
        if let Some(tx) = self.done.take() {
            let _ = tx.send((std::mem::take(&mut self.got), err.map(|e| format!("{e:?}"))));
        }
    }
}

/// What a `Collect` handler reports: the bytes and the close error.
type Collected = mpsc::Receiver<(Vec<u8>, Option<String>)>;

/// Sends `msg` on open (held until the tunnel is up) and collects the echo.
fn echo_acceptor(msg: &'static [u8]) -> (impl akio::Acceptor<Handler = Collect>, Collected) {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    (
        akio::fn_acceptor(move |c: &Conn<Collect>| {
            c.send(msg).unwrap();
            Collect {
                got: Vec::new(),
                done: Some(tx.lock().unwrap().clone()),
            }
        }),
        rx,
    )
}

#[test]
fn engine_connect_every_version_and_refusal() {
    let echo = echo_server();
    let e = server(|s| s.allow(|r| r.dest().port() != 9));
    let proxy = e.local_addrs()[0];
    let ce = client_engine();
    for (v, to) in [
        (Version::Socks5, Dest::Addr(echo)),
        (Version::Socks5, Dest::Name("localhost".into(), echo.port())),
        (Version::Socks4, Dest::Name("localhost".into(), echo.port())),
        (
            Version::Socks4a,
            Dest::Name("localhost".into(), echo.port()),
        ),
    ] {
        // The proxy by name: resolved off the I/O threads ("localhost" may be ::1 first,
        // where nothing listens: the next address is tried).
        let c = SocksClient::with_host(v, "localhost", proxy.port());
        let (a, rx) = echo_acceptor(b"hello through socks\n");
        c.dial(&ce, to.clone(), a, |e| panic!("dial: {e}"));
        let (got, _) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(got, b"hello through socks\n", "{v:?} {to}");
    }
    // A refusal goes to on_error (the connection to the proxy then closes).
    let c = SocksClient::new(Version::Socks5, proxy);
    let (a, rx) = echo_acceptor(b"x\n");
    let (etx, erx) = mpsc::channel();
    c.dial(
        &ce,
        "127.0.0.1:9".parse::<SocketAddr>().unwrap().into(),
        a,
        move |e| {
            etx.send(e).unwrap();
        },
    );
    let r = refusal(&erx.recv_timeout(Duration::from_secs(5)).unwrap());
    assert_eq!((r.status(), r.socks_reply()), (403, Some(2)));
    let (got, _) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(got.is_empty());
    // Nothing listens at the proxy address: on_error.
    let dead = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let (tx, rx) = mpsc::channel();
    let (a, _rx) = echo_acceptor(b"");
    SocksClient::new(Version::Socks5, dead).dial(&ce, echo.into(), a, move |e| {
        tx.send(e.kind()).unwrap();
    });
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        std::io::ErrorKind::ConnectionRefused
    );
    stop(&ce);
    stop(&e);
}

/// Accepts the BIND peer: connects to the bound address, echoes.
fn peer_echo(bound: SocketAddr) {
    thread::spawn(move || {
        let mut p = TcpStream::connect(bound).unwrap();
        let mut b = vec![0u8; 64 << 10];
        loop {
            match p.read(&mut b) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if p.write_all(&b[..n]).is_err() {
                        return;
                    }
                }
            }
        }
    });
}

#[test]
fn bind_blocking_and_on_the_engine() {
    let e = server(|s| s);
    let proxy = e.local_addrs()[0];
    let any: Dest = "0.0.0.0:0".parse::<SocketAddr>().unwrap().into();
    // Blocking, SOCKS5 and SOCKS4 (the server's new SOCKS4 BIND).
    for v in [Version::Socks5, Version::Socks4, Version::Socks4a] {
        let c = SocksClient::new(v, proxy);
        let b = c.bind_blocking(&any).unwrap();
        let bound = b.bound_addr();
        assert_eq!(bound.ip(), proxy.ip(), "{v:?}");
        peer_echo(bound);
        let (mut s, peer) = b.accept().unwrap();
        assert_eq!(peer.ip(), proxy.ip());
        roundtrip(&mut s, 512 << 10);
    }
    // On the engine.
    let ce = client_engine();
    for v in [Version::Socks5, Version::Socks4] {
        let c = SocksClient::new(v, proxy);
        let (a, rx) = echo_acceptor(b"bound and relayed\n");
        c.bind(&ce, any.clone(), peer_echo, a, |e| panic!("bind: {e}"));
        let (got, _) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(got, b"bound and relayed\n", "{v:?}");
    }
    // Nobody connects: the proxy's failure reply after its bind timeout.
    let short = server(|s| s.bind_timeout(Duration::from_millis(200)));
    let c = SocksClient::new(Version::Socks4, short.local_addrs()[0]);
    let b = c.bind_blocking(&any).unwrap();
    let r = refusal(&b.accept().unwrap_err());
    assert_eq!(r.socks_reply(), Some(0x5b));
    stop(&short);
    stop(&ce);
    stop(&e);
}

#[test]
fn socks4_bind_from_a_stated_address_only() {
    let e = server(|s| s.bind_timeout(Duration::from_millis(400)));
    let proxy = e.local_addrs()[0];
    // Raw SOCKS4 BIND expecting 10.9.8.7: a loopback peer is not taken.
    let mut s = TcpStream::connect(proxy).unwrap();
    s.write_all(&[4, 2, 0, 21, 10, 9, 8, 7, 0]).unwrap();
    let mut r = [0u8; 8];
    s.read_exact(&mut r).unwrap();
    assert_eq!(r[..2], [0, 0x5a]);
    let bound = SocketAddr::from(([r[4], r[5], r[6], r[7]], u16::from_be_bytes([r[2], r[3]])));
    let _stray = TcpStream::connect(bound).unwrap();
    s.read_exact(&mut r).unwrap();
    assert_eq!(r[..2], [0, 0x5b]);
    // BIND off: SOCKS4 BIND is refused like SOCKS5's.
    let off = server(|s| s.bind(false));
    let mut s = TcpStream::connect(off.local_addrs()[0]).unwrap();
    s.write_all(&[4, 2, 0, 21, 0, 0, 0, 0, 0]).unwrap();
    s.read_exact(&mut r).unwrap();
    assert_eq!(r[..2], [0, 0x5b]);
    stop(&off);
    stop(&e);
}

#[test]
fn udp_blocking_and_on_the_engine() {
    let echo = udp_echo();
    let e = server(|s| s);
    let proxy = e.local_addrs()[0];
    let c = SocksClient::new(Version::Socks5, proxy);
    let u = c.udp_associate_blocking().unwrap();
    u.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    assert!(u.is_open());
    let mut b = vec![0u8; 65_536];
    for size in [0, 1, 1400, 8000] {
        let payload: Vec<u8> = (0..size).map(|i| (i % 253) as u8).collect();
        u.send_to(&payload, &echo.into()).unwrap();
        let (n, from) = u.recv_from(&mut b).unwrap();
        assert_eq!((&b[..n], from), (&payload[..], Dest::Addr(echo)));
    }
    drop(u);

    let ce = client_engine();
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let (dtx, drx) = mpsc::channel();
    c.udp_associate(
        &ce,
        move |_a, from, payload| {
            let _ = tx.lock().unwrap().send((from, payload.to_vec()));
        },
        move |r| dtx.send(r).unwrap(),
    );
    let assoc = drx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
    assert!(assoc.relay_addr().is_some() && assoc.is_open());
    assoc.send_to(b"ping", &echo.into()).unwrap();
    let (from, got) = rx.recv_timeout(Duration::from_secs(3)).unwrap();
    assert_eq!((from, got.as_slice()), (Dest::Addr(echo), &b"ping"[..]));
    // The proxy closing the control connection ends it; so does close().
    assoc.close();
    assert!(!assoc.is_open());
    assert!(assoc.send_to(b"x", &echo.into()).is_err());

    // SOCKS4 has no UDP.
    let v4 = SocksClient::new(Version::Socks4, proxy);
    assert_eq!(
        v4.udp_associate_blocking().unwrap_err().kind(),
        std::io::ErrorKind::Unsupported
    );
    stop(&ce);
    stop(&e);
}

fn v4_header(frag: u8, to: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(a) = to else {
        unreachable!()
    };
    let mut h = vec![0, 0, frag, 1];
    h.extend_from_slice(&a.ip().octets());
    h.extend_from_slice(&a.port().to_be_bytes());
    h
}

#[test]
fn server_reassembles_fragments() {
    let echo = udp_echo();
    let e = server(|s| s);
    let proxy = e.local_addrs()[0];
    // A raw association: the client sends fragments itself.
    let mut ctl = TcpStream::connect(proxy).unwrap();
    ctl.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let u = UdpSocket::bind("127.0.0.1:0").unwrap();
    u.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    ctl.write_all(&[5, 1, 0]).unwrap();
    let mut r = [0u8; 2];
    ctl.read_exact(&mut r).unwrap();
    let mut req = vec![5, 3, 0];
    req.extend_from_slice(&v4_header(0, u.local_addr().unwrap())[3..]);
    ctl.write_all(&req).unwrap();
    let mut rep = [0u8; 10];
    ctl.read_exact(&mut rep).unwrap();
    assert_eq!(rep[1], 0);
    let relay = SocketAddr::from((
        [rep[4], rep[5], rep[6], rep[7]],
        u16::from_be_bytes([rep[8], rep[9]]),
    ));
    let send = |frag: u8, p: &[u8]| {
        let mut d = v4_header(frag, echo);
        d.extend_from_slice(p);
        u.send_to(&d, relay).unwrap();
    };
    let mut b = vec![0u8; 65_536];
    // Three fragments: relayed as one datagram.
    send(1, b"frag");
    send(2, b"mented ");
    send(0x83, b"datagram");
    let n = u.recv(&mut b).unwrap();
    assert_eq!(&b[10..n], b"fragmented datagram");
    // A gap drops the sequence; the next one still works.
    send(1, b"a");
    send(3, b"c");
    send(0x84, b"d");
    assert!(u.recv(&mut b).is_err(), "incomplete sequence relayed");
    send(0x81, b"single");
    let n = u.recv(&mut b).unwrap();
    assert_eq!(&b[10..n], b"single");
    // Larger than one datagram may carry: dropped (8000-byte pieces: macOS caps a datagram
    // at 9216 bytes by default).
    let piece = vec![7u8; 8000];
    for i in 1..=8 {
        send(i, &piece);
    }
    send(0x89, &piece);
    assert!(u.recv(&mut b).is_err());
    send(0, b"whole");
    let n = u.recv(&mut b).unwrap();
    assert_eq!(&b[10..n], b"whole");
    stop(&e);
}

/// A minimal SOCKS5 proxy answering one UDP ASSOCIATE with a relay socket that sends what it
/// is given (fragmented by the test) to the client.
fn fragmenting_relay(fragments: Vec<Vec<u8>>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    thread::spawn(move || {
        let (mut s, client) = l.accept().unwrap();
        let mut b = [0u8; 64];
        s.read_exact(&mut b[..3]).unwrap();
        s.write_all(&[5, 0]).unwrap();
        s.read_exact(&mut b[..10]).unwrap();
        let port = u16::from_be_bytes([b[8], b[9]]);
        let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
        let ra = relay.local_addr().unwrap();
        let mut rep = vec![5, 0, 0];
        rep.extend_from_slice(&v4_header(0, ra)[3..]);
        s.write_all(&rep).unwrap();
        thread::sleep(Duration::from_millis(100));
        for f in fragments {
            relay
                .send_to(&f, SocketAddr::new(client.ip(), port))
                .unwrap();
        }
        // Keep the control connection until the client leaves.
        let _ = s.read(&mut b);
    });
    a
}

#[test]
fn client_reassembles_fragments() {
    let from: SocketAddr = "192.0.2.1:53".parse().unwrap();
    let frag = |f: u8, p: &[u8]| {
        let mut d = v4_header(f, from);
        d.extend_from_slice(p);
        d
    };
    let wire = vec![
        frag(1, b"one "),
        frag(2, b"two "),
        frag(0x83, b"three"),
        frag(0, b"whole"),
        frag(1, b"lost "),
        frag(0x83, b"gap"),
    ];
    // Blocking.
    let proxy = fragmenting_relay(wire.clone());
    let u = SocksClient::new(Version::Socks5, proxy)
        .udp_associate_blocking()
        .unwrap();
    u.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut b = [0u8; 64];
    let (n, f) = u.recv_from(&mut b).unwrap();
    assert_eq!((&b[..n], f), (&b"one two three"[..], Dest::Addr(from)));
    let (n, _) = u.recv_from(&mut b).unwrap();
    assert_eq!(&b[..n], b"whole");
    u.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    assert!(u.recv_from(&mut b).is_err(), "gap reassembled");
    drop(u);
    // On the engine.
    let proxy = fragmenting_relay(wire);
    let ce = client_engine();
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let (dtx, drx) = mpsc::channel();
    SocksClient::new(Version::Socks5, proxy).udp_associate(
        &ce,
        move |_a, _from, p| {
            let _ = tx.lock().unwrap().send(p.to_vec());
        },
        move |r| dtx.send(r).unwrap(),
    );
    let a = drx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(3)).unwrap(),
        b"one two three"
    );
    assert_eq!(rx.recv_timeout(Duration::from_secs(3)).unwrap(), b"whole");
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
    a.close();
    stop(&ce);
}

#[test]
fn http_client_through_socks() {
    use akio_http::client::{Client, ClientRequest, Proxy};
    // An HTTP server (with a WebSocket route) on loopback.
    let he = Arc::new(
        Engine::builder()
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .backend(backend())
                    .serve(akio_http::serve(|ctx: &mut akio_http::Context| {
                        ctx.text(200, "via socks");
                    })),
            )
            .build()
            .unwrap(),
    );
    he.start().unwrap();
    let web = he.local_addrs()[0];
    let e = server(|s| s.auth(|u, p| u == "u" && p == "p"));
    let proxy = e.local_addrs()[0];
    let ce = client_engine();
    for url in [
        format!("socks5h://u:p@{proxy}"),
        format!("socks5://u:p@{proxy}"),
    ] {
        let client = Client::new(ce.clone()).with_proxy(Proxy::all(&url).unwrap());
        // `localhost`: by name to the proxy (socks5h) or resolved here first (socks5).
        let r = client
            .send(ClientRequest::get(&format!(
                "http://localhost:{}/",
                web.port()
            )))
            .wait()
            .unwrap_or_else(|e| panic!("{url}: {e:?}"));
        assert_eq!(
            (r.status, r.body.as_slice()),
            (200, &b"via socks"[..]),
            "{url}"
        );
    }
    // A wrong password: the refusal comes back as the client's error.
    let client =
        Client::new(ce.clone()).with_proxy(Proxy::all(&format!("socks5h://u:x@{proxy}")).unwrap());
    let err = client
        .send(ClientRequest::get(&format!(
            "http://127.0.0.1:{}/",
            web.port()
        )))
        .wait()
        .unwrap_err();
    assert!(
        format!("{err:?}").contains("authentication failed"),
        "{err:?}"
    );
    stop(&ce);
    stop(&e);
    stop(&he);
}

#[test]
fn fragments_both_ways() {
    let echo = udp_echo();
    let e = server(|s| s.udp_fragment_size(Some(600)));
    let proxy = e.local_addrs()[0];
    let payload: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
    // A raw association sees the server's fragments: 600-byte pieces, the last marked.
    let mut ctl = TcpStream::connect(proxy).unwrap();
    ctl.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let u = UdpSocket::bind("127.0.0.1:0").unwrap();
    u.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    ctl.write_all(&[5, 1, 0]).unwrap();
    let mut r = [0u8; 2];
    ctl.read_exact(&mut r).unwrap();
    let mut req = vec![5, 3, 0];
    req.extend_from_slice(&v4_header(0, u.local_addr().unwrap())[3..]);
    ctl.write_all(&req).unwrap();
    let mut rep = [0u8; 10];
    ctl.read_exact(&mut rep).unwrap();
    let relay = SocketAddr::from((
        [rep[4], rep[5], rep[6], rep[7]],
        u16::from_be_bytes([rep[8], rep[9]]),
    ));
    let mut d = v4_header(0, echo);
    d.extend_from_slice(&payload);
    u.send_to(&d, relay).unwrap();
    let mut b = vec![0u8; 65_536];
    let mut frags = Vec::new();
    let mut joined = Vec::new();
    for _ in 0..5 {
        let n = u.recv(&mut b).unwrap();
        frags.push(b[2]);
        assert!(n - 10 <= 600);
        joined.extend_from_slice(&b[10..n]);
    }
    assert_eq!(frags, [1, 2, 3, 4, 0x85]);
    assert_eq!(joined, payload);
    // Small ones stay whole.
    let mut d = v4_header(0, echo);
    d.extend_from_slice(b"small");
    u.send_to(&d, relay).unwrap();
    let n = u.recv(&mut b).unwrap();
    assert_eq!((b[2], &b[10..n]), (0, &b"small"[..]));
    drop(ctl);

    // The client sends in fragments, the server reassembles, the echo comes back in
    // fragments, the client reassembles.
    let c = SocksClient::new(Version::Socks5, proxy);
    let bu = c.udp_associate_blocking().unwrap();
    bu.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    bu.send_fragmented(&payload, &echo.into(), 700).unwrap();
    let (n, from) = bu.recv_from(&mut b).unwrap();
    assert_eq!((&b[..n], from), (&payload[..], Dest::Addr(echo)));
    assert_eq!(
        bu.send_fragmented(&payload, &echo.into(), 10)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput,
        "more than 127 fragments"
    );
    drop(bu);
    // On the engine.
    let ce = client_engine();
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let (dtx, drx) = mpsc::channel();
    c.udp_associate(
        &ce,
        move |_a, _from, p| {
            let _ = tx.lock().unwrap().send(p.to_vec());
        },
        move |r| dtx.send(r).unwrap(),
    );
    let a = drx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
    a.send_fragmented(&payload, &echo.into(), 1000).unwrap();
    assert_eq!(rx.recv_timeout(Duration::from_secs(3)).unwrap(), payload);
    a.send_fragmented(b"tiny", &echo.into(), 1000).unwrap();
    assert_eq!(rx.recv_timeout(Duration::from_secs(3)).unwrap(), b"tiny");
    a.close();
    stop(&ce);
    stop(&e);
}

#[test]
fn tls_to_the_proxy() {
    let echo = echo_server();
    let udp = udp_echo();
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = ck.0.as_der().to_vec();
    let scfg = akio::tls::ServerConfig::builder(
        vec![akio::tls::Certificate::from_der(cert.clone())],
        akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
    .build()
    .unwrap();
    let mut roots = akio::tls::RootCerts::empty();
    roots.add(&akio::tls::Certificate::from_der(cert)).unwrap();
    let ccfg = akio::tls::ClientConfig::builder()
        .roots(roots)
        .build()
        .unwrap();
    // akio-socks' server behind TLS.
    let er = EngineRef::new();
    let socks = Socks::new(er.clone())
        .destinations(akio_socks::Destinations::Any)
        .auth(|u, p| u == "u" && p == "p")
        .udp_associate(true);
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_millis(300);
                v
            })
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .backend(backend())
                    .serve(akio::tls::Tls::server(scfg, socks)),
            )
            .client_threads(usize::from(!uring()))
            .udp_client_threads(1)
            .build()
            .unwrap(),
    );
    er.set(&e);
    e.start().unwrap();
    let proxy = e.local_addrs()[0];
    let ce = client_engine();
    let c = SocksClient::with_host(Version::Socks5, "localhost", proxy.port())
        .auth("u", "p")
        .tls(ccfg.clone(), None);
    let (a, rx) = echo_acceptor(b"over tls to the proxy\n");
    c.dial(&ce, echo.into(), a, |e| panic!("dial: {e}"));
    let (got, _) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(got, b"over tls to the proxy\n");
    // UDP ASSOCIATE: the control connection over TLS, datagrams plain.
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let (dtx, drx) = mpsc::channel();
    c.udp_associate(
        &ce,
        move |_a, _from, p| {
            let _ = tx.lock().unwrap().send(p.to_vec());
        },
        move |r| dtx.send(r).unwrap(),
    );
    let assoc = drx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
    assoc.send_to(b"udp ping", &udp.into()).unwrap();
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(3)).unwrap(),
        b"udp ping"
    );
    assoc.close();
    // A name the certificate does not cover: the dial fails.
    let wrong = SocksClient::new(Version::Socks5, proxy)
        .auth("u", "p")
        .tls(ccfg, Some("other.example"));
    let (a, rx) = echo_acceptor(b"x\n");
    let (etx, erx) = mpsc::channel();
    wrong.dial(&ce, echo.into(), a, move |e| {
        let _ = etx.send(e);
    });
    // The failure is the dial's: before the tunnel opened.
    let err = erx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
    let (got, _) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(got.is_empty());
    // Without TLS the TLS-only proxy does not answer as SOCKS.
    let plain = SocksClient::new(Version::Socks5, proxy)
        .auth("u", "p")
        .handshake_timeout(Some(Duration::from_millis(300)));
    assert!(plain.dial_blocking(&echo.into()).is_err());
    // The blocking helpers cannot carry TLS.
    assert_eq!(
        c.dial_blocking(&echo.into()).unwrap_err().kind(),
        std::io::ErrorKind::Unsupported
    );
    assert_eq!(
        c.udp_associate_blocking().unwrap_err().kind(),
        std::io::ErrorKind::Unsupported
    );
    stop(&ce);
    stop(&e);
}
