//! GSS-API authentication (RFC 1961, ADR-071) between akio-socks' client and server, with the
//! test mechanism `akio_ws::gss::toy`: every protection level, large tunnels both ways, TLS to
//! the target inside a protected tunnel, BIND, UDP ASSOCIATE with wrapped datagrams (engine and
//! blocking clients, fragments), refusals, the access hook's user name, what is refused
//! (blocking `CONNECT` with protection), and the RFC 1961 messages on the wire.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

use akio::{Backend, Config, Conn, Engine, EngineRef, Handler, Listener, UringConfig};
use akio_socks::{
    Dest, ProxyRefused, Socks, SocksClient, Version,
    gssapi::{GssContext, Protection},
};
use akio_ws::gss::toy::Toy;

const SECRET: u8 = 0x42;

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

/// A UDP echo server on the loopback interface.
fn udp_echo_server() -> SocketAddr {
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

fn config() -> Config {
    let mut v = Config::default();
    v.shutdown_timeout = Duration::from_millis(300);
    v
}

/// A GSS-API SOCKS server (toy acceptor) granting at least `min`.
fn server(min: Protection, more: impl FnOnce(Socks) -> Socks) -> Arc<Engine> {
    server_levels(min..=Protection::Confidentiality, more)
}

/// A GSS-API SOCKS server (toy acceptor) granting `levels`.
fn server_levels(
    levels: std::ops::RangeInclusive<Protection>,
    more: impl FnOnce(Socks) -> Socks,
) -> Arc<Engine> {
    let er = EngineRef::new();
    let s = more(
        Socks::new(er.clone())
            .destinations(akio_socks::Destinations::Any)
            .bind(true)
            .udp_associate(true)
            .gssapi(
                || Ok(Box::new(Toy::acceptor(SECRET)) as Box<dyn GssContext>),
                levels,
            ),
    );
    let e = Arc::new(
        Engine::builder()
            .config(config())
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

fn client_engine() -> Arc<Engine> {
    let e = Arc::new(
        Engine::builder()
            .config(config())
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

fn client(proxy: SocketAddr, name: &'static str, secret: u8, p: Protection) -> SocksClient {
    SocksClient::new(Version::Socks5, proxy).gssapi(
        move |host: &str| {
            assert_eq!(host, "127.0.0.1");
            Ok(Box::new(Toy::initiator(name, secret)) as Box<dyn GssContext>)
        },
        p,
    )
}

fn refusal(e: &io::Error) -> Option<ProxyRefused> {
    e.get_ref()
        .and_then(|r| r.downcast_ref::<ProxyRefused>())
        .cloned()
}

/// Sends `n` bytes on open (held until the tunnel is up), reports the echo once it is whole.
struct Big {
    want: usize,
    got: Vec<u8>,
    done: Option<mpsc::Sender<Vec<u8>>>,
}

impl Handler for Big {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        self.got.extend_from_slice(data);
        if self.got.len() >= self.want {
            if let Some(tx) = self.done.take() {
                let _ = tx.send(std::mem::take(&mut self.got));
            }
            c.close();
        }
    }
    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<akio::Error>) {
        if let Some(tx) = self.done.take() {
            let _ = tx.send(std::mem::take(&mut self.got));
        }
    }
}

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 % 251) as u8).collect()
}

fn big_acceptor(n: usize) -> (impl akio::Acceptor<Handler = Big>, mpsc::Receiver<Vec<u8>>) {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let data = payload(n);
    (
        akio::fn_acceptor(move |c: &Conn<Big>| {
            c.send(&data).unwrap();
            Big {
                want: n,
                got: Vec::new(),
                done: Some(tx.lock().unwrap().clone()),
            }
        }),
        rx,
    )
}

/// Dials `to` through `c` and checks an echo of `n` bytes.
fn echo_through(ce: &Arc<Engine>, c: &SocksClient, to: Dest, n: usize) -> Result<(), io::Error> {
    let (a, rx) = big_acceptor(n);
    let (etx, erx) = mpsc::channel();
    c.dial(ce, to, a, move |e| {
        let _ = etx.send(e);
    });
    let got = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("tunnel closed");
    if let Ok(e) = erx.try_recv() {
        return Err(e);
    }
    if got.len() != n {
        return Err(erx
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_else(|_| io::Error::other(format!("{} of {n} bytes", got.len()))));
    }
    assert!(got == payload(n), "relayed bytes differ");
    Ok(())
}

#[test]
fn every_protection_level_both_ways() {
    let echo = echo_server();
    let ce = client_engine();
    for min in [
        Protection::None,
        Protection::Integrity,
        Protection::Confidentiality,
    ] {
        let e = server(min, |s| s);
        let proxy = e.local_addrs()[0];
        for want in [
            Protection::None,
            Protection::Integrity,
            Protection::Confidentiality,
        ] {
            // 1 MiB: many wrapped messages each way, across reads.
            let c = client(proxy, "alice", SECRET, want);
            echo_through(&ce, &c, echo.into(), 1 << 20)
                .unwrap_or_else(|e| panic!("server {min:?}, client {want:?}: {e}"));
        }
        stop(&e);
    }
    // On the engine, the client's context is made (and stepped) on its helper thread, never
    // on an I/O thread.
    let e = server(Protection::None, |s| s);
    let c = SocksClient::new(Version::Socks5, e.local_addrs()[0]).gssapi(
        |_host: &str| {
            assert_eq!(thread::current().name(), Some("akio-socks-gss"));
            Ok(Box::new(Toy::initiator("alice", SECRET)) as Box<dyn GssContext>)
        },
        Protection::Integrity,
    );
    echo_through(&ce, &c, echo.into(), 1000).unwrap();
    stop(&e);
    stop(&ce);
}

#[test]
fn refusals() {
    let echo = echo_server();
    let ce = client_engine();
    let e = server(Protection::None, |s| {
        s.allow(|r| r.user() != Some("mallory"))
    });
    let proxy = e.local_addrs()[0];
    // Wrong secret: the client's step fails on the proxy's proof.
    let err = echo_through(
        &ce,
        &client(proxy, "alice", 1, Protection::None),
        echo.into(),
        10,
    )
    .unwrap_err();
    assert_eq!(refusal(&err).map(|r| r.status()), Some(407), "{err}");
    // The acceptor refuses the name: the proxy aborts.
    let err = echo_through(
        &ce,
        &client(proxy, "deny", SECRET, Protection::None),
        echo.into(),
        10,
    )
    .unwrap_err();
    assert_eq!(refusal(&err).map(|r| r.status()), Some(407), "{err}");
    // Authenticated, but the access hook sees the GSS-API name and refuses it.
    let err = echo_through(
        &ce,
        &client(proxy, "mallory", SECRET, Protection::Integrity),
        echo.into(),
        10,
    )
    .unwrap_err();
    assert_eq!(
        refusal(&err).map(|r| r.socks_reply()),
        Some(Some(2)),
        "{err}"
    );
    // A plain client is not let in by a GSS-API-only server.
    let err = echo_through(
        &ce,
        &SocksClient::new(Version::Socks5, proxy),
        echo.into(),
        10,
    )
    .unwrap_err();
    assert_eq!(refusal(&err).map(|r| r.status()), Some(407), "{err}");
    stop(&e);
    // The same server also taking username/password: either works.
    let e = server(Protection::Integrity, |s| {
        s.auth(|u, p| u == "u" && p == "p")
    });
    let proxy = e.local_addrs()[0];
    echo_through(
        &ce,
        &SocksClient::new(Version::Socks5, proxy).auth("u", "p"),
        echo.into(),
        100,
    )
    .unwrap();
    echo_through(
        &ce,
        &client(proxy, "alice", SECRET, Protection::None),
        echo.into(),
        100,
    )
    .unwrap();
    stop(&e);
    stop(&ce);
}

#[test]
fn bind_and_tls_inside_a_protected_tunnel() {
    let e = server(Protection::Confidentiality, |s| s);
    let proxy = e.local_addrs()[0];
    let ce = client_engine();
    // BIND: both replies wrapped, then the relay.
    let any: Dest = "0.0.0.0:0".parse::<SocketAddr>().unwrap().into();
    let (a, rx) = big_acceptor(300 << 10);
    let peer = move |bound: SocketAddr| {
        thread::spawn(move || {
            let mut p = TcpStream::connect(bound).unwrap();
            let mut b = vec![0u8; 64 << 10];
            while let Ok(n) = p.read(&mut b) {
                if n == 0 || p.write_all(&b[..n]).is_err() {
                    return;
                }
            }
        });
    };
    client(proxy, "alice", SECRET, Protection::Integrity)
        .bind(&ce, any, peer, a, |e| panic!("bind: {e}"));
    let got = rx.recv_timeout(Duration::from_secs(20)).unwrap();
    assert!(got == payload(300 << 10));

    // TLS to the target, inside the wrapped tunnel.
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = ck.0.as_der().to_vec();
    let scfg = akio::tls::ServerConfig::builder(
        vec![akio::tls::Certificate::from_der(cert.clone())],
        akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
    .build()
    .unwrap();
    struct Echo;
    impl Handler for Echo {
        fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
            let _ = c.send(data);
        }
    }
    let target =
        Arc::new(
            Engine::builder()
                .config(config())
                .listen(Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(
                    akio::tls::Tls::server(scfg, akio::fn_acceptor(|_c: &Conn<Echo>| Echo)),
                ))
                .build()
                .unwrap(),
        );
    target.start().unwrap();
    let mut roots = akio::tls::RootCerts::empty();
    roots.add(&akio::tls::Certificate::from_der(cert)).unwrap();
    let ccfg = akio::tls::ClientConfig::builder()
        .roots(roots)
        .build()
        .unwrap();
    let (a, rx) = big_acceptor(200 << 10);
    let tls = akio::tls::Tls::client(ccfg, "localhost", a).unwrap();
    client(proxy, "alice", SECRET, Protection::Confidentiality).dial(
        &ce,
        target.local_addrs()[0].into(),
        tls,
        |e| panic!("dial: {e}"),
    );
    let got = rx.recv_timeout(Duration::from_secs(20)).unwrap();
    assert!(got == payload(200 << 10), "TLS inside GSS-API");
    stop(&target);
    stop(&ce);
    stop(&e);
}

#[test]
fn what_is_refused() {
    let echo = echo_server();
    let e = server(Protection::None, |s| s);
    let proxy = e.local_addrs()[0];
    // Blocking helpers: fine without protection, refused with.
    let mut s = client(proxy, "alice", SECRET, Protection::None)
        .dial_blocking(&echo.into())
        .unwrap();
    s.write_all(b"ping").unwrap();
    let mut b = [0u8; 4];
    s.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"ping");
    let c = client(proxy, "alice", SECRET, Protection::Integrity);
    assert_eq!(
        c.dial_blocking(&echo.into()).unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
    stop(&e);
}

/// Datagrams of `sizes` through an association on the engine, whole and in fragments, echoed
/// back by `echo`.
fn udp_through(ce: &Arc<Engine>, c: &SocksClient, echo: SocketAddr, sizes: &[usize]) {
    let (dtx, drx) = mpsc::channel::<(Dest, Vec<u8>)>();
    let dtx = Mutex::new(dtx);
    let (tx, rx) = mpsc::channel();
    c.udp_associate(
        ce,
        move |_, from, d| {
            let _ = dtx.lock().unwrap().send((from, d.to_vec()));
        },
        move |r| tx.send(r).unwrap(),
    );
    let a = rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
    for &n in sizes {
        let p = payload(n);
        // UDP on the loopback interface does not lose datagrams this small; retried in case.
        let mut got = None;
        for _ in 0..3 {
            if n > 1000 {
                a.send_fragmented(&p, &echo.into(), 700).unwrap();
            } else {
                a.send_to(&p, &echo.into()).unwrap();
            }
            if let Ok(r) = drx.recv_timeout(Duration::from_secs(2)) {
                got = Some(r);
                break;
            }
        }
        let (from, d) = got.unwrap_or_else(|| panic!("no echo of {n} bytes"));
        assert_eq!(from, Dest::from(echo));
        assert!(d == p, "{n} bytes differ");
    }
    a.close();
}

#[test]
fn udp_associate_at_every_level() {
    let echo = udp_echo_server();
    let ce = client_engine();
    for min in [
        Protection::None,
        Protection::Integrity,
        Protection::Confidentiality,
    ] {
        // Fragments relayed back in pieces of 900 bytes too.
        let e = server(min, |s| s.udp_fragment_size(Some(900)));
        let proxy = e.local_addrs()[0];
        for want in [
            Protection::None,
            Protection::Integrity,
            Protection::Confidentiality,
        ] {
            let c = client(proxy, "alice", SECRET, want);
            udp_through(&ce, &c, echo, &[1, 512, 1400, 5000]);
            // Blocking.
            let u = c.udp_associate_blocking().unwrap();
            u.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut b = vec![0u8; 8192];
            for n in [3, 1200, 4000] {
                let p = payload(n);
                if n > 1000 {
                    u.send_fragmented(&p, &echo.into(), 600).unwrap();
                } else {
                    u.send_to(&p, &echo.into()).unwrap();
                }
                let (k, from) = u
                    .recv_from(&mut b)
                    .unwrap_or_else(|e| panic!("server {min:?}, client {want:?}, {n}: {e}"));
                assert_eq!(from, Dest::from(echo));
                assert!(b[..k] == p[..], "{n} bytes differ");
            }
            assert!(u.is_open());
        }
        stop(&e);
    }
    stop(&ce);
}

/// The server's side of the wire, by hand: RFC 1961 messages, the protection level a client
/// asking for less gets, UDP ASSOCIATE with wrapped datagrams (RFC 1961 §5), the abort on a bad
/// token.
#[test]
fn wire_format_against_the_server() {
    use akio_ws::gss::{self, GssStep};
    let e = server(Protection::Integrity, |s| s);
    let proxy = e.local_addrs()[0];
    let read_msg = |s: &mut TcpStream| -> (u8, Vec<u8>) {
        let mut h = [0u8; 2];
        s.read_exact(&mut h).unwrap();
        assert_eq!(h[0], 1);
        if h[1] == 0xff {
            return (0xff, Vec::new());
        }
        let mut l = [0u8; 2];
        s.read_exact(&mut l).unwrap();
        let mut t = vec![0u8; usize::from(u16::from_be_bytes(l))];
        s.read_exact(&mut t).unwrap();
        (h[1], t)
    };
    let mut s = TcpStream::connect(proxy).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(&[5, 2, 0, 1]).unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).unwrap();
    assert_eq!(m, [5, 1]);
    let mut ctx = Toy::initiator("bob", SECRET);
    let GssStep::Continue(t) = ctx.step(&[]).unwrap() else {
        unreachable!()
    };
    let mut out = Vec::new();
    gss::push_msg(&mut out, gss::MTYP_AUTH, &t).unwrap();
    s.write_all(&out).unwrap();
    let (mtyp, t) = read_msg(&mut s);
    assert_eq!(mtyp, gss::MTYP_AUTH);
    assert_eq!(ctx.step(&t).unwrap(), GssStep::Complete(Vec::new()));
    // Asks for none; the server's minimum is integrity.
    out.clear();
    gss::protection_msg(&mut ctx, Protection::None, &mut out).unwrap();
    // UDP ASSOCIATE, wrapped, in the same write.
    gss::seal_data(&mut ctx, false, &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0], &mut out).unwrap();
    s.write_all(&out).unwrap();
    let (mtyp, t) = read_msg(&mut s);
    assert_eq!(mtyp, gss::MTYP_PROTECTION);
    assert_eq!(
        gss::protection_of(&mut ctx, &t).unwrap(),
        Protection::Integrity
    );
    let (mtyp, t) = read_msg(&mut s);
    assert_eq!(mtyp, gss::MTYP_DATA);
    let reply = ctx.unwrap(&t).unwrap();
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let relay = SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    // A datagram for the UDP echo server: `VER 1, MTYP 3, LEN, TOKEN`, the token wrapping the
    // SOCKS UDP request header and the payload.
    let uecho = udp_echo_server();
    let u = UdpSocket::bind("127.0.0.1:0").unwrap();
    u.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut d = vec![0, 0, 0, 1, 127, 0, 0, 1];
    d.extend_from_slice(&uecho.port().to_be_bytes());
    d.extend_from_slice(b"hello");
    // Unwrapped: dropped.
    u.send_to(&d, relay).unwrap();
    let mut b = [0u8; 2048];
    assert!(u.recv_from(&mut b).is_err());
    let mut w = Vec::new();
    gss::push_msg(&mut w, gss::MTYP_DATA, &ctx.wrap(false, &d).unwrap()).unwrap();
    u.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    u.send_to(&w, relay).unwrap();
    let (n, _) = u.recv_from(&mut b).unwrap();
    let (mtyp, token, len) = gss::parse_msg(&b[..n]).unwrap().unwrap();
    assert_eq!((mtyp, len), (gss::MTYP_DATA, n));
    // The reply header names the echo server, then the payload.
    assert_eq!(ctx.unwrap(token).unwrap(), d);
    // A token the acceptor refuses: VER 1, MTYP 0xff, then the close.
    let mut s = TcpStream::connect(proxy).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(&[5, 1, 1]).unwrap();
    s.read_exact(&mut m).unwrap();
    out.clear();
    gss::push_msg(&mut out, gss::MTYP_AUTH, b"garbage").unwrap();
    s.write_all(&out).unwrap();
    assert_eq!(read_msg(&mut s).0, 0xff);
    assert_eq!(s.read(&mut m).unwrap_or(0), 0);
    // A server capped at integrity grants no more, and a client asking for confidentiality
    // then refuses it.
    let capped = server_levels(Protection::None..=Protection::Integrity, |s| s);
    let echo = echo_server();
    let ce = client_engine();
    let c = client(
        capped.local_addrs()[0],
        "alice",
        SECRET,
        Protection::Integrity,
    );
    echo_through(&ce, &c, echo.into(), 1000).unwrap();
    let c = client(
        capped.local_addrs()[0],
        "alice",
        SECRET,
        Protection::Confidentiality,
    );
    let err = echo_through(&ce, &c, echo.into(), 10).unwrap_err();
    assert!(err.to_string().contains("protection"), "{err}");
    stop(&ce);
    stop(&capped);
    // SOCKS4 is off on a GSS-API server.
    let mut s = TcpStream::connect(proxy).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(&[4, 1, 0, 80, 127, 0, 0, 1, 0]).unwrap();
    let mut r = [0u8; 8];
    s.read_exact(&mut r).unwrap();
    assert_eq!(r[1], 0x5b);
    stop(&e);
}
