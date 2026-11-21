//! GSS-API authentication (RFC 1961, ADR-071) between only-socks' client and server, with the
//! test mechanism `only_ws::gss::toy`: every protection level, large tunnels both ways, TLS to
//! the target inside a protected tunnel, BIND, refusals, the access hook's user name, what is
//! refused (UDP, blocking helpers with protection), and the RFC 1961 messages on the wire.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

use only::{Backend, Config, Conn, Engine, EngineRef, Handler, Listener, UringConfig};
use only_socks::{
    Dest, ProxyRefused, Socks, SocksClient, Version,
    gssapi::{GssContext, Protection},
};
use only_ws::gss::toy::Toy;

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

fn uring() -> bool {
    std::env::var("ONLY_TEST_BACKEND").as_deref() == Ok("uring")
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

/// A GSS-API SOCKS server (toy acceptor) requiring at least `min`.
fn server(min: Protection, more: impl FnOnce(Socks) -> Socks) -> Arc<Engine> {
    let er = EngineRef::new();
    let s = more(
        Socks::new(er.clone())
            .destinations(only_socks::Destinations::Any)
            .bind(true)
            .udp_associate(true)
            .gssapi(
                || Ok(Box::new(Toy::acceptor(SECRET)) as Box<dyn GssContext>),
                min,
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
    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<only::Error>) {
        if let Some(tx) = self.done.take() {
            let _ = tx.send(std::mem::take(&mut self.got));
        }
    }
}

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 % 251) as u8).collect()
}

fn big_acceptor(n: usize) -> (impl only::Acceptor<Handler = Big>, mpsc::Receiver<Vec<u8>>) {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let data = payload(n);
    (
        only::fn_acceptor(move |c: &Conn<Big>| {
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
            assert_eq!(thread::current().name(), Some("only-socks-gss"));
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
    let ck = only_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = ck.0.as_der().to_vec();
    let scfg = only::tls::ServerConfig::builder(
        vec![only::tls::Certificate::from_der(cert.clone())],
        only::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
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
                    only::tls::Tls::server(scfg, only::fn_acceptor(|_c: &Conn<Echo>| Echo)),
                ))
                .build()
                .unwrap(),
        );
    target.start().unwrap();
    let mut roots = only::tls::RootCerts::empty();
    roots.add(&only::tls::Certificate::from_der(cert)).unwrap();
    let ccfg = only::tls::ClientConfig::builder()
        .roots(roots)
        .build()
        .unwrap();
    let (a, rx) = big_acceptor(200 << 10);
    let tls = only::tls::Tls::client(ccfg, "localhost", a).unwrap();
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
    // UDP ASSOCIATE over GSS-API: refused by the client.
    let ce = client_engine();
    let (tx, rx) = mpsc::channel();
    c.udp_associate(&ce, |_, _, _| {}, move |r| tx.send(r.map(|_| ())).unwrap());
    let err = rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    assert!(c.udp_associate_blocking().is_err());
    stop(&ce);
    stop(&e);
}

/// The server's side of the wire, by hand: RFC 1961 messages, the protection level a client
/// asking for less gets, UDP ASSOCIATE refused once protected, the abort on a bad token.
#[test]
fn wire_format_against_the_server() {
    use only_ws::gss::{self, GssStep};
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
    assert_eq!(&reply[..2], &[5, 7]); // command not supported
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
    // SOCKS4 is off on a GSS-API server.
    let mut s = TcpStream::connect(proxy).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(&[4, 1, 0, 80, 127, 0, 0, 1, 0]).unwrap();
    let mut r = [0u8; 8];
    s.read_exact(&mut r).unwrap();
    assert_eq!(r[1], 0x5b);
    stop(&e);
}
