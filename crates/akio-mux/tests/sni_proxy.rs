//! TLS routing by server name without terminating it, and the PROXY protocol (ADR-095), on a
//! real engine.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

use akio::{AnyAcceptor, Config, Conn, Engine, Handler, Listener, fn_acceptor, tls::Tls};
use akio_mux::{
    ClientHello, Mux, Rule, SniMatcher,
    proxy::{self, ProxyHeader, ProxyProtocol, Version},
};

/// Answers every read with `tag`, the client address the connection reports, then the data.
struct Tagged(&'static str);
impl Handler for Tagged {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let mut out = format!("{}|{}|", self.0, proxy::client_addr(c)).into_bytes();
        out.extend_from_slice(data);
        let _ = c.send(&out);
    }
}

fn tagged(tag: &'static str) -> impl akio::Acceptor {
    fn_acceptor(move |_c: &Conn<Tagged>| Tagged(tag))
}

/// Echoes with a prefix (behind TLS).
struct Prefixed(&'static [u8]);
impl Handler for Prefixed {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let mut out = self.0.to_vec();
        out.extend_from_slice(data);
        let _ = c.send(&out);
    }
}

fn backend() -> akio::Backend {
    if std::env::var("AKIO_TEST_BACKEND").as_deref() == Ok("uring") {
        let mut v = akio::UringConfig::default();
        v.strict = true;
        akio::Backend::IoUring(v)
    } else {
        akio::Backend::Epoll
    }
}

fn engine(acc: impl Into<AnyAcceptor>) -> Engine {
    let e = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(300);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .serve_any(acc),
        )
        .client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

/// A ClientHello message (handshake header included).
fn hello_msg(sni: Option<&str>, alpn: &[&[u8]], pad: usize) -> Vec<u8> {
    let mut exts = Vec::new();
    if let Some(n) = sni {
        let l = n.len() as u16;
        exts.extend_from_slice(&[0, 0]);
        exts.extend_from_slice(&(l + 5).to_be_bytes());
        exts.extend_from_slice(&(l + 3).to_be_bytes());
        exts.push(0);
        exts.extend_from_slice(&l.to_be_bytes());
        exts.extend_from_slice(n.as_bytes());
    }
    if !alpn.is_empty() {
        let mut list = Vec::new();
        for p in alpn {
            list.push(p.len() as u8);
            list.extend_from_slice(p);
        }
        exts.extend_from_slice(&[0, 16]);
        exts.extend_from_slice(&((list.len() + 2) as u16).to_be_bytes());
        exts.extend_from_slice(&(list.len() as u16).to_be_bytes());
        exts.extend_from_slice(&list);
    }
    // padding (21)
    exts.extend_from_slice(&[0, 21]);
    exts.extend_from_slice(&(pad as u16).to_be_bytes());
    exts.resize(exts.len() + pad, 0);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[1u8; 32]);
    body.push(0);
    body.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    let mut msg = vec![1];
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    msg.extend_from_slice(&body);
    msg
}

fn records(msg: &[u8], rec: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for c in msg.chunks(rec) {
        out.extend_from_slice(&[0x16, 3, 1]);
        out.extend_from_slice(&(c.len() as u16).to_be_bytes());
        out.extend_from_slice(c);
    }
    out
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.set_nodelay(true).unwrap();
    s
}

/// Reads until `n` bytes or EOF.
fn read_n(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut b = [0u8; 4096];
    while out.len() < n {
        match s.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(k) => out.extend_from_slice(&b[..k]),
        }
    }
    out
}

/// Reads to EOF; how long it took, or `None` if the connection stayed open for `within`.
fn closed_within(s: &mut TcpStream, within: Duration) -> Option<Duration> {
    let t0 = Instant::now();
    if s.set_read_timeout(Some(within)).is_err() {
        return Some(Duration::ZERO); // macOS: EINVAL on a socket already reset
    }
    let mut b = [0u8; 256];
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

fn sni_mux() -> Mux {
    Mux::new()
        .route(
            Rule::TlsSni(SniMatcher::new(["exact.test"])),
            tagged("exact"),
        )
        .route(
            Rule::TlsSni(SniMatcher::new(["*.pass.test"])),
            tagged("wild"),
        )
        .route(
            Rule::TlsHello(Arc::new(|h: &ClientHello<'_>| {
                h.server_name().is_none() && h.offers_alpn(b"h2")
            })),
            tagged("nosni-h2"),
        )
        .route(Rule::Tls, tagged("tls"))
        .fallback(tagged("fallback"))
}

/// Sends `wire` in pieces of `piece` bytes with a pause between them, reads until the server
/// is quiet, and returns `(tag, client address, every byte the route echoed)`.
fn exchange(addr: SocketAddr, wire: &[u8], piece: usize) -> (String, String, Vec<u8>) {
    let mut s = connect(addr);
    for c in wire.chunks(piece.max(1)) {
        s.write_all(c).unwrap();
        if piece < wire.len() {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let mut all = read_n(&mut s, 1);
    s.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut b = [0u8; 4096];
    while let Ok(k @ 1..) = s.read(&mut b) {
        all.extend_from_slice(&b[..k]);
    }
    // Every reply is `tag|addr|data`; take the prefix of the first and strip it everywhere.
    let text = String::from_utf8_lossy(&all).into_owned();
    let mut it = text.splitn(3, '|');
    let (tag, peer) = (
        it.next().unwrap_or("").to_owned(),
        it.next().unwrap_or("").to_owned(),
    );
    let prefix = format!("{tag}|{peer}|").into_bytes();
    let mut data = Vec::new();
    let mut rest = &all[..];
    while !rest.is_empty() {
        if rest.starts_with(&prefix) {
            rest = &rest[prefix.len()..];
        } else {
            data.push(rest[0]);
            rest = &rest[1..];
        }
    }
    (tag, peer, data)
}

#[test]
fn sni_routes_split_hellos_without_terminating() {
    let e = engine(sni_mux());
    let addr = e.local_addrs()[0];
    for (sni, alpn, want) in [
        (Some("exact.test"), &[][..], "exact"),
        (Some("EXACT.test."), &[][..], "exact"),
        (Some("a.pass.test"), &[&b"h2"[..]][..], "wild"),
        (Some("a.b.pass.test"), &[][..], "tls"), // one label only
        (Some("pass.test"), &[][..], "tls"),
        (None, &[&b"h2"[..]][..], "nosni-h2"),
        (None, &[][..], "tls"),
    ] {
        let msg = hello_msg(sni, alpn, 300);
        // One record in one write; several records; several records in tiny writes.
        for (rec, piece) in [(1 << 14, usize::MAX), (64, usize::MAX), (100, 7), (5, 33)] {
            let wire = records(&msg, rec);
            let (tag, _, data) = exchange(addr, &wire, piece.min(wire.len()));
            assert_eq!(tag, want, "{sni:?} rec {rec} piece {piece}");
            // The route got every byte of the hello, untouched: TLS was not terminated.
            assert_eq!(data, wire, "{sni:?} rec {rec}");
        }
    }
    // Not TLS at all.
    assert_eq!(exchange(addr, b"GET / HTTP/1.1\r\n\r\n", 64).0, "fallback");
    e.shutdown();
    e.wait();
}

#[test]
fn malformed_oversized_and_slow_hellos() {
    // A malformed hello: no SNI rule matches, `Rule::Tls` still does.
    let e = engine(sni_mux());
    let addr = e.local_addrs()[0];
    let mut bad = records(&hello_msg(Some("exact.test"), &[], 0), 1 << 14);
    bad[5] = 2; // a ServerHello
    assert_eq!(exchange(addr, &bad, bad.len()).0, "tls");
    e.shutdown();
    e.wait();

    // An explicit limit below the hello: the fallback gets it, every byte.
    let e = engine(
        Mux::new()
            .max_sniff_bytes(256)
            .route(
                Rule::TlsSni(SniMatcher::new(["exact.test"])),
                tagged("exact"),
            )
            .fallback(tagged("fallback")),
    );
    let addr = e.local_addrs()[0];
    let wire = records(&hello_msg(Some("exact.test"), &[], 600), 1 << 14);
    let (tag, _, data) = exchange(addr, &wire, 100);
    assert_eq!(tag, "fallback");
    assert_eq!(data, wire);
    e.shutdown();
    e.wait();

    // The default limit grows with an SNI route: a 10 KiB hello over several records passes.
    let e = engine(sni_mux());
    let addr = e.local_addrs()[0];
    let wire = records(&hello_msg(Some("x.pass.test"), &[], 10_000), 4000);
    assert_eq!(exchange(addr, &wire, 1500).0, "wild");
    e.shutdown();
    e.wait();

    // Half a hello, then nothing: closed at the sniff deadline.
    let e = engine(sni_mux().sniff_timeout(Some(Duration::from_millis(300))));
    let addr = e.local_addrs()[0];
    let wire = records(&hello_msg(Some("exact.test"), &[], 300), 1 << 14);
    let mut s = connect(addr);
    s.write_all(&wire[..wire.len() / 2]).unwrap();
    let t = closed_within(&mut s, Duration::from_secs(5)).expect("closed");
    assert!(t >= Duration::from_millis(200), "{t:?}");
    e.shutdown();
    e.wait();
}

/// A real TLS client: its hello is read for routing, then the chosen route terminates TLS.
#[test]
fn real_client_hello_routes_to_tls_server() {
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
            Rule::TlsSni(SniMatcher::new(["localhost"])),
            Tls::server(scfg, fn_acceptor(|_c: &Conn<Prefixed>| Prefixed(b"tls:"))),
        )
        .fallback(tagged("fallback"));
    let e = engine(mux);
    let addr = e.local_addrs()[0];
    let mut roots = akio::tls::RootCerts::empty();
    roots.add(&akio::tls::Certificate::from_der(cert)).unwrap();
    let ccfg = akio::tls::ClientConfig::builder()
        .roots(roots)
        .build()
        .unwrap();
    let mut tls = akio::tls::stream::Stream::client(&ccfg, "localhost", connect(addr)).unwrap();
    tls.write_all(b"hello").unwrap();
    let mut b = [0u8; 9];
    tls.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"tls:hello");
    e.shutdown();
    e.wait();
}

#[test]
fn proxy_v1_v2_local_and_composition_with_sni() {
    let e = engine(ProxyProtocol::new_any(sni_mux()));
    let addr = e.local_addrs()[0];
    let hello = records(&hello_msg(Some("a.pass.test"), &[], 200), 50);

    // v1, then the hello, in small writes: the header goes, the mux sees the hello.
    let v1 = b"PROXY TCP4 203.0.113.7 192.0.2.1 40000 443\r\n";
    let wire = [&v1[..], &hello].concat();
    let (tag, peer, data) = exchange(addr, &wire, 9);
    assert_eq!((&tag[..], &peer[..]), ("wild", "203.0.113.7:40000"));
    assert_eq!(data, hello);

    // v2 with TLVs, IPv6.
    let h = ProxyHeader::proxy(
        "[2001:db8::7]:1234".parse().unwrap(),
        "[2001:db8::1]:443".parse().unwrap(),
    )
    .with_tlv(proxy::tlv::AUTHORITY, "a.pass.test")
    .with_tlv(proxy::tlv::CRC32C, [0; 4]);
    let wire = [h.encode_v2().unwrap(), hello.clone()].concat();
    let (tag, peer, data) = exchange(addr, &wire, 11);
    assert_eq!((&tag[..], &peer[..]), ("wild", "[2001:db8::7]:1234"));
    assert_eq!(data, hello);

    // LOCAL: the real address applies.
    let wire = [ProxyHeader::local().encode_v2().unwrap(), b"plain".to_vec()].concat();
    let (tag, peer, data) = exchange(addr, &wire, wire.len());
    assert_eq!(tag, "fallback");
    assert!(peer.starts_with("127.0.0.1:"), "{peer}");
    assert_eq!(data, b"plain");

    // No header: closed.
    let mut s = connect(addr);
    s.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    assert!(closed_within(&mut s, Duration::from_secs(5)).is_some());
    // A malformed v1 header: closed.
    let mut s = connect(addr);
    s.write_all(b"PROXY TCP4 1.2.3.4 5.6.7.8 01 2\r\n").unwrap();
    assert!(closed_within(&mut s, Duration::from_secs(5)).is_some());
    e.shutdown();
    e.wait();
}

#[test]
fn proxy_limits_slowloris_and_trust() {
    let e = engine(
        ProxyProtocol::new(tagged("app"))
            .header_timeout(Some(Duration::from_millis(300)))
            .max_header_bytes(256),
    );
    let addr = e.local_addrs()[0];
    // One byte every 100 ms: closed at the deadline, not after 4 s of trickling.
    let mut s = connect(addr);
    let t0 = Instant::now();
    // The trickle stops when a write fails (the server closed) or after 2 s.
    for b in b"PROXY TCP4 1.2.3.4 5.6.7.8 1000 2000\r\n" {
        if s.write_all(&[*b]).is_err() || t0.elapsed() > Duration::from_secs(2) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    closed_within(&mut s, Duration::from_secs(5)).expect("closed");
    let t = t0.elapsed();
    assert!(t < Duration::from_millis(1900), "{t:?}");
    // A v2 header announcing more than the limit: closed at once.
    let mut forged = ProxyHeader::local().encode_v2().unwrap();
    forged[14..16].copy_from_slice(&0xffffu16.to_be_bytes());
    let mut s = connect(addr);
    s.write_all(&forged).unwrap();
    let t = closed_within(&mut s, Duration::from_secs(5)).expect("closed");
    assert!(t < Duration::from_millis(250), "{t:?}");
    // Truncated, then silent: closed at the deadline.
    let v2 = ProxyHeader::proxy("10.0.0.1:1".parse().unwrap(), "10.0.0.2:2".parse().unwrap())
        .encode_v2()
        .unwrap();
    let mut s = connect(addr);
    s.write_all(&v2[..20]).unwrap();
    let t = closed_within(&mut s, Duration::from_secs(5)).expect("closed");
    assert!(t >= Duration::from_millis(200), "{t:?}");
    e.shutdown();
    e.wait();

    // allow_missing: a connection without a header passes untouched.
    let e = engine(ProxyProtocol::new(tagged("app")).allow_missing(true));
    let addr = e.local_addrs()[0];
    let (tag, peer, data) = exchange(addr, b"hello", 5);
    assert!(
        tag == "app" && peer.starts_with("127.0.0.1:"),
        "{tag} {peer}"
    );
    assert_eq!(data, b"hello");
    e.shutdown();
    e.wait();

    // An untrusted peer's header is not believed: the bytes go to the app as they are.
    let e = engine(ProxyProtocol::new(tagged("app")).trusted(|p| !p.ip().is_loopback()));
    let addr = e.local_addrs()[0];
    let v1 = b"PROXY TCP4 6.6.6.6 5.6.7.8 1 2\r\n";
    let (tag, peer, data) = exchange(addr, v1, v1.len());
    assert!(
        tag == "app" && peer.starts_with("127.0.0.1:"),
        "{tag} {peer}"
    );
    assert_eq!(data, v1);
    e.shutdown();
    e.wait();
}

/// The dial side: a header written first on an outgoing connection reaches a PROXY listener.
#[test]
fn dial_side_writes_the_header() {
    let seen: Arc<Mutex<Option<SocketAddr>>> = Arc::default();
    let seen2 = seen.clone();
    struct Server(Arc<Mutex<Option<SocketAddr>>>);
    impl Handler for Server {
        fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
            *self.0.lock().unwrap() = proxy::header(c).and_then(ProxyHeader::source);
            let _ = c.send(data);
        }
    }
    let e = engine(ProxyProtocol::new(fn_acceptor(move |_c: &Conn<Server>| {
        Server(seen2.clone())
    })));
    let addr = e.local_addrs()[0];
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    struct Client(mpsc::Sender<Vec<u8>>);
    impl Handler for Client {
        fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
            let _ = self.0.send(data.to_vec());
        }
    }
    for version in [Version::V1, Version::V2] {
        let tx = tx.clone();
        e.dial(
            addr,
            fn_acceptor(move |c: &Conn<Client>| {
                let h = ProxyHeader::proxy(
                    "198.51.100.9:7000".parse().unwrap(),
                    "192.0.2.10:443".parse().unwrap(),
                );
                proxy::send_header(c, &h, version).unwrap();
                c.send(b"ping").unwrap();
                Client(tx.clone())
            }),
            |err| panic!("dial: {err}"),
        );
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), b"ping");
        assert_eq!(
            *seen.lock().unwrap(),
            Some("198.51.100.9:7000".parse().unwrap()),
            "{version:?}"
        );
        *seen.lock().unwrap() = None;
    }
    e.shutdown();
    e.wait();
}

/// The header attached to a connection says how many bytes it took on the wire: v1, v2 with
/// TLVs, and LOCAL (whose address block is discarded), each followed by data in one write.
#[test]
fn attached_header_has_its_wire_length() {
    struct Len;
    impl Handler for Len {
        fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
            let n = proxy::header(c).and_then(ProxyHeader::wire_len);
            let mut out = format!("{n:?}|").into_bytes();
            out.extend_from_slice(data);
            let _ = c.send(&out);
        }
    }
    let e = engine(ProxyProtocol::new(fn_acceptor(|_c: &Conn<Len>| Len)));
    let addr = e.local_addrs()[0];
    let h = ProxyHeader::proxy(
        "203.0.113.7:40000".parse().unwrap(),
        "192.0.2.1:443".parse().unwrap(),
    );
    let v2 = h.clone().with_tlv(proxy::tlv::AUTHORITY, "a.test");
    let mut local = ProxyHeader::local().encode_v2().unwrap();
    local[13] = 0x11;
    local[15] = 12;
    local.extend_from_slice(&[0; 12]);
    for (wire, n) in [
        (h.encode_v1().unwrap(), 44),
        (v2.encode_v2().unwrap(), 16 + 12 + 3 + 6),
        (local, 28),
    ] {
        assert_eq!(wire.len(), n);
        let mut s = connect(addr);
        s.write_all(&[&wire[..], b"data"].concat()).unwrap();
        let want = format!("Some({n})|data");
        assert_eq!(read_n(&mut s, want.len()), want.as_bytes());
    }
    e.shutdown();
    e.wait();
}
