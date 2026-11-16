//! SOCKS5/4/4a and HTTP CONNECT proxying to a plain echo server.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::Duration,
};

use only::{Backend, Config, Engine, EngineRef, Listener, UringConfig};
use only_socks::{Destinations, ProxyConfig, Socks, connect_proxy_with};

/// A thread-per-connection echo server (independent of `only`).
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

/// An upstream that first sends `n` bytes without reading anything, then echoes. Like many
/// real servers, it does not read while its own writes are blocked.
fn talk_first_server(n: usize) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming().flatten() {
            thread::spawn(move || {
                let mut s = s;
                if write_pattern(&mut s, n).is_err() {
                    return;
                }
                let mut b = vec![0u8; 64 << 10];
                loop {
                    match s.read(&mut b) {
                        Ok(0) | Err(_) => return,
                        Ok(k) => {
                            if s.write_all(&b[..k]).is_err() {
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

/// Byte `i` of the test stream.
fn pattern_byte(i: usize) -> u8 {
    (i % 251) as u8
}

/// Writes bytes `0..n` of the test stream, a chunk at a time.
fn write_pattern(s: &mut TcpStream, n: usize) -> std::io::Result<()> {
    let chunk: Vec<u8> = (0..251 * 1024).map(pattern_byte).collect(); // whole periods
    let mut left = n;
    while left > 0 {
        let k = left.min(chunk.len());
        s.write_all(&chunk[..k])?;
        left -= k;
    }
    Ok(())
}

/// Reads `n` bytes of the test stream and checks them.
fn read_pattern(s: &mut TcpStream, n: usize) {
    const B: usize = 64 << 10;
    let want: Vec<u8> = (0..B + 251).map(pattern_byte).collect();
    let mut b = vec![0u8; B];
    let mut at = 0;
    while at < n {
        let k = s.read(&mut b[..(n - at).min(B)]).unwrap();
        assert!(k > 0, "EOF after {at} of {n} bytes");
        let o = at % 251;
        assert!(b[..k] == want[o..o + k], "wrong bytes at {at}");
        at += k;
    }
}

/// `ONLY_TEST_BACKEND=uring` runs these on io_uring.
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

/// A config that lets the tests reach their loopback servers.
fn loopback_ok() -> ProxyConfig {
    let mut c = ProxyConfig::default();
    c.destinations = Destinations::Any;
    c
}

/// Starts a proxy that may dial loopback (the default policy would deny the test servers).
fn start(socks: Option<Socks>, http: bool, er: &EngineRef) -> Arc<Engine> {
    let socks = socks.map(|s| s.destinations(Destinations::Any));
    start_with(socks, http.then(loopback_ok), er)
}

/// Starts a SOCKS server as given, or an HTTP CONNECT proxy with `http`.
fn start_with(socks: Option<Socks>, http: Option<ProxyConfig>, er: &EngineRef) -> Arc<Engine> {
    let l = Listener::tcp("127.0.0.1:0".parse().unwrap())
        .backend(backend())
        .threads(2);
    let l = match socks {
        Some(s) => l.serve(s),
        None => {
            let cfg = http.expect("socks or http");
            l.serve(only_http::serve(connect_proxy_with(er.clone(), cfg)))
        }
    };
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_millis(300);
                v
            })
            .listen(l)
            // Client threads are always epoll; on io_uring, upstreams share the listener's.
            .client_threads(if uring() { 0 } else { 2 })
            .build()
            .unwrap(),
    );
    er.set(&e);
    e.start().unwrap();
    e
}

fn connect(a: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(a).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

fn read_n(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut b = vec![0; n];
    s.read_exact(&mut b).unwrap();
    b
}

/// Pushes `n` bytes through and reads them back concurrently.
fn roundtrip(mut s: TcpStream, n: usize) {
    let data: Vec<u8> = (0..n).map(pattern_byte).collect();
    let mut w = s.try_clone().unwrap();
    let d2 = data.clone();
    let t = thread::spawn(move || w.write_all(&d2).unwrap());
    let got = read_n(&mut s, n);
    t.join().unwrap();
    assert!(got == data, "relayed bytes differ");
}

fn socks5_connect(
    proxy: SocketAddr,
    target: &[u8],
    auth: Option<(&str, &str)>,
) -> (TcpStream, Vec<u8>) {
    let mut s = connect(proxy);
    match auth {
        None => {
            s.write_all(&[5, 1, 0]).unwrap();
            assert_eq!(read_n(&mut s, 2), [5, 0]);
        }
        Some((u, p)) => {
            s.write_all(&[5, 1, 2]).unwrap();
            assert_eq!(read_n(&mut s, 2), [5, 2]);
            let mut m = vec![1, u.len() as u8];
            m.extend_from_slice(u.as_bytes());
            m.push(p.len() as u8);
            m.extend_from_slice(p.as_bytes());
            s.write_all(&m).unwrap();
            let r = read_n(&mut s, 2);
            if r != [1, 0] {
                return (s, r);
            }
        }
    }
    let mut req = vec![5, 1, 0];
    req.extend_from_slice(target);
    s.write_all(&req).unwrap();
    let head = read_n(&mut s, 4);
    let rest = match head[3] {
        1 => 6,
        4 => 18,
        _ => 0,
    };
    let mut r = head;
    r.extend(read_n(&mut s, rest));
    (s, r)
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

#[test]
fn socks5_ipv4_domain_and_backpressure() {
    let echo = echo_server();
    let er = EngineRef::new();
    let e = start(Some(Socks::new(er.clone())), false, &er);
    let proxy = e.local_addrs()[0];
    let (s, r) = socks5_connect(proxy, &ipv4(echo), None);
    assert_eq!(r[1], 0, "succeeded");
    // 8 MiB each way through the relay (well above its 256 KiB pause threshold).
    roundtrip(s, 8 << 20);
    // A domain name, resolved on the pool.
    let mut t = vec![3, 9];
    t.extend_from_slice(b"localhost");
    t.extend_from_slice(&echo.port().to_be_bytes());
    let (mut s, r) = socks5_connect(proxy, &t, None);
    if r[1] == 0 {
        s.write_all(b"hello via name").unwrap();
        assert_eq!(read_n(&mut s, 14), b"hello via name");
    } else {
        // `localhost` may resolve to ::1 only on some hosts, where the echo server is not.
        assert_eq!(r[1], 5);
    }
    // Refused target and unsupported command.
    let dead = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let (_s, r) = socks5_connect(proxy, &ipv4(dead), None);
    assert_eq!(r[1], 5, "connection refused");
    let mut s = connect(proxy);
    s.write_all(&[5, 1, 0]).unwrap();
    read_n(&mut s, 2);
    let mut req = vec![5, 2, 0]; // BIND
    req.extend(ipv4(echo));
    s.write_all(&req).unwrap();
    assert_eq!(read_n(&mut s, 2), [5, 7]);
    e.shutdown();
    e.wait();
}

/// Regression: the engine's write backpressure paused reading the upstream while client data
/// was queued for it. An upstream that does not read while its own writes are blocked then
/// waited on the proxy while the proxy waited on it, and the tunnel hung. With a plain echo
/// server it took a slow client (a loaded machine, `socks5_ipv4_domain_and_backpressure` hung
/// about once in 20 runs); a server that talks first and a client whose data piles up before it
/// reads hang every time. The relay now paces both directions by itself.
#[test]
fn relay_upstream_that_talks_first() {
    // Well above what the kernel buffers in each direction (a few MiB on loopback).
    const N: usize = 32 << 20;
    let up = talk_first_server(N);
    let run = |mut s: TcpStream| {
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut w = s.try_clone().unwrap();
        let t = thread::spawn(move || write_pattern(&mut w, N).unwrap());
        // Let our data pile up in the kernel first, so it rushes at the server's side as soon as
        // we read.
        thread::sleep(Duration::from_millis(200));
        read_pattern(&mut s, N); // what the server sent first
        read_pattern(&mut s, N); // the echo of ours
        t.join().unwrap();
    };
    // SOCKS5.
    let er = EngineRef::new();
    let e = start(Some(Socks::new(er.clone())), false, &er);
    let (s, r) = socks5_connect(e.local_addrs()[0], &ipv4(up), None);
    assert_eq!(r[1], 0);
    run(s);
    e.shutdown();
    e.wait();
    // HTTP CONNECT.
    let er = EngineRef::new();
    let e = start(None, true, &er);
    let mut s = connect(e.local_addrs()[0]);
    s.write_all(format!("CONNECT {up} HTTP/1.1\r\nHost: {up}\r\n\r\n").as_bytes())
        .unwrap();
    let ok = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    assert_eq!(read_n(&mut s, ok.len()), ok);
    run(s);
    e.shutdown();
    e.wait();
}

#[test]
fn socks5_username_password() {
    let echo = echo_server();
    let er = EngineRef::new();
    let e = start(
        Some(Socks::new(er.clone()).auth(|u, p| u == "alice" && p == "s3cret")),
        false,
        &er,
    );
    let proxy = e.local_addrs()[0];
    let (_s, r) = socks5_connect(proxy, &ipv4(echo), Some(("alice", "wrong")));
    assert_eq!(r, [1, 1]);
    let (mut s, r) = socks5_connect(proxy, &ipv4(echo), Some(("alice", "s3cret")));
    assert_eq!(r[1], 0);
    s.write_all(b"authed").unwrap();
    assert_eq!(read_n(&mut s, 6), b"authed");
    // No-auth clients are turned away when auth is required.
    let mut s = connect(proxy);
    s.write_all(&[5, 1, 0]).unwrap();
    assert_eq!(read_n(&mut s, 2), [5, 0xff]);
    e.shutdown();
    e.wait();
}

#[test]
fn socks4_and_4a() {
    let echo = echo_server();
    let er = EngineRef::new();
    let e = start(Some(Socks::new(er.clone())), false, &er);
    let proxy = e.local_addrs()[0];
    let SocketAddr::V4(v4) = echo else {
        unreachable!()
    };
    let mut s = connect(proxy);
    let mut req = vec![4, 1];
    req.extend_from_slice(&echo.port().to_be_bytes());
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(b"user\0");
    s.write_all(&req).unwrap();
    assert_eq!(read_n(&mut s, 8)[1], 0x5a);
    s.write_all(b"four").unwrap();
    assert_eq!(read_n(&mut s, 4), b"four");
    // 4a: 0.0.0.1 and a host name.
    let mut s = connect(proxy);
    let mut req = vec![4, 1];
    req.extend_from_slice(&echo.port().to_be_bytes());
    req.extend_from_slice(&[0, 0, 0, 1]);
    req.push(0); // empty user id
    req.extend_from_slice(b"127.0.0.1");
    req.push(0);
    s.write_all(&req).unwrap();
    assert_eq!(read_n(&mut s, 8)[1], 0x5a);
    s.write_all(b"4a!").unwrap();
    assert_eq!(read_n(&mut s, 3), b"4a!");
    e.shutdown();
    e.wait();
}

#[test]
fn http_connect_tunnel() {
    let echo = echo_server();
    let er = EngineRef::new();
    let e = start(None, true, &er);
    let proxy = e.local_addrs()[0];
    let mut s = connect(proxy);
    s.write_all(format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n").as_bytes())
        .unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut b).unwrap();
        head.push(b[0]);
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
    roundtrip(s, 4 << 20);
    // A target nobody listens on: 502.
    let dead = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut s = connect(proxy);
    s.write_all(format!("CONNECT {dead} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
        .unwrap();
    let mut all = Vec::new();
    s.read_to_end(&mut all).unwrap();
    assert!(String::from_utf8_lossy(&all).starts_with("HTTP/1.1 502"));
    // Anything but CONNECT: 405.
    let mut s = connect(proxy);
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut all = Vec::new();
    s.read_to_end(&mut all).unwrap();
    assert!(String::from_utf8_lossy(&all).starts_with("HTTP/1.1 405"));
    e.shutdown();
    e.wait();
}

/// Reads until EOF or error; panics if neither comes within `within`.
fn expect_closed(s: &mut TcpStream, within: Duration) -> Vec<u8> {
    s.set_read_timeout(Some(within)).unwrap();
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
                panic!("still open after {within:?}")
            }
            Err(_) => return all,
        }
    }
}

fn http_connect(proxy: SocketAddr, target: &str) -> TcpStream {
    let mut s = connect(proxy);
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .unwrap();
    s
}

fn read_head(s: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut b).unwrap();
        head.push(b[0]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// The default policy turns away loopback targets, by address and by name, on every protocol.
#[test]
fn default_policy_denies_private_destinations() {
    let echo = echo_server();
    let er = EngineRef::new();
    let e = start_with(Some(Socks::new(er.clone())), None, &er);
    let proxy = e.local_addrs()[0];
    let (mut s, r) = socks5_connect(proxy, &ipv4(echo), None);
    assert_eq!(r[1], 2, "not allowed by ruleset");
    expect_closed(&mut s, Duration::from_secs(5));
    let mut t = vec![3, 9];
    t.extend_from_slice(b"localhost");
    t.extend_from_slice(&echo.port().to_be_bytes());
    let (_s, r) = socks5_connect(proxy, &t, None);
    assert!(r[1] == 2 || r[1] == 4, "localhost resolves to loopback: {}", r[1]);
    // SOCKS4 to 127.0.0.1.
    let SocketAddr::V4(v4) = echo else {
        unreachable!()
    };
    let mut s = connect(proxy);
    let mut req = vec![4, 1];
    req.extend_from_slice(&echo.port().to_be_bytes());
    req.extend_from_slice(&v4.ip().octets());
    req.push(0);
    s.write_all(&req).unwrap();
    assert_eq!(read_n(&mut s, 8)[1], 0x5b);
    // 169.254.169.254 (cloud metadata) never gets dialled.
    let (_s, r) = socks5_connect(proxy, &[1, 169, 254, 169, 254, 0, 80], None);
    assert_eq!(r[1], 2);
    e.shutdown();
    e.wait();

    let er = EngineRef::new();
    let e = start_with(None, Some(ProxyConfig::default()), &er);
    let proxy = e.local_addrs()[0];
    let mut s = http_connect(proxy, &echo.to_string());
    assert!(read_head(&mut s).starts_with("HTTP/1.1 403"));
    let mut s = http_connect(proxy, &format!("localhost:{}", echo.port()));
    let all = String::from_utf8_lossy(&expect_closed(&mut s, Duration::from_secs(5))).into_owned();
    assert!(all.starts_with("HTTP/1.1 403") || all.starts_with("HTTP/1.1 502"), "{all}");
    e.shutdown();
    e.wait();
}

fn timeouts(handshake: Option<Duration>, idle: Option<Duration>) -> ProxyConfig {
    let mut c = loopback_ok();
    c.handshake_timeout = handshake;
    c.idle_timeout = idle;
    c
}

/// A client that never finishes its greeting, or trickles it a byte at a time, is cut off at the
/// handshake timeout; one that finishes in time keeps its tunnel past it.
#[test]
fn socks_handshake_timeout() {
    let echo = echo_server();
    let er = EngineRef::new();
    let cfg = timeouts(Some(Duration::from_millis(300)), None);
    let e = start_with(Some(Socks::new(er.clone()).config(cfg)), None, &er);
    let proxy = e.local_addrs()[0];
    // Silent client.
    let mut s = connect(proxy);
    let t0 = std::time::Instant::now();
    expect_closed(&mut s, Duration::from_secs(5));
    assert!(t0.elapsed() >= Duration::from_millis(250), "{:?}", t0.elapsed());
    // Slowloris: a byte every 50 ms of a request that would complete after 600 ms.
    let mut s = connect(proxy);
    let mut msg = vec![5, 1, 0, 5, 1, 0];
    msg.extend(ipv4(echo));
    let mut cut = false;
    for b in msg {
        if s.write_all(&[b]).is_err() {
            cut = true;
            break;
        }
        thread::sleep(Duration::from_millis(60));
    }
    if !cut {
        let all = expect_closed(&mut s, Duration::from_secs(5));
        // It may have got the method reply, never the CONNECT reply.
        assert!(all.len() <= 2, "{all:?}");
    }
    // In time: the tunnel outlives the handshake timeout.
    let (mut s, r) = socks5_connect(proxy, &ipv4(echo), None);
    assert_eq!(r[1], 0);
    thread::sleep(Duration::from_millis(700));
    s.write_all(b"still here").unwrap();
    assert_eq!(read_n(&mut s, 10), b"still here");
    e.shutdown();
    e.wait();
}

/// A tunnel that moves data keeps going past the idle timeout; a quiet one is closed.
#[test]
fn tunnel_idle_timeout() {
    let echo = echo_server();
    let idle = Duration::from_millis(400);
    for http in [false, true] {
        let er = EngineRef::new();
        let cfg = timeouts(None, Some(idle));
        let e = if http {
            start_with(None, Some(cfg), &er)
        } else {
            start_with(Some(Socks::new(er.clone()).config(cfg)), None, &er)
        };
        let proxy = e.local_addrs()[0];
        let mut s = if http {
            let mut s = http_connect(proxy, &echo.to_string());
            assert!(read_head(&mut s).starts_with("HTTP/1.1 200"));
            s
        } else {
            let (s, r) = socks5_connect(proxy, &ipv4(echo), None);
            assert_eq!(r[1], 0);
            s
        };
        // Busy for well over the idle timeout.
        for _ in 0..8 {
            s.write_all(b"ping").unwrap();
            assert_eq!(read_n(&mut s, 4), b"ping");
            thread::sleep(Duration::from_millis(150));
        }
        // Then quiet.
        let t0 = std::time::Instant::now();
        expect_closed(&mut s, Duration::from_secs(5));
        assert!(t0.elapsed() >= Duration::from_millis(250), "{:?}", t0.elapsed());
        e.shutdown();
        e.wait();
    }
}

/// HTTP CONNECT whose upstream never answers the SYN is cut off at the handshake timeout
/// (10.255.255.1 is unroutable on most hosts; if it is refused at once, a 502 comes first).
#[test]
fn connect_handshake_timeout() {
    let er = EngineRef::new();
    let cfg = timeouts(Some(Duration::from_millis(300)), None);
    let e = start_with(None, Some(cfg), &er);
    let mut s = http_connect(e.local_addrs()[0], "10.255.255.1:9");
    let all = expect_closed(&mut s, Duration::from_secs(5));
    let all = String::from_utf8_lossy(&all);
    assert!(all.is_empty() || all.starts_with("HTTP/1.1 502"), "{all}");
    e.shutdown();
    e.wait();
}
