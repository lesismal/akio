//! The sockmap fast path of `CONNECT` tunnels (`ProxyConfig::sockmap`). Needs the relay
//! (privileged; Linux 6.15+ for transfers that fill send buffers): skipped without it unless
//! `ONLY_TEST_EXPECT_EBPF=1`. On older kernels only the small transfers run, through
//! `Relay::new_any_kernel`.
#![allow(missing_docs)]
#![cfg(target_os = "linux")]

use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

use only::{Backend, Config, Engine, EngineRef, Listener, UringConfig, ebpf::Relay};
use only_socks::{Destinations, ProxyConfig, Socks, connect_proxy_with, spliced_tunnels};

/// The splice counter is process-wide: one test at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn expect_ebpf() -> bool {
    std::env::var("ONLY_TEST_EXPECT_EBPF").is_ok_and(|v| v == "1")
}

/// The relay and whether bulk transfers are safe (kernel with the EAGAIN fix).
fn relay() -> Option<(Relay, bool)> {
    match Relay::new(0) {
        Ok(r) => return Some((r, true)),
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {}
        Err(e) if !expect_ebpf() => {
            eprintln!("skipping: {e}");
            return None;
        }
        Err(e) => panic!("relay: {e}"),
    }
    match Relay::new_any_kernel(0) {
        Ok(r) => Some((r, false)),
        Err(e) if !expect_ebpf() => {
            eprintln!("skipping: {e}");
            None
        }
        Err(e) => panic!("relay: {e}"),
    }
}

fn backend() -> Backend {
    if std::env::var("ONLY_TEST_BACKEND").as_deref() == Ok("uring") {
        let mut v = UringConfig::default();
        v.strict = true;
        Backend::IoUring(v)
    } else {
        Backend::Epoll
    }
}

fn cfg(relay: &Relay, idle: Option<Duration>) -> ProxyConfig {
    let mut c = ProxyConfig::default();
    c.destinations = Destinations::Any;
    c.sockmap = Some(relay.clone());
    c.idle_timeout = idle;
    c
}

/// A SOCKS (or with `http`, an HTTP CONNECT) proxy with the fast path.
fn proxy(c: ProxyConfig, http: bool) -> (Arc<Engine>, SocketAddr) {
    let er = EngineRef::new();
    let l = Listener::tcp("127.0.0.1:0".parse().unwrap())
        .backend(backend())
        .threads(2);
    let l = if http {
        l.serve(only_http::serve(connect_proxy_with(er.clone(), c)))
    } else {
        l.serve(Socks::new(er.clone()).config(c))
    };
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_millis(300);
                v
            })
            .listen(l)
            .build()
            .unwrap(),
    );
    er.set(&e);
    e.start().unwrap();
    let a = e.local_addrs()[0];
    (e, a)
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn read_n(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut b = vec![0; n];
    s.read_exact(&mut b).unwrap();
    b
}

/// A tunnel to `target` through the proxy at `p`.
fn tunnel(p: SocketAddr, target: SocketAddr, http: bool) -> TcpStream {
    let mut s = TcpStream::connect(p).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    if http {
        write!(s, "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.extend(read_n(&mut s, 1));
        }
        assert!(head.starts_with(b"HTTP/1.1 200"), "{head:?}");
    } else {
        let SocketAddr::V4(t) = target else {
            unreachable!()
        };
        s.write_all(&[5, 1, 0]).unwrap();
        assert_eq!(read_n(&mut s, 2), [5, 0]);
        let mut req = vec![5, 1, 0, 1];
        req.extend(t.ip().octets());
        req.extend(t.port().to_be_bytes());
        s.write_all(&req).unwrap();
        assert_eq!(read_n(&mut s, 10)[1], 0);
    }
    s
}

/// Runs `serve` on every accepted connection, each on its own thread.
fn server(serve: impl Fn(TcpStream) + Send + Sync + 'static) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    let serve = Arc::new(serve);
    thread::spawn(move || {
        for s in l.incoming().flatten() {
            let f = serve.clone();
            thread::spawn(move || f(s));
        }
    });
    a
}

fn echo(mut s: TcpStream) {
    let mut b = vec![0u8; 64 << 10];
    while let Ok(n) = s.read(&mut b) {
        if n == 0 || s.write_all(&b[..n]).is_err() {
            return;
        }
    }
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 % 251) as u8).collect()
}

#[test]
fn connect_tunnels_are_spliced_in_both_directions() {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let Some((relay, bulk)) = relay() else { return };
    let target = server(echo);
    for http in [false, true] {
        let (e, p) = proxy(cfg(&relay, None), http);
        let before = spliced_tunnels();
        let mut s = tunnel(p, target, http);
        let n = if bulk { 16 << 20 } else { 64 << 10 };
        let data = pattern(n);
        let mut w = s.try_clone().unwrap();
        let d = data.clone();
        let t = thread::spawn(move || w.write_all(&d).unwrap());
        let got = read_n(&mut s, n);
        t.join().unwrap();
        assert!(got == data, "relayed bytes differ (http: {http})");
        assert_eq!(spliced_tunnels(), before + 1, "http: {http}");
        drop(s);
        stop(&e);
    }
}

#[test]
fn a_download_that_ends_with_close_arrives_whole() {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let Some((relay, bulk)) = relay() else { return };
    let n = if bulk { 32 << 20 } else { 32 << 10 };
    // The upstream waits for two bytes (so the tunnel is spliced first), then sends `n` bytes
    // and closes at once: what the kernel still holds for the slow client must not be lost.
    let target = server(move |mut s| {
        let mut go = [0u8; 2];
        if s.read_exact(&mut go).is_ok() {
            let _ = s.write_all(&pattern(n));
        }
    });
    let (e, p) = proxy(cfg(&relay, None), false);
    let before = spliced_tunnels();
    let mut s = tunnel(p, target, false);
    s.write_all(b"go").unwrap();
    thread::sleep(Duration::from_millis(300)); // let the buffers fill
    let mut got = Vec::new();
    s.read_to_end(&mut got).unwrap();
    assert_eq!(got.len(), n);
    assert!(got == pattern(n), "downloaded bytes differ");
    assert_eq!(spliced_tunnels(), before + 1);
    stop(&e);
}

#[test]
fn an_upload_that_ends_with_close_arrives_whole() {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let Some((relay, bulk)) = relay() else { return };
    let n = if bulk { 32 << 20 } else { 32 << 10 };
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    // A slow sink: reads everything until EOF, then reports it.
    let target = server(move |mut s| {
        thread::sleep(Duration::from_millis(300));
        let mut got = Vec::new();
        let _ = s.read_to_end(&mut got);
        let _ = tx.lock().unwrap().send(got);
    });
    let (e, p) = proxy(cfg(&relay, None), false);
    let mut s = tunnel(p, target, false);
    s.write_all(&pattern(n)).unwrap();
    s.shutdown(Shutdown::Write).unwrap();
    let got = rx.recv_timeout(Duration::from_secs(30)).unwrap();
    assert_eq!(got.len(), n);
    assert!(got == pattern(n), "uploaded bytes differ");
    drop(s);
    stop(&e);
}

#[test]
fn early_data_and_greeting_servers_relay_in_userspace() {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let Some((relay, _)) = relay() else { return };
    let (e, p) = proxy(cfg(&relay, None), false);
    // Data behind the request, in the same write: not spliced, and it arrives first.
    let target = server(echo);
    let before = spliced_tunnels();
    let mut s = TcpStream::connect(p).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(&[5, 1, 0]).unwrap();
    assert_eq!(read_n(&mut s, 2), [5, 0]);
    let SocketAddr::V4(t) = target else {
        unreachable!()
    };
    let mut req = vec![5, 1, 0, 1];
    req.extend(t.ip().octets());
    req.extend(t.port().to_be_bytes());
    req.extend(b"early");
    s.write_all(&req).unwrap();
    assert_eq!(read_n(&mut s, 10)[1], 0);
    assert_eq!(read_n(&mut s, 5), b"early");
    s.write_all(b"later").unwrap();
    assert_eq!(read_n(&mut s, 5), b"later");
    assert_eq!(spliced_tunnels(), before);
    // A server that greets first: whether or not the greeting beat the splice, it arrives,
    // and so does what follows.
    let greeter = server(|mut s| {
        let _ = s.write_all(b"220 hello\r\n");
        echo(s);
    });
    for _ in 0..20 {
        let mut s = tunnel(p, greeter, false);
        assert_eq!(read_n(&mut s, 11), b"220 hello\r\n");
        s.write_all(b"ehlo").unwrap();
        assert_eq!(read_n(&mut s, 4), b"ehlo");
    }
    stop(&e);
}

#[test]
fn spliced_tunnels_keep_their_idle_timeout() {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let Some((relay, _)) = relay() else { return };
    let target = server(echo);
    let (e, p) = proxy(cfg(&relay, Some(Duration::from_millis(400))), false);
    let before = spliced_tunnels();
    let mut s = tunnel(p, target, false);
    // Busy for well over the idle timeout: the bytes never reach the handlers.
    for _ in 0..8 {
        s.write_all(b"ping").unwrap();
        assert_eq!(read_n(&mut s, 4), b"ping");
        thread::sleep(Duration::from_millis(150));
    }
    assert_eq!(spliced_tunnels(), before + 1);
    // Then quiet: closed.
    let t0 = Instant::now();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut b = [0u8; 1];
    assert_eq!(s.read(&mut b).unwrap(), 0, "closed, not timed out");
    assert!(
        t0.elapsed() >= Duration::from_millis(250),
        "{:?}",
        t0.elapsed()
    );
    stop(&e);
}
