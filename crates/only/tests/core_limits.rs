//! Engine limits on the hot path: ordered (pipelined) responses held back behind a slow one
//! (`Config::max_pending_responses`, the write watermark, `max_queued_bytes`), and the TLS
//! handshake timeout. Run on both backends (`ONLY_TEST_BACKEND=uring` for io_uring).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use only::{
    Config, Conn, Engine, Error, Handler, Listener, fn_acceptor,
    tls::{self as ftls, Tls},
};

/// What the server saw, shared with the test.
#[derive(Default)]
struct Seen {
    /// A slow response is still being prepared on the pool.
    slow: AtomicBool,
    /// Requests read while the slow response was outstanding.
    read_while_slow: AtomicUsize,
    /// Most reserved responses outstanding at once.
    max_pending: AtomicUsize,
    /// Most bytes held back at once.
    max_held: AtomicUsize,
    /// Reads were paused by the ordered limit at some point.
    paused: AtomicBool,
    /// Reads were no longer paused once the slow response went out.
    resumed: AtomicBool,
    /// `resumed` is set (after the slow response was filled, so possibly after the client
    /// already read it).
    resumed_checked: AtomicBool,
    /// `on_close` ran with an error.
    closed_err: AtomicBool,
}

/// `d`: a response prepared on the pool (slow); `r`: a one-byte response filled at once;
/// `R`: a 16 KiB response filled at once; `.`: padding, not a request.
struct H {
    seen: Arc<Seen>,
    delay: Duration,
}

const BIG: usize = 16 << 10;

impl Handler for H {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        for &b in data {
            if b == b'.' {
                continue;
            }
            let Ok(slot) = c.reserve_response() else {
                return;
            };
            match b {
                b'd' => {
                    self.seen.slow.store(true, Ordering::SeqCst);
                    let (seen, delay, inner) = (self.seen.clone(), self.delay, c.inner().clone());
                    c.spawn_blocking(
                        move || {
                            thread::sleep(delay);
                            seen.slow.store(false, Ordering::SeqCst);
                            slot.fill(b"D".to_vec());
                            seen.resumed.store(!inner.read_held(), Ordering::SeqCst);
                            seen.resumed_checked.store(true, Ordering::SeqCst);
                        },
                        |_, _, ()| {},
                    )
                    .unwrap();
                }
                b'r' => slot.fill(b"r".to_vec()),
                b'R' => slot.fill(vec![b'R'; BIG]),
                _ => slot.fill(Vec::new()),
            }
            if self.seen.slow.load(Ordering::SeqCst) && b != b'd' {
                self.seen.read_while_slow.fetch_add(1, Ordering::SeqCst);
            }
            let (n, held) = c.inner().pending_responses();
            self.seen.max_pending.fetch_max(n, Ordering::SeqCst);
            self.seen.max_held.fetch_max(held, Ordering::SeqCst);
            if c.inner().read_held() {
                self.seen.paused.store(true, Ordering::SeqCst);
            }
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, err: Option<Error>) {
        if err.is_some() {
            self.seen.closed_err.store(true, Ordering::SeqCst);
        }
    }
}

fn start(cfg: Config, delay: Duration) -> (Engine, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let s2 = seen.clone();
    let e = Engine::builder()
        .config(cfg)
        .listen(
            Listener::tcp("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(move |_c: &Conn<H>| H {
                    seen: s2.clone(),
                    delay,
                })),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    (e, seen)
}

/// Whether reads resumed after the slow response (waits for the pool thread to tell).
fn resumed(seen: &Seen) -> bool {
    let t0 = Instant::now();
    while !seen.resumed_checked.load(Ordering::SeqCst) && t0.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(1));
    }
    seen.resumed.load(Ordering::SeqCst)
}

fn base() -> Config {
    let mut v = Config::default();
    v.shutdown_timeout = Duration::from_millis(300);
    // Small reads, so a single read cannot carry many requests past the limit.
    v.read_buffer = 1024;
    v
}

fn connect(e: &Engine) -> TcpStream {
    let s = TcpStream::connect(e.local_addrs()[0]).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

/// Sends `req` from another thread (the server stops reading, so a blocking write of all of
/// it would wait for the replies the test reads here), and reads `want` bytes of replies.
fn exchange(s: &mut TcpStream, req: Vec<u8>, want: usize) -> Vec<u8> {
    let mut w = s.try_clone().unwrap();
    let t = thread::spawn(move || w.write_all(&req));
    let mut got = vec![0u8; want];
    s.read_exact(&mut got).unwrap();
    t.join().unwrap().unwrap();
    got
}

/// One slow response, then thousands of pipelined ones: the server stops reading at the limit
/// (plus what one read carried) until the slow one is out, then answers all, in order.
#[test]
fn pipelined_behind_slow_response_is_bounded() {
    let (e, seen) = start(base(), Duration::from_millis(500));
    let mut s = connect(&e);
    let n = 20_000;
    let mut req = vec![b'd'];
    req.extend(std::iter::repeat_n(b'r', n));
    let got = exchange(&mut s, req, n + 1);
    assert_eq!(got[0], b'D');
    assert!(got[1..].iter().all(|&b| b == b'r'));
    let read = seen.read_while_slow.load(Ordering::SeqCst);
    let max = seen.max_pending.load(Ordering::SeqCst);
    // Paused at 32 pending; a read already in progress is still parsed (up to 1024 bytes).
    assert!(read <= 32 + 2 * 1024, "read {read} requests behind the slow one");
    assert!(max <= 32 + 1024, "{max} responses pending at once");
    assert!(seen.paused.load(Ordering::SeqCst));
    assert!(resumed(&seen));
    e.shutdown();
    e.wait();
}

/// Just under the limit reads never pause; at it they do.
#[test]
fn pending_limit_under_and_at() {
    for (behind, pauses) in [(30usize, false), (31, true)] {
        let mut cfg = base();
        cfg.max_pending_responses = Some(32);
        let (e, seen) = start(cfg, Duration::from_millis(200));
        let mut s = connect(&e);
        let mut req = vec![b'd'];
        req.extend(std::iter::repeat_n(b'r', behind));
        // One write: the slow one and everything behind it arrive in one read.
        let got = exchange(&mut s, req, behind + 1);
        assert_eq!(got[0], b'D');
        assert_eq!(seen.max_pending.load(Ordering::SeqCst), behind + 1);
        assert_eq!(seen.paused.load(Ordering::SeqCst), pauses, "{behind} behind");
        assert!(resumed(&seen));
        e.shutdown();
        e.wait();
    }
}

/// `None`: any number of responses may wait (the byte limits still apply).
#[test]
fn pending_limit_off() {
    let mut cfg = base();
    cfg.max_pending_responses = None;
    let (e, seen) = start(cfg, Duration::from_millis(200));
    let mut s = connect(&e);
    let mut req = vec![b'd'];
    req.extend(std::iter::repeat_n(b'r', 500));
    let got = exchange(&mut s, req, 501);
    assert_eq!(got[0], b'D');
    assert!(!seen.paused.load(Ordering::SeqCst));
    e.shutdown();
    e.wait();
}

/// Large responses behind a slow one pause reads at the write watermark, not at the count.
#[test]
fn held_bytes_pause_at_watermark() {
    let mut cfg = base();
    cfg.max_pending_responses = None;
    cfg.write_high_watermark = 64 << 10;
    cfg.max_queued_bytes = 16 << 20;
    // Requests of 64 bytes and reads of 512 (io_uring's smallest buffer): 8 requests per read.
    cfg.read_buffer = 512;
    let (e, seen) = start(cfg, Duration::from_millis(300));
    let mut s = connect(&e);
    let n = 200;
    let mut req = vec![b'd'];
    for _ in 0..n {
        req.push(b'R');
        req.extend_from_slice(&[b'.'; 63]);
    }
    let got = exchange(&mut s, req, 1 + n * BIG);
    assert_eq!(got[0], b'D');
    assert!(got[1..].iter().all(|&b| b == b'R'));
    assert!(seen.paused.load(Ordering::SeqCst));
    let held = seen.max_held.load(Ordering::SeqCst);
    // Paused once 64 KiB (4 responses) were held: what one read already carried may add to it.
    assert!(held <= (64 << 10) + 8 * BIG, "held {held}");
    let read = seen.read_while_slow.load(Ordering::SeqCst);
    assert!(read <= 4 + 2 * 8, "read {read} requests behind the slow one");
    e.shutdown();
    e.wait();
}

/// Held-back responses over `max_queued_bytes` end the connection instead of growing.
#[test]
fn held_bytes_over_max_closes() {
    let mut cfg = base();
    cfg.max_pending_responses = None;
    cfg.write_high_watermark = 1 << 20; // never pauses first
    cfg.max_queued_bytes = 64 << 10;
    let (e, seen) = start(cfg, Duration::from_millis(300));
    let mut s = connect(&e);
    let mut req = vec![b'd'];
    req.extend(std::iter::repeat_n(b'R', 8)); // 128 KiB behind the slow one
    s.write_all(&req).unwrap();
    let mut sink = Vec::new();
    // Closed (possibly reset) without the responses.
    let _ = s.read_to_end(&mut sink);
    assert!(sink.len() < 8 * BIG, "got {} bytes", sink.len());
    let t0 = Instant::now();
    while !seen.closed_err.load(Ordering::SeqCst) && t0.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(seen.closed_err.load(Ordering::SeqCst));
    e.shutdown();
    e.wait();
}

// ---- TLS handshake timeout ----------------------------------------------------------------

struct Echo;

impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
}

fn tls_server(timeout: Option<Duration>) -> Engine {
    let ck = only_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cfg = ftls::ServerConfig::builder(
        vec![ftls::Certificate::from_der(ck.0.as_der().to_vec())],
        ftls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
    .handshake_timeout(timeout)
    .build()
    .unwrap();
    let e = Engine::builder()
        .config(base())
        .listen(
            Listener::tcp("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                .backend(common::backend())
                .threads(1)
                .serve(Tls::server(cfg, fn_acceptor(|_c: &Conn<Echo>| Echo))),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

/// The first bytes of a ClientHello: a handshake record announcing 512 bytes, and 5 of them.
const PARTIAL_HELLO: &[u8] = &[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03];

/// Whether the server closed `s` within `within` (EOF or reset).
fn closed_within(s: &mut TcpStream, within: Duration) -> bool {
    s.set_read_timeout(Some(within)).unwrap();
    let mut b = [0u8; 64];
    match common::read_retry(s, &mut b) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => !matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
    }
}

/// A client that sends part of a ClientHello and stops is cut off after the timeout and
/// counted as a failed handshake.
#[test]
fn tls_partial_client_hello_times_out() {
    let e = tls_server(Some(Duration::from_millis(300)));
    let mut s = connect(&e);
    s.write_all(PARTIAL_HELLO).unwrap();
    let t0 = Instant::now();
    assert!(closed_within(&mut s, Duration::from_secs(5)));
    let took = t0.elapsed();
    assert!(took >= Duration::from_millis(250), "closed after {took:?}");
    assert!(e.metrics().total.handshake_failures >= 1);
    // A silent client (nothing sent at all) is cut off the same way.
    let mut s = connect(&e);
    assert!(closed_within(&mut s, Duration::from_secs(5)));
    e.shutdown();
    e.wait();
}

/// With the timeout off, a half-finished handshake is left alone; a finished one is never cut
/// by the timeout.
#[test]
fn tls_handshake_timeout_off_and_completed() {
    let e = tls_server(None);
    let mut s = connect(&e);
    s.write_all(PARTIAL_HELLO).unwrap();
    assert!(!closed_within(&mut s, Duration::from_millis(600)));
    e.shutdown();
    e.wait();

    // Completed handshakes outlive the timeout: an `only` client dials, waits past it, echoes.
    let e = tls_server(Some(Duration::from_millis(200)));
    let ck_roots = {
        // Trust anything: this test is about timing, not verification.
        ftls::ClientConfig::builder()
            .insecure_skip_verify()
            .handshake_timeout(Some(Duration::from_millis(200)))
            .build()
            .unwrap()
    };
    let got = Arc::new(std::sync::Mutex::new(Vec::new()));
    let closed = Arc::new(AtomicBool::new(false));
    struct Cli {
        got: Arc<std::sync::Mutex<Vec<u8>>>,
        closed: Arc<AtomicBool>,
    }
    impl Handler for Cli {
        fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
            self.got.lock().unwrap().extend_from_slice(data);
        }
        fn on_close(&mut self, _c: &Conn<Self>, _err: Option<Error>) {
            self.closed.store(true, Ordering::SeqCst);
        }
    }
    let (g2, c2) = (got.clone(), closed.clone());
    let conn = Arc::new(std::sync::Mutex::new(None));
    let conn2 = conn.clone();
    let acc = Tls::client(
        ck_roots,
        "localhost",
        fn_acceptor(move |c: &Conn<Cli>| {
            *conn2.lock().unwrap() = Some(c.clone());
            Cli {
                got: g2.clone(),
                closed: c2.clone(),
            }
        }),
    )
    .unwrap();
    e.dial(e.local_addrs()[0], acc, |err| panic!("dial: {err}"));
    let t0 = Instant::now();
    while conn.lock().unwrap().is_none() && t0.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(5));
    }
    let c = conn.lock().unwrap().clone().unwrap();
    c.send(b"ping").unwrap(); // held until the handshake completes
    thread::sleep(Duration::from_millis(600));
    c.send(b"pong").unwrap();
    let t0 = Instant::now();
    while got.lock().unwrap().len() < 8 && t0.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(&got.lock().unwrap()[..], b"pingpong");
    assert!(!closed.load(Ordering::SeqCst));
    assert_eq!(e.metrics().total.handshake_failures, 0);
    e.shutdown();
    e.wait();
}
