//! Engine-wide limits (akit's A214 and A215): the budget of bytes queued across every
//! connection (`Config::max_pending_bytes`, ADR-172) and the limit on accepted connections that
//! dialed ones do not count against (`Config::max_accepted_connections`, ADR-173). Run on both
//! backends (`AKIO_TEST_BACKEND=uring` for io_uring) and with work-stealing scheduling
//! (`AKIO_DEFAULT_SCHEDULING=work-stealing`).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

use akio::{Config, Conn, Engine, Handler, Listener, fn_acceptor};

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

fn wait_until(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
    let t0 = Instant::now();
    while t0.elapsed() < limit {
        if f() {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }
    f()
}

/// True once the peer closed the connection (EOF or reset) within `limit`.
fn closed_within(s: &mut TcpStream, limit: Duration) -> bool {
    s.set_read_timeout(Some(limit)).unwrap();
    let mut b = [0u8; 64];
    loop {
        match s.read(&mut b) {
            Ok(0) => return true,
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return false;
            }
            Err(_) => return true,
        }
    }
}

/// Reads until `want` arrived; `false` if `limit` passed first (or the connection ended).
fn read_until(s: &mut TcpStream, want: u8, limit: Duration) -> bool {
    let until = Instant::now() + limit;
    let mut b = [0u8; 64];
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        s.set_read_timeout(Some(left)).unwrap();
        match s.read(&mut b) {
            Ok(0) => return false,
            Ok(n) if b[..n].contains(&want) => return true,
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
}

/// Reads and discards `n` bytes.
fn drain(s: &mut TcpStream, n: usize) {
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut b = vec![0u8; 256 << 10];
    let mut got = 0;
    while got < n {
        match s.read(&mut b) {
            Ok(0) => panic!("eof after {got} of {n}"),
            Ok(k) => got += k,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => panic!("read: {e}"),
        }
    }
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn quick() -> Config {
    let mut v = Config::default();
    v.shutdown_timeout = Duration::from_millis(300);
    v
}

// ---- max_pending_bytes (A214) ---------------------------------------------------------------

/// What a byte `f` asks for: more than the kernel's buffers on both sides take.
const FLOOD: usize = 48 << 20;

/// `f`: queue `FLOOD` bytes; anything else: echo it.
struct Flood;
impl Handler for Flood {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        for &b in data {
            if b == b'f' {
                c.send(&vec![b'.'; FLOOD]).unwrap();
            } else {
                let _ = c.send(&[b]);
            }
        }
    }
}

fn flood_engine(max_pending: Option<usize>) -> (Engine, SocketAddr) {
    let mut cfg = quick();
    cfg.max_pending_bytes = max_pending;
    cfg.max_queued_bytes = 2 * FLOOD;
    let e = Engine::builder()
        .config(cfg)
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(2)
                .serve(fn_acceptor(|_c: &Conn<Flood>| Flood)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    (e, addr)
}

/// A client that asks for a flood and does not read it, until the engine holds `at_least`
/// bytes for it.
fn slow_client(e: &Engine, addr: SocketAddr, at_least: usize) -> TcpStream {
    let mut a = connect(addr);
    a.write_all(b"f").unwrap();
    assert!(
        wait_until(Duration::from_secs(10), || e.telemetry().pending_bytes()
            >= at_least),
        "queued {} of {at_least}",
        e.telemetry().pending_bytes()
    );
    a
}

/// A client whose reads the budget pauses: what it sent once the engine was over the budget is
/// not echoed (its first read may be: reads pause after the current one).
fn paused_client(addr: SocketAddr) -> TcpStream {
    let mut b = connect(addr);
    b.write_all(b"a").unwrap();
    let _ = read_until(&mut b, b'a', Duration::from_millis(300));
    b.write_all(b"b").unwrap();
    assert!(
        !read_until(&mut b, b'b', Duration::from_millis(500)),
        "read while over the budget"
    );
    b
}

#[test]
fn budget_pauses_every_connection_and_resumes_under_it() {
    let (e, addr) = flood_engine(Some(4 << 20));
    let mut a = slow_client(&e, addr, 8 << 20);
    assert!(wait_until(Duration::from_secs(5), || e
        .telemetry()
        .over_budget()));
    let mut b = paused_client(addr);
    // A new connection is paused too.
    let mut c = paused_client(addr);
    assert!(e.metrics().total.budget_pauses >= 2);
    // The slow client takes its bytes: the queues fall under the budget, the others resume.
    drain(&mut a, FLOOD);
    assert!(
        read_until(&mut b, b'b', Duration::from_secs(5)),
        "b resumed"
    );
    assert!(
        read_until(&mut c, b'b', Duration::from_secs(5)),
        "c resumed"
    );
    assert!(!e.telemetry().over_budget());
    b.write_all(b"z").unwrap();
    assert!(read_until(&mut b, b'z', Duration::from_secs(5)));
    drop((a, b, c));
    stop(&e);
}

#[test]
fn budget_under_and_off() {
    // Under the budget: a flood the budget holds does not pause anyone.
    let (e, addr) = flood_engine(Some(512 << 20));
    let a = slow_client(&e, addr, 8 << 20);
    let mut b = connect(addr);
    for x in *b"ab" {
        b.write_all(&[x]).unwrap();
        assert!(read_until(&mut b, x, Duration::from_secs(5)));
    }
    assert!(!e.telemetry().over_budget());
    assert_eq!(e.metrics().total.budget_pauses, 0);
    drop((a, b));
    stop(&e);
    // No budget (the default): neither.
    let (e, addr) = flood_engine(None);
    assert_eq!(e.telemetry().live().max_pending_bytes(), None);
    let a = slow_client(&e, addr, 8 << 20);
    let mut b = connect(addr);
    for x in *b"ab" {
        b.write_all(&[x]).unwrap();
        assert!(read_until(&mut b, x, Duration::from_secs(5)));
    }
    assert_eq!(e.metrics().total.budget_pauses, 0);
    drop((a, b));
    stop(&e);
}

#[test]
fn budget_removed_or_raised_at_run_time_resumes_reads() {
    let (e, addr) = flood_engine(Some(4 << 20));
    let a = slow_client(&e, addr, 8 << 20);
    assert!(wait_until(Duration::from_secs(5), || e
        .telemetry()
        .over_budget()));
    let mut b = paused_client(addr);
    // Removed by a reload: the paused connection resumes though nothing drained.
    let mut cfg = quick();
    cfg.max_queued_bytes = 2 * FLOOD;
    assert!(e.reload(&cfg).applied.contains(&"max_pending_bytes"));
    assert!(read_until(&mut b, b'b', Duration::from_secs(5)), "resumed");
    assert!(!e.telemetry().over_budget());
    // Set again, at the budget: paused again.
    e.telemetry().live().set_max_pending_bytes(Some(4 << 20));
    assert!(wait_until(Duration::from_secs(5), || e
        .telemetry()
        .over_budget()));
    b.write_all(b"c").unwrap();
    let _ = read_until(&mut b, b'c', Duration::from_millis(300));
    b.write_all(b"d").unwrap();
    assert!(!read_until(&mut b, b'd', Duration::from_millis(500)));
    // Raised above what is queued: resumed.
    e.telemetry().live().set_max_pending_bytes(Some(1 << 30));
    assert!(read_until(&mut b, b'd', Duration::from_secs(5)), "resumed");
    drop((a, b));
    stop(&e);
}

#[test]
fn budget_forgets_connections_that_close_while_paused() {
    let (e, addr) = flood_engine(Some(4 << 20));
    let mut a = slow_client(&e, addr, 8 << 20);
    assert!(wait_until(Duration::from_secs(5), || e
        .telemetry()
        .over_budget()));
    for _ in 0..20 {
        drop(paused_client(addr));
    }
    let mut b = paused_client(addr);
    drain(&mut a, FLOOD);
    assert!(read_until(&mut b, b'b', Duration::from_secs(5)));
    assert!(wait_until(Duration::from_secs(5), || e
        .telemetry()
        .open_connections()
        == 2));
    drop((a, b));
    stop(&e);
}

// ---- max_accepted_connections (A215) --------------------------------------------------------

struct Echo;
impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
}

fn echo_engine(cfg: Config) -> (Engine, SocketAddr) {
    let e = Engine::builder()
        .config(cfg)
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    (e, addr)
}

/// `n` connections the engine dials to a listener of the test's, which keeps them open.
fn dial(e: &Engine, n: usize) -> (TcpListener, Vec<TcpStream>) {
    let l = TcpListener::bind(localhost()).unwrap();
    let to = l.local_addr().unwrap();
    for _ in 0..n {
        e.dial(to, fn_acceptor(|_c: &Conn<Echo>| Echo), |err| {
            panic!("dial: {err}")
        });
    }
    let held = (0..n).map(|_| l.accept().unwrap().0).collect();
    (l, held)
}

fn served(addr: SocketAddr) -> TcpStream {
    let mut s = connect(addr);
    s.write_all(b"1").unwrap();
    assert!(read_until(&mut s, b'1', Duration::from_secs(5)), "served");
    s
}

#[test]
fn accepted_limit_does_not_count_dialed_connections() {
    let mut cfg = quick();
    cfg.max_accepted_connections = 2;
    let (e, addr) = echo_engine(cfg);
    let (_l, _held) = dial(&e, 3);
    assert!(wait_until(Duration::from_secs(5), || e
        .telemetry()
        .open_connections()
        == 3));
    assert_eq!(e.telemetry().open_accepted(), 0);
    // Under and at the limit: served, though the engine has five connections open.
    let a = served(addr);
    let b = served(addr);
    assert_eq!(e.telemetry().open_accepted(), 2);
    assert_eq!(e.telemetry().open_connections(), 5);
    // Over it: closed at once, counted as rejected.
    let mut c = connect(addr);
    assert!(closed_within(&mut c, Duration::from_secs(3)));
    assert!(wait_until(Duration::from_secs(5), || e
        .metrics()
        .total
        .rejected
        == 1));
    assert_eq!(e.telemetry().open_accepted(), 2);
    // One goes: room for the next.
    drop(a);
    assert!(wait_until(Duration::from_secs(5), || e
        .telemetry()
        .open_accepted()
        == 1));
    let d = served(addr);
    // Raised at run time.
    let mut cfg = quick();
    cfg.max_accepted_connections = 3;
    assert_eq!(e.reload(&cfg).applied, vec!["max_accepted_connections"]);
    let f = served(addr);
    assert_eq!(e.telemetry().open_accepted(), 3);
    drop((b, d, f));
    assert!(wait_until(Duration::from_secs(5), || e
        .telemetry()
        .open_accepted()
        == 0));
    stop(&e);
}

#[test]
fn connection_limit_still_counts_dialed_connections() {
    // max_connections counts every connection: with three dialed, a third client is refused.
    let mut cfg = quick();
    cfg.max_connections = 5;
    cfg.max_accepted_connections = 10;
    let (e, addr) = echo_engine(cfg);
    let (_l, _held) = dial(&e, 3);
    assert!(wait_until(Duration::from_secs(5), || e
        .telemetry()
        .open_connections()
        == 3));
    let a = served(addr);
    let b = served(addr);
    let mut c = connect(addr);
    assert!(closed_within(&mut c, Duration::from_secs(3)));
    assert_eq!(e.telemetry().open_accepted(), 2);
    drop((a, b));
    stop(&e);
}
