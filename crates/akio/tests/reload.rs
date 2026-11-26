//! Hot reload of the read buffer, listen backlog, UDP idle timeout and write timeout
//! (ADR-108), and I/O thread resizing under load (ADR-028).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpStream, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use akio::{Acceptor, Config, Conn, Engine, Handler, Listener, fn_acceptor};

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn quick() -> Config {
    let mut v = Config::default();
    v.shutdown_timeout = Duration::from_millis(300);
    v
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

/// `read_exact`, retrying EINTR (io_uring in-process can interrupt blocking reads).
fn read_n(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    let mut off = 0;
    while off < n {
        match s.read(&mut buf[off..]) {
            Ok(0) => panic!("eof after {off} of {n} bytes"),
            Ok(k) => off += k,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => panic!("read: {e}"),
        }
    }
    buf
}

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

fn wait_until(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
    let t0 = Instant::now();
    while t0.elapsed() < limit {
        if f() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    f()
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

/// Echo that records the largest chunk `on_data` was handed.
struct Echo(Arc<AtomicUsize>);
impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        self.0.fetch_max(data.len(), Ordering::Relaxed);
        let _ = c.send(data);
    }
}

/// An echo acceptor whose `on_shutdown` closes the connection once its output is out.
struct Closing(Arc<AtomicUsize>);
impl Acceptor for Closing {
    type Handler = Echo;
    fn on_open(&self, _c: &Conn<Echo>) -> Echo {
        Echo(self.0.clone())
    }
    fn on_shutdown(&self, c: &Conn<Echo>) {
        c.close_after_send();
    }
}

fn echo_engine(cfg: Config, threads: usize) -> (Engine, SocketAddr, Arc<AtomicUsize>) {
    let max = Arc::new(AtomicUsize::new(0));
    let e = Engine::builder()
        .config(cfg)
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(threads)
                .serve(Closing(max.clone())),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    (e, addr, max)
}

/// Sends `n` bytes and reads them back, from a writer thread so neither side's buffers fill.
fn echo_bulk(s: &mut TcpStream, n: usize) {
    let mut w = s.try_clone().unwrap();
    let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
    let expect = data.clone();
    let t = thread::spawn(move || w.write_all(&data).unwrap());
    assert_eq!(read_n(s, n), expect);
    t.join().unwrap();
}

#[test]
fn reloaded_read_buffer_applies_to_open_connections() {
    let (e, addr, max) = echo_engine(quick(), 1);
    let mut a = connect(addr);
    echo_bulk(&mut a, 1 << 20);
    let before = max.swap(0, Ordering::Relaxed);
    assert!(
        before > 1024,
        "chunks of up to {before} bytes before the reload"
    );

    let mut cfg = quick();
    cfg.read_buffer = 1024;
    let r = e.reload(&cfg);
    assert_eq!(r.applied, vec!["read_buffer"]);
    assert_eq!(e.telemetry().live().read_buffer(), 1024);
    // The loop applies it at its next reload notification; one round trip after that settles
    // it (on io_uring the connection's receive moves to the new buffers when re-armed).
    thread::sleep(Duration::from_millis(100));
    a.write_all(b"x").unwrap();
    assert_eq!(read_n(&mut a, 1), b"x");
    max.store(0, Ordering::Relaxed);
    // The same, already open connection now reads at most 1 KiB at a time.
    echo_bulk(&mut a, 1 << 20);
    let after = max.load(Ordering::Relaxed);
    assert!(
        after <= 1024,
        "chunks of up to {after} bytes after the reload"
    );
    // A new connection too.
    let mut b = connect(addr);
    echo_bulk(&mut b, 256 << 10);
    assert!(max.load(Ordering::Relaxed) <= 1024);

    // And back up, several times in a row (io_uring: a change while the previous buffers are
    // still in use waits for them).
    for rb in [4096, 512, 8192] {
        cfg.read_buffer = rb;
        e.reload(&cfg);
        echo_bulk(&mut a, 64 << 10);
    }
    thread::sleep(Duration::from_millis(100));
    a.write_all(b"y").unwrap();
    assert_eq!(read_n(&mut a, 1), b"y");
    max.store(0, Ordering::Relaxed);
    echo_bulk(&mut a, 1 << 20);
    assert!(max.load(Ordering::Relaxed) <= 8192);
    assert!(max.load(Ordering::Relaxed) > 1024);
    drop((a, b));
    stop(&e);
}

#[test]
fn reloaded_backlog_relistens_the_live_socket() {
    // An inherited listener lets the test keep a handle on the very socket the engine serves.
    let std_l = std::net::TcpListener::bind(localhost()).unwrap();
    let probe = std_l.try_clone().unwrap();
    let max = Arc::new(AtomicUsize::new(0));
    let e = Engine::builder()
        .config(quick())
        .listen(
            Listener::tcp_from_std(std_l)
                .backend(common::backend())
                .threads(2)
                .serve(Closing(max)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let mut cfg = quick();
    cfg.backlog = 77;
    assert_eq!(e.reload(&cfg).applied, vec!["backlog"]);
    #[cfg(target_os = "linux")]
    assert!(
        wait_until(Duration::from_secs(3), || akio_sys_backlog(&probe) == 77),
        "backlog {}",
        akio_sys_backlog(&probe)
    );
    #[cfg(not(target_os = "linux"))]
    drop(probe);
    // Still serving.
    let mut c = connect(addr);
    c.write_all(b"ok").unwrap();
    assert_eq!(read_n(&mut c, 2), b"ok");
    drop(c);
    stop(&e);
}

#[cfg(target_os = "linux")]
fn akio_sys_backlog(l: &std::net::TcpListener) -> u32 {
    akio_sys::listen_backlog(l).unwrap()
}

#[test]
fn reloaded_udp_idle_timeout_applies_to_open_peers() {
    struct UdpEcho(Arc<AtomicUsize>);
    impl Handler for UdpEcho {
        fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
            let _ = c.send(data);
        }
        fn on_close(&mut self, _c: &Conn<Self>, _err: Option<akio::Error>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let closed = Arc::new(AtomicUsize::new(0));
    let c2 = closed.clone();
    let e = Engine::builder()
        .config(quick())
        .listen(
            Listener::udp(localhost())
                .threads(1)
                .serve(fn_acceptor(move |_c: &Conn<UdpEcho>| UdpEcho(c2.clone()))),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let s = UdpSocket::bind(localhost()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.send_to(b"hi", addr).unwrap();
    let mut b = [0u8; 16];
    assert_eq!(s.recv(&mut b).unwrap(), 2);
    // 60 s by default: the peer would stay. Shorten it at runtime.
    let mut cfg = quick();
    cfg.udp_idle_timeout = Duration::from_millis(200);
    assert_eq!(e.reload(&cfg).applied, vec!["udp_idle_timeout"]);
    assert!(wait_until(Duration::from_secs(3), || closed
        .load(Ordering::Relaxed)
        == 1));
    assert_eq!(e.metrics().total.idle_timeouts, 1);
    stop(&e);
}

#[test]
fn reloaded_write_timeout_applies_to_open_connections() {
    const BIG: usize = 4 << 20;
    // Each read asks for `BIG` bytes more; the peer never reads them.
    struct Flood(Arc<Mutex<Vec<ErrorKind>>>);
    impl Handler for Flood {
        fn on_data(&mut self, c: &Conn<Self>, _data: &[u8]) {
            let _ = c.send(&vec![7u8; BIG]);
        }
        fn on_close(&mut self, _c: &Conn<Self>, err: Option<akio::Error>) {
            if let Some(akio::Error::Io(e)) = err {
                self.0.lock().unwrap().push(e.kind());
            }
        }
    }
    let kinds = Arc::new(Mutex::new(Vec::new()));
    let k = kinds.clone();
    let mut cfg = quick();
    cfg.write_timeout = None;
    cfg.max_queued_bytes = 64 << 20;
    let e = Engine::builder()
        .config(cfg.clone())
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(move |_c: &Conn<Flood>| Flood(k.clone()))),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let mut stalled = connect(addr);
    stalled.write_all(b"go").unwrap();
    // No write timeout: the stalled connection stays.
    thread::sleep(Duration::from_millis(600));
    assert!(kinds.lock().unwrap().is_empty());
    // Turned on at run time: the next write that queues output arms the check.
    cfg.write_timeout = Some(Duration::from_millis(200));
    assert_eq!(e.reload(&cfg).applied, vec!["write_timeout"]);
    assert_eq!(
        e.telemetry().live().write_timeout(),
        Some(Duration::from_millis(200))
    );
    stalled.write_all(b"go").unwrap();
    assert!(wait_until(Duration::from_secs(5), || !kinds
        .lock()
        .unwrap()
        .is_empty()));
    assert_eq!(*kinds.lock().unwrap(), vec![ErrorKind::TimedOut]);
    assert_eq!(e.metrics().total.write_timeouts, 1);
    // Turned off again: a new stalled connection stays, its check (if one was pending) ends.
    e.telemetry().live().set_write_timeout(None);
    let mut stalled2 = connect(addr);
    stalled2.write_all(b"go").unwrap();
    thread::sleep(Duration::from_millis(600));
    stalled2.write_all(b"go").unwrap();
    thread::sleep(Duration::from_millis(300));
    assert_eq!(kinds.lock().unwrap().len(), 1);
    drop((stalled, stalled2));
    stop(&e);
}

// ---- thread resizing ---------------------------------------------------------------------------

/// Load generator: `short` threads each open, exchange and close connections in a loop;
/// `long` connections stay open and echo all along. Every failure is recorded.
struct Load {
    stop: Arc<AtomicBool>,
    errors: Arc<Mutex<Vec<String>>>,
    exchanges: Arc<AtomicU64>,
    handles: Vec<thread::JoinHandle<()>>,
}

impl Load {
    fn start(addr: SocketAddr, short: usize, long: usize) -> Load {
        let stop = Arc::new(AtomicBool::new(false));
        let errors = Arc::new(Mutex::new(Vec::new()));
        let exchanges = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();
        for t in 0..short {
            let (stop, errors, n) = (stop.clone(), errors.clone(), exchanges.clone());
            handles.push(thread::spawn(move || {
                let mut i = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    i += 1;
                    match Self::exchange(addr, t, i) {
                        Ok(()) => {
                            n.fetch_add(1, Ordering::Relaxed);
                        }
                        // The client ran out of ephemeral ports (TIME_WAIT on its side): not the
                        // server's doing; back off.
                        Err(e) if e.kind() == ErrorKind::AddrNotAvailable => {
                            thread::sleep(Duration::from_millis(50));
                        }
                        Err(e) => errors.lock().unwrap().push(format!("short {t}/{i}: {e}")),
                    }
                    // Paced so a long soak stays within the client's ephemeral ports (macOS
                    // has 16k and keeps closed ones 15 s; Linux reuses them on loopback).
                    thread::sleep(Duration::from_millis(if cfg!(target_os = "macos") {
                        10
                    } else {
                        1
                    }));
                }
            }));
        }
        for t in 0..long {
            let (stop, errors, n) = (stop.clone(), errors.clone(), exchanges.clone());
            handles.push(thread::spawn(move || {
                let r = (|| -> std::io::Result<()> {
                    let mut s = loop {
                        match TcpStream::connect(addr) {
                            Err(e) if e.kind() == ErrorKind::AddrNotAvailable => {
                                thread::sleep(Duration::from_millis(100));
                            }
                            r => break r?,
                        }
                    };
                    s.set_read_timeout(Some(Duration::from_secs(10)))?;
                    let mut i = 0u32;
                    while !stop.load(Ordering::Relaxed) {
                        i += 1;
                        let msg = format!("long {t} {i};").into_bytes();
                        s.write_all(&msg)?;
                        let mut got = vec![0u8; msg.len()];
                        read_full(&mut s, &mut got)?;
                        if got != msg {
                            return Err(std::io::Error::other("echo mismatch"));
                        }
                        n.fetch_add(1, Ordering::Relaxed);
                        thread::sleep(Duration::from_millis(2));
                    }
                    Ok(())
                })();
                if let Err(e) = r {
                    errors.lock().unwrap().push(format!("long {t}: {e}"));
                }
            }));
        }
        Load {
            stop,
            errors,
            exchanges,
            handles,
        }
    }

    fn exchange(addr: SocketAddr, t: usize, i: u64) -> std::io::Result<()> {
        let mut s = TcpStream::connect(addr)?;
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        let msg = format!("short {t} {i} ")
            .repeat(1 + (i % 50) as usize)
            .into_bytes();
        s.write_all(&msg)?;
        let mut got = vec![0u8; msg.len()];
        read_full(&mut s, &mut got)?;
        if got != msg {
            return Err(std::io::Error::other("echo mismatch"));
        }
        Ok(())
    }

    fn finish(self) -> (u64, Vec<String>) {
        self.stop.store(true, Ordering::Relaxed);
        for h in self.handles {
            h.join().unwrap();
        }
        let n = self.exchanges.load(Ordering::Relaxed);
        (n, std::mem::take(&mut *self.errors.lock().unwrap()))
    }
}

fn read_full(s: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<()> {
    let mut off = 0;
    while off < buf.len() {
        match s.read(&mut buf[off..]) {
            Ok(0) => return Err(std::io::Error::new(ErrorKind::UnexpectedEof, "eof")),
            Ok(k) => off += k,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Threads of the group serving `addr` by state: (running and active, retiring, exited).
fn loop_states(e: &Engine) -> (usize, usize, usize) {
    let m = e.metrics();
    let (mut active, mut retiring, mut exited) = (0, 0, 0);
    for l in &m.loops {
        match (l.running, l.retiring) {
            (true, false) => active += 1,
            (true, true) => retiring += 1,
            (false, _) => exited += 1,
        }
    }
    (active, retiring, exited)
}

#[test]
fn threads_grow_and_shrink_under_load_without_dropping_connections() {
    if common::work_stealing() {
        return; // work-stealing scheduling refuses set_threads (ADR-104)
    }
    let (e, addr, _) = echo_engine(quick(), 2);
    assert_eq!(e.threads(), vec![2]);
    let load = Load::start(addr, 4, 6);
    thread::sleep(Duration::from_millis(200));
    for n in [4, 1, 3, 1, 2, 5, 2] {
        e.set_threads(0, n).unwrap();
        assert_eq!(e.threads(), vec![n]);
        // Reloads mixed in: none of them may disturb the traffic either.
        let mut cfg = quick();
        cfg.read_buffer = if n % 2 == 0 { 4096 } else { 64 << 10 };
        cfg.backlog = 128 + n as i32;
        e.reload(&cfg);
        thread::sleep(Duration::from_millis(150));
    }
    let before = load.exchanges.load(Ordering::Relaxed);
    thread::sleep(Duration::from_millis(200));
    assert!(
        load.exchanges.load(Ordering::Relaxed) > before,
        "traffic stalled"
    );
    let (n, errors) = load.finish();
    assert!(
        errors.is_empty(),
        "{} errors, first: {:?}",
        errors.len(),
        &errors[..errors.len().min(5)]
    );
    assert!(n > 100, "only {n} exchanges");
    // Once the clients are gone the retired threads exit: two active, three gone.
    assert!(
        wait_until(Duration::from_secs(5), || loop_states(&e) == (2, 0, 3)),
        "{:?}",
        loop_states(&e)
    );
    // One series per thread index ever used (five), not one per loop started.
    assert_eq!(e.metrics().loops.len(), 5);
    let mut c = connect(addr);
    c.write_all(b"end").unwrap();
    assert_eq!(read_n(&mut c, 3), b"end");
    drop(c);
    stop(&e);
}

#[test]
fn retiring_thread_keeps_its_connections_until_they_close() {
    if common::work_stealing() {
        return; // work-stealing scheduling refuses set_threads (ADR-104)
    }
    let (e, addr, _) = echo_engine(quick(), 2);
    // Enough connections that both threads own some.
    let mut conns: Vec<TcpStream> = (0..16).map(|_| connect(addr)).collect();
    for c in &mut conns {
        c.write_all(b"a").unwrap();
        assert_eq!(read_n(c, 1), b"a");
    }
    let owners: Vec<usize> = e
        .connections(Duration::from_secs(2))
        .iter()
        .map(|c| c.owner.thread)
        .collect();
    assert_eq!(owners.len(), 16);
    let on_1 = owners.iter().filter(|&&t| t == 1).count();
    e.set_threads(0, 1).unwrap();
    assert!(wait_until(Duration::from_secs(2), || loop_states(&e) == (1, 1, 0)));
    // Every connection still works, on the thread it started on.
    for c in &mut conns {
        c.write_all(b"b").unwrap();
        assert_eq!(read_n(c, 1), b"b");
    }
    let table = e.connections(Duration::from_secs(2));
    assert_eq!(table.iter().filter(|c| c.owner.thread == 1).count(), on_1);
    // New connections all go to thread 0.
    let mut fresh: Vec<TcpStream> = (0..8).map(|_| connect(addr)).collect();
    for c in &mut fresh {
        c.write_all(b"c").unwrap();
        assert_eq!(read_n(c, 1), b"c");
    }
    let table = e.connections(Duration::from_secs(2));
    assert_eq!(table.iter().filter(|c| c.owner.thread == 1).count(), on_1);
    assert_eq!(table.len(), 24);
    // Closing them lets the retired thread exit.
    drop(conns);
    assert!(
        wait_until(Duration::from_secs(5), || loop_states(&e) == (1, 0, 1)),
        "{:?}",
        loop_states(&e)
    );
    // Growing again starts a thread at index 1, continuing its counters.
    let accepted_1 = e.metrics().loops[1].counters.accepted;
    e.set_threads(0, 2).unwrap();
    assert!(wait_until(Duration::from_secs(2), || loop_states(&e) == (2, 0, 0)));
    assert!(e.metrics().loops[1].counters.accepted >= accepted_1);
    let mut more: Vec<TcpStream> = (0..32).map(|_| connect(addr)).collect();
    for c in &mut more {
        c.write_all(b"d").unwrap();
        assert_eq!(read_n(c, 1), b"d");
    }
    drop((fresh, more));
    stop(&e);
}

#[test]
fn revived_thread_takes_connections_again() {
    if common::work_stealing() {
        return; // work-stealing scheduling refuses set_threads (ADR-104)
    }
    let (e, addr, _) = echo_engine(quick(), 2);
    let mut conns: Vec<TcpStream> = (0..16).map(|_| connect(addr)).collect();
    for c in &mut conns {
        c.write_all(b"a").unwrap();
        assert_eq!(read_n(c, 1), b"a");
    }
    e.set_threads(0, 1).unwrap();
    // Still retiring (it has connections): growing makes it active again, same thread.
    e.set_threads(0, 2).unwrap();
    assert!(wait_until(Duration::from_secs(2), || loop_states(&e) == (2, 0, 0)));
    let accepted = e.metrics().loops[1].counters.accepted;
    let mut more: Vec<TcpStream> = (0..64).map(|_| connect(addr)).collect();
    for c in &mut more {
        c.write_all(b"b").unwrap();
        assert_eq!(read_n(c, 1), b"b");
    }
    // Linux spreads SO_REUSEPORT connections by hash; elsewhere the threads race on one
    // socket. Either way thread 1 takes part again (64 connections make a miss improbable).
    assert!(
        wait_until(Duration::from_secs(2), || e.metrics().loops[1]
            .counters
            .accepted
            > accepted),
        "thread 1 accepted nothing after being revived: accepted before {accepted}, loops {:?}",
        e.metrics()
            .loops
            .iter()
            .map(|l| (
                l.running,
                l.retiring,
                l.counters.accepted,
                l.counters.accept_errors
            ))
            .collect::<Vec<_>>()
    );
    drop((conns, more));
    stop(&e);
}

#[test]
fn retire_timeout_shuts_down_what_a_retired_thread_still_serves() {
    if common::work_stealing() {
        return; // work-stealing scheduling refuses set_threads (ADR-104)
    }
    let mut cfg = quick();
    cfg.retire_timeout = Some(Duration::from_millis(200));
    let (e, addr, _) = echo_engine(cfg, 2);
    let mut conns: Vec<TcpStream> = (0..16).map(|_| connect(addr)).collect();
    for c in &mut conns {
        c.write_all(b"a").unwrap();
        assert_eq!(read_n(c, 1), b"a");
    }
    let on_1: Vec<u64> = e
        .connections(Duration::from_secs(2))
        .iter()
        .filter(|c| c.owner.thread == 1)
        .map(|c| c.id)
        .collect();
    assert!(!on_1.is_empty());
    e.set_threads(0, 1).unwrap();
    // `on_shutdown` closes them (this acceptor's choice); the thread then exits.
    assert!(
        wait_until(Duration::from_secs(5), || loop_states(&e) == (1, 0, 1)),
        "{:?}",
        loop_states(&e)
    );
    let closed = conns
        .iter_mut()
        .map(|c| closed_within(c, Duration::from_millis(50)))
        .filter(|&c| c)
        .count();
    assert_eq!(closed, on_1.len());
    stop(&e);
}

#[test]
fn client_group_threads_resize_and_dials_spread() {
    struct Count(Arc<AtomicUsize>);
    impl Handler for Count {
        fn on_data(&mut self, c: &Conn<Self>, _data: &[u8]) {
            self.0.fetch_add(1, Ordering::Relaxed);
            c.close();
        }
    }
    let (srv, addr, _) = echo_engine(quick(), 1);
    let e = Engine::builder()
        .config(quick())
        .client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    assert_eq!(e.threads(), vec![1]);
    e.set_threads(0, 3).unwrap();
    assert_eq!(e.threads(), vec![3]);
    let got = Arc::new(AtomicUsize::new(0));
    for _ in 0..30 {
        let g = got.clone();
        e.dial(
            addr,
            fn_acceptor(move |c: &Conn<Count>| {
                let _ = c.send(b"x");
                Count(g.clone())
            }),
            |err| panic!("dial: {err}"),
        );
    }
    assert!(wait_until(Duration::from_secs(5), || got
        .load(Ordering::Relaxed)
        == 30));
    let m = e.metrics();
    assert!(
        m.loops.iter().all(|l| l.counters.dialed >= 5),
        "{:?}",
        m.loops
            .iter()
            .map(|l| l.counters.dialed)
            .collect::<Vec<_>>()
    );
    e.set_threads(0, 1).unwrap();
    for _ in 0..10 {
        let g = got.clone();
        e.dial(
            addr,
            fn_acceptor(move |c: &Conn<Count>| {
                let _ = c.send(b"x");
                Count(g.clone())
            }),
            |err| panic!("dial: {err}"),
        );
    }
    assert!(wait_until(Duration::from_secs(5), || got
        .load(Ordering::Relaxed)
        == 40));
    assert!(wait_until(Duration::from_secs(5), || loop_states(&e) == (1, 0, 2)));
    stop(&e);
    stop(&srv);
}

#[test]
fn set_threads_errors() {
    if common::work_stealing() {
        return; // work-stealing scheduling refuses set_threads (ADR-104)
    }
    let (e, _addr, _) = echo_engine(quick(), 1);
    assert_eq!(e.set_threads(5, 2).unwrap_err().kind(), ErrorKind::NotFound);
    // 0 means 1.
    e.set_threads(0, 0).unwrap();
    assert_eq!(e.threads(), vec![1]);
    e.shutdown();
    assert_eq!(
        e.set_threads(0, 2).unwrap_err().kind(),
        ErrorKind::NotConnected
    );
    e.wait();

    let u = Engine::builder()
        .listen(
            Listener::udp(localhost())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<Nop>| Nop)),
        )
        .build()
        .unwrap();
    u.start().unwrap();
    assert_eq!(
        u.set_threads(0, 2).unwrap_err().kind(),
        ErrorKind::Unsupported
    );
    stop(&u);

    let n = Engine::builder()
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<Nop>| Nop)),
        )
        .build()
        .unwrap();
    assert_eq!(
        n.set_threads(0, 2).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
}

struct Nop;
impl Handler for Nop {
    fn on_data(&mut self, _c: &Conn<Self>, _data: &[u8]) {}
}

/// Long-running soak: resizes and reloads continuously under load for `AKIO_SOAK_SECS`
/// (default 60) seconds. `cargo test -p akio --release --test reload soak -- --ignored`.
#[test]
#[ignore = "soak test; run explicitly"]
fn soak_resize_and_reload_under_load() {
    let secs: u64 = std::env::var("AKIO_SOAK_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let max_threads: usize = std::env::var("AKIO_SOAK_THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8);
    let (e, addr, _) = echo_engine(quick(), 2);
    let load = Load::start(addr, 8, 32);
    let t0 = Instant::now();
    let mut step = 0u64;
    let mut rng = 0x9e37_79b9_7f4a_7c15u64;
    while t0.elapsed() < Duration::from_secs(secs) {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let n = 1 + (rng % max_threads as u64) as usize;
        e.set_threads(0, n).unwrap();
        let mut cfg = quick();
        cfg.read_buffer = [512, 4096, 16 << 10, 64 << 10][(rng >> 8) as usize % 4];
        cfg.backlog = 64 + (rng >> 16) as i32 % 1024;
        cfg.idle_timeout = Some(Duration::from_secs(30));
        e.reload(&cfg);
        step += 1;
        thread::sleep(Duration::from_millis(20 + (rng >> 24) % 200));
    }
    let (n, errors) = load.finish();
    let m = e.metrics();
    eprintln!(
        "soak: {secs} s, {step} resizes, {n} exchanges, {} accepted, threads {:?}, states {:?}",
        m.total.accepted,
        e.threads(),
        loop_states(&e)
    );
    assert!(
        errors.is_empty(),
        "{} errors, first: {:?}",
        errors.len(),
        &errors[..errors.len().min(5)]
    );
    stop(&e);
}
