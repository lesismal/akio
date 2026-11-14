//! End-to-end tests of the engine on the platform's native backend (epoll / kqueue).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use only::{Config, Conn, Engine, Error, Handler, Listener, fn_acceptor};

/// Tests keep client sockets open while stopping; don't wait the default 10 s for them.
fn cfg() -> Config {
    {
        let mut v = Config::default();
        v.shutdown_timeout = Duration::from_millis(300);
        v
    }
}

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

struct Echo;
impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
}

fn echo_engine(threads: usize) -> Engine {
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(threads)
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

#[test]
fn echo_many_connections_and_messages() {
    let e = echo_engine(2);
    let addr = e.local_addrs()[0];
    let clients: Vec<_> = (0..16)
        .map(|i| {
            thread::spawn(move || {
                let mut s = connect(addr);
                for j in 0..200u32 {
                    let msg = format!("client {i} message {j}");
                    s.write_all(msg.as_bytes()).unwrap();
                    let mut buf = vec![0; msg.len()];
                    s.read_exact(&mut buf).unwrap();
                    assert_eq!(buf, msg.as_bytes());
                }
            })
        })
        .collect();
    for c in clients {
        c.join().unwrap();
    }
    stop(&e);
}

#[test]
fn large_payload_survives_backpressure() {
    // 8 MiB through a server whose write watermark is tiny: reads pause and resume repeatedly.
    let mut cfg = cfg();
    cfg.write_high_watermark = 16 << 10;
    cfg.read_buffer = 8 << 10;
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
    let data: Vec<u8> = (0..8 << 20).map(|i: usize| (i * 31 % 251) as u8).collect();

    let mut w = connect(addr);
    let mut r = w.try_clone().unwrap();
    let send = data.clone();
    let writer = thread::spawn(move || w.write_all(&send).unwrap());
    let mut got = vec![0u8; data.len()];
    r.read_exact(&mut got).unwrap();
    writer.join().unwrap();
    assert!(got == data, "echoed bytes differ");
    stop(&e);
}

/// Records every connection so another thread can use the handles.
struct Collect;
impl Handler for Collect {
    fn on_data(&mut self, _c: &Conn<Self>, _d: &[u8]) {}
}

#[test]
fn send_from_other_threads_arrives_in_order() {
    let conns: Arc<Mutex<Vec<Conn<Collect>>>> = Arc::default();
    let reg = conns.clone();
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(2)
                .serve(fn_acceptor(move |c: &Conn<Collect>| {
                    reg.lock().unwrap().push(c.clone());
                    Collect
                })),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let mut client = connect(e.local_addrs()[0]);
    while conns.lock().unwrap().is_empty() {
        thread::sleep(Duration::from_millis(5));
    }
    let conn = conns.lock().unwrap()[0].clone();

    // 4 threads each send 1000 numbered 8-byte records; per-thread order must be preserved.
    let senders: Vec<_> = (0..4u32)
        .map(|t| {
            let c = conn.clone();
            thread::spawn(move || {
                for i in 0..1000u32 {
                    let mut rec = [0u8; 8];
                    rec[..4].copy_from_slice(&t.to_be_bytes());
                    rec[4..].copy_from_slice(&i.to_be_bytes());
                    c.send(&rec).unwrap();
                }
            })
        })
        .collect();
    let mut buf = vec![0u8; 4 * 1000 * 8];
    client.read_exact(&mut buf).unwrap();
    for s in senders {
        s.join().unwrap();
    }
    let mut next = [0u32; 4];
    for rec in buf.chunks(8) {
        let t = u32::from_be_bytes(rec[..4].try_into().unwrap()) as usize;
        let i = u32::from_be_bytes(rec[4..].try_into().unwrap());
        assert_eq!(i, next[t], "thread {t} records out of order");
        next[t] += 1;
    }
    assert_eq!(next, [1000; 4]);
    stop(&e);
}

struct Bye;
impl Handler for Bye {
    fn on_data(&mut self, c: &Conn<Self>, _d: &[u8]) {
        let _ = c.send(&vec![7u8; 1 << 20]); // bigger than the socket buffer: must be queued
        c.close_after_send();
        assert!(
            matches!(c.send(b"x"), Err(Error::Closed)),
            "send after close_after_send must fail"
        );
    }
}

#[test]
fn close_after_send_flushes_everything_then_eof() {
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<Bye>| Bye)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let mut s = connect(e.local_addrs()[0]);
    s.write_all(b"go").unwrap();
    let mut all = Vec::new();
    s.read_to_end(&mut all).unwrap(); // EOF arrives only after the whole megabyte
    assert_eq!(all.len(), 1 << 20);
    assert!(all.iter().all(|&b| b == 7));
    stop(&e);
}

struct Counting {
    closed: Arc<AtomicUsize>,
}
impl Handler for Counting {
    fn on_data(&mut self, _c: &Conn<Self>, _d: &[u8]) {}
    fn on_close(&mut self, c: &Conn<Self>, _err: Option<Error>) {
        assert!(matches!(c.send(b"x"), Err(Error::Closed)));
        self.closed.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn on_close_runs_exactly_once_per_connection() {
    let (opened, closed) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let (o2, c2) = (opened.clone(), closed.clone());
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(2)
                .serve(fn_acceptor(move |_c: &Conn<Counting>| {
                    o2.fetch_add(1, Ordering::SeqCst);
                    Counting { closed: c2.clone() }
                })),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    for _ in 0..50 {
        let mut s = connect(addr);
        s.write_all(b"hello").unwrap();
        drop(s);
    }
    for _ in 0..200 {
        if closed.load(Ordering::SeqCst) == 50 {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(opened.load(Ordering::SeqCst), 50);
    assert_eq!(closed.load(Ordering::SeqCst), 50);
    stop(&e);
    assert_eq!(
        closed.load(Ordering::SeqCst),
        50,
        "no double close during shutdown"
    );
}

struct Panicky;
impl Handler for Panicky {
    fn on_data(&mut self, c: &Conn<Self>, d: &[u8]) {
        assert!(d != b"boom", "boom");
        let _ = c.send(d);
    }
}

#[test]
fn handler_panic_closes_only_that_connection() {
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<Panicky>| Panicky)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let mut good = connect(addr);
    let mut bad = connect(addr);
    bad.write_all(b"boom").unwrap();
    let mut buf = [0u8; 8];
    assert_eq!(
        bad.read(&mut buf).unwrap_or(0),
        0,
        "panicking connection is closed"
    );
    good.write_all(b"still alive").unwrap();
    let mut out = [0u8; 11];
    good.read_exact(&mut out).unwrap();
    assert_eq!(&out, b"still alive");
    stop(&e);
}

struct Holder;
impl Handler for Holder {
    fn on_data(&mut self, c: &Conn<Self>, d: &[u8]) {
        let _ = c.send(d);
        c.hold_reads(true);
        let c2 = c.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(300));
            c2.hold_reads(false);
        });
    }
}

#[test]
fn hold_reads_pauses_until_resumed() {
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<Holder>| Holder)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let mut s = connect(e.local_addrs()[0]);
    s.write_all(b"a").unwrap();
    let mut b = [0u8; 1];
    s.read_exact(&mut b).unwrap();
    // Reads are now held: the second message is only processed after the resume.
    let t = std::time::Instant::now();
    s.write_all(b"b").unwrap();
    s.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"b");
    assert!(
        t.elapsed() >= Duration::from_millis(150),
        "reply came while reads were held"
    );
    stop(&e);
}

struct Polite;
impl Handler for Polite {
    fn on_data(&mut self, _c: &Conn<Self>, _d: &[u8]) {}
}
struct PoliteAcceptor;
impl only::Acceptor for PoliteAcceptor {
    type Handler = Polite;
    fn on_open(&self, _c: &Conn<Polite>) -> Polite {
        Polite
    }
    fn on_shutdown(&self, c: &Conn<Polite>) {
        let _ = c.send(b"bye");
        c.close_after_send();
    }
}

#[test]
fn graceful_shutdown_notifies_and_waits_for_close() {
    let e = Arc::new(
        Engine::builder()
            .config(cfg())
            .listen(
                Listener::tcp(localhost())
                    .backend(common::backend())
                    .threads(2)
                    .serve(PoliteAcceptor),
            )
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let mut clients: Vec<_> = (0..8).map(|_| connect(addr)).collect();
    thread::sleep(Duration::from_millis(100)); // let every connection be accepted
    let waiter = {
        let e = e.clone();
        thread::spawn(move || e.wait())
    };
    e.shutdown();
    for c in &mut clients {
        let mut all = Vec::new();
        c.read_to_end(&mut all).unwrap();
        assert_eq!(all, b"bye");
    }
    waiter.join().unwrap(); // wait() returns once every connection closed
    assert!(
        TcpStream::connect(addr).is_err(),
        "listener is closed after shutdown"
    );
}

struct Greeter {
    got: Arc<Mutex<Vec<u8>>>,
}
impl Handler for Greeter {
    fn on_data(&mut self, _c: &Conn<Self>, d: &[u8]) {
        self.got.lock().unwrap().extend_from_slice(d);
    }
}

#[test]
fn dial_connects_and_runs_handler() {
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let got: Arc<Mutex<Vec<u8>>> = Arc::default();
    let g = got.clone();
    e.dial(
        addr,
        fn_acceptor(move |c: &Conn<Greeter>| {
            c.send(b"hello over dial").unwrap();
            Greeter { got: g.clone() }
        }),
        |err| panic!("dial failed: {err}"),
    );
    for _ in 0..200 {
        if got.lock().unwrap().len() == 15 {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(&*got.lock().unwrap(), b"hello over dial");

    // A refused connection reports through on_error.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let (tx, rx) = std::sync::mpsc::channel();
    e.dial(dead, fn_acceptor(|_c: &Conn<Echo>| Echo), move |err| {
        tx.send(err.kind()).unwrap();
    });
    assert!(
        rx.recv_timeout(Duration::from_secs(5)).is_ok(),
        "on_error not called for a refused dial"
    );
    stop(&e);
}

#[test]
fn send_reports_overload_beyond_queue_limit() {
    struct Flood {
        outcome: Arc<Mutex<Option<Error>>>,
    }
    impl Handler for Flood {
        fn on_data(&mut self, c: &Conn<Self>, _d: &[u8]) {
            let chunk = vec![1u8; 64 << 10];
            for _ in 0..4096 {
                if let Err(e) = c.send(&chunk) {
                    *self.outcome.lock().unwrap() = Some(e);
                    return;
                }
            }
        }
    }
    let outcome: Arc<Mutex<Option<Error>>> = Arc::default();
    let o = outcome.clone();
    let mut cfg = cfg();
    cfg.max_queued_bytes = 1 << 20;
    let e = Engine::builder()
        .config(cfg)
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(move |_c: &Conn<Flood>| Flood {
                    outcome: o.clone(),
                })),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let mut s = connect(e.local_addrs()[0]);
    s.write_all(b"go").unwrap(); // and never read: the queue must hit the limit
    for _ in 0..200 {
        if outcome.lock().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(matches!(*outcome.lock().unwrap(), Some(Error::Overloaded)));
    drop(s);
    stop(&e);
}

#[test]
fn ebpf_acceleration_degrades_or_attaches_and_strict_fails_where_unavailable() {
    let build = |strict: bool| {
        Engine::builder()
            .config(cfg())
            .listen(
                Listener::tcp(localhost())
                    .backend(common::backend())
                    .threads(2)
                    .accel(only::Accel::Ebpf({
                        let mut v = only::EbpfConfig::default();
                        v.strict = strict;
                        v
                    }))
                    .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
            )
            .build()
    };
    let e = build(false).unwrap();
    let st = e.accel_status().to_vec();
    if cfg!(target_os = "linux") {
        assert!(matches!(st[0], only::AccelStatus::Steering(_)), "{st:?}");
    } else {
        assert!(matches!(st[0], only::AccelStatus::Degraded(_)), "{st:?}");
        assert_eq!(
            build(true).err().map(|e| e.kind()),
            Some(std::io::ErrorKind::Unsupported)
        );
    }
    // Still serves.
    e.start().unwrap();
    let mut s = connect(e.local_addrs()[0]);
    s.write_all(b"hi").unwrap();
    let mut b = [0u8; 2];
    s.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"hi");
    drop(s);
    stop(&e);
}

#[test]
fn idle_timeout_closes_silent_connections_only() {
    struct H(Arc<Mutex<Vec<std::io::ErrorKind>>>);
    impl Handler for H {
        fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
            let _ = c.send(data);
        }
        fn on_close(&mut self, _c: &Conn<Self>, err: Option<Error>) {
            if let Some(Error::Io(e)) = err {
                self.0.lock().unwrap().push(e.kind());
            }
        }
    }
    let kinds = Arc::new(Mutex::new(Vec::new()));
    let k = kinds.clone();
    let e = Engine::builder()
        .config({
            let mut v = cfg();
            v.idle_timeout = Some(Duration::from_millis(300));
            v
        })
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(2)
                .serve(fn_acceptor(move |_c: &Conn<H>| H(k.clone()))),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let mut silent = connect(addr);
    let mut chatty = connect(addr);
    // `chatty` keeps talking past several timeout periods; `silent` never does.
    let t0 = std::time::Instant::now();
    while t0.elapsed() < Duration::from_millis(1000) {
        chatty.write_all(b"x").unwrap();
        let mut b = [0u8; 1];
        chatty.read_exact(&mut b).unwrap();
        thread::sleep(Duration::from_millis(50));
    }
    // The silent connection was closed by the server (EOF), after roughly the timeout.
    let mut b = [0u8; 1];
    assert_eq!(
        silent.read(&mut b).unwrap(),
        0,
        "idle connection should be closed"
    );
    assert_eq!(*kinds.lock().unwrap(), vec![std::io::ErrorKind::TimedOut]);
    // The chatty one is still alive.
    chatty.write_all(b"y").unwrap();
    let mut b = [0u8; 1];
    chatty.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"y");
    stop(&e);
}

#[test]
fn write_timeout_closes_connections_that_stop_reading() {
    const BIG: usize = 8 << 20;
    struct H(Arc<Mutex<Vec<std::io::ErrorKind>>>);
    impl Handler for H {
        fn on_data(&mut self, c: &Conn<Self>, _data: &[u8]) {
            let _ = c.send(&vec![7u8; BIG]);
        }
        fn on_close(&mut self, _c: &Conn<Self>, err: Option<Error>) {
            if let Some(Error::Io(e)) = err {
                self.0.lock().unwrap().push(e.kind());
            }
        }
    }
    let kinds = Arc::new(Mutex::new(Vec::new()));
    let k = kinds.clone();
    let e = Engine::builder()
        .config({
            let mut v = cfg();
            v.write_timeout = Some(Duration::from_millis(500));
            v
        })
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(2)
                .serve(fn_acceptor(move |_c: &Conn<H>| H(k.clone()))),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    // `stalled` asks for 8 MiB and never reads; `reader` reads it all, which takes longer than
    // the timeout in total but makes progress all along.
    let mut stalled = connect(addr);
    stalled.write_all(b"go").unwrap();
    let mut reader = connect(addr);
    reader.write_all(b"go").unwrap();
    let mut got = 0;
    let mut b = vec![0u8; 64 << 10];
    while got < BIG {
        let n = match reader.read(&mut b) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue, // io_uring in-process
            r => r.unwrap(),
        };
        assert!(n > 0, "reader closed after {got} bytes");
        got += n;
        if got % (1 << 20) < n {
            thread::sleep(Duration::from_millis(150)); // 8 x 150 ms in all: past the timeout
        }
    }
    let t0 = std::time::Instant::now();
    while kinds.lock().unwrap().is_empty() && t0.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(*kinds.lock().unwrap(), vec![std::io::ErrorKind::TimedOut]);
    drop(stalled);
    stop(&e);
}

/// Two listeners of one engine, each on its own backend, serving independently.
#[cfg(target_os = "linux")]
#[test]
fn listeners_can_use_different_backends_in_one_engine() {
    use only::{Backend, UringConfig};
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::tcp(localhost())
                .backend(Backend::Epoll)
                .threads(2)
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .listen(
            Listener::tcp(localhost())
                .backend(Backend::IoUring({
                    let mut v = UringConfig::default();
                    v.strict = true;
                    v
                }))
                .threads(2)
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    for addr in e.local_addrs() {
        let mut c = connect(addr);
        c.write_all(b"hello").unwrap();
        let mut b = [0u8; 5];
        c.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"hello");
    }
    stop(&e);
}

#[test]
fn serves_an_inherited_listener_and_keeps_it_listening_after_shutdown() {
    // A socket bound elsewhere (a supervisor, systemd): the engine serves a clone of it.
    let std_l = std::net::TcpListener::bind(localhost()).unwrap();
    let addr = std_l.local_addr().unwrap();
    let keep = std_l.try_clone().unwrap();
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::tcp_from_std(std_l)
                .backend(common::backend())
                .threads(3)
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    assert_eq!(e.local_addrs(), vec![addr]);
    for i in 0..12u8 {
        let mut s = connect(addr);
        s.write_all(&[i; 5]).unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [i; 5]);
    }
    stop(&e);
    // The engine closed its copies only: the socket still listens and queues connections.
    let _queued = connect(addr);
    keep.set_nonblocking(false).unwrap();
    assert!(keep.accept().is_ok());
}
