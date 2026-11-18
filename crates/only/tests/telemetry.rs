//! Metrics, the connection table, slow-callback records and live reload.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpStream, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use only::{Config, Conn, Engine, Error, Handler, Listener, SlowHook, fn_acceptor};

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

/// `read_exact`, retrying EINTR (io_uring in-process can interrupt blocking reads).
fn read_n(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut v = vec![0; n];
    let mut got = 0;
    while got < n {
        match s.read(&mut v[got..]) {
            Ok(0) => panic!("eof after {got} of {n}"),
            Ok(k) => got += k,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => panic!("read: {e}"),
        }
    }
    v
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

struct Echo;
impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
}

fn quick() -> Config {
    {
        let mut v = Config::default();
        v.shutdown_timeout = Duration::from_millis(300);
        v
    }
}

fn echo_engine(cfg: Config, threads: usize) -> (Engine, SocketAddr) {
    let e = Engine::builder()
        .config(cfg)
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(threads)
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    (e, addr)
}

/// Metrics once `done` holds (up to 5 s): a reply reaches the client a moment before the
/// server thread records the write that sent it.
fn settled(e: &Engine, done: impl Fn(&only::Metrics) -> bool) -> only::Metrics {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let m = e.metrics();
        if done(&m) || Instant::now() > until {
            return m;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

#[test]
fn metrics_count_connections_bytes_and_render_prometheus() {
    let (e, addr) = echo_engine(quick(), 2);
    let mut clients: Vec<TcpStream> = (0..3).map(|_| connect(addr)).collect();
    for c in &mut clients {
        c.write_all(&[7u8; 1000]).unwrap();
        assert_eq!(read_n(c, 1000), vec![7u8; 1000]);
    }
    let m = settled(&e, |m| m.total.bytes_out >= 3000 && m.total.writes >= 3);
    assert_eq!(m.loops.len(), 2, "one entry per I/O thread");
    assert!(m.loops.iter().all(|l| l.running));
    assert_eq!(m.total.accepted, 3);
    assert_eq!(m.total.bytes_in, 3000);
    assert_eq!(m.total.bytes_out, 3000);
    assert!(m.total.reads >= 3 && m.total.writes >= 3);
    assert!(m.total.iterations > 0 && m.total.events > 0);
    assert!(m.total.callbacks >= 3);
    assert_eq!(m.total.queued_bytes, 0);
    assert_eq!(m.open_connections, 3);
    assert_eq!(m.loops.iter().map(|l| l.open()).sum::<u64>(), 3);
    assert!(m.pool.is_some());

    let text = m.to_prometheus();
    assert!(text.contains("# TYPE only_connections_accepted_total counter"));
    assert!(text.contains(&format!(
        "only_written_bytes_total{{listener=\"{addr}\",backend="
    )));
    assert!(text.contains("# TYPE only_send_queue_bytes gauge"));
    assert!(text.contains("only_pool_threads "));
    // Every sample line is `name{labels} value` or `name value`.
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let v = line.rsplit(' ').next().unwrap();
        assert!(v.parse::<f64>().is_ok(), "bad sample line: {line}");
    }
    // The same series as `Families` (what push exporters read), rendered identically.
    let mut fam = only::metrics::Families::new();
    m.collect_into(&mut fam);
    let samples = |t: &str| {
        let mut v: Vec<String> = t
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(str::to_owned)
            .collect();
        v.sort();
        v
    };
    assert_eq!(samples(&fam.to_prometheus()), samples(&text));
    assert_eq!(fam.dropped(), 0);
    let all = e.telemetry().collect_all();
    assert!(all.get("only_connections_accepted_total").is_some());
    let json = m.to_json();
    assert!(json.starts_with('{') && json.contains("\"bytes_in\":3000"));

    drop(clients);
    assert!(wait_until(Duration::from_secs(5), || {
        e.metrics().total.closed == 3 && e.telemetry().open_connections() == 0
    }));
    stop(&e);
    assert!(e.metrics().loops.iter().all(|l| !l.running));
}

#[test]
fn connection_table_lists_every_connection() {
    let (e, addr) = echo_engine(quick(), 2);
    let mut clients: Vec<TcpStream> = (0..4).map(|_| connect(addr)).collect();
    for (i, c) in clients.iter_mut().enumerate() {
        c.write_all(&vec![1u8; 10 * (i + 1)]).unwrap();
        read_n(c, 10 * (i + 1));
    }
    let rows = e.connections(Duration::from_secs(5));
    assert_eq!(rows.len(), 4, "{rows:?}");
    for c in &clients {
        let local = c.local_addr().unwrap();
        let r = rows
            .iter()
            .find(|r| r.peer == local)
            .expect("row per client");
        assert_eq!(r.local, addr);
        assert_eq!(r.owner.listener, Some(addr));
        assert_eq!(r.bytes_in, r.bytes_out);
        assert!(r.bytes_in >= 10);
        assert_eq!(r.queued_bytes, 0);
        assert!(!r.udp && r.transport.is_none() && !r.read_held);
    }
    let json = only::telemetry::connections_json(&rows);
    assert!(json.starts_with('[') && json.matches("\"peer\"").count() == 4);
    stop(&e);
    // Stopped threads are not asked (and the call does not wait for them).
    let t0 = Instant::now();
    assert!(e.connections(Duration::from_secs(5)).is_empty());
    assert!(t0.elapsed() < Duration::from_secs(1));
}

struct Sleepy;
impl Handler for Sleepy {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        thread::sleep(Duration::from_millis(30));
        let _ = c.send(data);
    }
}

#[test]
fn slow_callbacks_are_recorded_counted_and_hooked() {
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let mut cfg = quick();
    cfg.slow_callback_threshold = Some(Duration::from_millis(10));
    cfg.slow_hook = Some(SlowHook(Arc::new(move |_| {
        h.fetch_add(1, Ordering::SeqCst);
    })));
    let e = Engine::builder()
        .config(cfg)
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<Sleepy>| Sleepy)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let mut c = connect(e.local_addrs()[0]);
    c.write_all(b"x").unwrap();
    read_n(&mut c, 1);
    let recs = e.slow_callbacks();
    assert_eq!(recs.len(), 1, "{recs:?}");
    assert_eq!(recs[0].kind, "on_data");
    assert!(recs[0].elapsed >= Duration::from_millis(25));
    assert_eq!(recs[0].threshold, Duration::from_millis(10));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(e.metrics().total.slow_callbacks, 1);
    assert!(e.metrics().total.callback_ns >= 25_000_000);

    // Raising the threshold at runtime silences the detector.
    e.telemetry()
        .live()
        .set_slow_callback_threshold(Some(Duration::from_secs(1)));
    c.write_all(b"y").unwrap();
    read_n(&mut c, 1);
    assert_eq!(e.slow_callbacks().len(), 1);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    drop(c);
    stop(&e);
}

#[test]
fn reload_enables_and_disables_the_idle_timeout_for_open_connections() {
    let (e, addr) = echo_engine(quick(), 1);
    let mut a = connect(addr);
    a.write_all(b"hi").unwrap();
    read_n(&mut a, 2);

    // Enable: the already open connection is closed for idleness.
    let mut cfg = quick();
    cfg.idle_timeout = Some(Duration::from_millis(150));
    cfg.read_buffer = 1234; // not reloadable
    let r = e.reload(&cfg);
    assert!(r.applied.contains(&"idle_timeout"), "{r:?}");
    assert_eq!(r.ignored, vec!["read_buffer"]);
    assert!(closed_within(&mut a, Duration::from_secs(3)));
    assert!(wait_until(Duration::from_secs(2), || e
        .metrics()
        .total
        .idle_timeouts
        == 1));

    // Disable again: a quiet connection now stays open.
    let mut b = connect(addr);
    b.write_all(b"hi").unwrap();
    read_n(&mut b, 2);
    cfg.idle_timeout = None;
    let r = e.reload(&cfg);
    assert_eq!(r.applied, vec!["idle_timeout"]);
    assert!(!closed_within(&mut b, Duration::from_millis(500)));
    b.write_all(b"ok").unwrap();
    assert_eq!(read_n(&mut b, 2), b"ok");
    // A reload with nothing changed reports nothing.
    assert_eq!(e.reload(&cfg).applied, Vec::<&str>::new());
    drop(b);
    stop(&e);
}

#[test]
fn max_connections_refuses_accepts_beyond_the_limit() {
    let (e, addr) = echo_engine(
        {
            let mut v = quick();
            v.max_connections = 2;
            v
        },
        1,
    );
    let mut a = connect(addr);
    let mut b = connect(addr);
    for s in [&mut a, &mut b] {
        s.write_all(b"1").unwrap();
        read_n(s, 1);
    }
    let mut c = connect(addr);
    assert!(closed_within(&mut c, Duration::from_secs(3)));
    assert_eq!(e.metrics().total.rejected, 1);
    // Raise the limit at runtime: a new connection is served.
    e.telemetry().live().set_max_connections(3);
    let mut d = connect(addr);
    d.write_all(b"2").unwrap();
    assert_eq!(read_n(&mut d, 1), b"2");
    assert_eq!(e.telemetry().open_connections(), 3);
    drop((a, b, d));
    stop(&e);
}

/// Sends `n` bytes on the first byte received and reports the result.
struct Big(usize, Arc<Mutex<Option<Result<(), Error>>>>);
impl Handler for Big {
    fn on_data(&mut self, c: &Conn<Self>, _data: &[u8]) {
        *self.1.lock().unwrap() = Some(c.send(&vec![0u8; self.0]));
    }
}

#[test]
fn reloaded_queue_limit_applies_and_overload_is_counted() {
    let res = Arc::new(Mutex::new(None));
    let r2 = res.clone();
    let e = Engine::builder()
        .config(quick())
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(move |_c: &Conn<Big>| Big(1 << 20, r2.clone()))),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let mut cfg = quick();
    cfg.max_queued_bytes = 64 << 10;
    assert_eq!(e.reload(&cfg).applied, vec!["max_queued_bytes"]);
    let mut c = connect(e.local_addrs()[0]);
    c.write_all(b"go").unwrap();
    assert!(wait_until(Duration::from_secs(5), || res
        .lock()
        .unwrap()
        .is_some()));
    assert!(matches!(*res.lock().unwrap(), Some(Err(Error::Overloaded))));
    assert_eq!(e.metrics().total.overloaded, 1);
    drop(c);
    stop(&e);
}

/// Sends a large reply without reading: the send queue and the backpressure counter move.
struct Flood;
impl Handler for Flood {
    fn on_data(&mut self, c: &Conn<Self>, _data: &[u8]) {
        let _ = c.send(&vec![1u8; 8 << 20]);
    }
}

#[test]
fn send_queue_gauge_and_backpressure_events() {
    let e = Engine::builder()
        .config(quick())
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<Flood>| Flood)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let mut c = connect(e.local_addrs()[0]);
    c.write_all(b"go").unwrap();
    assert!(wait_until(Duration::from_secs(5), || {
        let m = e.metrics();
        m.total.queued_bytes > 0 && m.total.backpressure >= 1
    }));
    let rows = e.connections(Duration::from_secs(5));
    assert_eq!(rows.len(), 1);
    assert!(rows[0].queued_bytes > 0 && rows[0].backpressure);
    // Drain it: the gauge returns to zero.
    let mut left = 8 << 20;
    let mut buf = vec![0u8; 1 << 16];
    while left > 0 {
        match c.read(&mut buf) {
            Ok(0) => panic!("eof"),
            Ok(n) => left -= n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => panic!("{e}"),
        }
    }
    assert!(wait_until(Duration::from_secs(5), || e
        .metrics()
        .total
        .queued_bytes
        == 0));
    assert_eq!(e.metrics().total.bytes_out, 8 << 20);
    drop(c);
    stop(&e);
}

#[test]
fn udp_datagrams_and_peers_are_counted() {
    let e = Engine::builder()
        .config(quick())
        .listen(
            Listener::udp(localhost())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 64];
    for i in 0..3u8 {
        s.send_to(&[i; 5], addr).unwrap();
        let (n, _) = s.recv_from(&mut buf).unwrap();
        assert_eq!(n, 5);
    }
    let m = settled(&e, |m| m.total.datagrams_out >= 3);
    assert_eq!(m.loops[0].owner.backend, "udp");
    assert_eq!(m.total.datagrams_in, 3);
    assert_eq!(m.total.datagrams_out, 3);
    assert_eq!(m.total.bytes_in, 15);
    assert_eq!(m.total.accepted, 1);
    let rows = e.connections(Duration::from_secs(5));
    assert_eq!(rows.len(), 1);
    assert!(rows[0].udp);
    assert_eq!(rows[0].peer, s.local_addr().unwrap());
    assert_eq!((rows[0].bytes_in, rows[0].bytes_out), (15, 15));
    stop(&e);
}

#[test]
fn reused_config_gets_a_fresh_hub() {
    let cfg = quick();
    let hub = cfg.telemetry.clone();
    let (e1, _) = echo_engine(cfg.clone(), 1);
    assert!(Arc::ptr_eq(e1.telemetry(), &hub));
    let (e2, _) = echo_engine(cfg, 1);
    assert!(!Arc::ptr_eq(e2.telemetry(), &hub));
    assert_eq!(e1.metrics().loops.len(), 1);
    assert_eq!(e2.metrics().loops.len(), 1);
    stop(&e1);
    stop(&e2);
}
