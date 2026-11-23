//! TCP listeners added, removed and drained on a running engine, and the accept filter
//! (ADR-094). Runs on epoll / kqueue, and on io_uring with `AKIO_TEST_BACKEND=uring`.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use akio::{
    Acceptor, Config, Conn, Engine, Handler, Listener, ListenerId, LoopMetrics, fn_acceptor,
};

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn quick() -> Config {
    let mut v = Config::default();
    v.shutdown_timeout = Duration::from_millis(500);
    v
}

struct Echo;
impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
}

/// Echoes; on shutdown sends "bye" and counts, but leaves the connection open (so the drain
/// deadline is what closes it).
#[derive(Clone, Default)]
struct Lingering {
    shutdowns: Arc<AtomicUsize>,
    closes: Arc<AtomicUsize>,
}

struct LingerConn(Arc<AtomicUsize>);
impl Handler for LingerConn {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<akio::Error>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl Acceptor for Lingering {
    type Handler = LingerConn;
    fn on_open(&self, _c: &Conn<LingerConn>) -> LingerConn {
        LingerConn(self.closes.clone())
    }
    fn on_shutdown(&self, c: &Conn<LingerConn>) {
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        let _ = c.send(b"bye");
    }
}

fn echo_listener(addr: SocketAddr, threads: usize) -> Listener {
    Listener::tcp(addr)
        .backend(common::backend())
        .threads(threads)
        .serve(fn_acceptor(|_c: &Conn<Echo>| Echo))
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

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

fn echo_once(s: &mut TcpStream, msg: &[u8]) {
    s.write_all(msg).unwrap();
    assert_eq!(read_n(s, msg.len()), msg);
}

/// Whether a fresh connection to `addr` is served (echoed), as opposed to accepted by the
/// kernel and then closed or reset by the engine (refused by the filter). A connect that fails
/// (EINTR with io_uring in the process, say) is tried again.
fn served(addr: SocketAddr) -> bool {
    let t = Instant::now();
    loop {
        if let Some(v) = probe(addr) {
            return v;
        }
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "cannot connect to {addr}"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

/// Whether connecting to `addr` is refused (nothing listens there any more).
fn refused(addr: SocketAddr) -> bool {
    matches!(TcpStream::connect(addr), Err(e) if e.kind() == ErrorKind::ConnectionRefused)
}

fn probe(addr: SocketAddr) -> Option<bool> {
    let mut s = TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    if s.write_all(b"ping").is_err() {
        return Some(false);
    }
    let mut b = [0u8; 4];
    let mut off = 0;
    while off < 4 {
        match s.read(&mut b[off..]) {
            Ok(0) => return Some(false),
            Ok(k) => off += k,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                panic!("no answer from {addr}")
            }
            Err(_) => return Some(false),
        }
    }
    Some(&b == b"ping")
}

fn wait_for(what: &str, limit: Duration, c: impl Fn() -> bool) {
    let t = Instant::now();
    while !c() {
        assert!(t.elapsed() < limit, "timed out: {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

/// Whether the peer closed `s` within `limit` (EOF or reset).
fn closed_within(s: &mut TcpStream, limit: Duration) -> bool {
    let end = Instant::now() + limit;
    let mut b = [0u8; 64];
    loop {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        s.set_read_timeout(Some(left)).unwrap();
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

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn loops_of(e: &Engine, addr: SocketAddr) -> Vec<LoopMetrics> {
    e.metrics()
        .loops
        .into_iter()
        .filter(|l| l.owner.listener == Some(addr))
        .collect()
}

#[test]
fn listeners_added_while_running_serve_next_to_the_others() {
    let e = Arc::new(
        Engine::builder()
            .config(quick())
            .listen(echo_listener(localhost(), 2))
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    let first = e.local_addrs()[0];
    // Traffic on the first listener throughout: one long connection and new ones.
    let mut a = connect(first);
    echo_once(&mut a, b"before");
    let stop_hammer = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hammer = {
        let stop = stop_hammer.clone();
        thread::spawn(move || {
            let mut n = 0;
            while !stop.load(Ordering::SeqCst) {
                assert!(served(first), "the first listener stopped serving");
                n += 1;
            }
            n
        })
    };
    let ids: Vec<ListenerId> = (0..3)
        .map(|_| e.add_listener(echo_listener(localhost(), 2)).unwrap())
        .collect();
    assert_eq!(
        ids.iter().map(|i| i.get()).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    echo_once(&mut a, b"during");
    let infos = e.listeners();
    assert_eq!(infos.len(), 4);
    assert_eq!(infos[0].id.get(), 0);
    assert_eq!(infos[0].local_addr, first);
    for info in &infos[1..] {
        assert_ne!(info.local_addr.port(), 0);
        assert_eq!(info.threads, 2);
        assert!(!info.udp);
        let mut c = connect(info.local_addr);
        echo_once(&mut c, b"added");
    }
    // The builder's view is unchanged.
    assert_eq!(e.local_addrs(), vec![first]);
    echo_once(&mut a, b"after");
    // A runtime listener's thread count changes by id.
    e.set_listener_threads(ids[0], 3).unwrap();
    assert_eq!(e.listeners()[1].threads, 3);
    for _ in 0..8 {
        assert!(served(infos[1].local_addr));
    }
    e.set_listener_threads(ids[0], 1).unwrap();
    assert!(served(infos[1].local_addr));
    // Removing and draining them does not disturb the first one either.
    e.remove_listener(ids[1]).unwrap();
    e.shutdown_listener(ids[2], Duration::from_millis(50))
        .unwrap();
    echo_once(&mut a, b"after removal");
    stop_hammer.store(true, Ordering::SeqCst);
    assert!(hammer.join().unwrap() > 0);
    stop(&e);
    assert_eq!(
        e.add_listener(echo_listener(localhost(), 1))
            .unwrap_err()
            .kind(),
        ErrorKind::NotConnected
    );
}

#[test]
fn an_engine_without_listeners_gets_them_before_and_after_start() {
    let e = Arc::new(Engine::builder().config(quick()).build().unwrap());
    let early = e.add_listener(echo_listener(localhost(), 1)).unwrap();
    assert_eq!(early.get(), 0);
    let runner = {
        let e = e.clone();
        thread::spawn(move || e.run().unwrap())
    };
    let late = e.add_listener(echo_listener(localhost(), 2)).unwrap();
    for info in e.listeners() {
        assert!(served(info.local_addr), "{:?}", info.id);
    }
    // `wait` (in `run`) does not return before `shutdown`, though no builder listener exists.
    thread::sleep(Duration::from_millis(100));
    assert!(!runner.is_finished());
    assert!(e.listeners().iter().any(|i| i.id == late));
    e.shutdown();
    runner.join().unwrap();
}

#[test]
fn removal_keeps_open_connections_and_refuses_new_ones() {
    let e = Engine::builder()
        .config(quick())
        .listen(echo_listener(localhost(), 1))
        .build()
        .unwrap();
    e.start().unwrap();
    let other = e.local_addrs()[0];
    let id = e.add_listener(echo_listener(localhost(), 2)).unwrap();
    let addr = e.listeners()[1].local_addr;
    let mut open: Vec<TcpStream> = (0..6).map(|_| connect(addr)).collect();
    for (i, s) in open.iter_mut().enumerate() {
        echo_once(s, format!("hello {i}").as_bytes());
    }
    let accepted_before = e.metrics().total.accepted;
    e.remove_listener(id).unwrap();
    assert!(e.listeners().iter().all(|i| i.id != id));
    // New connections are refused once the threads closed their sockets.
    wait_for("refused", Duration::from_secs(5), || refused(addr));
    // Open connections keep working, under traffic, and so does the other listener.
    for round in 0..20 {
        for s in &mut open {
            echo_once(s, format!("round {round}").as_bytes());
        }
    }
    assert!(served(other));
    // The threads holding connections still run (an idle one may have exited: on macOS the
    // threads race to accept, so one may hold none).
    assert!(loops_of(&e, addr).iter().any(|l| l.running));
    // Once they close, the threads exit and leave the metrics; the totals stay.
    drop(open);
    wait_for("threads exit", Duration::from_secs(5), || {
        e.listeners(); // reaps
        loops_of(&e, addr).is_empty()
    });
    assert!(e.metrics().total.accepted >= accepted_before);
    wait_for(
        "every connection counted closed",
        Duration::from_secs(5),
        || {
            let t = e.metrics().total;
            t.closed == t.accepted
        },
    );
    // Unknown and removed ids.
    assert_eq!(
        e.remove_listener(id).unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        e.shutdown_listener(id, Duration::ZERO).unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        e.set_listener_filter(id, |_| true).unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        e.set_listener_threads(id, 2).unwrap_err().kind(),
        ErrorKind::NotFound
    );
    stop(&e);
}

#[test]
fn removing_a_builder_listener_keeps_its_threads_for_dials() {
    // No client_threads: dials use the threads of the (only) listener.
    let e = Engine::builder()
        .config(quick())
        .listen(echo_listener(localhost(), 1))
        .listen(echo_listener(localhost(), 1))
        .build()
        .unwrap();
    e.start().unwrap();
    let addrs = e.local_addrs();
    let mut held = connect(addrs[1]);
    echo_once(&mut held, b"x");
    e.remove_listener(e.listeners()[1].id).unwrap();
    wait_for("refused", Duration::from_secs(5), || refused(addrs[1]));
    echo_once(&mut held, b"still");
    drop(held);
    // The builder's indexes are stable.
    assert_eq!(e.local_addrs(), addrs);
    // Dialing still works (on the removed listener's threads) after its connections closed.
    thread::sleep(Duration::from_millis(100));
    let (tx, rx) = std::sync::mpsc::channel();
    struct Dialed(std::sync::mpsc::Sender<Vec<u8>>);
    impl Handler for Dialed {
        fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
            let _ = self.0.send(data.to_vec());
        }
    }
    let tx2 = tx;
    e.dial(
        addrs[0],
        fn_acceptor(move |c: &Conn<Dialed>| {
            let _ = c.send(b"dialed");
            Dialed(tx2.clone())
        }),
        |err| panic!("dial failed: {err}"),
    );
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), b"dialed");
    stop(&e);
}

#[test]
fn shutdown_listener_notifies_then_closes_at_the_drain_deadline() {
    let acc = Lingering::default();
    let e = Engine::builder().config(quick()).build().unwrap();
    e.start().unwrap();
    let id = e
        .add_listener(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(2)
                .serve(acc.clone()),
        )
        .unwrap();
    let addr = e.listeners()[0].local_addr;
    let mut open: Vec<TcpStream> = (0..4).map(|_| connect(addr)).collect();
    for s in &mut open {
        echo_once(s, b"hi");
    }
    let drain = Duration::from_millis(800);
    let t0 = Instant::now();
    e.shutdown_listener(id, drain).unwrap();
    // `on_shutdown` runs at once for every connection.
    for s in &mut open {
        assert_eq!(read_n(s, 3), b"bye");
    }
    assert!(t0.elapsed() < drain);
    assert_eq!(acc.shutdowns.load(Ordering::SeqCst), 4);
    // Still served during the drain.
    for s in &mut open {
        echo_once(s, b"draining");
    }
    // A client that goes away midway is closed at once (its `on_close` runs).
    let gone = open.pop().unwrap();
    drop(gone);
    wait_for(
        "on_close of the client that left",
        Duration::from_secs(2),
        || acc.closes.load(Ordering::SeqCst) == 1,
    );
    // Closed at the deadline, not before: the close is seen no earlier than `drain` after the
    // call (the deadline is set when the threads get the command, after `t0`).
    assert_eq!(
        acc.closes.load(Ordering::SeqCst),
        1,
        "closed before the drain ended"
    );
    for s in &mut open {
        assert!(
            closed_within(s, Duration::from_secs(5)),
            "not closed after the drain"
        );
        assert!(
            t0.elapsed() >= drain,
            "closed {:?} after the call",
            t0.elapsed()
        );
    }
    wait_for("on_close", Duration::from_secs(5), || {
        acc.closes.load(Ordering::SeqCst) == 4
    });
    wait_for("threads exit", Duration::from_secs(5), || {
        e.listeners();
        loops_of(&e, addr).is_empty()
    });
    stop(&e);
}

#[test]
fn a_zero_drain_closes_at_once() {
    let acc = Lingering::default();
    let e = Engine::builder().config(quick()).build().unwrap();
    e.start().unwrap();
    let id = e
        .add_listener(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve(acc.clone()),
        )
        .unwrap();
    let addr = e.listeners()[0].local_addr;
    let mut s = connect(addr);
    echo_once(&mut s, b"hi");
    e.shutdown_listener(id, Duration::ZERO).unwrap();
    assert!(closed_within(&mut s, Duration::from_secs(2)));
    wait_for("on_close", Duration::from_secs(5), || {
        acc.closes.load(Ordering::SeqCst) == 1
    });
    stop(&e);
}

#[test]
fn a_removed_listeners_port_can_be_bound_again() {
    let e = Engine::builder().config(quick()).build().unwrap();
    e.start().unwrap();
    for drain in [None, Some(Duration::from_millis(50))] {
        let id = e.add_listener(echo_listener(localhost(), 3)).unwrap();
        let addr = e
            .listeners()
            .iter()
            .find(|i| i.id == id)
            .unwrap()
            .local_addr;
        let mut held = connect(addr);
        echo_once(&mut held, b"x");
        match drain {
            None => e.remove_listener(id).unwrap(),
            Some(d) => e.shutdown_listener(id, d).unwrap(),
        }
        // A plain bind (no SO_REUSEPORT) succeeds only once every socket of the old one is
        // closed, while a connection of it is still open.
        wait_for("port free", Duration::from_secs(5), || {
            std::net::TcpListener::bind(addr).is_ok()
        });
        let again = e.add_listener(echo_listener(addr, 2)).unwrap();
        assert!(served(addr));
        if drain.is_none() {
            echo_once(&mut held, b"old one still served");
        }
        e.remove_listener(again).unwrap();
    }
    stop(&e);
}

#[test]
fn max_listeners_under_at_and_over_counting_removed_ones_still_serving() {
    let e = Engine::builder()
        .config(quick())
        .max_listeners(3)
        .listen(echo_listener(localhost(), 1))
        .build()
        .unwrap();
    e.start().unwrap();
    let a = e.add_listener(echo_listener(localhost(), 1)).unwrap(); // 2 of 3
    let _b = e.add_listener(echo_listener(localhost(), 1)).unwrap(); // 3 of 3: at
    let over = e.add_listener(echo_listener(localhost(), 1)).unwrap_err();
    assert_eq!(over.kind(), ErrorKind::QuotaExceeded);
    // A removed listener with an open connection still holds its threads, so its place.
    let addr = e.listeners()[1].local_addr;
    let mut held = connect(addr);
    echo_once(&mut held, b"x");
    e.remove_listener(a).unwrap();
    wait_for("refused", Duration::from_secs(5), || refused(addr));
    assert_eq!(
        e.add_listener(echo_listener(localhost(), 1))
            .unwrap_err()
            .kind(),
        ErrorKind::QuotaExceeded
    );
    // Once its connection is gone, the place is free again.
    drop(held);
    let t = Instant::now();
    let c = loop {
        match e.add_listener(echo_listener(localhost(), 1)) {
            Ok(id) => break id,
            Err(err) => {
                assert_eq!(err.kind(), ErrorKind::QuotaExceeded);
                assert!(t.elapsed() < Duration::from_secs(5), "never freed");
                thread::sleep(Duration::from_millis(10));
            }
        }
    };
    assert!(served(
        e.listeners().iter().find(|i| i.id == c).unwrap().local_addr
    ));
    stop(&e);
}

#[test]
fn what_cannot_be_added_removed_or_filtered() {
    let e = Engine::builder()
        .config(quick())
        .listen(Listener::udp(localhost()).serve(fn_acceptor(|_c: &Conn<Echo>| Echo)))
        .build()
        .unwrap();
    e.start().unwrap();
    let udp = e.listeners()[0].clone();
    assert!(udp.udp);
    assert_eq!(
        e.remove_listener(udp.id).unwrap_err().kind(),
        ErrorKind::Unsupported
    );
    assert_eq!(
        e.shutdown_listener(udp.id, Duration::ZERO)
            .unwrap_err()
            .kind(),
        ErrorKind::Unsupported
    );
    assert_eq!(
        e.set_listener_filter(udp.id, |_| false).unwrap_err().kind(),
        ErrorKind::Unsupported
    );
    let add_udp =
        e.add_listener(Listener::udp(localhost()).serve(fn_acceptor(|_c: &Conn<Echo>| Echo)));
    assert_eq!(add_udp.unwrap_err().kind(), ErrorKind::InvalidInput);
    let no_serve = e.add_listener(Listener::tcp(localhost()));
    assert_eq!(no_serve.unwrap_err().kind(), ErrorKind::InvalidInput);
    // A bind error comes back from the call.
    let taken = std::net::TcpListener::bind(localhost()).unwrap();
    let busy = e.add_listener(echo_listener(taken.local_addr().unwrap(), 1));
    assert!(busy.is_err());
    assert_eq!(e.listeners().len(), 1);
    stop(&e);
    // A filter on a UDP listener is refused by the builder.
    let built = Engine::builder()
        .listen(
            Listener::udp(localhost())
                .filter(|_| true)
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build();
    assert_eq!(built.unwrap_err().kind(), ErrorKind::InvalidInput);
}

#[test]
fn the_filter_refuses_and_accepts_and_is_swapped_at_run_time() {
    let seen: Arc<Mutex<Vec<SocketAddr>>> = Arc::default();
    let log = seen.clone();
    let e = Engine::builder()
        .config(quick())
        .listen(echo_listener(localhost(), 2).filter(move |peer| {
            log.lock().unwrap().push(*peer);
            true
        }))
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let id = e.listeners()[0].id;
    // Called with the peer's address, before the acceptor.
    let mut c = connect(addr);
    echo_once(&mut c, b"allowed");
    assert!(seen.lock().unwrap().contains(&c.local_addr().unwrap()));
    assert_eq!(e.metrics().total.filtered, 0);
    // Swapped under traffic: deny everything.
    // In force for every accept after the call returns.
    e.set_listener_filter(id, |_| false).unwrap();
    for _ in 0..10 {
        assert!(!served(addr));
    }
    // The connection accepted before keeps working.
    echo_once(&mut c, b"still here");
    let refused = e.metrics().total.filtered;
    assert!(refused >= 10, "filtered {refused}");
    // Refused connections are not counted as accepted.
    let accepted = e.metrics().total.accepted;
    // A rule on the address.
    e.set_listener_filter(id, |peer| peer.ip().is_loopback())
        .unwrap();
    assert!(served(addr));
    assert!(e.metrics().total.accepted > accepted);
    // Cleared: every connection is accepted.
    e.set_listener_filter(id, |_| false).unwrap();
    assert!(!served(addr));
    e.clear_listener_filter(id).unwrap();
    for _ in 0..10 {
        assert!(served(addr));
    }
    // Threads added later take the current filter.
    e.set_listener_filter(id, |_| false).unwrap();
    e.set_listener_threads(id, 4).unwrap();
    for _ in 0..8 {
        assert!(!served(addr));
    }
    assert!(e.metrics().total.filtered > refused);
    assert!(
        e.metrics()
            .to_prometheus()
            .contains("akio_connections_filtered_total")
    );
    stop(&e);
}

#[test]
fn a_filter_on_a_listener_added_at_run_time_applies_from_its_first_connection() {
    let e = Engine::builder().config(quick()).build().unwrap();
    e.start().unwrap();
    let denied = Arc::new(AtomicUsize::new(0));
    let d = denied.clone();
    let id = e
        .add_listener(echo_listener(localhost(), 2).filter(move |_| {
            d.fetch_add(1, Ordering::SeqCst);
            false
        }))
        .unwrap();
    let addr = e.listeners()[0].local_addr;
    for _ in 0..5 {
        assert!(!served(addr));
    }
    assert_eq!(denied.load(Ordering::SeqCst), 5);
    assert_eq!(e.metrics().total.filtered, 5);
    assert_eq!(e.metrics().total.accepted, 0);
    e.clear_listener_filter(id).unwrap();
    assert!(served(addr));
    stop(&e);
}

#[test]
fn a_panicking_filter_refuses_the_connection_and_the_loop_survives() {
    // Every other call panics (not by port: Linux gives connects even ports).
    let calls = Arc::new(AtomicUsize::new(0));
    let e = Engine::builder()
        .config(quick())
        .listen(echo_listener(localhost(), 1).filter(move |peer| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            assert!(n % 2 != 0, "filter panic for {peer}");
            true
        }))
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let (mut ok, mut refused) = (0, 0);
    for _ in 0..40 {
        if served(addr) {
            ok += 1;
        } else {
            refused += 1;
        }
    }
    assert!(ok > 0 && refused > 0, "ok {ok} refused {refused}");
    assert_eq!(e.metrics().total.filtered, refused);
    stop(&e);
}
