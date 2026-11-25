//! Listeners sharing an I/O thread group (ADR-130): by default TCP listeners on epoll/kqueue
//! loops share one group, sized by `EngineBuilder::io_threads`; `Listener::threads` and
//! `Listener::dedicated` keep a group of their own; removing, filtering and resizing act on
//! the right listener.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use akio::{Config, Conn, Engine, EngineBuilder, Handler, Listener, fn_acceptor};

/// Shared groups are epoll/kqueue loops: runs that force io_uring or rounds scheduling skip.
fn skip() -> bool {
    common::rounds()
        || std::env::var("AKIO_TEST_BACKEND").as_deref() == Ok("uring")
        || std::env::var("AKIO_DEFAULT_BACKEND").is_ok()
}

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn quick() -> Config {
    let mut v = Config::default();
    v.shutdown_timeout = Duration::from_millis(300);
    v
}

/// Echoes with its listener's tag in front, and counts `on_shutdown` and `on_close`.
struct Tagged {
    tag: u8,
    closed: Arc<AtomicUsize>,
}

impl Handler for Tagged {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let mut out = vec![self.tag];
        out.extend_from_slice(data);
        let _ = c.send(&out);
    }
    fn on_close(&mut self, _c: &Conn<Self>, _e: Option<akio::Error>) {
        self.closed.fetch_add(1, Ordering::SeqCst);
    }
}

/// A listener whose connections echo with `tag`; `closed` counts their closes.
fn tagged(tag: u8, closed: &Arc<AtomicUsize>) -> Listener {
    let closed = closed.clone();
    Listener::tcp(localhost()).serve(fn_acceptor(move |_c: &Conn<Tagged>| Tagged {
        tag,
        closed: closed.clone(),
    }))
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

/// Sends `b"x"` and returns the tag of the answer.
fn tag_of(s: &mut TcpStream) -> u8 {
    s.write_all(b"x").unwrap();
    let mut b = [0u8; 2];
    s.read_exact(&mut b).unwrap();
    assert_eq!(b[1], b'x');
    b[0]
}

/// I/O threads running and not retiring.
fn running_loops(e: &Engine) -> usize {
    e.metrics()
        .loops
        .iter()
        .filter(|l| l.running && !l.retiring)
        .count()
}

fn wait_for(what: &str, c: impl Fn() -> bool) {
    let t = Instant::now();
    while !c() {
        assert!(t.elapsed() < Duration::from_secs(5), "timed out: {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

#[test]
fn listeners_share_one_group_by_default() {
    if skip() {
        return;
    }
    let closed = Arc::new(AtomicUsize::new(0));
    let e = Engine::builder()
        .config(quick())
        .io_threads(2)
        .listen(tagged(b'a', &closed))
        .listen(tagged(b'b', &closed))
        .listen(tagged(b'c', &closed))
        .build()
        .unwrap();
    e.start().unwrap();
    // Three listeners, one group of two threads.
    assert_eq!(e.threads(), vec![2, 2, 2]);
    assert_eq!(running_loops(&e), 2);
    let addrs = e.local_addrs();
    let mut conns: Vec<TcpStream> = addrs.iter().map(|a| connect(*a)).collect();
    for (s, want) in conns.iter_mut().zip(*b"abc") {
        assert_eq!(tag_of(s), want, "each listener keeps its own acceptor");
    }
    // The shared threads name no listener; each connection names its own.
    let m = e.metrics();
    assert!(m.loops.iter().all(|l| l.owner.listener.is_none()));
    let infos = e.connections(Duration::from_secs(2));
    assert_eq!(infos.len(), 3);
    for ci in &infos {
        assert_eq!(ci.owner.listener, Some(ci.local), "{ci:?}");
        assert!(addrs.contains(&ci.local));
    }
    drop(conns);
    stop(&e);
}

#[test]
fn threads_and_dedicated_keep_a_group_of_their_own() {
    if skip() {
        return;
    }
    let cores = thread::available_parallelism().map_or(1, |n| n.get());
    let closed = Arc::new(AtomicUsize::new(0));
    let e = EngineBuilder::default()
        .config(quick())
        .io_threads(2)
        .listen(tagged(b'a', &closed))
        .listen(tagged(b'b', &closed).threads(3))
        .listen(tagged(b'c', &closed).dedicated())
        .listen(tagged(b'd', &closed))
        .build()
        .unwrap();
    e.start().unwrap();
    assert_eq!(e.threads(), vec![2, 3, cores, 2]);
    assert_eq!(running_loops(&e), 2 + 3 + cores);
    for (a, want) in e.local_addrs().into_iter().zip(*b"abcd") {
        assert_eq!(tag_of(&mut connect(a)), want);
    }
    stop(&e);
}

#[test]
fn removing_a_shared_listener_leaves_the_others_and_the_threads() {
    if skip() {
        return;
    }
    let (ca, cb) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let e = Engine::builder()
        .config(quick())
        .io_threads(2)
        .listen(tagged(b'a', &ca))
        .listen(tagged(b'b', &cb))
        .build()
        .unwrap();
    e.start().unwrap();
    let ids: Vec<_> = e.listeners().iter().map(|l| l.id).collect();
    let (aa, ab) = (e.local_addrs()[0], e.local_addrs()[1]);
    let mut a = connect(aa);
    let mut b = connect(ab);
    assert_eq!(tag_of(&mut a), b'a');
    assert_eq!(tag_of(&mut b), b'b');
    // Drained: `a`'s connection is closed after the drain, `b`'s is not touched.
    e.shutdown_listener(ids[0], Duration::from_millis(100))
        .unwrap();
    wait_for("a's connection closed", || ca.load(Ordering::SeqCst) == 1);
    assert_eq!(cb.load(Ordering::SeqCst), 0);
    assert_eq!(
        tag_of(&mut b),
        b'b',
        "the other listener's connection still works"
    );
    assert!(
        TcpStream::connect(aa).is_err(),
        "the removed listener's socket is closed"
    );
    assert_eq!(
        tag_of(&mut connect(ab)),
        b'b',
        "the other listener still accepts"
    );
    // The threads stay for `b`; the removed listener reports none.
    assert_eq!(running_loops(&e), 2);
    assert_eq!(e.threads(), vec![0, 2]);
    assert_eq!(e.listeners().len(), 1);
    drop((a, b));
    stop(&e);
}

#[test]
fn a_filter_applies_to_its_listener_only() {
    if skip() {
        return;
    }
    let closed = Arc::new(AtomicUsize::new(0));
    let e = Engine::builder()
        .config(quick())
        .io_threads(1)
        .listen(tagged(b'a', &closed).filter(|_| false))
        .listen(tagged(b'b', &closed))
        .build()
        .unwrap();
    e.start().unwrap();
    let (aa, ab) = (e.local_addrs()[0], e.local_addrs()[1]);
    let mut a = connect(aa);
    let _ = a.write_all(b"x");
    let mut buf = [0u8; 2];
    assert!(
        matches!(a.read(&mut buf), Ok(0) | Err(_)),
        "a's filter refuses it"
    );
    assert_eq!(tag_of(&mut connect(ab)), b'b');
    // Swapped at run time on `b` only.
    let ids: Vec<_> = e.listeners().iter().map(|l| l.id).collect();
    e.clear_listener_filter(ids[0]).unwrap();
    e.set_listener_filter(ids[1], |_| false).unwrap();
    assert_eq!(tag_of(&mut connect(aa)), b'a');
    let mut b = connect(ab);
    let _ = b.write_all(b"x");
    assert!(matches!(b.read(&mut buf), Ok(0) | Err(_)));
    stop(&e);
}

#[test]
fn resizing_a_shared_listener_resizes_the_group() {
    if skip() {
        return;
    }
    let closed = Arc::new(AtomicUsize::new(0));
    let e = Engine::builder()
        .config(quick())
        .io_threads(1)
        .listen(tagged(b'a', &closed))
        .listen(tagged(b'b', &closed))
        .build()
        .unwrap();
    e.start().unwrap();
    let ids: Vec<_> = e.listeners().iter().map(|l| l.id).collect();
    e.set_listener_threads(ids[0], 3).unwrap();
    assert_eq!(e.threads(), vec![3, 3]);
    wait_for("three threads", || running_loops(&e) == 3);
    // Both listeners are served on every thread: many connections all answered.
    for _ in 0..12 {
        for (a, want) in e.local_addrs().into_iter().zip(*b"ab") {
            assert_eq!(tag_of(&mut connect(a)), want);
        }
    }
    e.set_threads(1, 1).unwrap();
    assert_eq!(e.threads(), vec![1, 1]);
    for (a, want) in e.local_addrs().into_iter().zip(*b"ab") {
        assert_eq!(tag_of(&mut connect(a)), want);
    }
    stop(&e);
}

#[test]
fn a_listener_added_at_run_time_joins_the_shared_group() {
    if skip() {
        return;
    }
    let closed = Arc::new(AtomicUsize::new(0));
    let e = Engine::builder()
        .config(quick())
        .io_threads(2)
        .listen(tagged(b'a', &closed))
        .build()
        .unwrap();
    e.start().unwrap();
    let id = e.add_listener(tagged(b'n', &closed)).unwrap();
    let info = e.listeners().into_iter().find(|l| l.id == id).unwrap();
    assert_eq!(info.threads, 2);
    assert_eq!(running_loops(&e), 2, "no new threads");
    assert_eq!(tag_of(&mut connect(info.local_addr)), b'n');
    assert_eq!(tag_of(&mut connect(e.local_addrs()[0])), b'a');
    // And a dedicated one gets threads of its own.
    let d = e.add_listener(tagged(b'd', &closed).threads(1)).unwrap();
    let info = e.listeners().into_iter().find(|l| l.id == d).unwrap();
    assert_eq!(info.threads, 1);
    assert_eq!(running_loops(&e), 3);
    assert_eq!(tag_of(&mut connect(info.local_addr)), b'd');
    e.remove_listener(id).unwrap();
    assert_eq!(tag_of(&mut connect(e.local_addrs()[0])), b'a');
    stop(&e);
}

// ---- rounds scheduling (ADR-104): listeners with one `RoundsConfig` share its workers ----------

/// Rounds listeners need epoll/kqueue: runs that force io_uring skip.
fn skip_rounds() -> bool {
    std::env::var("AKIO_TEST_BACKEND").as_deref() == Ok("uring")
        || std::env::var("AKIO_DEFAULT_BACKEND").is_ok()
}

/// One poller and `workers` workers.
fn rounds(workers: usize) -> akio::Scheduling {
    akio::Scheduling::Rounds(akio::RoundsConfig::new(1, workers))
}

/// Threads of the engine: workers and pollers of rounds groups, loops of the others.
fn all_threads(e: &Engine) -> usize {
    e.metrics().loops.len()
}

#[test]
fn rounds_listeners_share_their_workers() {
    if skip_rounds() {
        return;
    }
    let closed = Arc::new(AtomicUsize::new(0));
    let e = Engine::builder()
        .config(quick())
        .listen(tagged(b'a', &closed).scheduling(rounds(2)))
        .listen(tagged(b'b', &closed).scheduling(rounds(2)))
        .listen(tagged(b'c', &closed).scheduling(rounds(3)))
        .build()
        .unwrap();
    e.start().unwrap();
    // `a` and `b` share 2 workers and a poller; `c` has 3 workers and a poller of its own.
    assert_eq!(e.threads(), vec![2, 2, 3]);
    assert_eq!(all_threads(&e), (2 + 1) + (3 + 1));
    for _ in 0..8 {
        for (a, want) in e.local_addrs().into_iter().zip(*b"abc") {
            assert_eq!(tag_of(&mut connect(a)), want);
        }
    }
    // Each connection names its listener, though the threads name none.
    let mut conns: Vec<TcpStream> = e.local_addrs().into_iter().map(connect).collect();
    for (s, want) in conns.iter_mut().zip(*b"abc") {
        assert_eq!(tag_of(s), want);
    }
    let infos = e.connections(Duration::from_secs(2));
    assert_eq!(infos.len(), 3);
    for ci in &infos {
        assert_eq!(ci.owner.listener, Some(ci.local), "{ci:?}");
    }
    drop(conns);
    stop(&e);
}

#[test]
fn removing_a_shared_rounds_listener_leaves_the_others() {
    if skip_rounds() {
        return;
    }
    let (ca, cb) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let e = Engine::builder()
        .config(quick())
        .listen(tagged(b'a', &ca).scheduling(rounds(2)))
        .listen(tagged(b'b', &cb).scheduling(rounds(2)))
        .build()
        .unwrap();
    e.start().unwrap();
    let ids: Vec<_> = e.listeners().iter().map(|l| l.id).collect();
    let (aa, ab) = (e.local_addrs()[0], e.local_addrs()[1]);
    let mut a = connect(aa);
    let mut b = connect(ab);
    assert_eq!(tag_of(&mut a), b'a');
    assert_eq!(tag_of(&mut b), b'b');
    e.shutdown_listener(ids[0], Duration::from_millis(100))
        .unwrap();
    wait_for("a's connection closed", || ca.load(Ordering::SeqCst) == 1);
    assert_eq!(cb.load(Ordering::SeqCst), 0);
    assert_eq!(tag_of(&mut b), b'b');
    assert!(TcpStream::connect(aa).is_err());
    assert_eq!(tag_of(&mut connect(ab)), b'b');
    assert_eq!(all_threads(&e), 3, "the workers stay for b");
    drop((a, b));
    stop(&e);
}

#[test]
fn rounds_filters_and_run_time_listeners_are_per_listener() {
    if skip_rounds() {
        return;
    }
    let closed = Arc::new(AtomicUsize::new(0));
    let e = Engine::builder()
        .config(quick())
        .listen(
            tagged(b'a', &closed)
                .scheduling(rounds(2))
                .filter(|_| false),
        )
        .listen(tagged(b'b', &closed).scheduling(rounds(2)))
        .build()
        .unwrap();
    e.start().unwrap();
    let (aa, ab) = (e.local_addrs()[0], e.local_addrs()[1]);
    let mut a = connect(aa);
    let _ = a.write_all(b"x");
    let mut buf = [0u8; 2];
    assert!(matches!(a.read(&mut buf), Ok(0) | Err(_)));
    assert_eq!(tag_of(&mut connect(ab)), b'b');
    // Added at run time: it joins the same workers.
    let id = e
        .add_listener(tagged(b'n', &closed).scheduling(rounds(2)))
        .unwrap();
    let info = e.listeners().into_iter().find(|l| l.id == id).unwrap();
    assert_eq!(info.threads, 2);
    assert_eq!(all_threads(&e), 3, "no new threads");
    for _ in 0..8 {
        assert_eq!(tag_of(&mut connect(info.local_addr)), b'n');
    }
    e.remove_listener(id).unwrap();
    assert_eq!(tag_of(&mut connect(ab)), b'b');
    stop(&e);
}
