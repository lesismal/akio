//! A listener's table of its connections (ADR-180, akit A232): `Listener::on_accept` and
//! `on_close`, and `ConnHandle`'s close, deadline and idle timeout, from the connection's I/O
//! thread and from others (on the backend under test: epoll/kqueue, io_uring with
//! `AKIO_TEST_BACKEND=uring`, work stealing with `AKIO_DEFAULT_SCHEDULING=work-stealing`).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use akio::{Config, Conn, ConnHandle, Engine, Error, Handler, Listener, fn_acceptor};

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

fn wait_for(what: &str, c: impl Fn() -> bool) {
    let t = Instant::now();
    while !c() {
        assert!(t.elapsed() < Duration::from_secs(10), "timed out: {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

/// The application's table: the connections open, and the ids of those closed.
#[derive(Default)]
struct Table {
    open: Mutex<HashMap<u64, ConnHandle>>,
    accepted: Mutex<Vec<u64>>,
    closed: Mutex<Vec<u64>>,
}

impl Table {
    fn len(&self) -> usize {
        self.open.lock().unwrap().len()
    }
    /// The open connection whose peer is the client socket `s`.
    fn of(&self, s: &TcpStream) -> ConnHandle {
        let peer = s.local_addr().unwrap();
        let open = self.open.lock().unwrap();
        open.values()
            .find(|h| h.peer_addr() == peer)
            .unwrap()
            .clone()
    }
    fn was_closed(&self, id: u64) -> bool {
        self.closed.lock().unwrap().contains(&id)
    }
}

/// Echoes; a `c` byte cancels the connection's close deadline, an `i` sets its idle timeout to
/// 200 ms, both through a handle.
struct Echo;

impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let h = c.handle();
        if data.contains(&b'c') {
            h.cancel_close();
        }
        if data.contains(&b'i') {
            h.set_idle_timeout(Some(Duration::from_millis(200)))
                .unwrap();
        }
        let _ = c.send(data);
    }
}

/// An engine whose listener keeps `table` and runs `accept` on each new connection.
fn engine(table: &Arc<Table>, accept: impl Fn(&ConnHandle) + Send + Sync + 'static) -> Engine {
    let mut cfg = Config::default();
    cfg.shutdown_timeout = Duration::from_millis(300);
    cfg.idle_timeout = Some(Duration::from_secs(30));
    let (ta, tc) = (table.clone(), table.clone());
    let e = Engine::builder()
        .config(cfg)
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(common::backend())
                .threads(2)
                .on_accept(move |h| {
                    assert!(h.is_open());
                    ta.open.lock().unwrap().insert(h.id(), h.clone());
                    ta.accepted.lock().unwrap().push(h.id());
                    accept(h);
                })
                .on_close(move |h| {
                    assert!(!h.is_open());
                    tc.open.lock().unwrap().remove(&h.id());
                    tc.closed.lock().unwrap().push(h.id());
                })
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn echo(s: &mut TcpStream, b: &[u8]) {
    s.write_all(b).unwrap();
    let mut got = vec![0u8; b.len()];
    s.read_exact(&mut got).unwrap();
    assert_eq!(got, b);
}

/// Whether the server closed `s`: an end of stream or a reset, not the read timeout.
fn eof(s: &mut TcpStream) -> bool {
    let mut b = [0u8; 16];
    match common::read_retry(s, &mut b) {
        Ok(n) => n == 0,
        Err(e) => !matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
    }
}

#[test]
fn table_of_connections_and_close_from_another_thread() {
    let table = Arc::new(Table::default());
    let e = engine(&table, |_| {});
    let addr = e.local_addrs()[0];
    let mut conns: Vec<TcpStream> = (0..3).map(|_| connect(addr)).collect();
    wait_for("three accepted", || table.len() == 3);
    for s in &mut conns {
        echo(s, b"x");
    }
    // The application closes the first one connected, from this thread. It finds it by its
    // peer's address, not as the first accepted: on Linux each I/O thread accepts from its own
    // `SO_REUSEPORT` socket, so the order of `on_accept`s is not the order of the connects.
    let first = table.of(&conns[0]);
    let local = first.local_addr();
    assert_eq!(local, addr);
    first.close();
    assert!(eof(&mut conns[0]), "closed by the handle");
    wait_for("on_close of the first", || table.was_closed(first.id()));
    assert_eq!(table.len(), 2);
    assert!(!first.is_open());
    // Closed: a deadline or an idle timeout is refused, closing again does nothing.
    assert!(matches!(
        first.close_after(Duration::ZERO),
        Err(Error::Closed)
    ));
    assert!(matches!(first.set_idle_timeout(None), Err(Error::Closed)));
    first.close();
    // The others still echo; the peer closing them empties the table.
    echo(&mut conns[1], b"y");
    conns.clear();
    wait_for("table empty", || table.len() == 0);
    assert_eq!(table.closed.lock().unwrap().len(), 3);
    stop(&e);
}

#[test]
fn deadline_closes_whatever_the_peer_sends() {
    let table = Arc::new(Table::default());
    // Every connection is closed 300 ms after it was accepted (set on its I/O thread).
    let e = engine(&table, |h| {
        h.close_after(Duration::from_millis(300)).unwrap();
    });
    let addr = e.local_addrs()[0];
    let t0 = Instant::now();
    let mut s = connect(addr);
    // Traffic every 50 ms does not keep it open.
    let mut closed_at = None;
    while t0.elapsed() < Duration::from_secs(5) {
        if s.write_all(b"x").is_err() {
            closed_at = Some(t0.elapsed());
            break;
        }
        let mut b = [0u8; 1];
        match common::read_retry(&mut s, &mut b) {
            Ok(1) => {}
            _ => {
                closed_at = Some(t0.elapsed());
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    let at = closed_at.expect("closed by the deadline");
    assert!(at >= Duration::from_millis(250), "{at:?}");
    assert!(at < Duration::from_secs(3), "{at:?}");
    wait_for("on_close", || table.len() == 0);
    stop(&e);
}

#[test]
fn cancelled_deadline_keeps_the_connection() {
    let table = Arc::new(Table::default());
    let e = engine(&table, |h| {
        h.close_after(Duration::from_millis(200)).unwrap();
    });
    let addr = e.local_addrs()[0];
    let mut kept = connect(addr);
    let mut timed = connect(addr);
    // `c` cancels the deadline from the handler (the request "with a valid session").
    echo(&mut kept, b"c");
    thread::sleep(Duration::from_millis(500));
    assert!(eof(&mut timed), "the other one was closed at its deadline");
    echo(&mut kept, b"x");
    assert_eq!(table.len(), 1);
    // A new deadline from another thread replaces the cancelled one; one already past closes
    // at the loop's next turn.
    let h = table.open.lock().unwrap().values().next().unwrap().clone();
    h.close_after(Duration::from_secs(60)).unwrap();
    h.close_at(
        Instant::now()
            .checked_sub(Duration::from_millis(1))
            .unwrap(),
    )
    .unwrap();
    assert!(eof(&mut kept));
    wait_for("both closed", || table.len() == 0);
    stop(&e);
}

#[test]
fn a_later_deadline_replaces_an_earlier_one() {
    let table = Arc::new(Table::default());
    let e = engine(&table, |h| {
        h.close_after(Duration::from_millis(100)).unwrap();
        // The last one set is in force: 700 ms, not 100.
        h.close_after(Duration::from_millis(700)).unwrap();
    });
    let t0 = Instant::now();
    let mut s = connect(e.local_addrs()[0]);
    thread::sleep(Duration::from_millis(350));
    // (No `c` or `i` in it: those cancel the deadline or set an idle timeout.)
    echo(&mut s, b"x");
    assert!(eof(&mut s));
    assert!(
        t0.elapsed() >= Duration::from_millis(600),
        "{:?}",
        t0.elapsed()
    );
    stop(&e);
}

#[test]
fn idle_timeout_through_a_handle() {
    let table = Arc::new(Table::default());
    let e = engine(&table, |_| {});
    let mut s = connect(e.local_addrs()[0]);
    // `i` sets a 200 ms idle timeout from the handler; the engine's is 30 s.
    let t0 = Instant::now();
    echo(&mut s, b"i");
    assert!(eof(&mut s), "closed when idle");
    assert!(
        t0.elapsed() >= Duration::from_millis(150),
        "{:?}",
        t0.elapsed()
    );
    assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
    wait_for("on_close", || table.len() == 0);
    stop(&e);
}

#[test]
fn eviction_when_the_table_is_full() {
    // fit's rule in small: at most two connections; a new one closes the oldest.
    let table = Arc::new(Table::default());
    let t = table.clone();
    let e = engine(&table, move |_new| {
        let open = t.open.lock().unwrap();
        if open.len() > 2 {
            let accepted = t.accepted.lock().unwrap();
            let oldest = accepted.iter().find(|id| open.contains_key(id)).unwrap();
            open[oldest].close();
        }
    });
    let addr = e.local_addrs()[0];
    let mut a = connect(addr);
    echo(&mut a, b"a");
    let mut b = connect(addr);
    echo(&mut b, b"b");
    let mut c = connect(addr);
    echo(&mut c, b"c");
    assert!(eof(&mut a), "the oldest was evicted");
    echo(&mut b, b"b");
    wait_for("two left", || table.len() == 2);
    stop(&e);
}

#[test]
fn a_panicking_accept_hook_refuses_the_connection() {
    let table = Arc::new(Table::default());
    let e = engine(&table, |_| panic!("refused"));
    let mut s = connect(e.local_addrs()[0]);
    assert!(eof(&mut s));
    // The table, which took the connection in before the panic, is told it closed.
    wait_for("on_close of the refused one", || table.len() == 0);
    assert_eq!(table.closed.lock().unwrap().len(), 1);
    stop(&e);
}
