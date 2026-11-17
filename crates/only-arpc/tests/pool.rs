//! Client pools: spreading calls, least-pending choice, reconnecting, heartbeats, failed dials.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    collections::HashMap,
    net::{SocketAddr, TcpListener},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use only::{Config, Engine, Listener};
use only_arpc::{Balance, CallError, Pool, Routes, Server};

fn engine(server: Option<Server>) -> Arc<Engine> {
    let mut b = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(300);
            v
        })
        .client_threads(2);
    if let Some(s) = server {
        b = b.listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .threads(2)
                .serve(s),
        );
    }
    let e = Arc::new(b.build().unwrap());
    e.start().unwrap();
    e
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < Duration::from_secs(10), "timed out: {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

const T: Option<Duration> = Some(Duration::from_secs(5));

/// The index of the connection the pool picks next.
fn picked(pool: &Pool) -> usize {
    let p = pool.peer();
    pool.peers()
        .iter()
        .position(|q| std::ptr::eq(p, q))
        .unwrap()
}

/// A server whose `/who` answers with the caller's address and `/hold` never answers.
fn server(by_conn: Arc<Mutex<HashMap<SocketAddr, usize>>>) -> Server {
    Server::new(Arc::new(
        Routes::new()
            .handle("/who", move |ctx| {
                let a = ctx.peer().peer_addr().unwrap();
                *by_conn.lock().unwrap().entry(a).or_default() += 1;
                ctx.write(a.to_string().as_bytes());
            })
            .handle("/hold", |ctx| drop(ctx.detach())),
    ))
}

#[test]
fn round_robin_spreads_calls_over_every_connection() {
    let counts = Arc::new(Mutex::new(HashMap::new()));
    let e = engine(Some(server(counts.clone())));
    let pool = Pool::builder()
        .size(4)
        .dial(&e, e.local_addrs()[0], Arc::new(Routes::new()))
        .unwrap();
    assert_eq!(pool.peers().len(), 4);
    assert_eq!(pool.connected(), 4);
    for _ in 0..400 {
        pool.call("/who", b"", T).wait().unwrap();
    }
    let c = counts.lock().unwrap().clone();
    assert_eq!(c.len(), 4, "{c:?}");
    assert!(c.values().all(|&n| n == 100), "{c:?}");
    pool.close();
    stop(&e);
}

#[test]
fn least_pending_avoids_busy_connections() {
    let counts = Arc::new(Mutex::new(HashMap::new()));
    let e = engine(Some(server(counts.clone())));
    let pool = Pool::builder()
        .size(3)
        .balance(Balance::LeastPending)
        .dial(&e, e.local_addrs()[0], Arc::new(Routes::new()))
        .unwrap();
    // Load two connections with calls that are never answered.
    let busy = [&pool.peers()[0], &pool.peers()[1]];
    let held: Vec<_> = busy
        .iter()
        .flat_map(|p| (0..5).map(|_| p.call("/hold", b"", Some(Duration::from_secs(60)))))
        .collect();
    let idle = pool.peers()[2].clone();
    for _ in 0..50 {
        assert_eq!(picked(&pool), 2);
        pool.call("/who", b"", T).wait().unwrap();
    }
    assert_eq!(counts.lock().unwrap().len(), 1);
    assert_eq!(idle.pending_calls(), 0);
    // When it is down too, the least loaded of the others is picked.
    idle.close();
    wait_until("down", || pool.connected() == 2);
    let extra = pool.peers()[0].call("/hold", b"", Some(Duration::from_secs(60)));
    assert_eq!(picked(&pool), 1);
    pool.close();
    for f in held.into_iter().chain([extra]) {
        assert_eq!(f.wait(), Err(CallError::Closed));
    }
    stop(&e);
}

#[test]
fn lost_connections_are_skipped_then_reconnect() {
    let counts = Arc::new(Mutex::new(HashMap::new()));
    let s = server(counts.clone());
    let e = engine(Some(s.clone()));
    let pool = Pool::builder()
        .size(3)
        .reconnect_interval(Duration::from_millis(300))
        .heartbeat(None)
        .dial(&e, e.local_addrs()[0], Arc::new(Routes::new()))
        .unwrap();
    wait_until("registered", || s.peers().len() == 3);
    // The server drops one client: calls keep working on the other two meanwhile.
    s.peers()[0].close();
    wait_until("one down", || pool.connected() == 2);
    for _ in 0..20 {
        pool.call("/who", b"", T).wait().unwrap();
    }
    wait_until("reconnected", || pool.connected() == 3);
    counts.lock().unwrap().clear();
    for _ in 0..30 {
        pool.call("/who", b"", T).wait().unwrap();
    }
    assert_eq!(counts.lock().unwrap().len(), 3);
    // Every connection down: calls fail at once instead of waiting.
    pool.close();
    wait_until("all down", || pool.connected() == 0);
    let t = Instant::now();
    assert_eq!(pool.call("/who", b"", T).wait(), Err(CallError::Closed));
    assert!(!pool.notify("/who", b""));
    assert!(t.elapsed() < Duration::from_secs(1));
    stop(&e);
}

#[test]
fn heartbeat_replaces_a_silent_connection() {
    // A "server" that accepts and never says anything (nor answers pings).
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let a2 = accepted.clone();
    thread::spawn(move || {
        for c in l.incoming() {
            a2.fetch_add(1, Ordering::SeqCst);
            // Held open, never read or written.
            std::mem::forget(c);
        }
    });
    let e = engine(None);
    let pool = Pool::builder()
        .size(1)
        .heartbeat(Some(Duration::from_millis(100)))
        .reconnect_interval(Duration::from_millis(50))
        .dial(&e, addr, Arc::new(Routes::new()))
        .unwrap();
    // Silent for two intervals: closed and dialed again, repeatedly.
    wait_until("redialed", || accepted.load(Ordering::SeqCst) >= 3);
    pool.close();
    stop(&e);
}

#[test]
fn heartbeat_keeps_a_live_idle_connection() {
    let e = engine(Some(server(Arc::default())));
    let s_addr = e.local_addrs()[0];
    let pool = Pool::builder()
        .size(2)
        .heartbeat(Some(Duration::from_millis(50)))
        .dial(&e, s_addr, Arc::new(Routes::new()))
        .unwrap();
    let before: Vec<_> = pool
        .peers()
        .iter()
        .map(|p| p.local_addr_for_test())
        .collect();
    thread::sleep(Duration::from_millis(600));
    let after: Vec<_> = pool
        .peers()
        .iter()
        .map(|p| p.local_addr_for_test())
        .collect();
    assert_eq!(before, after, "pongs keep the connections");
    assert_eq!(pool.connected(), 2);
    pool.close();
    stop(&e);
}

trait LocalAddr {
    fn local_addr_for_test(&self) -> Option<SocketAddr>;
}

impl LocalAddr for only_arpc::Peer {
    /// The connection's local address as the server sees it (a reconnection gets a new one).
    fn local_addr_for_test(&self) -> Option<SocketAddr> {
        let r = self.call("/who", b"", T).wait().ok()?;
        String::from_utf8(r).ok()?.parse().ok()
    }
}

#[test]
fn a_failed_dial_fails_the_pool() {
    // Nothing listens there.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    let e = engine(None);
    let r = Pool::builder()
        .size(3)
        .connect_timeout(Duration::from_secs(5))
        .dial(&e, addr, Arc::new(Routes::new()));
    assert!(r.is_err());
    stop(&e);
}
