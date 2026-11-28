//! A follow-up of akit's A301: an arpc connection ends at its engine's graceful shutdown once
//! the calls in flight are over, client side and server side, instead of holding
//! `Engine::wait` until `shutdown_timeout`.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

use akio::{Config, Engine, Listener};
use akio_arpc::{CallError, Responder, Routes, SERVER_BUSY, Server, dial_blocking};

/// Well beyond what any of these shutdowns may take.
const LONG: Duration = Duration::from_secs(20);
const T: Duration = Duration::from_secs(10);

fn engine(server: Option<Server>, shutdown_timeout: Duration) -> Arc<Engine> {
    let mut b = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = shutdown_timeout;
            v
        })
        .client_threads(1);
    if let Some(s) = server {
        b = b.listen(Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(s));
    }
    let e = Arc::new(b.build().unwrap());
    e.start().unwrap();
    e
}

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < T, "timed out: {what}");
        thread::sleep(Duration::from_millis(2));
    }
}

/// `/echo`, and `/held`, whose answer the test gives through the responder it is handed.
fn routes(held: mpsc::Sender<Responder>) -> Routes {
    let held = Mutex::new(held);
    Routes::new()
        .handle("/echo", |ctx| {
            let b = ctx.body().to_vec();
            ctx.write(&b);
        })
        .handle("/held", move |ctx| {
            let _ = held.lock().unwrap().send(ctx.detach());
        })
}

fn stop(e: &Engine) -> Duration {
    let t0 = Instant::now();
    e.shutdown();
    e.wait();
    t0.elapsed()
}

#[test]
fn an_idle_client_ends_at_its_engine_shutdown() {
    let (htx, _hrx) = mpsc::channel();
    let server = Server::new(Arc::new(routes(htx)));
    let se = engine(Some(server.clone()), Duration::from_millis(300));
    let addr = se.local_addrs()[0];
    let ce = engine(None, LONG);
    let peer = dial_blocking(&ce, addr, Arc::new(Routes::new())).unwrap();
    assert_eq!(peer.call("/echo", b"hi", Some(T)).wait().unwrap(), b"hi");
    let took = stop(&ce);
    assert!(took < T, "the client's engine took {took:?}");
    assert!(!peer.is_connected());
    // The server saw the connection go (and no reconnection came).
    wait_until("the server's peer gone", || server.peers().is_empty());
    assert_eq!(
        peer.call("/echo", b"hi", Some(T)).wait(),
        Err(CallError::Closed)
    );
    stop(&se);
}

#[test]
fn a_busy_client_ends_once_its_calls_are_answered() {
    let (htx, hrx) = mpsc::channel();
    let server = Server::new(Arc::new(routes(htx)));
    let se = engine(Some(server.clone()), Duration::from_millis(300));
    let addr = se.local_addrs()[0];
    let ce = engine(None, LONG);
    let peer = dial_blocking(&ce, addr, Arc::new(Routes::new())).unwrap();
    let (atx, arx) = mpsc::channel();
    peer.call_async("/held", b"", Some(LONG), move |r| {
        let _ = atx.send(r);
    });
    let responder = hrx.recv_timeout(T).unwrap();
    ce.shutdown();
    // The connection takes no more calls, but stays for the one in flight.
    wait_until("the client draining", || !peer.is_connected());
    assert_eq!(
        peer.call("/echo", b"late", Some(T)).wait(),
        Err(CallError::Closed)
    );
    assert!(!peer.notify("/echo", b"late"));
    assert_eq!(server.peers().len(), 1);
    responder.write(b"answered");
    assert_eq!(arx.recv_timeout(T).unwrap().unwrap(), b"answered");
    let t0 = Instant::now();
    ce.wait();
    assert!(
        t0.elapsed() < T,
        "the client's engine took {:?}",
        t0.elapsed()
    );
    wait_until("the server's peer gone", || server.peers().is_empty());
    stop(&se);
}

#[test]
fn a_server_connection_ends_once_its_calls_are_answered() {
    let (htx, hrx) = mpsc::channel();
    let server = Server::new(Arc::new(routes(htx)));
    let se = engine(Some(server.clone()), LONG);
    let addr = se.local_addrs()[0];
    let ce = engine(None, Duration::from_millis(300));
    let (dtx, drx) = mpsc::channel();
    let dtx = Mutex::new(dtx);
    let client = Routes::new().on_disconnected(move |_p| {
        let _ = dtx.lock().unwrap().send(());
    });
    let peer = dial_blocking(&ce, addr, Arc::new(client)).unwrap();
    // A second, idle client: it must not hold the shutdown either.
    let idle = dial_blocking(&ce, addr, Arc::new(Routes::new())).unwrap();
    assert_eq!(idle.call("/echo", b"hi", Some(T)).wait().unwrap(), b"hi");
    let (atx, arx) = mpsc::channel();
    peer.call_async("/held", b"", Some(LONG), move |r| {
        let _ = atx.send(r);
    });
    let responder = hrx.recv_timeout(T).unwrap();
    let t0 = Instant::now();
    se.shutdown();
    wait_until("the server draining", || {
        server.peers().iter().all(|p| !p.is_connected())
    });
    // The idle connection is closed at once; the busy one refuses new calls.
    wait_until("the idle client cut off", || !idle.is_connected());
    assert_eq!(
        peer.call("/echo", b"late", Some(T)).wait(),
        Err(CallError::Remote(SERVER_BUSY.into()))
    );
    assert!(drx.try_recv().is_err());
    responder.write(b"answered");
    assert_eq!(arx.recv_timeout(T).unwrap().unwrap(), b"answered");
    drx.recv_timeout(T).unwrap();
    se.wait();
    assert!(
        t0.elapsed() < T,
        "the server's engine took {:?}",
        t0.elapsed()
    );
    idle.close();
    peer.close();
    stop(&ce);
}
