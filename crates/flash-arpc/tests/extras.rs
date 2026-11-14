//! arpc corners: request metadata, detached errors, awaiting a call, body limits, disconnect
//! hooks, calls on a closed peer and failed dials.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    future::Future,
    pin::pin,
    sync::{Arc, Mutex, mpsc},
    task::{Context as TaskContext, Poll, Wake, Waker},
    thread,
    time::Duration,
};

use flash::{Config, Engine, Listener};
use flash_arpc::{CallError, Routes, Server, StreamEvent, dial};

fn engine(server: Option<Server>) -> Arc<Engine> {
    let mut b = Engine::builder()
        .config(Config {
            shutdown_timeout: Duration::from_millis(300),
            ..Config::default()
        })
        .client_threads(1);
    if let Some(s) = server {
        b = b.listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .threads(1)
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

/// Minimal executor: polls `f` on this thread, parking until woken.
fn block_on<F: Future>(f: F) -> F::Output {
    struct Unpark(thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut cx = TaskContext::from_waker(&waker);
    let mut f = pin!(f);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        thread::park_timeout(Duration::from_millis(100));
    }
}

#[test]
fn metadata_detached_errors_and_awaiting() {
    let (tx, rx) = mpsc::channel();
    let tx = Arc::new(Mutex::new(tx));
    let t2 = tx.clone();
    let routes = Routes::new()
        .handle("/meta", |ctx| {
            let s = format!(
                "{} notify={} peer={}",
                ctx.method(),
                ctx.is_notify(),
                ctx.peer().is_connected()
            );
            ctx.write(s.as_bytes());
        })
        .handle("/note", move |ctx| {
            let _ = t2
                .lock()
                .unwrap()
                .send(format!("{} notify={}", ctx.method(), ctx.is_notify()));
        })
        .handle("/late-fail", |ctx| {
            let r = ctx.detach();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(80));
                r.error("late failure");
            });
        })
        .handle_stream("/info", |s| {
            let head = format!("{}#{}", s.method(), s.id());
            let mut sent = false;
            move |s: &flash_arpc::Stream, ev: StreamEvent<'_>| match ev {
                StreamEvent::Message(_) if !sent => {
                    sent = true;
                    s.send(head.as_bytes());
                    s.send(if s.peer().is_connected() {
                        b"up"
                    } else {
                        b"down"
                    });
                }
                StreamEvent::Message(_) => {}
                StreamEvent::Eof => {
                    s.close_send();
                }
            }
        })
        .on_disconnected(move |_p| {
            let _ = tx.lock().unwrap().send("disconnected".into());
        });
    let e = engine(Some(Server::new(Arc::new(routes))));
    let peer = dial(&e, e.local_addrs()[0], Arc::new(Routes::new())).unwrap();
    assert!(peer.peer_addr().is_some());

    assert_eq!(
        peer.call("/meta", b"", None).wait().unwrap(),
        b"/meta notify=false peer=true"
    );
    assert!(peer.notify("/note", b""));
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        "/note notify=true"
    );
    // Awaited (the future is polled before the answer is there), and a detached error.
    let r = block_on(peer.call("/late-fail", b"", None));
    assert_eq!(r, Err(CallError::Remote("late failure".into())));
    let r = block_on(peer.call("/meta", b"", None));
    assert!(r.is_ok());

    let (stx, srx) = mpsc::channel();
    let s = peer.new_stream("/info", move |_s, ev| {
        if let StreamEvent::Message(m) = ev {
            let _ = stx.send(String::from_utf8_lossy(m).into_owned());
        }
    });
    assert!(s.send(b"go"));
    let head = srx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(head.starts_with("/info#"), "{head}");
    assert_eq!(srx.recv_timeout(Duration::from_secs(5)).unwrap(), "up");
    assert_eq!(s.method(), "/info");
    assert!(s.peer().is_connected());
    let _ = s.id();
    assert!(s.close_send());

    // Closing: the server's disconnect hook runs; calls on the closed peer fail at once.
    peer.close();
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        "disconnected"
    );
    thread::sleep(Duration::from_millis(50));
    assert!(!peer.is_connected());
    assert_eq!(peer.call("/meta", b"", None).wait(), Err(CallError::Closed));
    let (ctx, crx) = mpsc::channel();
    peer.call_async("/meta", b"", None, move |r| {
        let _ = ctx.send(r);
    });
    assert_eq!(
        crx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Err(CallError::Closed)
    );
    assert!(!peer.notify("/note", b""));
    stop(&e);
}

#[test]
fn oversized_bodies_close_the_connection() {
    let routes = Routes::new().max_body(64).handle("/echo", |ctx| {
        let b = ctx.body().to_vec();
        ctx.write(&b);
    });
    let e = engine(Some(Server::new(Arc::new(routes))));
    let peer = dial(&e, e.local_addrs()[0], Arc::new(Routes::new())).unwrap();
    assert_eq!(peer.call("/echo", b"small", None).wait().unwrap(), b"small");
    assert_eq!(
        peer.call("/echo", &[0u8; 1000], Some(Duration::from_secs(5)))
            .wait(),
        Err(CallError::Closed)
    );
    stop(&e);
}

#[test]
fn errors_format_and_dial_failures() {
    assert_eq!(CallError::Remote("boom".into()).to_string(), "boom");
    assert_eq!(CallError::Closed.to_string(), "connection closed");
    assert_eq!(CallError::Timeout.to_string(), "timeout");
    // Nothing listens on a port we just released.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let e = engine(None);
    assert!(dial(&e, port, Arc::new(Routes::new())).is_err());
    stop(&e);
}
