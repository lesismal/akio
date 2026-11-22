//! arpc between two `akio` peers.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

use akio::{Config, Engine, Listener};
use akio_arpc::{CallError, Routes, Server, StreamEvent, dial_blocking};

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

fn server_routes(log: Arc<Mutex<Vec<String>>>) -> Routes {
    let l2 = log.clone();
    Routes::new()
        .handle("/echo", |ctx| {
            let b = ctx.body().to_vec();
            ctx.write(&b);
        })
        .handle("/fail", |ctx| ctx.error("it failed"))
        .handle("/later", |ctx| {
            let r = ctx.detach();
            let body = ctx.body().to_vec();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(50));
                r.write(&[b"later:".as_slice(), &body].concat());
            });
        })
        .handle("/note", move |ctx| {
            log.lock()
                .unwrap()
                .push(String::from_utf8_lossy(ctx.body()).into_owned());
        })
        .handle("/callback", |ctx| {
            // Two-way: call the client while serving its call, answer when it answers.
            let r = ctx.detach();
            ctx.peer()
                .call_async("/client/name", b"?", None, move |res| match res {
                    Ok(name) => r.write(&[b"hello ".as_slice(), &name].concat()),
                    Err(e) => r.error(&e.to_string()),
                });
        })
        .handle("/never", |ctx| {
            let _ = ctx.detach(); // dropped: no answer ever
        })
        .handle_stream("/upper", |_s| {
            |s: &akio_arpc::Stream, ev: StreamEvent<'_>| match ev {
                StreamEvent::Message(m) => {
                    s.send(&m.to_ascii_uppercase());
                }
                StreamEvent::Eof => {
                    s.close_send();
                }
            }
        })
        .on_connected(move |_p| l2.lock().unwrap().push("connected".into()))
}

#[test]
fn calls_errors_notifies_two_way_and_detached_answers() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let server = Server::new(Arc::new(server_routes(log.clone())));
    let e = engine(Some(server));
    let client_routes = Routes::new().handle("/client/name", |ctx| ctx.write(b"rustacean"));
    let peer = dial_blocking(&e, e.local_addrs()[0], Arc::new(client_routes)).unwrap();

    assert_eq!(peer.call("/echo", b"ping", None).wait().unwrap(), b"ping");
    assert_eq!(
        peer.call("/echo", &vec![7u8; 3 << 20], None)
            .wait()
            .unwrap()
            .len(),
        3 << 20
    );
    assert_eq!(
        peer.call("/fail", b"", None).wait(),
        Err(CallError::Remote("it failed".into()))
    );
    assert_eq!(
        peer.call("/missing", b"", None).wait(),
        Err(CallError::Remote(akio_arpc::METHOD_NOT_FOUND.into()))
    );
    assert_eq!(peer.call("/later", b"x", None).wait().unwrap(), b"later:x");
    assert_eq!(
        peer.call("/callback", b"", None).wait().unwrap(),
        b"hello rustacean"
    );
    assert_eq!(
        peer.call("/never", b"", Some(Duration::from_millis(100)))
            .wait(),
        Err(CallError::Timeout)
    );
    assert!(peer.notify("/note", b"noted"));
    // Many concurrent calls on one connection.
    let futs: Vec<_> = (0..300)
        .map(|i| (i, peer.call("/echo", format!("m{i}").as_bytes(), None)))
        .collect();
    for (i, f) in futs {
        assert_eq!(f.wait().unwrap(), format!("m{i}").as_bytes());
    }
    thread::sleep(Duration::from_millis(50));
    let l = log.lock().unwrap().clone();
    assert!(
        l.contains(&"noted".to_string()) && l.contains(&"connected".to_string()),
        "{l:?}"
    );
    peer.close();
    e.shutdown();
    e.wait();
}

#[test]
fn streams_both_directions() {
    let server = Server::new(Arc::new(server_routes(Arc::default())));
    let e = engine(Some(server));
    let peer = dial_blocking(&e, e.local_addrs()[0], Arc::new(Routes::new())).unwrap();
    let (tx, rx) = mpsc::channel();
    let s = peer.new_stream("/upper", move |_s, ev| {
        let _ = tx.send(match ev {
            StreamEvent::Message(m) => Some(m.to_vec()),
            StreamEvent::Eof => None,
        });
    });
    for w in ["alpha", "beta", "gamma"] {
        assert!(s.send(w.as_bytes()));
    }
    s.close_send();
    let mut got = Vec::new();
    while let Some(m) = rx.recv_timeout(Duration::from_secs(5)).unwrap() {
        got.push(String::from_utf8(m).unwrap());
    }
    assert_eq!(got, ["ALPHA", "BETA", "GAMMA"]);
    // A stream for a method the server does not serve ends right away.
    let (tx, rx) = mpsc::channel();
    let s = peer.new_stream("/nobody", move |_s, ev| {
        let _ = tx.send(matches!(ev, StreamEvent::Eof));
    });
    s.send(b"x");
    assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap());
    peer.close();
    e.shutdown();
    e.wait();
}

#[test]
fn broadcast_and_reconnect() {
    let server = Server::new(Arc::new(server_routes(Arc::default())));
    let e = engine(Some(server.clone()));
    let addr = e.local_addrs()[0];
    let got = Arc::new(Mutex::new(Vec::new()));
    let peers: Vec<_> = (0..3)
        .map(|i| {
            let g = got.clone();
            let routes = Routes::new().handle("/news", move |ctx| {
                g.lock().unwrap().push((i, ctx.body().to_vec()));
            });
            dial_blocking(&e, addr, Arc::new(routes)).unwrap()
        })
        .collect();
    let t = std::time::Instant::now();
    while server.peers().len() < 3 {
        assert!(t.elapsed() < Duration::from_secs(5));
        thread::sleep(Duration::from_millis(5));
    }
    server.broadcast("/news", b"extra!");
    let t = std::time::Instant::now();
    while got.lock().unwrap().len() < 3 {
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "broadcast reached {:?}",
            got.lock().unwrap()
        );
        thread::sleep(Duration::from_millis(5));
    }
    // The server drops a client; it reconnects on its own and calls work again.
    for p in server.peers() {
        p.close();
    }
    thread::sleep(Duration::from_millis(1500));
    assert!(peers[0].is_connected(), "reconnected");
    assert_eq!(
        peers[0].call("/echo", b"again", None).wait().unwrap(),
        b"again"
    );
    for p in &peers {
        p.close();
    }
    e.shutdown();
    e.wait();
}
