//! Companion of the book's "arpc" chapter: a server with calls, notifies, a detached answer and
//! broadcast; a client that also serves the server's notifies.
//!
//! `cargo run -p flash-arpc --example guide-arpc`

use std::{
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

use flash::{Engine, Listener};
use flash_arpc::{CallError, Routes, Server, dial};

fn main() -> std::io::Result<()> {
    // ANCHOR: server
    let routes = Routes::new()
        .handle("/echo", |ctx| {
            let body = ctx.body().to_vec();
            ctx.write(&body); // answer inline: the handler runs on the I/O thread
        })
        .handle("/slow", |ctx| {
            let r = ctx.detach(); // answer later, from any thread
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(20));
                r.write(b"done");
            });
        })
        .handle("/fail", |ctx| ctx.error("not today"))
        .on_connected(|peer| println!("client {:?} connected", peer.peer_addr()));
    let server = Server::new(Arc::new(routes));
    let engine = Arc::new(
        Engine::builder()
            .listen(Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(server.clone()))
            .client_threads(1)
            .build()?,
    );
    engine.start()?;
    // ANCHOR_END: server

    // ANCHOR: client
    let (tx, rx) = mpsc::channel();
    // The client side has routes too: the server may call or notify it.
    let client_routes = Routes::new().handle("/news", move |ctx| {
        let _ = tx.send(String::from_utf8_lossy(ctx.body()).into_owned());
    });
    let peer = dial(&engine, engine.local_addrs()[0], Arc::new(client_routes))?;
    let t = Some(Duration::from_secs(5));
    assert_eq!(peer.call("/echo", b"ping", t).wait().unwrap(), b"ping");
    assert_eq!(peer.call("/slow", b"", t).wait().unwrap(), b"done");
    assert_eq!(
        peer.call("/fail", b"", t).wait(),
        Err(CallError::Remote("not today".into()))
    );
    peer.call_async("/echo", b"async", t, |r| println!("async answer: {r:?}"));
    peer.notify("/echo", b"one-way"); // no answer expected
    server.broadcast("/news", b"hello everyone"); // one encoded frame, shared
    println!(
        "notify from server: {}",
        rx.recv_timeout(Duration::from_secs(5)).unwrap()
    );
    // ANCHOR_END: client

    peer.close();
    engine.shutdown();
    engine.wait();
    Ok(())
}
