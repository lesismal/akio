//! Companion of the book's "arpc" chapter: a server with calls, notifies, a detached answer and
//! broadcast; a client that also serves the server's notifies; middleware, coders and a pool.
//!
//! `cargo run -p akio-arpc --example guide-arpc`

use std::{
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

use akio::{Engine, Listener};
use akio_arpc::{
    Balance, CallError, Pool, Routes, Server, Values,
    coder::{Appender, FLAG_BIT_TRACING, Gzip},
    dial_blocking,
};

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
    let peer = dial_blocking(&engine, engine.local_addrs()[0], Arc::new(client_routes))?;
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

    // ANCHOR: middleware
    let coded = |r: Routes| {
        // The same chain on both ends; Go peers use arpcex's appender and gzip coders.
        r.coder(Appender::new("trace", FLAG_BIT_TRACING))
            .coder(Gzip::new(1024))
    };
    let routes = coded(Routes::new())
        .middleware(|ctx, next| {
            // Before the handler: refuse calls without a trace id (abort = no `next.run`).
            if ctx.values().get("trace").is_none() {
                return ctx.error("no trace");
            }
            let t = std::time::Instant::now();
            next.run(ctx);
            // After it: the answer has been sent.
            println!("{} took {:?}", ctx.method(), t.elapsed());
        })
        .method_middleware("/admin", |ctx, next| {
            if ctx.values().get("trace") == Some(b"root") {
                next.run(ctx);
            } else {
                ctx.error("forbidden");
            }
        })
        .handle("/admin", |ctx| ctx.write(b"welcome"))
        .handle("/echo", |ctx| {
            let body = ctx.body().to_vec();
            ctx.write(&body);
        });
    let coded_server = Server::new(Arc::new(routes));
    let engine2 = Arc::new(
        Engine::builder()
            .listen(Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(coded_server))
            .client_threads(1)
            .build()?,
    );
    engine2.start()?;
    // ANCHOR_END: middleware

    // ANCHOR: pool
    let pool = Pool::builder()
        .size(4)
        .balance(Balance::LeastPending)
        .heartbeat(Some(Duration::from_secs(15)))
        .dial(
            &engine2,
            engine2.local_addrs()[0],
            Arc::new(coded(Routes::new())),
        )?;
    let trace = Values::new().with("trace", "req-42");
    let big = vec![b'x'; 64 * 1024]; // sent gzip-compressed
    assert_eq!(
        pool.call_with("/echo", &big, t, &trace).wait().unwrap(),
        big
    );
    assert_eq!(
        pool.call("/echo", b"", t).wait(),
        Err(CallError::Remote("no trace".into()))
    );
    assert_eq!(
        pool.call_with("/admin", b"", t, &trace).wait(),
        Err(CallError::Remote("forbidden".into()))
    );
    println!(
        "{} of {} connections up",
        pool.connected(),
        pool.peers().len()
    );
    pool.close();
    // ANCHOR_END: pool

    engine2.shutdown();
    engine2.wait();
    engine.shutdown();
    engine.wait();
    Ok(())
}
