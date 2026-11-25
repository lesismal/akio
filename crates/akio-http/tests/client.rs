//! The HTTP client against `akio`'s own server (plain and TLS).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    future::Future,
    pin::pin,
    sync::Arc,
    task::{Context as TaskContext, Poll, Wake, Waker},
    thread,
    time::Duration,
};

use akio::{Backend, Config, Engine, Listener, UringConfig, tls::Tls};
use akio_http::{
    Context, Headers, Response, Router,
    client::{Client, ClientError, ClientRequest},
    serve,
};

fn backend() -> Backend {
    match std::env::var("AKIO_TEST_BACKEND").as_deref() {
        Ok("uring") => Backend::IoUring({
            let mut v = UringConfig::default();
            v.strict = true;
            v
        }),
        _ => Backend::Epoll,
    }
}

fn app() -> Router {
    Router::new()
        .get("/hello", |ctx: &mut Context| ctx.text(200, "hello client"))
        .get("/port", |ctx: &mut Context| {
            let p = ctx.peer().port();
            ctx.text(200, p.to_string());
        })
        .post("/echo", |ctx: &mut Context| {
            let b = ctx.body().to_vec();
            ctx.bytes(200, "application/octet-stream", b);
        })
        .get("/chunked", |ctx: &mut Context| {
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            thread::spawn(move || {
                for i in 0..4 {
                    s.write(format!("chunk{i};").as_bytes()).unwrap();
                    thread::sleep(Duration::from_millis(20));
                }
                s.finish();
            });
        })
        .get("/close", |ctx: &mut Context| {
            ctx.respond(Response::text(200, "bye").header("Connection", "close"));
        })
        .get("/slow", |ctx: &mut Context| {
            let d = ctx.detach().unwrap();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(600));
                d.respond(Response::text(200, "late"));
            });
        })
        .get("/missing-length", |ctx: &mut Context| {
            // HTTP/1.1 keep-alive answer with Content-Length 0 and no body.
            ctx.respond(Response::new(204));
        })
}

fn start(acceptor: impl akio::Acceptor) -> Engine {
    let e = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(500);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .threads(2)
                .serve(acceptor),
        )
        .client_threads(2)
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

fn plain() -> (Arc<Engine>, Client, String) {
    let e = Arc::new(start(serve(app())));
    let base = format!("http://{}", e.local_addrs()[0]);
    let client = Client::new(e.clone());
    (e, client, base)
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn block_on<F: Future>(f: F) -> F::Output {
    struct T(thread::Thread);
    impl Wake for T {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(T(thread::current())));
    let mut cx = TaskContext::from_waker(&waker);
    let mut f = pin!(f);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        thread::park_timeout(Duration::from_secs(10));
    }
}

#[test]
fn get_post_head_and_status_handling() {
    let (e, c, base) = plain();
    let r = c
        .send(ClientRequest::get(&format!("{base}/hello")))
        .wait()
        .unwrap();
    assert_eq!(
        (r.status, r.reason.as_str(), r.body.as_slice()),
        (200, "OK", &b"hello client"[..])
    );
    assert!(r.headers.get("date").is_some());
    let body: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
    let r = c
        .send(ClientRequest::post(&format!("{base}/echo"), body.clone()))
        .wait()
        .unwrap();
    assert!(r.body == body, "POST body echoed");
    let mut head = ClientRequest::get(&format!("{base}/hello"));
    head.method = akio_http::Method::Head;
    let r = c.send(head).wait().unwrap();
    assert_eq!((r.status, r.body.len()), (200, 0));
    assert_eq!(r.headers.get("content-length"), Some("12"));
    assert_eq!(
        c.send(ClientRequest::get(&format!("{base}/nope")))
            .wait()
            .unwrap()
            .status,
        404
    );
    let r = c
        .send(ClientRequest::get(&format!("{base}/missing-length")))
        .wait()
        .unwrap();
    assert_eq!((r.status, r.body.len()), (204, 0));
    stop(&e);
}

#[test]
fn chunked_responses_and_close_delimited_ones() {
    let (e, c, base) = plain();
    let r = c
        .send(ClientRequest::get(&format!("{base}/chunked")))
        .wait()
        .unwrap();
    assert_eq!(r.body, b"chunk0;chunk1;chunk2;chunk3;");
    assert_eq!(r.headers.get("transfer-encoding"), Some("chunked"));
    let r = c
        .send(ClientRequest::get(&format!("{base}/close")))
        .wait()
        .unwrap();
    assert_eq!(r.body, b"bye");
    stop(&e);
}

#[test]
fn keep_alive_connections_are_reused_and_parallel_requests_work() {
    let (e, c, base) = plain();
    let p1 = c
        .send(ClientRequest::get(&format!("{base}/port")))
        .wait()
        .unwrap()
        .body;
    let p2 = c
        .send(ClientRequest::get(&format!("{base}/port")))
        .wait()
        .unwrap()
        .body;
    assert_eq!(p1, p2, "the second request reused the connection");
    // After a `Connection: close` answer the next one dials again.
    c.send(ClientRequest::get(&format!("{base}/close")))
        .wait()
        .unwrap();
    let p3 = c
        .send(ClientRequest::get(&format!("{base}/port")))
        .wait()
        .unwrap()
        .body;
    let p4 = c
        .send(ClientRequest::get(&format!("{base}/port")))
        .wait()
        .unwrap()
        .body;
    assert_eq!(p3, p4);
    // 60 requests from 6 threads.
    let threads: Vec<_> = (0..6)
        .map(|t| {
            let (c, base) = (c.clone(), base.clone());
            thread::spawn(move || {
                for i in 0..10 {
                    let msg = format!("t{t}-{i}").into_bytes();
                    let r = c
                        .send(ClientRequest::post(&format!("{base}/echo"), msg.clone()))
                        .wait()
                        .unwrap();
                    assert_eq!(r.body, msg);
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    stop(&e);
}

#[test]
fn errors_timeouts_and_await() {
    let (e, c, base) = plain();
    assert!(matches!(
        c.send(ClientRequest::get("ftp://x/")).wait(),
        Err(ClientError::InvalidUrl(_))
    ));
    // Nothing listens on this port.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    assert!(matches!(
        c.send(ClientRequest::get(&format!("http://{dead}/")))
            .wait(),
        Err(ClientError::Io(_))
    ));
    // wait_timeout gives up; the late answer is simply dropped.
    let fut = c.send(ClientRequest::get(&format!("{base}/slow")));
    assert!(fut.wait_timeout(Duration::from_millis(100)).is_none());
    // async/await works too.
    let r = block_on(c.send(ClientRequest::get(&format!("{base}/hello")))).unwrap();
    assert_eq!(r.body, b"hello client");
    // https without a TLS configuration is refused cleanly.
    assert!(matches!(
        c.send(ClientRequest::get("https://127.0.0.1:1/")).wait(),
        Err(ClientError::Io(_))
    ));
    thread::sleep(Duration::from_millis(700)); // let /slow finish before the server stops
    stop(&e);
}

#[test]
fn https_through_only_tls() {
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = ck.0.as_der().to_vec();
    let scfg = akio::tls::ServerConfig::builder(
        vec![akio::tls::Certificate::from_der(cert.clone())],
        akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
    .build()
    .unwrap();
    let e = Arc::new(start(Tls::server(scfg, serve(app()))));
    let mut roots = akio::tls::RootCerts::empty();
    roots.add(&akio::tls::Certificate::from_der(cert)).unwrap();
    let ccfg = akio::tls::ClientConfig::builder()
        .roots(roots)
        .build()
        .unwrap();
    let c = Client::new(e.clone()).with_tls(ccfg);
    let url = format!("https://localhost:{}/hello", e.local_addrs()[0].port());
    let r = c.send(ClientRequest::get(&url)).wait().unwrap();
    assert_eq!(r.body, b"hello client");
    // A second request reuses the TLS connection.
    let u2 = format!("https://localhost:{}/port", e.local_addrs()[0].port());
    let a = c.send(ClientRequest::get(&u2)).wait().unwrap().body;
    let b = c.send(ClientRequest::get(&u2)).wait().unwrap().body;
    assert_eq!(a, b);
    stop(&e);
}

/// `with_tls_server_name` (A108): a server reached by its address whose certificate names
/// another host is verified, and asked in SNI, under that name; without it, or with another
/// name, the handshake fails; an empty name restores the URL's host.
#[test]
fn https_with_a_tls_server_name() {
    let ck = akio_x509::generate_simple_self_signed(["example.com"]).unwrap();
    let cert = ck.0.as_der().to_vec();
    let scfg = akio::tls::ServerConfig::builder(
        vec![akio::tls::Certificate::from_der(cert.clone())],
        akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
    .build()
    .unwrap();
    let e = Arc::new(start(Tls::server(scfg, serve(app()))));
    let mut roots = akio::tls::RootCerts::empty();
    roots.add(&akio::tls::Certificate::from_der(cert)).unwrap();
    let ccfg = akio::tls::ClientConfig::builder()
        .roots(roots)
        .build()
        .unwrap();
    let url = format!("https://127.0.0.1:{}/hello", e.local_addrs()[0].port());
    let plain = Client::new(e.clone()).with_tls(ccfg);
    let r = plain.send(ClientRequest::get(&url)).wait();
    assert!(r.is_err(), "{r:?}");
    let named = plain.clone().with_tls_server_name("example.com");
    let r = named.send(ClientRequest::get(&url)).wait().unwrap();
    assert_eq!(r.body, b"hello client");
    // Reused: the connection is kept by the URL's host and port.
    let u2 = format!("https://127.0.0.1:{}/port", e.local_addrs()[0].port());
    let a = named.send(ClientRequest::get(&u2)).wait().unwrap().body;
    let b = named.send(ClientRequest::get(&u2)).wait().unwrap().body;
    assert_eq!(a, b);
    let wrong = plain.with_tls_server_name("other.example");
    assert!(wrong.send(ClientRequest::get(&url)).wait().is_err());
    let restored = named.with_tls_server_name("");
    assert!(restored.send(ClientRequest::get(&url)).wait().is_err());
    stop(&e);
}

/// An engine that only hosts client connections, with the default 10 s `shutdown_timeout`.
fn client_engine() -> Arc<Engine> {
    let e = Engine::builder().client_threads(2).build().unwrap();
    e.start().unwrap();
    Arc::new(e)
}

#[test]
fn engine_shutdown_does_not_wait_for_idle_keep_alive_connections() {
    // The server lives on its own engine, so only the client side can end the connections.
    let server = start(serve(app()));
    let base = format!("http://{}", server.local_addrs()[0]);
    let e = client_engine();
    let c = Client::new(e.clone());
    let r = c.send(ClientRequest::get(&format!("{base}/hello"))).wait();
    assert_eq!(r.unwrap().status, 200);
    // The connection now sits idle in the client's pool. It used to stay open through the
    // graceful shutdown, so `wait` took the whole 10 s `shutdown_timeout`.
    let t0 = std::time::Instant::now();
    stop(&e);
    assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());

    // A request in flight when the shutdown starts still gets its response; its connection
    // then closes instead of going back to the pool.
    let e = client_engine();
    let c = Client::new(e.clone());
    let late = c.send(ClientRequest::get(&format!("{base}/slow")));
    thread::sleep(Duration::from_millis(100));
    let t0 = std::time::Instant::now();
    e.shutdown();
    let r = late.wait().unwrap();
    assert_eq!(r.body, b"late");
    e.wait();
    assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
    stop(&server);
}

/// A server of plain sockets: each connection answers `ok` to every request, `delay` after it
/// arrives; each connection's end is sent on the channel.
fn counting_server(delay: Duration) -> (std::net::SocketAddr, std::sync::mpsc::Receiver<()>) {
    use std::io::{BufRead, BufReader, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(c) = c else { return };
            let tx = tx.clone();
            thread::spawn(move || {
                let mut w = c.try_clone().unwrap();
                let mut r = BufReader::new(c);
                'conn: loop {
                    loop {
                        let mut line = String::new();
                        match r.read_line(&mut line) {
                            Ok(0) | Err(_) => break 'conn,
                            Ok(_) if line == "\r\n" => break,
                            Ok(_) => {}
                        }
                    }
                    thread::sleep(delay);
                    if w.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .is_err()
                    {
                        break;
                    }
                }
                let _ = tx.send(());
            });
        }
    });
    (addr, rx)
}

/// akit's A10: `close_idle` closes the idle connections now, and the one in flight once its
/// response is in, rather than after `idle_timeout`.
#[test]
fn close_idle_closes_idle_connections_now() {
    let e = client_engine();
    let (addr, closed) = counting_server(Duration::ZERO);
    let c = Client::new(e.clone());
    let url = format!("http://{addr}/");
    for _ in 0..2 {
        assert_eq!(c.send(ClientRequest::get(&url)).wait().unwrap().body, b"ok");
    }
    // One connection, kept idle.
    assert!(closed.recv_timeout(Duration::from_millis(300)).is_err());
    let other = c.clone();
    // Through a clone: clones share the client.
    other.close_idle();
    closed
        .recv_timeout(Duration::from_secs(5))
        .expect("the idle connection was not closed");
    // From then on a connection closes once its response is in.
    assert_eq!(c.send(ClientRequest::get(&url)).wait().unwrap().body, b"ok");
    closed
        .recv_timeout(Duration::from_secs(5))
        .expect("a connection went back idle after close_idle");
    stop(&e);

    // A request in flight when it is called gets its response; its connection then closes.
    let e = client_engine();
    let (addr, closed) = counting_server(Duration::from_millis(300));
    let c = Client::new(e.clone());
    let late = c.send(ClientRequest::get(&format!("http://{addr}/")));
    thread::sleep(Duration::from_millis(100));
    c.close_idle();
    assert_eq!(late.wait().unwrap().body, b"ok");
    closed
        .recv_timeout(Duration::from_secs(5))
        .expect("the connection in flight went back idle");
    stop(&e);
}
