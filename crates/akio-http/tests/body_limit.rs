//! A response that closes its HTTP/1 connection and stops reading the body it refused (akit
//! A24), a request body bounded by a middleware (`Context::limit_body`, akit A49) on HTTP/1 and
//! HTTP/2, and the address a request came to (`Context::local_addr`, akit A148).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

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

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{
    BodyEvent, Context, Headers, HttpConfig, Response, Router, Service, Streaming,
    client::ClientRequest,
    h2client::{H2Client, H2Options},
    serve_with,
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

/// What the routes saw.
#[derive(Default)]
struct Seen {
    /// `/hello` calls.
    hello: AtomicUsize,
    /// Handlers of a limited route called.
    called: AtomicUsize,
    /// `BodyEvent::TooLarge` events.
    too_large: AtomicUsize,
    /// Body bytes delivered to `/refuse`'s sink.
    refused_bytes: AtomicUsize,
}

/// A streamed body summed: its length answered at its end, `TooLarge` counted.
fn sum(seen: &Arc<Seen>) -> impl Service {
    let seen = seen.clone();
    Streaming(move |ctx: &mut Context| {
        seen.called.fetch_add(1, Ordering::SeqCst);
        let seen = seen.clone();
        let mut n = 0usize;
        ctx.on_body(move |ctx, ev| match ev {
            BodyEvent::Chunk(b) => n += b.len(),
            BodyEvent::End(_) => ctx.text(200, n.to_string()),
            BodyEvent::TooLarge => {
                seen.too_large.fetch_add(1, Ordering::SeqCst);
            }
        });
    })
}

fn app(seen: &Arc<Seen>) -> Router {
    let (s1, s2, s3, s4) = (seen.clone(), seen.clone(), seen.clone(), seen.clone());
    Router::new()
        // `body_limit` as akit's: 1000 bytes, for the routes registered before the layer.
        .post("/sum", sum(seen))
        // Suspended with its body streaming (ADR-159), resumed into `sum` from another thread:
        // the limit set before the suspension holds in the resumed context.
        .post(
            "/suspended",
            Streaming({
                let seen = seen.clone();
                move |ctx: &mut Context| {
                    let s = ctx.suspend().expect("a streamed body suspends");
                    let seen = seen.clone();
                    thread::spawn(move || {
                        thread::sleep(Duration::from_millis(30));
                        s.resume(move |ctx| sum(&seen).call(ctx));
                    });
                }
            }),
        )
        .post("/buffered", move |ctx: &mut Context| {
            s1.called.fetch_add(1, Ordering::SeqCst);
            let n = ctx.body().len();
            ctx.text(200, n.to_string());
        })
        .post(
            "/detached",
            Streaming(move |ctx: &mut Context| {
                let seen = s2.clone();
                let mut d = ctx.detach();
                ctx.on_body(move |_ctx, ev| match ev {
                    BodyEvent::Chunk(_) => {}
                    BodyEvent::End(_) => {
                        if let Some(d) = d.take() {
                            d.respond(Response::text(200, "whole"));
                        }
                    }
                    BodyEvent::TooLarge => {
                        seen.too_large.fetch_add(1, Ordering::SeqCst);
                        // The handler holds the response: it answers, from another thread.
                        if let Some(d) = d.take() {
                            thread::spawn(move || {
                                d.respond(
                                    Response::text(413, "the sink said too large")
                                        .header("Connection", "close"),
                                );
                            });
                        }
                    }
                });
            }),
        )
        .layer(|ctx: &mut Context, next: &dyn Service| {
            if ctx.limit_body(1000) {
                next.call(ctx);
            }
        })
        // The declared length taken away before the limit is set: the body is refused as it
        // grows.
        .post(
            "/undeclared",
            Streaming(move |ctx: &mut Context| {
                if let Some(r) = ctx.req_mut() {
                    r.headers.remove("content-length");
                }
                if ctx.limit_body(1000) {
                    sum(&s3).call(ctx);
                }
            }),
        )
        // A limit set after the handler set its sink.
        .post(
            "/late",
            Streaming(move |ctx: &mut Context| {
                sum(&s4).call(ctx);
                ctx.limit_body(1000);
            }),
        )
        .post(
            "/refuse",
            Streaming({
                let seen = seen.clone();
                move |ctx: &mut Context| {
                    let seen = seen.clone();
                    ctx.on_body(move |_ctx, ev| {
                        if let BodyEvent::Chunk(b) = ev {
                            seen.refused_bytes.fetch_add(b.len(), Ordering::SeqCst);
                        }
                    });
                    ctx.respond(Response::text(413, "no thanks").header("Connection", "close"));
                }
            }),
        )
        .post(
            "/refuse-later",
            Streaming(|ctx: &mut Context| {
                let d = ctx.detach().unwrap();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(50));
                    d.respond(Response::text(413, "later").header("Connection", "close"));
                });
            }),
        )
        .get("/close", |ctx: &mut Context| {
            ctx.respond(Response::text(200, "bye").header("Connection", "close"));
        })
        .get("/stream-close", |ctx: &mut Context| {
            let mut h = Headers::new();
            h.set("Connection", "close");
            let s = ctx.stream_response(200, h).unwrap();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(30));
                s.write(b"streamed").unwrap();
                s.finish();
            });
        })
        .get("/hello", {
            let seen = seen.clone();
            move |ctx: &mut Context| {
                seen.hello.fetch_add(1, Ordering::SeqCst);
                ctx.text(200, "hello");
            }
        })
        .get("/local", |ctx: &mut Context| {
            let a = ctx.local_addr().to_string();
            ctx.text(200, a);
        })
}

fn start(seen: &Arc<Seen>) -> Arc<Engine> {
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_millis(500);
                v
            })
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .backend(backend())
                    .threads(2)
                    .serve(serve_with(HttpConfig::default(), app(seen))),
            )
            .client_threads(2)
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    e
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn connect(e: &Engine) -> TcpStream {
    let s = TcpStream::connect(e.local_addrs()[0]).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

/// Reads until the connection ends: what came, and whether it ended (EOF or reset) rather
/// than went quiet past the read timeout.
fn read_to_close(s: &mut TcpStream) -> (String, bool) {
    let mut out = Vec::new();
    let mut buf = [0u8; 16 << 10];
    let closed = loop {
        match s.read(&mut buf) {
            Ok(0) => break true,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break false;
            }
            Err(_) => break true,
        }
    };
    (String::from_utf8_lossy(&out).into_owned(), closed)
}

/// Reads one response framed by its `Content-Length`: its head and body.
fn read_response(s: &mut TcpStream) -> (String, String) {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        if let Some(at) = out.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&out[..at]).into_owned();
            let len: usize = head
                .lines()
                .find_map(|l| {
                    let (n, v) = l.split_once(':')?;
                    n.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse().unwrap())
                })
                .expect("a Content-Length");
            while out.len() < at + 4 + len {
                let n = s.read(&mut buf).expect("the body");
                assert!(n > 0, "the body ends early");
                out.extend_from_slice(&buf[..n]);
            }
            let body = String::from_utf8_lossy(&out[at + 4..at + 4 + len]).into_owned();
            return (head, body);
        }
        let n = s.read(&mut buf).expect("a response head");
        assert!(n > 0, "closed before a response");
        out.extend_from_slice(&buf[..n]);
    }
}

fn post(path: &str, body: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}

/// A chunked request body of `pieces`, ended.
fn post_chunked(path: &str, pieces: &[usize]) -> Vec<u8> {
    let mut r = format!("POST {path} HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
        .into_bytes();
    for &n in pieces {
        r.extend_from_slice(format!("{n:x}\r\n").as_bytes());
        r.extend(std::iter::repeat_n(b'x', n));
        r.extend_from_slice(b"\r\n");
    }
    r.extend_from_slice(b"0\r\n\r\n");
    r
}

/// A24: a `413` with `Connection: close` given before the body is read closes the connection
/// at once, with no byte of a 100 MiB body read (it used to wait for the body, or its timeout).
#[test]
fn a_close_response_before_the_body_closes_without_reading_it() {
    let seen = Arc::new(Seen::default());
    let e = start(&seen);
    let mut s = connect(&e);
    let t = Instant::now();
    s.write_all(b"POST /refuse HTTP/1.1\r\nHost: x\r\nContent-Length: 104857600\r\n\r\n")
        .unwrap();
    let (got, closed) = read_to_close(&mut s);
    assert!(got.starts_with("HTTP/1.1 413 "), "{got}");
    assert!(got.contains("Connection: close\r\n"), "{got}");
    assert!(got.ends_with("no thanks"), "{got}");
    assert!(closed, "the connection closes");
    assert!(t.elapsed() < Duration::from_secs(4));
    assert_eq!(seen.refused_bytes.load(Ordering::SeqCst), 0);

    // From a detached handler, after some of the body came: the same.
    let mut s = connect(&e);
    let mut req =
        b"POST /refuse-later HTTP/1.1\r\nHost: x\r\nContent-Length: 104857600\r\n\r\n".to_vec();
    req.extend(std::iter::repeat_n(b'x', 1000));
    s.write_all(&req).unwrap();
    let (got, closed) = read_to_close(&mut s);
    assert!(got.starts_with("HTTP/1.1 413 "), "{got}");
    assert!(got.ends_with("later"), "{got}");
    assert!(closed, "the connection closes");
    stop(&e);
}

/// A24: a keep-alive response leaves the connection open; one that says `Connection: close`
/// ends it, and the requests pipelined behind it are not served.
#[test]
fn a_close_response_ends_the_connection_and_its_pipelined_requests() {
    let seen = Arc::new(Seen::default());
    let e = start(&seen);
    let mut s = connect(&e);
    for _ in 0..2 {
        s.write_all(b"GET /hello HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let (head, body) = read_response(&mut s);
        assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
        assert!(!head.contains("Connection: close"), "{head}");
        assert_eq!(body, "hello");
    }
    assert_eq!(seen.hello.load(Ordering::SeqCst), 2);

    s.write_all(
        b"GET /close HTTP/1.1\r\nHost: x\r\n\r\nGET /hello HTTP/1.1\r\nHost: x\r\n\r\nGET /hello HTTP/1.1\r\nHost: x\r\n\r\n",
    )
    .unwrap();
    let (got, closed) = read_to_close(&mut s);
    assert!(closed, "the connection closes: {got}");
    assert_eq!(got.matches("HTTP/1.1 ").count(), 1, "{got}");
    assert!(got.ends_with("bye"), "{got}");
    assert_eq!(
        seen.hello.load(Ordering::SeqCst),
        2,
        "no pipelined request served"
    );

    // A streamed response saying so closes once it is done, the requests behind it unserved.
    let mut s = connect(&e);
    s.write_all(
        b"GET /stream-close HTTP/1.1\r\nHost: x\r\n\r\nGET /hello HTTP/1.1\r\nHost: x\r\n\r\n",
    )
    .unwrap();
    let (got, closed) = read_to_close(&mut s);
    assert!(closed, "the connection closes: {got}");
    assert_eq!(got.matches("HTTP/1.1 ").count(), 1, "{got}");
    assert!(got.contains("streamed"), "{got}");
    assert!(!got.contains("hello"), "{got}");
    assert_eq!(seen.hello.load(Ordering::SeqCst), 2);
    stop(&e);
}

/// A49 on HTTP/1: a streamed body under and at the limit goes through; one declared over it
/// is refused before the handler runs and before any of it is read; one that grows past it
/// tells its sink, is answered `413` and closes the connection.
#[test]
fn limit_body_http1() {
    let seen = Arc::new(Seen::default());
    let e = start(&seen);
    let mut s = connect(&e);
    for n in [999usize, 1000] {
        s.write_all(&post("/sum", &vec![b'x'; n])).unwrap();
        let (head, body) = read_response(&mut s);
        assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
        assert_eq!(body, n.to_string());
    }
    assert_eq!(seen.called.load(Ordering::SeqCst), 2);

    // Declared over: refused at once, the handler not called, the body not read.
    s.write_all(b"POST /sum HTTP/1.1\r\nHost: x\r\nContent-Length: 1001\r\n\r\n")
        .unwrap();
    let (got, closed) = read_to_close(&mut s);
    assert!(got.starts_with("HTTP/1.1 413 "), "{got}");
    assert!(got.contains("Connection: close\r\n"), "{got}");
    assert!(closed);
    assert_eq!(seen.called.load(Ordering::SeqCst), 2);
    assert_eq!(seen.too_large.load(Ordering::SeqCst), 0);

    // Growing past it (chunked, no declared length): the sink hears it, `413`, closed.
    for (path, calls) in [("/sum", 3), ("/late", 4)] {
        let mut s = connect(&e);
        let before = seen.too_large.load(Ordering::SeqCst);
        s.write_all(&post_chunked(path, &[600, 600])).unwrap();
        let (got, closed) = read_to_close(&mut s);
        assert!(got.starts_with("HTTP/1.1 413 "), "{path}: {got}");
        assert!(closed, "{path}");
        assert_eq!(seen.too_large.load(Ordering::SeqCst), before + 1, "{path}");
        assert_eq!(seen.called.load(Ordering::SeqCst), calls, "{path}");
    }

    // At the limit, chunked: through.
    let mut s = connect(&e);
    s.write_all(&post_chunked("/late", &[500, 500])).unwrap();
    let (head, body) = read_response(&mut s);
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    assert_eq!(body, "1000");

    // A detached handler answers itself, as its sink is told.
    let mut s = connect(&e);
    s.write_all(&post_chunked("/detached", &[800, 800]))
        .unwrap();
    let (got, closed) = read_to_close(&mut s);
    assert!(got.starts_with("HTTP/1.1 413 "), "{got}");
    assert!(got.ends_with("the sink said too large"), "{got}");
    assert!(closed);

    // A buffered body over the limit: `413`, and the connection stays (the body was read).
    let mut s = connect(&e);
    s.write_all(&post("/buffered", &[b'x'; 1001])).unwrap();
    let (head, _) = read_response(&mut s);
    assert!(head.starts_with("HTTP/1.1 413 "), "{head}");
    s.write_all(&post("/buffered", &[b'x'; 1000])).unwrap();
    let (head, body) = read_response(&mut s);
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    assert_eq!(body, "1000");
    stop(&e);
}

/// A49 with A75: a limit set before a streamed request is suspended holds in the context it is
/// resumed in; under it the body arrives whole.
#[test]
fn limit_body_holds_across_a_suspension() {
    let seen = Arc::new(Seen::default());
    let e = start(&seen);
    let mut s = connect(&e);
    s.write_all(&post_chunked("/suspended", &[500, 400]))
        .unwrap();
    let (head, body) = read_response(&mut s);
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    assert_eq!(body, "900");

    let mut s = connect(&e);
    s.write_all(&post_chunked("/suspended", &[600, 600]))
        .unwrap();
    let (got, closed) = read_to_close(&mut s);
    assert!(got.starts_with("HTTP/1.1 413 "), "{got}");
    assert!(closed);
    assert_eq!(seen.too_large.load(Ordering::SeqCst), 1);
    stop(&e);
}

/// A49 on HTTP/2: a declared length over the limit is refused at once, a body that grows past
/// it is refused as it does, and the connection's other streams go on.
#[test]
fn limit_body_http2() {
    let seen = Arc::new(Seen::default());
    let e = start(&seen);
    let addr = e.local_addrs()[0];
    let c = H2Client::dial_blocking(&e, addr, None, H2Options::default()).unwrap();
    let url = |p: &str| format!("http://{addr}{p}");
    let send = |p: &str, n: usize| {
        c.send(ClientRequest::post(&url(p), vec![b'x'; n]))
            .wait()
            .unwrap()
    };
    let r = send("/sum", 1000);
    assert_eq!(
        (r.status, String::from_utf8(r.body).unwrap()),
        (200, "1000".into())
    );
    let called = seen.called.load(Ordering::SeqCst);
    let r = send("/sum", 1001);
    assert_eq!(r.status, 413);
    assert_eq!(
        seen.called.load(Ordering::SeqCst),
        called,
        "refused before the handler"
    );
    // No declared length: refused as it grows, the sink told.
    let r = send("/undeclared", 64 << 10);
    assert_eq!(r.status, 413);
    assert_eq!(seen.too_large.load(Ordering::SeqCst), 1);
    let r = send("/undeclared", 900);
    assert_eq!(
        (r.status, String::from_utf8(r.body).unwrap()),
        (200, "900".into())
    );
    // The connection serves on.
    let r = c.send(ClientRequest::get(&url("/hello"))).wait().unwrap();
    assert_eq!(r.status, 200);
    stop(&e);
}

/// A148: the address a request came to, on HTTP/1.1 and HTTP/2.
#[test]
fn local_address_of_a_request() {
    let seen = Arc::new(Seen::default());
    let e = start(&seen);
    let addr: SocketAddr = e.local_addrs()[0];
    let mut s = connect(&e);
    s.write_all(b"GET /local HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let (_, body) = read_response(&mut s);
    assert_eq!(body, addr.to_string());
    let c = H2Client::dial_blocking(&e, addr, None, H2Options::default()).unwrap();
    let r = c
        .send(ClientRequest::get(&format!("http://{addr}/local")))
        .wait()
        .unwrap();
    assert_eq!(String::from_utf8(r.body).unwrap(), addr.to_string());
    stop(&e);
}
