//! Requests whose body streams, suspended (`Context::suspend` with `BodyMode::Stream`, ADR-159,
//! akit A75): the body's reads are held from the suspension until the resumed handler took
//! its sink, what was read meanwhile (one read's worth, a stream window) is kept for it, and
//! the handler gets the whole body in order; a large body is paced, not buffered; a handler
//! that holds the reads keeps them held; a second suspension; pipelined requests behind; a
//! client that goes meanwhile; HTTP/1.1 and HTTP/2.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{
    BodyEvent, Context, H2Config, HttpConfig, Router, Streaming, Suspended,
    client::ClientRequest,
    h2client::{H2Client, H2Options},
    message::Method,
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

fn pat(i: usize) -> u8 {
    (i * 7 % 251) as u8
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(pat).collect()
}

/// What the resumed handlers saw.
#[derive(Default)]
struct Seen {
    /// The first piece of the body the resumed sink got: what was kept while suspended.
    first: AtomicUsize,
    /// The bytes the test's client had written when the request was resumed.
    written_at_resume: AtomicUsize,
    /// Pieces delivered while the resumed handler held the reads (after the kept one).
    while_held: AtomicUsize,
    /// A context taking its body could be suspended again.
    resuspended: AtomicBool,
    gone: AtomicBool,
    /// A body's end reached a resumed sink of a request whose client went.
    gone_ended: AtomicBool,
}

/// What the test's client wrote so far (the large upload).
static WRITTEN: AtomicUsize = AtomicUsize::new(0);

/// The resumed handler: takes the body, checks it against the pattern, answers `ok <len>`.
fn take_body(ctx: &mut Context, seen: &Arc<Seen>) {
    let seen = seen.clone();
    let (mut off, mut bad, mut first) = (0usize, None, true);
    ctx.on_body(move |ctx, ev| match ev {
        BodyEvent::Chunk(b) => {
            if std::mem::take(&mut first) {
                seen.first.store(b.len(), Ordering::Relaxed);
                if ctx.suspend().is_some() {
                    seen.resuspended.store(true, Ordering::Relaxed);
                }
            }
            for (i, &x) in b.iter().enumerate() {
                if bad.is_none() && x != pat(off + i) {
                    bad = Some(off + i);
                }
            }
            off += b.len();
        }
        BodyEvent::TooLarge => {}
        BodyEvent::End(_) => {
            let r = match bad {
                None => format!("ok {off}"),
                Some(at) => format!("bad at {at} of {off}"),
            };
            ctx.text(200, r);
        }
    });
}

fn ms(ctx: &Context) -> u64 {
    ctx.param("ms").unwrap().parse().unwrap()
}

fn later(ms: u64, f: impl FnOnce() + Send + 'static) {
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(ms));
        f();
    });
}

fn app(seen: &Arc<Seen>) -> Router {
    let (s1, s2, s3, s4) = (seen.clone(), seen.clone(), seen.clone(), seen.clone());
    Router::new()
        // Suspended, resumed `ms` later from another thread.
        .route(
            Method::Post,
            "/later/:ms",
            Streaming(move |ctx: &mut Context| {
                let ms = ms(ctx);
                let s = ctx.suspend().expect("a streamed body suspends");
                assert!(ctx.suspend().is_none(), "the server's context is done with");
                let seen = s1.clone();
                later(ms, move || {
                    seen.written_at_resume
                        .store(WRITTEN.load(Ordering::Relaxed), Ordering::Relaxed);
                    s.resume(|ctx| take_body(ctx, &seen));
                });
            }),
        )
        // Resumed into a second check, suspended again, then resumed.
        .route(
            Method::Post,
            "/twice/:ms",
            Streaming(move |ctx: &mut Context| {
                let ms = ms(ctx);
                let s = ctx.suspend().unwrap();
                let seen = s2.clone();
                later(ms, move || {
                    s.resume(|ctx| {
                        let again = ctx.suspend().expect("suspended again");
                        later(ms, move || again.resume(|ctx| take_body(ctx, &seen)));
                    });
                });
            }),
        )
        // The resumed handler holds the reads `ms` before taking more.
        .route(
            Method::Post,
            "/held/:ms",
            Streaming(move |ctx: &mut Context| {
                let ms = ms(ctx);
                let s = ctx.suspend().unwrap();
                let seen = s3.clone();
                later(20, move || {
                    s.resume(|ctx| {
                        let reads = ctx.body_reads().expect("a streamed body");
                        reads.hold(true);
                        let released = Arc::new(AtomicBool::new(false));
                        let r2 = released.clone();
                        later(ms, move || {
                            r2.store(true, Ordering::Relaxed);
                            reads.hold(false);
                        });
                        let (mut off, mut n) = (0usize, 0usize);
                        ctx.on_body(move |ctx, ev| match ev {
                            BodyEvent::Chunk(b) => {
                                n += 1;
                                if n > 1 && !released.load(Ordering::Relaxed) {
                                    seen.while_held.fetch_add(1, Ordering::Relaxed);
                                }
                                off += b.len();
                            }
                            BodyEvent::TooLarge => {}
                            BodyEvent::End(_) => ctx.text(200, format!("ok {off}")),
                        });
                    });
                });
            }),
        )
        // The client goes while the request is suspended.
        .route(
            Method::Post,
            "/gone",
            Streaming(move |ctx: &mut Context| {
                let seen = s4.clone();
                let (tx, rx) = std::sync::mpsc::channel();
                let g = seen.clone();
                ctx.on_gone(move || {
                    g.gone.store(true, Ordering::Relaxed);
                    let _ = tx.send(());
                });
                let s: Suspended = ctx.suspend().unwrap();
                thread::spawn(move || {
                    let _ = rx.recv_timeout(Duration::from_secs(5));
                    s.resume(|ctx| {
                        ctx.on_body(move |_, ev| {
                            if matches!(ev, BodyEvent::End(_)) {
                                seen.gone_ended.store(true, Ordering::Relaxed);
                            }
                        });
                    });
                });
            }),
        )
        // Suspended and dropped: answered 500, its body read and dropped.
        .route(
            Method::Post,
            "/dropped",
            Streaming(|ctx: &mut Context| drop(ctx.suspend().unwrap())),
        )
        .get("/plain", |ctx: &mut Context| ctx.text(200, "plain"))
}

fn start(seen: &Arc<Seen>) -> Arc<Engine> {
    let e = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(500);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .threads(1)
                .serve(serve_with(HttpConfig::default(), app(seen))),
        )
        .client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    Arc::new(e)
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.set_nodelay(true).unwrap();
    s
}

fn read_resp(s: &mut TcpStream) -> (u16, String) {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = loop {
            match s.read(&mut b) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                r => break r.expect("read response head"),
            }
        };
        assert!(n > 0, "closed: {:?}", String::from_utf8_lossy(&head));
        head.push(b[0]);
    }
    let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
    let status = head[9..12].parse().unwrap();
    let len: usize = head
        .split("\r\n")
        .find_map(|l| {
            l.strip_prefix("content-length:")
                .map(|v| v.trim().parse().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0; len];
    s.read_exact(&mut body).unwrap();
    (status, String::from_utf8(body).unwrap())
}

fn post_head(path: &str, len: usize) -> String {
    format!("POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {len}\r\n\r\n")
}

#[test]
fn http1_a_suspended_streamed_body_reaches_the_resumed_handler_in_order() {
    let seen = Arc::new(Seen::default());
    let e = start(&seen);
    let a = e.local_addrs()[0];
    let mut s = connect(a);
    // Head and a small body in one write: all of it read before the suspension's hold.
    let mut req = post_head("/later/80", 3).into_bytes();
    req.extend_from_slice(&pattern(3));
    s.write_all(&req).unwrap();
    assert_eq!(read_resp(&mut s), (200, "ok 3".to_owned()));
    // A body sent in pieces, while suspended and after.
    let body = pattern(300_000);
    s.write_all(post_head("/later/100", body.len()).as_bytes())
        .unwrap();
    for c in body.chunks(7000) {
        s.write_all(c).unwrap();
    }
    assert_eq!(read_resp(&mut s), (200, "ok 300000".to_owned()));
    // Chunked, suspended twice.
    let mut req =
        b"POST /twice/40 HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    let body = pattern(50_000);
    for c in body.chunks(9000) {
        req.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
        req.extend_from_slice(c);
        req.extend_from_slice(b"\r\n");
    }
    req.extend_from_slice(b"0\r\n\r\n");
    s.write_all(&req).unwrap();
    assert_eq!(read_resp(&mut s), (200, "ok 50000".to_owned()));
    assert!(
        !seen.resuspended.load(Ordering::Relaxed),
        "a context taking its body is not suspended again"
    );
    stop(&e);
}

#[test]
fn http1_requests_pipelined_behind_a_suspended_streamed_one_wait_their_turn() {
    let seen = Arc::new(Seen::default());
    let e = start(&seen);
    let mut s = connect(e.local_addrs()[0]);
    let mut req = post_head("/later/100", 5).into_bytes();
    req.extend_from_slice(&pattern(5));
    req.extend_from_slice(b"GET /plain HTTP/1.1\r\nHost: x\r\n\r\n");
    req.extend_from_slice(post_head("/dropped", 4).as_bytes());
    req.extend_from_slice(b"abcd");
    req.extend_from_slice(b"GET /plain HTTP/1.1\r\nHost: x\r\n\r\n");
    s.write_all(&req).unwrap();
    assert_eq!(read_resp(&mut s), (200, "ok 5".to_owned()));
    assert_eq!(read_resp(&mut s), (200, "plain".to_owned()));
    assert_eq!(read_resp(&mut s).0, 500, "dropped unresumed");
    assert_eq!(
        read_resp(&mut s),
        (200, "plain".to_owned()),
        "its body was read"
    );
    stop(&e);
}

#[test]
fn http1_a_large_body_is_held_while_suspended_not_buffered() {
    let seen = Arc::new(Seen::default());
    let e = start(&seen);
    let s = connect(e.local_addrs()[0]);
    let total = 32 << 20;
    let mut w = s.try_clone().unwrap();
    WRITTEN.store(0, Ordering::Relaxed);
    let body = pattern(total);
    let writer = thread::spawn(move || {
        w.write_all(post_head("/later/300", total).as_bytes())
            .unwrap();
        for c in body.chunks(64 << 10) {
            w.write_all(c).unwrap();
            WRITTEN.fetch_add(c.len(), Ordering::Relaxed);
        }
    });
    let mut s = s;
    let t = Instant::now();
    assert_eq!(read_resp(&mut s), (200, format!("ok {total}")));
    writer.join().unwrap();
    assert!(t.elapsed() >= Duration::from_millis(250));
    // While suspended the client was paced by the socket buffers ...
    let at_resume = seen.written_at_resume.load(Ordering::Relaxed);
    assert!(at_resume < total, "the upload was paced: {at_resume}");
    // ... and the server kept what one read brought, no more.
    let first = seen.first.load(Ordering::Relaxed);
    assert!(first <= 256 << 10, "kept while suspended: {first}");
    stop(&e);
}

#[test]
fn http1_a_resumed_handler_holding_the_reads_keeps_them_held() {
    let seen = Arc::new(Seen::default());
    let e = start(&seen);
    let s = connect(e.local_addrs()[0]);
    let total = 8 << 20;
    let mut w = s.try_clone().unwrap();
    let body = pattern(total);
    let writer = thread::spawn(move || {
        w.write_all(post_head("/held/300", total).as_bytes())
            .unwrap();
        w.write_all(&body).unwrap();
    });
    let mut s = s;
    let t = Instant::now();
    assert_eq!(read_resp(&mut s), (200, format!("ok {total}")));
    writer.join().unwrap();
    assert!(t.elapsed() >= Duration::from_millis(300));
    assert_eq!(
        seen.while_held.load(Ordering::Relaxed),
        0,
        "nothing read while the handler held the reads"
    );
    stop(&e);
}

#[test]
fn http1_a_client_gone_while_suspended_runs_on_gone() {
    let seen = Arc::new(Seen::default());
    let e = start(&seen);
    let mut s = connect(e.local_addrs()[0]);
    s.write_all(post_head("/gone", 1000).as_bytes()).unwrap();
    s.write_all(&pattern(10)).unwrap();
    thread::sleep(Duration::from_millis(50));
    drop(s);
    let t = Instant::now();
    while !seen.gone.load(Ordering::Relaxed) && t.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(seen.gone.load(Ordering::Relaxed), "on_gone ran");
    thread::sleep(Duration::from_millis(100));
    assert!(
        !seen.gone_ended.load(Ordering::Relaxed),
        "the body never ended"
    );
    // The server goes on serving.
    let mut s = connect(e.local_addrs()[0]);
    s.write_all(b"GET /plain HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    assert_eq!(read_resp(&mut s), (200, "plain".to_owned()));
    stop(&e);
}

#[test]
fn h2_a_suspended_streamed_body_is_held_and_reaches_the_resumed_handler() {
    let seen = Arc::new(Seen::default());
    let mut cfg = HttpConfig::default();
    cfg.h2 = Some(H2Config::default());
    let e = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(500);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .threads(1)
                .serve(serve_with(cfg, app(&seen))),
        )
        .client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let e = Arc::new(e);
    let addr = e.local_addrs()[0];
    let c = H2Client::dial_blocking(&e, addr, None, H2Options::default()).unwrap();
    let total = 4 << 20;
    let send = |path: &str, n: usize| {
        let r = c
            .send(ClientRequest::post(
                &format!("http://{addr}{path}"),
                pattern(n),
            ))
            .wait()
            .unwrap();
        (r.status, String::from_utf8(r.body).unwrap())
    };
    assert_eq!(send("/later/200", total), (200, format!("ok {total}")));
    // At most the stream's window (1 MiB by default) was taken while suspended.
    let first = seen.first.load(Ordering::Relaxed);
    assert!(
        first <= (1 << 20) + (64 << 10),
        "kept while suspended: {first}"
    );
    assert_eq!(send("/twice/30", 100_000), (200, "ok 100000".to_owned()));
    assert_eq!(send("/later/0", 7), (200, "ok 7".to_owned()));
    assert_eq!(send("/dropped", 70_000).0, 500);
    // HTTP/2 holds by keeping the window: what the window allows still arrives.
    assert_eq!(send("/held/200", 3 << 20), (200, format!("ok {}", 3 << 20)));
    drop(c);
    stop(&e);
}
