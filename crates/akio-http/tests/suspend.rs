//! Requests suspended and resumed (`Context::suspend`, `Context::suspend_to_pool`, ADR-109): the
//! request goes on where it stopped, from the pool or any thread, with what the context held;
//! a request suspended again; HTTP/1.1 answers stay in request order; an unresumed or unanswered request gets 500; a full
//! pool 503; a streamed body cannot be suspended.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    thread,
    time::Duration,
};

use akio::{Backend, Config, Engine, Listener, PoolConfig, UringConfig};
use akio_http::{
    BodyMode, Context, H2Config, HttpConfig, Request, Response, Router, Service,
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

fn start<S: Service>(app: S, cfg: HttpConfig, pool: Option<PoolConfig>) -> Arc<Engine> {
    let mut b = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(500);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .threads(1)
                .serve(serve_with(cfg, app)),
        )
        .client_threads(1);
    if let Some(p) = pool {
        b = b.pool(p);
    }
    let e = Arc::new(b.build().unwrap());
    e.start().unwrap();
    e
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.set_nodelay(true).unwrap();
    s
}

/// Reads one Content-Length framed response: its status, head and body.
fn read_resp(s: &mut TcpStream) -> (u16, String, String) {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = s.read(&mut b).expect("read response head");
        assert!(
            n > 0,
            "closed mid-head: {:?}",
            String::from_utf8_lossy(&head)
        );
        head.push(b[0]);
    }
    let head = String::from_utf8(head).unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    let len: usize = head
        .split("\r\n")
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0; len];
    s.read_exact(&mut body).unwrap();
    (status, head, String::from_utf8(body).unwrap())
}

fn on_pool_thread() -> bool {
    thread::current().name() == Some("akio-pool")
}

fn ms(ctx: &Context) -> u64 {
    ctx.param("ms").unwrap().parse().unwrap()
}

/// Routes that suspend: to the pool, to a thread of their own, never resumed, resumed without
/// an answer; and one answered inline.
fn app() -> Router {
    Router::new()
        .get("/inline/:ms", |ctx: &mut Context| {
            let body = format!("inline {}", ms(ctx));
            ctx.text(200, body);
        })
        .get("/pool/:ms", |ctx: &mut Context| {
            let ms = ms(ctx);
            // What the context holds goes with it: locals, filters, extra headers.
            ctx.set_local("who", "alice");
            ctx.add_response_header("x-before", "1");
            ctx.add_response_filter(|resp: &mut Response, _: &Request| {
                resp.headers.set("x-filter", "1");
            });
            // False when the pool is full: answered 503 then.
            let _ = ctx.suspend_to_pool(move |s| {
                assert!(on_pool_thread());
                assert_eq!(s.req().path(), format!("/pool/{ms}"));
                thread::sleep(Duration::from_millis(ms));
                s.resume(|ctx| {
                    // A resumed request may be suspended again (a second check).
                    let again = ctx.suspend().unwrap();
                    thread::spawn(move || {
                        again.resume(|ctx| {
                            let body = format!("pool {ms} {}", ctx.local("who").unwrap());
                            ctx.text(200, body);
                        });
                    });
                });
            });
            // The server's context reads as detached: no 500 from it.
            assert!(ctx.suspend().is_none());
        })
        .get("/thread/:ms", |ctx: &mut Context| {
            let ms = ms(ctx);
            let s = ctx.suspend().unwrap();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(ms));
                s.resume(|ctx| {
                    let body = format!("thread {}", ctx.param("ms").unwrap());
                    ctx.text(200, body);
                });
            });
        })
        .get("/dropped", |ctx: &mut Context| {
            let s = ctx.suspend().unwrap();
            thread::spawn(move || drop(s));
        })
        .get("/unanswered", |ctx: &mut Context| {
            let s = ctx.suspend().unwrap();
            thread::spawn(move || s.resume(|_| {}));
        })
        .get("/detached", |ctx: &mut Context| {
            let s = ctx.suspend().unwrap();
            thread::spawn(move || {
                s.resume(|ctx| {
                    let d = ctx.detach().unwrap();
                    thread::spawn(move || d.respond(Response::text(200, "detached later")));
                });
            });
        })
        .post("/echo", |ctx: &mut Context| {
            assert!(ctx.suspend_to_pool(|s| {
                s.resume(|ctx| {
                    let body = format!("echo {}", String::from_utf8_lossy(ctx.body()));
                    ctx.text(200, body);
                });
            }));
        })
        .get("/answered", |ctx: &mut Context| {
            ctx.text(200, "answered");
            assert!(ctx.suspend().is_none(), "suspended after its answer");
        })
}

/// Pipelines `raw` requests on one connection in one write, and reads `n` answers.
fn pipeline(addr: SocketAddr, paths: &[&str]) -> Vec<(u16, String, String)> {
    let mut s = connect(addr);
    let raw: String = paths
        .iter()
        .map(|p| format!("GET {p} HTTP/1.1\r\nHost: x\r\n\r\n"))
        .collect();
    s.write_all(raw.as_bytes()).unwrap();
    paths.iter().map(|_| read_resp(&mut s)).collect()
}

#[test]
fn http1_suspended_requests_go_on_in_request_order() {
    let paths = [
        "/pool/150",
        "/inline/1",
        "/thread/80",
        "/inline/2",
        "/pool/0",
        "/detached",
        "/thread/0",
        "/answered",
    ];
    let want = [
        "pool 150 alice",
        "inline 1",
        "thread 80",
        "inline 2",
        "pool 0 alice",
        "detached later",
        "thread 0",
        "answered",
    ];
    for handlers_on_logical_pool in [false, true] {
        let mut cfg = HttpConfig::default();
        cfg.handlers_on_logical_pool = handlers_on_logical_pool;
        let e = start(app(), cfg, None);
        for _ in 0..3 {
            let got = pipeline(e.local_addrs()[0], &paths);
            let bodies: Vec<&str> = got.iter().map(|(_, _, b)| b.as_str()).collect();
            assert_eq!(
                bodies, want,
                "handlers_on_logical_pool={handlers_on_logical_pool}"
            );
            let (status, head, _) = &got[0];
            assert_eq!(*status, 200);
            let head = head.to_ascii_lowercase();
            assert!(
                head.contains("x-before: 1") && head.contains("x-filter: 1"),
                "{head}"
            );
        }
        stop(&e);
    }
}

#[test]
fn http1_unresumed_and_unanswered_requests_get_500() {
    let e = start(app(), HttpConfig::default(), None);
    let got = pipeline(
        e.local_addrs()[0],
        &["/dropped", "/unanswered", "/inline/7"],
    );
    assert_eq!(got[0].0, 500);
    assert_eq!(got[1].0, 500);
    assert_eq!((got[2].0, got[2].2.as_str()), (200, "inline 7"));
    stop(&e);
}

#[test]
fn http1_a_body_read_whole_goes_with_the_request() {
    let e = start(app(), HttpConfig::default(), None);
    let mut s = connect(e.local_addrs()[0]);
    s.write_all(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
        .unwrap();
    assert_eq!(read_resp(&mut s).2, "echo hello");
    stop(&e);
}

#[test]
fn http1_a_full_pool_answers_503() {
    let mut pool = PoolConfig::default();
    pool.min_threads = 1;
    pool.max_threads = 1;
    pool.queue_capacity = 1;
    let e = start(app(), HttpConfig::default(), Some(pool));
    let got = pipeline(
        e.local_addrs()[0],
        &["/pool/300", "/pool/1", "/pool/2", "/pool/3", "/inline/4"],
    );
    assert_eq!(got[0].2, "pool 300 alice");
    for (i, (status, head, body)) in got.iter().enumerate().skip(1).take(3) {
        match status {
            200 => assert_eq!(*body, format!("pool {i} alice")),
            503 => {
                assert_eq!(body, "server busy");
                assert!(head.to_ascii_lowercase().contains("retry-after: 1"));
            }
            s => panic!("status {s}"),
        }
    }
    assert!(
        got.iter().filter(|(s, _, _)| *s == 503).count() >= 2,
        "{got:?}"
    );
    assert_eq!(got[4].2, "inline 4");
    stop(&e);
}

/// A service that takes bodies as they arrive, and tries to suspend.
struct Streams;

impl Service for Streams {
    fn call(&self, ctx: &mut Context) {
        let suspended = ctx.suspend().is_some();
        ctx.on_body(move |ctx, ev| {
            if matches!(ev, akio_http::BodyEvent::End(_)) {
                ctx.text(200, format!("suspended={suspended}"));
            }
        });
    }

    fn body_mode(&self, _req: &Request) -> BodyMode {
        BodyMode::Stream
    }

    fn streams_bodies(&self) -> bool {
        true
    }
}

#[test]
fn a_streamed_body_cannot_be_suspended() {
    let e = start(Streams, HttpConfig::default(), None);
    let mut s = connect(e.local_addrs()[0]);
    s.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc")
        .unwrap();
    assert_eq!(read_resp(&mut s).2, "suspended=false");
    stop(&e);
}

#[test]
fn h2_suspended_streams_go_on() {
    let mut cfg = HttpConfig::default();
    cfg.h2 = Some(H2Config::default());
    let e = start(app(), cfg, None);
    let addr = e.local_addrs()[0];
    let c = H2Client::dial_blocking(&e, addr, None, H2Options::default()).unwrap();
    let paths = [
        "/pool/100",
        "/thread/50",
        "/inline/3",
        "/dropped",
        "/pool/0",
    ];
    let futs: Vec<_> = paths
        .iter()
        .map(|p| c.send(ClientRequest::get(&format!("http://{addr}{p}"))))
        .collect();
    let got: Vec<(u16, String)> = futs
        .into_iter()
        .map(|f| {
            let r = f.wait().unwrap();
            (r.status, String::from_utf8(r.body).unwrap())
        })
        .collect();
    assert_eq!(got[0], (200, "pool 100 alice".to_owned()));
    assert_eq!(got[1], (200, "thread 50".to_owned()));
    assert_eq!(got[2], (200, "inline 3".to_owned()));
    assert_eq!(got[3].0, 500);
    assert_eq!(got[4], (200, "pool 0 alice".to_owned()));
    stop(&e);
}
