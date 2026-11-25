//! Held response heads and asynchronous body filters (`Context::hold_response_head`,
//! `Context::add_body_filter`, ADR-128), over HTTP/1.1 and HTTP/2: a head held and resumed from
//! another thread, replaced by a local response, cut by its deadline; a body filtered elsewhere,
//! streamed or whole, held to its end, chained, compressed after, failing, through a file, and a
//! large body paced through it; the request's end heard after the filtered body.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::Read,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{
    BodyChunk, BodyFilter, BodyStream, Context, End, FileBody, FilterDone, H2Config, Headers,
    HeldHead, HttpConfig, Method, Request, Response, Router, Service,
    client::{Client, ClientRequest, ClientResponse},
    h2client::{H2Client, H2Options},
    middleware::{self, Compress, StreamCompress},
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

const T: Duration = Duration::from_secs(10);

/// What the handlers, hooks and filters saw, by path.
#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<String>>>);

impl Log {
    fn push(&self, s: String) {
        self.0.lock().unwrap().push(s);
    }

    fn end(&self, path: &'static str) -> impl FnOnce(End) + Send + 'static {
        let l = self.clone();
        move |e| l.push(format!("{path} {e:?}"))
    }

    fn of(&self, path: &str) -> Vec<String> {
        let pre = format!("{path} ");
        let v = self.0.lock().unwrap();
        v.iter().filter(|s| s.starts_with(&pre)).cloned().collect()
    }

    /// Waits for `want`, in any order.
    fn wait_set(&self, path: &str, want: &[&str]) {
        let mut want = want.to_vec();
        want.sort_unstable();
        let sorted = || {
            let mut v = self.of(path);
            v.sort();
            v
        };
        let t0 = Instant::now();
        while t0.elapsed() < T && sorted() != want {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(sorted(), want, "{path}");
    }

    fn wait(&self, path: &str, want: &[&str]) {
        let t0 = Instant::now();
        while t0.elapsed() < T && self.of(path) != want {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(self.of(path), want, "{path}");
    }
}

type Work = dyn FnMut(BodyChunk) -> Result<(Vec<u8>, Headers), ()> + Send;

/// A body filter whose calls are answered from a thread of their own, a little later, by `work`.
struct Later {
    work: Arc<Mutex<Box<Work>>>,
    log: Log,
    path: &'static str,
}

impl Later {
    fn new(
        log: &Log,
        path: &'static str,
        work: impl FnMut(BodyChunk) -> Result<(Vec<u8>, Headers), ()> + Send + 'static,
    ) -> Later {
        Later {
            work: Arc::new(Mutex::new(Box::new(work))),
            log: log.clone(),
            path,
        }
    }
}

impl BodyFilter for Later {
    fn filter(&mut self, chunk: BodyChunk, done: FilterDone) {
        let work = self.work.clone();
        if chunk.end {
            self.log.push(format!("{} last", self.path));
        }
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(2));
            let r = (work.lock().unwrap())(chunk);
            match r {
                Ok((data, trailers)) => done.done(data, trailers),
                Err(()) => done.fail(),
            }
        });
    }

    fn abort(&mut self) {
        self.log.push(format!("{} abort", self.path));
    }
}

/// Upper-cases each part; at the end, adds `x-calls` to the trailers.
fn upper(log: &Log, path: &'static str) -> Later {
    let mut calls = 0;
    Later::new(log, path, move |c| {
        calls += 1;
        let mut t = c.trailers;
        if c.end {
            t.set("x-calls", calls.to_string());
        }
        Ok((c.data.to_ascii_uppercase(), t))
    })
}

/// Holds the whole body to its end, then sends it between `<` and `>` (as the Proxy-Wasm Go
/// SDK's `http_body` example holds and replaces it).
fn hold_all(log: &Log, path: &'static str) -> Later {
    let mut held = Vec::new();
    Later::new(log, path, move |c| {
        held.extend_from_slice(&c.data);
        if !c.end {
            return Ok((Vec::new(), Headers::new()));
        }
        let mut out = b"<".to_vec();
        out.append(&mut held);
        out.push(b'>');
        Ok((out, c.trailers))
    })
}

/// Hands `h` to a thread that resumes it a little later, `x-held` set.
fn resume_later(h: HeldHead, _: &Request) {
    thread::spawn(move || {
        let mut h = h;
        thread::sleep(Duration::from_millis(20));
        let n = h.headers().get("x-order").unwrap_or("").to_owned();
        let v = format!("{}:{n}", h.status());
        h.headers_mut().set("x-held", v);
        h.resume();
    });
}

/// Writes `parts` from another thread, a little apart, then finishes (with `x-in: 1` as a
/// trailer when `trailers`).
fn write_later(s: BodyStream, parts: &'static [&'static str], trailers: bool) {
    thread::spawn(move || {
        for p in parts {
            if s.write(p.as_bytes()).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(3));
        }
        if trailers {
            let mut t = Headers::new();
            t.set("x-in", "1");
            s.finish_with_trailers(t);
        } else {
            s.finish();
        }
    });
}

/// `BIG` bytes, paced by the stream's queued bytes, through a filter that answers later.
const BIG: usize = 3 << 20;

fn big_byte(i: usize) -> u8 {
    b'a' + (i % 26) as u8
}

fn write_big(s: BodyStream) {
    thread::spawn(move || {
        let mut at = 0;
        while at < BIG {
            while s.queued_bytes() > 512 << 10 {
                let (tx, rx) = std::sync::mpsc::channel();
                s.on_drain(move || {
                    let _ = tx.send(());
                });
                if rx.recv_timeout(T).is_err() {
                    return;
                }
            }
            let n = (BIG - at).min(16 << 10);
            let piece: Vec<u8> = (at..at + n).map(big_byte).collect();
            if s.write(&piece).is_err() {
                return;
            }
            at += n;
        }
        s.finish();
    });
}

fn file_body(content: &[u8]) -> FileBody {
    let dir = std::env::temp_dir().join(format!("akio-response-hooks-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let p = dir.join(format!("f{n}"));
    std::fs::write(&p, content).unwrap();
    let f = std::fs::File::open(&p).unwrap();
    let _ = std::fs::remove_file(&p);
    FileBody::new(Arc::new(f), 0, content.len() as u64)
}

fn app(log: &Log) -> impl Service {
    let l = log.clone();
    let compress = {
        let mut c = Compress::default();
        c.min_bytes = 1;
        c.stream = Some(StreamCompress::default());
        c
    };
    let gz = Router::new()
        .get("/gzip", {
            let l = l.clone();
            move |ctx: &mut Context| {
                ctx.add_body_filter(upper(&l, "/gzip"));
                ctx.bytes(200, "text/plain", b"compressible ".repeat(64));
            }
        })
        .layer(middleware::compress(compress));
    let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13) = (
        l.clone(),
        l.clone(),
        l.clone(),
        l.clone(),
        l.clone(),
        l.clone(),
        l.clone(),
        l.clone(),
        l.clone(),
        l.clone(),
        l.clone(),
        l.clone(),
        l,
    );
    let router = Router::new()
        .get("/hold/whole", move |ctx: &mut Context| {
            ctx.on_end(l1.end("/hold/whole"));
            ctx.add_response_filter(|r: &mut Response, _: &Request| {
                r.headers.set("x-order", "filter");
            });
            ctx.hold_response_head(T, resume_later);
            ctx.add_outer_response_filter(|r: &mut Response, _: &Request| {
                let held = r.headers.get("x-held").unwrap_or("-").to_owned();
                r.headers.set("x-outer", held);
            });
            ctx.text(200, "whole");
        })
        .get("/hold/twice", move |ctx: &mut Context| {
            ctx.hold_response_head(T, |mut h: HeldHead, _: &Request| {
                assert_eq!(h.body(), Some(&b"twice"[..]));
                h.headers_mut().set("x-first", "1");
                h.resume();
            });
            ctx.hold_response_head(T, |h: HeldHead, _: &Request| {
                assert_eq!(h.headers().get("x-first"), Some("1"));
                resume_later(h, &Request::new(Method::Get, "/"));
            });
            ctx.text(200, "twice");
        })
        .get("/hold/stream", move |ctx: &mut Context| {
            ctx.on_end(l2.end("/hold/stream"));
            ctx.hold_response_head(T, resume_later);
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            // Written and finished while the head is held.
            s.write(b"a").unwrap();
            s.write(b"b").unwrap();
            assert!(s.queued_bytes() >= 2);
            s.finish();
        })
        .get("/hold/local", move |ctx: &mut Context| {
            ctx.on_end(l3.end("/hold/local"));
            ctx.hold_response_head(T, |h: HeldHead, _: &Request| {
                thread::spawn(move || h.respond(Response::text(403, "denied")));
            });
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            let l = l3.clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(100));
                l.push(format!("/hold/local write {}", s.write(b"x").is_ok()));
            });
        })
        .get("/hold/timeout", move |ctx: &mut Context| {
            ctx.on_end(l4.end("/hold/timeout"));
            let l = l4.clone();
            ctx.hold_response_head(
                Duration::from_millis(50),
                move |h: HeldHead, _: &Request| {
                    thread::spawn(move || {
                        thread::sleep(Duration::from_millis(300));
                        l.push(format!("/hold/timeout live {}", h.is_live()));
                        h.resume();
                    });
                },
            );
            ctx.text(200, "late");
        })
        .get("/filter/stream", move |ctx: &mut Context| {
            ctx.on_end(l5.end("/filter/stream"));
            ctx.add_body_filter(upper(&l5, "/filter/stream"));
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            write_later(s, &["ab", "cd", "ef"], true);
        })
        .get("/filter/whole", move |ctx: &mut Context| {
            ctx.on_end(l6.end("/filter/whole"));
            ctx.add_body_filter(upper(&l6, "/filter/whole"));
            ctx.text(200, "hello");
        })
        .get("/filter/held", move |ctx: &mut Context| {
            ctx.on_end(l7.end("/filter/held"));
            ctx.hold_response_head(T, resume_later);
            ctx.add_body_filter(hold_all(&l7, "/filter/held"));
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            write_later(s, &["x", "y", "z"], false);
        })
        .get("/filter/chain", move |ctx: &mut Context| {
            ctx.add_body_filter(upper(&l8, "/filter/chain"));
            ctx.add_body_filter(hold_all(&l8, "/filter/chain"));
            ctx.text(200, "chained");
        })
        .get("/filter/fail", move |ctx: &mut Context| {
            ctx.on_end(l9.end("/filter/fail"));
            let mut n = 0;
            ctx.add_body_filter(Later::new(&l9, "/filter/fail", move |c| {
                n += 1;
                if n == 2 {
                    return Err(());
                }
                Ok((c.data, c.trailers))
            }));
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            let l = l9.clone();
            thread::spawn(move || {
                for _ in 0..200 {
                    if s.write(b"0123456789").is_err() {
                        l.push("/filter/fail write failed".into());
                        return;
                    }
                    thread::sleep(Duration::from_millis(2));
                }
                s.finish();
            });
        })
        .get("/filter/head", move |ctx: &mut Context| {
            ctx.add_body_filter(upper(&l10, "/filter/head"));
            ctx.text(200, "head");
        })
        .get("/filter/big", move |ctx: &mut Context| {
            ctx.on_end(l11.end("/filter/big"));
            ctx.add_body_filter(Later::new(&l11, "/filter/big", |c| {
                Ok((c.data, c.trailers))
            }));
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            write_big(s);
        })
        .get("/filter/file", move |ctx: &mut Context| {
            ctx.on_end(l12.end("/filter/file"));
            ctx.add_body_filter(upper(&l12, "/filter/file"));
            let content: Vec<u8> = (0..200_000).map(big_byte).collect();
            let mut r = Response::new(200);
            r.headers.set("Content-Type", "text/plain");
            r.file = Some(file_body(&content));
            ctx.respond(r);
        })
        .get("/filter/nobody", move |ctx: &mut Context| {
            ctx.add_body_filter(upper(&l13, "/filter/nobody"));
            ctx.respond(Response::new(204));
        });
    let router = router.nest("/c", gz);
    move |ctx: &mut Context| router.call(ctx)
}

struct Server {
    e: Arc<Engine>,
    log: Log,
}

fn start(h2: bool) -> Server {
    let log = Log::default();
    let mut cfg = HttpConfig::default();
    if h2 {
        cfg.h2 = Some(H2Config::default());
    }
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
                    .serve(serve_with(cfg, app(&log))),
            )
            .client_threads(1)
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    Server { e, log }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.e.shutdown();
        self.e.wait();
    }
}

/// Sends requests over one protocol.
enum Proto {
    H1(Client, String),
    H2(H2Client, String),
}

impl Proto {
    fn new(s: &Server, h2: bool) -> Proto {
        let addr = s.e.local_addrs()[0];
        let base = format!("http://{addr}");
        if h2 {
            let c = H2Client::dial_blocking(&s.e, addr, None, H2Options::default()).unwrap();
            Proto::H2(c, base)
        } else {
            Proto::H1(Client::new(s.e.clone()), base)
        }
    }

    fn req(&self, method: Method, path: &str, gzip: bool) -> Result<ClientResponse, String> {
        let url = |b: &str| format!("{b}{path}");
        let mk = |b: &str| {
            let mut r = ClientRequest::new(method.clone(), &url(b)).timeout(T);
            if gzip {
                r = r.header("Accept-Encoding", "gzip");
            }
            r
        };
        match self {
            Proto::H1(c, b) => c.send(mk(b)).wait().map_err(|e| format!("{e:?}")),
            Proto::H2(c, b) => c.send(mk(b)).wait().map_err(|e| format!("{e:?}")),
        }
    }

    fn get(&self, path: &str) -> Result<ClientResponse, String> {
        self.req(Method::Get, path, false)
    }
}

fn body(r: &ClientResponse) -> &str {
    std::str::from_utf8(&r.body).unwrap()
}

fn h(r: &ClientResponse, name: &str) -> Option<String> {
    r.headers.get(name).map(str::to_owned)
}

fn held_heads(h2: bool) {
    let s = start(h2);
    let p = Proto::new(&s, h2);
    let log = &s.log;

    let r = p.get("/hold/whole").unwrap();
    assert_eq!((r.status, body(&r)), (200, "whole"));
    assert_eq!(h(&r, "x-held").as_deref(), Some("200:filter"));
    assert_eq!(
        h(&r, "x-outer").as_deref(),
        Some("200:filter"),
        "outer filters after"
    );
    assert_eq!(h(&r, "content-length").as_deref(), Some("5"));
    log.wait("/hold/whole", &["/hold/whole Sent"]);

    let r = p.get("/hold/twice").unwrap();
    assert_eq!((r.status, body(&r)), (200, "twice"));
    assert_eq!(h(&r, "x-first").as_deref(), Some("1"));
    assert_eq!(h(&r, "x-held").as_deref(), Some("200:"));

    let r = p.get("/hold/stream").unwrap();
    assert_eq!((r.status, body(&r)), (200, "ab"));
    assert_eq!(h(&r, "x-held").as_deref(), Some("200:"));
    log.wait("/hold/stream", &["/hold/stream Sent"]);

    let r = p.get("/hold/local").unwrap();
    assert_eq!((r.status, body(&r)), (403, "denied"));
    log.wait(
        "/hold/local",
        &["/hold/local Sent", "/hold/local write false"],
    );

    let r = p.get("/hold/timeout");
    assert!(r.is_err(), "cut at its deadline: {r:?}");
    // The HTTP/1 client tries an idempotent request cut short once more, on a new connection.
    let t0 = Instant::now();
    loop {
        let seen = log.of("/hold/timeout");
        let n = seen.len() / 2;
        let want: Vec<&str> = ["/hold/timeout Gone"]
            .repeat(n)
            .into_iter()
            .chain(["/hold/timeout live false"].repeat(n))
            .collect();
        let mut sorted = seen.clone();
        sorted.sort();
        if n >= 1 && sorted == want {
            break;
        }
        assert!(t0.elapsed() < T, "/hold/timeout: {seen:?}");
        thread::sleep(Duration::from_millis(5));
    }

    // The connection still serves (HTTP/2: the other streams went on).
    let r = p.get("/hold/whole").unwrap();
    assert_eq!(body(&r), "whole");
}

fn body_filters(h2: bool) {
    let s = start(h2);
    let p = Proto::new(&s, h2);
    let log = &s.log;

    let r = p.get("/filter/stream").unwrap();
    assert_eq!((r.status, body(&r)), (200, "ABCDEF"));
    assert_eq!(r.trailers.get("x-in"), Some("1"));
    assert!(r.trailers.get("x-calls").is_some());
    log.wait(
        "/filter/stream",
        &["/filter/stream last", "/filter/stream Sent"],
    );

    let r = p.get("/filter/whole").unwrap();
    assert_eq!((r.status, body(&r)), (200, "HELLO"));
    assert_eq!(h(&r, "content-length"), None, "goes as a stream");
    assert_eq!(r.trailers.get("x-calls"), Some("1"), "one last call");
    if !h2 {
        assert_eq!(h(&r, "transfer-encoding").as_deref(), Some("chunked"));
    }
    log.wait(
        "/filter/whole",
        &["/filter/whole last", "/filter/whole Sent"],
    );

    let r = p.get("/filter/held").unwrap();
    assert_eq!((r.status, body(&r)), (200, "<xyz>"));
    assert_eq!(h(&r, "x-held").as_deref(), Some("200:"));
    log.wait("/filter/held", &["/filter/held last", "/filter/held Sent"]);

    let r = p.get("/filter/chain").unwrap();
    assert_eq!(body(&r), "<CHAINED>", "in the order they were added");
    assert_eq!(r.trailers.get("x-calls"), Some("1"));

    let r = p.get("/filter/fail");
    assert!(r.is_err(), "cut by the failing call: {r:?}");
    // The cut ends the request, then aborts the filter; the writer fails meanwhile.
    log.wait_set(
        "/filter/fail",
        &[
            "/filter/fail Gone",
            "/filter/fail abort",
            "/filter/fail write failed",
        ],
    );

    let r = p.req(Method::Head, "/filter/head", false).unwrap();
    assert_eq!((r.status, body(&r)), (200, ""));
    assert_eq!(h(&r, "content-length").as_deref(), Some("4"));
    let r = p.get("/filter/nobody").unwrap();
    assert_eq!(r.status, 204);
    assert!(log.of("/filter/head").is_empty() && log.of("/filter/nobody").is_empty());

    let r = p.get("/filter/big").unwrap();
    assert_eq!(r.body.len(), BIG);
    assert!(r.body.iter().enumerate().all(|(i, b)| *b == big_byte(i)));
    log.wait("/filter/big", &["/filter/big last", "/filter/big Sent"]);

    let r = p.get("/filter/file").unwrap();
    assert_eq!(r.body.len(), 200_000);
    assert!(
        r.body
            .iter()
            .enumerate()
            .all(|(i, b)| *b == big_byte(i).to_ascii_uppercase())
    );
    log.wait("/filter/file", &["/filter/file last", "/filter/file Sent"]);

    // The coding applies to the filter's output: the filter saw the identity body.
    let r = p.req(Method::Get, "/c/gzip", true).unwrap();
    assert_eq!(h(&r, "content-encoding").as_deref(), Some("gzip"));
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(&r.body[..])
        .read_to_end(&mut out)
        .unwrap();
    assert_eq!(out, b"COMPRESSIBLE ".repeat(64));
    let r = p.get("/c/gzip").unwrap();
    assert_eq!(r.body, b"COMPRESSIBLE ".repeat(64));

    // Another request on the same client still goes.
    assert_eq!(body(&p.get("/filter/whole").unwrap()), "HELLO");
}

#[test]
fn http1_held_heads() {
    held_heads(false);
}

#[test]
fn http2_held_heads() {
    held_heads(true);
}

#[test]
fn http1_body_filters() {
    body_filters(false);
}

#[test]
fn http2_body_filters() {
    body_filters(true);
}
