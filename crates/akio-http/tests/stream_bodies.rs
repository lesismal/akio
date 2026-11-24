//! Bodies streamed with linked backpressure (ADR-101): the HTTP/1 client's request bodies
//! written as they are produced and responses delivered as they arrive, and the server's hold on
//! a streamed request body's reads and drain notice of a streamed response, on HTTP/1.1 and
//! HTTP/2.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{
    BodyEvent, Context, Headers, HttpConfig, Router, Streaming,
    client::{
        Client, ClientError, ClientOptions, ClientRequest, ClientResponse, RequestBody,
        ResponseBody, ResponseHandler, ResponseHead, StreamedBody,
    },
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

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 13 % 251) as u8).collect()
}

/// Drain notices the paced responses waited for (every test's server).
static DRAINS: AtomicUsize = AtomicUsize::new(0);

/// Streams `n` bytes, pausing while more than 512 KiB are queued until the stream drains.
fn paced(ctx: &mut Context) {
    let n: usize = ctx.param("n").unwrap().parse().unwrap();
    let s = ctx.stream_response(200, Headers::new()).unwrap();
    thread::spawn(move || {
        let data = pattern(n);
        let (tx, rx) = mpsc::channel::<()>();
        let mut most = 0;
        for piece in data.chunks(64 << 10) {
            while s.queued_bytes() > 512 << 10 {
                let tx = tx.clone();
                s.on_drain(move || {
                    DRAINS.fetch_add(1, Ordering::Relaxed);
                    let _ = tx.send(());
                });
                rx.recv_timeout(Duration::from_secs(10))
                    .expect("the stream drains");
            }
            if s.write(piece).is_err() {
                return;
            }
            most = most.max(s.queued_bytes());
        }
        // Writes stop past 512 KiB: what is queued stays near it.
        assert!(most <= (512 << 10) + (64 << 10), "queued {most}");
        s.finish();
    });
}

/// Holds the body's reads at its first chunk for `ms`, then answers `total,taken-while-held`.
fn held(ctx: &mut Context) {
    let ms: u64 = ctx.param("ms").unwrap().parse().unwrap();
    let reads = ctx.body_reads().expect("a streamed body");
    let total = Arc::new(AtomicUsize::new(0));
    let at_release = Arc::new(AtomicUsize::new(usize::MAX));
    let mut first = true;
    ctx.on_body(move |ctx, ev| match ev {
        BodyEvent::Chunk(b) => {
            total.fetch_add(b.len(), Ordering::Relaxed);
            if std::mem::take(&mut first) {
                reads.hold(true);
                let (reads, total, at) = (reads.clone(), total.clone(), at_release.clone());
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(ms));
                    at.store(total.load(Ordering::Relaxed), Ordering::Relaxed);
                    reads.hold(false);
                });
            }
        }
        BodyEvent::End(_) => {
            let t = total.load(Ordering::Relaxed);
            ctx.text(200, format!("{t},{}", at_release.load(Ordering::Relaxed)));
        }
    });
}

fn app() -> Router {
    Router::new()
        .post(
            "/sum",
            Streaming(|ctx: &mut Context| {
                let mut sum = 0u64;
                let mut hash = 0u64;
                ctx.on_body(move |ctx, ev| match ev {
                    BodyEvent::Chunk(b) => {
                        for &x in b {
                            hash = hash.wrapping_mul(31).wrapping_add(u64::from(x));
                        }
                        sum += b.len() as u64;
                    }
                    BodyEvent::End(t) => {
                        let tr = t.get("x-sum").unwrap_or("-").to_owned();
                        ctx.text(200, format!("{sum},{hash},{tr}"));
                    }
                });
            }),
        )
        .post(
            "/early",
            Streaming(|ctx: &mut Context| ctx.text(413, "too large")),
        )
        .post("/held/:ms", Streaming(held))
        .get("/paced/:n", paced)
        .get("/big/:n", |ctx: &mut Context| {
            let n: usize = ctx.param("n").unwrap().parse().unwrap();
            ctx.bytes(200, "application/octet-stream", pattern(n));
        })
        .get("/trailers", |ctx: &mut Context| {
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            s.write(b"ab").unwrap();
            s.write(b"cd").unwrap();
            let mut t = Headers::new();
            t.append("x-t", "1");
            s.finish_with_trailers(t);
        })
        .get("/hello", |ctx: &mut Context| ctx.text(200, "hello"))
}

fn start(cfg: HttpConfig) -> Arc<Engine> {
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
                    .serve(serve_with(cfg, app())),
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

fn base(e: &Engine) -> String {
    format!("http://{}", e.local_addrs()[0])
}

fn hash(b: &[u8]) -> u64 {
    b.iter()
        .fold(0u64, |h, &x| h.wrapping_mul(31).wrapping_add(u64::from(x)))
}

/// Writes `data` in 64 KiB pieces, pausing while more than 256 KiB are queued.
fn produce(body: &RequestBody, data: &[u8]) -> akio_core::Result<()> {
    let (tx, rx) = mpsc::channel::<()>();
    for piece in data.chunks(64 << 10) {
        while body.queued_bytes() > 256 << 10 {
            let tx = tx.clone();
            body.on_drain(move || {
                let _ = tx.send(());
            });
            rx.recv_timeout(Duration::from_secs(10))
                .expect("the request body drains");
        }
        body.write(piece)?;
    }
    Ok(())
}

type Done = mpsc::Receiver<Result<ClientResponse, ClientError>>;

/// Sends `req` streamed: `write` runs on a thread of its own with the body.
fn streamed(
    c: &Client,
    req: ClientRequest,
    write: impl FnOnce(RequestBody) + Send + 'static,
) -> Done {
    let (tx, rx) = mpsc::channel();
    c.request_streamed(
        req,
        move |body| {
            thread::spawn(move || write(body));
        },
        move |r| {
            let _ = tx.send(r);
        },
    );
    rx
}

fn wait(rx: &Done) -> Result<ClientResponse, ClientError> {
    rx.recv_timeout(Duration::from_secs(20)).expect("an answer")
}

#[test]
fn request_bodies_written_as_produced_chunked_or_with_a_length() {
    let e = start(HttpConfig::default());
    let c = Client::new(e.clone());
    let url = format!("{}/sum", base(&e));
    let data = Arc::new(pattern(4 << 20));
    // Chunked, with a trailer.
    let d = data.clone();
    let rx = streamed(&c, ClientRequest::post(&url, Vec::new()), move |body| {
        produce(&body, &d).unwrap();
        let mut t = Headers::new();
        t.append("x-sum", "yes");
        body.finish_with_trailers(t).unwrap();
    });
    let r = wait(&rx).unwrap();
    assert_eq!(
        String::from_utf8(r.body).unwrap(),
        format!("{},{},yes", data.len(), hash(&data))
    );
    // A `Content-Length` body, on the connection the first one left in the pool.
    let d = data.clone();
    let req = ClientRequest::post(&url, Vec::new()).streamed(Some(data.len() as u64));
    assert_eq!(req.streamed, Some(StreamedBody::Length(data.len() as u64)));
    let rx = streamed(&c, req, move |body| {
        produce(&body, &d).unwrap();
        body.finish().unwrap();
    });
    let r = wait(&rx).unwrap();
    assert_eq!(
        String::from_utf8(r.body).unwrap(),
        format!("{},{},-", data.len(), hash(&data))
    );
    // Too many bytes for the length: the write fails, and so does the request.
    let req = ClientRequest::post(&url, Vec::new()).streamed(Some(10));
    let rx = streamed(&c, req, |body| {
        body.write(b"0123456789").unwrap();
        assert!(body.write(b"x").is_err());
        assert!(body.finish().is_err());
    });
    assert!(wait(&rx).is_err());
    // Too few: `finish` fails, and so does the request.
    let req = ClientRequest::post(&url, Vec::new()).streamed(Some(10));
    let rx = streamed(&c, req, |body| {
        body.write(b"01234").unwrap();
        assert!(body.finish().is_err());
    });
    assert!(wait(&rx).is_err());
    // Dropped unfinished: the request fails.
    let rx = streamed(&c, ClientRequest::post(&url, Vec::new()), |body| {
        body.write(b"part").unwrap();
        drop(body);
    });
    assert!(matches!(
        wait(&rx),
        Err(ClientError::Closed | ClientError::Io(_))
    ));
    // The client still works.
    let r = c
        .send(ClientRequest::get(&format!("{}/hello", base(&e))))
        .wait()
        .unwrap();
    assert_eq!(r.body, b"hello");
    stop(&e);
}

#[test]
fn a_response_before_the_body_is_finished() {
    let e = start(HttpConfig::default());
    let c = Client::new(e.clone());
    let (wtx, wrx) = mpsc::channel();
    let rx = streamed(
        &c,
        ClientRequest::post(&format!("{}/early", base(&e)), Vec::new()),
        move |body| {
            // Keep writing until the connection, closed once the answer is in, refuses. The
            // answer may even be in before the first write (it comes with the head).
            let t = Instant::now();
            let mut failed = body.write(b"first").is_err();
            while !failed && t.elapsed() < Duration::from_secs(10) {
                if body.write(&[0u8; 1024]).is_err() {
                    failed = true;
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
            let _ = wtx.send(failed);
        },
    );
    let r = wait(&rx).unwrap();
    assert_eq!((r.status, r.body.as_slice()), (413, &b"too large"[..]));
    assert!(wrx.recv_timeout(Duration::from_secs(15)).unwrap());
    stop(&e);
}

/// What a test handler saw.
#[derive(Default)]
struct Seen {
    head: Option<ResponseHead>,
    body: Vec<u8>,
    trailers: Option<Headers>,
    error: Option<String>,
}

struct Recorder {
    seen: Arc<Mutex<Seen>>,
    on_head: Option<mpsc::Sender<ResponseBody>>,
    done: mpsc::Sender<()>,
}

impl ResponseHandler for Recorder {
    fn on_head(&mut self, head: ResponseHead, body: ResponseBody) {
        self.seen.lock().unwrap().head = Some(head);
        if let Some(tx) = self.on_head.take() {
            let _ = tx.send(body);
        }
    }
    fn on_data(&mut self, chunk: &[u8]) {
        self.seen.lock().unwrap().body.extend_from_slice(chunk);
    }
    fn on_end(&mut self, trailers: &Headers) {
        self.seen.lock().unwrap().trailers = Some(trailers.clone());
        let _ = self.done.send(());
    }
    fn on_error(&mut self, e: ClientError) {
        self.seen.lock().unwrap().error = Some(e.to_string());
        let _ = self.done.send(());
    }
}

fn record(
    c: &Client,
    req: ClientRequest,
) -> (
    Arc<Mutex<Seen>>,
    mpsc::Receiver<ResponseBody>,
    mpsc::Receiver<()>,
) {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let (htx, hrx) = mpsc::channel();
    let (dtx, drx) = mpsc::channel();
    c.request_with(
        req,
        Recorder {
            seen: seen.clone(),
            on_head: Some(htx),
            done: dtx,
        },
    );
    (seen, hrx, drx)
}

#[test]
fn responses_delivered_as_they_arrive_with_held_reads() {
    let e = start(HttpConfig::default());
    // The whole-body limit does not apply to a response delivered as it arrives.
    let c = Client::new(e.clone()).with_options({
        let mut o = ClientOptions::default();
        o.max_body_bytes = 1000;
        o
    });
    let n = 16 << 20;
    let (seen, hrx, drx) = record(&c, ClientRequest::get(&format!("{}/big/{n}", base(&e))));
    let rb = hrx.recv_timeout(Duration::from_secs(10)).unwrap();
    rb.hold_reads(true);
    thread::sleep(Duration::from_millis(300));
    let a = seen.lock().unwrap().body.len();
    thread::sleep(Duration::from_millis(300));
    let b = seen.lock().unwrap().body.len();
    // Held: at most one read's worth more arrives, and not the whole body.
    assert!(b < n, "held reads stopped the body ({b} of {n})");
    assert!(b - a <= 1 << 20, "held: {a} then {b}");
    rb.hold_reads(false);
    drx.recv_timeout(Duration::from_secs(20)).unwrap();
    {
        let s = seen.lock().unwrap();
        assert!(s.error.is_none(), "{:?}", s.error);
        assert_eq!(s.head.as_ref().unwrap().status, 200);
        assert!(s.body == pattern(n), "body intact");
    }
    // Chunked, with trailers.
    let (seen, _h, drx) = record(&c, ClientRequest::get(&format!("{}/trailers", base(&e))));
    drx.recv_timeout(Duration::from_secs(10)).unwrap();
    {
        let s = seen.lock().unwrap();
        assert_eq!(s.body, b"abcd");
        assert_eq!(s.trailers.as_ref().unwrap().get("x-t"), Some("1"));
    }
    // A slow paced download (the server waits for its drains) read as it arrives.
    let before = DRAINS.load(Ordering::Relaxed);
    let n = 8 << 20;
    let (seen, hrx, drx) = record(&c, ClientRequest::get(&format!("{}/paced/{n}", base(&e))));
    let rb = hrx.recv_timeout(Duration::from_secs(10)).unwrap();
    for _ in 0..5 {
        rb.hold_reads(true);
        thread::sleep(Duration::from_millis(40));
        rb.hold_reads(false);
    }
    drx.recv_timeout(Duration::from_secs(20)).unwrap();
    assert!(seen.lock().unwrap().body == pattern(n));
    assert!(
        DRAINS.load(Ordering::Relaxed) > before,
        "the server waited for drains"
    );
    // Cancelled: the handler hears `Closed`.
    let (seen, hrx, drx) = record(
        &c,
        ClientRequest::get(&format!("{}/big/{}", base(&e), 16 << 20)),
    );
    let rb = hrx.recv_timeout(Duration::from_secs(10)).unwrap();
    rb.hold_reads(true);
    rb.cancel();
    drx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(seen.lock().unwrap().error.is_some());
    // And the pooled connection serves the next request.
    let r = c
        .send(ClientRequest::get(&format!("{}/hello", base(&e))))
        .wait()
        .unwrap();
    assert_eq!(r.body, b"hello");
    stop(&e);
}

/// A handler that both streams the request body and takes the response as it arrives.
struct Both {
    data: Arc<Vec<u8>>,
    seen: Arc<Mutex<Seen>>,
    done: mpsc::Sender<()>,
}

impl ResponseHandler for Both {
    fn on_request_body(&mut self, body: RequestBody) {
        let d = self.data.clone();
        thread::spawn(move || {
            produce(&body, &d).unwrap();
            body.finish().unwrap();
        });
    }
    fn on_head(&mut self, head: ResponseHead, _body: ResponseBody) {
        self.seen.lock().unwrap().head = Some(head);
    }
    fn on_data(&mut self, chunk: &[u8]) {
        self.seen.lock().unwrap().body.extend_from_slice(chunk);
    }
    fn on_end(&mut self, _trailers: &Headers) {
        let _ = self.done.send(());
    }
    fn on_error(&mut self, e: ClientError) {
        self.seen.lock().unwrap().error = Some(e.to_string());
        let _ = self.done.send(());
    }
}

#[test]
fn streamed_both_ways() {
    let e = start(HttpConfig::default());
    let c = Client::new(e.clone());
    let data = Arc::new(pattern(2 << 20));
    let seen = Arc::new(Mutex::new(Seen::default()));
    let (tx, rx) = mpsc::channel();
    c.request_with(
        ClientRequest::post(&format!("{}/sum", base(&e)), Vec::new()).streamed(None),
        Both {
            data: data.clone(),
            seen: seen.clone(),
            done: tx,
        },
    );
    rx.recv_timeout(Duration::from_secs(20)).unwrap();
    let s = seen.lock().unwrap();
    assert!(s.error.is_none(), "{:?}", s.error);
    assert_eq!(
        String::from_utf8(s.body.clone()).unwrap(),
        format!("{},{},-", data.len(), hash(&data))
    );
    drop(s);
    stop(&e);
}

#[test]
fn server_holds_a_streamed_body_and_paces_by_drains_http1() {
    // A body timeout shorter than the hold: held reads are not the client's slowness.
    let e = start({
        let mut v = HttpConfig::default();
        v.body_timeout = Some(Duration::from_millis(150));
        v
    });
    let c = Client::new(e.clone());
    let n = 16 << 20;
    let r = c
        .send(ClientRequest::post(
            &format!("{}/held/500", base(&e)),
            pattern(n),
        ))
        .wait()
        .unwrap();
    let text = String::from_utf8(r.body).unwrap();
    let (total, at) = text.split_once(',').unwrap();
    let (total, at): (usize, usize) = (total.parse().unwrap(), at.parse().unwrap());
    assert_eq!(total, n);
    assert!(at < n, "reads were held: {at} of {n} taken meanwhile");
    // A paced download completes, waiting for drains.
    let before = DRAINS.load(Ordering::Relaxed);
    let m = 8 << 20;
    let r = c
        .send(ClientRequest::get(&format!("{}/paced/{m}", base(&e))))
        .wait();
    // The client's whole-body limit (64 MiB) is above it.
    let r = r.unwrap();
    assert!(r.body == pattern(m));
    assert!(DRAINS.load(Ordering::Relaxed) >= before);
    // The connection's next request is read normally (the hold ended with the body).
    let r = c
        .send(ClientRequest::get(&format!("{}/hello", base(&e))))
        .wait()
        .unwrap();
    assert_eq!(r.body, b"hello");
    stop(&e);
}

#[test]
fn server_holds_a_streamed_body_and_paces_by_drains_http2() {
    let e = start(HttpConfig::default());
    let addr = e.local_addrs()[0];
    let c = H2Client::dial_blocking(&e, addr, None, {
        let mut o = H2Options::default();
        o.max_body_bytes = 64 << 20;
        o
    })
    .unwrap();
    let n = 6 << 20;
    let r = c
        .send(ClientRequest::post(
            &format!("http://{addr}/held/400"),
            pattern(n),
        ))
        .wait()
        .unwrap();
    let text = String::from_utf8(r.body).unwrap();
    let (total, at) = text.split_once(',').unwrap();
    let (total, at): (usize, usize) = (total.parse().unwrap(), at.parse().unwrap());
    assert_eq!(total, n);
    // The stream's window (1 MiB) bounds what the client sends meanwhile.
    assert!(at <= 2 << 20, "held: {at} taken meanwhile");
    // Another stream on the same connection goes on while one is held.
    let held = c.send(ClientRequest::post(
        &format!("http://{addr}/held/400"),
        pattern(3 << 20),
    ));
    thread::sleep(Duration::from_millis(50));
    let t = Instant::now();
    let r = c
        .send(ClientRequest::get(&format!("http://{addr}/hello")))
        .wait()
        .unwrap();
    assert_eq!(r.body, b"hello");
    assert!(
        t.elapsed() < Duration::from_millis(300),
        "{:?}",
        t.elapsed()
    );
    assert!(held.wait().unwrap().body.starts_with(b"3145728,"));
    // A paced download completes over HTTP/2.
    let before = DRAINS.load(Ordering::Relaxed);
    let m = 8 << 20;
    let r = c
        .send(ClientRequest::get(&format!("http://{addr}/paced/{m}")))
        .wait()
        .unwrap();
    assert!(r.body == pattern(m));
    assert!(DRAINS.load(Ordering::Relaxed) >= before);
    stop(&e);
}
