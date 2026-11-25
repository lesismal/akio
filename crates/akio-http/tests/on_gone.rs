//! A request that hears its client go before its response is finished (`Context::on_gone`,
//! `Detached::on_gone`, ADR-108), on HTTP/1.1 and HTTP/2: a detached request whose client
//! closes, or (HTTP/2) resets the stream; a streamed response cut short; a streamed request
//! body cut short, whose sink is dropped; a callback registered after the client went; and
//! responses finished first, which hear nothing.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::TcpStream,
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
    BodyEvent, Context, Detached, Headers, HttpConfig, Response, Router, Streaming, hpack::Encoder,
    serve_with,
};

const T: Duration = Duration::from_secs(10);

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

/// What the handlers report: requests that heard their client go (by path), sinks dropped,
/// and detached requests handed to the test.
#[derive(Clone, Default)]
struct Seen {
    gone: Arc<Mutex<Vec<String>>>,
    sinks_dropped: Arc<AtomicUsize>,
    detached: Arc<Mutex<Option<mpsc::Sender<Detached>>>>,
    arrived: Arc<Mutex<Option<mpsc::Sender<String>>>>,
}

impl Seen {
    fn gone_cb(&self, path: &str) -> impl FnOnce() + Send + 'static {
        let (g, p) = (self.gone.clone(), path.to_owned());
        move || g.lock().unwrap().push(p)
    }

    fn arrived(&self, path: &str) {
        if let Some(tx) = &*self.arrived.lock().unwrap() {
            let _ = tx.send(path.to_owned());
        }
    }

    fn gone(&self) -> Vec<String> {
        let mut v = self.gone.lock().unwrap().clone();
        v.sort();
        v
    }
}

/// Sets a counter when dropped (a body sink's captures).
struct OnDrop(Arc<AtomicUsize>);

impl Drop for OnDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn app(seen: Seen) -> Router {
    let (s1, s2, s3, s4, s5) = (seen.clone(), seen.clone(), seen.clone(), seen.clone(), seen);
    let held = Arc::new(Mutex::new(Vec::<Detached>::new()));
    let streams = Arc::new(Mutex::new(Vec::new()));
    Router::new()
        // Detached, never answered (kept, so the connection stays).
        .get("/wait", move |ctx: &mut Context| {
            let mut d = ctx.detach().unwrap();
            d.on_gone(s1.gone_cb("/wait"));
            held.lock().unwrap().push(d);
            s1.arrived("/wait");
        })
        // Registered on the context, then answered later.
        .get("/answered", move |ctx: &mut Context| {
            ctx.on_gone(s2.gone_cb("/answered"));
            let d = ctx.detach().unwrap();
            let s = s2.clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(50));
                d.respond(Response::text(200, "done"));
                s.arrived("/answered");
            });
        })
        // A streamed response: unfinished (kept), or finished.
        .get("/stream/:finish", move |ctx: &mut Context| {
            let finish = ctx.param("finish") == Some("1");
            let path = format!("/stream/{}", u8::from(finish));
            ctx.on_gone(s3.gone_cb(&path));
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            s.write(b"part").unwrap();
            if finish {
                s.finish();
            } else {
                streams.lock().unwrap().push(s);
            }
            s3.arrived(&path);
        })
        // Handed to the test to register later.
        .get("/late", move |ctx: &mut Context| {
            let d = ctx.detach().unwrap();
            if let Some(tx) = &*s4.detached.lock().unwrap() {
                let _ = tx.send(d);
            }
        })
        // A streamed body, detached at its head as a proxy would.
        .post(
            "/upload",
            Streaming(move |ctx: &mut Context| {
                ctx.on_gone(s5.gone_cb("/upload"));
                let guard = OnDrop(s5.sinks_dropped.clone());
                let s = s5.clone();
                let mut d = ctx.detach();
                let mut first = true;
                ctx.on_body(move |_ctx, ev| {
                    let _ = &guard;
                    match ev {
                        BodyEvent::Chunk(_) if std::mem::take(&mut first) => s.arrived("/upload"),
                        BodyEvent::Chunk(_) => {}
                        BodyEvent::End(_) => {
                            if let Some(d) = d.take() {
                                d.respond(Response::text(200, "got it"));
                            }
                        }
                        BodyEvent::TooLarge => {}
                    }
                });
            }),
        )
}

fn start() -> (Arc<Engine>, Seen, mpsc::Receiver<String>) {
    let seen = Seen::default();
    let (tx, rx) = mpsc::channel();
    *seen.arrived.lock().unwrap() = Some(tx);
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_millis(300);
                v
            })
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .backend(backend())
                    .threads(1)
                    .serve(serve_with(HttpConfig::default(), app(seen.clone()))),
            )
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    (e, seen, rx)
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn wait_until(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
    let t0 = Instant::now();
    while t0.elapsed() < limit {
        if f() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    f()
}

fn connect(e: &Engine) -> TcpStream {
    let s = TcpStream::connect(e.local_addrs()[0]).unwrap();
    s.set_read_timeout(Some(T)).unwrap();
    s
}

fn get(s: &mut TcpStream, path: &str) {
    write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
}

/// Reads until `needle` has been seen.
fn read_until(s: &mut TcpStream, needle: &[u8]) {
    let mut got = Vec::new();
    let mut b = [0u8; 4096];
    while !got.windows(needle.len()).any(|w| w == needle) {
        let n = s.read(&mut b).unwrap();
        assert!(n > 0, "closed before {:?}", String::from_utf8_lossy(needle));
        got.extend_from_slice(&b[..n]);
    }
}

#[test]
fn http1_requests_hear_their_client_go() {
    let (e, seen, arrived) = start();
    // Detached and waiting: the client closes.
    let mut s = connect(&e);
    get(&mut s, "/wait");
    assert_eq!(arrived.recv_timeout(T).unwrap(), "/wait");
    drop(s);
    assert!(wait_until(T, || seen.gone() == ["/wait"]));

    // Answered before the client closes: nothing.
    let mut s = connect(&e);
    get(&mut s, "/answered");
    assert_eq!(arrived.recv_timeout(T).unwrap(), "/answered");
    read_until(&mut s, b"done");
    drop(s);
    // A streamed response: finished hears nothing, unfinished hears the client go.
    let mut s = connect(&e);
    get(&mut s, "/stream/1");
    assert_eq!(arrived.recv_timeout(T).unwrap(), "/stream/1");
    read_until(&mut s, b"0\r\n\r\n");
    drop(s);
    let mut s = connect(&e);
    get(&mut s, "/stream/0");
    assert_eq!(arrived.recv_timeout(T).unwrap(), "/stream/0");
    read_until(&mut s, b"part");
    drop(s);
    assert!(wait_until(T, || seen.gone() == ["/stream/0", "/wait"]));
    thread::sleep(Duration::from_millis(200));
    assert_eq!(seen.gone(), ["/stream/0", "/wait"]);
    stop(&e);
}

#[test]
fn http1_registered_after_the_client_went_runs_at_once() {
    let (e, seen, _arrived) = start();
    let (tx, rx) = mpsc::channel();
    *seen.detached.lock().unwrap() = Some(tx);
    let mut s = connect(&e);
    get(&mut s, "/late");
    let mut d = rx.recv_timeout(T).unwrap();
    drop(s);
    thread::sleep(Duration::from_millis(300));
    let me = thread::current().id();
    let ran_on = Arc::new(Mutex::new(None));
    let r = ran_on.clone();
    d.on_gone(move || *r.lock().unwrap() = Some(thread::current().id()));
    assert_eq!(*ran_on.lock().unwrap(), Some(me));
    drop(d);
    stop(&e);
}

#[test]
fn http1_streamed_body_cut_short_drops_its_sink() {
    let (e, seen, arrived) = start();
    let mut s = connect(&e);
    s.write_all(b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n")
        .unwrap();
    s.write_all(&[b'u'; 1000]).unwrap();
    assert_eq!(arrived.recv_timeout(T).unwrap(), "/upload");
    drop(s);
    assert!(wait_until(T, || seen.gone() == ["/upload"]));
    assert!(wait_until(T, || seen.sinks_dropped.load(Ordering::SeqCst) == 1));
    // Completed: answered, nothing heard.
    let mut s = connect(&e);
    s.write_all(b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n0123456789")
        .unwrap();
    read_until(&mut s, b"got it");
    drop(s);
    thread::sleep(Duration::from_millis(200));
    assert_eq!(seen.gone(), ["/upload"]);
    stop(&e);
}

// ---- HTTP/2 ----------------------------------------------------------------------------------

const HEADERS: u8 = 1;
const RST_STREAM: u8 = 3;
const SETTINGS: u8 = 4;
const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const ACK: u8 = 0x1;

struct Peer {
    s: TcpStream,
    enc: Encoder,
}

impl Peer {
    fn open(e: &Engine) -> Peer {
        let mut p = Peer {
            s: connect(e),
            enc: Encoder::new(),
        };
        p.s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
        p.send(SETTINGS, 0, 0, &[]);
        p.send(SETTINGS, ACK, 0, &[]);
        p
    }

    fn send(&mut self, ty: u8, flags: u8, sid: u32, payload: &[u8]) {
        let mut b = (payload.len() as u32).to_be_bytes()[1..].to_vec();
        b.push(ty);
        b.push(flags);
        b.extend_from_slice(&sid.to_be_bytes());
        b.extend_from_slice(payload);
        self.s.write_all(&b).unwrap();
    }

    fn get(&mut self, sid: u32, path: &str) {
        let block = self.enc.encode(
            [
                (":method", "GET"),
                (":scheme", "http"),
                (":path", path),
                (":authority", "x"),
            ]
            .iter()
            .map(|(n, v)| (n.as_bytes(), v.as_bytes())),
        );
        self.send(HEADERS, END_HEADERS | END_STREAM, sid, &block);
    }
}

#[test]
fn http2_requests_hear_their_stream_reset_or_connection_close() {
    let (e, seen, arrived) = start();
    let mut p = Peer::open(&e);
    // Reset by the client: that stream alone.
    p.get(1, "/wait");
    assert_eq!(arrived.recv_timeout(T).unwrap(), "/wait");
    p.get(3, "/stream/0");
    assert_eq!(arrived.recv_timeout(T).unwrap(), "/stream/0");
    p.send(RST_STREAM, 0, 1, &8u32.to_be_bytes());
    assert!(wait_until(T, || seen.gone() == ["/wait"]));
    // Answered: nothing when the connection then closes; the unfinished stream hears it.
    p.get(5, "/answered");
    assert_eq!(arrived.recv_timeout(T).unwrap(), "/answered");
    thread::sleep(Duration::from_millis(100));
    drop(p);
    assert!(wait_until(T, || seen.gone() == ["/stream/0", "/wait"]));
    thread::sleep(Duration::from_millis(200));
    assert_eq!(seen.gone(), ["/stream/0", "/wait"]);
    stop(&e);
}
