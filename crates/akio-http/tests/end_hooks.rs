//! A request's end heard (`Context::on_end`, `Detached::on_end`, ADR-127), on HTTP/1.1 and
//! HTTP/2: a response sent whole, sent later from a detached request, a streamed one once
//! finished (not at its head), hooks run in order; a detached request whose client goes while it
//! waits, or whose `Detached` is dropped; an unfinished stream whose client goes; a hook
//! registered after the end; a suspended request; and `on_gone` beside `on_end`, each heard once.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{
    Context, Detached, End, Headers, HttpConfig, Response, Router, hpack::Encoder, serve_with,
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

/// What the requests report, in order: `path end` for an end hook, `path note` otherwise.
#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<String>>>);

impl Log {
    fn push(&self, s: String) {
        self.0.lock().unwrap().push(s);
    }

    fn end(&self, path: &str) -> impl FnOnce(End) + Send + 'static {
        let (l, p) = (self.clone(), path.to_owned());
        move |e| l.push(format!("{p} {e:?}"))
    }

    fn of(&self, path: &str) -> Vec<String> {
        let pre = format!("{path} ");
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.starts_with(&pre))
            .cloned()
            .collect()
    }

    fn wait(&self, path: &str, want: &[&str]) {
        let t0 = Instant::now();
        while t0.elapsed() < T && self.of(path) != want {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(self.of(path), want, "{path}");
    }
}

fn app(log: Log, arrived: mpsc::Sender<String>, late: mpsc::Sender<Detached>) -> Router {
    let arrived = Arc::new(Mutex::new(arrived));
    let late = Arc::new(Mutex::new(late));
    let held = Arc::new(Mutex::new(Vec::<Detached>::new()));
    let streams = Arc::new(Mutex::new(Vec::new()));
    let say = move |p: &str| {
        let _ = arrived.lock().unwrap().send(p.to_owned());
    };
    let (l1, l2, l3, l4, l5, l6, l7, l8) = (
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
        log,
    );
    let (a3, a4, a5, a6) = (say.clone(), say.clone(), say.clone(), say.clone());
    Router::new()
        // Answered at once; two hooks, run in order.
        .get("/now", move |ctx: &mut Context| {
            assert!(ctx.on_end(l1.end("/now 1")));
            assert!(ctx.on_end(l1.end("/now 2")));
            ctx.text(200, "now");
        })
        // Detached, answered later from another thread; `on_gone` beside it hears nothing.
        .get("/later", move |ctx: &mut Context| {
            ctx.on_end(l2.end("/later"));
            let l = l2.clone();
            ctx.on_gone(move || l.push("/later gone".into()));
            let d = ctx.detach().unwrap();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(50));
                d.respond(Response::text(200, "later"));
            });
        })
        // A streamed response: ended when finished, not when its head is sent.
        .get("/stream/:finish", move |ctx: &mut Context| {
            let finish = ctx.param("finish") == Some("1");
            let path = format!("/stream/{}", u8::from(finish));
            ctx.on_end(l3.end(&path));
            let l = l3.clone();
            let p = path.clone();
            ctx.on_gone(move || l.push(format!("{p} gone")));
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            s.write(b"part").unwrap();
            if finish {
                let l = l3.clone();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(100));
                    l.push("/stream/1 finishing".into());
                    s.write(b"rest").unwrap();
                    s.finish();
                });
            } else {
                streams.lock().unwrap().push(s);
            }
            a3(&path);
        })
        // Detached and kept, never answered: its client goes.
        .get("/wait", move |ctx: &mut Context| {
            ctx.on_end(l4.end("/wait"));
            held.lock().unwrap().push(ctx.detach().unwrap());
            a4("/wait");
        })
        // Detached, then given up: dropped unanswered.
        .get("/dropped", move |ctx: &mut Context| {
            let mut d = ctx.detach().unwrap();
            d.on_end(l5.end("/dropped"));
            drop(d);
        })
        // Handed to the test, which registers once the client went.
        .get("/late", move |ctx: &mut Context| {
            let d = ctx.detach().unwrap();
            let _ = late.lock().unwrap().send(d);
        })
        // Registered after the response was sent: at once; after a detach with none before:
        // refused.
        .get("/after", move |ctx: &mut Context| {
            if ctx.req().query() == Some("detach") {
                let d = ctx.detach().unwrap();
                let refused = !ctx.on_end(l6.end("/after"));
                l6.push(format!("/after refused={refused}"));
                d.respond(Response::text(200, "after"));
                return;
            }
            ctx.text(200, "after");
            assert!(ctx.on_end(l6.end("/after")));
            a5("/after");
        })
        // Suspended, resumed on another thread, answered there.
        .get("/suspended", move |ctx: &mut Context| {
            ctx.on_end(l7.end("/suspended"));
            let s = ctx.suspend().unwrap();
            let l = l7.clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(30));
                l.push("/suspended resumed".into());
                s.resume(|ctx| ctx.text(200, "resumed"));
            });
            a6("/suspended");
        })
        // Not answered by its handler: the server's 500 is sent.
        .get("/unanswered", move |ctx: &mut Context| {
            ctx.on_end(l8.end("/unanswered"));
        })
}

struct Server {
    e: Arc<Engine>,
    log: Log,
    arrived: mpsc::Receiver<String>,
    late: mpsc::Receiver<Detached>,
}

fn start() -> Server {
    let log = Log::default();
    let (tx, arrived) = mpsc::channel();
    let (ltx, late) = mpsc::channel();
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
                    .serve(serve_with(HttpConfig::default(), app(log.clone(), tx, ltx))),
            )
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    Server {
        e,
        log,
        arrived,
        late,
    }
}

impl Server {
    fn stop(self) {
        self.e.shutdown();
        self.e.wait();
    }

    fn arrived(&self, path: &str) {
        assert_eq!(self.arrived.recv_timeout(T).unwrap(), path);
    }
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
fn http1_responses_sent_whole_end_sent() {
    let srv = start();
    let mut s = connect(&srv.e);
    get(&mut s, "/now");
    read_until(&mut s, b"now");
    srv.log.wait("/now", &["/now 1 Sent", "/now 2 Sent"]);
    get(&mut s, "/later");
    read_until(&mut s, b"later");
    srv.log.wait("/later", &["/later Sent"]);
    get(&mut s, "/stream/1");
    srv.arrived("/stream/1");
    read_until(&mut s, b"0\r\n\r\n");
    srv.log
        .wait("/stream/1", &["/stream/1 finishing", "/stream/1 Sent"]);
    get(&mut s, "/after");
    read_until(&mut s, b"after");
    srv.arrived("/after");
    srv.log.wait("/after", &["/after Sent"]);
    get(&mut s, "/suspended");
    read_until(&mut s, b"resumed");
    srv.arrived("/suspended");
    srv.log
        .wait("/suspended", &["/suspended resumed", "/suspended Sent"]);
    get(&mut s, "/unanswered");
    read_until(&mut s, b"handler did not respond");
    srv.log.wait("/unanswered", &["/unanswered Sent"]);
    // The connection closing after all that: nothing more heard.
    drop(s);
    thread::sleep(Duration::from_millis(200));
    for p in ["/now", "/later", "/stream/1", "/suspended"] {
        assert!(
            srv.log
                .of(p)
                .iter()
                .all(|s| !s.ends_with("Gone") && !s.ends_with("gone"))
        );
    }
    srv.stop();
}

#[test]
fn http1_after_a_detach_with_no_hook_is_refused() {
    let srv = start();
    let mut s = connect(&srv.e);
    get(&mut s, "/after?detach");
    read_until(&mut s, b"after");
    srv.log.wait("/after", &["/after refused=true"]);
    srv.stop();
}

#[test]
fn http1_requests_whose_client_goes_end_gone() {
    let srv = start();
    // Detached and waiting: heard as the client goes, not when the `Detached` is let go.
    let mut s = connect(&srv.e);
    get(&mut s, "/wait");
    srv.arrived("/wait");
    thread::sleep(Duration::from_millis(50));
    assert!(srv.log.of("/wait").is_empty());
    drop(s);
    srv.log.wait("/wait", &["/wait Gone"]);
    // A stream unfinished: `on_gone` first, then the end, once each.
    let mut s = connect(&srv.e);
    get(&mut s, "/stream/0");
    srv.arrived("/stream/0");
    read_until(&mut s, b"part");
    drop(s);
    srv.log
        .wait("/stream/0", &["/stream/0 gone", "/stream/0 Gone"]);
    // Given up by the server.
    let mut s = connect(&srv.e);
    get(&mut s, "/dropped");
    srv.log.wait("/dropped", &["/dropped Gone"]);
    let mut b = [0u8; 64];
    assert_eq!(s.read(&mut b).unwrap(), 0, "a dropped request closes");
    thread::sleep(Duration::from_millis(200));
    assert_eq!(srv.log.of("/wait"), ["/wait Gone"]);
    assert_eq!(srv.log.of("/dropped"), ["/dropped Gone"]);
    srv.stop();
}

#[test]
fn http1_registered_after_the_client_went_runs_at_once() {
    let srv = start();
    let mut s = connect(&srv.e);
    get(&mut s, "/late");
    let mut d = srv.late.recv_timeout(T).unwrap();
    // Watched before the client goes, so the going is heard.
    d.on_gone(|| {});
    drop(s);
    thread::sleep(Duration::from_millis(300));
    let me = thread::current().id();
    let ran = Arc::new(Mutex::new(None));
    let r = ran.clone();
    d.on_end(move |e| *r.lock().unwrap() = Some((e, thread::current().id())));
    assert_eq!(*ran.lock().unwrap(), Some((End::Gone, me)));
    drop(d);
    srv.stop();
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
fn http2_requests_end_sent_or_gone() {
    let srv = start();
    let mut p = Peer::open(&srv.e);
    p.get(1, "/now");
    srv.log.wait("/now", &["/now 1 Sent", "/now 2 Sent"]);
    p.get(3, "/later");
    srv.log.wait("/later", &["/later Sent"]);
    p.get(5, "/stream/1");
    srv.arrived("/stream/1");
    srv.log
        .wait("/stream/1", &["/stream/1 finishing", "/stream/1 Sent"]);
    p.get(7, "/suspended");
    srv.arrived("/suspended");
    srv.log
        .wait("/suspended", &["/suspended resumed", "/suspended Sent"]);
    p.get(9, "/dropped");
    srv.log.wait("/dropped", &["/dropped Gone"]);
    // Reset by the client: that stream alone.
    p.get(11, "/wait");
    srv.arrived("/wait");
    p.get(13, "/stream/0");
    srv.arrived("/stream/0");
    p.send(RST_STREAM, 0, 11, &8u32.to_be_bytes());
    srv.log.wait("/wait", &["/wait Gone"]);
    assert!(srv.log.of("/stream/0").is_empty());
    // The connection closes: the unfinished stream hears it.
    drop(p);
    srv.log
        .wait("/stream/0", &["/stream/0 gone", "/stream/0 Gone"]);
    thread::sleep(Duration::from_millis(200));
    assert_eq!(srv.log.of("/later"), ["/later Sent"]);
    assert_eq!(srv.log.of("/wait"), ["/wait Gone"]);
    srv.stop();
}
