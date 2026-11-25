//! A listener's response observer (`HttpAcceptor::observer`, `Context::set_observed`, ADR-158,
//! akit A29): told once of each observed request's response, with its words, on the thread that
//! sends it, after the filters; whether answered inline, detached, suspended, streamed or held;
//! over HTTP/1.1 and HTTP/2; and not for a request that did not ask, nor one never answered.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{
    Context, HttpConfig, Request, Response, ResponseObserver, Router, Service,
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

/// What the observer was told of one response.
#[derive(Clone, Debug)]
struct Seen {
    status: u16,
    path: String,
    words: [u64; 2],
    thread: Option<String>,
    /// The `x-filter` and `x-extra` headers the response went with.
    filter: bool,
    extra: bool,
    took: Duration,
}

#[derive(Default)]
struct Log(Mutex<Vec<Seen>>);

impl ResponseObserver for Log {
    fn on_response(&self, resp: &Response, req: &Request, words: [u64; 2], started: Instant) {
        self.0.lock().unwrap().push(Seen {
            status: resp.status,
            path: req.path().to_owned(),
            words,
            thread: thread::current().name().map(str::to_owned),
            filter: resp.headers.get("x-filter").is_some(),
            extra: resp.headers.get("x-extra").is_some(),
            took: started.elapsed(),
        });
    }
}

impl Log {
    fn of(&self, path: &str) -> Vec<Seen> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.path == path)
            .cloned()
            .collect()
    }

    /// Waits up to 5 s for `path` to be observed.
    fn wait(&self, path: &str) -> Vec<Seen> {
        let t = Instant::now();
        loop {
            let v = self.of(path);
            if !v.is_empty() || t.elapsed() > Duration::from_secs(5) {
                return v;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

fn start<S: Service>(app: S, log: Option<Arc<Log>>) -> Arc<Engine> {
    let mut acc = serve_with(HttpConfig::default(), app);
    if let Some(l) = log {
        acc = acc.observer(l);
    }
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
                .serve(acc),
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
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.set_nodelay(true).unwrap();
    s
}

/// Reads one response, Content-Length framed or chunked: its status and body.
fn read_resp(s: &mut TcpStream) -> (u16, String) {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert!(s.read(&mut b).expect("read response head") > 0, "closed");
        head.push(b[0]);
    }
    let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
    let status = head[9..12].parse().unwrap();
    if head.contains("transfer-encoding: chunked") {
        let mut body = Vec::new();
        loop {
            let mut line = Vec::new();
            while !line.ends_with(b"\r\n") {
                s.read_exact(&mut b).unwrap();
                line.push(b[0]);
            }
            let n = usize::from_str_radix(std::str::from_utf8(&line).unwrap().trim(), 16).unwrap();
            let mut chunk = vec![0; n + 2];
            s.read_exact(&mut chunk).unwrap();
            if n == 0 {
                return (status, String::from_utf8(body).unwrap());
            }
            body.extend_from_slice(&chunk[..n]);
        }
    }
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

fn get(s: &mut TcpStream, path: &str) -> (u16, String) {
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
        .unwrap();
    read_resp(s)
}

fn answerer(f: impl FnOnce() + Send + 'static) {
    thread::Builder::new()
        .name("answerer".into())
        .spawn(f)
        .unwrap();
}

fn app() -> Router {
    Router::new()
        .get("/inline", |ctx: &mut Context| {
            assert!(ctx.set_observed([1, 2]));
            ctx.text(200, "inline");
        })
        .get("/unobserved", |ctx: &mut Context| {
            ctx.text(200, "unobserved");
        })
        .get("/detached", |ctx: &mut Context| {
            ctx.set_observed([3, 4]);
            let d = ctx.detach().unwrap();
            answerer(move || {
                thread::sleep(Duration::from_millis(30));
                d.respond(Response::text(201, "detached"));
            });
        })
        .get("/filtered", |ctx: &mut Context| {
            ctx.set_observed([0, 0]);
            // A later call replaces the words.
            ctx.set_observed([5, 6]);
            ctx.add_response_header("x-extra", "1");
            ctx.add_response_filter(|resp: &mut Response, _: &Request| {
                resp.headers.set("x-filter", "1");
            });
            ctx.text(200, "filtered");
        })
        .get("/streamed", |ctx: &mut Context| {
            ctx.set_observed([7, 8]);
            let s = ctx.stream_response(200, akio_http::Headers::new()).unwrap();
            answerer(move || {
                s.write(b"stre").unwrap();
                s.write(b"amed").unwrap();
                s.finish();
            });
        })
        .get("/held", |ctx: &mut Context| {
            ctx.set_observed([9, 10]);
            ctx.add_response_filter(|resp: &mut Response, _: &Request| {
                resp.headers.set("x-filter", "1");
            });
            ctx.hold_response_head(Duration::from_secs(5), |h, _| {
                answerer(move || h.resume());
            });
            ctx.text(200, "held");
        })
        .get("/suspended", |ctx: &mut Context| {
            ctx.set_observed([11, 12]);
            let s = ctx.suspend().unwrap();
            answerer(move || s.resume(|ctx| ctx.text(202, "suspended")));
        })
        .get("/late", |ctx: &mut Context| {
            let d = ctx.detach().unwrap();
            assert!(!ctx.set_observed([13, 14]), "the response was taken");
            d.respond(Response::text(200, "late"));
        })
        .get("/gone", |ctx: &mut Context| {
            ctx.set_observed([15, 16]);
            let (tx, rx) = mpsc::channel();
            ctx.on_gone(move || {
                let _ = tx.send(());
            });
            let d = ctx.detach().unwrap();
            answerer(move || {
                rx.recv_timeout(Duration::from_secs(5)).unwrap();
                d.respond(Response::text(499, "gone"));
            });
        })
        .get("/dropped", |ctx: &mut Context| {
            ctx.set_observed([17, 18]);
            let d = ctx.detach().unwrap();
            answerer(move || drop(d));
        })
}

#[test]
fn http1_responses_are_observed_once_with_their_words() {
    let log = Arc::new(Log::default());
    let e = start(app(), Some(log.clone()));
    let mut s = connect(e.local_addrs()[0]);
    for (path, status, body) in [
        ("/inline", 200, "inline"),
        ("/unobserved", 200, "unobserved"),
        ("/detached", 201, "detached"),
        ("/filtered", 200, "filtered"),
        ("/streamed", 200, "streamed"),
        ("/held", 200, "held"),
        ("/suspended", 202, "suspended"),
        ("/late", 200, "late"),
    ] {
        assert_eq!(get(&mut s, path), (status, body.to_owned()), "{path}");
    }
    let one = |path: &str| {
        let v = log.wait(path);
        assert_eq!(v.len(), 1, "{path} observed once: {v:?}");
        v[0].clone()
    };
    let inline = one("/inline");
    assert_eq!((inline.status, inline.words), (200, [1, 2]));
    assert_ne!(inline.thread.as_deref(), Some("answerer"));
    assert!(inline.took < Duration::from_secs(5));
    let detached = one("/detached");
    assert_eq!((detached.status, detached.words), (201, [3, 4]));
    assert_eq!(
        detached.thread.as_deref(),
        Some("answerer"),
        "the sending thread"
    );
    assert!(
        detached.took >= Duration::from_millis(25),
        "{:?}",
        detached.took
    );
    let filtered = one("/filtered");
    assert_eq!(filtered.words, [5, 6]);
    assert!(filtered.filter && filtered.extra, "after the filters");
    let streamed = one("/streamed");
    assert_eq!((streamed.status, streamed.words), (200, [7, 8]));
    let held = one("/held");
    assert_eq!((held.words, held.filter), ([9, 10], true));
    assert_eq!(
        held.thread.as_deref(),
        Some("answerer"),
        "once the head went"
    );
    let suspended = one("/suspended");
    assert_eq!((suspended.status, suspended.words), (202, [11, 12]));
    thread::sleep(Duration::from_millis(50));
    assert!(log.of("/unobserved").is_empty());
    assert!(log.of("/late").is_empty());
    assert_eq!(log.0.lock().unwrap().len(), 6, "nothing observed twice");
    stop(&e);
}

#[test]
fn a_response_sent_after_its_client_went_is_observed_and_one_never_sent_is_not() {
    let log = Arc::new(Log::default());
    let e = start(app(), Some(log.clone()));
    let a = e.local_addrs()[0];
    let mut s = connect(a);
    s.write_all(b"GET /gone HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    thread::sleep(Duration::from_millis(50));
    drop(s);
    let gone = log.wait("/gone");
    assert_eq!(gone.len(), 1);
    assert_eq!((gone[0].status, gone[0].words), (499, [15, 16]));
    let mut s = connect(a);
    s.write_all(b"GET /dropped HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut b = [0u8; 1];
    // Dropping the detached response closes the connection.
    assert!(matches!(s.read(&mut b), Ok(0) | Err(_)));
    thread::sleep(Duration::from_millis(50));
    assert!(log.of("/dropped").is_empty());
    stop(&e);
}

#[test]
fn without_an_observer_set_observed_stores_nothing() {
    let app = Router::new().get("/", |ctx: &mut Context| {
        let stored = ctx.set_observed([1, 2]);
        ctx.text(200, format!("stored={stored}"));
    });
    let e = start(app, None);
    let mut s = connect(e.local_addrs()[0]);
    assert_eq!(get(&mut s, "/"), (200, "stored=false".to_owned()));
    stop(&e);
}

#[test]
fn h2_responses_are_observed() {
    let log = Arc::new(Log::default());
    let e = start(app(), Some(log.clone()));
    let addr = e.local_addrs()[0];
    let c = H2Client::dial_blocking(&e, addr, None, H2Options::default()).unwrap();
    for (path, status) in [
        ("/inline", 200),
        ("/detached", 201),
        ("/unobserved", 200),
        ("/streamed", 200),
        ("/suspended", 202),
    ] {
        let r = c
            .send(ClientRequest::get(&format!("http://{addr}{path}")))
            .wait()
            .unwrap();
        assert_eq!(r.status, status, "{path}");
    }
    for (path, words) in [
        ("/inline", [1, 2]),
        ("/detached", [3, 4]),
        ("/streamed", [7, 8]),
        ("/suspended", [11, 12]),
    ] {
        let v = log.wait(path);
        assert_eq!(v.len(), 1, "{path}");
        assert_eq!(v[0].words, words);
    }
    assert!(log.of("/unobserved").is_empty());
    stop(&e);
}
