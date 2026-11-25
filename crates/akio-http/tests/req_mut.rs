//! A request changed by a middleware (`Context::req_mut`, ADR-126), on HTTP/1.1 and HTTP/2:
//! fields set, added and removed and the target rewritten by a middleware in front of a router
//! (which then routes the new path), seen by the handler, `path()`, `header()` and the response
//! filters; a target changed by a route's layer, after routing, whose parameters keep reading the
//! path they were matched in; `None` once detached; whole again in a resumed suspended request.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{
    Context, HttpConfig, Request, Response, Router, Service, hpack::Encoder, serve_with,
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

type Seen = Arc<Mutex<mpsc::Sender<String>>>;

fn say(seen: &Seen, s: String) {
    let _ = seen.lock().unwrap().send(s);
}

/// A middleware in front of the router: rewrites `/old/...` to `/new/...` and edits fields.
struct Front {
    router: Router,
    seen: Seen,
}

impl Service for Front {
    fn call(&self, ctx: &mut Context) {
        if ctx.path().starts_with("/old/") {
            let seen = self.seen.clone();
            ctx.add_response_filter(move |_: &mut Response, req: &Request| {
                say(&seen, format!("filter {}", req.target));
            });
            let req = ctx.req_mut().expect("owned before the handler");
            let rest = req.target["/old/".len()..].to_owned();
            req.target = format!("/new/{rest}");
            req.headers.set("x-set", "1");
            req.headers.append("x-added", "a");
            req.headers.append("x-added", "b");
            req.headers.remove("x-drop");
        }
        self.router.call(ctx);
    }
}

fn app(seen: Seen) -> Front {
    let (s1, s2, s3, s4) = (seen.clone(), seen.clone(), seen.clone(), seen.clone());
    let router = Router::new()
        .get("/new/:id", move |ctx: &mut Context| {
            let added: Vec<&str> = ctx.req().headers.get_all("x-added").collect();
            say(
                &s1,
                format!(
                    "handler path={} target={} id={} set={:?} added={added:?} drop={:?}",
                    ctx.path(),
                    ctx.req().target,
                    ctx.param("id").unwrap_or("-"),
                    ctx.header("x-set"),
                    ctx.header("x-drop"),
                ),
            );
            ctx.text(200, "new");
        })
        .get("/old/:id", move |ctx: &mut Context| {
            say(&s2, "routed to /old".into());
            ctx.text(200, "old");
        })
        .get("/detach", move |ctx: &mut Context| {
            let d = ctx.detach().unwrap();
            say(&s3, format!("detached req_mut={}", ctx.req_mut().is_some()));
            d.respond(Response::text(200, "detached"));
        })
        .get("/suspend", move |ctx: &mut Context| {
            let s = ctx.suspend().unwrap();
            let seen = s4.clone();
            thread::spawn(move || {
                s.resume(|ctx| {
                    let ok = match ctx.req_mut() {
                        Some(r) => {
                            r.headers.set("x-after", "resumed");
                            true
                        }
                        None => false,
                    };
                    say(&seen, format!("resumed {ok} {:?}", ctx.header("x-after")));
                    ctx.text(200, "resumed");
                });
            });
        });
    // A route's layer: runs after routing, so it changes the target without routing again.
    let s5 = seen.clone();
    let router = router.get("/item/:id/:rest", move |ctx: &mut Context| {
        say(
            &s5,
            format!(
                "layered path={} id={} rest={} raw={}",
                ctx.path(),
                ctx.param("id").unwrap_or("-"),
                ctx.param("rest").unwrap_or("-"),
                ctx.param_raw("id").unwrap_or("-"),
            ),
        );
        ctx.text(200, "layered");
    });
    let router = router.layer(|ctx: &mut Context, next: &dyn Service| {
        if ctx.path().starts_with("/item/") {
            if let Some(r) = ctx.req_mut() {
                r.target = "/elsewhere/entirely/x".into();
            }
        }
        next.call(ctx);
    });
    Front { router, seen }
}

fn start() -> (Arc<Engine>, mpsc::Receiver<String>) {
    let (tx, rx) = mpsc::channel();
    let seen = Arc::new(Mutex::new(tx));
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
                    .serve(serve_with(HttpConfig::default(), app(seen))),
            )
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    (e, rx)
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn connect(e: &Engine) -> TcpStream {
    let s = TcpStream::connect(e.local_addrs()[0]).unwrap();
    s.set_read_timeout(Some(T)).unwrap();
    s
}

fn read_until(s: &mut TcpStream, needle: &[u8]) {
    let mut got = Vec::new();
    let mut b = [0u8; 4096];
    while !got.windows(needle.len()).any(|w| w == needle) {
        let n = s.read(&mut b).unwrap();
        assert!(n > 0, "closed before {:?}", String::from_utf8_lossy(needle));
        got.extend_from_slice(&b[..n]);
    }
}

fn next(rx: &mpsc::Receiver<String>) -> String {
    rx.recv_timeout(T).unwrap()
}

const REWRITTEN: &str = "handler path=/new/7 target=/new/7?q=1 id=7 set=Some(\"1\") \
                         added=[\"a\", \"b\"] drop=None";

#[test]
fn http1_middleware_changes_the_request() {
    let (e, rx) = start();
    let mut s = connect(&e);
    s.write_all(b"GET /old/7?q=1 HTTP/1.1\r\nHost: x\r\nX-Drop: yes\r\nX-Set: 0\r\n\r\n")
        .unwrap();
    read_until(&mut s, b"new");
    assert_eq!(next(&rx), REWRITTEN);
    assert_eq!(next(&rx), "filter /new/7?q=1");
    // The next request on the connection is its own: nothing carried over.
    s.write_all(b"GET /new/8 HTTP/1.1\r\nHost: x\r\nX-Drop: kept\r\n\r\n")
        .unwrap();
    read_until(&mut s, b"new");
    assert_eq!(
        next(&rx),
        "handler path=/new/8 target=/new/8 id=8 set=None added=[] drop=Some(\"kept\")"
    );
    s.write_all(b"GET /item/a%20b/c HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    read_until(&mut s, b"layered");
    assert_eq!(
        next(&rx),
        "layered path=/elsewhere/entirely/x id=a b rest=c raw=a%20b"
    );
    s.write_all(b"GET /detach HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    read_until(&mut s, b"detached");
    assert_eq!(next(&rx), "detached req_mut=false");
    s.write_all(b"GET /suspend HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    read_until(&mut s, b"resumed");
    assert_eq!(next(&rx), "resumed true Some(\"resumed\")");
    drop(s);
    stop(&e);
}

// ---- HTTP/2 ----------------------------------------------------------------------------------

const HEADERS: u8 = 1;
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

    fn get(&mut self, sid: u32, path: &str, fields: &[(&str, &str)]) {
        let mut all = vec![
            (":method", "GET"),
            (":scheme", "http"),
            (":path", path),
            (":authority", "x"),
        ];
        all.extend_from_slice(fields);
        let block = self
            .enc
            .encode(all.iter().map(|(n, v)| (n.as_bytes(), v.as_bytes())));
        self.send(HEADERS, END_HEADERS | END_STREAM, sid, &block);
    }
}

#[test]
fn http2_middleware_changes_the_request() {
    let (e, rx) = start();
    let mut p = Peer::open(&e);
    p.get(1, "/old/7?q=1", &[("x-drop", "yes"), ("x-set", "0")]);
    assert_eq!(next(&rx), REWRITTEN);
    assert_eq!(next(&rx), "filter /new/7?q=1");
    p.get(3, "/item/a%20b/c", &[]);
    assert_eq!(
        next(&rx),
        "layered path=/elsewhere/entirely/x id=a b rest=c raw=a%20b"
    );
    p.get(5, "/detach", &[]);
    assert_eq!(next(&rx), "detached req_mut=false");
    p.get(7, "/suspend", &[]);
    assert_eq!(next(&rx), "resumed true Some(\"resumed\")");
    drop(p);
    stop(&e);
}
