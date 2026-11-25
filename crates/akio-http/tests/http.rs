//! HTTP/1.1 over real sockets, on the native backend (and io_uring with AKIO_TEST_BACKEND=uring).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{Context, HttpConfig, Response, Router, Service, middleware, serve, serve_with};

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

fn start<S: Service>(acceptor: akio_http::HttpAcceptor<S>) -> Engine {
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
        .build()
        .unwrap();
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

struct Resp {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Resp {
    fn h(&self, n: &str) -> Option<&str> {
        self.headers
            .get(&n.to_ascii_lowercase())
            .map(String::as_str)
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Reads one response (Content-Length framed) from the stream.
fn read_resp(s: &mut TcpStream) -> Resp {
    read_resp_opt(s, true)
}

/// `read_body = false` for answers to HEAD, which announce a length but send no body.
fn read_resp_opt(s: &mut TcpStream, read_body: bool) -> Resp {
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        // Retry EINTR like `read_exact` does: with io_uring in the same process, blocking reads
        // of other threads can be interrupted by the kernel's task-work signalling.
        let n = loop {
            match s.read(&mut b) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                r => break r.expect("read response head"),
            }
        };
        assert!(
            n > 0,
            "connection closed mid-head: {:?}",
            String::from_utf8_lossy(&buf)
        );
        buf.push(b[0]);
    }
    let head = String::from_utf8(buf).unwrap();
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let mut headers = HashMap::new();
    for l in lines.filter(|l| !l.is_empty()) {
        let (k, v) = l.split_once(':').unwrap();
        headers.insert(k.to_ascii_lowercase(), v.trim().to_owned());
    }
    let len: usize = headers
        .get("content-length")
        .map_or(0, |v| v.parse().unwrap());
    let mut body = vec![0; len];
    if read_body && status != 204 && status != 304 {
        s.read_exact(&mut body).unwrap();
    } else {
        body.clear();
    }
    Resp {
        status,
        headers,
        body,
    }
}

fn request(addr: SocketAddr, raw: &str) -> Resp {
    let mut s = connect(addr);
    s.write_all(raw.as_bytes()).unwrap();
    read_resp(&mut s)
}

fn at_eof(s: &mut TcpStream) -> bool {
    let mut b = [0u8; 1];
    loop {
        match s.read(&mut b) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            r => return matches!(r, Ok(0)),
        }
    }
}

fn app() -> Router {
    let r = Router::new()
        .get("/", |ctx: &mut Context| ctx.text(200, "root"))
        .get("/users/me", |ctx: &mut Context| ctx.text(200, "me"))
        .get("/users/:id", |ctx: &mut Context| {
            let id = ctx.param("id").unwrap().to_owned();
            ctx.text(200, format!("user {id}"));
        })
        .post("/users/:id", |ctx: &mut Context| {
            ctx.text(201, format!("created {}", ctx.param("id").unwrap()));
        })
        .get("/files/*path", |ctx: &mut Context| {
            let p = ctx.param("path").unwrap().to_owned();
            ctx.text(200, format!("file [{p}]"));
        })
        .post("/echo", |ctx: &mut Context| {
            let trailer = ctx.req().trailers.get("x-sum").unwrap_or("-").to_owned();
            let mut body = ctx.body().to_vec();
            body.extend_from_slice(format!("|{trailer}").as_bytes());
            ctx.bytes(200, "application/octet-stream", body);
        })
        .get("/query", |ctx: &mut Context| {
            let v = ctx.req().query_param("q").unwrap_or("none").to_owned();
            ctx.text(200, v);
        })
        .get("/forget", |_ctx: &mut Context| {})
        .get("/items/{slug}", |ctx: &mut Context| {
            let s = ctx.param("slug").unwrap().to_owned();
            let raw = ctx.param_raw("slug").unwrap().to_owned();
            ctx.text(200, format!("item {s} raw {raw}"));
        });
    r.get("/items/{n:[0-9]+}", |ctx: &mut Context| {
        let n = ctx.param("n").unwrap().to_owned();
        ctx.text(200, format!("item #{n}"));
    })
}

#[test]
fn basic_routing_head_404_405() {
    let e = start(serve(app()));
    let a = e.local_addrs()[0];
    let r = request(a, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!((r.status, r.text().as_str()), (200, "root"));
    assert_eq!(r.h("content-type"), Some("text/plain; charset=utf-8"));
    assert!(r.h("date").is_some());
    assert_eq!(
        request(a, "GET /users/me HTTP/1.1\r\nHost: x\r\n\r\n").text(),
        "me"
    );
    assert_eq!(
        request(a, "GET /users/42 HTTP/1.1\r\nHost: x\r\n\r\n").text(),
        "user 42"
    );
    assert_eq!(
        request(a, "GET /files/a/b/c.txt HTTP/1.1\r\nHost: x\r\n\r\n").text(),
        "file [a/b/c.txt]"
    );
    assert_eq!(
        request(a, "GET /query?q=hi HTTP/1.1\r\nHost: x\r\n\r\n").text(),
        "hi"
    );
    // Regexp parameters beat plain ones; values are percent-decoded, the raw text is kept.
    assert_eq!(
        request(a, "GET /items/42?x=1 HTTP/1.1\r\nHost: x\r\n\r\n").text(),
        "item #42"
    );
    assert_eq!(
        request(a, "GET /items/a%20b%2Fc HTTP/1.1\r\nHost: x\r\n\r\n").text(),
        "item a b/c raw a%20b%2Fc"
    );
    assert_eq!(
        request(a, "GET /files/x%20y/z HTTP/1.1\r\nHost: x\r\n\r\n").text(),
        "file [x y/z]"
    );
    assert_eq!(
        request(a, "GET /users/caf%C3%A9 HTTP/1.1\r\nHost: x\r\n\r\n").text(),
        "user café"
    );

    let r = request(a, "GET /nope HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(r.status, 404);
    let r = request(a, "DELETE /users/42 HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(r.status, 405);
    assert_eq!(r.h("allow"), Some("GET, HEAD, POST"));

    // HEAD: headers of the GET answer, no body.
    let mut s = connect(a);
    s.write_all(b"HEAD /users/42 HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let r = read_resp_opt(&mut s, false);
    assert_eq!(r.status, 200);
    assert_eq!(r.h("content-length"), Some("7"));
    // The connection is still in sync: the next response is not the leftover HEAD body.
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut head = [0u8; 12];
    s.read_exact(&mut head).unwrap();
    assert_eq!(&head, b"HTTP/1.1 200", "HEAD must not have sent a body");

    // A handler that neither responds nor detaches gets a 500.
    assert_eq!(
        request(a, "GET /forget HTTP/1.1\r\nHost: x\r\n\r\n").status,
        500
    );
    stop(&e);
}

#[test]
fn bodies_content_length_chunked_with_trailers_and_limits() {
    let e = start(serve_with(
        {
            let mut v = HttpConfig::default();
            v.max_body_bytes = 1000;
            v
        },
        app(),
    ));
    let a = e.local_addrs()[0];
    let r = request(
        a,
        "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
    );
    assert_eq!(r.text(), "hello|-");
    let r = request(
        a,
        "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n\
         5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Sum: 11\r\n\r\n",
    );
    assert_eq!(r.text(), "hello world|11");
    // Over the limit: 413 before the body is read, then the connection closes.
    let mut s = connect(a);
    s.write_all(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5000\r\n\r\n")
        .unwrap();
    assert_eq!(read_resp(&mut s).status, 413);
    assert!(at_eof(&mut s));
    // Chunked over the limit.
    let big = "x".repeat(600);
    let raw = format!(
        "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n{0:x}\r\n{big}\r\n{0:x}\r\n{big}\r\n0\r\n\r\n",
        600
    );
    assert_eq!(request(a, &raw).status, 413);
    stop(&e);
}

#[test]
fn keep_alive_close_http10_and_split_delivery() {
    let e = start(serve(app()));
    let a = e.local_addrs()[0];
    // Several requests on one connection.
    let mut s = connect(a);
    for i in 0..5 {
        s.write_all(format!("GET /users/{i} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .unwrap();
        assert_eq!(read_resp(&mut s).text(), format!("user {i}"));
    }
    // Connection: close.
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let r = read_resp(&mut s);
    assert_eq!(r.h("connection"), Some("close"));
    assert!(at_eof(&mut s));
    // HTTP/1.0 closes by default, and keeps alive on request.
    let mut s = connect(a);
    s.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    assert_eq!(read_resp(&mut s).h("connection"), Some("close"));
    assert!(at_eof(&mut s));
    let mut s = connect(a);
    s.write_all(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
        .unwrap();
    assert_eq!(read_resp(&mut s).h("connection"), Some("keep-alive"));
    s.write_all(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
        .unwrap();
    assert_eq!(read_resp(&mut s).status, 200);
    // A request dribbled one byte at a time.
    let mut s = connect(a);
    for b in b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc" {
        s.write_all(&[*b]).unwrap();
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(read_resp(&mut s).text(), "abc|-");
    stop(&e);
}

/// A connection reuses a finished request's target buffer for the next one (ADR-025): targets
/// of every length, a detached request (which keeps its own) and one too long to keep, all
/// pipelined in one write, each answered with its own target.
#[test]
fn pipelined_targets_reuse_the_buffer_and_stay_exact() {
    let app = Router::new()
        .get("/t/*rest", |ctx: &mut Context| {
            let t = ctx.req().target.clone();
            ctx.text(200, t);
        })
        .get("/d/*rest", |ctx: &mut Context| {
            let d = ctx.detach().unwrap();
            thread::spawn(move || {
                let t = d.req().target.clone();
                d.respond(Response::text(200, t));
            });
        });
    let e = start(serve(app));
    let mut s = connect(e.local_addrs()[0]);
    let long = format!("/t/{}", "x".repeat(2000));
    let targets = [
        "/t/a-fairly-long-first-target?q=1".to_owned(),
        "/t/b".to_owned(),
        "/d/detached-one".to_owned(),
        "/t/c?after=detached".to_owned(),
        long,
        "/t/d".to_owned(),
        "/t/".to_owned(),
    ];
    let raw: String = targets
        .iter()
        .map(|t| format!("GET {t} HTTP/1.1\r\nHost: x\r\n\r\n"))
        .collect();
    s.write_all(raw.as_bytes()).unwrap();
    for t in &targets {
        assert_eq!(&read_resp(&mut s).text(), t);
    }
    stop(&e);
}

/// Echoes the request's `x-` fields in order and answers with `:n` extra fields `r-0`, `r-1`...
/// (from another thread when the path starts with `/hd/`).
fn echo_fields(ctx: &mut Context) {
    let n: usize = ctx.param("n").unwrap().parse().unwrap();
    let body: String = ctx
        .req()
        .headers
        .iter()
        .filter(|(k, _)| k.starts_with("x-"))
        .map(|(k, v)| format!("{k}={v};"))
        .collect();
    let mut r = Response::text(200, body);
    for i in 0..n {
        r = r.header(&format!("r-{i}"), format!("v{i}"));
    }
    if ctx.path().starts_with("/hd/") {
        let d = ctx.detach().unwrap();
        thread::spawn(move || d.respond(r));
    } else {
        ctx.respond(r);
    }
}

/// Request and response heads of every size, one after another on a connection, as the
/// per-thread spare header storage sees them (ADR-081): `(path, request x- fields)`.
fn field_cases() -> Vec<(String, Vec<(String, String)>)> {
    let f = |n: &str, v: &str| (n.to_owned(), v.to_owned());
    vec![
        (
            "/h/5".into(),
            (0..10)
                .map(|i| f(&format!("x-f{i}"), &"v".repeat(i)))
                .collect(),
        ),
        ("/h/0".into(), vec![f("x-one", "1")]),
        ("/h/3".into(), vec![f("x-big", &"b".repeat(5000))]),
        ("/h/0".into(), vec![]),
        (
            "/hd/4".into(),
            vec![f("x-d1", "a"), f("x-d2", "b"), f("x-d3", "c")],
        ),
        ("/h/1".into(), vec![f("x-two", "2")]),
        (
            "/h/2".into(),
            vec![f("x-m", "m"), f("x-n", ""), f("x-o", "o")],
        ),
    ]
}

/// Each request sees exactly its own fields and each response carries exactly its own,
/// whatever the heads before them on the connection held (ADR-081).
#[test]
fn pipelined_heads_reuse_header_storage_and_stay_exact() {
    let app = Router::new()
        .get("/h/:n", echo_fields)
        .get("/hd/:n", echo_fields);
    let e = start(serve(app));
    let mut s = connect(e.local_addrs()[0]);
    let cases = field_cases();
    let raw: String = cases
        .iter()
        .map(|(p, fs)| {
            let fs: String = fs.iter().map(|(n, v)| format!("{n}: {v}\r\n")).collect();
            format!("GET {p} HTTP/1.1\r\nHost: x\r\n{fs}\r\n")
        })
        .collect();
    s.write_all(raw.as_bytes()).unwrap();
    for (p, fs) in &cases {
        let r = read_resp(&mut s);
        let want: String = fs.iter().map(|(n, v)| format!("{n}={v};")).collect();
        assert_eq!(r.text(), want, "{p}");
        let n: usize = p.rsplit('/').next().unwrap().parse().unwrap();
        for i in 0..8 {
            let v = format!("v{i}");
            assert_eq!(r.h(&format!("r-{i}")), (i < n).then_some(v.as_str()), "{p}");
        }
        assert_eq!(r.h("content-type"), Some("text/plain; charset=utf-8"));
    }
    stop(&e);
}

/// A `&'static str` of `len` bytes (a repeating pattern, so a byte out of place shows).
fn text_of(len: usize) -> &'static str {
    static S: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    &S.get_or_init(|| {
        (0..400_000)
            .map(|i| char::from(b'a' + (i % 23) as u8))
            .collect()
    })[..len]
}

/// Body lengths around the pool's size classes, for `text(200, &str)` bodies (ADR-081).
const TEXT_LENS: [usize; 9] = [13, 0, 511, 512, 513, 5000, 300_000, 1, 16384];

/// `text(200, &str)` bodies come from the thread's buffer pool and go back once copied out
/// (ADR-081): pipelined responses of every size, sent here or from another thread, each carry
/// exactly their own body.
#[test]
fn pipelined_text_bodies_reuse_pool_buffers_and_stay_exact() {
    let app = Router::new()
        .get("/s/:len", |ctx: &mut Context| {
            let len: usize = ctx.param("len").unwrap().parse().unwrap();
            ctx.text(200, text_of(len));
        })
        .get("/sd/:len", |ctx: &mut Context| {
            let len: usize = ctx.param("len").unwrap().parse().unwrap();
            let d = ctx.detach().unwrap();
            thread::spawn(move || d.respond(Response::text(200, text_of(len))));
        });
    let e = start(serve(app));
    let mut s = connect(e.local_addrs()[0]);
    let paths: Vec<String> = (0..3)
        .flat_map(|round| {
            TEXT_LENS
                .iter()
                .map(move |l| format!("/{}/{l}", if round == 1 { "sd" } else { "s" }))
        })
        .collect();
    let raw: String = paths
        .iter()
        .map(|p| format!("GET {p} HTTP/1.1\r\nHost: x\r\n\r\n"))
        .collect();
    s.write_all(raw.as_bytes()).unwrap();
    for p in &paths {
        let r = read_resp(&mut s);
        let len: usize = p.rsplit('/').next().unwrap().parse().unwrap();
        assert_eq!(r.status, 200, "{p}");
        assert!(r.body == text_of(len).as_bytes(), "{p}: body differs");
        assert_eq!(r.h("content-length"), Some(len.to_string().as_str()), "{p}");
    }
    stop(&e);
}

#[test]
fn pipelined_requests_are_answered_in_order_even_when_finished_out_of_order() {
    // Later requests finish first.
    let app = Router::new().get("/slow/:ms", |ctx: &mut Context| {
        let ms: u64 = ctx.param("ms").unwrap().parse().unwrap();
        let d = ctx.detach().unwrap();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(ms));
            let body = format!("done {ms}");
            d.respond(Response::text(200, body));
        });
    });
    let e = start(serve(app));
    let a = e.local_addrs()[0];
    let mut s = connect(a);
    let raw: String = [150, 100, 50, 0]
        .iter()
        .map(|ms| format!("GET /slow/{ms} HTTP/1.1\r\nHost: x\r\n\r\n"))
        .collect();
    s.write_all(raw.as_bytes()).unwrap(); // one write, four requests
    for ms in [150, 100, 50, 0] {
        assert_eq!(read_resp(&mut s).text(), format!("done {ms}"));
    }
    stop(&e);
}

#[test]
fn expect_continue_and_protocol_errors() {
    let e = start(serve(app()));
    let a = e.local_addrs()[0];
    let mut s = connect(a);
    s.write_all(
        b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n",
    )
    .unwrap();
    let mut buf = [0u8; 25];
    s.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"HTTP/1.1 100 Continue\r\n\r\n");
    s.write_all(b"data").unwrap();
    assert_eq!(read_resp(&mut s).text(), "data|-");

    for (raw, status) in [
        ("GARBAGE\r\n\r\n", 400),
        ("GET / HTTP/1.1\r\n\r\n", 400), // no Host
        ("GET / HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n", 400), // two (A169)
        ("GET / HTTP/1.0\r\nHost: x\r\nhost: x\r\n\r\n", 400),
        (
            "GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            400,
        ),
        (
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
            400,
        ),
        (
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n",
            400,
        ),
        (
            "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n",
            501,
        ),
        ("GET / HTTP/2.0\r\nHost: x\r\n\r\n", 505),
    ] {
        let mut s = connect(a);
        s.write_all(raw.as_bytes()).unwrap();
        let r = read_resp(&mut s);
        assert_eq!(r.status, status, "for {raw:?}");
        assert!(at_eof(&mut s), "connection must close after {raw:?}");
    }
    stop(&e);

    // Head too large.
    let e = start(serve_with(
        {
            let mut v = HttpConfig::default();
            v.max_header_bytes = 256;
            v
        },
        app(),
    ));
    let a = e.local_addrs()[0];
    let big = format!(
        "GET / HTTP/1.1\r\nHost: x\r\nX-Big: {}\r\n\r\n",
        "a".repeat(1000)
    );
    assert_eq!(request(a, &big).status, 431);
    // Unterminated head that never ends is cut off too.
    let mut s = connect(a);
    s.write_all(format!("GET / HTTP/1.1\r\nX: {}", "a".repeat(600)).as_bytes())
        .unwrap();
    assert_eq!(read_resp(&mut s).status, 431);
    stop(&e);
}

#[test]
fn middleware_recover_request_id_cors_logger() {
    type Seen = Vec<(String, Option<u16>)>;
    let log: Arc<Mutex<Seen>> = Arc::default();
    let l = log.clone();
    let app = Router::new()
        .get("/ok", |ctx: &mut Context| {
            let id = ctx.local("request_id").unwrap_or("").to_owned();
            ctx.text(200, id);
        })
        .get("/boom", |_ctx: &mut Context| panic!("handler bug"))
        .layer(middleware::request_id())
        .layer(middleware::recover())
        .layer(middleware::cors(middleware::Cors::default()))
        .layer(middleware::logger(move |r| {
            l.lock().unwrap().push((r.target.clone(), r.status));
        }));
    let e = start(serve(app));
    let a = e.local_addrs()[0];

    let mut s = connect(a);
    s.write_all(b"GET /ok HTTP/1.1\r\nHost: x\r\nX-Request-Id: abc-123\r\n\r\n")
        .unwrap();
    let r = read_resp(&mut s);
    assert_eq!(r.text(), "abc-123");
    assert_eq!(r.h("x-request-id"), Some("abc-123"));
    // A panic becomes a 500 and the connection stays usable.
    s.write_all(b"GET /boom HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    assert_eq!(read_resp(&mut s).status, 500);
    s.write_all(b"GET /ok HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let r = read_resp(&mut s);
    assert_eq!(r.status, 200);
    assert!(
        r.h("x-request-id").is_some_and(|id| id.len() > 8),
        "generated id"
    );

    // CORS: simple and preflight.
    let r = request(
        a,
        "GET /ok HTTP/1.1\r\nHost: x\r\nOrigin: https://a.example\r\n\r\n",
    );
    assert_eq!(r.h("access-control-allow-origin"), Some("*"));
    let r = request(
        a,
        "OPTIONS /ok HTTP/1.1\r\nHost: x\r\nOrigin: https://a.example\r\nAccess-Control-Request-Method: POST\r\n\r\n",
    );
    assert_eq!(r.status, 204);
    assert!(
        r.h("access-control-allow-methods")
            .unwrap()
            .contains("POST")
    );
    assert!(
        request(a, "GET /ok HTTP/1.1\r\nHost: x\r\n\r\n")
            .h("access-control-allow-origin")
            .is_none()
    );

    let seen = log.lock().unwrap().clone();
    assert!(seen.contains(&("/boom".to_string(), Some(500))), "{seen:?}");
    assert!(seen.contains(&("/ok".to_string(), Some(200))));
    stop(&e);
}

#[test]
fn a_panic_without_recover_closes_only_that_connection() {
    let app = Router::new()
        .get("/boom", |_ctx: &mut Context| panic!("bug"))
        .get("/ok", |ctx: &mut Context| ctx.text(200, "ok"));
    let e = start(serve(app));
    let a = e.local_addrs()[0];
    let mut bad = connect(a);
    bad.write_all(b"GET /boom HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    assert!(at_eof(&mut bad));
    assert_eq!(
        request(a, "GET /ok HTTP/1.1\r\nHost: x\r\n\r\n").text(),
        "ok"
    );
    stop(&e);
}

#[test]
fn nested_routers_and_layers_apply_to_their_own_routes() {
    let api = Router::new()
        .get("/users/:id", |ctx: &mut Context| {
            ctx.text(200, format!("api user {}", ctx.param("id").unwrap()));
        })
        .layer(|ctx: &mut Context, next: &dyn Service| {
            ctx.add_response_header("X-Api", "1");
            next.call(ctx);
        });
    let app = Router::new()
        .get("/", |ctx: &mut Context| ctx.text(200, "root"))
        .nest("/api/v1", api);
    let e = start(serve(app));
    let a = e.local_addrs()[0];
    let r = request(a, "GET /api/v1/users/5 HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(r.text(), "api user 5");
    assert_eq!(r.h("x-api"), Some("1"));
    assert!(
        request(a, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .h("x-api")
            .is_none()
    );
    stop(&e);
}

#[test]
fn graceful_shutdown_lets_a_detached_response_finish_and_ends_idle_connections() {
    let app = Router::new().get("/slow", |ctx: &mut Context| {
        let d = ctx.detach().unwrap();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(200));
            d.respond(Response::text(200, "finished"));
        });
    });
    let e = Arc::new(start(serve(app)));
    let a = e.local_addrs()[0];
    let mut busy = connect(a);
    let mut idle = connect(a);
    busy.write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    thread::sleep(Duration::from_millis(50));
    let t = std::time::Instant::now();
    e.shutdown();
    assert_eq!(
        read_resp(&mut busy).text(),
        "finished",
        "in-flight response survives shutdown"
    );
    assert!(at_eof(&mut busy));
    assert!(at_eof(&mut idle), "idle keep-alive connection is closed");
    e.wait();
    assert!(t.elapsed() < Duration::from_secs(3));
}
