//! A streamed HTTP/1 response framed by the `Content-Length` its head gives (akit A35): the
//! pieces go as written, a write past the length is refused, a stream finished short of it is
//! cut, and a coding or a body filter (which change the length) drop it for `chunked`.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{
    BodyChunk, BodyFilter, BodyTap, Context, End, FilterDone, Headers, HttpConfig, Router, TapEnd,
    client::ClientRequest,
    h2client::{H2Client, H2Options},
    middleware::{Compress, StreamCompress, compress},
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
    (0..n).map(|i| b'a' + (i % 26) as u8).collect()
}

fn sized(n: usize) -> Headers {
    let mut h = Headers::new();
    h.set("Content-Type", "text/plain");
    h.set("Content-Length", n.to_string());
    h
}

/// What the routes report: the writes refused, how requests ended, what taps saw.
#[derive(Default)]
struct Seen {
    refused: Mutex<Vec<String>>,
    ends: Mutex<Vec<End>>,
    taps: Mutex<Vec<(usize, TapEnd)>>,
}

struct Tap(Arc<Seen>, usize);

impl BodyTap for Tap {
    fn data(&mut self, data: &[u8]) {
        self.1 += data.len();
    }
    fn end(&mut self, end: TapEnd) {
        self.0.taps.lock().unwrap().push((self.1, end));
    }
}

/// A body filter that sends each piece twice: the body is not the length given.
struct Twice;

impl BodyFilter for Twice {
    fn filter(&mut self, chunk: BodyChunk, done: FilterDone) {
        let mut d = chunk.data.clone();
        d.extend_from_slice(&chunk.data);
        done.done(d, chunk.trailers);
    }
}

fn app(seen: &Arc<Seen>) -> Router {
    let (s1, s2, s3) = (seen.clone(), seen.clone(), seen.clone());
    let gz = Router::new()
        .get("/gz/:n", |ctx: &mut Context| {
            let n: usize = ctx.param("n").unwrap().parse().unwrap();
            let s = ctx.stream_response(200, sized(n)).unwrap();
            s.write(&pattern(n)).unwrap();
            s.finish();
        })
        .layer(compress({
            let mut c = Compress::default();
            c.stream = Some(StreamCompress::default());
            c
        }));
    Router::new()
        // `n` bytes in three pieces, from another thread, the length given; its body tapped.
        .get("/sized/:n", move |ctx: &mut Context| {
            let n: usize = ctx.param("n").unwrap().parse().unwrap();
            let seen = s1.clone();
            ctx.add_response_filter(move |resp, _req| resp.tap_body(Tap(seen, 0)));
            let s = ctx.stream_response(200, sized(n)).unwrap();
            thread::spawn(move || {
                let data = pattern(n);
                let third = n / 3;
                for piece in [&data[..third], &data[third..2 * third], &data[2 * third..]] {
                    s.write(piece).unwrap();
                }
                s.finish();
            });
        })
        // Four bytes of the ten given, then finished: cut.
        .get("/short", move |ctx: &mut Context| {
            let seen = s2.clone();
            ctx.on_end(move |e| seen.ends.lock().unwrap().push(e));
            let seen = s2.clone();
            ctx.add_response_filter(move |resp, _req| resp.tap_body(Tap(seen, 0)));
            let s = ctx.stream_response(200, sized(10)).unwrap();
            s.write(b"abcd").unwrap();
            s.finish();
        })
        // Four bytes given: a write past them is refused whole, the stream goes on.
        .get("/over", move |ctx: &mut Context| {
            let s = ctx.stream_response(200, sized(4)).unwrap();
            s.write(b"abc").unwrap();
            let e = s.write(b"de").unwrap_err();
            s3.refused.lock().unwrap().push(e.to_string());
            s.write(b"d").unwrap();
            s.finish();
        })
        // A body filter changes the body: chunked, the length dropped.
        .get("/twice", |ctx: &mut Context| {
            ctx.add_body_filter(Twice);
            let s = ctx.stream_response(200, sized(6)).unwrap();
            s.write(b"abc").unwrap();
            s.write(b"def").unwrap();
            s.finish();
        })
        .get("/hello", |ctx: &mut Context| ctx.text(200, "hello"))
        .nest("", gz)
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

/// The value of header `name` in `head`.
fn field<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// Reads one response: its head, and its body as framed (by its length or chunked; none for
/// `head_only`).
fn read_response(s: &mut TcpStream, head_only: bool) -> (String, Vec<u8>) {
    let mut out = Vec::new();
    let mut buf = [0u8; 16 << 10];
    let more = |s: &mut TcpStream, out: &mut Vec<u8>, buf: &mut [u8]| {
        let n = s.read(buf).expect("more of the response");
        assert!(
            n > 0,
            "the response ends early: {}",
            String::from_utf8_lossy(out)
        );
        out.extend_from_slice(&buf[..n]);
    };
    let at = loop {
        if let Some(at) = out.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
        more(s, &mut out, &mut buf);
    };
    let head = String::from_utf8_lossy(&out[..at]).into_owned();
    let mut rest = out.split_off(at + 4);
    if head_only {
        assert!(rest.is_empty());
        return (head, Vec::new());
    }
    if let Some(len) = field(&head, "content-length") {
        let len: usize = len.parse().unwrap();
        while rest.len() < len {
            more(s, &mut rest, &mut buf);
        }
        assert_eq!(rest.len(), len, "no more than the length");
        return (head, rest);
    }
    assert_eq!(field(&head, "transfer-encoding"), Some("chunked"), "{head}");
    while !rest.ends_with(b"0\r\n\r\n") {
        more(s, &mut rest, &mut buf);
    }
    // Unframe.
    let mut body = Vec::new();
    let mut p = &rest[..];
    loop {
        let eol = p.windows(2).position(|w| w == b"\r\n").unwrap();
        let n = usize::from_str_radix(std::str::from_utf8(&p[..eol]).unwrap(), 16).unwrap();
        if n == 0 {
            break;
        }
        body.extend_from_slice(&p[eol + 2..eol + 2 + n]);
        p = &p[eol + 2 + n + 2..];
    }
    (head, body)
}

fn get(s: &mut TcpStream, path: &str) {
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
        .unwrap();
}

/// Reads until the connection ends (EOF or reset; `false` if it went quiet instead).
fn read_to_close(s: &mut TcpStream) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) => return (out, true),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return (out, false);
            }
            Err(_) => return (out, true),
        }
    }
}

/// Exactly the length given, not chunked, on a connection that serves on; HEAD too.
#[test]
fn a_streamed_response_framed_by_its_length() {
    let seen = Arc::new(Seen::default());
    let e = start(&seen);
    let mut s = connect(&e);
    for n in [0usize, 1, 100_000, 3 << 20] {
        get(&mut s, &format!("/sized/{n}"));
        let (head, body) = read_response(&mut s, false);
        assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
        assert_eq!(field(&head, "content-length"), Some(n.to_string().as_str()));
        assert_eq!(field(&head, "transfer-encoding"), None, "{head}");
        assert!(body == pattern(n), "{n}: the body as written");
    }
    // HEAD: the length, no body, and the connection serves on.
    s.write_all(b"HEAD /sized/10 HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let (head, _) = read_response(&mut s, true);
    assert_eq!(field(&head, "content-length"), Some("10"));
    get(&mut s, "/hello");
    let (_, body) = read_response(&mut s, false);
    assert_eq!(body, b"hello");
    // The taps saw every byte (the HEAD answer has none to see).
    thread::sleep(Duration::from_millis(50));
    let taps = seen.taps.lock().unwrap().clone();
    assert_eq!(
        taps,
        [0, 1, 100_000, 3 << 20]
            .map(|n| (n, TapEnd::Finished))
            .to_vec()
    );

    // HTTP/1.0: framed by the length, closed after.
    let mut s = connect(&e);
    s.write_all(b"GET /sized/26 HTTP/1.0\r\n\r\n").unwrap();
    let (got, closed) = read_to_close(&mut s);
    let got = String::from_utf8(got).unwrap();
    assert!(got.contains("Content-Length: 26\r\n"), "{got}");
    assert!(got.ends_with("abcdefghijklmnopqrstuvwxyz"), "{got}");
    assert!(closed);
    stop(&e);
}

/// A stream finished short of its length is cut: the connection closes after what was
/// written, its tap hears `Cut`, its request ends `Gone`.
#[test]
fn a_sized_stream_finished_short_closes_the_connection() {
    let seen = Arc::new(Seen::default());
    let e = start(&seen);
    let mut s = connect(&e);
    s.write_all(b"GET /short HTTP/1.1\r\nHost: x\r\n\r\nGET /hello HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let (got, closed) = read_to_close(&mut s);
    let got = String::from_utf8(got).unwrap();
    assert!(closed, "{got}");
    assert!(got.contains("Content-Length: 10\r\n"), "{got}");
    assert!(got.ends_with("\r\n\r\nabcd"), "{got}");
    assert_eq!(got.matches("HTTP/1.1 ").count(), 1, "{got}");
    assert_eq!(*seen.ends.lock().unwrap(), [End::Gone]);
    assert_eq!(*seen.taps.lock().unwrap(), [(4, TapEnd::Cut)]);
    stop(&e);
}

/// A write past the length is refused whole; the stream goes on, and the connection serves on
/// once it is complete.
#[test]
fn a_write_past_the_length_is_refused() {
    let seen = Arc::new(Seen::default());
    let e = start(&seen);
    let mut s = connect(&e);
    get(&mut s, "/over");
    let (head, body) = read_response(&mut s, false);
    assert_eq!(field(&head, "content-length"), Some("4"));
    assert_eq!(body, b"abcd");
    let refused = seen.refused.lock().unwrap().clone();
    assert_eq!(refused.len(), 1);
    assert!(refused[0].contains("Content-Length"), "{refused:?}");
    get(&mut s, "/hello");
    let (_, body) = read_response(&mut s, false);
    assert_eq!(body, b"hello");
    stop(&e);
}

/// A coding (the compress middleware's) or a body filter changes the body: its length is
/// dropped, and it goes chunked.
#[test]
fn a_coding_or_a_body_filter_drops_the_length() {
    let seen = Arc::new(Seen::default());
    let e = start(&seen);
    let mut s = connect(&e);
    s.write_all(b"GET /gz/5000 HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n\r\n")
        .unwrap();
    let (head, body) = read_response(&mut s, false);
    assert_eq!(field(&head, "content-encoding"), Some("gzip"), "{head}");
    assert_eq!(field(&head, "content-length"), None, "{head}");
    assert!(body.len() < 5000 && body.starts_with(&[0x1f, 0x8b]), "gzip");
    // Without the coding: framed by its length.
    get(&mut s, "/gz/5000");
    let (head, body) = read_response(&mut s, false);
    assert_eq!(field(&head, "content-length"), Some("5000"), "{head}");
    assert_eq!(body, pattern(5000));
    get(&mut s, "/twice");
    let (head, body) = read_response(&mut s, false);
    assert_eq!(field(&head, "content-length"), None, "{head}");
    assert_eq!(body, b"abcabcdefdef");
    get(&mut s, "/hello");
    let (_, body) = read_response(&mut s, false);
    assert_eq!(body, b"hello");
    stop(&e);
}

/// HTTP/2 frames the body itself and keeps the field.
#[test]
fn http2_keeps_the_length() {
    let seen = Arc::new(Seen::default());
    let e = start(&seen);
    let addr = e.local_addrs()[0];
    let c = H2Client::dial_blocking(&e, addr, None, H2Options::default()).unwrap();
    let r = c
        .send(ClientRequest::get(&format!("http://{addr}/sized/70000")))
        .wait()
        .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.headers.get("content-length"), Some("70000"));
    assert!(r.body == pattern(70000));
    stop(&e);
}
