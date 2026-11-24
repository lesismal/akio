//! Body taps and outer response filters (ADR-116): a filter sees a streamed body as it is sent,
//! encoded, and how it ended; an outer filter sees the response as the filters inside it left it.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver},
    },
    thread,
    time::Duration,
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{
    BodyTap, Coding, Context, Headers, Request, Response, Router, TapEnd, parse_http_date, serve,
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

fn start(app: Router) -> Engine {
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
                .serve(serve(app)),
        )
        .client_threads(1)
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
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.set_nodelay(true).unwrap();
    s
}

fn read_line(s: &mut TcpStream) -> Vec<u8> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    while !line.ends_with(b"\r\n") {
        s.read_exact(&mut b).unwrap();
        line.push(b[0]);
    }
    line.truncate(line.len() - 2);
    line
}

fn read_head(s: &mut TcpStream) -> (u16, HashMap<String, String>) {
    let status = String::from_utf8(read_line(s)).unwrap();
    let status = status.split(' ').nth(1).unwrap().parse().unwrap();
    let mut h = HashMap::new();
    loop {
        let l = String::from_utf8(read_line(s)).unwrap();
        if l.is_empty() {
            return (status, h);
        }
        let (k, v) = l.split_once(':').unwrap();
        h.insert(k.to_ascii_lowercase(), v.trim().to_owned());
    }
}

/// The next chunk's data; `None` at the last chunk (whose trailer lines are read too).
fn read_chunk(s: &mut TcpStream) -> Option<Vec<u8>> {
    let n = usize::from_str_radix(std::str::from_utf8(&read_line(s)).unwrap(), 16).unwrap();
    if n == 0 {
        while !read_line(s).is_empty() {}
        return None;
    }
    let mut data = vec![0; n];
    s.read_exact(&mut data).unwrap();
    assert_eq!(read_line(s), b"", "chunk ends with CRLF");
    Some(data)
}

/// What a tap saw.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Data(Vec<u8>),
    End(TapEnd),
}

struct Recorder(Arc<Mutex<Vec<Seen>>>);

impl BodyTap for Recorder {
    fn data(&mut self, data: &[u8]) {
        self.0.lock().unwrap().push(Seen::Data(data.to_vec()));
    }

    fn end(&mut self, end: TapEnd) {
        self.0.lock().unwrap().push(Seen::End(end));
    }
}

/// Waits for the tap to have been told how the body ended, and returns what it saw.
fn ended(seen: &Mutex<Vec<Seen>>) -> Vec<Seen> {
    for _ in 0..500 {
        {
            let mut s = seen.lock().unwrap();
            if matches!(s.last(), Some(Seen::End(_))) {
                return std::mem::take(&mut *s);
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("the tap was not told the end: {:?}", seen.lock().unwrap());
}

/// The bytes a tap saw, and how the body ended.
fn joined(seen: Vec<Seen>) -> (Vec<u8>, TapEnd) {
    let mut out = Vec::new();
    let mut end = None;
    for s in seen {
        match s {
            Seen::Data(d) => {
                assert!(end.is_none(), "data after the end");
                out.extend_from_slice(&d);
            }
            Seen::End(e) => {
                assert!(end.is_none(), "told the end twice");
                end = Some(e);
            }
        }
    }
    (out, end.unwrap())
}

/// An app whose `/stream` streams the pieces it is sent (`None` finishes, `Some("")` finishes
/// with a trailer), behind a layer whose outer filter taps the body and records the head as the
/// inner filter (registered after it) left it.
fn app(
    pieces: Arc<Mutex<Receiver<Option<&'static str>>>>,
    seen: Arc<Mutex<Vec<Seen>>>,
    heads: Arc<Mutex<Vec<String>>>,
    encode: bool,
) -> Router {
    Router::new()
        .get("/stream", move |ctx: &mut Context| {
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            let pieces = pieces.clone();
            thread::spawn(move || {
                loop {
                    let next = pieces.lock().unwrap().recv_timeout(Duration::from_secs(5));
                    match next {
                        Ok(Some("")) => {
                            let mut t = Headers::new();
                            t.set("X-Checksum", "1");
                            return s.finish_with_trailers(t);
                        }
                        Ok(Some(p)) => {
                            if s.write(p.as_bytes()).is_err() {
                                return; // dropped unfinished
                            }
                        }
                        Ok(None) | Err(_) => return s.finish(),
                    }
                }
            });
        })
        .get("/whole", |ctx: &mut Context| ctx.text(200, "whole"))
        .layer(move |ctx: &mut Context, next: &dyn akio_http::Service| {
            let seen = seen.clone();
            let heads = heads.clone();
            let h2 = heads.clone();
            // Outer filters, registered first, run last, the last registered first.
            ctx.add_outer_response_filter(move |resp: &mut Response, _: &Request| {
                let enc = resp.headers.get("content-encoding").unwrap_or("-");
                let order = resp.headers.get("x-order").unwrap_or("-");
                heads.lock().unwrap().push(format!("{enc} {order}"));
                resp.tap_body(Recorder(seen));
            });
            ctx.add_outer_response_filter(move |resp: &mut Response, _: &Request| {
                h2.lock().unwrap().push("second outer".to_owned());
                resp.headers.set("X-Order", "inner, second outer");
            });
            ctx.add_response_filter(move |resp: &mut Response, _: &Request| {
                resp.headers.set("X-Order", "inner");
                if encode && resp.is_streaming() {
                    let c = Coding::gzip(1);
                    resp.set_stream_coding(Some(c));
                    resp.headers.set("Content-Encoding", c.name());
                }
            });
            next.call(ctx);
        })
}

fn get(s: &mut TcpStream, method: &str, path: &str) {
    s.write_all(format!("{method} {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
        .unwrap();
}

#[test]
fn a_tap_sees_the_body_as_sent_and_how_it_ended() {
    let (tx, rx) = mpsc::channel();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let heads = Arc::new(Mutex::new(Vec::new()));
    let e = start(app(
        Arc::new(Mutex::new(rx)),
        seen.clone(),
        heads.clone(),
        false,
    ));
    let addr = e.local_addrs()[0];

    // Finished: every byte, in order, then Finished; the outer filters ran after the inner one,
    // the second registered first.
    let mut s = connect(addr);
    get(&mut s, "GET", "/stream");
    let _ = read_head(&mut s);
    tx.send(Some("one ")).unwrap();
    assert_eq!(read_chunk(&mut s).unwrap(), b"one ");
    tx.send(Some("two")).unwrap();
    tx.send(None).unwrap();
    while read_chunk(&mut s).is_some() {}
    assert_eq!(
        joined(ended(&seen)),
        (b"one two".to_vec(), TapEnd::Finished)
    );
    assert_eq!(
        std::mem::take(&mut *heads.lock().unwrap()),
        ["second outer", "- inner, second outer"]
    );

    // With trailers.
    get(&mut s, "GET", "/stream");
    let _ = read_head(&mut s);
    tx.send(Some("body")).unwrap();
    tx.send(Some("")).unwrap();
    while read_chunk(&mut s).is_some() {}
    assert_eq!(joined(ended(&seen)), (b"body".to_vec(), TapEnd::Trailers));

    // The client goes: the write fails, the stream is dropped unfinished, and the tap hears Cut.
    get(&mut s, "GET", "/stream");
    let _ = read_head(&mut s);
    tx.send(Some("first")).unwrap();
    assert_eq!(read_chunk(&mut s).unwrap(), b"first");
    drop(s);
    thread::sleep(Duration::from_millis(100));
    for _ in 0..20 {
        let _ = tx.send(Some("more"));
        thread::sleep(Duration::from_millis(10));
    }
    let (got, end) = joined(ended(&seen));
    assert_eq!(end, TapEnd::Cut);
    assert!(got.starts_with(b"first"), "{got:?}");

    // HEAD and a whole response: the tap is dropped unused.
    let mut s = connect(addr);
    get(&mut s, "HEAD", "/stream");
    let _ = read_head(&mut s);
    tx.send(None).unwrap();
    get(&mut s, "GET", "/whole");
    let (status, _) = read_head(&mut s);
    assert_eq!(status, 200);
    thread::sleep(Duration::from_millis(100));
    assert!(
        seen.lock().unwrap().is_empty(),
        "{:?}",
        seen.lock().unwrap()
    );
    stop(&e);
}

#[test]
fn a_tap_sees_the_encoded_body() {
    let (tx, rx) = mpsc::channel();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let heads = Arc::new(Mutex::new(Vec::new()));
    let e = start(app(
        Arc::new(Mutex::new(rx)),
        seen.clone(),
        heads.clone(),
        true,
    ));
    let mut s = connect(e.local_addrs()[0]);
    get(&mut s, "GET", "/stream");
    let (_, h) = read_head(&mut s);
    assert_eq!(h.get("content-encoding").map(String::as_str), Some("gzip"));
    let text = "a line that repeats, a line that repeats\n".repeat(50);
    tx.send(Some(Box::leak(text.clone().into_boxed_str())))
        .unwrap();
    tx.send(None).unwrap();
    let mut wire = Vec::new();
    while let Some(c) = read_chunk(&mut s) {
        wire.extend_from_slice(&c);
    }
    let (tapped, end) = joined(ended(&seen));
    assert_eq!(end, TapEnd::Finished);
    assert_eq!(tapped, wire, "the tap sees what the client got");
    let plain = akio_deflate::decompress(akio_deflate::Format::Gzip, &tapped, 1 << 20).unwrap();
    assert_eq!(plain, text.as_bytes());
    assert_eq!(
        heads.lock().unwrap().last().map(String::as_str),
        Some("gzip inner, second outer"),
        "the outer filter sees the inner filter's coding"
    );
    stop(&e);
}

#[test]
fn http_dates_are_exported() {
    assert_eq!(
        parse_http_date("Sun Nov  6 08:49:37 1994"),
        Some(784_111_777)
    );
}
