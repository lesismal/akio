//! Compressed streamed responses (ADR-074): every coding decodes with our decoders and the
//! command-line tools, each server-sent event can be decoded as soon as it is written, and what
//! must stay uncompressed does.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, Sender},
    },
    thread,
    time::Duration,
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{
    Context, Headers, Router,
    client::ClientRequest,
    h2client::{H2Client, H2Event, H2Options},
    middleware::{self, Compress, StreamCompress},
    serve,
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

/// Every coding on offer, streamed responses included.
fn all_codings() -> Compress {
    let mut c = Compress::default();
    c.brotli = Some(5);
    c.zstd = Some(3);
    c.stream = Some(StreamCompress::default());
    c
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.set_nodelay(true).unwrap();
    s
}

fn read_exact(s: &mut TcpStream, buf: &mut [u8]) {
    s.read_exact(buf).unwrap();
}

fn read_line(s: &mut TcpStream) -> Vec<u8> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    while !line.ends_with(b"\r\n") {
        read_exact(s, &mut b);
        line.push(b[0]);
    }
    line.truncate(line.len() - 2);
    line
}

/// The status and header fields (names in lower case) of a response head.
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

/// The next chunk's data; `None` at the last chunk.
fn read_chunk(s: &mut TcpStream) -> Option<Vec<u8>> {
    let n = usize::from_str_radix(std::str::from_utf8(&read_line(s)).unwrap(), 16).unwrap();
    let mut data = vec![0; n];
    read_exact(s, &mut data);
    assert_eq!(read_line(s), b"", "chunk ends with CRLF");
    (n > 0).then_some(data)
}

fn get(s: &mut TcpStream, path: &str, accept: &str) {
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: x\r\nAccept-Encoding: {accept}\r\n\r\n").as_bytes(),
    )
    .unwrap();
}

/// One server-sent event, about 100 bytes of JSON.
fn event(i: usize) -> String {
    format!(
        "event: tick\nid: {i}\ndata: {{\"seq\":{i},\"price\":{}.{:02},\"symbol\":\"SYM{}\",\"note\":\"steady\"}}\n\n",
        100 + i % 37,
        i % 100,
        i % 13
    )
}

/// A decoder fed piece by piece, the way a browser decodes a response as it arrives.
#[allow(clippy::large_enum_variant, reason = "one per test")]
enum Dec {
    Deflate(akio_deflate::Inflater),
    Br(akio_brotli::Decompressor),
    Zstd(akio_zstd::Decompressor),
}

impl Dec {
    fn new(coding: &str) -> Dec {
        match coding {
            "gzip" => Dec::Deflate(akio_deflate::Inflater::new(akio_deflate::Format::Gzip)),
            "deflate" => Dec::Deflate(akio_deflate::Inflater::new(akio_deflate::Format::Zlib)),
            "br" => Dec::Br(akio_brotli::Decompressor::new()),
            "zstd" => Dec::Zstd(akio_zstd::Decompressor::new()),
            c => panic!("coding {c}"),
        }
    }

    /// Decodes `data`, appending to `out`.
    fn feed(&mut self, data: &[u8], out: &mut Vec<u8>) {
        let mut rest = data;
        loop {
            let used = match self {
                Dec::Deflate(d) => d.decompress_vec(rest, out, 1 << 26).unwrap().consumed,
                Dec::Br(d) => d.decompress_vec(rest, out, 1 << 26).unwrap().consumed,
                Dec::Zstd(d) => d.decompress_vec(rest, out, 1 << 26).unwrap().consumed,
            };
            rest = &rest[used..];
            if rest.is_empty() || used == 0 {
                return;
            }
        }
    }

    fn done(&self) -> bool {
        match self {
            Dec::Deflate(d) => d.is_done(),
            Dec::Br(d) => d.is_done(),
            Dec::Zstd(d) => d.is_done(),
        }
    }
}

/// Decodes a complete body with the coding's command-line tool; `None` when it is not
/// installed (`deflate` has none: flate2's zlib decoder stands in).
fn cli_decode(coding: &str, body: &[u8]) -> Option<Vec<u8>> {
    let tool = match coding {
        "deflate" => {
            let mut v = Vec::new();
            flate2::read::ZlibDecoder::new(body)
                .read_to_end(&mut v)
                .unwrap();
            return Some(v);
        }
        "br" => "brotli",
        t => t,
    };
    let Ok(mut c) = Command::new(tool)
        .args(["-d", "-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    else {
        eprintln!("{tool}(1) not found; skipped");
        return None;
    };
    let mut stdin = c.stdin.take().unwrap();
    let data = body.to_vec();
    let w = thread::spawn(move || stdin.write_all(&data).unwrap());
    let out = c.wait_with_output().unwrap();
    w.join().unwrap();
    assert!(
        out.status.success(),
        "{tool} -d: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(out.stdout)
}

const CASES: [(&str, &str); 6] = [
    ("gzip, deflate, br, zstd", "br"),
    ("gzip, zstd", "zstd"),
    ("gzip, deflate, br;q=0, zstd", "zstd"),
    ("gzip", "gzip"),
    ("deflate", "deflate"),
    ("identity, gzip;q=0.5", "gzip"),
];

/// A streamed download (events, then a few large writes) compressed with each coding:
/// chunked on HTTP/1.1, decodable with our decoders and the command-line tools.
#[test]
fn streamed_responses_decode_with_every_coding() {
    let mut want = Vec::new();
    for i in 0..300 {
        want.extend_from_slice(event(i).as_bytes());
    }
    let page = "<li class=\"row\">all work and no play makes jack a dull boy</li>\n".repeat(4000);
    for _ in 0..3 {
        want.extend_from_slice(page.as_bytes());
    }
    let app = Router::new()
        .get("/download", move |ctx: &mut Context| {
            let mut h = Headers::new();
            h.set("Content-Type", "text/html; charset=utf-8");
            // A length given for a streamed body cannot survive compression.
            h.set("Content-Length", "999");
            let s = ctx.stream_response(200, h).unwrap();
            let page = page.clone();
            thread::spawn(move || {
                for i in 0..300 {
                    s.write(event(i).as_bytes()).unwrap();
                }
                for _ in 0..3 {
                    s.write(page.as_bytes()).unwrap();
                }
                s.finish();
            });
        })
        .layer(middleware::compress(all_codings()));
    let e = start(app);
    let mut s = connect(e.local_addrs()[0]);
    for (accept, coding) in CASES {
        // All on one keep-alive connection: each stream ends cleanly.
        get(&mut s, "/download", accept);
        let (status, h) = read_head(&mut s);
        assert_eq!(status, 200);
        assert_eq!(
            h.get("content-encoding").map(String::as_str),
            Some(coding),
            "{accept}"
        );
        assert_eq!(h.get("vary").map(String::as_str), Some("Accept-Encoding"));
        assert_eq!(
            h.get("transfer-encoding").map(String::as_str),
            Some("chunked")
        );
        assert!(!h.contains_key("content-length"), "{h:?}");
        let mut body = Vec::new();
        let mut chunks = 0;
        while let Some(c) = read_chunk(&mut s) {
            body.extend_from_slice(&c);
            chunks += 1;
        }
        assert!(chunks > 300, "{coding}: a chunk per write ({chunks})");
        assert!(
            body.len() < want.len() / 4,
            "{coding}: {} bytes",
            body.len()
        );
        let mut d = Dec::new(coding);
        let mut out = Vec::new();
        d.feed(&body, &mut out);
        assert!(d.done(), "{coding}: the stream is ended");
        assert!(out == want, "{coding}: ours");
        if let Some(out) = cli_decode(coding, &body) {
            assert!(out == want, "{coding}: command-line tool");
        }
    }
    stop(&e);
}

/// The SSE handler of the lock-step tests: writes event `i`, then waits until the client has
/// decoded it before writing the next, so an encoder that held output back would stall it.
fn lockstep_app(n: usize, acks: Arc<Mutex<Receiver<usize>>>) -> Router {
    Router::new()
        .get("/events", move |ctx: &mut Context| {
            let mut h = Headers::new();
            h.set("Content-Type", "text/event-stream");
            h.set("Cache-Control", "no-cache");
            let s = ctx.stream_response(200, h).unwrap();
            let acks = acks.clone();
            thread::spawn(move || {
                let acks = acks.lock().unwrap();
                for i in 0..n {
                    s.write(event(i).as_bytes()).unwrap();
                    assert_eq!(
                        acks.recv_timeout(Duration::from_secs(10)),
                        Ok(i),
                        "client never decoded event {i}"
                    );
                }
                s.finish();
            });
        })
        .layer(middleware::compress(all_codings()))
}

/// Server-sent events over HTTP/1.1: each event can be decoded from the bytes received while
/// the server waits before writing the next one.
#[test]
fn sse_events_arrive_one_by_one() {
    const N: usize = 20;
    let (tx, rx): (Sender<usize>, _) = mpsc::channel();
    let e = start(lockstep_app(N, Arc::new(Mutex::new(rx))));
    for (accept, coding) in CASES {
        let mut s = connect(e.local_addrs()[0]);
        get(&mut s, "/events", accept);
        let (_, h) = read_head(&mut s);
        assert_eq!(h.get("content-encoding").map(String::as_str), Some(coding));
        let mut d = Dec::new(coding);
        let mut out = Vec::new();
        let mut want = Vec::new();
        for i in 0..N {
            want.extend_from_slice(event(i).as_bytes());
            // The server writes nothing more until told: what decodes now is all there is.
            let chunk = read_chunk(&mut s).expect("an event");
            d.feed(&chunk, &mut out);
            assert!(out == want, "{coding}: event {i} decodes on arrival");
            tx.send(i).unwrap();
        }
        assert!(
            read_chunk(&mut s).is_some(),
            "{coding}: the end of the stream"
        );
        assert!(read_chunk(&mut s).is_none());
    }
    stop(&e);
}

/// The same over HTTP/2: each event arrives in DATA that decodes to it.
#[test]
fn sse_over_http2_events_arrive_one_by_one() {
    const N: usize = 10;
    let (tx, rx) = mpsc::channel();
    let e = start(lockstep_app(N, Arc::new(Mutex::new(rx))));
    let addr = e.local_addrs()[0];
    let c = H2Client::dial_blocking(&e, addr, None, H2Options::default()).unwrap();
    for (accept, coding) in [("br", "br"), ("zstd", "zstd"), ("gzip", "gzip")] {
        let (etx, erx) = mpsc::channel();
        let up = c.open(
            ClientRequest::get(&format!("http://{addr}/events")).header("accept-encoding", accept),
            move |ev| {
                let _ = etx.send(match ev {
                    H2Event::Head { headers, .. } => {
                        Err(headers.get("content-encoding").unwrap_or("").to_owned())
                    }
                    H2Event::Data(d) => Ok(d.to_vec()),
                    H2Event::End => Err("end".into()),
                    H2Event::Trailers(_) => Err("trailers".into()),
                    H2Event::Error(e) => Err(format!("error {e}")),
                });
            },
        );
        assert!(up.finish(), "no request body");
        let next = || erx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(next(), Err(coding.to_owned()));
        let mut d = Dec::new(coding);
        let (mut out, mut want) = (Vec::new(), Vec::new());
        for i in 0..N {
            want.extend_from_slice(event(i).as_bytes());
            while out.len() < want.len() {
                match next() {
                    Ok(data) => d.feed(&data, &mut out),
                    Err(e) => panic!("{coding}: {e} before event {i}"),
                }
            }
            assert!(out == want, "{coding}: event {i}");
            tx.send(i).unwrap();
        }
        loop {
            match next() {
                Ok(data) => d.feed(&data, &mut out),
                Err(e) if e == "end" => break,
                Err(e) => panic!("{coding}: {e}"),
            }
        }
        assert!(d.done() && out == want, "{coding}: complete");
    }
    stop(&e);
}

/// HTTP/1.0: the compressed body is close-delimited.
#[test]
fn close_delimited_stream_is_compressed() {
    let app = Router::new()
        .get("/s", |ctx: &mut Context| {
            let mut h = Headers::new();
            h.set("Content-Type", "application/json");
            let s = ctx.stream_response(200, h).unwrap();
            for i in 0..50 {
                s.write(format!("{{\"n\":{i},\"pad\":\"aaaaaaaaaaaaaaaa\"}}\n").as_bytes())
                    .unwrap();
            }
            s.finish();
        })
        .layer(middleware::compress(all_codings()));
    let e = start(app);
    let mut s = connect(e.local_addrs()[0]);
    s.write_all(b"GET /s HTTP/1.0\r\nAccept-Encoding: zstd\r\n\r\n")
        .unwrap();
    let (_, h) = read_head(&mut s);
    assert_eq!(h.get("content-encoding").map(String::as_str), Some("zstd"));
    assert!(!h.contains_key("transfer-encoding"));
    let mut body = Vec::new();
    s.read_to_end(&mut body).unwrap();
    let want: String = (0..50)
        .map(|i| format!("{{\"n\":{i},\"pad\":\"aaaaaaaaaaaaaaaa\"}}\n"))
        .collect();
    assert_eq!(
        akio_zstd::decompress(&body, 1 << 20).unwrap(),
        want.as_bytes()
    );
    stop(&e);
}

/// What stays as written: streams without the switch, already-encoded bodies, binary types,
/// other statuses, clients that accept no coding; HEAD gets the head of the coding only.
#[test]
fn streams_left_alone() {
    let stream = |ctx: &mut Context, status: u16, ty: &str, enc: Option<&str>| {
        let mut h = Headers::new();
        h.set("Content-Type", ty);
        if let Some(enc) = enc {
            h.set("Content-Encoding", enc);
        }
        let s = ctx.stream_response(status, h).unwrap();
        s.write(b"plain text, plain text, plain text").unwrap();
        s.finish();
    };
    let routes = || {
        Router::new()
            .get("/text", move |ctx: &mut Context| {
                stream(ctx, 200, "text/plain", None);
            })
            .get("/encoded", move |ctx: &mut Context| {
                stream(ctx, 200, "text/plain", Some("identity"));
            })
            .get("/bin", move |ctx: &mut Context| {
                stream(ctx, 200, "application/octet-stream", None);
            })
            .get("/missing", move |ctx: &mut Context| {
                stream(ctx, 404, "text/plain", None);
            })
            .get("/buffered", |ctx: &mut Context| {
                ctx.text(200, "buffered ".repeat(500));
            })
    };
    let off = start(
        routes()
            .layer(middleware::compress(Compress::default()))
            .layer(middleware::etag()),
    );
    let on = start(
        routes()
            .layer(middleware::compress(all_codings()))
            .layer(middleware::etag()),
    );
    let fetch = |e: &Engine, req: &str| {
        let mut s = connect(e.local_addrs()[0]);
        s.write_all(req.as_bytes()).unwrap();
        let (status, h) = read_head(&mut s);
        let mut body = Vec::new();
        if !req.starts_with("HEAD") && h.contains_key("transfer-encoding") {
            while let Some(c) = read_chunk(&mut s) {
                body.extend_from_slice(&c);
            }
        }
        (status, h, body)
    };
    let req = |path: &str, accept: &str| {
        format!("GET {path} HTTP/1.1\r\nHost: x\r\nAccept-Encoding: {accept}\r\n\r\n")
    };
    for (e, path, accept, coded) in [
        (&off, "/text", "gzip", None),
        (&on, "/text", "gzip", Some("gzip")),
        (&on, "/text", "", None),
        (&on, "/text", "compress, gzip;q=0", None),
        (&on, "/encoded", "gzip", Some("identity")),
        (&on, "/bin", "gzip", None),
        (&on, "/missing", "gzip", None),
    ] {
        let (_, h, body) = fetch(e, &req(path, accept));
        assert_eq!(
            h.get("content-encoding").map(String::as_str),
            coded,
            "{path} {accept}"
        );
        // A streamed body has no ETag: it is not known when the head goes out.
        assert!(!h.contains_key("etag"), "{path}: {h:?}");
        if coded != Some("gzip") {
            assert_eq!(body, b"plain text, plain text, plain text", "{path}");
            assert!(
                !h.contains_key("vary") || path == "/encoded",
                "{path}: {h:?}"
            );
        }
    }
    // Buffered responses are compressed whether or not streams are.
    let (_, h, _) = fetch(&off, &req("/buffered", "gzip"));
    assert_eq!(h.get("content-encoding").map(String::as_str), Some("gzip"));
    // HEAD: the head a GET would have, no body.
    let (status, h, _) = fetch(
        &on,
        "HEAD /text HTTP/1.1\r\nHost: x\r\nAccept-Encoding: br\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert_eq!(h.get("content-encoding").map(String::as_str), Some("br"));
    stop(&off);
    stop(&on);
}

/// Counts the guards alive; dropping one counts it out.
struct Guard(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for Guard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[test]
fn a_filter_of_its_own_sets_the_coding_and_keeps_a_guard_until_the_stream_ends() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let alive = Arc::new(AtomicUsize::new(0));
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let go_rx = Arc::new(Mutex::new(go_rx));
    let a2 = alive.clone();
    let app = Router::new()
        .get("/events", move |ctx: &mut Context| {
            let mut h = Headers::new();
            h.set("Content-Type", "text/event-stream");
            let s = ctx.stream_response(200, h).unwrap();
            let go = go_rx.clone();
            thread::spawn(move || {
                s.write(b"data: one\n\n").unwrap();
                let _ = go.lock().unwrap().recv_timeout(Duration::from_secs(5));
                // A client that went makes the write fail: the stream is dropped unfinished.
                if s.write(b"data: two\n\n").is_ok() {
                    s.finish();
                }
            });
        })
        .layer(move |ctx: &mut Context, next: &dyn akio_http::Service| {
            let alive = a2.clone();
            ctx.add_response_filter(
                move |resp: &mut akio_http::Response, _: &akio_http::Request| {
                    if !resp.is_streaming() {
                        return;
                    }
                    let coding = akio_http::Coding::zstd(1, 17);
                    resp.set_stream_coding(Some(coding));
                    assert_eq!(resp.stream_coding(), Some(coding));
                    resp.headers.set("Content-Encoding", coding.name());
                    alive.fetch_add(1, Ordering::SeqCst);
                    resp.keep_until_sent(Guard(alive));
                },
            );
            next.call(ctx);
        });
    let e = start(app);
    let wait_none = |what: &str| {
        for _ in 0..500 {
            if alive.load(Ordering::SeqCst) == 0 {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("{what}: the guard was kept");
    };
    // To its end: decoded event by event; the guard goes when the stream is finished.
    let mut s = connect(e.local_addrs()[0]);
    get(&mut s, "/events", "zstd");
    let (status, h) = read_head(&mut s);
    assert_eq!(
        (status, h.get("content-encoding").map(String::as_str)),
        (200, Some("zstd"))
    );
    let mut dec = Dec::new("zstd");
    let mut out = Vec::new();
    dec.feed(&read_chunk(&mut s).unwrap(), &mut out);
    assert_eq!(out, b"data: one\n\n");
    assert_eq!(
        alive.load(Ordering::SeqCst),
        1,
        "kept while the stream is open"
    );
    go_tx.send(()).unwrap();
    while let Some(c) = read_chunk(&mut s) {
        dec.feed(&c, &mut out);
    }
    assert_eq!(out, b"data: one\n\ndata: two\n\n");
    assert!(dec.done());
    wait_none("finished");
    // A client that goes: the guard goes with the stream.
    let mut s = connect(e.local_addrs()[0]);
    get(&mut s, "/events", "zstd");
    let _ = read_head(&mut s);
    let _ = read_chunk(&mut s);
    assert_eq!(alive.load(Ordering::SeqCst), 1);
    drop(s);
    thread::sleep(Duration::from_millis(100));
    go_tx.send(()).unwrap();
    wait_none("client gone");
    // HEAD: the fields, no body, and the guard is not kept.
    let mut s = connect(e.local_addrs()[0]);
    s.write_all(b"HEAD /events HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let (_, h) = read_head(&mut s);
    assert_eq!(h.get("content-encoding").map(String::as_str), Some("zstd"));
    go_tx.send(()).unwrap();
    wait_none("HEAD");
    stop(&e);
}
