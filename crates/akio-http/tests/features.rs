//! Streaming bodies, static files, compression, ETag, CSRF, rate limiting.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{
    BodyEvent, Context, Headers, Router, Service, Streaming,
    files::Files,
    middleware::{self, Compress},
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

fn start<S: Service>(s: S) -> Engine {
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
                .serve(serve(s)),
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

fn read_retry(s: &mut TcpStream, buf: &mut [u8]) {
    let mut got = 0;
    while got < buf.len() {
        match s.read(&mut buf[got..]) {
            Ok(0) => panic!("eof after {got}/{}", buf.len()),
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => panic!("read: {e}"),
        }
    }
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    s.set_nodelay(true).unwrap();
    s
}

struct Resp {
    status: u16,
    h: HashMap<String, String>,
    body: Vec<u8>,
}

impl Resp {
    fn header(&self, n: &str) -> Option<&str> {
        self.h.get(n).map(String::as_str)
    }
}

/// Reads a response framed by Content-Length or chunked; `head_only` for HEAD answers.
fn read_resp(s: &mut TcpStream, head_only: bool) -> Resp {
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        read_retry(s, &mut b);
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
    let h: HashMap<String, String> = lines
        .filter(|l| !l.is_empty())
        .map(|l| {
            let (k, v) = l.split_once(':').unwrap();
            (k.to_ascii_lowercase(), v.trim().to_owned())
        })
        .collect();
    let mut body = Vec::new();
    if !head_only && status != 204 && status != 304 {
        if h.get("transfer-encoding").map(String::as_str) == Some("chunked") {
            loop {
                let mut line = Vec::new();
                while !line.ends_with(b"\r\n") {
                    read_retry(s, &mut b);
                    line.push(b[0]);
                }
                let n = usize::from_str_radix(
                    std::str::from_utf8(&line[..line.len() - 2]).unwrap(),
                    16,
                )
                .unwrap();
                let mut chunk = vec![0; n + 2];
                read_retry(s, &mut chunk);
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..n]);
            }
        } else if let Some(len) = h.get("content-length") {
            body = vec![0; len.parse().unwrap()];
            read_retry(s, &mut body);
        }
    }
    Resp { status, h, body }
}

fn get(addr: SocketAddr, path: &str, extra: &str) -> Resp {
    let mut s = connect(addr);
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n{extra}\r\n").as_bytes())
        .unwrap();
    read_resp(&mut s, false)
}

fn tempdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("akio-http-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

// ---- streaming responses and requests --------------------------------------------------------

#[test]
fn streamed_response_is_chunked_and_holds_back_later_pipelined_responses() {
    let app = Router::new()
        .get("/sse", |ctx: &mut Context| {
            let mut h = Headers::new();
            h.set("Content-Type", "text/event-stream");
            let stream = ctx.stream_response(200, h).unwrap();
            thread::spawn(move || {
                for i in 0..3 {
                    stream.write(format!("data: {i}\n\n").as_bytes()).unwrap();
                    thread::sleep(Duration::from_millis(60));
                }
                stream.finish();
            });
        })
        .get("/after", |ctx: &mut Context| ctx.text(200, "after"));
    let e = start(app);
    let mut s = connect(e.local_addrs()[0]);
    // Both requests in one write: the second answer must wait for the stream to end.
    s.write_all(b"GET /sse HTTP/1.1\r\nHost: x\r\n\r\nGET /after HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let r = read_resp(&mut s, false);
    assert_eq!(r.header("transfer-encoding"), Some("chunked"));
    assert_eq!(r.header("content-type"), Some("text/event-stream"));
    assert_eq!(r.body, b"data: 0\n\ndata: 1\n\ndata: 2\n\n");
    let r2 = read_resp(&mut s, false);
    assert_eq!(r2.body, b"after");
    stop(&e);
}

#[test]
fn streamed_response_over_http10_is_close_delimited() {
    let app = Router::new().get("/s", |ctx: &mut Context| {
        let stream = ctx.stream_response(200, Headers::new()).unwrap();
        stream.write(b"part one ").unwrap();
        stream.write(b"part two").unwrap();
        stream.finish();
    });
    let e = start(app);
    let mut s = connect(e.local_addrs()[0]);
    s.write_all(b"GET /s HTTP/1.0\r\n\r\n").unwrap();
    let mut all = Vec::new();
    s.read_to_end(&mut all).unwrap();
    let text = String::from_utf8(all).unwrap();
    assert!(text.ends_with("\r\n\r\npart one part two"), "{text:?}");
    assert!(!text.to_ascii_lowercase().contains("transfer-encoding"));
    stop(&e);
}

#[test]
fn streamed_request_bodies_arrive_in_chunks_without_a_size_limit() {
    let total = Arc::new(AtomicUsize::new(0));
    let chunks = Arc::new(AtomicUsize::new(0));
    let (t, c) = (total, chunks.clone());
    let app = Router::new().post(
        "/upload",
        Streaming(move |ctx: &mut Context| {
            let (t, c) = (t.clone(), c.clone());
            let mut sum = 0usize;
            ctx.on_body(move |ctx, ev| match ev {
                BodyEvent::Chunk(b) => {
                    sum += b.len();
                    c.fetch_add(1, Ordering::SeqCst);
                }
                BodyEvent::End(trailers) => {
                    t.store(sum, Ordering::SeqCst);
                    let tr = trailers.get("x-done").unwrap_or("-").to_owned();
                    ctx.text(200, format!("got {sum} {tr}"));
                }
            });
        }),
    );
    let e = start(app);
    let addr = e.local_addrs()[0];
    // Content-Length body, bigger than the default buffered limit (1 MiB).
    let body = pattern(3 << 20);
    let mut s = connect(addr);
    s.write_all(
        format!(
            "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )
    .unwrap();
    s.write_all(&body).unwrap();
    assert_eq!(
        read_resp(&mut s, false).body,
        format!("got {} -", body.len()).as_bytes()
    );
    assert!(chunks.load(Ordering::SeqCst) > 1, "delivered in pieces");
    // Chunked body with a trailer on the same connection.
    let mut wire =
        b"POST /upload HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for _ in 0..4 {
        wire.extend_from_slice(b"5\r\nhello\r\n");
    }
    wire.extend_from_slice(b"0\r\nX-Done: yes\r\n\r\n");
    s.write_all(&wire).unwrap();
    assert_eq!(read_resp(&mut s, false).body, b"got 20 yes");
    stop(&e);
}

// ---- static files ----------------------------------------------------------------------------

#[test]
fn static_files_serve_ranges_conditionals_index_and_refuse_traversal() {
    let dir = tempdir("static");
    std::fs::write(dir.join("hello.txt"), "hello static").unwrap();
    std::fs::write(dir.join("index.html"), "<h1>home</h1>").unwrap();
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("sub/index.html"), "sub index").unwrap();
    std::fs::write(
        dir.parent()
            .unwrap()
            .join(format!("secret-{}.txt", std::process::id())),
        "secret",
    )
    .unwrap();
    let big = pattern(2 << 20);
    std::fs::write(dir.join("big.bin"), &big).unwrap();
    std::fs::write(dir.join("app.js"), "console.log(1)").unwrap();
    std::fs::write(dir.join("app.js.gz"), b"GZ-DATA").unwrap();
    let files = Files::new(&dir)
        .max_cached_bytes(64 << 10)
        .check_interval(Duration::ZERO);
    let e = start(Router::new().get("/s/*path", files));
    let a = e.local_addrs()[0];

    let r = get(a, "/s/hello.txt", "");
    assert_eq!((r.status, r.body.as_slice()), (200, &b"hello static"[..]));
    assert_eq!(r.header("content-type"), Some("text/plain; charset=utf-8"));
    assert_eq!(r.header("accept-ranges"), Some("bytes"));
    let etag = r.header("etag").unwrap().to_owned();
    let lm = r.header("last-modified").unwrap().to_owned();
    // Conditional requests.
    assert_eq!(
        get(a, "/s/hello.txt", &format!("If-None-Match: {etag}\r\n")).status,
        304
    );
    assert_eq!(
        get(a, "/s/hello.txt", &format!("If-Modified-Since: {lm}\r\n")).status,
        304
    );
    assert_eq!(
        get(a, "/s/hello.txt", "If-None-Match: \"other\"\r\n").status,
        200
    );
    // Dates compare by time, not by text: a later date is "not modified", an earlier one is.
    assert_eq!(
        get(
            a,
            "/s/hello.txt",
            "If-Modified-Since: Fri, 01 Jan 2100 00:00:00 GMT\r\n"
        )
        .status,
        304
    );
    assert_eq!(
        get(
            a,
            "/s/hello.txt",
            "If-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\n"
        )
        .status,
        200
    );
    // If-None-Match wins over If-Modified-Since.
    assert_eq!(
        get(
            a,
            "/s/hello.txt",
            &format!("If-None-Match: \"other\"\r\nIf-Modified-Since: {lm}\r\n")
        )
        .status,
        200
    );
    // Preconditions for state-checking clients: 412 unless the representation matches.
    assert_eq!(
        get(a, "/s/hello.txt", &format!("If-Match: {etag}\r\n")).status,
        200
    );
    assert_eq!(get(a, "/s/hello.txt", "If-Match: *\r\n").status, 200);
    let r = get(a, "/s/hello.txt", "If-Match: \"other\"\r\n");
    assert_eq!((r.status, r.header("etag")), (412, Some(etag.as_str())));
    assert_eq!(
        get(a, "/s/hello.txt", &format!("If-Match: W/{etag}\r\n")).status,
        412,
        "If-Match uses the strong comparison"
    );
    assert_eq!(
        get(
            a,
            "/s/hello.txt",
            "If-Unmodified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\n"
        )
        .status,
        412
    );
    assert_eq!(
        get(a, "/s/hello.txt", &format!("If-Unmodified-Since: {lm}\r\n")).status,
        200
    );
    // If-Range: the range only while the client's copy is current.
    let r = get(
        a,
        "/s/hello.txt",
        &format!("Range: bytes=0-4\r\nIf-Range: {etag}\r\n"),
    );
    assert_eq!((r.status, r.body.as_slice()), (206, &b"hello"[..]));
    let r = get(
        a,
        "/s/hello.txt",
        &format!("Range: bytes=0-4\r\nIf-Range: {lm}\r\n"),
    );
    assert_eq!(r.status, 206);
    let r = get(
        a,
        "/s/hello.txt",
        "Range: bytes=0-4\r\nIf-Range: \"stale\"\r\n",
    );
    assert_eq!((r.status, r.body.as_slice()), (200, &b"hello static"[..]));
    let r = get(
        a,
        "/s/hello.txt",
        "Range: bytes=0-4\r\nIf-Range: Thu, 01 Jan 1970 00:00:00 GMT\r\n",
    );
    assert_eq!(r.status, 200);
    let r = get(
        a,
        "/s/hello.txt",
        &format!("Range: bytes=0-4\r\nIf-Range: W/{etag}\r\n"),
    );
    assert_eq!(r.status, 200, "a weak tag never satisfies If-Range");
    // Ranges.
    let r = get(a, "/s/hello.txt", "Range: bytes=6-\r\n");
    assert_eq!((r.status, r.body.as_slice()), (206, &b"static"[..]));
    assert_eq!(r.header("content-range"), Some("bytes 6-11/12"));
    let r = get(a, "/s/hello.txt", "Range: bytes=-6\r\n");
    assert_eq!(r.body, b"static");
    let r = get(a, "/s/hello.txt", "Range: bytes=50-60\r\n");
    assert_eq!(r.status, 416);
    assert_eq!(r.header("content-range"), Some("bytes */12"));
    // Directories and index files.
    assert_eq!(get(a, "/s/", "").body, b"<h1>home</h1>");
    assert_eq!(get(a, "/s/sub", "").body, b"sub index");
    // Traversal and odd paths.
    for p in [
        "/s/../secret.txt",
        "/s/%2e%2e/x",
        "/s/a/..%2f..%2fx",
        "/s/%00",
        "/s/a%5cb",
    ] {
        assert_eq!(get(a, p, "").status, 404, "{p}");
    }
    assert_eq!(get(a, "/s/missing.txt", "").status, 404);
    // HEAD: headers only, the real length.
    let mut s = connect(a);
    s.write_all(b"HEAD /s/hello.txt HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let r = read_resp(&mut s, true);
    assert_eq!((r.status, r.header("content-length")), (200, Some("12")));
    // Pre-compressed twin for clients that accept it.
    let r = get(a, "/s/app.js", "Accept-Encoding: gzip, br\r\n");
    assert_eq!(r.header("content-encoding"), Some("gzip"));
    assert_eq!(r.body, b"GZ-DATA");
    assert_eq!(
        r.header("content-type"),
        Some("text/javascript; charset=utf-8")
    );
    let r = get(a, "/s/app.js", "");
    assert_eq!(r.body, b"console.log(1)");
    // A file too big for the cache goes out with sendfile, byte for byte; a range of it too.
    let r = get(a, "/s/big.bin", "");
    assert_eq!(r.body.len(), big.len());
    assert!(r.body == big, "sendfile corrupted the body");
    let r = get(a, "/s/big.bin", "Range: bytes=1000000-1999999\r\n");
    assert_eq!(r.status, 206);
    assert!(r.body == big[1_000_000..2_000_000]);
    // The large file's open handle is cached; replacing the file is noticed (interval zero).
    let big_etag = get(a, "/s/big.bin", "").header("etag").unwrap().to_owned();
    assert_eq!(
        get(a, "/s/big.bin", &format!("If-None-Match: {big_etag}\r\n")).status,
        304
    );
    let big2 = pattern(3 << 20);
    std::fs::write(dir.join("big.bin.tmp"), &big2).unwrap();
    std::fs::rename(dir.join("big.bin.tmp"), dir.join("big.bin")).unwrap();
    let r = get(a, "/s/big.bin", "");
    assert!(r.body == big2, "stale open-file cache entry");
    assert_ne!(r.header("etag"), Some(big_etag.as_str()));
    std::fs::write(dir.join("big.bin"), &big).unwrap();
    // The file changes: the next request sees it (check interval is zero here).
    std::fs::write(dir.join("hello.txt"), "changed on disk!").unwrap();
    assert_eq!(get(a, "/s/hello.txt", "").body, b"changed on disk!");
    // A file response followed by a pipelined small response stays in order.
    let mut s = connect(a);
    s.write_all(
        b"GET /s/big.bin HTTP/1.1\r\nHost: x\r\n\r\nGET /s/hello.txt HTTP/1.1\r\nHost: x\r\n\r\n",
    )
    .unwrap();
    assert!(read_resp(&mut s, false).body == big);
    assert_eq!(read_resp(&mut s, false).body, b"changed on disk!");
    stop(&e);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(
        dir.parent()
            .unwrap()
            .join(format!("secret-{}.txt", std::process::id())),
    );
}

/// The parts of a `multipart/byteranges` body: `(Content-Range, data)` each.
fn byteranges(r: &Resp) -> Vec<(String, Vec<u8>)> {
    let ct = r.header("content-type").expect("content type");
    let bnd = ct
        .strip_prefix("multipart/byteranges; boundary=")
        .unwrap_or_else(|| panic!("not multipart: {ct}"));
    let delim = format!("--{bnd}");
    let body = &r.body;
    let find = |from: usize, pat: &[u8]| {
        body[from..]
            .windows(pat.len())
            .position(|w| w == pat)
            .map(|i| i + from)
    };
    let mut parts = Vec::new();
    let mut at = find(0, delim.as_bytes()).expect("first boundary");
    assert_eq!(at, 0, "no preamble");
    loop {
        at += delim.len();
        if body[at..].starts_with(b"--\r\n") {
            assert_eq!(at + 4, body.len(), "nothing after the close delimiter");
            return parts;
        }
        assert!(body[at..].starts_with(b"\r\n"));
        let head_end = find(at, b"\r\n\r\n").unwrap();
        let head = std::str::from_utf8(&body[at + 2..head_end]).unwrap();
        let cr = head
            .split("\r\n")
            .find_map(|l| l.strip_prefix("Content-Range: "))
            .expect("part Content-Range")
            .to_owned();
        assert!(head.contains("Content-Type: "), "part Content-Type");
        let next = find(head_end, format!("\r\n{delim}").as_bytes()).unwrap();
        parts.push((cr, body[head_end + 4..next].to_vec()));
        at = next + 2;
    }
}

#[test]
fn static_files_answer_multi_range_requests() {
    let dir = tempdir("multirange");
    let small = pattern(1000);
    let big = pattern(3 << 20);
    std::fs::write(dir.join("small.bin"), &small).unwrap();
    std::fs::write(dir.join("big.bin"), &big).unwrap();
    let files = Files::new(&dir)
        .max_cached_bytes(64 << 10)
        .check_interval(Duration::ZERO);
    let e = start(Router::new().get("/s/*path", files));
    let a = e.local_addrs()[0];

    // From the memory cache and from an open file (sendfile is not used for multipart).
    for (name, data) in [("small.bin", &small), ("big.bin", &big)] {
        let len = data.len();
        let path = format!("/s/{name}");
        let r = get(a, &path, "Range: bytes=0-9,500-599,-5\r\n");
        assert_eq!(r.status, 206, "{name}");
        assert!(
            r.header("content-range").is_none(),
            "no top-level Content-Range"
        );
        assert_eq!(
            r.header("content-length"),
            Some(r.body.len().to_string().as_str())
        );
        let parts = byteranges(&r);
        assert_eq!(
            parts,
            vec![
                (format!("bytes 0-9/{len}"), data[..10].to_vec()),
                (format!("bytes 500-599/{len}"), data[500..600].to_vec()),
                (
                    format!("bytes {}-{}/{len}", len - 5, len - 1),
                    data[len - 5..].to_vec()
                ),
            ],
            "{name}"
        );
        // Coalesced down to one range: a plain 206.
        let r = get(a, &path, "Range: bytes=0-9,5-20,21-30\r\n");
        assert_eq!(r.status, 206);
        assert_eq!(
            r.header("content-range"),
            Some(format!("bytes 0-30/{len}").as_str())
        );
        assert_eq!(r.body, data[..31]);
        // Unsatisfiable members are dropped.
        let r = get(a, &path, "Range: bytes=0-1,99999999-,200-201\r\n");
        assert_eq!(byteranges(&r).len(), 2);
        let r = get(a, &path, "Range: bytes=99999999-,88888888-\r\n");
        assert_eq!(r.status, 416);
        assert_eq!(
            r.header("content-range"),
            Some(format!("bytes */{len}").as_str())
        );
        // Too many ranges: the whole file.
        let many: Vec<String> = (0..40).map(|i| format!("{}-{}", i * 20, i * 20)).collect();
        let r = get(a, &path, &format!("Range: bytes={}\r\n", many.join(",")));
        assert_eq!(r.status, 200);
        assert!(r.body == *data);
    }
    // If-Range guards multi-range requests too.
    let etag = get(a, "/s/small.bin", "")
        .header("etag")
        .unwrap()
        .to_owned();
    let r = get(
        a,
        "/s/small.bin",
        &format!("Range: bytes=0-1,500-501\r\nIf-Range: {etag}\r\n"),
    );
    assert_eq!(byteranges(&r).len(), 2);
    let r = get(
        a,
        "/s/small.bin",
        "Range: bytes=0-1,500-501\r\nIf-Range: \"old\"\r\n",
    );
    assert_eq!((r.status, r.body.len()), (200, small.len()));
    // Parts adding up to more than 1 MiB: the whole file instead.
    let r = get(a, "/s/big.bin", "Range: bytes=0-699999,1000000-1699999\r\n");
    assert_eq!(r.status, 200);
    assert!(r.body == big);
    // HEAD ignores ranges.
    let mut s = connect(a);
    s.write_all(b"HEAD /s/small.bin HTTP/1.1\r\nHost: x\r\nRange: bytes=0-1,5-6\r\n\r\n")
        .unwrap();
    let r = read_resp(&mut s, true);
    assert_eq!((r.status, r.header("content-length")), (200, Some("1000")));
    stop(&e);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn static_files_open_file_cache_survives_churn() {
    let dir = tempdir("churn");
    let names: Vec<String> = (0..12).map(|i| format!("f{i}.bin")).collect();
    let datas: Vec<Vec<u8>> = (0..12).map(|i| pattern(100_000 + i * 1000)).collect();
    for (n, d) in names.iter().zip(&datas) {
        std::fs::write(dir.join(n), d).unwrap();
    }
    let files = Files::new(&dir)
        .max_cached_bytes(1024)
        .max_open_files(3)
        .check_interval(Duration::from_secs(3600));
    let e = start(Router::new().get("/s/*path", files));
    let a = e.local_addrs()[0];
    // Many more files than slots, in rounds: every response is right.
    for round in 0..3 {
        for i in (0..names.len()).rev().chain(0..names.len()) {
            let r = get(a, &format!("/s/{}", names[i]), "");
            assert_eq!(r.status, 200);
            assert!(r.body == datas[i], "round {round} file {i}");
            let r = get(
                a,
                &format!("/s/{}", names[i]),
                "Range: bytes=10-19,2000-2009\r\n",
            );
            assert_eq!(byteranges(&r)[1].1, datas[i][2000..2010]);
        }
    }
    stop(&e);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A tree of files under a fresh directory.
fn tree(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let d = tempdir(name);
    for (p, body) in files {
        let full = d.join(p);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, body).unwrap();
    }
    d
}

fn get_with(a: SocketAddr, path: &str, accept: &str) -> Resp {
    if accept.is_empty() {
        get(a, path, "")
    } else {
        get(a, path, &format!("Accept-Encoding: {accept}\r\n"))
    }
}

/// `n` bytes of JavaScript-like text, which compresses as such text does.
fn js_text(n: usize) -> String {
    let words = [
        "function", "return", "const", "let", "var", "if", "else", "for", "while", "this",
    ];
    let mut s = String::new();
    let mut x = 7u64;
    while s.len() < n {
        x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let w = words[(x >> 33) as usize % words.len()];
        s.push_str(&format!(
            "{w} v{}={};",
            (x >> 20) % 1000,
            (x >> 40) % 1_000_000
        ));
    }
    s.truncate(n);
    s
}

/// `n` bytes that do not compress.
fn noise(n: usize) -> Vec<u8> {
    let mut x = 11u64;
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            (x >> 56) as u8
        })
        .collect()
}

fn decode(coding: &str, body: &[u8]) -> Vec<u8> {
    match coding {
        "gzip" => akio_deflate::decompress(akio_deflate::Format::Gzip, body, 1 << 24).unwrap(),
        "br" => akio_brotli::decompress(body, 1 << 24).unwrap(),
        "zstd" => akio_zstd::decompress(body, 1 << 24).unwrap(),
        _ => body.to_vec(),
    }
}

/// Gets `path` with `accept` until its answer's `Content-Encoding` is `coding`: the copy is made
/// on the disk pool after the first request for it.
fn until_coded(a: SocketAddr, path: &str, accept: &str, coding: &str) -> Resp {
    for _ in 0..500 {
        let r = get_with(a, path, accept);
        if r.header("content-encoding").unwrap_or("") == coding {
            return r;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("{path} {accept:?}: never {coding:?}");
}

#[test]
fn compressed_copies_of_cached_files() {
    let js = js_text(20_000);
    let dir = tree(
        "packs",
        &[
            ("app.js", &js),
            ("small.txt", "short"),
            ("pic.png", &js),
            ("twin.js", &js),
            ("twin.js.gz", "gzip-twin"),
            ("big.js", &js_text(300_000)),
        ],
    );
    std::fs::write(dir.join("noise.txt"), noise(20_000)).unwrap();
    let e = start(
        Files::new(&dir)
            .check_interval(Duration::from_secs(3600))
            .twins(&["gzip"])
            .compress(&["br", "zstd", "gzip"]),
    );
    let a = e.local_addrs()[0];
    let identity = get_with(a, "/app.js", "");
    assert_eq!(identity.header("content-encoding"), None);
    assert_eq!(identity.body, js.as_bytes());
    assert_eq!(identity.header("vary"), Some("Accept-Encoding"));
    let tag = identity.header("etag").unwrap().to_owned();
    for (accept, coding) in [
        ("gzip", "gzip"),
        // Equal q: the first listed.
        ("gzip, br, zstd", "br"),
        ("br;q=0.5, zstd", "zstd"),
    ] {
        let r = until_coded(a, "/app.js", accept, coding);
        assert_eq!(decode(coding, &r.body), js.as_bytes(), "{accept}");
        assert!(
            r.body.len() < js.len() / 2,
            "{accept}: {} bytes",
            r.body.len()
        );
        let own = format!("{}-{coding}\"", tag.trim_end_matches('"'));
        assert_eq!(r.header("etag"), Some(own.as_str()), "{accept}");
        assert_eq!(r.header("accept-ranges"), None, "{accept}");
        assert_eq!(r.header("vary"), Some("Accept-Encoding"));
        assert_eq!(r.header("content-type"), identity.header("content-type"));
        assert_eq!(
            r.header("content-length").map(str::to_owned),
            Some(r.body.len().to_string())
        );
        // The copy's tag answers a conditional request.
        let r = get(
            a,
            "/app.js",
            &format!("Accept-Encoding: {accept}\r\nIf-None-Match: {own}\r\n"),
        );
        assert_eq!(r.status, 304, "{accept}");
    }
    // A range is of the file as it is.
    let r = get(
        a,
        "/app.js",
        "Accept-Encoding: gzip\r\nRange: bytes=0-3\r\n",
    );
    assert_eq!(r.status, 206);
    assert_eq!(r.body, &js.as_bytes()[..4]);
    assert_eq!(r.header("content-encoding"), None);
    // A twin on disk goes ahead of a copy.
    let r = get_with(a, "/twin.js", "gzip");
    assert_eq!(r.body, b"gzip-twin");
    // Small files, images, files that do not compress and files too large to cache go as
    // they are.
    for path in ["/small.txt", "/pic.png", "/noise.txt", "/big.js"] {
        for _ in 0..5 {
            let r = get_with(a, path, "gzip");
            assert_eq!(r.header("content-encoding"), None, "{path}");
            assert_eq!(r.header("vary"), Some("Accept-Encoding"), "{path}");
            thread::sleep(Duration::from_millis(10));
        }
    }
    // Refused, nothing is compressed.
    let r = get_with(a, "/app.js", "gzip;q=0, identity");
    assert_eq!(r.header("content-encoding"), None);
    // HEAD has the copy's fields and length.
    let mut s = connect(a);
    s.write_all(b"HEAD /app.js HTTP/1.1\r\nHost: x\r\nAccept-Encoding: zstd\r\n\r\n")
        .unwrap();
    let r = read_resp(&mut s, true);
    assert_eq!(r.header("content-encoding"), Some("zstd"));
    let zstd = get_with(a, "/app.js", "zstd");
    assert_eq!(
        r.header("content-length").map(str::to_owned),
        Some(zstd.body.len().to_string())
    );
    stop(&e);
}

#[test]
fn compressed_twins_by_q_value_among_the_configured_encodings() {
    let dir = tree(
        "twins-q",
        &[
            ("app.js", "identity-js"),
            ("app.js.br", "br-js"),
            ("app.js.zst", "zstd-js"),
            ("app.js.gz", "gzip-js"),
            ("style.css", "identity-css"),
            ("style.css.gz", "gzip-css"),
        ],
    );
    let e = start(Files::new(&dir).check_interval(Duration::from_secs(3600)));
    let a = e.local_addrs()[0];
    for (path, accept, enc, body) in [
        // Equal q: the first of br, zstd, gzip.
        ("/app.js", "gzip, br", "br", "br-js"),
        ("/app.js", "br;q=0.5, gzip", "gzip", "gzip-js"),
        ("/app.js", "zstd", "zstd", "zstd-js"),
        // q=0 refuses a coding.
        ("/app.js", "br;q=0, identity", "", "identity-js"),
        ("/app.js", "*", "br", "br-js"),
        ("/app.js", "*, br;q=0", "zstd", "zstd-js"),
        ("/app.js", "*;q=0.2, gzip;q=0.3", "gzip", "gzip-js"),
        ("/app.js", "", "", "identity-js"),
        // Names in any case, blanks around the parameters.
        ("/app.js", "GZIP", "gzip", "gzip-js"),
        ("/app.js", "gzip ; Q=0.8, br ; q = 0.1", "gzip", "gzip-js"),
        // A q value that does not parse, or above 1, counts as 1.
        ("/app.js", "gzip;q=2, br;q=0.9", "gzip", "gzip-js"),
        ("/app.js", "deflate", "", "identity-js"),
        ("/style.css", "br, gzip", "gzip", "gzip-css"),
    ] {
        // Twice: from the disk pool, then from the cache on the I/O thread.
        for _ in 0..2 {
            let r = get_with(a, path, accept);
            assert_eq!(r.status, 200, "{path} {accept:?}");
            assert_eq!(
                (
                    r.header("content-encoding").unwrap_or(""),
                    r.body.as_slice()
                ),
                (enc, body.as_bytes()),
                "{path} {accept:?}"
            );
            assert_eq!(r.header("vary"), Some("Accept-Encoding"));
        }
    }
    // Two Accept-Encoding fields are one list.
    let r = get(
        a,
        "/app.js",
        "Accept-Encoding: br;q=0.1\r\nAccept-Encoding: zstd\r\n",
    );
    assert_eq!(r.header("content-encoding"), Some("zstd"));
    stop(&e);

    // Only the twins configured, in the order given among equals.
    let e = start(
        Files::new(&dir)
            .twins(&["gzip", "zstd", "deflate", "gzip"])
            .check_interval(Duration::ZERO),
    );
    let a = e.local_addrs()[0];
    for (accept, enc) in [
        ("br, zstd, gzip", "gzip"),
        ("br, zstd", "zstd"),
        ("br", ""),
        ("*", "gzip"),
    ] {
        let r = get_with(a, "/app.js", accept);
        assert_eq!(
            r.header("content-encoding").unwrap_or(""),
            enc,
            "{accept:?}"
        );
        assert_eq!(r.header("vary"), Some("Accept-Encoding"));
    }
    stop(&e);

    // None: no lookups and no Vary; a twin is a file like another.
    let e = start(Files::new(&dir).twins(&[]));
    let a = e.local_addrs()[0];
    let r = get_with(a, "/app.js", "br, gzip");
    assert_eq!(
        (
            r.header("content-encoding"),
            r.header("vary"),
            r.body.as_slice()
        ),
        (None, None, &b"identity-js"[..])
    );
    assert_eq!(get(a, "/app.js.gz", "").body, b"gzip-js");
    stop(&e);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn serve_takes_the_path_the_caller_names() {
    let dir = tree(
        "serve-path",
        &[
            ("ok.txt", "ok"),
            ("d/index.html", "d-index"),
            ("a b.txt", "ab"),
        ],
    );
    let files = Files::new(&dir).check_interval(Duration::ZERO);
    // A caller that strips its own prefix and routes by a path of its own.
    let e = start(move |ctx: &mut Context| {
        let p = ctx
            .path()
            .strip_prefix("/assets")
            .unwrap_or("/nope")
            .to_owned();
        files.serve(ctx, &p);
    });
    let a = e.local_addrs()[0];
    assert_eq!(get(a, "/assets/ok.txt", "").body, b"ok");
    assert_eq!(get(a, "/assets/d/", "").body, b"d-index");
    assert_eq!(get(a, "/assets/a%20b.txt", "").body, b"ab");
    assert_eq!(get(a, "/ok.txt", "").status, 404);
    // Still checked: what climbs above the root.
    for p in ["/assets/../ok.txt", "/assets/%2e%2e/ok.txt", "/assets/a%00"] {
        assert_eq!(get(a, p, "").status, 404, "{p}");
    }
    stop(&e);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn try_paths_serve_the_first_candidate_that_exists() {
    let dir = tree(
        "try-paths",
        &[
            ("index.html", "app"),
            ("assets/a.js", "js"),
            ("docs/index.html", "docs"),
            ("plain/x.txt", "x"),
            (".app/index.html", "hidden-app"),
            ("a", "a"),
        ],
    );
    for check in [Duration::from_secs(3600), Duration::ZERO] {
        let e = start(
            Files::new(&dir)
                .try_paths(&["{path}", "{path}/", "/index.html"])
                .check_interval(check),
        );
        let a = e.local_addrs()[0];
        for (path, status, body) in [
            ("/assets/a.js", 200, "js"),
            // A directory, served by its index, not redirected.
            ("/docs", 200, "docs"),
            ("/docs/", 200, "docs"),
            ("/some/client/route", 200, "app"),
            // No index: falls through.
            ("/plain/", 200, "app"),
            ("/", 200, "app"),
            // A file asked for as a directory is passed over.
            ("/a/", 200, "app"),
            ("/../secret", 404, "Not Found"),
        ] {
            // Twice: resolved on the disk pool, then (with a check interval) from what was
            // resolved.
            for _ in 0..2 {
                let r = get(a, path, "");
                assert_eq!(
                    (r.status, r.body.as_slice()),
                    (status, body.as_bytes()),
                    "{path} {check:?}"
                );
                assert_eq!(r.header("location"), None);
            }
        }
        stop(&e);
    }

    // None exists: 404. A candidate outside the root, or hidden, is passed over.
    let e = start(
        Files::new(&dir)
            .try_paths(&["/../a", "{path}", "/.app/index.html", "/missing.html"])
            .hide(|p| {
                p.split('/')
                    .any(|s| s.starts_with('.') && s != "." && s != "..")
            }),
    );
    let a = e.local_addrs()[0];
    assert_eq!(get(a, "/a", "").body, b"a");
    assert_eq!(get(a, "/nope", "").status, 404);
    // The path asked for is hidden too.
    assert_eq!(get(a, "/.app/index.html", "").status, 404);
    stop(&e);

    // A resolution that changes on disk is followed with a check interval of 0.
    let e = start(
        Files::new(&dir)
            .try_paths(&["{path}", "/index.html"])
            .check_interval(Duration::ZERO),
    );
    let a = e.local_addrs()[0];
    assert_eq!(get(a, "/late.txt", "").body, b"app");
    std::fs::write(dir.join("late.txt"), "late").unwrap();
    assert_eq!(get(a, "/late.txt", "").body, b"late");
    std::fs::remove_file(dir.join("late.txt")).unwrap();
    assert_eq!(get(a, "/late.txt", "").body, b"app");
    stop(&e);

    // Many distinct paths: what is kept stays bounded, and answers stay right.
    let e = start(
        Files::new(&dir)
            .try_paths(&["{path}", "/index.html"])
            .check_interval(Duration::from_secs(3600)),
    );
    let a = e.local_addrs()[0];
    let mut s = connect(a);
    for i in 0..5000 {
        s.write_all(format!("GET /r/{i} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .unwrap();
        let r = read_resp(&mut s, false);
        assert_eq!(r.body, b"app", "{i}");
    }
    assert_eq!(get(a, "/assets/a.js", "").body, b"js");
    stop(&e);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn directory_listings() {
    let dir = tree(
        "listing",
        &[
            ("files/b.txt", "bb"),
            ("files/a&b<c>.txt", "a"),
            ("files/q?x.txt", "q"),
            ("files/.hidden", "h"),
            ("files/sub/z", "z"),
            ("withindex/index.html", "idx"),
            ("withindex/other", "o"),
        ],
    );
    let e = start(Files::new(&dir).list_directories(10_000));
    let a = e.local_addrs()[0];
    let r = get(a, "/files/", "");
    let body = String::from_utf8(r.body.clone()).unwrap();
    assert_eq!(r.status, 200, "{body}");
    assert_eq!(r.header("content-type"), Some("text/html; charset=utf-8"));
    assert_eq!(r.header("cache-control"), Some("no-cache"));
    for want in [
        "<title>Index of /files/</title>",
        "<h1>Index of /files/</h1>",
        r#"<a href="../">../</a>"#,
        r#"<a href="./sub/">sub/</a>"#,
        r#"<a href="./a&amp;b%3Cc%3E.txt">a&amp;b&lt;c&gt;.txt</a>"#,
        r#"<a href="./q%3Fx.txt">q?x.txt</a>"#,
        r#"<a href="./b.txt">b.txt</a></td><td>2</td>"#,
    ] {
        assert!(body.contains(want), "listing lacks {want}:\n{body}");
    }
    assert!(!body.contains("hidden"), "{body}");
    assert!(
        body.find("sub/").unwrap() < body.find("a&amp;b").unwrap(),
        "directories first:\n{body}"
    );
    assert!(!body.contains("Only the first"));
    // The root has no parent link; an index file wins; without its slash a directory is not
    // listed.
    let root = String::from_utf8(get(a, "/", "").body).unwrap();
    assert!(
        root.contains("<title>Index of /</title>") && !root.contains("../"),
        "{root}"
    );
    assert_eq!(get(a, "/withindex/", "").body, b"idx");
    assert_eq!(get(a, "/files", "").status, 404);
    let r = {
        let mut s = connect(a);
        s.write_all(b"HEAD /files/ HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        read_resp(&mut s, true)
    };
    assert_eq!(r.status, 200);
    stop(&e);

    // Without listings: 404.
    let e = start(Files::new(&dir));
    assert_eq!(get(e.local_addrs()[0], "/files/", "").status, 404);
    stop(&e);

    // At most max entries read, and the page says so.
    let many = tempdir("listing-many");
    std::fs::create_dir_all(many.join("d")).unwrap();
    for i in 0..20 {
        std::fs::write(many.join(format!("d/f{i:02}.txt")), "x").unwrap();
    }
    let e = start(Files::new(&many).list_directories(5));
    let body = String::from_utf8(get(e.local_addrs()[0], "/d/", "").body).unwrap();
    assert_eq!(body.matches("<tr><td><a href=\"./f").count(), 5, "{body}");
    assert!(
        body.contains("Only the first 5 entries the directory gave are listed."),
        "{body}"
    );
    stop(&e);
    let e = start(Files::new(&many).list_directories(20));
    let body = String::from_utf8(get(e.local_addrs()[0], "/d/", "").body).unwrap();
    assert_eq!(body.matches("<tr><td><a href=\"./f").count(), 20);
    assert!(!body.contains("Only the first"));
    stop(&e);

    // A directory try_paths reaches is listed, as the candidate names it.
    let e = start(
        Files::new(&dir)
            .try_paths(&["{path}/"])
            .list_directories(100),
    );
    let r = get(e.local_addrs()[0], "/files", "");
    let body = String::from_utf8(r.body).unwrap();
    assert!(
        r.status == 200 && body.contains("<title>Index of /files/</title>"),
        "{body}"
    );
    stop(&e);
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(&many).unwrap();
}

// ---- middleware ------------------------------------------------------------------------------

#[test]
fn compress_etag_and_response_time() {
    let text = "all work and no play makes jack a dull boy. ".repeat(100);
    let t = text.clone();
    let app = Router::new()
        .get("/text", move |ctx: &mut Context| ctx.text(200, t.clone()))
        .get("/tiny", |ctx: &mut Context| ctx.text(200, "tiny"))
        .get("/bin", |ctx: &mut Context| {
            ctx.bytes(200, "application/octet-stream", vec![7; 5000]);
        })
        .layer(middleware::etag())
        .layer(middleware::compress(Compress::default()))
        .layer(middleware::response_time());
    let e = start(app);
    let a = e.local_addrs()[0];
    let r = get(a, "/text", "Accept-Encoding: gzip\r\n");
    assert_eq!(r.header("content-encoding"), Some("gzip"));
    assert!(r.header("x-response-time").unwrap().ends_with("ms"));
    assert!(r.body.len() < text.len() / 5);
    let mut plain = String::new();
    flate2_gunzip(&r.body).read_to_string(&mut plain).unwrap();
    assert_eq!(plain, text);
    // No Accept-Encoding, q=0, tiny bodies and binary types stay as they are.
    assert_eq!(get(a, "/text", "").body, text.as_bytes());
    assert!(
        get(a, "/text", "Accept-Encoding: gzip;q=0\r\n")
            .header("content-encoding")
            .is_none()
    );
    assert!(
        get(a, "/tiny", "Accept-Encoding: gzip\r\n")
            .header("content-encoding")
            .is_none()
    );
    assert!(
        get(a, "/bin", "Accept-Encoding: gzip\r\n")
            .header("content-encoding")
            .is_none()
    );
    // ETag and 304.
    let r = get(a, "/tiny", "");
    let tag = r.header("etag").unwrap().to_owned();
    assert!(tag.starts_with("W/\""));
    let r = get(a, "/tiny", &format!("If-None-Match: {tag}\r\n"));
    assert_eq!((r.status, r.body.len()), (304, 0));
    stop(&e);
}

#[test]
fn compress_with_brotli_and_zstd() {
    let text = "all work and no play makes jack a dull boy. ".repeat(100);
    let t = text.clone();
    let mut both = Compress::default();
    both.brotli = Some(5);
    both.zstd = Some(3);
    let mut zstd_only = Compress::default();
    zstd_only.zstd = Some(3);
    let t2 = text.clone();
    let app = Router::new()
        .get("/text", move |ctx: &mut Context| ctx.text(200, t.clone()))
        .layer(middleware::compress(both));
    let app2 = Router::new()
        .get("/text", move |ctx: &mut Context| ctx.text(200, t2.clone()))
        .layer(middleware::compress(zstd_only));
    let (e, e2) = (start(app), start(app2));
    let (a, a2) = (e.local_addrs()[0], e2.local_addrs()[0]);
    let body = |r: &Resp| -> Vec<u8> {
        match r.header("content-encoding") {
            Some("br") => akio_brotli::decompress(&r.body, 1 << 20).unwrap(),
            Some("zstd") => akio_zstd::decompress(&r.body, 1 << 20).unwrap(),
            Some("gzip") => {
                let mut v = Vec::new();
                flate2_gunzip(&r.body).read_to_end(&mut v).unwrap();
                v
            }
            _ => r.body.clone(),
        }
    };
    // Chrome's and Firefox's Accept-Encoding: br first, then zstd, then gzip.
    for (addr, accept, want) in [
        (a, "gzip, deflate, br, zstd", "br"),
        (a, "gzip, zstd", "zstd"),
        (a, "gzip, deflate, br;q=0, zstd", "zstd"),
        (a, "gzip", "gzip"),
        (a2, "gzip, deflate, br, zstd", "zstd"),
        (a2, "gzip, br", "gzip"),
    ] {
        let r = get(addr, "/text", &format!("Accept-Encoding: {accept}\r\n"));
        assert_eq!(r.header("content-encoding"), Some(want), "{accept}");
        assert_eq!(r.header("vary"), Some("Accept-Encoding"));
        assert!(r.body.len() < text.len() / 5, "{want}: {}", r.body.len());
        assert_eq!(body(&r), text.as_bytes(), "{accept}");
    }
    stop(&e);
    stop(&e2);
}

fn flate2_gunzip(data: &[u8]) -> impl Read + '_ {
    flate2::read::GzDecoder::new(data)
}

#[test]
fn csrf_double_submit_cookie() {
    let app = Router::new()
        .get("/form", |ctx: &mut Context| {
            let t = ctx.local("csrf_token").unwrap().to_owned();
            ctx.text(200, t);
        })
        .post("/act", |ctx: &mut Context| ctx.text(200, "done"))
        .layer(middleware::csrf());
    let e = start(app);
    let a = e.local_addrs()[0];
    let r = get(a, "/form", "");
    let cookie = r.header("set-cookie").unwrap().to_owned();
    assert!(cookie.starts_with("csrf_token=") && cookie.contains("SameSite=Lax"));
    let token = String::from_utf8(r.body).unwrap();
    assert_eq!(token.len(), 32);
    let post = |extra: &str| {
        let mut s = connect(a);
        s.write_all(
            format!("POST /act HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n{extra}\r\n").as_bytes(),
        )
        .unwrap();
        read_resp(&mut s, false).status
    };
    assert_eq!(post(""), 403, "no cookie, no header");
    assert_eq!(
        post(&format!("Cookie: csrf_token={token}\r\n")),
        403,
        "cookie alone"
    );
    assert_eq!(
        post(&format!(
            "Cookie: csrf_token={token}\r\nX-CSRF-Token: {}\r\n",
            "0".repeat(32)
        )),
        403
    );
    assert_eq!(
        post(&format!(
            "Cookie: csrf_token={token}\r\nX-CSRF-Token: {token}\r\n"
        )),
        200
    );
    // An existing token is reused, not reissued.
    let r = get(a, "/form", &format!("Cookie: csrf_token={token}\r\n"));
    assert!(r.header("set-cookie").is_none());
    assert_eq!(r.body, token.as_bytes());
    stop(&e);
}

#[test]
fn limiter_allows_a_burst_then_answers_429_and_recovers() {
    let app = Router::new()
        .get("/", |ctx: &mut Context| ctx.text(200, "ok"))
        .layer(middleware::limiter(20.0, 5));
    let e = start(app);
    let a = e.local_addrs()[0];
    let mut s = connect(a);
    let mut statuses = Vec::new();
    for _ in 0..12 {
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let r = read_resp(&mut s, false);
        if r.status == 429 {
            assert!(r.header("retry-after").is_some());
        }
        statuses.push(r.status);
    }
    assert_eq!(
        statuses.iter().filter(|s| **s == 200).count(),
        5 + statuses[5..].iter().filter(|s| **s == 200).count()
    );
    assert!(
        statuses[..5].iter().all(|s| *s == 200),
        "the burst is served: {statuses:?}"
    );
    assert!(
        statuses.contains(&429),
        "then the limit bites: {statuses:?}"
    );
    thread::sleep(Duration::from_millis(300)); // 20/s refills several tokens
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    assert_eq!(read_resp(&mut s, false).status, 200);
    stop(&e);
}
