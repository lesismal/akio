//! A file body given a stream coding by a response filter (ADR-124): read in pieces on the disk
//! pool, encoded there and sent as a streamed body, chunked on HTTP/1.1, close-delimited on
//! HTTP/1.0, framed on HTTP/2; a slow client holds the reads back; a HEAD answer has the head
//! alone.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    sync::mpsc,
    thread,
    time::Duration,
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{
    Coding, Context, Request, Response, Router, Service,
    client::ClientRequest,
    files::Files,
    h2client::{H2Client, H2Event, H2Options},
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

/// Lines of text: compresses, and every byte checked.
fn content(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len + 64);
    let mut i = 0usize;
    while v.len() < len {
        v.extend_from_slice(format!("line {i} of the file, {}\n", i * 7919 % 1000).as_bytes());
        i += 1;
    }
    v.truncate(len);
    v
}

/// Bytes that do not compress: the encoded body is as large as the file, megabytes ahead of
/// a slow client.
fn noise(len: usize) -> Vec<u8> {
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

struct Server {
    engine: Engine,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.engine.shutdown();
        self.engine.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const BIG: usize = 3 << 20;

/// Every file is sent from disk; a filter gives every file body gzip.
fn start(name: &str) -> Server {
    let dir = std::env::temp_dir().join(format!("akio-file-coding-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("big.txt"), content(BIG)).unwrap();
    std::fs::write(dir.join("noise.bin"), noise(BIG)).unwrap();
    let files = Files::new(&dir).max_cached_bytes(0).twins(&[]);
    let app = Router::new()
        .fallback(files)
        .layer(|ctx: &mut Context, next: &dyn Service| {
            ctx.add_response_filter(|resp: &mut Response, _: &Request| {
                if resp.file.is_some() {
                    resp.set_stream_coding(Some(Coding::gzip(6)));
                    resp.headers.set("Content-Encoding", "gzip");
                    resp.headers.remove("Content-Length");
                    resp.headers.remove("Accept-Ranges");
                }
            });
            next.call(ctx);
        });
    let engine = Engine::builder()
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
    engine.start().unwrap();
    Server { engine, dir }
}

fn gunzip(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    s
}

fn read_line(s: &mut TcpStream) -> String {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    while !line.ends_with(b"\r\n") {
        s.read_exact(&mut b).unwrap();
        line.push(b[0]);
    }
    line.truncate(line.len() - 2);
    String::from_utf8(line).unwrap()
}

fn read_head(s: &mut TcpStream) -> (u16, HashMap<String, String>) {
    let status = read_line(s).split(' ').nth(1).unwrap().parse().unwrap();
    let mut h = HashMap::new();
    loop {
        let l = read_line(s);
        if l.is_empty() {
            return (status, h);
        }
        let (k, v) = l.split_once(':').unwrap();
        h.insert(k.to_ascii_lowercase(), v.trim().to_owned());
    }
}

fn read_chunked(s: &mut TcpStream) -> Vec<u8> {
    let mut body = Vec::new();
    loop {
        let n = usize::from_str_radix(&read_line(s), 16).unwrap();
        let mut data = vec![0; n];
        s.read_exact(&mut data).unwrap();
        assert_eq!(read_line(s), "");
        if n == 0 {
            return body;
        }
        body.extend_from_slice(&data);
    }
}

#[test]
fn file_bodies_are_encoded_over_http1() {
    let s = start("h1");
    let addr = s.engine.local_addrs()[0];
    let mut c = connect(addr);
    // Keep-alive HTTP/1.1, twice on one connection: chunked.
    for _ in 0..2 {
        c.write_all(b"GET /big.txt HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let (status, h) = read_head(&mut c);
        assert_eq!(status, 200);
        assert_eq!(h.get("content-encoding").map(String::as_str), Some("gzip"));
        assert_eq!(
            h.get("transfer-encoding").map(String::as_str),
            Some("chunked")
        );
        assert!(!h.contains_key("content-length"), "{h:?}");
        let body = read_chunked(&mut c);
        assert!(body.len() < BIG / 3, "{} bytes", body.len());
        assert!(gunzip(&body) == content(BIG), "decoded body differs");
    }
    // A HEAD answer: the head alone, and the connection goes on.
    c.write_all(b"HEAD /big.txt HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let (status, h) = read_head(&mut c);
    assert_eq!(status, 200);
    assert_eq!(h.get("content-encoding").map(String::as_str), Some("gzip"));
    // The connection goes on after it.
    c.write_all(b"GET /big.txt HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let (status, _) = read_head(&mut c);
    assert_eq!(status, 200);
    assert!(gunzip(&read_chunked(&mut c)) == content(BIG));
    // HTTP/1.0: close-delimited.
    let mut c = connect(addr);
    c.write_all(b"GET /big.txt HTTP/1.0\r\nHost: x\r\n\r\n")
        .unwrap();
    let (status, h) = read_head(&mut c);
    assert_eq!(status, 200);
    assert!(!h.contains_key("transfer-encoding"));
    let mut body = Vec::new();
    c.read_to_end(&mut body).unwrap();
    assert!(gunzip(&body) == content(BIG));
}

#[test]
fn a_slow_client_holds_the_reads_back() {
    let s = start("slow");
    let addr = s.engine.local_addrs()[0];
    let mut c = connect(addr);
    c.write_all(b"GET /noise.bin HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let (status, _) = read_head(&mut c);
    assert_eq!(status, 200);
    // Read a little at a time: the pump waits for the connection to drain, and goes on.
    let mut body = Vec::new();
    loop {
        let n = usize::from_str_radix(&read_line(&mut c), 16).unwrap();
        let mut data = vec![0; n];
        c.read_exact(&mut data).unwrap();
        assert_eq!(read_line(&mut c), "");
        if n == 0 {
            break;
        }
        body.extend_from_slice(&data);
        thread::sleep(Duration::from_micros(300));
    }
    assert!(gunzip(&body) == noise(BIG));
    // A client that goes midway: the server goes on serving others.
    let mut gone = connect(addr);
    gone.write_all(b"GET /noise.bin HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let _ = read_head(&mut gone);
    drop(gone);
    let mut c = connect(addr);
    c.write_all(b"GET /big.txt HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let _ = read_head(&mut c);
    assert!(gunzip(&read_chunked(&mut c)) == content(BIG));
}

#[test]
fn file_bodies_are_encoded_over_http2() {
    let s = start("h2");
    let addr = s.engine.local_addrs()[0];
    let c = H2Client::dial_blocking(&s.engine, addr, None, H2Options::default()).unwrap();
    let (tx, rx) = mpsc::channel();
    let up = c.open(
        ClientRequest::get(&format!("http://{addr}/big.txt")),
        move |ev| {
            let _ = tx.send(match ev {
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
    assert!(up.finish());
    let next = || rx.recv_timeout(Duration::from_secs(20)).unwrap();
    assert_eq!(next(), Err("gzip".to_owned()));
    let mut body = Vec::new();
    loop {
        match next() {
            Ok(d) => body.extend_from_slice(&d),
            Err(e) if e == "end" => break,
            Err(e) => panic!("{e}"),
        }
    }
    assert!(gunzip(&body) == content(BIG));
}
