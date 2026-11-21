//! monoio reference server: `monoio-ref <tcp|http> <addr> <threads> [uring|legacy]`
//!
//! Thread-per-core like `only`: `threads` threads, each with its own monoio runtime (io_uring
//! driver by default, `legacy` = epoll) and its own `SO_REUSEPORT` listener on `addr`, so the
//! kernel spreads connections over the threads and a connection stays on the thread that
//! accepted it.
//!
//! - `tcp`: echo, the same handler as `only`'s `bench-server` and `tokio-ref`.
//! - `http`: HTTP/1.1 keep-alive with pipelining, `GET /plaintext` and `GET /json` (the routes of
//!   `only`'s `http-bench` and `hyper-ref`), parsed with httparse; responses carry `Date`,
//!   `Content-Type` and `Content-Length`, the JSON body is serialised per request with
//!   serde_json (as hyper-ref does). No HTTP/2: monoio has no HTTP/2 server of its own.
//!
//! `MONOIO_REF_BUF` sets the per-connection read buffer (default 65536, the size `only`'s I/O
//! threads read with); memory runs use a smaller one, as for `tokio-ref`.

use std::{
    cell::RefCell,
    net::SocketAddr,
    time::{Duration, Instant, SystemTime},
};

use monoio::{
    buf::{IoBufMut, SliceMut},
    io::{AsyncReadRent, AsyncWriteRentExt},
    net::{ListenerOpts, TcpListener, TcpStream},
    IoUringDriver, LegacyDriver, RuntimeBuilder,
};

#[derive(serde::Serialize)]
struct Message {
    message: &'static str,
}

fn buf_size() -> usize {
    std::env::var("MONOIO_REF_BUF")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(65536)
}

thread_local! {
    // The `Date` value, formatted at most twice a second per thread.
    static DATE: RefCell<(Instant, String)> =
        RefCell::new((Instant::now(), httpdate::fmt_http_date(SystemTime::now())));
}

fn date() -> String {
    DATE.with(|d| {
        let mut d = d.borrow_mut();
        if d.0.elapsed() >= Duration::from_millis(500) {
            *d = (Instant::now(), httpdate::fmt_http_date(SystemTime::now()));
        }
        d.1.clone()
    })
}

async fn echo(mut s: TcpStream) {
    let mut b: Vec<u8> = Vec::with_capacity(buf_size());
    loop {
        // A Vec is read into from its start; the read sets its length.
        let (r, buf) = s.read(b).await;
        b = buf;
        match r {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let (r, buf) = s.write_all(b).await;
        b = buf;
        if r.is_err() {
            return;
        }
    }
}

fn respond(path: &str, date: &str, json: &mut Vec<u8>, out: &mut Vec<u8>) {
    let (status, ctype, body): (&str, &str, &[u8]) = match path {
        "/plaintext" => ("200 OK", "text/plain; charset=utf-8", b"Hello, World!"),
        "/json" => {
            json.clear();
            serde_json::to_writer(
                &mut *json,
                &Message {
                    message: "Hello, World!",
                },
            )
            .unwrap();
            ("200 OK", "application/json", json)
        }
        _ => ("404 Not Found", "text/plain", b""),
    };
    out.extend_from_slice(b"HTTP/1.1 ");
    out.extend_from_slice(status.as_bytes());
    out.extend_from_slice(b"\r\nContent-Type: ");
    out.extend_from_slice(ctype.as_bytes());
    out.extend_from_slice(b"\r\nContent-Length: ");
    out.extend_from_slice(body.len().to_string().as_bytes());
    out.extend_from_slice(b"\r\nDate: ");
    out.extend_from_slice(date.as_bytes());
    out.extend_from_slice(b"\r\n\r\n");
    out.extend_from_slice(body);
}

async fn http(mut s: TcpStream) {
    let size = buf_size();
    let mut buf: Vec<u8> = Vec::with_capacity(size);
    let mut out: Vec<u8> = Vec::with_capacity(size);
    let mut json: Vec<u8> = Vec::with_capacity(64);
    loop {
        if buf.len() == buf.capacity() {
            if buf.len() >= 1 << 20 {
                return; // a head this large is not a benchmark request
            }
            buf.reserve(buf.capacity());
        }
        // Append after what is left of a partial request.
        let (len, cap) = (buf.len(), buf.capacity());
        let (r, slice): (_, SliceMut<Vec<u8>>) = s.read(buf.slice_mut(len..cap)).await;
        buf = slice.into_inner();
        match r {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let date = date();
        let mut pos = 0;
        loop {
            let mut headers = [httparse::EMPTY_HEADER; 32];
            let mut req = httparse::Request::new(&mut headers);
            match req.parse(&buf[pos..]) {
                Ok(httparse::Status::Complete(n)) => {
                    let body = req
                        .headers
                        .iter()
                        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                        .and_then(|h| std::str::from_utf8(h.value).ok()?.trim().parse().ok())
                        .unwrap_or(0usize);
                    if buf.len() - pos < n + body {
                        break;
                    }
                    respond(req.path.unwrap_or(""), &date, &mut json, &mut out);
                    pos += n + body;
                }
                Ok(httparse::Status::Partial) => break,
                Err(_) => return,
            }
        }
        buf.drain(..pos);
        if !out.is_empty() {
            let (r, o) = s.write_all(out).await;
            out = o;
            if r.is_err() {
                return;
            }
            out.clear();
        }
    }
}

async fn serve(proto: String, addr: SocketAddr) {
    let opts = ListenerOpts::new()
        .reuse_port(true)
        .reuse_addr(true)
        .backlog(4096);
    let l = TcpListener::bind_with_config(addr, &opts).expect("bind");
    loop {
        let Ok((s, _)) = l.accept().await else {
            continue;
        };
        s.set_nodelay(true).ok();
        if proto == "http" {
            monoio::spawn(http(s));
        } else {
            monoio::spawn(echo(s));
        }
    }
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let proto = a[0].clone();
    assert!(
        proto == "tcp" || proto == "http",
        "usage: monoio-ref <tcp|http> <addr> <threads> [uring|legacy]"
    );
    let addr: SocketAddr = a[1].parse().expect("addr");
    let threads: usize = a[2].parse().expect("threads");
    let legacy = a.get(3).map(String::as_str) == Some("legacy");
    let workers: Vec<_> = (0..threads)
        .map(|_| {
            let proto = proto.clone();
            std::thread::spawn(move || {
                if legacy {
                    RuntimeBuilder::<LegacyDriver>::new()
                        .build()
                        .expect("runtime")
                        .block_on(serve(proto, addr));
                } else {
                    RuntimeBuilder::<IoUringDriver>::new()
                        .with_entries(1024)
                        .build()
                        .expect("io_uring runtime")
                        .block_on(serve(proto, addr));
                }
            })
        })
        .collect();
    for w in workers {
        let _ = w.join();
    }
}
