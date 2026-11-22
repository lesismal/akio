//! Server and idle-stream holder for the streamed-response compression benchmark (ADR-074,
//! `tools/bench/stream-compress.sh`):
//!
//! `stream-bench serve <addr> <threads> [stream]`: the `compress` middleware with `gzip`, `br`
//! (quality 5) and `zstd` (level 3) for buffered responses, and with `stream` also for
//! streamed ones (`StreamCompress` defaults).
//!
//! * `GET /sse`: 16 server-sent events of about 100 bytes, one write each, then the end.
//! * `GET /bulk`: 16 writes of 16 KiB of generated HTML, then the end.
//! * `GET /hold?events=<k>`: `k` events, written by a producer thread as the client reads
//!   them, then the stream stays open (an idle SSE client).
//!
//! `stream-bench hold <addr> <conns> <events> <accept-encoding>`: opens `conns` connections to
//! `/hold?events=<events>`, reads everything they get and prints `ready <conns> <bytes>` once
//! nothing more arrives; then keeps them open until killed.

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Mutex,
    time::{Duration, Instant},
};

use akio::{Backend, Engine, Listener};
use akio_http::{BodyStream, Context, Headers, Router, middleware, serve};

/// One server-sent event, about 100 bytes of JSON.
fn event(i: usize) -> String {
    format!(
        "event: tick\nid: {i}\ndata: {{\"seq\":{i},\"price\":{}.{:02},\"symbol\":\"SYM{}\",\"note\":\"steady\"}}\n\n",
        100 + i % 37,
        i % 100,
        i % 13
    )
}

/// 16 KiB of generated HTML rows, different for each `i`.
fn rows(i: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 << 10);
    let mut n = i * 1000;
    while out.len() < (16 << 10) - 80 {
        out.extend_from_slice(
            format!(
                "<tr><td>{n}</td><td>item-{}</td><td class=\"p\">{}.{:02}</td></tr>\n",
                n % 97,
                n % 1000,
                n % 100
            )
            .as_bytes(),
        );
        n += 1;
    }
    out
}

fn headers(content_type: &str) -> Headers {
    let mut h = Headers::new();
    h.set("Content-Type", content_type);
    h
}

/// Streams kept open by `/hold`, with the events still to write and the next one.
static HELD: Mutex<Vec<(BodyStream, usize, usize)>> = Mutex::new(Vec::new());

/// Writes the held streams' events, one write per event, while each has less than 16 KiB
/// queued: paced by the client, as an event source is, so that what is measured afterwards is
/// the stream's state and not a backlog the allocator kept.
fn producer() {
    loop {
        let mut wrote = false;
        for (s, k, next) in HELD.lock().unwrap().iter_mut() {
            while *next < *k && s.queued_bytes() < 16 << 10 {
                let _ = s.write(event(*next).as_bytes());
                *next += 1;
                wrote = true;
            }
        }
        if !wrote {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

fn serve_main(a: &[String]) -> std::io::Result<()> {
    let addr = a[0].parse().expect("address");
    let threads: usize = a[1].parse().expect("threads");
    let mut cfg = middleware::Compress::default();
    cfg.brotli = Some(5);
    cfg.zstd = Some(3);
    if a.get(2).map(String::as_str) == Some("stream") {
        cfg.stream = Some(middleware::StreamCompress::default()); // STREAM-ONLY
    }
    let bulk: Vec<Vec<u8>> = (0..16).map(rows).collect();
    let app = Router::new()
        .get("/sse", |ctx: &mut Context| {
            let s = ctx
                .stream_response(200, headers("text/event-stream"))
                .unwrap();
            for i in 0..16 {
                let _ = s.write(event(i).as_bytes());
            }
            s.finish();
        })
        .get("/bulk", move |ctx: &mut Context| {
            let s = ctx
                .stream_response(200, headers("text/html; charset=utf-8"))
                .unwrap();
            for b in &bulk {
                let _ = s.write(b);
            }
            s.finish();
        })
        .get("/hold", |ctx: &mut Context| {
            let k: usize = ctx
                .req()
                .query_param("events")
                .and_then(|v| v.parse().ok())
                .unwrap_or(3);
            let s = ctx
                .stream_response(200, headers("text/event-stream"))
                .unwrap();
            HELD.lock().unwrap().push((s, k, 0));
        })
        .layer(middleware::compress(cfg));
    let e = Engine::builder()
        .listen(
            Listener::tcp(addr)
                .backend(Backend::Epoll)
                .threads(threads)
                .serve(serve(app)),
        )
        .build()?;
    e.start()?;
    std::thread::spawn(producer);
    e.wait();
    Ok(())
}

/// Reads whatever the sockets have; whether there was anything.
fn drain(socks: &mut [TcpStream], buf: &mut [u8], total: &mut u64) -> bool {
    let mut got = false;
    for s in socks {
        while let Ok(n) = s.read(buf) {
            if n == 0 {
                break;
            }
            *total += n as u64;
            got = true;
        }
    }
    got
}

fn hold_main(a: &[String]) {
    let addr: std::net::SocketAddr = a[0].parse().expect("address");
    let conns: usize = a[1].parse().expect("conns");
    let events: usize = a[2].parse().expect("events");
    let accept = &a[3];
    let mut socks = Vec::with_capacity(conns);
    let mut buf = vec![0u8; 1 << 16];
    let mut total = 0u64;
    for _ in 0..conns {
        let mut s = TcpStream::connect(addr).expect("connect");
        s.write_all(
            format!(
                "GET /hold?events={events} HTTP/1.1\r\nHost: x\r\nAccept-Encoding: {accept}\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
        s.set_nonblocking(true).unwrap();
        socks.push(s);
        // Keep the earlier streams drained while connecting the next ones.
        drain(&mut socks, &mut buf, &mut total);
    }
    // Drain until two seconds pass without a byte.
    let mut quiet = Instant::now();
    while quiet.elapsed() < Duration::from_secs(2) {
        if drain(&mut socks, &mut buf, &mut total) {
            quiet = Instant::now();
        } else {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    println!("ready {} {total}", socks.len());
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn main() -> std::io::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("serve") if a.len() >= 3 => serve_main(&a[1..]),
        Some("hold") if a.len() >= 5 => {
            hold_main(&a[1..]);
            Ok(())
        }
        _ => {
            eprintln!(
                "usage: stream-bench serve <addr> <threads> [stream]\n       stream-bench hold <addr> <conns> <events> <accept-encoding>"
            );
            std::process::exit(2);
        }
    }
}
