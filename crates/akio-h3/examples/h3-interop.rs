//! HTTP/3 interop peer for tools/interop/h3 (quic-go) and tools/interop/quic/docker.sh:
//!
//! ```text
//! h3-interop server 127.0.0.1:9401 [qpack] [prefer-v2] [0rtt] [twin 127.0.0.1:9404]
//!                                    serves /, /user/:id, /echo, /stream (with trailers),
//!                                    /count (streamed request body), /ws (WebSocket over
//!                                    HTTP/3); qpack turns on the QPACK encoder's dynamic
//!                                    table, prefer-v2 moves clients to QUIC v2 (RFC 9368),
//!                                    0rtt accepts 0-RTT (prints "early request" for a GET /
//!                                    that came in 0-RTT); twin also serves on a second
//!                                    address without prefer-v2, with the same TLS
//!                                    configuration (tickets from one resume on the other)
//! h3-interop client 127.0.0.1:9400   checks a quic-go server
//! h3-interop client-fib 127.0.0.1:9402   checks a fib server (/ and /echo only)
//! h3-interop client-quiche 127.0.0.1:9411   checks quiche-server (tools/interop/quic/quiche.sh):
//!                                    its root holds index.html ("hello from quiche"); it
//!                                    serves /stream-bytes/N and answers POST with 405
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use akio::{Engine, Listener};
use akio_h3::{H3Client, H3Config, H3Event, H3WsOptions};
use akio_http::message::{Headers, Method};
use akio_http::ws::{Message, WsHandler, WsSender};
use akio_http::{BodyEvent, Context, Router, Streaming, WsOptions};

struct Echo;

impl WsHandler for Echo {
    fn on_message(&mut self, ws: &WsSender, msg: Message) {
        let _ = match msg {
            Message::Text(t) => ws.send_text(&t),
            Message::Binary(b) => ws.send_binary(&b),
        };
    }
}

struct Collect(mpsc::Sender<Option<Message>>);

impl WsHandler for Collect {
    fn on_message(&mut self, _ws: &WsSender, msg: Message) {
        let _ = self.0.send(Some(msg));
    }
    fn on_close(&mut self, _code: Option<u16>, _reason: &str) {
        let _ = self.0.send(None);
    }
}

fn fail(msg: String) -> ! {
    println!("FAIL: {msg}");
    std::process::exit(1)
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 + (i >> 9)) as u8).collect()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let addr = a[2].parse().expect("addr");
    if a[1] == "server" {
        let ck = akio_x509::generate_simple_self_signed(["localhost"]).expect("cert");
        let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
        let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
        let app = || {
            Router::new()
                .get("/", |ctx: &mut Context| {
                    if ctx.header("early-data") == Some("1") {
                        println!("early request");
                    }
                    ctx.text(200, "hello h3");
                })
                .get("/user/:id", |ctx: &mut Context| {
                    let id = ctx.param("id").unwrap_or("?").to_owned();
                    ctx.text(200, format!("user {id} {:?}", ctx.req().version));
                })
                .post("/echo", |ctx: &mut Context| {
                    let body = ctx.req().body.clone();
                    ctx.bytes(200, "application/octet-stream", body);
                })
                .get("/ws", |ctx: &mut Context| {
                    let mut o = WsOptions::default();
                    o.protocols = vec!["chat".into()];
                    ctx.upgrade_websocket(Echo, &o);
                })
                .route(
                    Method::Post,
                    "/count",
                    Streaming(|ctx: &mut Context| {
                        let n = Arc::new(AtomicU64::new(0));
                        ctx.on_body(move |ctx, ev| match ev {
                            BodyEvent::Chunk(d) => {
                                n.fetch_add(d.len() as u64, Ordering::Relaxed);
                            }
                            BodyEvent::End(_) => {
                                ctx.text(200, n.load(Ordering::Relaxed).to_string());
                            }
                        });
                    }),
                )
                .get("/stream", |ctx: &mut Context| {
                    let mut h = Headers::new();
                    h.set("trailer", "x-checksum");
                    let s = ctx.stream_response(200, h).expect("stream");
                    for i in 0..50 {
                        let _ = s.write(format!("line {i}\n").as_bytes());
                    }
                    let mut t = Headers::new();
                    t.set("x-checksum", "abc");
                    s.finish_with_trailers(t);
                })
        };
        let mut quic = akio_h3::server_config(vec![cert], key).expect("config");
        let mut cfg = H3Config::default();
        if a.iter().any(|x| x == "qpack") {
            cfg.qpack_encoder_capacity = 4096;
        }
        if a.iter().any(|x| x == "0rtt") {
            quic = quic.zero_rtt(true);
        }
        let twin = a
            .iter()
            .position(|x| x == "twin")
            .map(|i| a[i + 1].parse().expect("twin addr"));
        let plain = quic.clone();
        if a.iter().any(|x| x == "prefer-v2") {
            // Compatible version negotiation (RFC 9368): version 1 clients listing version 2
            // move to it within the handshake.
            quic = quic.prefer_version(akio_quic::Version::V2);
        }
        let mut b = Engine::builder().listen(Listener::udp(addr).serve(akio_h3::serve_with(
            quic,
            cfg.clone(),
            app(),
        )));
        if let Some(t) = twin {
            b = b.listen(Listener::udp(t).serve(akio_h3::serve_with(plain, cfg, app())));
        }
        let e = b.build().expect("engine");
        e.start().expect("start");
        println!("ready");
        e.wait();
        return;
    }
    let e = Engine::builder()
        .udp_client_threads(1)
        .build()
        .expect("engine");
    e.start().expect("start");
    let cc = akio_quic::client_config_insecure(&[b"h3"]).expect("client config");
    let c = H3Client::dial(&e, addr, "localhost", cc).expect("connect");
    let t = Duration::from_secs(20);
    if a[1] == "client-quiche" {
        quiche(&c, t);
        c.close();
        println!("ok: akio-h3 client -> quiche server");
        return;
    }
    let r = c.get("/", t).unwrap_or_else(|e| fail(e.to_string()));
    let body = String::from_utf8_lossy(&r.body).into_owned();
    let fib = a[1] == "client-fib";
    let want = if fib {
        "hello from fib HTTP/3"
    } else {
        "hello from quic-go HTTP/3.0 localhost"
    };
    if r.status != 200 || !body.starts_with(want) {
        fail(format!("GET /: {} {body:?}", r.status));
    }
    let mut h = Headers::new();
    h.set("x-test", "yes");
    let big = pattern(3 << 20);
    let r = c
        .request_blocking(Method::Post, "/echo", &h, big.clone(), t)
        .unwrap_or_else(|e| fail(e.to_string()));
    if r.body != big || (!fib && r.headers.get("x-req-header") != Some("yes")) {
        fail(format!("POST /echo: {} bytes", r.body.len()));
    }
    if fib {
        parallel(&c, t);
        c.close();
        println!("ok: akio-h3 client -> fib server");
        return;
    }
    let r = c
        .get("/trailers", t)
        .unwrap_or_else(|e| fail(e.to_string()));
    let sum = r
        .trailers
        .as_ref()
        .and_then(|t| t.get("x-sum").map(str::to_owned));
    if r.body != b"body" || sum.as_deref() != Some("42") {
        fail(format!("trailers: {:?} {sum:?}", r.body));
    }
    let r = c.get("/big", t).unwrap_or_else(|e| fail(e.to_string()));
    if r.body != pattern(4 << 20) {
        fail(format!("GET /big: {} bytes", r.body.len()));
    }
    parallel(&c, t);
    streamed_responses(&c, t);
    // A streamed upload (no content-length) to quic-go's /count.
    let (tx, rx) = mpsc::channel();
    let up = c.upload(Method::Post, "/count", &Headers::new(), move |r| {
        let _ = tx.send(r);
    });
    let piece = pattern(64 << 10);
    for _ in 0..256 {
        while up.queued_bytes() > 4 << 20 {
            std::thread::sleep(Duration::from_millis(1));
        }
        up.write(&piece);
    }
    up.finish();
    let r = rx
        .recv_timeout(t)
        .unwrap_or_else(|_| fail("upload: timeout".into()))
        .unwrap_or_else(|e| fail(e.to_string()));
    if r.body != (256u64 << 16).to_string().as_bytes() {
        fail(format!("upload: {:?}", String::from_utf8_lossy(&r.body)));
    }
    // WebSocket over HTTP/3 to quic-go's /ws.
    let (tx, rx) = mpsc::channel();
    let mut o = H3WsOptions::default();
    o.protocols = vec!["v0".into(), "chat".into()];
    let ws = c
        .websocket_blocking("/ws", &o, Collect(tx), t)
        .unwrap_or_else(|e| fail(format!("websocket: {e}")));
    if ws.subprotocol().as_deref() != Some("chat") {
        fail(format!("websocket subprotocol: {:?}", ws.subprotocol()));
    }
    let big = pattern(300 << 10);
    ws.send_text("hello quic-go").expect("send");
    ws.send_binary(&big).expect("send");
    let next = || {
        rx.recv_timeout(t)
            .unwrap_or_else(|_| fail("websocket: timeout".into()))
    };
    if next() != Some(Message::Text("hello quic-go".into())) || next() != Some(Message::Binary(big))
    {
        fail("websocket echo".into());
    }
    ws.close(1000, "");
    if next().is_some() {
        fail("websocket: no close".into());
    }
    c.close();
    println!(
        "ok: akio-h3 client -> quic-go server (incl. WebSocket over HTTP/3, streamed upload, \
         streamed responses)"
    );
}

/// Against quiche-server (0.30): files from its root, `/stream-bytes/N` (N bytes of 'W'), 405
/// for any other method, sent after it stops reading the request (STOP_SENDING) so that a
/// request body still in flight is cut off; at most 100 concurrent streams.
fn quiche(c: &H3Client, t: Duration) {
    let r = c.get("/", t).unwrap_or_else(|e| fail(e.to_string()));
    let body = String::from_utf8_lossy(&r.body).into_owned();
    if r.status != 200 || body.trim_end() != "hello from quiche" {
        fail(format!("GET /: {} {body:?}", r.status));
    }
    if r.headers.get("server") != Some("quiche") {
        fail(format!("GET /: server {:?}", r.headers.get("server")));
    }
    let n = 4 << 20;
    let r = c
        .get(&format!("/stream-bytes/{n}"), t)
        .unwrap_or_else(|e| fail(e.to_string()));
    if r.status != 200 || r.body.len() != n || r.body.iter().any(|&b| b != b'W') {
        fail(format!(
            "GET /stream-bytes: {} {} bytes",
            r.status,
            r.body.len()
        ));
    }
    let r = c.get("/missing", t).unwrap_or_else(|e| fail(e.to_string()));
    if r.status != 404 {
        fail(format!("GET /missing: {}", r.status));
    }
    // POST: quiche answers 405 and stops reading; a small body and one far larger than its
    // stream window (1 MB by default), which it never reads.
    for size in [100, 3 << 20] {
        let r = c
            .request_blocking(Method::Post, "/echo", &Headers::new(), pattern(size), t)
            .unwrap_or_else(|e| fail(format!("POST {size} bytes: {e}")));
        if r.status != 405 {
            fail(format!("POST {size} bytes: {}", r.status));
        }
    }
    // More requests at once than the 100 streams quiche allows.
    parallel(c, t);
    // A streamed response, paused and resumed.
    let (tx, rx) = mpsc::channel();
    let mut got = (0u16, 0usize, 0usize);
    let slot = Arc::new(std::sync::Mutex::new(None::<Arc<akio_h3::H3Upload>>));
    let s2 = slot.clone();
    let up = Arc::new(c.open(
        Method::Get,
        &format!("/stream-bytes/{n}"),
        &Headers::new(),
        move |ev| match ev {
            H3Event::Head { status, .. } => got.0 = status,
            H3Event::Data(d) => {
                got.1 += d.len();
                got.2 += 1;
                if got.2 == 1 {
                    let up = s2.lock().unwrap().clone();
                    if let Some(up) = up {
                        up.hold_reads(true);
                        std::thread::spawn(move || {
                            std::thread::sleep(Duration::from_millis(300));
                            up.hold_reads(false);
                        });
                    }
                }
            }
            H3Event::End => {
                let _ = tx.send(Ok(got));
            }
            H3Event::Error(e) => {
                let _ = tx.send(Err(e));
            }
            _ => {}
        },
    ));
    *slot.lock().unwrap() = Some(up.clone());
    up.finish();
    let (status, len, pieces) = rx
        .recv_timeout(t)
        .unwrap_or_else(|_| fail("open /stream-bytes: timeout".into()))
        .unwrap_or_else(|e| fail(format!("open /stream-bytes: {e}")));
    if status != 200 || len != n || pieces < 2 {
        fail(format!(
            "open /stream-bytes: {status} {len} bytes in {pieces}"
        ));
    }
}

/// What a streamed response (`H3Client::open`) brought: status, body, trailers, pieces.
type Streamed = (u16, Vec<u8>, Option<Headers>, usize);

/// Streamed responses from quic-go: /big read in pieces, paused for a while (`hold_reads`) and
/// resumed; /trailers with its trailers.
fn streamed_responses(c: &H3Client, t: Duration) {
    let open = |path: &str, hold: bool| -> Streamed {
        let (tx, rx) = mpsc::channel();
        let mut s: Streamed = (0, Vec::new(), None, 0);
        let slot = Arc::new(std::sync::Mutex::new(None::<Arc<akio_h3::H3Upload>>));
        let s2 = slot.clone();
        let up = Arc::new(
            c.open(Method::Get, path, &Headers::new(), move |ev| match ev {
                H3Event::Head { status, .. } => s.0 = status,
                H3Event::Data(d) => {
                    s.1.extend_from_slice(d);
                    s.3 += 1;
                    if hold && s.3 == 1 {
                        // Pause after the first piece, resume a little later from another thread.
                        let up = s2.lock().unwrap().clone();
                        if let Some(up) = up {
                            up.hold_reads(true);
                            std::thread::spawn(move || {
                                std::thread::sleep(Duration::from_millis(300));
                                up.hold_reads(false);
                            });
                        }
                    }
                }
                H3Event::Trailers(h) => s.2 = Some(h.clone()),
                H3Event::End => {
                    let _ = tx.send(Ok(std::mem::take(&mut s)));
                }
                H3Event::Error(e) => {
                    let _ = tx.send(Err(e));
                }
                _ => {}
            }),
        );
        *slot.lock().unwrap() = Some(up.clone());
        up.finish();
        rx.recv_timeout(t)
            .unwrap_or_else(|_| fail(format!("open {path}: timeout")))
            .unwrap_or_else(|e| fail(format!("open {path}: {e}")))
    };
    let (status, body, _, pieces) = open("/big", true);
    if status != 200 || body != pattern(4 << 20) || pieces < 2 {
        fail(format!(
            "open /big: {status} {} bytes in {pieces}",
            body.len()
        ));
    }
    let (status, body, trailers, _) = open("/trailers", false);
    let sum = trailers.as_ref().and_then(|h| h.get("x-sum"));
    if status != 200 || body != b"body" || sum != Some("42") {
        fail(format!("open /trailers: {status} {body:?} {sum:?}"));
    }
}

fn parallel(c: &H3Client, t: Duration) {
    let (tx, rx) = mpsc::channel();
    for i in 0..200 {
        let tx = tx.clone();
        c.request(Method::Get, "/", &Headers::new(), Vec::new(), move |r| {
            let _ = tx.send((i, r));
        });
    }
    for _ in 0..200 {
        let (i, r) = rx
            .recv_timeout(t)
            .unwrap_or_else(|_| fail("parallel: timeout".into()));
        if r.map(|r| r.status) != Ok(200) {
            fail(format!("parallel {i}"));
        }
    }
}
