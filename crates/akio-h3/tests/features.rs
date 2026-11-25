//! WebSocket over HTTP/3 (RFC 9220), streamed request bodies and the QPACK dynamic table, end
//! to end over loopback.
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use akio::{Engine, Listener};
use akio_h3::{H3Client, H3ClientOptions, H3Config, H3Error, H3WsOptions};
use akio_http::message::{Headers, Method};
use akio_http::ws::{Message, WsConfig, WsHandler, WsSender};
use akio_http::{BodyEvent, Context, Router, Streaming, WsOptions};

const T: Duration = Duration::from_secs(20);

struct Echo;

impl WsHandler for Echo {
    fn on_message(&mut self, ws: &WsSender, msg: Message) {
        let _ = match msg {
            Message::Text(t) => ws.send_text(&t),
            Message::Binary(b) => ws.send_binary(&b),
        };
    }
}

/// Reports what a client WebSocket sees.
#[derive(Debug, PartialEq)]
enum Ev {
    Open,
    Msg(Message),
    Close(Option<u16>),
}

struct Watch(mpsc::Sender<Ev>);

impl WsHandler for Watch {
    fn on_open(&mut self, _ws: &WsSender) {
        let _ = self.0.send(Ev::Open);
    }
    fn on_message(&mut self, _ws: &WsSender, msg: Message) {
        let _ = self.0.send(Ev::Msg(msg));
    }
    fn on_close(&mut self, code: Option<u16>, _reason: &str) {
        let _ = self.0.send(Ev::Close(code));
    }
}

/// FNV-1a over the bytes, for checking large bodies without keeping them.
fn fnv(h: u64, data: &[u8]) -> u64 {
    data.iter()
        .fold(h, |h, &b| (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3))
}

const FNV0: u64 = 0xcbf2_9ce4_8422_2325;

fn app() -> Router {
    Router::new()
        .get("/", |ctx: &mut Context| ctx.text(200, "hello h3"))
        .get("/ws", |ctx: &mut Context| {
            let mut o = WsOptions::default();
            o.protocols = vec!["chat".into()];
            o.config.permessage_deflate = true;
            ctx.upgrade_websocket(Echo, &o);
        })
        .post("/echo", |ctx: &mut Context| {
            let mut h = Headers::new();
            for (n, v) in ctx.req().headers.iter() {
                if n.starts_with("x-") {
                    h.append(n, v);
                }
            }
            let body = ctx.req().body.clone();
            let mut r = akio_http::Response::with_body(200, "application/octet-stream", body);
            for (n, v) in h.iter() {
                r.headers.append(n, v);
            }
            ctx.respond(r);
        })
        .route(
            Method::Post,
            "/count",
            Streaming(|ctx: &mut Context| {
                let state = Arc::new(Mutex::new((0u64, FNV0, 0usize)));
                ctx.on_body(move |ctx, ev| match ev {
                    BodyEvent::Chunk(d) => {
                        let mut s = state.lock().unwrap();
                        s.0 += d.len() as u64;
                        s.1 = fnv(s.1, d);
                        s.2 += 1;
                    }
                    BodyEvent::End(t) => {
                        let s = *state.lock().unwrap();
                        let tr = t.get("x-done").unwrap_or("-").to_owned();
                        ctx.text(200, format!("{} {:x} {} {tr}", s.0, s.1, s.2 > 1));
                    }
                    BodyEvent::TooLarge => {}
                });
            }),
        )
}

fn server(cfg: H3Config) -> (Arc<Engine>, SocketAddr) {
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let quic = akio_h3::server_config(vec![cert], key).unwrap();
    let e = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap()).serve(akio_h3::serve_with(
                quic,
                cfg,
                app(),
            )),
        )
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    (Arc::new(e), addr)
}

fn client(e: &Engine, addr: SocketAddr, cfg: &H3Config) -> H3Client {
    let cc = akio_quic::client_config_insecure(&[b"h3"]).unwrap();
    let mut opts = H3ClientOptions::default();
    opts.qpack_max_table_capacity = cfg.qpack_max_table_capacity;
    opts.qpack_blocked_streams = cfg.qpack_blocked_streams;
    opts.qpack_encoder_capacity = cfg.qpack_encoder_capacity;
    H3Client::dial_with(e, addr, "localhost", cc, opts).unwrap()
}

#[test]
fn websocket_echo_over_h3() {
    let (e, addr) = server(H3Config::default());
    let c = client(&e, addr, &H3Config::default());
    // Plain requests and WebSockets share the connection.
    assert_eq!(c.get("/", T).unwrap().body, b"hello h3");
    for deflate in [false, true] {
        let (tx, rx) = mpsc::channel();
        let mut o = H3WsOptions::default();
        o.protocols = vec!["v0".into(), "chat".into()];
        o.config = WsConfig::default();
        o.config.permessage_deflate = deflate;
        let ws = c.websocket_blocking("/ws", &o, Watch(tx), T).unwrap();
        assert_eq!(rx.recv_timeout(T).unwrap(), Ev::Open);
        assert_eq!(ws.subprotocol().as_deref(), Some("chat"));
        ws.send_text("hello over h3").unwrap();
        assert_eq!(
            rx.recv_timeout(T).unwrap(),
            Ev::Msg(Message::Text("hello over h3".into()))
        );
        // A large message crosses many DATA frames and QUIC packets.
        let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        ws.send_binary(&big).unwrap();
        assert_eq!(rx.recv_timeout(T).unwrap(), Ev::Msg(Message::Binary(big)));
        for i in 0..100 {
            ws.send_text(&format!("m{i}")).unwrap();
        }
        for i in 0..100 {
            assert_eq!(
                rx.recv_timeout(T).unwrap(),
                Ev::Msg(Message::Text(format!("m{i}")))
            );
        }
        ws.close(1000, "bye");
        assert_eq!(rx.recv_timeout(T).unwrap(), Ev::Close(Some(1000)));
        assert!(!ws.is_open());
    }
    // Refused: no such route (404), or a route that does not upgrade (405 for CONNECT on a
    // POST-only path).
    let (tx, _rx) = mpsc::channel();
    let r = c.websocket_blocking("/nope", &H3WsOptions::default(), Watch(tx), T);
    assert_eq!(r.err(), Some(H3Error::Status(404)));
    let (tx, _rx) = mpsc::channel();
    let r = c.websocket_blocking("/echo", &H3WsOptions::default(), Watch(tx), T);
    assert_eq!(r.err(), Some(H3Error::Status(405)));
    // The connection still serves requests.
    assert_eq!(c.get("/", T).unwrap().status, 200);
    // Many WebSockets at once on one connection.
    let mut socks = Vec::new();
    for i in 0..20 {
        let (tx, rx) = mpsc::channel();
        let ws = c
            .websocket_blocking("/ws", &H3WsOptions::default(), Watch(tx), T)
            .unwrap();
        assert_eq!(rx.recv_timeout(T).unwrap(), Ev::Open);
        ws.send_text(&format!("sock {i}")).unwrap();
        socks.push((ws, rx, i));
    }
    for (ws, rx, i) in &socks {
        assert_eq!(
            rx.recv_timeout(T).unwrap(),
            Ev::Msg(Message::Text(format!("sock {i}")))
        );
        ws.close(1000, "");
    }
    // Closing the connection ends the remaining sessions.
    let (tx, rx) = mpsc::channel();
    let ws = c
        .websocket_blocking("/ws", &H3WsOptions::default(), Watch(tx), T)
        .unwrap();
    assert_eq!(rx.recv_timeout(T).unwrap(), Ev::Open);
    c.close();
    assert_eq!(rx.recv_timeout(T).unwrap(), Ev::Close(Some(1006)));
    assert!(!ws.is_open());
    e.shutdown();
}

#[test]
fn streamed_request_bodies() {
    // A buffered limit far below the uploads: streamed bodies are not held.
    let mut cfg = H3Config::default();
    cfg.max_body_bytes = 1 << 20;
    let (e, addr) = server(cfg);
    let c = client(&e, addr, &H3Config::default());
    // 64 MiB in 64 KiB pieces, paced by what is queued.
    let total: u64 = 64 << 20;
    let piece: Vec<u8> = (0..64 << 10).map(|i| (i * 7 % 256) as u8).collect();
    let (tx, rx) = mpsc::channel();
    let mut h = Headers::new();
    h.set("content-length", total.to_string());
    let up = c.upload(Method::Post, "/count", &h, move |r| {
        let _ = tx.send(r);
    });
    let mut want = FNV0;
    let mut sent = 0;
    while sent < total {
        while up.queued_bytes() > 8 << 20 {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(up.write(&piece));
        want = fnv(want, &piece);
        sent += piece.len() as u64;
    }
    assert!(up.finish());
    assert!(!up.write(b"late"));
    let r = rx.recv_timeout(Duration::from_secs(60)).unwrap().unwrap();
    assert_eq!(
        String::from_utf8(r.body).unwrap(),
        format!("{total} {want:x} true -")
    );
    // Unpaced: far more than the stream's send buffer at once. What QUIC refuses waits in the
    // upload and goes out as the stream drains. A 256 KiB buffer makes the second 1 MiB write
    // overflow whatever the speed of the link (16 MiB, the default, can drain on loopback as
    // fast as the test writes).
    let mut t = akio_quic::TransportConfig::default();
    t.stream_send_buffer = 256 << 10;
    let cc = akio_quic::client_config_insecure(&[b"h3"])
        .unwrap()
        .transport(&t);
    let small = H3Client::dial_with(&e, addr, "localhost", cc, H3ClientOptions::default()).unwrap();
    let (tx, rx) = mpsc::channel();
    let up = small.upload(Method::Post, "/count", &Headers::new(), move |r| {
        let _ = tx.send(r);
    });
    let big: Vec<u8> = (0..1 << 20).map(|i| (i * 13 % 251) as u8).collect();
    let mut want = FNV0;
    for _ in 0..32 {
        assert!(up.write(&big));
        want = fnv(want, &big);
    }
    assert!(up.queued_bytes() > 0);
    assert!(up.finish());
    let r = rx.recv_timeout(Duration::from_secs(60)).unwrap().unwrap();
    assert_eq!(
        String::from_utf8(r.body).unwrap(),
        format!("{} {want:x} true -", 32u64 << 20)
    );
    // Written before the stream opened, and a body that arrives with its head.
    let (tx, rx) = mpsc::channel();
    let up = c.upload(Method::Post, "/count", &Headers::new(), move |r| {
        let _ = tx.send(r);
    });
    assert!(up.write(b"ab"));
    assert!(up.write(b"cd"));
    assert!(up.finish());
    let r = rx.recv_timeout(T).unwrap().unwrap();
    let body = String::from_utf8(r.body).unwrap();
    assert!(
        body.starts_with(&format!("4 {:x} ", fnv(FNV0, b"abcd"))),
        "{body}"
    );
    let r = c
        .request_blocking(Method::Post, "/count", &Headers::new(), b"xyz".to_vec(), T)
        .unwrap();
    assert!(String::from_utf8(r.body).unwrap().starts_with("3 "));
    // An upload to a buffered handler, and the buffered limit still applies there.
    let (tx, rx) = mpsc::channel();
    let mut h = Headers::new();
    h.set("x-test", "up");
    let up = c.upload(Method::Post, "/echo", &h, move |r| {
        let _ = tx.send(r);
    });
    for _ in 0..10 {
        assert!(up.write(&piece[..1000]));
    }
    up.finish();
    let r = rx.recv_timeout(T).unwrap().unwrap();
    assert_eq!((r.status, r.body.len()), (200, 10_000));
    assert_eq!(r.headers.get("x-test"), Some("up"));
    let r = c
        .request_blocking(Method::Post, "/echo", &Headers::new(), vec![0; 2 << 20], T)
        .unwrap();
    assert_eq!(r.status, 413);
    // A body that does not match its content-length is a stream error.
    let (tx, rx) = mpsc::channel();
    let mut h = Headers::new();
    h.set("content-length", "10");
    let up = c.upload(Method::Post, "/count", &h, move |r| {
        let _ = tx.send(r);
    });
    up.write(b"short");
    up.finish();
    assert!(matches!(
        rx.recv_timeout(T).unwrap(),
        Err(H3Error::Reset(_))
    ));
    e.shutdown();
}

/// Bytes sent by the client and the server for `n` requests with repetitive headers.
fn header_traffic(server_enc: usize, client_enc: usize, n: usize) -> (u64, u64) {
    let mut s = H3Config::default();
    s.qpack_encoder_capacity = server_enc;
    let (e, addr) = server(s);
    let mut cc = H3Config::default();
    cc.qpack_encoder_capacity = client_enc;
    let c = client(&e, addr, &cc);
    // Let SETTINGS arrive both ways first.
    assert_eq!(c.get("/", T).unwrap().status, 200);
    let before = c.connection().stats().udp_tx.bytes;
    let mut h = Headers::new();
    h.set("x-application-id", "akio-h3-feature-tests");
    h.set("x-tenant", "some-tenant-with-a-long-name");
    h.set("user-agent", "akio-h3 test client/1.0");
    let (tx, rx) = mpsc::channel();
    let done = Arc::new(AtomicU64::new(0));
    for i in 0..n {
        let tx = tx.clone();
        let done = done.clone();
        let mut h = h.clone();
        h.set("x-seq", (i % 4).to_string());
        // Sequential: later requests can reference what earlier ones inserted.
        let r = c
            .request_blocking(Method::Post, "/echo", &h, b"x".to_vec(), T)
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(
            r.headers.get("x-tenant"),
            Some("some-tenant-with-a-long-name")
        );
        assert_eq!(r.headers.get("x-seq"), Some((i % 4).to_string().as_str()));
        done.fetch_add(1, Ordering::Relaxed);
        let _ = tx.send(());
    }
    drop(tx);
    assert_eq!(rx.iter().count(), n);
    let sent = c.connection().stats().udp_tx.bytes - before;
    let srv = c.connection().stats().udp_rx.bytes;
    c.close();
    e.shutdown();
    (sent, srv)
}

#[test]
fn qpack_dynamic_table_end_to_end() {
    let n = 200;
    let (plain_tx, plain_rx) = header_traffic(0, 0, n);
    let (dyn_tx, dyn_rx) = header_traffic(4096, 4096, n);
    // Both directions shrink once the repeated fields are table references.
    assert!(
        dyn_tx * 10 < plain_tx * 8,
        "client bytes: dynamic {dyn_tx} vs static {plain_tx}"
    );
    assert!(
        dyn_rx < plain_rx,
        "server bytes: dynamic {dyn_rx} vs static {plain_rx}"
    );
    // One side's encoder with the other's decoder only, and a client that allows no table.
    header_traffic(4096, 0, 20);
    header_traffic(0, 4096, 20);
    let mut s = H3Config::default();
    s.qpack_encoder_capacity = 4096;
    let (e, addr) = server(s);
    let mut cc = H3Config::default();
    cc.qpack_max_table_capacity = 0;
    cc.qpack_encoder_capacity = 4096;
    let c = client(&e, addr, &cc);
    for _ in 0..20 {
        let mut h = Headers::new();
        h.set("x-a", "repeated value");
        let r = c
            .request_blocking(Method::Post, "/echo", &h, Vec::new(), T)
            .unwrap();
        assert_eq!(r.headers.get("x-a"), Some("repeated value"));
    }
    e.shutdown();
}
