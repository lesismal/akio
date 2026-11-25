//! Sends from an application thread while the peer's data waits to be handled: the thread's
//! send runs the connection's handler, which must not need a lock the thread holds (QPACK
//! encoding held the encoder's, a WebSocket send its sender's, and the thread waited on itself
//! for good).
//!
//! `akio_quic::testing::defer_delivery` makes the interleaving certain and is process-wide:
//! the tests of this binary take turns (`SERIAL`).
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use akio::{Engine, Listener};
use akio_h3::{H3Client, H3ClientOptions, H3Config, H3WsOptions};
use akio_http::message::{Headers, Method, Response};
use akio_http::ws::{Message, WsHandler, WsSender};
use akio_http::{Context, Router, WsOptions};
use akio_quic::Side;
use akio_quic::testing::defer_delivery;

const T: Duration = Duration::from_secs(20);

/// The tests take turns: the hook they use is process-wide.
static SERIAL: Mutex<()> = Mutex::new(());

/// `defer_delivery` for one side until dropped (a failed test does not leave it on).
struct Deferred;

impl Deferred {
    fn on(side: Side) -> Deferred {
        defer_delivery(Some(side));
        Deferred
    }
}

impl Drop for Deferred {
    fn drop(&mut self) {
        defer_delivery(None);
    }
}

/// Runs `f` on a thread of its own and fails the test if it does not return within `T`.
fn bounded<R: Send + 'static>(what: &str, f: impl FnOnce() -> R + Send + 'static) -> R {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(T)
        .unwrap_or_else(|_| panic!("{what} did not return within {T:?}"))
}

struct Srv {
    e: Engine,
    addr: SocketAddr,
    /// Requests to `/held`, left for the test to answer.
    held: Arc<Mutex<Vec<akio_http::Detached>>>,
    /// The sender of the last WebSocket opened on `/ws`.
    ws: Arc<Mutex<Option<WsSender>>>,
}

/// The server's WebSocket: echoes each message after a ping.
struct PingEcho(Arc<Mutex<Option<WsSender>>>);

impl WsHandler for PingEcho {
    fn on_open(&mut self, ws: &WsSender) {
        *self.0.lock().unwrap() = Some(ws.clone());
    }
    fn on_message(&mut self, ws: &WsSender, msg: Message) {
        let _ = ws.ping(b"p");
        if let Message::Text(t) = msg {
            let _ = ws.send_text(&t);
        }
    }
}

/// The client's WebSocket: reports the text messages.
struct Texts(mpsc::Sender<String>);

impl WsHandler for Texts {
    fn on_message(&mut self, _ws: &WsSender, msg: Message) {
        if let Message::Text(t) = msg {
            let _ = self.0.send(t);
        }
    }
}

fn server() -> Srv {
    let held = Arc::new(Mutex::new(Vec::new()));
    let h2 = held.clone();
    let ws = Arc::new(Mutex::new(None));
    let w2 = ws.clone();
    let app = Router::new()
        .get("/ws", move |ctx: &mut Context| {
            ctx.upgrade_websocket(PingEcho(w2.clone()), &WsOptions::default());
        })
        .get("/small", |ctx: &mut Context| ctx.text(200, "small body"))
        .get("/held", move |ctx: &mut Context| {
            h2.lock().unwrap().push(ctx.detach().unwrap());
        });
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let quic = akio_h3::server_config(vec![cert], key).unwrap();
    let e = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap()).serve(akio_h3::serve_with(
                quic,
                H3Config::default(),
                app,
            )),
        )
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    Srv { e, addr, held, ws }
}

fn client(s: &Srv, encoder: usize) -> H3Client {
    let mut o = H3ClientOptions::default();
    o.qpack_encoder_capacity = encoder;
    let cc = akio_quic::client_config_insecure(&[b"h3"]).unwrap();
    let c = H3Client::dial_with(&s.e, s.addr, "localhost", cc, o).unwrap();
    // SETTINGS both ways: the encoders exist from here on.
    assert_eq!(c.get("/small", T).unwrap().status, 200);
    std::thread::sleep(Duration::from_millis(100));
    c
}

/// Headers whose field repeats: inserted into the dynamic table on its second appearance.
fn repeated(name: &str, value: &str) -> Headers {
    let mut h = Headers::new();
    h.append(name, value);
    h.append(name, value);
    h
}

fn send(c: &H3Client, h: &Headers) -> mpsc::Receiver<Result<Response, akio_h3::H3Error>> {
    let (tx, rx) = mpsc::channel();
    c.request(Method::Get, "/small", h, Vec::new(), move |r| {
        let _ = tx.send(r);
    });
    rx
}

/// Responses encoded on an application thread.
#[test]
fn server_encodes_off_the_handler() {
    let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let s = server();
    let c = client(&s, 0);
    let (tx, rx) = mpsc::channel();
    for _ in 0..2 {
        let tx = tx.clone();
        c.request(
            Method::Get,
            "/held",
            &Headers::new(),
            Vec::new(),
            move |r| {
                let _ = tx.send(r);
            },
        );
    }
    let start = Instant::now();
    while s.held.lock().unwrap().len() < 2 {
        assert!(start.elapsed() < T, "requests not held");
        std::thread::sleep(Duration::from_millis(1));
    }
    let (a, b) = {
        let mut held = s.held.lock().unwrap();
        let b = held.pop().unwrap();
        (held.pop().unwrap(), b)
    };
    let deferred = Deferred::on(Side::Server);
    // The first response inserts into the table; the client acknowledges it on its decoder
    // stream, and the acknowledgment waits at the server.
    bounded("the first response", move || {
        let mut r = Response::new(200);
        r.headers = repeated("x-first", "one");
        a.respond(r);
    });
    let r = rx.recv_timeout(T).unwrap().unwrap();
    assert_eq!(r.headers.get("x-first"), Some("one"));
    std::thread::sleep(Duration::from_millis(200));
    // The second inserts too, sending on the encoder stream: that send runs the handler on
    // this thread, and the handler reads the acknowledgment.
    bounded("the second response (server)", move || {
        let mut r = Response::new(200);
        r.headers = repeated("x-second", "two");
        b.respond(r);
    });
    drop(deferred);
    let r = rx.recv_timeout(T).unwrap().unwrap();
    assert_eq!(r.headers.get("x-second"), Some("two"));
    assert_eq!(c.get("/small", T).unwrap().status, 200);
    s.e.shutdown();
}

/// Requests encoded on an application thread.
#[test]
fn client_encodes_off_the_handler() {
    let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let s = server();
    let c = client(&s, 4096);
    let deferred = Deferred::on(Side::Client);
    // The first request inserts; the server acknowledges it and that waits at the client.
    let c2 = c.clone();
    let first = bounded("the first request", move || {
        send(&c2, &repeated("x-first", "one"))
    });
    std::thread::sleep(Duration::from_millis(200));
    // The second inserts too: its encoder-stream send runs the handler here.
    let c2 = c.clone();
    let second = bounded("the second request (client)", move || {
        send(&c2, &repeated("x-second", "two"))
    });
    drop(deferred);
    // Whatever still waits runs with the next call.
    assert_eq!(c.get("/small", T).unwrap().status, 200);
    assert_eq!(first.recv_timeout(T).unwrap().unwrap().status, 200);
    assert_eq!(second.recv_timeout(T).unwrap().unwrap().status, 200);
    s.e.shutdown();
}

/// A client WebSocket sending on an application thread while a ping waits (answering it
/// takes the sender's lock).
#[test]
fn client_websocket_sends_off_the_handler() {
    let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let s = server();
    let c = client(&s, 0);
    let (tx, rx) = mpsc::channel();
    let ws = c
        .websocket_blocking("/ws", &H3WsOptions::default(), Texts(tx), T)
        .unwrap();
    let deferred = Deferred::on(Side::Client);
    // The server answers with a ping and the echo; both wait at the client.
    let w2 = ws.clone();
    bounded("the first message", move || w2.send_text("one")).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    bounded("the second message (client)", move || ws.send_text("two")).unwrap();
    drop(deferred);
    assert_eq!(c.get("/small", T).unwrap().status, 200);
    assert_eq!(rx.recv_timeout(T).unwrap(), "one");
    assert_eq!(rx.recv_timeout(T).unwrap(), "two");
    s.e.shutdown();
}

/// A server WebSocket sending on an application thread while the client's ping waits.
#[test]
fn server_websocket_sends_off_the_handler() {
    let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let s = server();
    let c = client(&s, 0);
    let (tx, rx) = mpsc::channel();
    let ws = c
        .websocket_blocking("/ws", &H3WsOptions::default(), Texts(tx), T)
        .unwrap();
    let start = Instant::now();
    let server_ws = loop {
        let w = s.ws.lock().unwrap().clone();
        if let Some(w) = w {
            break w;
        }
        assert!(start.elapsed() < T, "no server WebSocket");
        std::thread::sleep(Duration::from_millis(1));
    };
    let deferred = Deferred::on(Side::Server);
    // The client's ping waits at the server.
    ws.ping(b"c").unwrap();
    std::thread::sleep(Duration::from_millis(200));
    bounded("the server's message", move || {
        server_ws.send_text("from the server")
    })
    .unwrap();
    drop(deferred);
    assert_eq!(c.get("/small", T).unwrap().status, 200);
    assert_eq!(rx.recv_timeout(T).unwrap(), "from the server");
    s.e.shutdown();
}
