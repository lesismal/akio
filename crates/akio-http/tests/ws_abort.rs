//! A WebSocket ended at once (akit A238): `WsSender::abort` closes the transport now, without a
//! close frame, dropping what is queued; both ends' `on_close` hear 1006. Over HTTP/1.1 (plain
//! and TLS: akio-ws's client against `Context::upgrade_websocket`) and over HTTP/2 (`H2Client`
//! against the extended CONNECT: the stream is reset, the connection goes on), from either
//! side, from another thread and from inside the handler's callback (on the backend under
//! test: epoll/kqueue, io_uring with `AKIO_TEST_BACKEND=uring`).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use akio::{Backend, Config, Engine, Error, Listener, UringConfig};
use akio_http::{
    Context, H2Config, HttpConfig, Router, WsOptions,
    h2client::{H2Client, H2Options, H2WsOptions},
    serve_with,
    ws::{MessageRef, WsConfig, WsHandler, WsSender, client::DialOptions},
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

const WAIT: Duration = Duration::from_secs(20);
const MSG: usize = 16 << 10;

/// One end: counts the bytes it gets, reports its close; `abort` makes it abort from inside
/// the callback, and what it gets after that is counted apart (it must stay 0).
struct Probe {
    got: Arc<AtomicUsize>,
    after: Arc<AtomicUsize>,
    aborted: Arc<AtomicBool>,
    closes: mpsc::Sender<Option<u16>>,
    /// Server side: the end is handed over from `on_open`.
    open: Option<OpenWith>,
}

/// What a server's end hands over from `on_open` (through the first), with its closes (the
/// second).
type OpenWith = (Arc<Mutex<mpsc::Sender<End>>>, mpsc::Receiver<Option<u16>>);

impl WsHandler for Probe {
    fn on_open(&mut self, ws: &WsSender) {
        if let Some((tx, closes)) = self.open.take() {
            let end = End {
                ws: ws.clone(),
                got: self.got.clone(),
                after: self.after.clone(),
                closes,
            };
            let _ = tx.lock().unwrap().send(end);
        }
    }
    fn on_message_ref(&mut self, ws: &WsSender, msg: MessageRef<'_>) {
        if self.aborted.load(Ordering::Acquire) {
            self.after.fetch_add(1, Ordering::AcqRel);
            return;
        }
        if msg.as_bytes() == b"abort" {
            self.aborted.store(true, Ordering::Release);
            ws.abort();
            assert!(!ws.is_open());
            assert!(matches!(ws.send_text("late"), Err(Error::Closed)));
            return;
        }
        self.got.fetch_add(msg.as_bytes().len(), Ordering::AcqRel);
    }
    fn on_close(&mut self, code: Option<u16>, _reason: &str) {
        let _ = self.closes.send(code);
    }
}

struct End {
    ws: WsSender,
    got: Arc<AtomicUsize>,
    after: Arc<AtomicUsize>,
    closes: mpsc::Receiver<Option<u16>>,
}

impl End {
    fn closed_with(&self) -> Option<u16> {
        self.closes.recv_timeout(WAIT).expect("on_close")
    }
}

fn probe() -> (
    Probe,
    mpsc::Receiver<Option<u16>>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let (tx, rx) = mpsc::channel();
    let (got, after) = (Arc::default(), Arc::default());
    (
        Probe {
            got: Arc::clone(&got),
            after: Arc::clone(&after),
            aborted: Arc::default(),
            closes: tx,
            open: None,
        },
        rx,
        got,
        after,
    )
}

struct Server {
    e: Arc<Engine>,
    addr: SocketAddr,
    ends: mpsc::Receiver<End>,
    /// The client's TLS configuration, when the server speaks TLS.
    tls: Option<akio::tls::ClientConfig>,
}

fn start(tls: bool) -> Server {
    let (tx, ends) = mpsc::channel();
    let tx = Arc::new(Mutex::new(tx));
    let opts = {
        let mut o = WsOptions::default();
        o.config = {
            let mut v = WsConfig::default();
            v.permessage_deflate = false;
            v
        };
        o
    };
    let app = Router::new().get("/ws", move |ctx: &mut Context| {
        let (mut p, closes, _, _) = probe();
        p.open = Some((tx.clone(), closes));
        ctx.upgrade_websocket(p, &opts);
    });
    let mut cfg = HttpConfig::default();
    cfg.h2 = Some({
        let mut h2 = H2Config::default();
        h2.initial_window = 64 << 10;
        h2
    });
    let l = Listener::tcp("127.0.0.1:0".parse().unwrap())
        .backend(backend())
        .threads(2);
    let (l, ctls) = if tls {
        let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
        let cert = ck.0.as_der().to_vec();
        let scfg = akio::tls::ServerConfig::builder(
            vec![akio::tls::Certificate::from_der(cert.clone())],
            akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
        )
        .build()
        .unwrap();
        let mut roots = akio::tls::RootCerts::empty();
        roots.add(&akio::tls::Certificate::from_der(cert)).unwrap();
        let ccfg = akio::tls::ClientConfig::builder()
            .roots(roots)
            .build()
            .unwrap();
        (
            l.serve(akio::tls::Tls::server(scfg, serve_with(cfg, app))),
            Some(ccfg),
        )
    } else {
        (l.serve(serve_with(cfg, app)), None)
    };
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_secs(3);
                v
            })
            .listen(l)
            .client_threads(2)
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    Server {
        e,
        addr,
        ends,
        tls: ctls,
    }
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

/// A WebSocket over HTTP/1.1 (TLS when the server speaks it): (client end, server end).
fn dial_h1(srv: &Server) -> (End, End) {
    let (p, closes, got, after) = probe();
    let mut o = DialOptions::default();
    o.config.permessage_deflate = false;
    let url = match &srv.tls {
        Some(t) => {
            o.tls = Some(t.clone());
            o.server_name = Some("localhost".into());
            format!("wss://{}/ws", srv.addr)
        }
        None => format!("ws://{}/ws", srv.addr),
    };
    let ws = akio_http::ws::client::dial_blocking(&srv.e, &url, &o, p).unwrap();
    let server = srv.ends.recv_timeout(WAIT).unwrap();
    (
        End {
            ws,
            got,
            after,
            closes,
        },
        server,
    )
}

/// A WebSocket over HTTP/2 (h2c) on `c`: (client end, server end).
fn dial_h2(srv: &Server, c: &H2Client) -> (End, End) {
    let (p, closes, got, after) = probe();
    let mut o = H2WsOptions::default();
    o.config.permessage_deflate = false;
    let ws = c
        .websocket_blocking(&format!("ws://{}/ws", srv.addr), &o, p)
        .unwrap();
    let server = srv.ends.recv_timeout(WAIT).unwrap();
    (
        End {
            ws,
            got,
            after,
            closes,
        },
        server,
    )
}

fn wait_for(what: &str, f: impl Fn() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < WAIT, "timed out: {what}");
        thread::sleep(Duration::from_millis(2));
    }
}

/// A round trip each way, so both ends are known to work.
fn exchange(a: &End, b: &End) {
    let (ga, gb) = (a.got.load(Ordering::Acquire), b.got.load(Ordering::Acquire));
    a.ws.send_binary(&[1; 100]).unwrap();
    b.ws.send_binary(&[2; 200]).unwrap();
    wait_for("an exchange", || {
        b.got.load(Ordering::Acquire) == gb + 100 && a.got.load(Ordering::Acquire) == ga + 200
    });
}

/// `to` holds its reads; `from` queues a backlog it cannot write, then aborts: its sends fail
/// at once, both ends hear 1006 (no close frame), and `to`, resumed, gets less than was sent
/// (the backlog was dropped, not written).
fn abort_with_backlog(from: &End, to: &End) {
    exchange(from, to);
    let base = to.got.load(Ordering::Acquire);
    to.ws.hold_reads(true);
    let msg = vec![0x5a; MSG];
    let mut sent = 0;
    let t = Instant::now();
    'fill: loop {
        while from.ws.queued_bytes() < 1 << 20 {
            match from.ws.send_binary(&msg) {
                Ok(()) => sent += MSG,
                Err(Error::Overloaded) => break 'fill,
                Err(e) => panic!("send: {e:?}"),
            }
            assert!(sent < 256 << 20, "the held peer never pushed back");
        }
        thread::sleep(Duration::from_millis(200));
        if from.ws.queued_bytes() > 0 {
            break;
        }
        assert!(t.elapsed() < WAIT, "the held peer never pushed back");
    }
    assert!(from.ws.queued_bytes() > 0);
    from.ws.abort();
    assert!(!from.ws.is_open());
    assert!(matches!(from.ws.send_binary(&msg), Err(Error::Closed)));
    assert!(matches!(from.ws.ping(b"p"), Err(Error::Closed)));
    // A second abort, and a close after it, do nothing.
    from.ws.abort();
    from.ws.close(1000, "");
    assert_eq!(from.closed_with(), Some(1006));
    to.ws.hold_reads(false);
    assert_eq!(
        to.closed_with(),
        Some(1006),
        "a close frame reached the peer"
    );
    let got = to.got.load(Ordering::Acquire) - base;
    assert!(got < sent, "all {sent} bytes arrived: nothing was dropped");
    // Each heard it once.
    thread::sleep(Duration::from_millis(100));
    assert!(from.closes.try_recv().is_err());
    assert!(to.closes.try_recv().is_err());
}

/// `from` aborts from another thread with nothing queued: both ends hear 1006.
fn abort_idle(from: &End, to: &End) {
    exchange(from, to);
    from.ws.abort();
    assert!(matches!(from.ws.send_text("x"), Err(Error::Closed)));
    assert_eq!(from.closed_with(), Some(1006));
    assert_eq!(to.closed_with(), Some(1006));
    assert!(matches!(to.ws.send_text("x"), Err(Error::Closed)));
}

/// `to`'s handler aborts on the message `abort`: nothing after it reaches the handler, both
/// ends hear 1006.
fn abort_in_callback(from: &End, to: &End) {
    exchange(from, to);
    from.ws.send_text("abort").unwrap();
    for _ in 0..100 {
        if from.ws.send_text("after").is_err() {
            break;
        }
    }
    assert_eq!(to.closed_with(), Some(1006));
    assert_eq!(from.closed_with(), Some(1006));
    assert_eq!(to.after.load(Ordering::Acquire), 0, "delivered after abort");
}

/// A client's close handshake under way (it waits for the server's answer, which does not
/// come while the server holds its reads: over TCP, unlike a stream's window, that stops the
/// close frame too) is cut short by an abort: the client hears 1006 at once, the server the
/// close frame, read before the end of the connection.
fn abort_after_close(client: &End, server: &End) {
    exchange(client, server);
    server.ws.hold_reads(true);
    // The hold takes effect on the server's I/O thread: probe until a message stays unread
    // (the close frame then queues behind it).
    let t = Instant::now();
    loop {
        let before = server.got.load(Ordering::Acquire);
        client.ws.send_binary(&[7; 10]).unwrap();
        thread::sleep(Duration::from_millis(200));
        if server.got.load(Ordering::Acquire) == before {
            break;
        }
        assert!(t.elapsed() < WAIT, "the server's reads were never held");
    }
    client.ws.close(1000, "bye");
    thread::sleep(Duration::from_millis(100));
    assert!(
        client.closes.try_recv().is_err(),
        "closed before the answer"
    );
    client.ws.abort();
    assert_eq!(client.closed_with(), Some(1006));
    server.ws.hold_reads(false);
    assert_eq!(server.closed_with(), Some(1000));
}

fn http1(tls: bool) {
    let srv = start(tls);
    let (c, s) = dial_h1(&srv);
    abort_with_backlog(&s, &c);
    let (c, s) = dial_h1(&srv);
    abort_with_backlog(&c, &s);
    let (c, s) = dial_h1(&srv);
    abort_idle(&c, &s);
    let (c, s) = dial_h1(&srv);
    abort_idle(&s, &c);
    let (c, s) = dial_h1(&srv);
    abort_in_callback(&c, &s);
    let (c, s) = dial_h1(&srv);
    abort_in_callback(&s, &c);
    let (c, s) = dial_h1(&srv);
    abort_after_close(&c, &s);
    stop(&srv.e);
}

#[test]
fn http1_websocket_aborted() {
    http1(false);
}

#[test]
fn http1_websocket_over_tls_aborted() {
    http1(true);
}

#[test]
fn http2_websocket_aborted() {
    let srv = start(false);
    let mut co = H2Options::default();
    co.initial_window = 64 << 10;
    let c = H2Client::dial_blocking(&srv.e, srv.addr, None, co).unwrap();
    // Each abort resets one stream; the connection and its other WebSockets go on.
    let (keep_c, keep_s) = dial_h2(&srv, &c);
    let (a, b) = dial_h2(&srv, &c);
    abort_with_backlog(&b, &a);
    let (a, b) = dial_h2(&srv, &c);
    abort_with_backlog(&a, &b);
    let (a, b) = dial_h2(&srv, &c);
    abort_idle(&a, &b);
    let (a, b) = dial_h2(&srv, &c);
    abort_idle(&b, &a);
    let (a, b) = dial_h2(&srv, &c);
    abort_in_callback(&a, &b);
    let (a, b) = dial_h2(&srv, &c);
    abort_in_callback(&b, &a);
    exchange(&keep_c, &keep_s);
    assert!(keep_c.closes.try_recv().is_err() && keep_s.closes.try_recv().is_err());
    stop(&srv.e);
}
