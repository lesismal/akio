//! A WebSocket over HTTP/3 ended at once (akit A238): `WsSender::abort` resets the request
//! stream both ways (`H3_REQUEST_CANCELLED`), without a close frame, dropping what its send
//! buffer holds; both ends' `on_close` hear 1006, and the QUIC connection and its other
//! streams go on. From either side, from another thread and from inside the handler's
//! callback.
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use akio::{Engine, Error, Listener};
use akio_h3::{H3Client, H3ClientOptions, H3Config, H3WsOptions};
use akio_http::ws::{MessageRef, WsHandler, WsSender};
use akio_http::{Context, Router, WsOptions};

const T: Duration = Duration::from_secs(20);
const MSG: usize = 16 << 10;

/// One end: counts the bytes it gets, reports its close (and the thread it ran on); `abort`
/// makes it abort from inside the callback, and what it gets after that is counted apart.
struct Probe {
    got: Arc<AtomicUsize>,
    after: Arc<AtomicUsize>,
    aborted: Arc<AtomicBool>,
    closes: mpsc::Sender<Option<u16>>,
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
        self.closes.recv_timeout(T).expect("on_close")
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

fn server() -> (Arc<Engine>, SocketAddr, mpsc::Receiver<End>) {
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let quic = akio_h3::server_config(vec![cert], key).unwrap();
    let (tx, rx) = mpsc::channel();
    let tx = Arc::new(Mutex::new(tx));
    let app = Router::new().get("/ws", move |ctx: &mut Context| {
        let mut o = WsOptions::default();
        o.config.permessage_deflate = false;
        let (mut p, closes, _, _) = probe();
        p.open = Some((tx.clone(), closes));
        ctx.upgrade_websocket(p, &o);
    });
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
    (Arc::new(e), addr, rx)
}

fn dial(c: &H3Client, opened: &mpsc::Receiver<End>) -> (End, End) {
    let (p, closes, got, after) = probe();
    let mut o = H3WsOptions::default();
    o.config.permessage_deflate = false;
    let ws = c.websocket_blocking("/ws", &o, p, T).unwrap();
    let server = opened.recv_timeout(T).unwrap();
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
        assert!(t.elapsed() < T, "timed out: {what}");
        thread::sleep(Duration::from_millis(2));
    }
}

fn exchange(a: &End, b: &End) {
    let (ga, gb) = (a.got.load(Ordering::Acquire), b.got.load(Ordering::Acquire));
    a.ws.send_binary(&[1; 100]).unwrap();
    b.ws.send_binary(&[2; 200]).unwrap();
    wait_for("an exchange", || {
        b.got.load(Ordering::Acquire) == gb + 100 && a.got.load(Ordering::Acquire) == ga + 200
    });
}

/// `to` holds its reads; `from` fills its stream's send buffer, then aborts: its sends fail at
/// once, both ends hear 1006, and `to` got less than was sent.
fn abort_with_backlog(from: &End, to: &End) {
    exchange(from, to);
    let base = to.got.load(Ordering::Acquire);
    to.ws.hold_reads(true);
    let msg = vec![0x3c; MSG];
    let mut sent = 0;
    loop {
        match from.ws.send_binary(&msg) {
            Ok(()) => sent += MSG,
            Err(Error::Overloaded) => break,
            Err(e) => panic!("send: {e:?}"),
        }
        assert!(sent < 1 << 30, "the held peer never pushed back");
    }
    assert!(from.ws.queued_bytes() > 0);
    from.ws.abort();
    assert!(!from.ws.is_open());
    assert!(matches!(from.ws.send_binary(&msg), Err(Error::Closed)));
    from.ws.abort();
    from.ws.close(1000, "");
    assert_eq!(from.closed_with(), Some(1006));
    assert_eq!(
        to.closed_with(),
        Some(1006),
        "a close frame reached the peer"
    );
    to.ws.hold_reads(false);
    thread::sleep(Duration::from_millis(100));
    assert!(to.got.load(Ordering::Acquire) - base < sent);
    assert!(from.closes.try_recv().is_err() && to.closes.try_recv().is_err());
}

fn abort_idle(from: &End, to: &End) {
    exchange(from, to);
    from.ws.abort();
    assert!(matches!(from.ws.send_text("x"), Err(Error::Closed)));
    assert_eq!(from.closed_with(), Some(1006));
    assert_eq!(to.closed_with(), Some(1006));
}

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

#[test]
fn http3_websocket_aborted() {
    let (e, addr, opened) = server();
    let cc = akio_quic::client_config_insecure(&[b"h3"]).unwrap();
    let c = H3Client::dial_with(&e, addr, "localhost", cc, H3ClientOptions::default()).unwrap();
    let (keep_c, keep_s) = dial(&c, &opened);
    let (a, b) = dial(&c, &opened);
    abort_with_backlog(&b, &a);
    let (a, b) = dial(&c, &opened);
    abort_with_backlog(&a, &b);
    let (a, b) = dial(&c, &opened);
    abort_idle(&a, &b);
    let (a, b) = dial(&c, &opened);
    abort_idle(&b, &a);
    let (a, b) = dial(&c, &opened);
    abort_in_callback(&a, &b);
    let (a, b) = dial(&c, &opened);
    abort_in_callback(&b, &a);
    // A close under way (the client waits for the server's answer) is cut short.
    let (a, b) = dial(&c, &opened);
    exchange(&a, &b);
    a.ws.close(1000, "bye");
    a.ws.abort();
    assert!(matches!(a.closed_with(), Some(1000 | 1006)));
    assert!(b.closed_with().is_some());
    // The connection and its other WebSocket went on.
    exchange(&keep_c, &keep_s);
    assert!(keep_c.closes.try_recv().is_err() && keep_s.closes.try_recv().is_err());
    e.shutdown();
    e.wait();
}
