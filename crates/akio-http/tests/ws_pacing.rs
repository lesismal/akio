//! A WebSocket paced from outside (ADR-183, akit A236): `WsSender::hold_reads`, `on_drain`,
//! `peer_addr`, `set_relayed` and `set_max_queued_bytes`, over HTTP/1.1 (akio-ws's client
//! against `Context::upgrade_websocket`) and over HTTP/2 (`H2Client` against the extended
//! CONNECT), both directions, from threads other than the connections' (on the backend under
//! test: epoll/kqueue, io_uring with `AKIO_TEST_BACKEND=uring`).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
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
/// The engine's write high watermark: small, so that a queue passes it quickly.
const HIGH_WATER: usize = 64 << 10;

/// Counts the bytes of the messages it gets; `ping` messages are reported.
struct Count {
    got: Arc<AtomicUsize>,
    pings: Arc<AtomicUsize>,
}

impl WsHandler for Count {
    fn on_message_ref(&mut self, _ws: &WsSender, msg: MessageRef<'_>) {
        if msg.as_bytes() == b"ping" {
            self.pings.fetch_add(1, Ordering::AcqRel);
        } else {
            self.got.fetch_add(msg.as_bytes().len(), Ordering::AcqRel);
        }
    }
}

/// One end of a WebSocket as the test drives it.
#[derive(Clone)]
struct End {
    ws: WsSender,
    got: Arc<AtomicUsize>,
    pings: Arc<AtomicUsize>,
    /// Server side: how a drain waiter set inside the handler's callback ran (`DRAIN_*`).
    drained: Arc<AtomicUsize>,
}

/// The waiter has not run.
const DRAIN_NOT_YET: usize = 0;
/// It ran inside the callback that set it, before what the callback sent was queued: wrong.
const DRAIN_INSIDE: usize = 1;
/// It ran after the callback, once what it sent was out.
const DRAIN_AFTER: usize = 2;

fn counter() -> (Count, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let (got, pings) = (Arc::default(), Arc::default());
    (
        Count {
            got: Arc::clone(&got),
            pings: Arc::clone(&pings),
        },
        got,
        pings,
    )
}

/// The server's handler hands its end over from `on_open`.
struct ServerSide {
    count: Count,
    ends: Arc<Mutex<mpsc::Sender<End>>>,
    drained: Arc<AtomicUsize>,
}

impl WsHandler for ServerSide {
    fn on_open(&mut self, ws: &WsSender) {
        let end = End {
            ws: ws.clone(),
            got: self.count.got.clone(),
            pings: self.count.pings.clone(),
            drained: self.drained.clone(),
        };
        let _ = self.ends.lock().unwrap().send(end);
    }
    fn on_message_ref(&mut self, ws: &WsSender, msg: MessageRef<'_>) {
        if msg.as_bytes() == b"drain" {
            // Sent from the callback, then a waiter: it runs once they are out, not now.
            for _ in 0..3 {
                ws.send_binary(&[3u8; 1024]).unwrap();
            }
            let inside = Arc::new(AtomicUsize::new(1));
            let (i2, d) = (inside.clone(), self.drained.clone());
            ws.on_drain(move || {
                let how = if i2.load(Ordering::Acquire) == 1 {
                    DRAIN_INSIDE
                } else {
                    DRAIN_AFTER
                };
                d.store(how, Ordering::Release);
            });
            inside.store(0, Ordering::Release);
            return;
        }
        if msg.as_bytes() == b"flood" {
            // More than the kernel's buffers take (the peer holds its reads).
            let chunk = vec![1u8; MSG];
            for _ in 0..(32 << 20) / MSG {
                ws.send_binary(&chunk).unwrap();
            }
            return;
        }
        self.count.on_message_ref(ws, msg);
    }
}

struct Server {
    e: Arc<Engine>,
    addr: SocketAddr,
    ends: mpsc::Receiver<End>,
}

fn start() -> Server {
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
        let (count, _, _) = counter();
        ctx.upgrade_websocket(
            ServerSide {
                count,
                ends: tx.clone(),
                drained: Arc::default(),
            },
            &opts,
        );
    });
    let mut cfg = HttpConfig::default();
    cfg.h2 = Some({
        let mut h2 = H2Config::default();
        h2.initial_window = 64 << 10;
        h2
    });
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_secs(3);
                v.write_high_watermark = HIGH_WATER;
                v
            })
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .backend(backend())
                    .threads(2)
                    .serve(serve_with(cfg, app)),
            )
            .client_threads(2)
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    Server { e, addr, ends }
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

/// A WebSocket over HTTP/1.1: (client end, server end).
fn dial_h1(srv: &Server) -> (End, End) {
    let (count, got, pings) = counter();
    let mut o = DialOptions::default();
    o.config.permessage_deflate = false;
    let ws =
        akio_http::ws::client::dial_blocking(&srv.e, &format!("ws://{}/ws", srv.addr), &o, count)
            .unwrap();
    let server = srv.ends.recv_timeout(WAIT).unwrap();
    let drained = Arc::default();
    (
        End {
            ws,
            got,
            pings,
            drained,
        },
        server,
    )
}

/// A WebSocket over HTTP/2 (h2c): (client end, server end, the client keeping it).
fn dial_h2(srv: &Server) -> (End, End, H2Client) {
    let (count, got, pings) = counter();
    let mut co = H2Options::default();
    co.initial_window = 64 << 10;
    let c = H2Client::dial_blocking(&srv.e, srv.addr, None, co).unwrap();
    let mut o = H2WsOptions::default();
    o.config.permessage_deflate = false;
    let ws = c
        .websocket_blocking(&format!("ws://{}/ws", srv.addr), &o, count)
        .unwrap();
    let server = srv.ends.recv_timeout(WAIT).unwrap();
    let drained = Arc::default();
    (
        End {
            ws,
            got,
            pings,
            drained,
        },
        server,
        c,
    )
}

fn wait_for(what: &str, f: impl Fn() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < WAIT, "timed out: {what}");
        thread::sleep(Duration::from_millis(2));
    }
}

/// `to` holds its reads; `from` sends until its queue backs up (or a send is refused); what
/// `to` got stops growing, `from`'s drain waiter does not run. `to` resumes: everything
/// arrives and the waiter runs, on the connection's I/O thread.
fn held_then_drained(from: &End, to: &End) {
    let base = to.got.load(Ordering::Acquire);
    to.ws.hold_reads(true);
    let msg = vec![0x5a; MSG];
    let mut sent = 0;
    let t = Instant::now();
    'fill: loop {
        while from.ws.queued_bytes() < 256 << 10 {
            match from.ws.send_binary(&msg) {
                Ok(()) => sent += MSG,
                Err(Error::Overloaded) => break 'fill,
                Err(e) => panic!("send: {e:?}"),
            }
            assert!(sent < 256 << 20, "the held peer never pushed back");
        }
        // What was in flight when the reads were held arrives, and the kernel's buffers take
        // what they will; then the queue stays.
        thread::sleep(Duration::from_millis(300));
        if from.ws.queued_bytes() > 0 {
            break;
        }
        assert!(t.elapsed() < WAIT, "the held peer never pushed back");
    }
    let held = to.got.load(Ordering::Acquire);
    thread::sleep(Duration::from_millis(200));
    assert_eq!(
        to.got.load(Ordering::Acquire),
        held,
        "reads went on while held"
    );
    assert!(
        held - base < sent,
        "{} of {sent} delivered while held",
        held - base
    );
    let (dtx, drx) = mpsc::channel();
    from.ws.on_drain(move || {
        let _ = dtx.send(thread::current().name().map(str::to_owned));
    });
    assert!(
        drx.recv_timeout(Duration::from_millis(200)).is_err(),
        "drained while the peer held its reads"
    );
    to.ws.hold_reads(false);
    let t = Instant::now();
    while to.got.load(Ordering::Acquire) - base != sent {
        assert!(
            t.elapsed() < WAIT,
            "after the reads resumed: {} of {sent}, {} queued",
            to.got.load(Ordering::Acquire) - base,
            from.ws.queued_bytes(),
        );
        thread::sleep(Duration::from_millis(2));
    }
    let on = drx.recv_timeout(WAIT).expect("the drain waiter ran");
    assert_ne!(
        on.as_deref(),
        Some(thread::current().name().unwrap()),
        "ran on the I/O thread, not the caller's"
    );
    wait_for("the queue empty", || from.ws.queued_bytes() == 0);
    // Nothing queued: a waiter runs at once, on this thread.
    let (tx, rx) = mpsc::channel();
    from.ws.on_drain(move || {
        let _ = tx.send(());
    });
    rx.try_recv().expect("ran at once");
}

/// Over TCP, a waiter set inside the handler's callback, after messages sent there, runs once
/// they are out: after the callback returns (they join the connection's queue first), never
/// inside it. (Over HTTP/2 the stream's queue is what waits for a window: messages framed at
/// once leave it empty.)
fn drain_from_the_callback(client: &End, server: &End) {
    let base = client.got.load(Ordering::Acquire);
    client.ws.send_text("drain").unwrap();
    wait_for("the waiter set in the callback", || {
        server.drained.load(Ordering::Acquire) != DRAIN_NOT_YET
    });
    assert_eq!(server.drained.load(Ordering::Acquire), DRAIN_AFTER);
    wait_for("the callback's messages", || {
        client.got.load(Ordering::Acquire) - base == 3 * 1024
    });
}

#[test]
fn http1_websocket_paced_both_ways() {
    let srv = start();
    let (client, server) = dial_h1(&srv);
    assert_eq!(client.ws.peer_addr(), Some(srv.addr));
    let p = server.ws.peer_addr().expect("the client's address");
    assert!(p.ip().is_loopback() && p.port() != srv.addr.port(), "{p}");
    held_then_drained(&client, &server);
    held_then_drained(&server, &client);
    drain_from_the_callback(&client, &server);
    stop(&srv.e);
}

#[test]
fn http2_websocket_paced_both_ways() {
    let srv = start();
    let (client, server, _c) = dial_h2(&srv);
    assert_eq!(client.ws.peer_addr(), Some(srv.addr));
    let p = server.ws.peer_addr().expect("the client's address");
    assert!(p.ip().is_loopback() && p.port() != srv.addr.port(), "{p}");
    held_then_drained(&client, &server);
    held_then_drained(&server, &client);
    // The stream's queue is bounded by the connection's options.
    assert!(matches!(
        server.ws.set_max_queued_bytes(Some(1 << 20)),
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::Unsupported
    ));
    stop(&srv.e);
}

/// While its queue is past the write high watermark, a connection's reads pause, unless it is
/// one end of a relay (`set_relayed`): then a message from the peer still arrives.
#[test]
fn a_relayed_websocket_reads_past_its_high_watermark() {
    let srv = start();
    let (client, server) = dial_h1(&srv);
    client.ws.hold_reads(true);
    // The server queues past its watermark from its own callback, so that its I/O thread sees
    // the queue when the callback returns, and pauses its reads.
    client.ws.send_text("flood").unwrap();
    wait_for("the server's queue past its watermark", || {
        server.ws.queued_bytes() >= 4 * HIGH_WATER
    });
    client.ws.send_text("ping").unwrap();
    thread::sleep(Duration::from_millis(300));
    assert_eq!(
        server.pings.load(Ordering::Acquire),
        0,
        "read past the watermark"
    );
    server.ws.set_relayed(true);
    wait_for("the ping, once relayed", || {
        server.pings.load(Ordering::Acquire) == 1
    });
    assert!(server.ws.queued_bytes() >= 4 * HIGH_WATER, "still queued");
    client.ws.hold_reads(false);
    wait_for("the server's queue drained", || {
        server.ws.queued_bytes() == 0
    });
    stop(&srv.e);
}

/// A WebSocket's connection takes a bound of its own on its queue (A234): just under, at and
/// past it while the peer holds its reads; `None` restores the engine's.
#[test]
fn a_websocket_with_its_own_queue_bound() {
    let srv = start();
    let (client, server) = dial_h1(&srv);
    client.ws.hold_reads(true);
    let msg = vec![2u8; MSG];
    let frame = MSG + 4; // a 16 KiB binary frame's header is 4 bytes
    // At the bound, a frame and a byte are refused. That needs the queue to sit still, the
    // kernel taking no more: a queue unchanged for 100 ms may only be a server thread that has
    // not run (a busy machine), and the kernel takes some once it does. A send that goes in
    // then never passes the bound, but says the queue was not at it: settle and try again.
    let mut tries = 0;
    loop {
        // The kernel's buffers fill first: queue until something still waits once the queue
        // settles, then bound what waits. Something waiting right after a send may only be a
        // server thread yet to write it, and the kernel's send buffer grows as it takes data
        // (on a Linux host it took all that waited, try after try): fill again until it stays.
        let mut queued = 0;
        while queued == 0 {
            while server.ws.queued_bytes() == 0 {
                server.ws.send_binary(&msg).unwrap();
                thread::sleep(Duration::from_millis(1));
            }
            queued = server.ws.queued_bytes();
            loop {
                thread::sleep(Duration::from_millis(100));
                let now = server.ws.queued_bytes();
                if now == queued {
                    break;
                }
                queued = now;
            }
        }
        let bound = queued + 2 * frame;
        server.ws.set_max_queued_bytes(Some(bound)).unwrap();
        server.ws.send_binary(&msg).unwrap();
        server.ws.send_binary(&msg).unwrap(); // at the bound
        let past = [server.ws.send_binary(&msg), server.ws.send_binary(b"x")];
        assert!(
            server.ws.queued_bytes() <= bound,
            "the queue passed its bound"
        );
        server.ws.set_max_queued_bytes(None).unwrap();
        for r in &past {
            assert!(matches!(r, Ok(()) | Err(Error::Overloaded)), "{r:?}");
        }
        if past.iter().all(|r| matches!(r, Err(Error::Overloaded))) {
            break;
        }
        tries += 1;
        assert!(tries < 10, "the queue never settled at the bound");
    }
    server.ws.send_binary(&msg).unwrap();
    client.ws.hold_reads(false);
    wait_for("the server's queue drained", || {
        server.ws.queued_bytes() == 0
    });
    stop(&srv.e);
}
