//! Streamed responses on the HTTP/3 client (`H3Client::open`): pieces as they arrive,
//! trailers, flow control backpressure with `hold_reads`, cancellation, the head timeout, a
//! streamed upload and download at once, and the same with QPACK dynamic tables both ways.
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use akio::{Engine, Listener};
use akio_h3::{H3Client, H3ClientOptions, H3Config, H3Error, H3Event, H3Upload};
use akio_http::message::{Headers, Method};
use akio_http::{BodyEvent, Context, Router, Streaming};

const T: Duration = Duration::from_secs(20);

fn pattern(n: usize, salt: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 7 + salt) % 251) as u8).collect()
}

/// Writes `data` to a streamed response, retrying refused writes, then trailers.
fn produce(s: akio_http::BodyStream, data: Vec<u8>, sent: Arc<AtomicUsize>) {
    std::thread::spawn(move || {
        for piece in data.chunks(32 << 10) {
            loop {
                match s.write(piece) {
                    Ok(()) => break,
                    Err(akio::Error::Overloaded) => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => return,
                }
            }
            sent.fetch_add(piece.len(), Ordering::Relaxed);
        }
        let mut t = Headers::new();
        t.set("x-total", data.len().to_string());
        s.finish_with_trailers(t);
    });
}

struct Srv {
    e: Arc<Engine>,
    addr: SocketAddr,
    /// Bytes the `/big` producer got its server to take.
    sent: Arc<AtomicUsize>,
    /// Requests parked unanswered.
    parked: Arc<Mutex<Vec<akio_http::Detached>>>,
    /// The streamed response of `/gate`, its head sent, its body left to the test.
    gate: Arc<Mutex<Option<akio_http::BodyStream>>>,
}

fn server(cfg: H3Config) -> Srv {
    let sent = Arc::new(AtomicUsize::new(0));
    let parked = Arc::new(Mutex::new(Vec::new()));
    let gate = Arc::new(Mutex::new(None));
    let (s2, p2, g2) = (sent.clone(), parked.clone(), gate.clone());
    let app = Router::new()
        .get("/big/:n", move |ctx: &mut Context| {
            let n: usize = ctx.param("n").unwrap_or("0").parse().unwrap();
            let mut h = Headers::new();
            h.set("x-kind", "big");
            let s = ctx.stream_response(200, h).unwrap();
            produce(s, pattern(n, 5), s2.clone());
        })
        .get("/small", |ctx: &mut Context| ctx.text(200, "small body"))
        .get("/gate", move |ctx: &mut Context| {
            *g2.lock().unwrap() = Some(ctx.stream_response(200, Headers::new()).unwrap());
        })
        .get("/never", move |ctx: &mut Context| {
            p2.lock().unwrap().push(ctx.detach().unwrap());
        })
        .route(
            Method::Post,
            "/echo",
            Streaming(|ctx: &mut Context| {
                // Echoes the request body as it arrives, in a streamed response written from
                // a thread of its own (refused writes are retried there, not on the loop).
                let out = ctx.stream_response(200, Headers::new()).unwrap();
                let (tx, rx) = mpsc::channel::<Option<Vec<u8>>>();
                std::thread::spawn(move || {
                    while let Ok(Some(d)) = rx.recv() {
                        while let Err(akio::Error::Overloaded) = out.write(&d) {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    }
                    out.finish();
                });
                ctx.on_body(move |_ctx, ev| {
                    let _ = tx.send(match ev {
                        BodyEvent::Chunk(d) => Some(d.to_vec()),
                        BodyEvent::End(_) => None,
                    });
                });
            }),
        );
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let mut t = akio_quic::TransportConfig::default();
    t.stream_send_buffer = 128 << 10;
    t.send_buffer = 512 << 10;
    let quic = akio_h3::server_config(vec![cert], key)
        .unwrap()
        .transport(&t);
    let e = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap())
                .serve(akio_h3::serve_with(quic, cfg, app)),
        )
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    Srv {
        e: Arc::new(e),
        addr,
        sent,
        parked,
        gate,
    }
}

/// A client granting `window` bytes of credit per stream.
fn client(s: &Srv, window: u64, opts: H3ClientOptions) -> H3Client {
    let mut ct = akio_quic::TransportConfig::default();
    ct.stream_receive_window = window;
    ct.receive_window = Some(window * 8);
    let cc = akio_quic::client_config_insecure(&[b"h3"])
        .unwrap()
        .transport(&ct);
    H3Client::dial_with(&s.e, s.addr, "localhost", cc, opts).unwrap()
}

/// What a streamed response reported.
#[derive(Default)]
struct Seen {
    status: u16,
    kind: Option<String>,
    body: Vec<u8>,
    pieces: usize,
    trailers: Option<Headers>,
    end: bool,
    error: Option<H3Error>,
}

/// An event callback recording into `seen`; `done` gets a message at End or Error.
fn record(
    seen: Arc<Mutex<Seen>>,
    done: mpsc::Sender<()>,
) -> impl FnMut(H3Event<'_>) + Send + 'static {
    move |ev| {
        let mut s = seen.lock().unwrap();
        match ev {
            H3Event::Head { status, headers } => {
                s.status = status;
                s.kind = headers.get("x-kind").map(str::to_owned);
            }
            H3Event::Data(d) => {
                s.body.extend_from_slice(d);
                s.pieces += 1;
            }
            H3Event::Trailers(t) => s.trailers = Some(t.clone()),
            H3Event::End => {
                s.end = true;
                let _ = done.send(());
            }
            H3Event::Error(e) => {
                s.error = Some(e);
                let _ = done.send(());
            }
            _ => {}
        }
    }
}

/// Runs `f` on a thread of its own and fails the test if it does not return within `T`: a
/// call that deadlocks fails the test instead of hanging it. Its thread is the caller's kind
/// (not the connection's), so the call drives the connection as the caller's would.
fn bounded<R: Send + 'static>(what: &str, f: impl FnOnce() -> R + Send + 'static) -> R {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(T)
        .unwrap_or_else(|_| panic!("{what} did not return within {T:?}"))
}

fn get(c: &H3Client, path: &str) -> (Arc<Mutex<Seen>>, mpsc::Receiver<()>, H3Upload) {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let (tx, rx) = mpsc::channel();
    let up = c.open(Method::Get, path, &Headers::new(), record(seen.clone(), tx));
    assert!(up.finish());
    (seen, rx, up)
}

#[test]
fn streamed_responses_arrive_in_pieces_with_trailers() {
    let s = server(H3Config::default());
    let c = client(&s, 1 << 20, H3ClientOptions::default());
    // Larger than the buffered limit: streamed responses are not limited.
    let mut o = H3ClientOptions::default();
    o.max_body_bytes = 1 << 20;
    let limited = client(&s, 1 << 20, o);
    for c in [&c, &limited] {
        let n = 6 << 20;
        let (seen, rx, _up) = get(c, &format!("/big/{n}"));
        rx.recv_timeout(T).unwrap();
        let seen = seen.lock().unwrap();
        assert!(seen.error.is_none(), "{:?}", seen.error);
        assert!(seen.end);
        assert_eq!(seen.status, 200);
        assert_eq!(seen.kind.as_deref(), Some("big"));
        assert!(seen.body == pattern(n, 5));
        assert!(seen.pieces > 4, "{} pieces", seen.pieces);
        let t = seen.trailers.as_ref().unwrap();
        assert_eq!(t.get("x-total"), Some(n.to_string().as_str()));
    }
    // A response that comes whole (one packet) is streamed too.
    let (seen, rx, _up) = get(&c, "/small");
    rx.recv_timeout(T).unwrap();
    let seen = seen.lock().unwrap();
    assert!(seen.end);
    assert_eq!(seen.body, b"small body");
    // Buffered requests on the same connection are unaffected.
    assert_eq!(c.get("/small", T).unwrap().body, b"small body");
    s.e.shutdown();
}

#[test]
fn held_reads_hold_the_server_back() {
    let s = server(H3Config::default());
    let window = 64 << 10;
    let c = client(&s, window, H3ClientOptions::default());
    let n = 4 << 20;
    let seen = Arc::new(Mutex::new(Seen::default()));
    let (tx, rx) = mpsc::channel();
    let got = Arc::new(AtomicU64::new(0));
    let g2 = got.clone();
    let mut rec = record(seen.clone(), tx);
    // The consumer holds reads from its first body piece on.
    let held = Arc::new(AtomicBool::new(false));
    let h2 = held.clone();
    let slot: Arc<Mutex<Option<Arc<H3Upload>>>> = Arc::new(Mutex::new(None));
    let s2 = slot.clone();
    let up = Arc::new(c.open(
        Method::Get,
        &format!("/big/{n}"),
        &Headers::new(),
        move |ev| {
            if let H3Event::Data(d) = &ev {
                g2.fetch_add(d.len() as u64, Ordering::Relaxed);
                if !h2.swap(true, Ordering::Relaxed) {
                    if let Some(up) = s2.lock().unwrap().as_ref() {
                        up.hold_reads(true);
                    }
                }
            }
            rec(ev);
        },
    ));
    *slot.lock().unwrap() = Some(up.clone());
    assert!(up.finish());
    // Wait until the stream is held and quiet.
    let start = Instant::now();
    while !held.load(Ordering::Relaxed) && start.elapsed() < T {
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(300));
    let at_hold = got.load(Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(500));
    // Nothing more is reported, and the server is held at the window: it has taken at most
    // what we read, the window and its own send buffers (128 KiB per stream).
    assert_eq!(got.load(Ordering::Relaxed), at_hold);
    let sent = s.sent.load(Ordering::Relaxed);
    assert!(
        (sent as u64) < at_hold + window + (128 << 10) + (64 << 10),
        "server took {sent} with {at_hold} read"
    );
    assert!(sent < n);
    // Resumed: the rest arrives.
    up.hold_reads(false);
    rx.recv_timeout(T).unwrap();
    let seen = seen.lock().unwrap();
    assert!(seen.end, "{:?}", seen.error);
    assert!(seen.body == pattern(n, 5));
    s.e.shutdown();
}

#[test]
fn cancel_and_head_timeout() {
    let s = server(H3Config::default());
    let mut o = H3ClientOptions::default();
    o.request_timeout = Some(Duration::from_millis(1500));
    let c = client(&s, 64 << 10, o);
    // No head within the request timeout.
    let (seen, rx, _up) = get(&c, "/never");
    rx.recv_timeout(T).unwrap();
    assert_eq!(seen.lock().unwrap().error, Some(H3Error::Timeout));
    // Past the head the timeout no longer applies: a held response outlives it.
    let (seen, rx, up) = get(&c, &format!("/big/{}", 2 << 20));
    let start = Instant::now();
    while seen.lock().unwrap().status == 0 && start.elapsed() < T {
        std::thread::sleep(Duration::from_millis(2));
    }
    up.hold_reads(true);
    std::thread::sleep(Duration::from_millis(2000));
    assert!(seen.lock().unwrap().error.is_none());
    // Resuming may deliver the rest, the end included, on the resuming thread (it hung there).
    let _up = bounded("hold_reads(false)", move || {
        up.hold_reads(false);
        up
    });
    rx.recv_timeout(T).unwrap();
    assert!(seen.lock().unwrap().end);
    // Cancelled mid-body: nothing more is reported, writes fail.
    let (seen, rx, up) = get(&c, &format!("/big/{}", 8 << 20));
    let start = Instant::now();
    while seen.lock().unwrap().body.is_empty() && start.elapsed() < T {
        std::thread::sleep(Duration::from_millis(2));
    }
    // Cancelling may deliver what is pending on the cancelling thread (it hung there too).
    let up = bounded("cancel", move || {
        up.cancel();
        up
    });
    let len = seen.lock().unwrap().body.len();
    assert!(rx.recv_timeout(Duration::from_millis(500)).is_err());
    {
        let seen = seen.lock().unwrap();
        assert!(!seen.end && seen.error.is_none());
        assert!(seen.body.len() < 8 << 20, "{} of {len}", seen.body.len());
    }
    assert!(!up.write(b"x"));
    // The connection goes on.
    assert_eq!(c.get("/small", T).unwrap().status, 200);
    // The connection is cut mid-body: the download fails, once.
    let c = client(&s, 64 << 10, H3ClientOptions::default());
    let (seen, rx, up) = get(&c, &format!("/big/{}", 8 << 20));
    let start = Instant::now();
    while seen.lock().unwrap().body.is_empty() && start.elapsed() < T {
        std::thread::sleep(Duration::from_millis(2));
    }
    up.hold_reads(true);
    c.close();
    rx.recv_timeout(T).unwrap();
    assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
    {
        let seen = seen.lock().unwrap();
        assert!(!seen.end);
        assert!(
            matches!(seen.error, Some(H3Error::Closed(_))),
            "{:?}",
            seen.error
        );
    }
    assert!(!up.write(b"x"));
    s.parked.lock().unwrap().clear();
    s.e.shutdown();
}

/// Resuming held reads can deliver what was held on the resuming thread, the response's end
/// included; the request's own lock is not held meanwhile (it was, and the thread waited on
/// itself for good).
#[test]
fn resuming_delivers_on_the_calling_thread() {
    let s = server(H3Config::default());
    let c = client(&s, 64 << 10, H3ClientOptions::default());
    for round in 0..20 {
        let (seen, rx, up) = get(&c, "/gate");
        let start = Instant::now();
        while seen.lock().unwrap().status == 0 {
            assert!(start.elapsed() < T, "no head");
            std::thread::sleep(Duration::from_millis(1));
        }
        up.hold_reads(true);
        let body = s.gate.lock().unwrap().take().unwrap();
        body.write(b"held body").unwrap();
        body.finish();
        // The body and the end arrive, held.
        std::thread::sleep(Duration::from_millis(50));
        assert!(!seen.lock().unwrap().end);
        let up = bounded(&format!("round {round}: hold_reads(false)"), move || {
            up.hold_reads(false);
            up
        });
        rx.recv_timeout(T).unwrap();
        let seen = seen.lock().unwrap();
        assert!(seen.end, "{:?}", seen.error);
        assert_eq!(seen.body, b"held body");
        assert!(!up.write(b"x"));
    }
    s.e.shutdown();
}

/// A body streamed up while the response streams down, on one request, with the QPACK
/// encoders on (`enc`) or off.
fn duplex(enc: usize) {
    let mut cfg = H3Config::default();
    cfg.qpack_encoder_capacity = enc;
    let s = server(cfg);
    let mut o = H3ClientOptions::default();
    o.qpack_encoder_capacity = enc;
    let c = client(&s, 256 << 10, o);
    assert_eq!(c.get("/small", T).unwrap().status, 200);
    for round in 0..4 {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let (tx, rx) = mpsc::channel();
        let mut h = Headers::new();
        h.set("x-app", "duplex-test-application");
        let up = c.open(Method::Post, "/echo", &h, record(seen.clone(), tx));
        let data = pattern(1 << 20, round);
        for piece in data.chunks(50_000) {
            assert!(up.write(piece));
            while up.queued_bytes() > 1 << 20 {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        assert!(up.finish());
        rx.recv_timeout(T).unwrap();
        let seen = seen.lock().unwrap();
        assert!(seen.end, "{:?}", seen.error);
        assert!(seen.body == data);
    }
    s.e.shutdown();
}

#[test]
fn streamed_upload_and_download_at_once() {
    duplex(0);
    duplex(4096);
}
