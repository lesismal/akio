//! The WebSocket client against flash's own WebSocket server: plain, TLS, compression, large and
//! fragmented messages, close codes, subprotocols, handshake failures, many clients at once.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    net::TcpListener,
    sync::{
        Arc,
        mpsc::{self, Receiver, Sender},
    },
    time::Duration,
};

use flash::{Backend, Config, Engine, Listener, UringConfig, tls::rustls};
use flash_http::{Context, Router, WsOptions, serve};
use flash_ws::{
    Message, WsConfig, WsHandler, WsSender,
    client::{self, DialOptions, WsClientError},
    deflate::PmdOffer,
};

const T: Duration = Duration::from_secs(10);

fn backend() -> Backend {
    match std::env::var("FLASH_TEST_BACKEND").as_deref() {
        Ok("uring") => Backend::IoUring({
            let mut v = UringConfig::default();
            v.strict = true;
            v
        }),
        _ => Backend::Epoll,
    }
}

/// An engine serving `router` on one listener. Dials without `client_threads` run on the
/// listener's threads, so the client is exercised on the selected backend too.
fn start_with(router: Router, tls: Option<Arc<rustls::ServerConfig>>) -> (Arc<Engine>, u16) {
    let l = Listener::tcp("127.0.0.1:0".parse().unwrap())
        .backend(backend())
        .threads(2);
    let l = match tls {
        Some(cfg) => l.serve(flash::tls::Tls::server(cfg, serve(router))),
        None => l.serve(serve(router)),
    };
    let e = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(500);
            v
        })
        .listen(l)
        .build()
        .unwrap();
    e.start().unwrap();
    let port = e.local_addrs()[0].port();
    (Arc::new(e), port)
}

fn start(router: Router) -> (Arc<Engine>, u16) {
    start_with(router, None)
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

/// Server side: echoes every message; "close:<code>:<reason>" makes it close instead,
/// "frag:<n>:<text>" echoes <text> in frames of n bytes, "ping" makes it ping the client.
struct Echo {
    events: Option<Sender<Ev>>,
}

impl WsHandler for Echo {
    fn on_message(&mut self, ws: &WsSender, msg: Message) {
        match msg {
            Message::Text(t) => {
                if let Some(rest) = t.strip_prefix("close:") {
                    let (code, reason) = rest.split_once(':').unwrap();
                    ws.close(code.parse().unwrap(), reason);
                } else if let Some(rest) = t.strip_prefix("frag:") {
                    let (n, text) = rest.split_once(':').unwrap();
                    ws.send_text_fragmented(text, n.parse().unwrap()).unwrap();
                } else if t == "ping" {
                    ws.ping(b"srv").unwrap();
                } else {
                    let _ = ws.send_text(&t);
                }
            }
            Message::Binary(b) => {
                let _ = ws.send_binary(&b);
            }
        }
    }
    fn on_pong(&mut self, _ws: &WsSender, payload: &[u8]) {
        if let Some(tx) = &self.events {
            let _ = tx.send(Ev::Pong(payload.to_vec()));
        }
    }
    fn on_close(&mut self, code: Option<u16>, reason: &str) {
        if let Some(tx) = &self.events {
            let _ = tx.send(Ev::Close(code, reason.to_owned()));
        }
    }
}

fn echo_router(opts: WsOptions, server_events: Option<Sender<Ev>>) -> Router {
    Router::new().get("/ws", move |ctx: &mut Context| {
        // Report what the client sent, for the header tests.
        let seen = [
            "sec-websocket-extensions",
            "origin",
            "authorization",
            "user-agent",
        ]
        .iter()
        .map(|h| format!("{h}={}", ctx.header(h).unwrap_or("-")))
        .collect::<Vec<_>>()
        .join("|");
        let handler = Hello {
            seen,
            inner: Echo {
                events: server_events.clone(),
            },
        };
        ctx.upgrade_websocket(handler, &opts);
    })
}

/// Sends the request headers it saw as the first message, then echoes.
struct Hello {
    seen: String,
    inner: Echo,
}

impl WsHandler for Hello {
    fn on_open(&mut self, ws: &WsSender) {
        ws.send_text(&self.seen).unwrap();
    }
    fn on_message(&mut self, ws: &WsSender, msg: Message) {
        self.inner.on_message(ws, msg);
    }
    fn on_pong(&mut self, ws: &WsSender, payload: &[u8]) {
        self.inner.on_pong(ws, payload);
    }
    fn on_close(&mut self, code: Option<u16>, reason: &str) {
        self.inner.on_close(code, reason);
    }
}

#[derive(Debug, PartialEq)]
enum Ev {
    Open(Option<String>),
    Msg(Message),
    Pong(Vec<u8>),
    Close(Option<u16>, String),
}

/// Client side: reports everything.
struct Rec(Sender<Ev>);

impl WsHandler for Rec {
    fn on_open(&mut self, ws: &WsSender) {
        let _ = self.0.send(Ev::Open(ws.subprotocol()));
    }
    fn on_message(&mut self, _ws: &WsSender, msg: Message) {
        let _ = self.0.send(Ev::Msg(msg));
    }
    fn on_pong(&mut self, _ws: &WsSender, payload: &[u8]) {
        let _ = self.0.send(Ev::Pong(payload.to_vec()));
    }
    fn on_close(&mut self, code: Option<u16>, reason: &str) {
        let _ = self.0.send(Ev::Close(code, reason.to_owned()));
    }
}

/// Connects and consumes the open event and the server's greeting (the headers it saw).
fn open(
    e: &Arc<Engine>,
    url: &str,
    opts: &DialOptions,
) -> (WsSender, Receiver<Ev>, Option<String>, String) {
    let (tx, rx) = mpsc::channel();
    let ws =
        client::dial_blocking(e, url, opts, Rec(tx)).unwrap_or_else(|err| panic!("{url}: {err}"));
    let proto = match rx.recv_timeout(T).unwrap() {
        Ev::Open(p) => p,
        other => panic!("{other:?}"),
    };
    let seen = match rx.recv_timeout(T).unwrap() {
        Ev::Msg(Message::Text(t)) => t,
        other => panic!("{other:?}"),
    };
    (ws, rx, proto, seen)
}

fn next_msg(rx: &Receiver<Ev>) -> Message {
    match rx.recv_timeout(T).unwrap() {
        Ev::Msg(m) => m,
        other => panic!("{other:?}"),
    }
}

fn pattern(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761) | 1;
    (0..len)
        .map(|i| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            // Half compressible, half noise.
            if i % 2 == 0 { (i % 64) as u8 } else { x as u8 }
        })
        .collect()
}

fn roundtrips(ws: &WsSender, rx: &Receiver<Ev>) {
    ws.send_text("hello").unwrap();
    assert_eq!(next_msg(rx), Message::Text("hello".into()));
    ws.send_text("").unwrap();
    assert_eq!(next_msg(rx), Message::Text(String::new()));
    ws.send_text(&"héllo wörld ".repeat(500)).unwrap();
    assert_eq!(next_msg(rx), Message::Text("héllo wörld ".repeat(500)));
    for len in [0usize, 1, 125, 126, 65_535, 65_536, 300_000] {
        let data = pattern(len, len as u32);
        ws.send_binary(&data).unwrap();
        assert_eq!(next_msg(rx), Message::Binary(data), "len {len}");
    }
    ws.ping(b"cli").unwrap();
    assert_eq!(rx.recv_timeout(T).unwrap(), Ev::Pong(b"cli".to_vec()));
}

#[test]
fn plain_echo_ping_and_close_handshake() {
    let (stx, srx) = mpsc::channel();
    let (e, port) = start(echo_router(WsOptions::default(), Some(stx)));
    let url = format!("ws://127.0.0.1:{port}/ws");
    let (ws, rx, proto, seen) = open(&e, &url, &DialOptions::default());
    assert_eq!(proto, None);
    assert!(
        seen.contains("sec-websocket-extensions=permessage-deflate; client_max_window_bits"),
        "{seen}"
    );
    assert!(seen.contains("user-agent=flash-ws"), "{seen}");
    roundtrips(&ws, &rx);
    // The server pings: the client answers by itself.
    ws.send_text("ping").unwrap();
    assert_eq!(srx.recv_timeout(T).unwrap(), Ev::Pong(b"srv".to_vec()));
    // Client-initiated close: the server sees our code, we see its echo.
    ws.close(3001, "done here");
    assert!(!ws.is_open());
    assert!(ws.send_text("late").is_err());
    assert_eq!(
        srx.recv_timeout(T).unwrap(),
        Ev::Close(Some(3001), "done here".into())
    );
    assert_eq!(
        rx.recv_timeout(T).unwrap(),
        Ev::Close(Some(3001), String::new())
    );
    stop(&e);
}

#[test]
fn server_initiated_close_codes() {
    let (e, port) = start(echo_router(WsOptions::default(), None));
    let url = format!("ws://127.0.0.1:{port}/ws");
    for (code, reason) in [(1000u16, ""), (1001, "going"), (4001, "custom reason")] {
        let (ws, rx, _, _) = open(&e, &url, &DialOptions::default());
        ws.send_text(&format!("close:{code}:{reason}")).unwrap();
        assert_eq!(
            rx.recv_timeout(T).unwrap(),
            Ev::Close(Some(code), reason.into())
        );
        assert!(ws.send_text("x").is_err());
    }
    stop(&e);
}

#[test]
fn compression_negotiation_variants() {
    let (e, port) = start(echo_router(WsOptions::default(), None));
    let url = format!("ws://127.0.0.1:{port}/ws");
    let offers = [
        PmdOffer::default(),
        {
            let mut v = PmdOffer::default();
            v.client_no_context_takeover = true;
            v
        },
        {
            let mut v = PmdOffer::default();
            v.server_no_context_takeover = true;
            v.server_max_window_bits = Some(9);
            v
        },
        {
            let mut v = PmdOffer::default();
            v.client_no_context_takeover = true;
            v.server_no_context_takeover = true;
            v.server_max_window_bits = Some(12);
            v
        },
    ];
    for pmd in offers {
        let mut opts = DialOptions::default();
        opts.pmd = pmd;
        let (ws, rx, _, seen) = open(&e, &url, &opts);
        assert!(seen.contains(&pmd.header()), "{seen}");
        roundtrips(&ws, &rx);
        // Context takeover across many similar messages.
        for i in 0..50 {
            let m = format!("message number {i} with a repeated tail tail tail tail");
            ws.send_text(&m).unwrap();
            assert_eq!(next_msg(&rx), Message::Text(m));
        }
        ws.close(1000, "");
        assert_eq!(
            rx.recv_timeout(T).unwrap(),
            Ev::Close(Some(1000), String::new())
        );
    }
    // Compression off on either side: plain frames.
    let mut opts = DialOptions::default();
    opts.config = {
        let mut v = WsConfig::default();
        v.permessage_deflate = false;
        v
    };
    let (ws, rx, _, seen) = open(&e, &url, &opts);
    assert!(seen.contains("sec-websocket-extensions=-"), "{seen}");
    roundtrips(&ws, &rx);
    stop(&e);
    let (e, port) = start(echo_router(
        {
            let mut v = WsOptions::default();
            v.config = {
                let mut v = WsConfig::default();
                v.permessage_deflate = false;
                v
            };
            v
        },
        None,
    ));
    let url = format!("ws://127.0.0.1:{port}/ws");
    let (ws, rx, _, _) = open(&e, &url, &DialOptions::default());
    roundtrips(&ws, &rx);
    stop(&e);
}

#[test]
fn large_and_fragmented_messages_and_limits() {
    let (e, port) = start(echo_router(
        {
            let mut v = WsOptions::default();
            v.config = {
                let mut v = WsConfig::default();
                v.max_message_bytes = 64 << 20;
                v
            };
            v
        },
        None,
    ));
    let url = format!("ws://127.0.0.1:{port}/ws");
    for deflate in [false, true] {
        let mut opts = DialOptions::default();
        opts.config = {
            let mut v = WsConfig::default();
            v.max_message_bytes = 64 << 20;
            v.permessage_deflate = deflate;
            v
        };
        let (ws, rx, _, _) = open(&e, &url, &opts);
        let big = pattern(8 << 20, 7);
        ws.send_binary(&big).unwrap();
        assert!(
            next_msg(&rx) == Message::Binary(big.clone()),
            "8 MiB, deflate {deflate}"
        );
        // Client → server in small frames (UTF-8 split across frames included).
        let text = "fragmented € text ".repeat(1000);
        ws.send_text_fragmented(&text, 7).unwrap();
        assert_eq!(next_msg(&rx), Message::Text(text.clone()));
        ws.send_binary_fragmented(&big[..100_000], 4096).unwrap();
        assert_eq!(next_msg(&rx), Message::Binary(big[..100_000].to_vec()));
        // Server → client in small frames.
        ws.send_text(&format!("frag:5:{text}")).unwrap();
        assert_eq!(next_msg(&rx), Message::Text(text));
    }
    // A message over the client's limit fails the connection with 1009.
    let mut opts = DialOptions::default();
    opts.config = {
        let mut v = WsConfig::default();
        v.max_message_bytes = 1000;
        v
    };
    let (ws, rx, _, _) = open(&e, &url, &opts);
    ws.send_binary(&[1; 999]).unwrap();
    assert_eq!(next_msg(&rx), Message::Binary(vec![1; 999]));
    ws.send_binary(&pattern(5000, 1)).unwrap();
    match rx.recv_timeout(T).unwrap() {
        Ev::Close(Some(1009), _) => {}
        other => panic!("{other:?}"),
    }
    stop(&e);
}

#[test]
fn subprotocols_origin_and_headers() {
    let mut opts_srv = WsOptions::default();
    opts_srv.protocols = vec!["v2.json".into(), "chat".into()];
    opts_srv.origin_allowed = Some(|o| o == "https://good.example");
    let (e, port) = start(echo_router(opts_srv, None));
    let url = format!("ws://127.0.0.1:{port}/ws");
    let mut opts = DialOptions::default();
    opts.protocols = vec!["mqtt".into(), "chat".into()];
    opts.origin = Some("https://good.example".into());
    opts.headers = vec![
        ("Authorization".into(), "Bearer t0k3n".into()),
        ("User-Agent".into(), "tester/1".into()),
    ];
    let (ws, rx, proto, seen) = open(&e, &url, &opts);
    assert_eq!(proto.as_deref(), Some("chat"));
    assert_eq!(ws.subprotocol().as_deref(), Some("chat"));
    assert!(seen.contains("origin=https://good.example"), "{seen}");
    assert!(seen.contains("authorization=Bearer t0k3n"), "{seen}");
    assert!(seen.contains("user-agent=tester/1"), "{seen}");
    roundtrips(&ws, &rx);
    // No common subprotocol: the server picks none.
    let (_, _, proto, _) = open(&e, &url, &{
        let mut v = DialOptions::default();
        v.protocols = vec!["mqtt".into()];
        v
    });
    assert_eq!(proto, None);
    // The origin policy refuses: a status error.
    let err = client::dial_blocking(
        &e,
        &url,
        &{
            let mut v = DialOptions::default();
            v.origin = Some("https://evil.example".into());
            v
        },
        Rec(mpsc::channel().0),
    )
    .err()
    .unwrap();
    assert!(matches!(err, WsClientError::Status(403, _)), "{err}");
    stop(&e);
}

#[test]
fn handshake_failures() {
    let (e, port) = start(echo_router(WsOptions::default(), None));
    let fail = |url: &str, opts: &DialOptions| {
        client::dial_blocking(&e, url, opts, Rec(mpsc::channel().0))
            .err()
            .unwrap_or_else(|| panic!("{url} connected"))
    };
    let d = DialOptions::default();
    let err = fail(&format!("ws://127.0.0.1:{port}/nope"), &d);
    assert!(matches!(err, WsClientError::Status(404, _)), "{err}");
    assert!(matches!(
        fail("http://x/", &d),
        WsClientError::InvalidUrl(_)
    ));
    assert!(matches!(
        fail(&format!("wss://127.0.0.1:{port}/ws"), &d),
        WsClientError::Io(_)
    ));
    // Nothing listens there.
    let free = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = free.local_addr().unwrap().port();
    drop(free);
    let err = fail(&format!("ws://127.0.0.1:{dead}/"), &d);
    assert!(matches!(err, WsClientError::Io(_)), "{err}");
    // A server that accepts and never answers.
    let mute = TcpListener::bind("127.0.0.1:0").unwrap();
    let mport = mute.local_addr().unwrap().port();
    let mut opts = DialOptions::default();
    opts.handshake_timeout = Duration::from_millis(300);
    let t0 = std::time::Instant::now();
    let err = fail(&format!("ws://127.0.0.1:{mport}/"), &opts);
    assert!(matches!(err, WsClientError::Timeout), "{err}");
    assert!(t0.elapsed() < Duration::from_secs(5));
    drop(mute);
    // A plain HTTP server that is not WebSocket: 101 is never sent.
    let (e2, port2) = start(Router::new().get("/", |ctx: &mut Context| ctx.text(200, "hi")));
    let err = fail(&format!("ws://localhost:{port2}/"), &d);
    assert!(matches!(err, WsClientError::Status(200, _)), "{err}");
    stop(&e2);
    stop(&e);
}

#[test]
fn wss_with_sni_and_custom_roots() {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert = ck.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        ck.key_pair.serialize_der(),
    ));
    let scfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    let (e, port) = start_with(
        echo_router(WsOptions::default(), None),
        Some(Arc::new(scfg)),
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let ccfg = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let mut opts = DialOptions::default();
    opts.tls = Some(ccfg.clone());
    // `localhost` may resolve to ::1 first: the client falls back to 127.0.0.1.
    let url = format!("wss://localhost:{port}/ws");
    let (ws, rx, _, _) = open(&e, &url, &opts);
    roundtrips(&ws, &rx);
    let big = pattern(4 << 20, 3);
    ws.send_binary(&big).unwrap();
    assert!(next_msg(&rx) == Message::Binary(big));
    ws.close(1000, "tls bye");
    assert_eq!(
        rx.recv_timeout(T).unwrap(),
        Ev::Close(Some(1000), String::new())
    );
    // By IP with an explicit server name for verification and SNI.
    let mut opts_ip = DialOptions::default();
    opts_ip.tls = Some(ccfg.clone());
    opts_ip.server_name = Some("localhost".into());
    let (ws, rx, _, _) = open(&e, &format!("wss://127.0.0.1:{port}/ws"), &opts_ip);
    roundtrips(&ws, &rx);
    // A name the certificate does not cover fails verification.
    let mut bad = DialOptions::default();
    bad.tls = Some(ccfg);
    bad.server_name = Some("other.example".into());
    let err = client::dial_blocking(
        &e,
        &format!("wss://127.0.0.1:{port}/ws"),
        &bad,
        Rec(mpsc::channel().0),
    )
    .err()
    .unwrap();
    assert!(
        matches!(err, WsClientError::Io(_) | WsClientError::Closed),
        "{err}"
    );
    stop(&e);
}

#[test]
fn many_concurrent_clients_on_client_threads() {
    let (srv, port) = start(echo_router(WsOptions::default(), None));
    let cli = Arc::new(Engine::builder().client_threads(2).build().unwrap());
    cli.start().unwrap();
    let url = format!("ws://127.0.0.1:{port}/ws");
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let (cli, url) = (cli.clone(), url.clone());
            std::thread::spawn(move || {
                let conns: Vec<_> = (0..8)
                    .map(|_| open(&cli, &url, &DialOptions::default()))
                    .collect();
                for round in 0..20 {
                    for (i, (ws, _, _, _)) in conns.iter().enumerate() {
                        ws.send_text(&format!("{t}-{i}-{round}")).unwrap();
                    }
                    for (i, (_, rx, _, _)) in conns.iter().enumerate() {
                        assert_eq!(next_msg(rx), Message::Text(format!("{t}-{i}-{round}")));
                    }
                }
                for (ws, rx, _, _) in conns {
                    ws.close(1000, "");
                    assert_eq!(
                        rx.recv_timeout(T).unwrap(),
                        Ev::Close(Some(1000), String::new())
                    );
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    // Sending from many threads on one connection: frames never interleave.
    let (ws, rx, _, _) = open(&cli, &url, &DialOptions::default());
    let senders: Vec<_> = (0..4)
        .map(|t| {
            let ws = ws.clone();
            std::thread::spawn(move || {
                for i in 0..200 {
                    ws.send_binary(&pattern(1000 + i, t * 1000 + i as u32))
                        .unwrap();
                }
            })
        })
        .collect();
    for s in senders {
        s.join().unwrap();
    }
    for _ in 0..800 {
        match next_msg(&rx) {
            Message::Binary(b) => assert!((1000..1200).contains(&b.len())),
            other => panic!("{other:?}"),
        }
    }
    stop(&cli);
    stop(&srv);
}

/// Interop against an external echo server (e.g. a Go one), when `FLASH_WS_INTEROP_URL` is set:
/// `FLASH_WS_INTEROP_URL=ws://127.0.0.1:9100/ws cargo test -p flash-ws --test client interop`.
#[test]
fn interop_with_external_echo_server() {
    let Ok(url) = std::env::var("FLASH_WS_INTEROP_URL") else {
        return;
    };
    let cli = Arc::new(Engine::builder().client_threads(1).build().unwrap());
    cli.start().unwrap();
    for pmd in [false, true] {
        let mut opts = DialOptions::default();
        opts.config = {
            let mut v = WsConfig::default();
            v.permessage_deflate = pmd;
            v.max_message_bytes = 64 << 20;
            v
        };
        let (tx, rx) = mpsc::channel();
        let ws = client::dial_blocking(&cli, &url, &opts, Rec(tx)).unwrap();
        assert_eq!(rx.recv_timeout(T).unwrap(), Ev::Open(None));
        roundtrips(&ws, &rx);
        let big = pattern(8 << 20, 11);
        ws.send_binary(&big).unwrap();
        assert!(next_msg(&rx) == Message::Binary(big));
        let text = "interop € ".repeat(10_000);
        ws.send_text_fragmented(&text, 1000).unwrap();
        assert_eq!(next_msg(&rx), Message::Text(text));
        ws.close(1000, "bye");
        match rx.recv_timeout(T).unwrap() {
            Ev::Close(Some(1000), _) => {}
            other => panic!("{other:?}"),
        }
    }
    stop(&cli);
}
