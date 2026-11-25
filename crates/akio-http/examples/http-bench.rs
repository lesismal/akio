//! Server for the HTTP / WebSocket benchmarks (see docs/BENCHMARKS.md):
//!
//! `http-bench <addr> <threads> <epoll|uring> [tls]`
//!
//! * `GET /plaintext`: `Hello, World!` as `text/plain` (TechEmpower style).
//! * `GET /json`: `{"message":"Hello, World!"}`, serialised per request.
//! * `GET /ws`: WebSocket upgrade, echoes every message.
//!
//! HTTP/2 is served on the same port (prior knowledge / h2c upgrade, or ALPN `h2` with `tls`).
//! `AKIO_KTLS=off|hardware|software|software-tx` sets the kernel TLS mode of `tls` (`Ktls`;
//! takes effect with akio's `ktls` feature on Linux).
//!
//! Shared I/O groups (ADR-130, `tools/bench/shared.sh`): `AKIO_BENCH_LISTENERS=n` serves the
//! same app on `n` listeners, at the ports `port`, `port + 1`, ... of `addr` (plain only). Each
//! has `<threads>` I/O threads of its own (`Listener::threads`, as every listener had before
//! ADR-130), or with `AKIO_BENCH_SHARED=1` they share `<threads>` (`EngineBuilder::io_threads`).

use akio::{
    Backend, Engine, Listener,
    tls::{Certificate, PrivateKey, ServerConfig, Tls},
};
use akio_http::{
    Context, Router, WsOptions, serve,
    ws::{Message, WsHandler, WsSender},
};

struct Echo;

impl WsHandler for Echo {
    fn on_message(&mut self, ws: &WsSender, msg: Message) {
        let _ = match msg {
            Message::Text(t) => ws.send_text(&t),
            Message::Binary(b) => ws.send_binary(&b),
        };
    }
}

/// `{"message":<s>}` with JSON string escaping: a stand-in for a serializer, done per request.
fn json_message(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() + 14);
    out.extend_from_slice(b"{\"message\":\"");
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut b = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
            }
        }
    }
    out.extend_from_slice(b"\"}");
    out
}

fn main() -> std::io::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 3 {
        eprintln!("usage: http-bench <addr> <threads> <epoll|uring> [tls]");
        std::process::exit(2);
    }
    let addr = a[0].parse().expect("address");
    let threads: usize = a[1].parse().expect("threads");
    let backend = match a[2].as_str() {
        "uring" => Backend::IoUring(Default::default()),
        _ => Backend::Epoll,
    };
    let app = || {
        let opts = WsOptions::default();
        Router::new()
            .get("/plaintext", |ctx: &mut Context| {
                ctx.text(200, "Hello, World!");
            })
            .get("/json", |ctx: &mut Context| {
                ctx.bytes(200, "application/json", json_message("Hello, World!"));
            })
            .get("/ws", move |ctx: &mut Context| {
                ctx.upgrade_websocket(Echo, &opts);
            })
    };
    let listeners: usize = std::env::var("AKIO_BENCH_LISTENERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    if listeners > 1 {
        let shared = std::env::var("AKIO_BENCH_SHARED").as_deref() == Ok("1");
        let mut b = Engine::builder();
        if shared {
            b = b.io_threads(threads);
        }
        let base: std::net::SocketAddr = addr;
        for i in 0..listeners {
            let mut at = base;
            if base.port() != 0 {
                at.set_port(base.port() + i as u16);
            }
            let l = Listener::tcp(at).backend(backend.clone());
            let l = if shared { l } else { l.threads(threads) };
            b = b.listen(l.serve(serve(app())));
        }
        let engine = b.build()?;
        println!("listening on {:?}", engine.local_addrs());
        return engine.run();
    }
    let app = app();
    let l = Listener::tcp(addr).backend(backend).threads(threads);
    let l = if a.get(3).map(String::as_str) == Some("tls") {
        let ck =
            akio_x509::generate_simple_self_signed(["localhost"]).map_err(std::io::Error::other)?;
        let cfg = ServerConfig::builder(
            vec![Certificate::from_der(ck.0.as_der().to_vec())],
            PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
        )
        .alpn(["h2", "http/1.1"])
        .ktls(match std::env::var("AKIO_KTLS").as_deref() {
            Ok("hardware") => akio::tls::Ktls::Hardware,
            Ok("software") => akio::tls::Ktls::Software,
            Ok("software-tx") => akio::tls::Ktls::SoftwareTx,
            _ => akio::tls::Ktls::Off,
        })
        .build()?;
        l.serve(Tls::server(cfg, serve(app)))
    } else {
        l.serve(serve(app))
    };
    let engine = Engine::builder().listen(l).build()?;
    println!("listening on {:?}", engine.local_addrs());
    engine.run()
}
