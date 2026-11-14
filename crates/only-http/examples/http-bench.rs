//! Server for the HTTP / WebSocket benchmarks (see docs/BENCHMARKS.md):
//!
//! `http-bench <addr> <threads> <epoll|uring> [tls]`
//!
//! * `GET /plaintext`: `Hello, World!` as `text/plain` (TechEmpower style).
//! * `GET /json`: `{"message":"Hello, World!"}`, serialised per request.
//! * `GET /ws`: WebSocket upgrade, echoes every message.
//!
//! HTTP/2 is served on the same port (prior knowledge / h2c upgrade, or ALPN `h2` with `tls`).

use only::{
    Backend, Engine, Listener,
    tls::{Certificate, PrivateKey, ServerConfig, Tls},
};
use only_http::{
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
    let opts = WsOptions::default();
    let app = Router::new()
        .get("/plaintext", |ctx: &mut Context| {
            ctx.text(200, "Hello, World!");
        })
        .get("/json", |ctx: &mut Context| {
            ctx.bytes(200, "application/json", json_message("Hello, World!"));
        })
        .get("/ws", move |ctx: &mut Context| {
            ctx.upgrade_websocket(Echo, &opts);
        });
    let l = Listener::tcp(addr).backend(backend).threads(threads);
    let l = if a.get(3).map(String::as_str) == Some("tls") {
        let ck =
            only_x509::generate_simple_self_signed(["localhost"]).map_err(std::io::Error::other)?;
        let cfg = ServerConfig::builder(
            vec![Certificate::from_der(ck.0.as_der().to_vec())],
            PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
        )
        .alpn(["h2", "http/1.1"])
        .build()?;
        l.serve(Tls::server(cfg, serve(app)))
    } else {
        l.serve(serve(app))
    };
    let engine = Engine::builder().listen(l).build()?;
    println!("listening on {:?}", engine.local_addrs());
    engine.run()
}
