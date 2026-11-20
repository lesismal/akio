//! WebSocket over HTTP/2 (RFC 8441) interop with another implementation
//! (`tools/interop/h2ws/run.sh` runs it against Go's net/http).
//!
//! ```text
//! h2-ws-interop server <h2c-addr> <tls-addr>   echo WebSocket at /ws, text at /hello
//! h2-ws-interop client <h2c-addr> <tls-addr>   checks a server (h2c, then TLS)
//! ```
#![allow(missing_docs)]

use std::{
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

use only::{Engine, Listener, tls::Tls};
use only_http::{
    Context, H2Config, HttpConfig, Router, WsOptions,
    client::ClientRequest,
    h2client::{H2Client, H2Options, H2WsOptions},
    serve_with,
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

#[derive(Debug, PartialEq)]
enum Ev {
    Msg(Message),
    Close(Option<u16>),
}

struct Rec(mpsc::Sender<Ev>);

impl WsHandler for Rec {
    fn on_message(&mut self, _ws: &WsSender, msg: Message) {
        let _ = self.0.send(Ev::Msg(msg));
    }
    fn on_close(&mut self, code: Option<u16>, _reason: &str) {
        let _ = self.0.send(Ev::Close(code));
    }
}

fn app() -> Router {
    Router::new()
        .get("/ws", |ctx: &mut Context| {
            let mut o = WsOptions::default();
            o.protocols = vec!["chat".into()];
            ctx.upgrade_websocket(Echo, &o);
        })
        .get("/hello", |ctx: &mut Context| ctx.text(200, "hello h2"))
}

fn server(h2c: &str, tls: &str) {
    let ck = only_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let scfg = only::tls::ServerConfig::builder(
        vec![only::tls::Certificate::from_der(ck.0.as_der().to_vec())],
        only::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
    .alpn(["h2", "http/1.1"])
    .build()
    .unwrap();
    let cfg = || {
        let mut c = HttpConfig::default();
        c.h2 = Some(H2Config::default());
        c
    };
    let e = Engine::builder()
        .listen(Listener::tcp(h2c.parse().unwrap()).serve(serve_with(cfg(), app())))
        .listen(
            Listener::tcp(tls.parse().unwrap()).serve(Tls::server(scfg, serve_with(cfg(), app()))),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    eprintln!("only h2 websocket server on {h2c} (h2c) and {tls} (tls)");
    e.wait();
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u32).wrapping_mul(2_654_435_761).to_le_bytes()[2] ^ seed)
        .collect()
}

fn check(c: &H2Client, base: &str, deflate: bool) -> Result<(), String> {
    let (tx, rx) = mpsc::channel();
    let mut o = H2WsOptions::default();
    o.protocols = vec!["v9".into(), "chat".into()];
    o.config.permessage_deflate = deflate;
    let ws = c
        .websocket_blocking(&format!("{base}/ws"), &o, Rec(tx))
        .map_err(|e| format!("open: {e}"))?;
    if ws.subprotocol().as_deref() != Some("chat") {
        return Err(format!("subprotocol {:?}", ws.subprotocol()));
    }
    let next = || {
        rx.recv_timeout(Duration::from_secs(10))
            .map_err(|e| e.to_string())
    };
    let text = "compress me please ".repeat(4000);
    let msgs = [
        Message::Text("hello".into()),
        Message::Binary(pattern(3 << 20, u8::from(deflate))),
        Message::Text(text.clone()),
        Message::Binary(Vec::new()),
    ];
    for m in &msgs {
        match m {
            Message::Text(t) => ws.send_text(t),
            Message::Binary(b) => ws.send_binary(b),
        }
        .map_err(|e| format!("send: {e}"))?;
        let got = next()?;
        if got != Ev::Msg(m.clone()) {
            return Err(format!("echo mismatch (deflate {deflate})"));
        }
    }
    ws.send_text_fragmented(&text, 1000)
        .map_err(|e| e.to_string())?;
    if next()? != Ev::Msg(Message::Text(text)) {
        return Err("fragmented echo mismatch".into());
    }
    ws.close(1000, "bye");
    match next()? {
        Ev::Close(Some(1000)) => Ok(()),
        other => Err(format!("close: {other:?}")),
    }
}

fn client(h2c: &str, tls: &str) {
    let e = Arc::new(Engine::builder().client_threads(2).build().unwrap());
    e.start().unwrap();
    let insecure = only::tls::ClientConfig::builder()
        .insecure_skip_verify()
        .alpn(["h2"])
        .build()
        .unwrap();
    for (name, addr, tls_cfg) in [("h2c", h2c, None), ("tls", tls, Some(insecure))] {
        let sa = addr.parse().unwrap();
        let scheme = if tls_cfg.is_some() { "https" } else { "http" };
        let base = format!("{scheme}://localhost:{}", sa_port(addr));
        let c = H2Client::dial_blocking(
            &e,
            sa,
            tls_cfg.map(|c| (c, "localhost")),
            H2Options::default(),
        )
        .expect("dial");
        let plain = {
            let (c, base) = (c.clone(), base.clone());
            thread::spawn(move || {
                c.send(ClientRequest::get(&format!("{base}/hello")))
                    .wait()
                    .map(|r| r.body)
            })
        };
        let socks: Vec<_> = [true, false]
            .into_iter()
            .map(|deflate| {
                let (c, base) = (c.clone(), base.clone());
                thread::spawn(move || check(&c, &base, deflate))
            })
            .collect();
        for s in socks {
            if let Err(e) = s.join().unwrap() {
                eprintln!("only client -> go ({name}): {e}");
                std::process::exit(1);
            }
        }
        match plain.join().unwrap() {
            Ok(b) if b == b"hello from go" => {}
            other => {
                eprintln!("only client -> go ({name}): plain request {other:?}");
                std::process::exit(1);
            }
        }
        eprintln!("only client -> go ({name}): ok");
    }
}

fn sa_port(addr: &str) -> &str {
    addr.rsplit(':').next().unwrap()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match (a.get(1).map(String::as_str), a.get(2), a.get(3)) {
        (Some("server"), Some(h), Some(t)) => server(h, t),
        (Some("client"), Some(h), Some(t)) => client(h, t),
        _ => {
            eprintln!("usage: h2-ws-interop server|client <h2c-addr> <tls-addr>");
            std::process::exit(2);
        }
    }
}
