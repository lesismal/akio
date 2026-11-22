//! Companion of the book's "WebSocket" chapter: a broadcasting server mounted on a akio-http
//! router and two `akio` WebSocket clients.
//!
//! `cargo run -p akio-ws --example guide-ws`

use std::{
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};

use akio::Engine;
use akio_http::{Context, Router, WsOptions, serve};
use akio_ws::{
    Message, PreparedMessage, WsConfig, WsHandler, WsSender,
    client::{self, DialOptions},
};

// ANCHOR: server
type Room = Arc<Mutex<Vec<WsSender>>>;

struct Member {
    room: Room,
}

impl WsHandler for Member {
    fn on_open(&mut self, ws: &WsSender) {
        self.room.lock().unwrap().push(ws.clone());
    }

    fn on_message(&mut self, _ws: &WsSender, msg: Message) {
        if let Message::Text(t) = msg {
            // Encode once, send to everyone (each send is non-blocking).
            let m = PreparedMessage::text(&t);
            self.room
                .lock()
                .unwrap()
                .retain(|s| s.send_prepared(&m).is_ok());
        }
    }

    fn on_close(&mut self, code: Option<u16>, _reason: &str) {
        println!("member left with {code:?}");
    }
}

fn chat_app(room: Room) -> Router {
    let mut opts = WsOptions::default();
    opts.config = WsConfig::default(); // permessage-deflate on when the client offers it
    opts.config.max_message_bytes = 1 << 20;
    opts.protocols = vec!["chat".into()];
    opts.origin_allowed = None; // e.g. Some(|o| o == "https://example.com")
    Router::new().get("/ws", move |ctx: &mut Context| {
        // Answers 101 and switches the connection, or answers 400/403/426 itself.
        ctx.upgrade_websocket(Member { room: room.clone() }, &opts);
    })
}
// ANCHOR_END: server

// ANCHOR: client
struct Printer(mpsc::Sender<String>);

impl WsHandler for Printer {
    fn on_message(&mut self, _ws: &WsSender, msg: Message) {
        if let Message::Text(t) = msg {
            let _ = self.0.send(t);
        }
    }
}
// ANCHOR_END: client

fn main() -> std::io::Result<()> {
    let room: Room = Arc::default();
    let engine = Arc::new(
        Engine::builder()
            .listen(
                akio::Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(serve(chat_app(room))),
            )
            .client_threads(1)
            .build()?,
    );
    engine.start()?;
    let url = format!("ws://{}/ws", engine.local_addrs()[0]);

    // ANCHOR: dial
    let mut opts = DialOptions::default(); // wss:// needs `tls: Some(akio::tls::ClientConfig)`
    opts.protocols = vec!["chat".into()];
    opts.handshake_timeout = Duration::from_secs(5);
    let (tx, rx) = mpsc::channel();
    let alice = client::dial_blocking(&engine, &url, &opts, Printer(tx.clone())).expect("alice");
    let _bob = client::dial_blocking(&engine, &url, &opts, Printer(tx)).expect("bob");
    assert_eq!(alice.subprotocol().as_deref(), Some("chat"));
    alice.send_text("hi all").expect("send");
    // ANCHOR_END: dial
    for _ in 0..2 {
        println!(
            "got {:?}",
            rx.recv_timeout(Duration::from_secs(5)).expect("broadcast")
        );
    }
    alice.close(akio_ws::protocol::close::NORMAL, "bye");

    engine.shutdown();
    engine.wait();
    Ok(())
}
