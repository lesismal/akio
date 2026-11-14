//! Companion of the book's "WebSocket" chapter: a broadcasting server mounted on a flash-http
//! router and two flash WebSocket clients.
//!
//! `cargo run -p flash-ws --example guide-ws`

use std::{
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};

use flash::Engine;
use flash_http::{Context, Router, WsOptions, serve};
use flash_ws::{
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
    let opts = WsOptions {
        config: WsConfig {
            max_message_bytes: 1 << 20,
            ..WsConfig::default() // permessage-deflate on when the client offers it
        },
        protocols: vec!["chat".into()],
        origin_allowed: None, // e.g. Some(|o| o == "https://example.com")
    };
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
                flash::Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(serve(chat_app(room))),
            )
            .client_threads(1)
            .build()?,
    );
    engine.start()?;
    let url = format!("ws://{}/ws", engine.local_addrs()[0]);

    // ANCHOR: dial
    let opts = DialOptions {
        protocols: vec!["chat".into()],
        handshake_timeout: Duration::from_secs(5),
        ..DialOptions::default() // wss:// needs `tls: Some(Arc<rustls::ClientConfig>)`
    };
    let (tx, rx) = mpsc::channel();
    let alice = client::connect(&engine, &url, &opts, Printer(tx.clone())).expect("alice");
    let _bob = client::connect(&engine, &url, &opts, Printer(tx)).expect("bob");
    assert_eq!(alice.subprotocol().as_deref(), Some("chat"));
    alice.send_text("hi all").expect("send");
    // ANCHOR_END: dial
    for _ in 0..2 {
        println!(
            "got {:?}",
            rx.recv_timeout(Duration::from_secs(5)).expect("broadcast")
        );
    }
    alice.close(flash_ws::protocol::close::NORMAL, "bye");

    engine.shutdown();
    engine.wait();
    Ok(())
}
