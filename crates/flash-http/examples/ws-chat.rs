//! A tiny chat room: `cargo run --release -p flash-http --example ws-chat`, open
//! http://127.0.0.1:8081/ in two browser tabs.
//!
//! One HTTP route serves the page, another upgrades to WebSocket; every message is encoded once
//! (`PreparedMessage`) and sent to all connected clients.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use flash::{Engine, Listener};
use flash_http::{
    Context, Router, WsOptions, serve,
    ws::{Message, PreparedMessage, WsHandler, WsSender},
};

const PAGE: &str = r#"<!doctype html><meta charset=utf-8><title>flash chat</title>
<pre id=log style="height:60vh;overflow:auto;border:1px solid #888"></pre>
<form id=f><input id=m autofocus placeholder="say something"><button>send</button></form>
<script>
const ws = new WebSocket(`ws://${location.host}/chat`), log = document.getElementById('log');
ws.onmessage = e => { log.textContent += e.data + '\n'; log.scrollTop = log.scrollHeight; };
f.onsubmit = e => { e.preventDefault(); if (m.value) ws.send(m.value); m.value = ''; };
</script>"#;

#[derive(Default)]
struct Room {
    members: Mutex<HashMap<u64, WsSender>>,
}

impl Room {
    fn broadcast(&self, text: &str) {
        let msg = PreparedMessage::text(text); // encoded once, shared by every send
        for s in self.members.lock().unwrap().values() {
            let _ = s.send_prepared(&msg);
        }
    }
}

struct Member {
    id: u64,
    room: Arc<Room>,
}

impl WsHandler for Member {
    fn on_open(&mut self, ws: &WsSender) {
        self.room
            .members
            .lock()
            .unwrap()
            .insert(self.id, ws.clone());
        self.room.broadcast(&format!("* user{} joined", self.id));
    }
    fn on_message(&mut self, _ws: &WsSender, msg: Message) {
        if let Message::Text(t) = msg {
            self.room.broadcast(&format!("user{}: {t}", self.id));
        }
    }
    fn on_close(&mut self, _code: Option<u16>, _reason: &str) {
        self.room.members.lock().unwrap().remove(&self.id);
        self.room.broadcast(&format!("* user{} left", self.id));
    }
}

fn main() -> std::io::Result<()> {
    let room = Arc::new(Room::default());
    let next = Arc::new(AtomicU64::new(1));
    let app = Router::new()
        .get("/", |ctx: &mut Context| {
            ctx.bytes(200, "text/html; charset=utf-8", PAGE.as_bytes().to_vec());
        })
        .get("/chat", move |ctx: &mut Context| {
            let member = Member {
                id: next.fetch_add(1, Ordering::Relaxed),
                room: room.clone(),
            };
            ctx.upgrade_websocket(member, &WsOptions::default());
        });
    let engine = Engine::builder()
        .listen(Listener::tcp("127.0.0.1:8081".parse().expect("address")).serve(serve(app)))
        .build()?;
    println!("chat on http://{}/", engine.local_addrs()[0]);
    engine.run()
}
