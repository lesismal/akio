//! WebSocket echo server, the target of the Autobahn conformance suite:
//! `cargo run --release -p flash-http --example ws-echo -- 0.0.0.0:9001`

use flash::{Engine, Listener};
use flash_http::{
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

fn main() -> std::io::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9001".into())
        .parse()
        .expect("address");
    let opts = WsOptions::default();
    // Autobahn connects to "/", so serve the upgrade on every path.
    let app = Router::new()
        .get("/", {
            let opts = opts.clone();
            move |ctx: &mut Context| {
                ctx.upgrade_websocket(Echo, &opts);
            }
        })
        .fallback({
            move |ctx: &mut Context| {
                ctx.upgrade_websocket(Echo, &opts);
            }
        });
    let engine = Engine::builder()
        .listen(Listener::tcp(addr).serve(serve(app)))
        .build()?;
    println!("ws echo on {:?}", engine.local_addrs());
    engine.run()
}
