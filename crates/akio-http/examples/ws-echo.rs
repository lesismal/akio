//! WebSocket echo server, the target of the Autobahn conformance suite:
//! `cargo run --release -p akio-http --example ws-echo -- 0.0.0.0:9001`

use akio::{Engine, Listener};
use akio_http::{
    Context, Router, WsOptions, serve,
    ws::{MessageRef, WsHandler, WsSender},
};

struct Echo;

impl WsHandler for Echo {
    // Borrowed messages: echoing costs no allocation per message.
    fn on_message_ref(&mut self, ws: &WsSender, msg: MessageRef<'_>) {
        let _ = match msg {
            MessageRef::Text(t) => ws.send_text(t),
            MessageRef::Binary(b) => ws.send_binary(b),
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
