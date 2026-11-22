//! UDP echo with a per-peer counter: `cargo run --release -p only --example udp-echo`, then
//! `nc -u 127.0.0.1 7002` and type lines.

use akio::{Conn, Engine, Handler, Listener, fn_acceptor};

struct Peer {
    seen: u32,
}

impl Handler for Peer {
    /// One call per datagram.
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        self.seen += 1;
        let mut reply = format!("#{} from {}: ", self.seen, c.peer_addr()).into_bytes();
        reply.extend_from_slice(data);
        let _ = c.send(&reply); // one datagram back to this peer
    }
}

fn main() -> std::io::Result<()> {
    let addr = "127.0.0.1:7002".parse().expect("address");
    let engine = Engine::builder()
        .listen(Listener::udp(addr).serve(fn_acceptor(|_c: &Conn<Peer>| Peer { seen: 0 })))
        .build()?;
    println!("udp echo on {:?}", engine.local_addrs());
    engine.run()
}
