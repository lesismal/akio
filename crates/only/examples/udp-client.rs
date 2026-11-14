//! UDP client: `cargo run --release -p only --example udp-echo` in one terminal, then
//! `cargo run --release -p only --example udp-client` in another.

use std::time::Duration;

use only::{Acceptor, Conn, Engine, Handler};

struct Printer;

impl Handler for Printer {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        println!("{} -> {}", c.peer_addr(), String::from_utf8_lossy(data));
        c.close();
    }
}

struct Hello;

impl Acceptor for Hello {
    type Handler = Printer;
    fn on_open(&self, c: &Conn<Printer>) -> Printer {
        let _ = c.send(b"hello over udp"); // no handshake: usable right away
        Printer
    }
}

fn main() -> std::io::Result<()> {
    let engine = Engine::builder().udp_client_threads(1).build()?;
    engine.start()?;
    engine.dial_udp("127.0.0.1:7002".parse().expect("address"), Hello, |e| {
        eprintln!("dial failed: {e}");
    });
    std::thread::sleep(Duration::from_millis(500));
    engine.shutdown();
    engine.wait();
    Ok(())
}
