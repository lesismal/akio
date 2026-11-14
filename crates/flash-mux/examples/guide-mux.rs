//! Companion of the book's "Protocol multiplexing" chapter: HTTP (1 and 2), a custom
//! line protocol and a fallback on one port.
//!
//! `cargo run -p flash-mux --example guide-mux`

use std::{
    io::{Read, Write},
    net::TcpStream,
};

use flash::{Conn, Engine, Handler, Listener, fn_acceptor};
use flash_http::{Context, Router, serve};
use flash_mux::{Decision, Mux, Rule};

struct Tagged(&'static str);

impl Handler for Tagged {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(format!("[{}] {}", self.0, String::from_utf8_lossy(data)).as_bytes());
    }
}

fn ask(addr: std::net::SocketAddr, bytes: &[u8]) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(bytes).unwrap();
    let mut b = [0u8; 1024];
    let n = s.read(&mut b).unwrap();
    String::from_utf8_lossy(&b[..n]).into_owned()
}

fn main() -> std::io::Result<()> {
    // ANCHOR: mux
    let http = serve(Router::new().get("/", |ctx: &mut Context| ctx.text(200, "http here\n")));
    let mux = Mux::new()
        .route(Rule::Http, http) // HTTP/1.x request lines and the HTTP/2 preface
        .route(
            Rule::Prefix(b"PING".to_vec()),
            fn_acceptor(|_c: &Conn<Tagged>| Tagged("ping")),
        )
        .route(
            Rule::Custom(std::sync::Arc::new(|b: &[u8]| match b[0] {
                b'{' => Decision::Yes, // looks like JSON
                _ => Decision::No,
            })),
            fn_acceptor(|_c: &Conn<Tagged>| Tagged("json")),
        )
        .fallback(fn_acceptor(|_c: &Conn<Tagged>| Tagged("other")))
        .max_sniff_bytes(64); // give up sniffing (and use the fallback) after this many bytes
    let engine = Engine::builder()
        .listen(Listener::tcp("127.0.0.1:0".parse().unwrap()).serve_any(mux))
        .build()?;
    engine.start()?;
    // ANCHOR_END: mux
    let addr = engine.local_addrs()[0];
    println!(
        "{}",
        ask(addr, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .lines()
            .last()
            .unwrap()
    );
    println!("{}", ask(addr, b"PING 1"));
    println!("{}", ask(addr, b"{\"a\":1}"));
    println!("{}", ask(addr, b"hello"));
    engine.shutdown();
    engine.wait();
    Ok(())
}
