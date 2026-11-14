//! Companion of the book's "SOCKS and proxies" chapter: a SOCKS5 server with username/password
//! authentication and an HTTP CONNECT proxy on one engine, exercised by a hand-written SOCKS5
//! client against a local echo server.
//!
//! `cargo run -p flash-socks --example guide-socks`

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    thread,
};

use flash::{Engine, EngineRef, Listener};
use flash_socks::{Socks, connect_proxy};

fn echo_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            thread::spawn(move || {
                let mut b = [0u8; 4096];
                while let Ok(n) = s.read(&mut b) {
                    if n == 0 || s.write_all(&b[..n]).is_err() {
                        return;
                    }
                }
            });
        }
    });
    a
}

fn main() -> std::io::Result<()> {
    let target = echo_server();

    // ANCHOR: server
    // The proxies dial upstream through the engine, which does not exist yet: hand them an
    // EngineRef and point it at the engine once it is built.
    let engine_ref = EngineRef::new();
    let socks =
        Socks::new(engine_ref.clone()).auth(|user, pass| user == "ada" && pass == "lovelace");
    let engine = Arc::new(
        Engine::builder()
            .listen(Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(socks))
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .serve(flash_http::serve(connect_proxy(engine_ref.clone()))),
            )
            .client_threads(2) // upstream connections
            .build()?,
    );
    engine_ref.set(&engine);
    engine.start()?;
    // ANCHOR_END: server
    let socks_addr = engine.local_addrs()[0];

    // SOCKS5: greeting (username/password), auth, CONNECT to an IPv4 address.
    let mut s = TcpStream::connect(socks_addr)?;
    s.write_all(&[5, 1, 2])?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r)?;
    assert_eq!(r, [5, 2]);
    let (u, p) = (b"ada", b"lovelace");
    let mut auth = vec![1, u.len() as u8];
    auth.extend_from_slice(u);
    auth.push(p.len() as u8);
    auth.extend_from_slice(p);
    s.write_all(&auth)?;
    s.read_exact(&mut r)?;
    assert_eq!(r, [1, 0], "auth accepted");
    let SocketAddr::V4(t) = target else {
        unreachable!()
    };
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&t.ip().octets());
    req.extend_from_slice(&t.port().to_be_bytes());
    s.write_all(&req)?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply)?;
    assert_eq!(reply[1], 0, "CONNECT succeeded");
    s.write_all(b"through the proxy")?;
    let mut b = [0u8; 64];
    let n = s.read(&mut b)?;
    println!("echoed via SOCKS5: {}", String::from_utf8_lossy(&b[..n]));

    engine.shutdown();
    engine.wait();
    Ok(())
}
