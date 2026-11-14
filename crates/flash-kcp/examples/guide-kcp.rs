//! Companion of the book's "KCP" chapter: a KCP echo server and a client session with
//! kcp-go-compatible FEC and encryption.
//!
//! `cargo run -p flash-kcp --example guide-kcp`

use std::{
    sync::{Arc, mpsc},
    time::Duration,
};

use flash::{Engine, Listener};
use flash_kcp::{Crypt, KcpConfig, KcpHandler, KcpServer, Session};

// ANCHOR: server
struct Echo;

impl KcpHandler for Echo {
    fn on_message(&mut self, s: &Session, msg: Vec<u8>) {
        let _ = s.send(&msg); // fails with KcpError::Full when the send queue is full
    }
}
// ANCHOR_END: server

struct Client(mpsc::Sender<Vec<u8>>);

impl KcpHandler for Client {
    fn on_message(&mut self, _s: &Session, msg: Vec<u8>) {
        let _ = self.0.send(msg);
    }
}

fn main() -> std::io::Result<()> {
    // ANCHOR: config
    // Both sides must agree on crypt and FEC. The key is already derived (kcptun derives it
    // with PBKDF2-SHA1 from the passphrase); "aes" takes 32 bytes.
    let key = [7u8; 32];
    let mut cfg = KcpConfig::fast();
    cfg.crypt = Some(Arc::new(Crypt::new("aes", &key).expect("crypt")));
    cfg.data_shards = 10;
    cfg.parity_shards = 3;
    let server = KcpServer::new(cfg.clone(), |_s: &Session| Echo)
        .map_err(std::io::Error::other)?
        .max_sessions(10_000);
    let engine = Engine::builder()
        .listen(Listener::udp("127.0.0.1:0".parse().unwrap()).serve(server))
        .udp_client_threads(1) // flash_kcp::dial needs UDP client threads
        .build()?;
    engine.start()?;
    // ANCHOR_END: config

    // ANCHOR: client
    let (tx, rx) = mpsc::channel();
    let session = flash_kcp::dial(&engine, engine.local_addrs()[0], cfg, Client(tx))
        .map_err(std::io::Error::other)?;
    session.send(b"hello over KCP").expect("send"); // fine before the socket is up
    let echoed = rx.recv_timeout(Duration::from_secs(5)).expect("echo");
    println!(
        "{} (stats {:?})",
        String::from_utf8_lossy(&echoed),
        session.stats()
    );
    session.close();
    // ANCHOR_END: client

    engine.shutdown();
    engine.wait();
    Ok(())
}
