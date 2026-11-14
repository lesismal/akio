//! Companion of the book's "QUIC and HTTP/3" chapter: a QUIC echo server and a client on one
//! engine, with a throw-away self-signed certificate.
//!
//! `cargo run -p flash-quic --example guide-quic`

use std::{sync::mpsc, time::Duration};

use bytes::Bytes;
use flash::{Engine, Listener};
use flash_quic::{Connection, QuicHandler, QuicServer, StreamId};

// ANCHOR: server
/// Per-connection handler; callbacks run one at a time, in order, and must not block.
struct Echo;

impl QuicHandler for Echo {
    fn on_stream_data(&mut self, c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        let _ = c.send(id, data); // never blocks: queued until flow control allows
        if fin {
            let _ = c.finish(id);
        }
    }
}
// ANCHOR_END: server

// ANCHOR: client
struct Client {
    got: mpsc::Sender<Vec<u8>>,
    buf: Vec<u8>,
}

impl QuicHandler for Client {
    fn on_connected(&mut self, c: &Connection) {
        // Streams can be opened once the handshake is done.
        if let Some(id) = c.open_bi() {
            let _ = c.send(id, Bytes::from_static(b"hello over QUIC"));
            let _ = c.finish(id);
        }
    }

    fn on_stream_data(&mut self, c: &Connection, _id: StreamId, data: Bytes, fin: bool) {
        self.buf.extend_from_slice(&data);
        if fin {
            let _ = self.got.send(std::mem::take(&mut self.buf));
            c.close(0, b"done");
        }
    }
}
// ANCHOR_END: client

fn main() -> std::io::Result<()> {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .map_err(std::io::Error::other)?;
    let cert = flash::tls::Certificate::from_der(ck.cert.der().to_vec());
    let key = flash::tls::PrivateKey::from_pkcs8_der(ck.key_pair.serialize_der());

    // ANCHOR: engine
    let server_cfg = flash_quic::server_config(vec![cert.clone()], key, &[b"echo"])
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let engine = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap())
                .serve(QuicServer::new(server_cfg, |_c: &Connection| Echo)),
        )
        .udp_client_threads(1) // flash_quic::dial needs UDP client threads
        .build()?;
    engine.start()?;

    let mut roots = flash::tls::RootCerts::empty();
    roots.add(&cert).map_err(std::io::Error::other)?;
    let client_cfg = flash_quic::client_config(roots, &[b"echo"])
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let (tx, rx) = mpsc::channel();
    let _conn = flash_quic::dial(
        &engine,
        engine.local_addrs()[0],
        "localhost",
        client_cfg,
        Client {
            got: tx,
            buf: Vec::new(),
        },
    )
    .map_err(|e| std::io::Error::other(e.to_string()))?;
    let echoed = rx.recv_timeout(Duration::from_secs(5)).expect("echo");
    // ANCHOR_END: engine
    println!("{}", String::from_utf8_lossy(&echoed));

    engine.shutdown();
    engine.wait();
    Ok(())
}
