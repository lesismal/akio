//! Companion of the book's "TLS" chapter: a TLS server and a flash TLS client dialing it, with a
//! throw-away self-signed certificate.
//!
//! `cargo run -p flash --example guide-tls`

use std::{
    sync::{Arc, mpsc},
    time::Duration,
};

use flash::{
    Acceptor, Conn, Engine, Handler, Listener, fn_acceptor,
    tls::{Tls, rustls, tls_info},
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

struct Echo;

impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data); // plaintext in, plaintext out: flash encrypts
    }
}

struct Client(mpsc::Sender<String>);

impl Handler for Client {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let info = tls_info(c).expect("a TLS connection");
        let _ = self.0.send(format!(
            "{} (version {:?}, alpn {:?})",
            String::from_utf8_lossy(data),
            info.version,
            info.alpn.map(|a| String::from_utf8_lossy(&a).into_owned())
        ));
        c.close();
    }
}

struct Hello(mpsc::Sender<String>);

impl Acceptor for Hello {
    type Handler = Client;
    fn on_open(&self, c: &Conn<Client>) -> Client {
        // Sent during the handshake: held back and flushed as soon as it completes.
        let _ = c.send(b"hello over TLS");
        Client(self.0.clone())
    }
}

fn main() -> std::io::Result<()> {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(std::io::Error::other)?;
    let cert = ck.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    // ANCHOR: server
    let mut server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .map_err(std::io::Error::other)?;
    server_cfg.alpn_protocols = vec![b"echo".to_vec()];
    let engine = Arc::new(
        Engine::builder()
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(Tls::server(
                    Arc::new(server_cfg),
                    fn_acceptor(|_c: &Conn<Echo>| Echo),
                )),
            )
            .client_threads(1)
            .build()?,
    );
    engine.start()?;
    // ANCHOR_END: server

    // ANCHOR: client
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).map_err(std::io::Error::other)?;
    let mut client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"echo".to_vec()];
    let (tx, rx) = mpsc::channel();
    let acceptor = Tls::client(Arc::new(client_cfg), "localhost", Hello(tx))?;
    engine.dial(engine.local_addrs()[0], acceptor, |e| {
        eprintln!("dial: {e}");
    });
    println!("{}", rx.recv_timeout(Duration::from_secs(5)).expect("echo"));
    // ANCHOR_END: client

    engine.shutdown();
    engine.wait();
    Ok(())
}
