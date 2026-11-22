//! Companion of the book's "TLS" chapter: a TLS server and a `akio` TLS client dialing it, with a
//! throw-away self-signed certificate.
//!
//! `cargo run -p only --example guide-tls`

use std::{
    sync::{Arc, mpsc},
    time::Duration,
};

use akio::{
    Acceptor, Conn, Engine, Handler, Listener, fn_acceptor,
    tls::{Certificate, ClientConfig, PrivateKey, RootCerts, ServerConfig, Tls, tls_info},
};

struct Echo;

impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data); // plaintext in, plaintext out: only encrypts
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
    let ck =
        akio_x509::generate_simple_self_signed(["localhost"]).map_err(std::io::Error::other)?;
    // In production: Certificate::from_pem(&std::fs::read("cert.pem")?) and PrivateKey::from_pem.
    let cert = Certificate::from_der(ck.0.as_der().to_vec());
    let key = PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());

    // ANCHOR: server
    let server_cfg = ServerConfig::builder(vec![cert.clone()], key)
        .alpn(["echo"])
        .build()?;
    let engine = Arc::new(
        Engine::builder()
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .serve(Tls::server(server_cfg, fn_acceptor(|_c: &Conn<Echo>| Echo))),
            )
            .client_threads(1)
            .build()?,
    );
    engine.start()?;
    // ANCHOR_END: server

    // ANCHOR: client
    let mut roots = RootCerts::empty();
    roots.add(&cert)?;
    let client_cfg = ClientConfig::builder()
        .roots(roots)
        .alpn(["echo"])
        .build()?;
    let (tx, rx) = mpsc::channel();
    let acceptor = Tls::client(client_cfg, "localhost", Hello(tx))?;
    engine.dial(engine.local_addrs()[0], acceptor, |e| {
        eprintln!("dial: {e}");
    });
    println!("{}", rx.recv_timeout(Duration::from_secs(5)).expect("echo"));
    // ANCHOR_END: client

    engine.shutdown();
    engine.wait();
    Ok(())
}
