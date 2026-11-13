//! TLS echo server with a throw-away self-signed certificate:
//! `cargo run --release -p flash --example tls-echo` then
//! `openssl s_client -connect 127.0.0.1:7443 -quiet` (add `-alpn h2` to see ALPN in the reply).

use std::sync::Arc;

use flash::{
    Conn, Engine, Handler, Listener, fn_acceptor,
    tls::{Tls, rustls, tls_info},
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

struct Echo {
    first: bool,
}

impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if std::mem::take(&mut self.first) {
            if let Some(i) = tls_info(c) {
                let _ = c.send(format!("# {:?} alpn={:?}\n", i.version, i.alpn).as_bytes());
            }
        }
        let _ = c.send(data); // plaintext in, plaintext out; flash does the TLS
    }
}

fn main() -> std::io::Result<()> {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(std::io::Error::other)?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![ck.cert.der().clone()], key)
        .map_err(std::io::Error::other)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let addr = "127.0.0.1:7443".parse().expect("address");
    let engine = Engine::builder()
        .listen(Listener::tcp(addr).serve(Tls::server(
            Arc::new(cfg),
            fn_acceptor(|_c: &Conn<Echo>| Echo { first: true }),
        )))
        .build()?;
    println!(
        "tls echo on {:?} (self-signed, use -k / no verification)",
        engine.local_addrs()
    );
    engine.run()
}
