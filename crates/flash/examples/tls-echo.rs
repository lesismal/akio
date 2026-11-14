//! TLS echo server with a throw-away self-signed certificate:
//! `cargo run --release -p flash --example tls-echo` then
//! `openssl s_client -connect 127.0.0.1:7443 -quiet` (add `-alpn h2` to see ALPN in the reply).

use flash::{
    Conn, Engine, Handler, Listener, fn_acceptor,
    tls::{Certificate, PrivateKey, ServerConfig, Tls, tls_info},
};

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
    let cfg = ServerConfig::builder(
        vec![Certificate::from_der(ck.cert.der().to_vec())],
        PrivateKey::from_pkcs8_der(ck.key_pair.serialize_der()),
    )
    .alpn(["h2", "http/1.1"])
    .build()?;

    let addr = "127.0.0.1:7443".parse().expect("address");
    let engine = Engine::builder()
        .listen(Listener::tcp(addr).serve(Tls::server(
            cfg,
            fn_acceptor(|_c: &Conn<Echo>| Echo { first: true }),
        )))
        .build()?;
    println!(
        "tls echo on {:?} (self-signed, use -k / no verification)",
        engine.local_addrs()
    );
    engine.run()
}
