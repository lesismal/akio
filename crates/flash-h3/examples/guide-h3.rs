//! Companion of the book's "QUIC and HTTP/3" chapter: a flash-http router served over HTTP/3,
//! and the H3 client.
//!
//! `cargo run -p flash-h3 --example guide-h3`

use std::time::Duration;

use flash::{Engine, Listener};
use flash_h3::{H3Client, H3Config};
use flash_http::{Context, Router};

fn main() -> std::io::Result<()> {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .map_err(std::io::Error::other)?;
    let cert = ck.cert.der().clone();
    let key =
        flash_quic::rustls::pki_types::PrivateKeyDer::Pkcs8(ck.key_pair.serialize_der().into());

    // ANCHOR: server
    // The same Router (and middleware) you serve over HTTP/1 and HTTP/2.
    let app = Router::new().get("/hello/:name", |ctx: &mut Context| {
        let name = ctx.param("name").unwrap_or("?").to_owned();
        ctx.text(200, format!("hello {name} over {:?}\n", ctx.req().version));
    });
    let quic = flash_h3::server_config(vec![cert.clone()], key)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut limits = H3Config::default();
    limits.max_body_bytes = 8 << 20;
    limits.max_field_section_bytes = 64 << 10;
    let engine = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap())
                .serve(flash_h3::serve_with(quic, limits, app)),
        )
        .udp_client_threads(1)
        .build()?;
    engine.start()?;
    // ANCHOR_END: server

    // ANCHOR: client
    let mut roots = flash_quic::rustls::RootCertStore::empty();
    roots.add(cert).map_err(std::io::Error::other)?;
    let cfg = flash_quic::client_config(roots, &[b"h3"])
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let client = H3Client::dial(&engine, engine.local_addrs()[0], "localhost", cfg)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let resp = client
        .get("/hello/h3", Duration::from_secs(5))
        .map_err(std::io::Error::other)?;
    print!("{} {}", resp.status, String::from_utf8_lossy(&resp.body));
    client.close();
    // ANCHOR_END: client

    engine.shutdown();
    engine.wait();
    Ok(())
}
