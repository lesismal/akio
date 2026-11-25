//! Companion of the book's "QUIC and HTTP/3" chapter: a akio-http router served over HTTP/3
//! (with a streamed request body and a WebSocket), and the H3 client (with a streamed upload
//! and a streamed response).
//!
//! `cargo run -p akio-h3 --example guide-h3`

use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use akio::{Engine, Listener};
use akio_h3::{H3Client, H3Config, H3Event, H3WsOptions};
use akio_http::message::{Headers, Method};
use akio_http::ws::{Message, WsHandler, WsSender};
use akio_http::{BodyEvent, Context, Router, Streaming, WsOptions};

/// Echoes every WebSocket message.
struct Echo;

impl WsHandler for Echo {
    fn on_message(&mut self, ws: &WsSender, msg: Message) {
        let _ = match msg {
            Message::Text(t) => ws.send_text(&t),
            Message::Binary(b) => ws.send_binary(&b),
        };
    }
}

/// Prints what the client's WebSocket receives.
struct Print(mpsc::Sender<()>);

impl WsHandler for Print {
    fn on_message(&mut self, _ws: &WsSender, msg: Message) {
        println!("websocket got {msg:?}");
        let _ = self.0.send(());
    }
}

fn main() -> std::io::Result<()> {
    let ck =
        akio_x509::generate_simple_self_signed(["localhost"]).map_err(std::io::Error::other)?;
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());

    // ANCHOR: server
    // The same Router (and middleware) you serve over HTTP/1 and HTTP/2.
    let app = Router::new()
        .get("/hello/:name", |ctx: &mut Context| {
            let name = ctx.param("name").unwrap_or("?").to_owned();
            ctx.text(200, format!("hello {name} over {:?}\n", ctx.req().version));
        })
        // A GET route answers WebSocket upgrades on HTTP/1.1 and extended CONNECT on HTTP/3.
        .get("/ws", |ctx: &mut Context| {
            ctx.upgrade_websocket(Echo, &WsOptions::default());
        })
        // The body arrives piece by piece, never held whole.
        .route(
            Method::Post,
            "/upload",
            Streaming(|ctx: &mut Context| {
                let total = Arc::new(Mutex::new(0usize));
                ctx.on_body(move |ctx, ev| match ev {
                    BodyEvent::Chunk(data) => *total.lock().unwrap() += data.len(),
                    BodyEvent::End(_) => {
                        let n = *total.lock().unwrap();
                        ctx.text(200, format!("received {n} bytes\n"));
                    }
                    // Only past a limit a middleware set (`Context::limit_body`): answered 413.
                    BodyEvent::TooLarge => {}
                });
            }),
        );
    let quic = akio_h3::server_config(vec![cert.clone()], key)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut limits = H3Config::default();
    limits.max_body_bytes = 8 << 20;
    limits.max_field_section_bytes = 64 << 10;
    let engine = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap())
                .serve(akio_h3::serve_with(quic, limits, app)),
        )
        .udp_client_threads(1)
        .build()?;
    engine.start()?;
    // ANCHOR_END: server

    // ANCHOR: client
    let mut roots = akio::tls::RootCerts::empty();
    roots.add(&cert).map_err(std::io::Error::other)?;
    let cfg = akio_quic::client_config(roots, &[b"h3"])
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let client = H3Client::dial(&engine, engine.local_addrs()[0], "localhost", cfg)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let resp = client
        .get("/hello/h3", Duration::from_secs(5))
        .map_err(std::io::Error::other)?;
    print!("{} {}", resp.status, String::from_utf8_lossy(&resp.body));
    // ANCHOR_END: client

    // ANCHOR: upload
    let (tx, rx) = mpsc::channel();
    let upload = client.upload(Method::Post, "/upload", &Headers::new(), move |r| {
        let _ = tx.send(r);
    });
    let piece = vec![7u8; 64 << 10];
    for _ in 0..64 {
        // Pace the writer by what QUIC has not sent yet.
        while upload.queued_bytes() > 1 << 20 {
            std::thread::sleep(Duration::from_millis(1));
        }
        upload.write(&piece);
    }
    upload.finish();
    let resp = rx
        .recv_timeout(Duration::from_secs(10))
        .map_err(std::io::Error::other)?
        .map_err(std::io::Error::other)?;
    print!("{}", String::from_utf8_lossy(&resp.body));
    // ANCHOR_END: upload

    // ANCHOR: download
    // A streamed response: pieces as they arrive, nothing buffered. `hold_reads(true)` on the
    // returned handle would pause it (QUIC flow control then holds the server back).
    let (tx, rx) = mpsc::channel();
    let mut got = 0usize;
    let download = client.open(
        Method::Get,
        "/hello/stream",
        &Headers::new(),
        move |ev| match ev {
            H3Event::Head { status, .. } => println!("streamed response: {status}"),
            H3Event::Data(piece) => got += piece.len(),
            H3Event::End => {
                let _ = tx.send(Ok(got));
            }
            H3Event::Error(e) => {
                let _ = tx.send(Err(e));
            }
            _ => {}
        },
    );
    download.finish(); // no request body
    let n = rx
        .recv_timeout(Duration::from_secs(10))
        .map_err(std::io::Error::other)?
        .map_err(std::io::Error::other)?;
    println!("streamed {n} bytes");
    // ANCHOR_END: download

    // ANCHOR: websocket
    let (tx, rx) = mpsc::channel();
    let ws = client
        .websocket_blocking(
            "/ws",
            &H3WsOptions::default(),
            Print(tx),
            Duration::from_secs(5),
        )
        .map_err(std::io::Error::other)?;
    ws.send_text("hello over a QUIC stream")
        .map_err(std::io::Error::other)?;
    rx.recv_timeout(Duration::from_secs(5))
        .map_err(std::io::Error::other)?;
    ws.close(1000, "done");
    // ANCHOR_END: websocket

    client.close();

    engine.shutdown();
    engine.wait();
    Ok(())
}
