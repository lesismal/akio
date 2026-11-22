//! HTTP/3 responses under tight QUIC send buffers: file, large and streamed bodies arrive whole,
//! many at once on one connection (over the connection's buffer), and a streamed body's writes
//! are refused with `Overloaded` instead of piling up.
#![allow(missing_docs)]

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use akio::{Engine, Listener};
use akio_h3::H3Client;
use akio_http::message::{FileBody, Headers, Response};
use akio_http::{Context, Router};

const T: Duration = Duration::from_secs(30);

fn pattern(n: usize, salt: usize) -> Vec<u8> {
    (0..n).map(|i| ((i + salt) % 251) as u8).collect()
}

struct Setup {
    e: Arc<Engine>,
    c: H3Client,
    overloaded: Arc<AtomicUsize>,
    file: Vec<u8>,
}

fn setup() -> Setup {
    let file = pattern(3 << 20, 1);
    static N: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "akio-h3-bp-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::File::create(&path)
        .unwrap()
        .write_all(&file)
        .unwrap();
    let f = Arc::new(std::fs::File::open(&path).unwrap());
    let _ = std::fs::remove_file(&path);
    let overloaded = Arc::new(AtomicUsize::new(0));
    let ov = overloaded.clone();
    let len = file.len() as u64;
    let app = Router::new()
        .get("/file", move |ctx: &mut Context| {
            // A range in the middle, with trailers.
            let mut r = Response::from_file(
                200,
                "application/octet-stream",
                FileBody::new(f.clone(), 1000, len - 2000),
            );
            let mut t = Headers::new();
            t.set("x-done", "1");
            r.trailers = Some(t);
            ctx.respond(r);
        })
        .get("/big", |ctx: &mut Context| {
            ctx.bytes(200, "application/octet-stream", pattern(5 << 20, 2));
        })
        .get("/small/:i", |ctx: &mut Context| {
            let i = ctx.param("i").unwrap_or("?").to_owned();
            ctx.text(200, format!("small {i}"));
        })
        .get("/stream", move |ctx: &mut Context| {
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            let ov = ov.clone();
            std::thread::spawn(move || {
                let data = pattern(6 << 20, 3);
                for piece in data.chunks(64 << 10) {
                    // A producer that follows backpressure: refused writes are retried later.
                    loop {
                        match s.write(piece) {
                            Ok(()) => break,
                            Err(akio::Error::Overloaded) => {
                                ov.fetch_add(1, Ordering::Relaxed);
                                std::thread::sleep(Duration::from_millis(1));
                            }
                            Err(e) => panic!("write: {e}"),
                        }
                    }
                }
                s.finish();
            });
        });
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let mut t = akio_quic::TransportConfig::default();
    t.stream_send_buffer = 256 << 10;
    t.send_buffer = 1 << 20;
    let quic = akio_h3::server_config(vec![cert], key)
        .unwrap()
        .transport(&t);
    let e = Engine::builder()
        .listen(Listener::udp("127.0.0.1:0".parse().unwrap()).serve(akio_h3::serve(quic, app)))
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    // A client granting little credit at a time: the server's responses wait in its buffers.
    let mut ct = akio_quic::TransportConfig::default();
    ct.stream_receive_window = 64 << 10;
    ct.receive_window = Some(256 << 10);
    let cc = akio_quic::client_config_insecure(&[b"h3"])
        .unwrap()
        .transport(&ct);
    let c = H3Client::dial(&e, addr, "localhost", cc).unwrap();
    Setup {
        e: Arc::new(e),
        c,
        overloaded,
        file,
    }
}

#[test]
fn bodies_arrive_whole_under_small_send_buffers() {
    let s = setup();
    let r = s.c.get("/file", T).unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(
        r.headers.get("content-length"),
        Some((s.file.len() - 2000).to_string().as_str())
    );
    assert!(
        r.body == s.file[1000..s.file.len() - 1000],
        "file body differs"
    );
    assert_eq!(r.trailers.unwrap().get("x-done"), Some("1"));
    let r = s.c.get("/big", T).unwrap();
    assert!(r.body == pattern(5 << 20, 2), "large body differs");
    let r = s.c.get("/stream", T).unwrap();
    assert!(r.body == pattern(6 << 20, 3), "streamed body differs");
    assert!(
        s.overloaded.load(Ordering::Relaxed) > 0,
        "the streamed body never met a full buffer"
    );
    s.e.shutdown();
}

#[test]
fn many_responses_over_the_connection_buffer() {
    let s = setup();
    // Several large responses at once hold more than the connection's buffer: the rest of them,
    // and the small responses between them, wait for room and still arrive whole.
    let (tx, rx) = std::sync::mpsc::channel();
    let mut want = 0;
    for i in 0..8 {
        for path in [
            "/file".to_string(),
            "/big".to_string(),
            format!("/small/{i}"),
        ] {
            let tx = tx.clone();
            let p = path.clone();
            s.c.request(
                akio_http::message::Method::Get,
                &path,
                &Headers::new(),
                Vec::new(),
                move |r| {
                    let _ = tx.send((p, r));
                },
            );
            want += 1;
        }
    }
    for _ in 0..want {
        let (path, r) = rx.recv_timeout(T).unwrap();
        let r = r.unwrap();
        assert_eq!(r.status, 200, "{path}");
        match path.as_str() {
            "/file" => assert!(r.body == s.file[1000..s.file.len() - 1000], "file differs"),
            "/big" => assert!(r.body == pattern(5 << 20, 2), "big differs"),
            p => assert_eq!(
                String::from_utf8(r.body).unwrap(),
                format!("small {}", &p[7..])
            ),
        }
    }
    s.e.shutdown();
}
