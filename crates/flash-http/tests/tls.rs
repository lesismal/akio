//! HTTP/1.1 over TLS (`flash_tls::Tls` wrapping `serve`), driven by a blocking rustls client:
//! keep-alive, pipelining, large bodies both ways, chunked bodies both ways, static files (the
//! `sendfile` path goes through memory under TLS) and a WebSocket upgrade.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    thread,
    time::Duration,
};

use flash::{
    Backend, Config, Engine, Listener, UringConfig,
    tls::{Tls, rustls},
};
use flash_http::{
    Context, Headers, HttpConfig, Router, WsOptions,
    files::Files,
    serve_with,
    ws::{Message, WsHandler, WsSender},
};

fn backend() -> Backend {
    match std::env::var("FLASH_TEST_BACKEND").as_deref() {
        Ok("uring") => Backend::IoUring({
            let mut v = UringConfig::default();
            v.strict = true;
            v
        }),
        _ => Backend::Epoll,
    }
}

struct Echo;

impl WsHandler for Echo {
    fn on_message(&mut self, ws: &WsSender, msg: Message) {
        let _ = match msg {
            Message::Text(t) => ws.send_text(&format!("echo {t}")),
            Message::Binary(b) => ws.send_binary(&b),
        };
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 13 % 251) as u8).collect()
}

fn app(dir: &std::path::Path) -> Router {
    Router::new()
        .get("/hello/:who", |ctx: &mut Context| {
            let who = ctx.param("who").unwrap_or("?").to_owned();
            ctx.text(200, format!("hello {who}"));
        })
        .post("/echo", |ctx: &mut Context| {
            let b = ctx.body().to_vec();
            ctx.bytes(200, "application/octet-stream", b);
        })
        .get("/big", |ctx: &mut Context| {
            ctx.bytes(200, "application/octet-stream", pattern(3 << 20));
        })
        .get("/stream", |ctx: &mut Context| {
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            thread::spawn(move || {
                for i in 0..5 {
                    s.write(format!("part{i};").as_bytes()).unwrap();
                    thread::sleep(Duration::from_millis(5));
                }
                s.finish();
            });
        })
        .get("/ws", |ctx: &mut Context| {
            ctx.upgrade_websocket(Echo, &WsOptions::default());
        })
        .get(
            "/s/*path",
            Files::new(dir)
                .max_cached_bytes(1024)
                .check_interval(Duration::ZERO),
        )
}

struct Server {
    engine: Engine,
    client_cfg: Arc<rustls::ClientConfig>,
    dir: std::path::PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.engine.shutdown();
        self.engine.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start(name: &str) -> Server {
    let dir = std::env::temp_dir().join(format!("flash-http-tls-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("small.txt"), "small file over tls").unwrap();
    std::fs::write(dir.join("large.bin"), pattern(2 << 20)).unwrap();

    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert = ck.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        ck.key_pair.serialize_der(),
    ));
    let mut scfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    // The server offers h2 too; these clients ask for http/1.1 only.
    scfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let cfg = HttpConfig {
        max_body_bytes: 16 << 20,
        ..HttpConfig::default()
    };
    let engine = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(500);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .threads(2)
                .serve(Tls::server(Arc::new(scfg), serve_with(cfg, app(&dir)))),
        )
        .build()
        .unwrap();
    engine.start().unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut ccfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    ccfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Server {
        engine,
        client_cfg: Arc::new(ccfg),
        dir,
    }
}

/// A blocking TLS client connection with a read buffer.
struct Conn {
    tls: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    buf: Vec<u8>,
}

struct Resp {
    status: u16,
    h: HashMap<String, String>,
    body: Vec<u8>,
}

impl Resp {
    fn header(&self, n: &str) -> Option<&str> {
        self.h.get(n).map(String::as_str)
    }
}

impl Conn {
    fn open(s: &Server) -> Conn {
        let addr: SocketAddr = s.engine.local_addrs()[0];
        let tcp = TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        tcp.set_nodelay(true).unwrap();
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = rustls::ClientConnection::new(s.client_cfg.clone(), name).unwrap();
        Conn {
            tls: rustls::StreamOwned::new(conn, tcp),
            buf: Vec::new(),
        }
    }

    fn write(&mut self, b: &[u8]) {
        self.tls.write_all(b).unwrap();
        self.tls.flush().unwrap();
    }

    /// Reads more bytes into the buffer; false at EOF.
    fn fill(&mut self) -> bool {
        let mut b = [0u8; 16 << 10];
        loop {
            match self.tls.read(&mut b) {
                Ok(0) => return false,
                Ok(n) => {
                    self.buf.extend_from_slice(&b[..n]);
                    return true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return false,
                Err(e) => panic!("read: {e}"),
            }
        }
    }

    fn take(&mut self, n: usize) -> Vec<u8> {
        while self.buf.len() < n {
            assert!(self.fill(), "eof with {} of {n} bytes", self.buf.len());
        }
        self.buf.drain(..n).collect()
    }

    fn line(&mut self) -> String {
        loop {
            if let Some(i) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let l = self.take(i + 2);
                return String::from_utf8(l[..i].to_vec()).unwrap();
            }
            assert!(self.fill(), "eof inside a line");
        }
    }

    fn read_head(&mut self) -> (u16, HashMap<String, String>) {
        let status = self.line().split(' ').nth(1).unwrap().parse().unwrap();
        let mut h = HashMap::new();
        loop {
            let l = self.line();
            if l.is_empty() {
                return (status, h);
            }
            let (k, v) = l.split_once(':').unwrap();
            h.insert(k.to_ascii_lowercase(), v.trim().to_owned());
        }
    }

    fn read_resp(&mut self) -> Resp {
        let (status, h) = self.read_head();
        let mut body = Vec::new();
        if h.get("transfer-encoding").map(String::as_str) == Some("chunked") {
            loop {
                let n = usize::from_str_radix(&self.line(), 16).unwrap();
                let chunk = self.take(n + 2);
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..n]);
            }
        } else if let Some(n) = h.get("content-length") {
            body = self.take(n.parse().unwrap());
        }
        Resp { status, h, body }
    }

    fn get(&mut self, path: &str, extra: &str) -> Resp {
        self.write(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{extra}\r\n").as_bytes());
        self.read_resp()
    }
}

#[test]
fn keep_alive_and_pipelining_over_tls() {
    let s = start("keepalive");
    let mut c = Conn::open(&s);
    for i in 0..20 {
        let r = c.get(&format!("/hello/n{i}"), "");
        assert_eq!(r.status, 200);
        assert_eq!(r.body, format!("hello n{i}").as_bytes());
    }
    assert_eq!(
        c.tls.conn.alpn_protocol(),
        Some(&b"http/1.1"[..]),
        "h1 was negotiated"
    );
    // Ten pipelined requests in one write (one TLS record), answered in order; a decoded
    // parameter on the way.
    let mut batch = String::new();
    for i in 0..10 {
        batch.push_str(&format!(
            "GET /hello/p%20{i} HTTP/1.1\r\nHost: localhost\r\n\r\n"
        ));
    }
    batch.push_str("POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\ntail");
    c.write(batch.as_bytes());
    for i in 0..10 {
        assert_eq!(c.read_resp().body, format!("hello p {i}").as_bytes());
    }
    assert_eq!(c.read_resp().body, b"tail");
    // Connection: close is honoured: the server closes after answering.
    let r = c.get("/hello/last", "Connection: close\r\n");
    assert_eq!(r.body, b"hello last");
    assert!(!c.fill(), "the server should have closed the connection");
}

#[test]
fn large_and_chunked_bodies_over_tls() {
    let s = start("bodies");
    let mut c = Conn::open(&s);
    // A 5 MiB request body, then a 3 MiB response, on one connection.
    let up = pattern(5 << 20);
    c.write(
        format!(
            "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            up.len()
        )
        .as_bytes(),
    );
    c.write(&up);
    let r = c.read_resp();
    assert_eq!(r.status, 200);
    assert!(r.body == up, "large echo corrupted");
    let r = c.get("/big", "");
    assert!(r.body == pattern(3 << 20), "large response corrupted");
    // A chunked request body (with a trailer) in many small records.
    c.write(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n");
    let mut want = Vec::new();
    for i in 0..50 {
        let piece = format!("chunk-{i:03}|");
        want.extend_from_slice(piece.as_bytes());
        c.write(format!("{:x}\r\n{piece}\r\n", piece.len()).as_bytes());
    }
    c.write(b"0\r\nX-Done: yes\r\n\r\n");
    assert_eq!(c.read_resp().body, want);
    // A chunked (streamed) response, then the connection is still usable.
    let r = c.get("/stream", "");
    assert_eq!(r.header("transfer-encoding"), Some("chunked"));
    assert_eq!(r.body, b"part0;part1;part2;part3;part4;");
    assert_eq!(c.get("/hello/after", "").body, b"hello after");
}

#[test]
fn static_files_over_tls() {
    let s = start("files");
    let mut c = Conn::open(&s);
    let r = c.get("/s/small.txt", "");
    assert_eq!(r.body, b"small file over tls");
    let etag = r.header("etag").unwrap().to_owned();
    assert_eq!(
        c.get("/s/small.txt", &format!("If-None-Match: {etag}\r\n"))
            .status,
        304
    );
    // Too big for the memory cache: the file path, read through memory into TLS records.
    let big = pattern(2 << 20);
    let r = c.get("/s/large.bin", "");
    assert!(r.body == big, "file body corrupted over TLS");
    let r = c.get("/s/large.bin", "Range: bytes=1000-1999\r\n");
    assert_eq!(r.status, 206);
    assert!(r.body == big[1000..2000]);
    // Pipelined file + small responses stay in order.
    c.write(
        b"GET /s/large.bin HTTP/1.1\r\nHost: localhost\r\n\r\n\
          GET /s/small.txt HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert!(c.read_resp().body == big);
    assert_eq!(c.read_resp().body, b"small file over tls");
}

fn masked_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mask = [0xa1, 0xb2, 0xc3, 0xd4];
    let mut f = vec![0x80 | opcode];
    match payload.len() {
        n if n < 126 => f.push(0x80 | n as u8),
        n if n < 65_536 => {
            f.push(0x80 | 126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            f.push(0x80 | 127);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    f.extend_from_slice(&mask);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    f
}

fn read_frame(c: &mut Conn) -> (u8, Vec<u8>) {
    let h = c.take(2);
    assert_eq!(h[1] & 0x80, 0, "server frames are not masked");
    let len = match h[1] & 0x7f {
        126 => u16::from_be_bytes(c.take(2).try_into().unwrap()) as usize,
        127 => u64::from_be_bytes(c.take(8).try_into().unwrap()) as usize,
        n => n as usize,
    };
    (h[0] & 0x0f, c.take(len))
}

#[test]
fn websocket_upgrade_over_tls() {
    let s = start("ws");
    let mut c = Conn::open(&s);
    // A plain request first: the upgrade happens on a kept-alive TLS connection.
    assert_eq!(c.get("/hello/ws", "").body, b"hello ws");
    c.write(
        b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    );
    let (status, h) = c.read_head();
    assert_eq!(status, 101);
    assert_eq!(
        h.get("sec-websocket-accept").map(String::as_str),
        Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
    );
    c.write(&masked_frame(1, b"over tls"));
    assert_eq!(read_frame(&mut c), (1, b"echo over tls".to_vec()));
    let big = pattern(300 << 10);
    c.write(&masked_frame(2, &big));
    let (op, got) = read_frame(&mut c);
    assert_eq!(op, 2);
    assert!(got == big, "large binary message corrupted");
    // Close handshake.
    c.write(&masked_frame(8, &1000u16.to_be_bytes()));
    let (op, payload) = read_frame(&mut c);
    assert_eq!(op, 8);
    assert_eq!(&payload[..2], &1000u16.to_be_bytes());
}
