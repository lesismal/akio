//! Raw QUIC interop peer for tools/interop/quic (quic-go): an echo of streams and datagrams,
//! ALPN `echo`.
//!
//! ```text
//! quic-interop server 127.0.0.1:9501 [retry] [ku N]   echoes every stream and datagram
//! quic-interop client 127.0.0.1:9500 [bulk MB] [ku N] checks a quic-go echo server
//! ```
//!
//! `retry` validates every client address with a Retry first; `ku N` starts a 1-RTT key update
//! every N packets; `bulk MB` adds one stream of MB megabytes.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use only::{Engine, Listener};
use only_quic::{Bytes, Connection, ConnectionError, QuicHandler, QuicServer, StreamId};

fn fail(msg: String) -> ! {
    println!("FAIL: {msg}");
    std::process::exit(1)
}

fn pattern(n: usize, salt: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 + (i >> 9) + salt) as u8).collect()
}

fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

struct Echo;
impl QuicHandler for Echo {
    fn on_stream_data(&mut self, c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        let _ = c.send(id, data);
        if fin {
            let _ = c.finish(id);
        }
    }
    fn on_datagram(&mut self, c: &Connection, data: Bytes) {
        let _ = c.send_datagram(data);
    }
}

enum Got {
    Connected,
    Stream(StreamId, Vec<u8>),
    Datagram,
    Closed(ConnectionError),
}

struct Client {
    tx: mpsc::Sender<Got>,
    bufs: HashMap<StreamId, Vec<u8>>,
}

impl QuicHandler for Client {
    fn on_connected(&mut self, _c: &Connection) {
        let _ = self.tx.send(Got::Connected);
    }
    fn on_stream_data(&mut self, _c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        self.bufs.entry(id).or_default().extend_from_slice(&data);
        if fin {
            let b = self.bufs.remove(&id).unwrap_or_default();
            let _ = self.tx.send(Got::Stream(id, b));
        }
    }
    fn on_datagram(&mut self, _c: &Connection, _data: Bytes) {
        let _ = self.tx.send(Got::Datagram);
    }
    fn on_close(&mut self, _c: &Connection, r: ConnectionError) {
        let _ = self.tx.send(Got::Closed(r));
    }
}

fn certs() -> (Vec<only::tls::Certificate>, only::tls::PrivateKey) {
    let ck = only_x509::generate_simple_self_signed(["localhost"]).expect("cert");
    (
        vec![only::tls::Certificate::from_der(ck.0.as_der().to_vec())],
        only::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
}

fn server(addr: SocketAddr, args: &[String]) {
    let (certs, key) = certs();
    let mut cfg = only_quic::server_config(certs, key, &[b"echo"])
        .expect("config")
        .retry(args.iter().any(|a| a == "retry"));
    if let Some(n) = opt(args, "ku") {
        cfg = cfg.key_update_interval(n.parse().expect("ku"));
    }
    let e = Engine::builder()
        .listen(Listener::udp(addr).serve(QuicServer::new(cfg, |_c: &Connection| Echo)))
        .build()
        .expect("engine");
    e.start().expect("start");
    println!("ready");
    e.wait();
}

fn client(addr: SocketAddr, args: &[String]) {
    let e = Engine::builder()
        .udp_client_threads(1)
        .build()
        .expect("engine");
    e.start().expect("start");
    let mut cfg = only_quic::client_config_insecure(&[b"echo"]).expect("config");
    if let Some(n) = opt(args, "ku") {
        cfg = cfg.key_update_interval(n.parse().expect("ku"));
    }
    let (tx, rx) = mpsc::channel();
    let c = only_quic::dial(
        &e,
        addr,
        "localhost",
        cfg,
        Client {
            tx,
            bufs: HashMap::new(),
        },
    )
    .unwrap_or_else(|e| fail(format!("dial: {e}")));
    let next = |t: u64| match rx.recv_timeout(Duration::from_secs(t)) {
        Ok(Got::Closed(r)) => fail(format!("closed: {r}")),
        Ok(g) => g,
        Err(_) => fail("timed out".into()),
    };
    if !matches!(next(10), Got::Connected) {
        fail("no handshake".into());
    }
    if c.alpn().as_deref() != Some(&b"echo"[..]) {
        fail("alpn".into());
    }
    let mut want = HashMap::new();
    for i in 0..50 {
        let id = c
            .open_bi()
            .unwrap_or_else(|| fail("no stream credit".into()));
        let body = pattern(i * 3000, i);
        c.send(id, body.clone())
            .unwrap_or_else(|e| fail(format!("send: {e}")));
        c.finish(id)
            .unwrap_or_else(|e| fail(format!("finish: {e}")));
        want.insert(id, body);
    }
    while !want.is_empty() {
        if let Got::Stream(id, b) = next(30) {
            let w = want
                .remove(&id)
                .unwrap_or_else(|| fail(format!("unknown stream {id}")));
            if b != w {
                let at = b.iter().zip(&w).position(|(x, y)| x != y).unwrap_or(0);
                let end = (at + 16).min(b.len()).min(w.len());
                fail(format!(
                    "stream {id}: {} bytes back, want {}; first difference at {at}: {:02x?} vs {:02x?}",
                    b.len(),
                    w.len(),
                    &b[at..end],
                    &w[at..end]
                ));
            }
        }
    }
    for i in 0..20 {
        c.send_datagram(format!("dg-{i}").into_bytes())
            .unwrap_or_else(|e| fail(format!("datagram: {e}")));
    }
    let mut n = 0;
    let end = Instant::now() + Duration::from_secs(3);
    while n < 20 && Instant::now() < end {
        if let Ok(Got::Datagram) = rx.recv_timeout(Duration::from_millis(100)) {
            n += 1;
        }
    }
    if n < 15 {
        fail(format!("only {n} of 20 datagrams echoed"));
    }
    if let Some(mb) = opt(args, "bulk") {
        let mb: usize = mb.parse().expect("bulk");
        let body = pattern(mb << 20, 3);
        let start = Instant::now();
        let id = c
            .open_bi()
            .unwrap_or_else(|| fail("no stream credit".into()));
        c.send(id, body.clone())
            .unwrap_or_else(|e| fail(format!("send: {e}")));
        c.finish(id)
            .unwrap_or_else(|e| fail(format!("finish: {e}")));
        loop {
            if let Got::Stream(sid, b) = next(300) {
                if sid == id {
                    if b != body {
                        fail(format!("bulk: {} bytes back", b.len()));
                    }
                    break;
                }
            }
        }
        let el = start.elapsed();
        println!(
            "bulk {mb} MB echoed in {el:?} ({:.0} Mbit/s each way), {:?}",
            (mb * 8) as f64 / el.as_secs_f64(),
            c.stats()
        );
    }
    c.close(0, b"done");
    println!("ok: 50 streams, {n}/20 datagrams");
    e.shutdown();
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        fail("usage: server|client ADDR [retry] [bulk MB] [ku N]".into());
    }
    let addr = a[2].parse().expect("addr");
    match a[1].as_str() {
        "server" => server(addr, &a[3..]),
        "client" => client(addr, &a[3..]),
        m => fail(format!("unknown mode {m}")),
    }
}
