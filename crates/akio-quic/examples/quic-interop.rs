//! Raw QUIC interop peer for tools/interop/quic (quic-go): an echo of streams and datagrams,
//! ALPN `echo`; and HTTP/0.9 over QUIC (`hq-interop`, the raw-stream protocol of the QUIC
//! interop runner) for quiche (tools/interop/quic/quiche.sh).
//!
//! ```text
//! quic-interop server 127.0.0.1:9501 [retry] [ku N]   echoes every stream and datagram
//! quic-interop server 127.0.0.1:9501 hq [retry]       HTTP/0.9: `GET /N` answers N bytes of
//!                                                     'W', any other path "hello hq\n"
//! quic-interop client 127.0.0.1:9500 [bulk MB] [ku N] checks a quic-go echo server
//! quic-interop client 127.0.0.1:9500 hq SIZE          HTTP/0.9 client: 20 concurrent GETs of
//!                                                     /index.html, then /SIZE (SIZE bytes of 'W')
//! ```
//!
//! `retry` validates every client address with a Retry first; `ku N` starts a 1-RTT key update
//! every N packets; `bulk MB` adds one stream of MB megabytes; `v2` uses QUIC version 2 (a
//! server then accepts version 2 only); `bbr` uses BBR; `migrate` moves the client to a new
//! local port halfway and checks the echo goes on; `ecn` fails unless the client's path passed
//! ECN validation (Linux); `0rtt` accepts 0-RTT (server; it prints "0-RTT stream" for each
//! connection whose streams came early), or (client) resumes a first connection with 0-RTT,
//! sending its first stream before the handshake, and fails unless the server accepted it.
//! `prefer-v2` / `prefer-v1` (server) moves clients that list that version to it within the
//! handshake (compatible version negotiation, RFC 9368); the server prints "connected in V1" or
//! "V2" per connection. `expect-v1` / `expect-v2` (client) fails unless the connection ended up
//! in that version. `alpn P` uses ALPN `P` instead of `echo`, and `handshake-only` (client)
//! stops after the handshake: a check against servers of another protocol (ngtcp2's HTTP/3).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use akio::{Engine, Listener};
use akio_quic::{Bytes, Connection, ConnectionError, QuicHandler, QuicServer, StreamId};

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

/// HTTP/0.9 over QUIC (`hq-interop`): a request is `GET /path` and the stream's FIN; the
/// response is the body and FIN.
#[derive(Default)]
struct Hq {
    reqs: HashMap<StreamId, Vec<u8>>,
}
impl QuicHandler for Hq {
    fn on_stream_data(&mut self, c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        let req = self.reqs.entry(id).or_default();
        req.extend_from_slice(&data);
        if req.len() > 4096 {
            let _ = c.reset(id, 0x101);
            self.reqs.remove(&id);
            return;
        }
        if !fin {
            return;
        }
        let req = self.reqs.remove(&id).unwrap_or_default();
        let line = String::from_utf8_lossy(&req);
        let path = line
            .strip_prefix("GET ")
            .map_or("", |p| p.trim_end_matches(['\r', '\n']).trim());
        let body = match path.strip_prefix('/').and_then(|n| n.parse::<usize>().ok()) {
            Some(n) if n <= 64 << 20 => vec![b'W'; n],
            _ => b"hello hq\n".to_vec(),
        };
        let _ = c.send(id, body);
        let _ = c.finish(id);
    }
}

#[derive(Default)]
struct Echo {
    early_seen: bool,
}
impl QuicHandler for Echo {
    fn on_connected(&mut self, c: &Connection) {
        println!("connected in {:?} from {}", c.version(), c.remote_addr());
    }
    fn on_stream_data(&mut self, c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        if !self.early_seen && c.is_early(id) {
            self.early_seen = true;
            println!("0-RTT stream from {}", c.remote_addr());
        }
        let _ = c.send(id, data);
        if fin {
            let _ = c.finish(id);
        }
    }
    fn on_datagram(&mut self, c: &Connection, data: Bytes) {
        let _ = c.send_datagram(data);
    }
    fn on_close(&mut self, c: &Connection, r: ConnectionError) {
        if !matches!(
            r,
            ConnectionError::ApplicationClosed { .. } | ConnectionError::LocallyClosed
        ) {
            eprintln!(
                "connection from {} ({:?}) closed: {r}",
                c.remote_addr(),
                c.version()
            );
        }
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

fn certs() -> (Vec<akio::tls::Certificate>, akio::tls::PrivateKey) {
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).expect("cert");
    (
        vec![akio::tls::Certificate::from_der(ck.0.as_der().to_vec())],
        akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
}

fn server(addr: SocketAddr, args: &[String]) {
    let (certs, key) = certs();
    let hq = has(args, "hq");
    let alpn = opt(args, "alpn").unwrap_or_else(|| if hq { "hq-interop" } else { "echo" }.into());
    let mut cfg = akio_quic::server_config(certs, key, &[alpn.as_bytes()])
        .expect("config")
        .retry(args.iter().any(|a| a == "retry"));
    if has(args, "prefer-v2") {
        cfg = cfg.prefer_version(akio_quic::Version::V2);
    }
    if has(args, "prefer-v1") {
        cfg = cfg.prefer_version(akio_quic::Version::V1);
    }
    if let Some(n) = opt(args, "ku") {
        cfg = cfg.key_update_interval(n.parse().expect("ku"));
    }
    if has(args, "v2") {
        cfg = cfg.versions(&[akio_quic::Version::V2]);
    }
    if has(args, "bbr") {
        cfg = cfg.transport(&transport_bbr());
    }
    cfg = cfg.zero_rtt(has(args, "0rtt"));
    let l = Listener::udp(addr);
    let l = if hq {
        l.serve(QuicServer::new(cfg, |_c: &Connection| Hq::default()))
    } else {
        l.serve(QuicServer::new(cfg, |_c: &Connection| Echo::default()))
    };
    let e = Engine::builder().listen(l).build().expect("engine");
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
    let hq = opt(args, "hq");
    let alpn = opt(args, "alpn")
        .unwrap_or_else(|| if hq.is_some() { "hq-interop" } else { "echo" }.into());
    let mut cfg = akio_quic::client_config_insecure(&[alpn.as_bytes()]).expect("config");
    if let Some(n) = opt(args, "ku") {
        cfg = cfg.key_update_interval(n.parse().expect("ku"));
    }
    if has(args, "v2") {
        cfg = cfg.version(akio_quic::Version::V2);
    }
    if has(args, "bbr") {
        cfg = cfg.transport(&transport_bbr());
    }
    let zero_rtt = has(args, "0rtt");
    if zero_rtt {
        // A first connection for the session ticket.
        cfg = cfg.zero_rtt(true);
        let (tx, rx) = mpsc::channel();
        let c = akio_quic::dial(
            &e,
            addr,
            "localhost",
            cfg.clone(),
            Client {
                tx,
                bufs: HashMap::new(),
            },
        )
        .unwrap_or_else(|e| fail(format!("dial: {e}")));
        if !matches!(rx.recv_timeout(Duration::from_secs(10)), Ok(Got::Connected)) {
            fail("no first handshake".into());
        }
        std::thread::sleep(Duration::from_millis(300));
        c.close(0, b"");
    }
    let (tx, rx) = mpsc::channel();
    let c = akio_quic::dial(
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
        Ok(Got::Closed(r)) => fail(format!("closed: {r}: {:?}", c.stats())),
        Ok(g) => g,
        Err(_) => fail(format!("timed out: {:?}", c.stats())),
    };
    let mut want = HashMap::new();
    if zero_rtt {
        // Sent before the handshake: in 0-RTT.
        let id = c
            .open_bi()
            .unwrap_or_else(|| fail("no 0-RTT stream credit (no ticket?)".into()));
        let body = pattern(5000, 99);
        c.send(id, body.clone())
            .unwrap_or_else(|e| fail(format!("send: {e}")));
        c.finish(id)
            .unwrap_or_else(|e| fail(format!("finish: {e}")));
        want.insert(id, body);
    }
    let mut early_back = Vec::new();
    loop {
        match next(10) {
            Got::Connected => break,
            Got::Stream(id, b) => early_back.push((id, b)),
            _ => {}
        }
    }
    if zero_rtt {
        if c.early_data() != akio::tls::EarlyData::Accepted {
            fail(format!("0-RTT not accepted: {:?}", c.early_data()));
        }
        println!("0-RTT accepted");
    }
    for (id, b) in early_back {
        if want.remove(&id).is_some_and(|w| w != b) {
            fail(format!("stream {id} differs"));
        }
    }
    if c.alpn().as_deref() != Some(alpn.as_bytes()) {
        fail("alpn".into());
    }
    let want_version = if has(args, "expect-v1") {
        Some(akio_quic::Version::V1)
    } else if has(args, "expect-v2") || has(args, "v2") {
        Some(akio_quic::Version::V2)
    } else {
        None
    };
    if want_version.is_some_and(|v| v != c.version()) {
        fail(format!("version {:?}", c.version()));
    }
    if has(args, "handshake-only") {
        c.close(0, b"done");
        println!("ok: handshake in {:?}", c.version());
        e.shutdown();
        return;
    }
    if let Some(size) = hq {
        // HTTP/0.9: 20 concurrent small GETs, then one large one.
        let size: usize = size.parse().expect("hq SIZE");
        let get = |path: &str| {
            let id = c
                .open_bi()
                .unwrap_or_else(|| fail("no stream credit".into()));
            c.send(id, format!("GET {path}\r\n").into_bytes())
                .unwrap_or_else(|e| fail(format!("send: {e}")));
            c.finish(id)
                .unwrap_or_else(|e| fail(format!("finish: {e}")));
            id
        };
        let mut small: Vec<StreamId> = (0..20).map(|_| get("/index.html")).collect();
        let mut first = None;
        while !small.is_empty() {
            if let Got::Stream(id, b) = next(30) {
                let i = small
                    .iter()
                    .position(|s| *s == id)
                    .unwrap_or_else(|| fail(format!("unknown stream {id}")));
                small.swap_remove(i);
                if first.get_or_insert_with(|| b.clone()) != &b || b.is_empty() {
                    fail(format!(
                        "GET /index.html: {:?}",
                        String::from_utf8_lossy(&b)
                    ));
                }
            }
        }
        let start = Instant::now();
        let id = get(&format!("/{size}"));
        loop {
            if let Got::Stream(sid, b) = next(120) {
                if sid == id {
                    if b.len() != size || b.iter().any(|&x| x != b'W') {
                        fail(format!("GET /{size}: {} bytes", b.len()));
                    }
                    break;
                }
            }
        }
        let el = start.elapsed();
        c.close(0, b"done");
        println!(
            "ok: hq-interop, 20 x /index.html ({:?}), /{size} in {el:?}, {:?}, {:?}",
            String::from_utf8_lossy(first.as_deref().unwrap_or_default()).trim_end(),
            c.version(),
            c.stats()
        );
        e.shutdown();
        return;
    }
    let (streams, unit) = if has(args, "small") {
        (10, 200)
    } else {
        (50, 3000)
    };
    for i in 0..streams {
        if i == 25 && has(args, "migrate") {
            c.migrate(&e)
                .unwrap_or_else(|e| fail(format!("migrate: {e}")));
        }
        let id = c
            .open_bi()
            .unwrap_or_else(|| fail("no stream credit".into()));
        let body = pattern(i * unit, i);
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
    let st = c.stats();
    if has(args, "ecn") && !st.ecn_capable {
        fail(format!("ECN not validated: {st:?}"));
    }
    c.close(0, b"done");
    println!(
        "ok: {streams} streams, {n}/20 datagrams, {:?}, ecn {}",
        c.version(),
        st.ecn_capable
    );
    e.shutdown();
}

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn transport_bbr() -> akio_quic::TransportConfig {
    let mut t = akio_quic::TransportConfig::default();
    t.congestion = akio_quic::Congestion::Bbr;
    t
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
