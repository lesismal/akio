//! QUIC and HTTP/3 loopback benchmarks (public API only, so the same program measures any
//! version of the stack):
//!
//! ```text
//! quic-bench handshakes SECS PAR   full handshakes per second, PAR dials in flight
//! quic-bench bulk MB               one stream of MB megabytes to a discarding server
//! quic-bench h3 SECS CONC          HTTP/3 GET requests per second, CONC in flight on one connection
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use only::{Engine, Listener};
use only_h3::H3Client;
use only_http::{Context, Router};
use only_quic::{Connection, ConnectionError, QuicHandler, QuicServer, StreamId};

/// The stream payload type of the measured version.
type B = only_quic::Bytes;

fn certs() -> (Vec<only::tls::Certificate>, only::tls::PrivateKey) {
    let ck = only_x509::generate_simple_self_signed(["localhost"]).expect("cert");
    (
        vec![only::tls::Certificate::from_der(ck.0.as_der().to_vec())],
        only::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
}

/// Counts what arrives; answers "ok" when a stream ends.
struct Sink {
    got: HashMap<StreamId, u64>,
}
impl QuicHandler for Sink {
    fn on_stream_data(&mut self, c: &Connection, id: StreamId, data: B, fin: bool) {
        *self.got.entry(id).or_default() += data.len() as u64;
        if fin {
            self.got.remove(&id);
            let _ = c.send(id, b"ok".to_vec());
            let _ = c.finish(id);
        }
    }
}

fn quic_server(threads: usize) -> (Engine, SocketAddr) {
    let (certs, key) = certs();
    let cfg = only_quic::server_config(certs, key, &[b"bench"]).expect("config");
    let server = QuicServer::new(cfg, |_c: &Connection| Sink {
        got: HashMap::new(),
    });
    let e = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().expect("addr"))
                .threads(threads)
                .serve(server),
        )
        .build()
        .expect("engine");
    e.start().expect("start");
    let addr = e.local_addrs()[0];
    (e, addr)
}

fn client_engine(threads: usize) -> Engine {
    let e = Engine::builder()
        .udp_client_threads(threads)
        .build()
        .expect("engine");
    e.start().expect("start");
    e
}

struct Hs(mpsc::Sender<bool>);
impl QuicHandler for Hs {
    fn on_connected(&mut self, c: &Connection) {
        let _ = self.0.send(true);
        c.close(0, b"");
    }
    fn on_stream_data(&mut self, _c: &Connection, _id: StreamId, _d: B, _fin: bool) {}
    fn on_close(&mut self, _c: &Connection, r: ConnectionError) {
        if r != ConnectionError::LocallyClosed {
            let _ = self.0.send(false);
        }
    }
}

fn handshakes(secs: u64, par: usize) {
    let (_s, addr) = quic_server(2);
    let e = Arc::new(client_engine(2));
    let cfg = only_quic::client_config_insecure(&[b"bench"]).expect("config");
    let done = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let end = Instant::now() + Duration::from_secs(secs);
    let mut ts = Vec::new();
    for _ in 0..par {
        let (e, cfg, done, failed) = (e.clone(), cfg.clone(), done.clone(), failed.clone());
        ts.push(std::thread::spawn(move || {
            while Instant::now() < end {
                let (tx, rx) = mpsc::channel();
                let _c = only_quic::dial(&e, addr, "localhost", cfg.clone(), Hs(tx)).expect("dial");
                match rx.recv_timeout(Duration::from_secs(5)) {
                    Ok(true) => done.fetch_add(1, Ordering::Relaxed),
                    _ => failed.fetch_add(1, Ordering::Relaxed),
                };
            }
        }));
    }
    let start = Instant::now();
    for t in ts {
        let _ = t.join();
    }
    let el = start.elapsed().as_secs_f64();
    let n = done.load(Ordering::Relaxed);
    println!(
        "handshakes: {n} in {el:.1}s = {:.0}/s ({} failed, {par} in flight)",
        n as f64 / el,
        failed.load(Ordering::Relaxed)
    );
}

struct Up(mpsc::Sender<()>);
impl QuicHandler for Up {
    fn on_connected(&mut self, _c: &Connection) {
        let _ = self.0.send(());
    }
    fn on_stream_data(&mut self, _c: &Connection, _id: StreamId, _d: B, fin: bool) {
        if fin {
            let _ = self.0.send(());
        }
    }
}

fn bulk(mb: usize) {
    let (_s, addr) = quic_server(1);
    let e = client_engine(1);
    let cfg = only_quic::client_config_insecure(&[b"bench"]).expect("config");
    let (tx, rx) = mpsc::channel();
    let c = only_quic::dial(&e, addr, "localhost", cfg, Up(tx)).expect("dial");
    rx.recv_timeout(Duration::from_secs(5)).expect("handshake");
    let chunk = vec![0x5au8; 1 << 20];
    let start = Instant::now();
    let id = c.open_bi().expect("stream");
    for _ in 0..mb {
        // Keep a bounded amount queued, as a real producer would.
        while c.queued_bytes(id) > 8 << 20 {
            std::thread::sleep(Duration::from_micros(200));
        }
        c.send(id, chunk.clone()).expect("send");
    }
    c.finish(id).expect("finish");
    rx.recv_timeout(Duration::from_secs(600)).expect("ack");
    let el = start.elapsed().as_secs_f64();
    let st = c.stats();
    println!(
        "bulk: {mb} MB in {el:.2}s = {:.0} Mbit/s (rtt {:?}, lost {} of {} packets, {} datagrams in {} sends)",
        (mb * 8) as f64 / el,
        st.rtt,
        st.lost_packets,
        st.sent_packets,
        st.udp_tx.datagrams,
        st.udp_tx.ios
    );
}

fn h3(secs: u64, conc: usize) {
    let (certs, key) = certs();
    let app = Router::new().get("/", |ctx: &mut Context| ctx.text(200, "hello h3"));
    let quic = only_h3::server_config(certs, key).expect("config");
    let s = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().expect("addr")).serve(only_h3::serve(quic, app)),
        )
        .build()
        .expect("engine");
    s.start().expect("start");
    let addr = s.local_addrs()[0];
    let e = client_engine(1);
    let cfg = only_quic::client_config_insecure(&[b"h3"]).expect("config");
    let c = Arc::new(H3Client::dial(&e, addr, "localhost", cfg).expect("dial"));
    c.get("/", Duration::from_secs(5)).expect("first request");
    let done = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));
    let end = Instant::now() + Duration::from_secs(secs);
    let (tx, rx) = mpsc::channel::<()>();
    let tx = Arc::new(Mutex::new(tx));
    fn fire(
        c: Arc<H3Client>,
        done: Arc<AtomicUsize>,
        errors: Arc<AtomicUsize>,
        end: Instant,
        tx: Arc<Mutex<mpsc::Sender<()>>>,
    ) {
        let c2 = c.clone();
        c.request(
            only_http::message::Method::Get,
            "/",
            &only_http::message::Headers::new(),
            Vec::new(),
            move |r| {
                match r {
                    Ok(resp) if resp.status == 200 => done.fetch_add(1, Ordering::Relaxed),
                    _ => errors.fetch_add(1, Ordering::Relaxed),
                };
                if Instant::now() < end {
                    fire(c2, done, errors, end, tx);
                } else {
                    let _ = tx.lock().map(|t| t.send(()));
                }
            },
        );
    }
    let start = Instant::now();
    for _ in 0..conc {
        fire(c.clone(), done.clone(), errors.clone(), end, tx.clone());
    }
    for _ in 0..conc {
        let _ = rx.recv_timeout(Duration::from_secs(secs + 30));
    }
    let el = start.elapsed().as_secs_f64();
    let n = done.load(Ordering::Relaxed);
    let st = c.connection().stats();
    println!(
        "h3: {n} requests in {el:.1}s = {:.0} req/s ({} errors, {conc} in flight; per request {:.2} datagrams out, {:.2} in)",
        n as f64 / el,
        errors.load(Ordering::Relaxed),
        st.udp_tx.datagrams as f64 / n.max(1) as f64,
        st.udp_rx.datagrams as f64 / n.max(1) as f64
    );
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let arg = |i: usize, d: u64| a.get(i).and_then(|s| s.parse().ok()).unwrap_or(d);
    match a.get(1).map(String::as_str) {
        Some("handshakes") => handshakes(arg(2, 5), arg(3, 8) as usize),
        Some("bulk") => bulk(arg(2, 1024) as usize),
        Some("h3") => h3(arg(2, 5), arg(3, 64) as usize),
        _ => {
            println!("usage: quic-bench handshakes SECS PAR | bulk MB | h3 SECS CONC");
            std::process::exit(2);
        }
    }
}
