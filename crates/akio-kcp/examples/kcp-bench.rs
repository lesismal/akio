//! KCP loopback throughput (public API only, so the same program measures any version):
//!
//! ```text
//! kcp-bench bulk MB [SIZE]   MB megabytes of SIZE-byte messages (default 16384) from a client
//!                            to a counting server, fast mode with 1024-segment windows
//! kcp-bench echo SECS CONC   echoed 64-byte messages per second, CONC in flight on one session
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use akio::{Engine, Listener};
use akio_kcp::{KcpConfig, KcpError, KcpHandler, KcpServer, Session};

fn cfg() -> KcpConfig {
    let mut c = KcpConfig::fast();
    c.send_window = 1024;
    c.recv_window = 1024;
    c
}

struct Count(Arc<AtomicU64>);
impl KcpHandler for Count {
    fn on_message(&mut self, _s: &Session, msg: Vec<u8>) {
        self.0.fetch_add(msg.len() as u64, Ordering::Relaxed);
    }
}

struct Echo;
impl KcpHandler for Echo {
    fn on_message(&mut self, s: &Session, msg: Vec<u8>) {
        let _ = s.send(&msg);
    }
}

fn server<H: KcpHandler>(
    f: impl Fn() -> H + Send + Sync + 'static,
) -> (Engine, std::net::SocketAddr) {
    let mut c = cfg();
    c.write_queue = 1 << 16;
    let srv = KcpServer::new(c, move |_s: &Session| f()).expect("server");
    let e = Engine::builder()
        .listen(Listener::udp("127.0.0.1:0".parse().expect("addr")).serve(srv))
        .udp_client_threads(1)
        .build()
        .expect("engine");
    e.start().expect("start");
    let addr = e.local_addrs()[0];
    (e, addr)
}

fn bulk(mb: u64, size: usize) {
    let got = Arc::new(AtomicU64::new(0));
    let g = got.clone();
    let (e, addr) = server(move || Count(g.clone()));
    struct Quiet;
    impl KcpHandler for Quiet {
        fn on_message(&mut self, _s: &Session, _m: Vec<u8>) {}
    }
    let s = akio_kcp::dial(&e, addr, cfg(), Quiet).expect("dial");
    let msg = vec![0x5au8; size];
    let total = mb << 20;
    let start = Instant::now();
    let mut sent = 0u64;
    let mut full = 0u64;
    while sent < total {
        match s.send(&msg) {
            Ok(()) => sent += size as u64,
            Err(KcpError::Full) => {
                full += 1;
                std::thread::sleep(Duration::from_micros(50));
            }
            Err(e) => panic!("send: {e}"),
        }
    }
    let end = Instant::now() + Duration::from_secs(120);
    while got.load(Ordering::Relaxed) < sent {
        assert!(Instant::now() < end, "not all delivered");
        std::thread::sleep(Duration::from_micros(200));
    }
    let el = start.elapsed().as_secs_f64();
    let st = s.stats();
    println!(
        "kcp bulk: {mb} MB in {size}-byte messages in {el:.2}s = {:.0} Mbit/s ({full} Full, {} sent, {} retransmitted)",
        (sent * 8) as f64 / el / 1e6,
        st.sent,
        st.retransmitted + st.fast_retransmitted
    );
}

fn echo(secs: u64, conc: usize) {
    let (e, addr) = server(|| Echo);
    struct Back(mpsc::Sender<()>);
    impl KcpHandler for Back {
        fn on_message(&mut self, _s: &Session, _m: Vec<u8>) {
            let _ = self.0.send(());
        }
    }
    let (tx, rx) = mpsc::channel();
    let s = akio_kcp::dial(&e, addr, cfg(), Back(tx)).expect("dial");
    let msg = [7u8; 64];
    for _ in 0..conc {
        s.send(&msg).expect("send");
    }
    let start = Instant::now();
    let end = start + Duration::from_secs(secs);
    let mut n = 0u64;
    while Instant::now() < end {
        assert!(
            rx.recv_timeout(Duration::from_secs(5)).is_ok(),
            "echo stalled"
        );
        n += 1;
        while s.send(&msg).is_err() {
            std::thread::sleep(Duration::from_micros(20));
        }
    }
    let el = start.elapsed().as_secs_f64();
    println!(
        "kcp echo: {n} in {el:.1}s = {:.0} msg/s ({conc} in flight)",
        n as f64 / el
    );
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let arg = |i: usize, d: u64| a.get(i).and_then(|s| s.parse().ok()).unwrap_or(d);
    match a.get(1).map(String::as_str) {
        Some("bulk") => bulk(arg(2, 512), arg(3, 16384) as usize),
        Some("echo") => echo(arg(2, 5), arg(3, 64) as usize),
        _ => {
            println!("usage: kcp-bench bulk MB [SIZE] | echo SECS CONC");
            std::process::exit(2);
        }
    }
}
