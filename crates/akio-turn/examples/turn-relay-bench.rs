//! TURN relay throughput micro-benchmark: `PAIRS` client/peer pairs, each with an allocation
//! and a channel, blast 100-byte datagrams both ways (client → ChannelData → peer, and
//! peer → relay → ChannelData → client) for `SECS` seconds; prints datagrams relayed per
//! second in each direction.
//!
//! `cargo run --release -p akio-turn --example turn-relay-bench -- [PAIRS] [SECS] [THREADS]`
//!
//! `TURN_BENCH_ECN=<1|2|3>` marks every datagram of both senders with that ECN codepoint
//! (Linux and macOS), which the relay copies (RFC 8656 section 14, ADR-083).
//! `TURN_BENCH_TOS=<0-255>` marks them with that whole traffic class byte instead (DSCP and
//! ECN, ADR-091); `TURN_BENCH_ECN` is then ignored.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use akio::{Engine, Listener};
use akio_turn::stun::{
    Class, Message, MessageBuilder, Method, attr, long_term_key, transaction_id,
};
use akio_turn::{TurnConfig, TurnServer, static_auth};

struct Client {
    s: UdpSocket,
    server: SocketAddr,
    nonce: String,
    key: [u8; 16],
}

impl Client {
    fn request(&mut self, m: Method, f: impl Fn(MessageBuilder) -> MessageBuilder) -> Vec<u8> {
        for _ in 0..3 {
            let tid = transaction_id();
            let mut b = f(MessageBuilder::new(m, Class::Request, tid));
            if !self.nonce.is_empty() {
                b = b
                    .attr(attr::USERNAME, b"bench")
                    .attr(attr::REALM, b"akio")
                    .attr(attr::NONCE, self.nonce.as_bytes())
                    .integrity(&self.key);
            }
            self.s.send_to(&b.build(), self.server).expect("send");
            let mut buf = vec![0u8; 2048];
            let n = loop {
                let (n, _) = self.s.recv_from(&mut buf).expect("recv");
                if Message::parse(&buf[..n]).is_ok_and(|m| m.transaction_id() == tid) {
                    break n;
                }
            };
            buf.truncate(n);
            let msg = Message::parse(&buf).expect("parse");
            match msg.error_code() {
                Some((401 | 438, _)) => {
                    self.nonce = msg.get_str(attr::NONCE).expect("nonce").to_owned();
                }
                _ => return buf,
            }
        }
        panic!("still challenged");
    }
}

/// Sends `d` to `to`, marked with traffic class byte `ecn` (DSCP and ECN) where the platform
/// allows.
fn send(s: &UdpSocket, d: &[u8], to: SocketAddr, ecn: u8) {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if ecn != 0 {
        use std::os::fd::AsRawFd;
        let _ = akio_sys::send_to_tos(s.as_raw_fd(), d, Some(&to), ecn, to.is_ipv6());
        return;
    }
    let _ = ecn;
    let _ = s.send_to(d, to);
}

fn main() {
    let ecn: u8 = std::env::var("TURN_BENCH_TOS")
        .ok()
        .and_then(|v| v.parse().ok())
        .or_else(|| {
            std::env::var("TURN_BENCH_ECN")
                .ok()
                .and_then(|v| v.parse::<u8>().ok())
                .map(|e| e & 3)
        })
        .unwrap_or(0);
    let args: Vec<usize> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse().ok())
        .collect();
    let pairs = args.first().copied().unwrap_or(8);
    let secs = args.get(1).copied().unwrap_or(5) as u64;
    let threads = args.get(2).copied().unwrap_or(4);

    let auth = static_auth("akio", [("bench", "secret")]);
    let mut cfg =
        TurnConfig::new("akio", auth, "127.0.0.1".parse().expect("ip")).allow_private_peers(true);
    cfg.max_allocations_per_user = 100_000;
    let turn = TurnServer::new(cfg);
    let engine = Arc::new(
        Engine::builder()
            .listen(
                Listener::udp("127.0.0.1:0".parse().expect("addr"))
                    .threads(threads)
                    .serve(turn.clone()),
            )
            .build()
            .expect("engine"),
    );
    turn.set_engine(&engine);
    engine.start().expect("start");
    let server = engine.local_addrs()[0];

    let stop = Arc::new(AtomicBool::new(false));
    let to_peer = Arc::new(AtomicU64::new(0));
    let to_client = Arc::new(AtomicU64::new(0));
    let mut joins = Vec::new();
    let mut setups = Vec::new();
    for i in 0..pairs {
        let peer = UdpSocket::bind("127.0.0.1:0").expect("peer");
        let paddr = peer.local_addr().expect("addr");
        let s = UdpSocket::bind("127.0.0.1:0").expect("client");
        s.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let mut c = Client {
            s,
            server,
            nonce: String::new(),
            key: long_term_key("bench", "akio", "secret"),
        };
        let r = c.request(Method::ALLOCATE, |b| {
            b.attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0])
        });
        let relay = Message::parse(&r)
            .expect("parse")
            .get_xor_addr(attr::XOR_RELAYED_ADDRESS)
            .expect("relay");
        let ch = 0x4000 + i as u16;
        let r = c.request(Method::CHANNEL_BIND, |b| {
            b.attr(attr::CHANNEL_NUMBER, &[(ch >> 8) as u8, ch as u8, 0, 0])
                .xor_addr(attr::XOR_PEER_ADDRESS, paddr)
        });
        assert!(Message::parse(&r).expect("parse").error_code().is_none());
        setups.push((peer, c.s, relay, ch));
    }
    // Traffic starts once every allocation exists.
    for (peer, cs_sock, relay, ch) in setups {
        peer.set_read_timeout(Some(Duration::from_millis(100)))
            .expect("timeout");
        cs_sock
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("timeout");
        let cs = cs_sock.try_clone().expect("clone");
        let ps = peer.try_clone().expect("clone");
        // Client sender: ChannelData.
        let st = stop.clone();
        joins.push(thread::spawn(move || {
            let mut d = vec![0u8; 104];
            d[..2].copy_from_slice(&ch.to_be_bytes());
            d[2..4].copy_from_slice(&100u16.to_be_bytes());
            while !st.load(Ordering::Relaxed) {
                for _ in 0..64 {
                    send(&cs, &d, server, ecn);
                }
            }
        }));
        // Peer sender: plain datagrams to the relay.
        let st = stop.clone();
        joins.push(thread::spawn(move || {
            let d = [7u8; 100];
            while !st.load(Ordering::Relaxed) {
                for _ in 0..64 {
                    send(&ps, &d, relay, ecn);
                }
            }
        }));
        // Receivers.
        for (sock, ctr) in [(peer, to_peer.clone()), (cs_sock, to_client.clone())] {
            let st = stop.clone();
            joins.push(thread::spawn(move || {
                let mut b = [0u8; 2048];
                while !st.load(Ordering::Relaxed) {
                    if sock.recv_from(&mut b).is_ok() {
                        ctr.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
    }
    // Warm up, then measure.
    thread::sleep(Duration::from_secs(1));
    let (p0, c0) = (
        to_peer.load(Ordering::Relaxed),
        to_client.load(Ordering::Relaxed),
    );
    let t0 = Instant::now();
    thread::sleep(Duration::from_secs(secs));
    let el = t0.elapsed().as_secs_f64();
    let (p1, c1) = (
        to_peer.load(Ordering::Relaxed),
        to_client.load(Ordering::Relaxed),
    );
    stop.store(true, Ordering::Relaxed);
    for j in joins {
        let _ = j.join();
    }
    let tp = (p1 - p0) as f64 / el;
    let tc = (c1 - c0) as f64 / el;
    println!(
        "pairs={pairs} threads={threads} ecn={ecn} to_peer={tp:.0}/s to_client={tc:.0}/s total={:.0}/s",
        tp + tc
    );
    engine.shutdown();
    engine.wait();
}
