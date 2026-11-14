//! `Accel::Ebpf` steering through the engine, and the sockmap relay between two flash
//! connections (Linux). Steering with classic BPF needs no privileges; the eBPF tier and the
//! relay are used only when permitted, unless `FLASH_TEST_EXPECT_EBPF=1` demands them.
#![allow(missing_docs)]
#![cfg(target_os = "linux")]

mod common;

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use flash::{
    Accel, AccelStatus, Acceptor, Config, Conn, EbpfConfig, Engine, EngineRef, Handler, Listener,
    ebpf::{self, HashKey, Steering, Tier},
};
use flash_core::ConnInner;

fn expect_ebpf() -> bool {
    std::env::var("FLASH_TEST_EXPECT_EBPF").is_ok_and(|v| v == "1")
}

fn cfg() -> Config {
    Config {
        shutdown_timeout: Duration::from_millis(300),
        ..Config::default()
    }
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

/// Index `i` of the current I/O thread ("flash-io-i" / "flash-udp-i").
fn thread_index() -> usize {
    let name = thread::current().name().unwrap_or_default().to_string();
    name.rsplit('-').next().unwrap().parse().unwrap()
}

type Landed = Arc<Mutex<HashMap<SocketAddr, usize>>>;

/// Records which I/O thread each peer landed on.
struct Recorder(Landed);
struct Quiet;
impl Handler for Quiet {
    fn on_data(&mut self, _c: &Conn<Self>, _data: &[u8]) {}
}
impl Acceptor for Recorder {
    type Handler = Quiet;
    fn on_open(&self, c: &Conn<Quiet>) -> Quiet {
        self.0.lock().unwrap().insert(c.peer_addr(), thread_index());
        Quiet
    }
}

fn landed_on(l: &Landed, peer: SocketAddr) -> usize {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(&i) = l.lock().unwrap().get(&peer) {
            return i;
        }
        assert!(Instant::now() < deadline, "{peer} never opened");
        thread::sleep(Duration::from_millis(2));
    }
}

fn steered_engine(udp: bool, threads: usize, steering: Steering) -> (Engine, Landed) {
    let landed: Landed = Arc::default();
    let l = if udp {
        Listener::udp("127.0.0.1:0".parse().unwrap())
    } else {
        Listener::tcp("127.0.0.1:0".parse().unwrap()).backend(common::backend())
    };
    let e = Engine::builder()
        .config(cfg())
        .listen(
            l.threads(threads)
                .accel(Accel::Ebpf(EbpfConfig {
                    steering,
                    strict: true,
                    ..EbpfConfig::default()
                }))
                .serve(Recorder(landed.clone())),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    (e, landed)
}

fn pin_to_cpu(cpu: usize) {
    // SAFETY: `set` is a plain bitmask initialized by CPU_ZERO/CPU_SET before use.
    let ok = unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) == 0
    };
    assert!(ok, "sched_setaffinity({cpu})");
}

#[test]
fn cpu_steering_puts_each_connection_on_the_thread_of_its_cpu() {
    let cpus = thread::available_parallelism().map_or(1, |n| n.get());
    let threads = cpus.clamp(2, 4);
    let (e, landed) = steered_engine(false, threads, Steering::Cpu);
    let AccelStatus::Steering(info) = &e.accel_status()[0] else {
        panic!("{:?}", e.accel_status());
    };
    assert_eq!(info.sockets, threads);
    if expect_ebpf() {
        assert_eq!(info.tier, Tier::Ebpf, "{info:?}");
    }
    eprintln!("attached: {info} ({:?})", info.ebpf_unavailable);
    let addr = e.local_addrs()[0];
    let mut keep = Vec::new();
    for round in 0..2 {
        for cpu in 0..cpus.min(8) {
            let s = thread::spawn(move || {
                pin_to_cpu(cpu);
                TcpStream::connect(addr).unwrap()
            })
            .join()
            .unwrap();
            let peer = s.local_addr().unwrap();
            assert_eq!(
                landed_on(&landed, peer),
                cpu % threads,
                "round {round} cpu {cpu}"
            );
            keep.push(s);
        }
    }
    drop(keep);
    stop(&e);
}

#[test]
fn hash_steering_is_deterministic_for_tcp_connections() {
    let (e, landed) = steered_engine(false, 4, Steering::Hash(HashKey::SrcIpPort));
    let local = e.local_addrs()[0];
    let mut per_thread = [0usize; 4];
    let mut keep = Vec::new();
    for _ in 0..48 {
        let s = TcpStream::connect(local).unwrap();
        let peer = s.local_addr().unwrap();
        let want = ebpf::expected_index(Steering::Hash(HashKey::SrcIpPort), 4, peer, local);
        let got = landed_on(&landed, peer);
        assert_eq!(Some(got), want, "{peer}");
        per_thread[got] += 1;
        keep.push(s);
    }
    assert!(per_thread.iter().all(|&c| c > 0), "{per_thread:?}");
    drop(keep);
    stop(&e);
}

#[test]
fn hash_steering_by_source_ip_keeps_each_udp_host_on_one_thread() {
    let (e, landed) = steered_engine(true, 3, Steering::Hash(HashKey::SrcIp));
    let local = e.local_addrs()[0];
    for host in 1..=24u8 {
        for _port in 0..2 {
            // Two sockets (ports) per source address: same thread.
            let s = UdpSocket::bind(SocketAddr::from(([127, 0, 0, host], 0))).unwrap();
            s.send_to(b"x", local).unwrap();
            let peer = s.local_addr().unwrap();
            let want = ebpf::expected_index(Steering::Hash(HashKey::SrcIp), 3, peer, local);
            assert_eq!(Some(landed_on(&landed, peer)), want, "{peer}");
        }
    }
    stop(&e);
}

// ---- sockmap relay between two flash connections -------------------------------------------

/// Bytes userspace saw on the proxy's connections (0 when the kernel relays everything).
static USER_BYTES: AtomicUsize = AtomicUsize::new(0);

struct Side {
    other: Arc<Mutex<Option<Arc<ConnInner>>>>,
}
impl Handler for Side {
    fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
        USER_BYTES.fetch_add(data.len(), Ordering::Relaxed);
        if let Some(o) = self.other.lock().unwrap().as_ref() {
            let _ = o.send(data); // the userspace fallback
        }
    }
    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<flash::Error>) {
        if let Some(o) = self.other.lock().unwrap().take() {
            o.close_after_send();
        }
    }
}

/// A one-target TCP proxy: dials `upstream` per client and splices the two connections, then
/// writes `K` (kernel) or `U` (userspace fallback) to the client as its go-ahead.
struct Proxy {
    engine: EngineRef,
    upstream: SocketAddr,
    relay: Option<ebpf::Relay>,
}

impl Acceptor for Proxy {
    type Handler = Side;
    fn on_open(&self, c: &Conn<Side>) -> Side {
        let client = c.inner().clone();
        let to_upstream = Arc::new(Mutex::new(None));
        let slot = to_upstream.clone();
        let relay = self.relay.clone();
        let up_acceptor = flash::fn_acceptor(move |u: &Conn<Side>| {
            *slot.lock().unwrap() = Some(u.inner().clone());
            let spliced = relay
                .as_ref()
                .is_some_and(|r| r.splice_conns(&client, u.inner()).is_ok());
            let _ = client.send(if spliced { b"K" } else { b"U" });
            Side {
                other: Arc::new(Mutex::new(Some(client.clone()))),
            }
        });
        let c2 = c.inner().clone();
        self.engine
            .get()
            .unwrap()
            .dial(self.upstream, up_acceptor, move |_| c2.close());
        Side { other: to_upstream }
    }
}

fn read_n(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    let mut got = 0;
    while got < n {
        match s.read(&mut v[got..]) {
            Ok(0) => panic!("EOF after {got}/{n}"),
            Ok(k) => got += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => panic!("read: {e}"),
        }
    }
    v
}

#[test]
fn sockmap_relay_splices_proxied_flash_connections() {
    // Small transfers only, so kernels below ebpf::relay::MIN_KERNEL are fine too.
    let relay = match ebpf::Relay::new_unchecked(64) {
        Ok(r) => Some(r),
        Err(e) if expect_ebpf() => panic!("sockmap relay: {e}"),
        Err(e) => {
            eprintln!("sockmap relay unavailable ({e}): checking the userspace fallback");
            None
        }
    };
    // Upstream: a plain echo server.
    let up = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = up.local_addr().unwrap();
    thread::spawn(move || {
        for s in up.incoming() {
            let mut s = s.unwrap();
            thread::spawn(move || {
                let mut b = [0u8; 4096];
                loop {
                    match s.read(&mut b) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => s.write_all(&b[..n]).unwrap(),
                    }
                }
            });
        }
    });
    let er = EngineRef::new();
    let e = Arc::new(
        Engine::builder()
            .config(cfg())
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .backend(common::backend())
                    .threads(2)
                    .serve(Proxy {
                        engine: er.clone(),
                        upstream,
                        relay: relay.clone(),
                    }),
            )
            .build()
            .unwrap(),
    );
    er.set(&e);
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    USER_BYTES.store(0, Ordering::Relaxed);
    let mut total = 0;
    for i in 0..8 {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mode = read_n(&mut s, 1);
        assert_eq!(mode, if relay.is_some() { b"K" } else { b"U" });
        for j in 0..20 {
            let msg = format!("conn {i} message {j} {}", "x".repeat(j * 100));
            s.write_all(msg.as_bytes()).unwrap();
            assert_eq!(read_n(&mut s, msg.len()), msg.as_bytes());
            total += msg.len();
        }
    }
    let user = USER_BYTES.load(Ordering::Relaxed);
    if relay.is_some() {
        assert_eq!(user, 0, "spliced data must not reach userspace");
    } else {
        assert_eq!(user, 2 * total);
    }
    stop(&e);
}
