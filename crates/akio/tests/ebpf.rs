//! `Accel::Ebpf` steering through the engine, and the sockmap relay between two `akio`
//! connections (Linux). Steering with classic BPF needs no privileges; the eBPF tier and the
//! relay are used only when permitted, unless `AKIO_TEST_EXPECT_EBPF=1` demands them.
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
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use akio::{
    Accel, AccelStatus, Acceptor, Config, Conn, EbpfConfig, Engine, EngineRef, Handler, Listener,
    ebpf::{self, HashKey, Steering, Tier},
};
use akio_core::ConnInner;

fn expect_ebpf() -> bool {
    std::env::var("AKIO_TEST_EXPECT_EBPF").is_ok_and(|v| v == "1")
}

fn cfg() -> Config {
    {
        let mut v = Config::default();
        v.shutdown_timeout = Duration::from_millis(300);
        v
    }
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

/// Index `i` of the current I/O thread ("akio-io-i" / "akio-udp-i").
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
                .accel(Accel::Ebpf({
                    let mut v = EbpfConfig::default();
                    v.steering = steering;
                    v.strict = true;
                    v
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
        libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &raw const set) == 0
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

/// Records the I/O thread and the CPU it runs on when each connection opens.
struct CpuRecorder(Arc<Mutex<Vec<(usize, usize)>>>);
impl Acceptor for CpuRecorder {
    type Handler = Quiet;
    fn on_open(&self, _c: &Conn<Quiet>) -> Quiet {
        // SAFETY: sched_getcpu has no preconditions.
        let cpu = unsafe { libc::sched_getcpu() };
        self.0.lock().unwrap().push((thread_index(), cpu as usize));
        Quiet
    }
}

#[test]
fn pinned_threads_run_on_the_cpus_of_their_residue() {
    let cpus = thread::available_parallelism().map_or(1, |n| n.get());
    let threads = cpus.clamp(2, 4);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(common::backend())
                .threads(threads)
                .accel(Accel::Ebpf({
                    let mut v = EbpfConfig::default();
                    v.pin_threads = true;
                    v
                }))
                .serve(CpuRecorder(seen.clone())),
        )
        .build()
        .unwrap();
    let AccelStatus::Steering(info) = &e.accel_status()[0] else {
        panic!("{:?}", e.accel_status());
    };
    assert_eq!(info.pinned_threads, threads.min(cpus), "{info:?}");
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let mut keep = Vec::new();
    for cpu in 0..cpus.min(8) {
        keep.push(
            thread::spawn(move || {
                pin_to_cpu(cpu);
                TcpStream::connect(addr).unwrap()
            })
            .join()
            .unwrap(),
        );
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while seen.lock().unwrap().len() < keep.len() {
        assert!(Instant::now() < deadline, "connections did not open");
        thread::sleep(Duration::from_millis(2));
    }
    for &(t, cpu) in seen.lock().unwrap().iter().filter(|(t, _)| *t < cpus) {
        assert_eq!(cpu % threads, t, "thread {t} ran on CPU {cpu}");
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

// ---- sockmap relay between two `akio` connections -------------------------------------------

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
    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<akio::Error>) {
        let other = self.other.lock().unwrap().take();
        if let Some(o) = other {
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
        let client_conn = c.clone();
        let to_upstream = Arc::new(Mutex::new(None));
        let slot = to_upstream.clone();
        let relay = self.relay.clone();
        let up_acceptor = akio::fn_acceptor(move |u: &Conn<Side>| {
            *slot.lock().unwrap() = Some(u.inner().clone());
            let spliced = relay
                .as_ref()
                .is_some_and(|r| r.splice_conns(&client_conn, u).is_ok());
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
fn sockmap_relay_splices_proxied_only_connections() {
    // Small transfers only, so kernels below ebpf::relay::MIN_KERNEL are fine too.
    let relay = match ebpf::Relay::new_any_kernel(64) {
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

// ---- a connection's counters, and a spliced tunnel with a first write (akit A170) ----------

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(2));
    }
}

/// Counts what it reads.
struct Counted(Arc<AtomicUsize>);
impl Handler for Counted {
    fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
        self.0.fetch_add(data.len(), Ordering::SeqCst);
    }
}

/// `conn_byte_counts` of a live connection: what arrived while its reads are held is unread,
/// what the handler read is consumed, and what it sent is written. No privileges needed.
#[test]
fn conn_byte_counts_follow_a_live_connection() {
    let got = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let g = got.clone();
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(common::backend())
                .serve(akio::fn_acceptor(move |c: &Conn<Counted>| {
                    c.hold_reads(true);
                    let _ = tx.lock().unwrap().send(c.clone());
                    Counted(g.clone())
                })),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let mut s = TcpStream::connect(e.local_addrs()[0]).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let c = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    s.write_all(&[b'a'; 1000]).unwrap();
    let mut n = ebpf::ByteCounts::default();
    wait_until("1000 bytes received", || {
        n = ebpf::conn_byte_counts(&c).unwrap();
        n.received == 1000
    });
    assert_eq!((n.unread, n.consumed(), n.written), (1000, 0, 0), "{n:?}");
    assert_eq!(got.load(Ordering::SeqCst), 0);

    c.hold_reads(false);
    wait_until("the handler read them", || {
        got.load(Ordering::SeqCst) == 1000
    });
    let n = ebpf::conn_byte_counts(&c).unwrap();
    assert_eq!(
        (n.received, n.unread, n.consumed()),
        (1000, 0, 1000),
        "{n:?}"
    );

    c.send(&[b'b'; 500]).unwrap();
    assert_eq!(read_n(&mut s, 500), vec![b'b'; 500]);
    wait_until("500 bytes written", || {
        ebpf::conn_byte_counts(&c).unwrap().written == 500
    });
    stop(&e);
}

/// One proxied connection's state, shared by its two handlers.
struct TunnelState {
    relay: ebpf::Relay,
    tunnel: Mutex<Option<Arc<ebpf::Tunnel>>>,
    client: Mutex<Option<Conn<TunnelClient>>>,
    up: Mutex<Option<Conn<TunnelUp>>>,
    /// Payload a handler read while the tunnel was spliced (must stay 0).
    late: AtomicUsize,
    report: Mutex<mpsc::Sender<Result<Arc<ebpf::Tunnel>, String>>>,
}

impl TunnelState {
    fn tunnel(&self) -> Option<Arc<ebpf::Tunnel>> {
        self.tunnel.lock().unwrap().clone()
    }
}

/// The client's side: reads a greeting line in userspace, then holds its reads, dials the
/// upstream and splices, the greeting written first behind a marker.
struct TunnelClient {
    st: Arc<TunnelState>,
    engine: EngineRef,
    upstream: SocketAddr,
    greeting: Vec<u8>,
}

impl Handler for TunnelClient {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if let Some(t) = self.st.tunnel() {
            self.st.late.fetch_add(data.len(), Ordering::SeqCst);
            return t.late_payload();
        }
        if let Some(up) = self.st.up.lock().unwrap().as_ref() {
            let _ = up.send(data); // the userspace fallback
            return;
        }
        self.greeting.extend_from_slice(data);
        if !self.greeting.ends_with(b"\n") {
            return;
        }
        c.hold_reads(true);
        let st = self.st.clone();
        let first = [&b"FIRST:"[..], &self.greeting].concat();
        let c2 = c.clone();
        self.engine.get().unwrap().dial(
            self.upstream,
            akio::fn_acceptor(move |u: &Conn<TunnelUp>| {
                *st.up.lock().unwrap() = Some(u.clone());
                let client = st.client.lock().unwrap().clone().unwrap();
                match st.relay.tunnel(&client, u, &first) {
                    Ok(t) => {
                        let t = Arc::new(t);
                        *st.tunnel.lock().unwrap() = Some(t.clone());
                        let _ = st.report.lock().unwrap().send(Ok(t));
                    }
                    Err(e) => {
                        let _ = u.send(&first[e.written..]);
                        let _ = st.report.lock().unwrap().send(Err(e.to_string()));
                    }
                }
                client.hold_reads(false);
                TunnelUp { st: st.clone() }
            }),
            move |_| c2.close(),
        );
    }

    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<akio::Error>) {
        match self.st.tunnel() {
            Some(t) => t.close_after_forward(ebpf::TunnelSide::A, Duration::from_secs(5)),
            None => {
                if let Some(up) = self.st.up.lock().unwrap().as_ref() {
                    up.close_after_send();
                }
            }
        }
    }
}

/// The upstream's side.
struct TunnelUp {
    st: Arc<TunnelState>,
}

impl Handler for TunnelUp {
    fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
        if let Some(t) = self.st.tunnel() {
            self.st.late.fetch_add(data.len(), Ordering::SeqCst);
            return t.late_payload();
        }
        if let Some(c) = self.st.client.lock().unwrap().as_ref() {
            let _ = c.send(data);
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<akio::Error>) {
        match self.st.tunnel() {
            Some(t) => t.close_after_forward(ebpf::TunnelSide::B, Duration::from_secs(5)),
            None => {
                if let Some(c) = self.st.client.lock().unwrap().as_ref() {
                    c.close_after_send();
                }
            }
        }
    }
}

struct TunnelProxy {
    engine: EngineRef,
    upstream: SocketAddr,
    relay: ebpf::Relay,
    states: Arc<Mutex<Vec<Arc<TunnelState>>>>,
    report: Mutex<mpsc::Sender<Result<Arc<ebpf::Tunnel>, String>>>,
}

impl Acceptor for TunnelProxy {
    type Handler = TunnelClient;
    fn on_open(&self, c: &Conn<TunnelClient>) -> TunnelClient {
        let st = Arc::new(TunnelState {
            relay: self.relay.clone(),
            tunnel: Mutex::new(None),
            client: Mutex::new(Some(c.clone())),
            up: Mutex::new(None),
            late: AtomicUsize::new(0),
            report: Mutex::new(self.report.lock().unwrap().clone()),
        });
        self.states.lock().unwrap().push(st.clone());
        TunnelClient {
            st,
            engine: self.engine.clone(),
            upstream: self.upstream,
            greeting: Vec::new(),
        }
    }
}

/// A tunnel spliced with a first write: the upstream gets `first` (built from the greeting
/// userspace read) ahead of every relayed byte, the base counters say what userspace took and
/// wrote, the counters follow the relayed bytes, and when the client closes right after a bulk
/// write the upstream is closed only once all of it reached it.
#[test]
fn tunnel_writes_first_then_relays_and_drains_on_close() {
    let relay = match ebpf::Relay::new(64) {
        Ok(r) => r,
        Err(e) if expect_ebpf() => panic!("sockmap relay: {e}"),
        Err(e) => return eprintln!("skipping: sockmap relay unavailable ({e})"),
    };
    const BULK: usize = 4 << 20;
    // Upstream: checks what comes first, greets, then counts until EOF.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = l.local_addr().unwrap();
    let (utx, urx) = mpsc::channel();
    thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let first = read_n(&mut s, 12);
        s.write_all(b"UP-HELLO").unwrap();
        let mut total = 0usize;
        let mut ok = true;
        let mut b = vec![0u8; 64 << 10];
        loop {
            match s.read(&mut b) {
                Ok(0) => break,
                Ok(n) => {
                    ok &= b[..n]
                        .iter()
                        .enumerate()
                        .all(|(i, &x)| x == ((total + i) % 251) as u8);
                    total += n;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => panic!("upstream read after {total}: {e}"),
            }
        }
        let _ = utx.send((first, total, ok));
    });
    let er = EngineRef::new();
    let states = Arc::new(Mutex::new(Vec::new()));
    let (rtx, rrx) = mpsc::channel();
    let e = Arc::new(
        Engine::builder()
            .config(cfg())
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .backend(common::backend())
                    .serve(TunnelProxy {
                        engine: er.clone(),
                        upstream,
                        relay,
                        states: states.clone(),
                        report: Mutex::new(rtx),
                    }),
            )
            .build()
            .unwrap(),
    );
    er.set(&e);
    e.start().unwrap();

    let mut s = TcpStream::connect(e.local_addrs()[0]).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(b"GREET\n").unwrap();
    let t = rrx
        .recv_timeout(Duration::from_secs(10))
        .unwrap()
        .expect("spliced");
    assert_eq!(read_n(&mut s, 8), b"UP-HELLO");
    // Base: the client's 6 greeting bytes were read by userspace, the upstream was written the
    // 12 bytes of `first` (plus its SYN, which the kernel counts on a dialed socket).
    let [a, b] = t.base();
    assert_eq!((a.consumed(), a.written), (6, 0), "{a:?}");
    assert_eq!((b.consumed(), b.written), (0, 13), "{b:?}");
    assert_eq!(t.splice().base(), Some([a, b]));
    // The upstream's greeting is relayed to the client by the kernel.
    assert_eq!(t.relayed_from(ebpf::TunnelSide::B), Some(8));
    assert_eq!(t.relayed_from(ebpf::TunnelSide::A), Some(0));
    wait_until("the greeting in the client's send queue", || {
        t.counts(ebpf::TunnelSide::A)
            .is_some_and(|c| c.written == 8)
    });
    // Whether the greeting's movement is seen by the first `moved` depends on when the kernel
    // relayed it against the tunnel's baseline (io_uring and work-stealing scheduling may relay it
    // first); either way the tunnel goes quiet once the kernel is done with it.
    let _ = t.moved();
    wait_until("the tunnel quiet", || !t.moved());

    // Bulk, then close at once: the upstream must get every byte before its EOF.
    let bulk: Vec<u8> = (0..BULK).map(|i| (i % 251) as u8).collect();
    s.write_all(&bulk).unwrap();
    // The bulk is moving through the kernel: the idle probe sees it.
    wait_until("the bulk seen moving", || t.moved());
    drop(s);
    let closing = Instant::now();
    let (first, total, ok) = urx.recv_timeout(Duration::from_secs(30)).unwrap();
    // Closed once everything was forwarded, not after the 5 s stall.
    assert!(
        closing.elapsed() < Duration::from_secs(4),
        "{:?}",
        closing.elapsed()
    );
    assert_eq!(first, b"FIRST:GREET\n");
    assert_eq!(total, BULK);
    assert!(ok, "the relayed bytes differ");
    for st in states.lock().unwrap().iter() {
        assert_eq!(st.late.load(Ordering::SeqCst), 0);
    }
    stop(&e);
}
