//! Companion of the book's "Configuration", "Observability" and "TCP and UDP" chapters: every
//! engine knob, per-listener backends and acceleration, metrics, the connection table, slow
//! callbacks and hot reload, plus a UDP listener and a UDP dial.
//!
//! `cargo run -p akio --example guide-config`

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

use akio::{
    Accel, Acceptor, Backend, Config, Conn, EbpfConfig, Engine, Handler, Listener, PoolConfig,
    SlowHook, UringConfig, ebpf::Steering, fn_acceptor,
};

struct Echo;

impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if data.starts_with(b"block") {
            // Deliberately blocks the I/O thread: shows up as a slow callback.
            thread::sleep(Duration::from_millis(30));
        }
        let _ = c.send(data);
    }
}

struct UdpPeer;

impl Handler for UdpPeer {
    /// One call per datagram; `send` answers with one datagram to that peer.
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
}

struct UdpClient(mpsc::Sender<Vec<u8>>);

impl Handler for UdpClient {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = self.0.send(data.to_vec());
        c.close();
    }
}

struct UdpDial(mpsc::Sender<Vec<u8>>);

impl Acceptor for UdpDial {
    type Handler = UdpClient;
    fn on_open(&self, c: &Conn<UdpClient>) -> UdpClient {
        let _ = c.send(b"datagram"); // UDP has no handshake: usable at once
        UdpClient(self.0.clone())
    }
}

fn main() -> std::io::Result<()> {
    // ANCHOR: config
    // `Config` is #[non_exhaustive]: start from the defaults and set what you need.
    let mut cfg = Config::default();
    // Fixed at build time.
    cfg.read_buffer = 64 << 10; // per I/O thread; on_data sees at most this much
    cfg.backlog = 1024; // listen(2) backlog
    cfg.udp_idle_timeout = Duration::from_secs(60);
    cfg.udp_max_peers = Some(100_000); // default 65536; None = unlimited
    cfg.udp_gro = true; // Linux UDP GRO (the default), needs read_buffer >= 64 KiB
    // Reloadable with Engine::reload.
    cfg.write_high_watermark = 256 << 10; // pause reads above this many queued bytes
    cfg.max_queued_bytes = 64 << 20; // send() fails with Overloaded beyond this
    cfg.idle_timeout = Some(Duration::from_secs(300));
    cfg.slow_callback_threshold = Some(Duration::from_millis(10));
    cfg.slow_hook = Some(SlowHook(Arc::new(|s| {
        eprintln!("slow {} on conn {}: {:?}", s.kind, s.conn_id, s.elapsed);
    })));
    cfg.shutdown_timeout = Duration::from_secs(10);
    cfg.max_connections = 0; // 0 = unlimited
    cfg.log_level = None; // Some(akio::log::LevelFilter::Info) calls akio::log::set_max_level
    let telemetry = cfg.telemetry.clone(); // grab it before build to wire endpoints
    // ANCHOR_END: config

    // ANCHOR: listeners
    let mut pool = PoolConfig::default();
    pool.min_threads = 0;
    pool.max_threads = 64;
    pool.queue_capacity = 65_536;
    pool.keep_alive = Duration::from_secs(30);
    let mut steering = EbpfConfig::default();
    steering.steering = Steering::Cpu;
    let engine = Arc::new(
        Engine::builder()
            .config(cfg.clone())
            .pool(pool)
            // epoll (kqueue on macOS), two I/O threads.
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .threads(2)
                    .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
            )
            // io_uring with BPF steering; falls back to epoll / default hashing when the kernel
            // or privileges do not allow it (set `strict: true` to fail instead).
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .backend(Backend::IoUring(UringConfig::default()))
                    .accel(Accel::Ebpf(steering))
                    .threads(2)
                    .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
            )
            // A UDP listener: one Conn per peer address.
            .listen(
                Listener::udp("127.0.0.1:0".parse().unwrap())
                    .threads(1)
                    .serve(fn_acceptor(|_c: &Conn<UdpPeer>| UdpPeer)),
            )
            .client_threads(1) // for Engine::dial
            .udp_client_threads(1) // for Engine::dial_udp
            .build()?,
    );
    engine.start()?;
    println!("listening on {:?}", engine.local_addrs());
    println!("acceleration: {:?}", engine.accel_status());
    // ANCHOR_END: listeners
    let addrs = engine.local_addrs();

    let mut s = TcpStream::connect(addrs[0])?;
    let mut buf = [0u8; 64];
    s.write_all(b"block")?;
    let n = s.read(&mut buf)?;
    assert_eq!(&buf[..n], b"block");

    // ANCHOR: udp_dial
    let (tx, rx) = mpsc::channel();
    engine.dial_udp(addrs[2], UdpDial(tx), |e| eprintln!("udp dial failed: {e}"));
    let reply = rx.recv_timeout(Duration::from_secs(5)).expect("udp reply");
    // ANCHOR_END: udp_dial
    assert_eq!(reply, b"datagram");

    // ANCHOR: observe
    let m = engine.metrics();
    println!(
        "open={} accepted={} bytes_in={} slow={}",
        m.open_connections, m.total.accepted, m.total.bytes_in, m.total.slow_callbacks
    );
    let prometheus: String = m.to_prometheus(); // text exposition format 0.0.4
    assert!(prometheus.contains("akio_connections_accepted_total"));
    for row in engine.connections(Duration::from_secs(1)) {
        println!(
            "conn {} {} -> {} idle {:?}",
            row.id, row.peer, row.local, row.idle
        );
    }
    for rec in engine.slow_callbacks() {
        println!("slow: {} {:?} on {:?}", rec.kind, rec.elapsed, rec.owner);
    }
    println!(
        "pool: {:?}, udp: {:?}",
        engine.pool_stats(),
        engine.udp_stats()
    );
    // ANCHOR_END: observe

    // ANCHOR: reload
    let mut next = cfg;
    next.idle_timeout = Some(Duration::from_secs(30));
    next.max_connections = 10_000;
    next.read_buffer = 128 << 10; // open connections read with it from their next read on
    next.backlog = 4096; // listening sockets are listen()ed again
    next.write_timeout = None; // fixed at build time: reported, not applied
    let report = engine.reload(&next);
    println!(
        "applied {:?}, needs restart {:?}",
        report.applied, report.ignored
    );
    // The live values, as the I/O threads see them:
    assert_eq!(telemetry.live().max_connections(), 10_000);
    // I/O threads per listener, in local_addrs() order; grow the first listener to 4 threads,
    // then shrink it to 1: retired threads finish their connections, none is moved or closed.
    println!("threads: {:?}", engine.threads());
    engine.set_threads(0, 4)?;
    engine.set_threads(0, 1)?;
    // ANCHOR_END: reload

    engine.shutdown();
    engine.wait();
    Ok(())
}
