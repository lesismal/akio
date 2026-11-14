//! Two userspace stacks joined by an in-process memory wire (any platform, no privileges):
//! UDP and TCP echo through `Backend::Dpdk`, dialing from the second stack, KCP on top, and
//! graceful shutdown.
#![allow(missing_docs)]

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

use flash::{
    Backend, Config, Conn, Engine, Error, Handler, Listener,
    dpdk::{Device, DpdkConfig, MemoryWire},
    fn_acceptor,
};

const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

fn cfg() -> Config {
    let mut c = Config::default();
    c.shutdown_timeout = Duration::from_millis(500);
    c
}

struct Echo;
impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
}

/// Collects what a dialed connection receives.
struct Sink(mpsc::Sender<Vec<u8>>);
impl Handler for Sink {
    fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
        let _ = self.0.send(data.to_vec());
    }
}

fn backend(dev: Device, ip: Ipv4Addr) -> Backend {
    Backend::Dpdk(DpdkConfig::new(dev, ip))
}

/// Server engine on wire end A (UDP echo on 7000, TCP echo on 7001) and a client engine on end
/// B (a UDP and a TCP listener, so `dial_udp` / `dial` run on B's stack).
fn pair() -> (Engine, Engine) {
    let (a, b) = MemoryWire::new();
    let server = Engine::builder()
        .config(cfg())
        .listen(
            Listener::udp(SocketAddr::from((A, 7000)))
                .backend(backend(Device::Memory(a.clone()), A))
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .listen(
            Listener::tcp(SocketAddr::from((A, 7001)))
                .backend(backend(Device::Memory(a), A))
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build()
        .unwrap();
    let client = Engine::builder()
        .config(cfg())
        .listen(
            Listener::udp(SocketAddr::from(([0, 0, 0, 0], 0)))
                .backend(backend(Device::Memory(b.clone()), B))
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .listen(
            Listener::tcp(SocketAddr::from(([0, 0, 0, 0], 0)))
                .backend(backend(Device::Memory(b), B))
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build()
        .unwrap();
    server.start().unwrap();
    client.start().unwrap();
    (server, client)
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

#[test]
fn udp_echo_keeps_datagram_boundaries() {
    let (server, client) = pair();
    assert_eq!(server.local_addrs()[0], SocketAddr::from((A, 7000)));
    let (tx, rx) = mpsc::channel();
    let conn: Arc<Mutex<Option<Conn<Sink>>>> = Arc::default();
    let slot = conn.clone();
    client.dial_udp(
        SocketAddr::from((A, 7000)),
        fn_acceptor(move |c: &Conn<Sink>| {
            *slot.lock().unwrap() = Some(c.clone());
            Sink(tx.clone())
        }),
        |e| panic!("dial_udp: {e}"),
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let c = loop {
        let opened = conn.lock().unwrap().clone();
        if let Some(c) = opened {
            break c;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "dial_udp never opened"
        );
        std::thread::sleep(Duration::from_millis(1));
    };
    for i in 0..200u32 {
        let msg = format!("datagram-{i}-").repeat(1 + (i as usize % 20));
        c.send(msg.as_bytes()).unwrap();
        let got = rx.recv_timeout(Duration::from_secs(5)).expect("echo");
        assert_eq!(got, msg.as_bytes());
    }
    assert_eq!(server.udp_stats().peers, 1);
    stop(&client);
    stop(&server);
}

#[test]
fn tcp_echo_bulk_with_flow_control() {
    let (server, client) = pair();
    let (tx, rx) = mpsc::channel();
    let (otx, orx) = mpsc::channel();
    client.dial(
        SocketAddr::from((A, 7001)),
        fn_acceptor(move |c: &Conn<Sink>| {
            let _ = otx.send(c.clone());
            Sink(tx.clone())
        }),
        |e| panic!("dial: {e}"),
    );
    let c = orx.recv_timeout(Duration::from_secs(5)).expect("connected");
    assert_eq!(c.peer_addr(), SocketAddr::from((A, 7001)));
    // 4 MiB through 64 KiB windows: exercises backpressure and send queues on both sides.
    let data: Vec<u8> = (0..4u32 << 20).map(|i| (i % 251) as u8).collect();
    // The client keeps its send queue under the read-pause watermark (as an echo client must:
    // above it, flash stops reading the echoes, and the echo server stops reading too).
    let mut got = Vec::with_capacity(data.len());
    let mut chunks = data.chunks(16 << 10);
    let mut next = chunks.next();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while got.len() < data.len() {
        assert!(
            std::time::Instant::now() < deadline,
            "stalled at {} bytes",
            got.len()
        );
        while let Some(chunk) = next {
            if c.queued_bytes() > 64 << 10 {
                break;
            }
            c.send(chunk).unwrap();
            next = chunks.next();
        }
        if let Ok(d) = rx.recv_timeout(Duration::from_millis(100)) {
            got.extend(d);
        }
        assert!(got.len() <= data.len());
    }
    assert_eq!(got, data);
    stop(&client);
    stop(&server);
}

#[test]
fn tcp_close_after_send_and_on_close() {
    struct Greeter;
    impl Handler for Greeter {
        fn on_data(&mut self, _c: &Conn<Self>, _data: &[u8]) {}
    }
    struct Recorder(mpsc::Sender<Result<Vec<u8>, Option<String>>>);
    impl Handler for Recorder {
        fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
            let _ = self.0.send(Ok(data.to_vec()));
        }
        fn on_close(&mut self, _c: &Conn<Self>, err: Option<Error>) {
            let _ = self.0.send(Err(err.map(|e| e.to_string())));
        }
    }
    let (a, b) = MemoryWire::new();
    let closed = Arc::new(AtomicUsize::new(0));
    let closed2 = closed.clone();
    let server = Engine::builder()
        .config(cfg())
        .listen(
            Listener::tcp(SocketAddr::from((A, 80)))
                .backend(backend(Device::Memory(a), A))
                .serve(fn_acceptor(move |c: &Conn<Greeter>| {
                    closed2.fetch_add(1, Ordering::Relaxed);
                    let _ = c.send(b"hello, then goodbye");
                    c.close_after_send();
                    Greeter
                })),
        )
        .build()
        .unwrap();
    let client = Engine::builder()
        .config(cfg())
        .listen(
            Listener::tcp(SocketAddr::from((B, 0)))
                .backend(backend(Device::Memory(b), B))
                .serve(fn_acceptor(|_c: &Conn<Greeter>| Greeter)),
        )
        .build()
        .unwrap();
    server.start().unwrap();
    client.start().unwrap();
    let (tx, rx) = mpsc::channel();
    client.dial(
        SocketAddr::from((A, 80)),
        fn_acceptor(move |_c: &Conn<Recorder>| Recorder(tx.clone())),
        |e| panic!("dial: {e}"),
    );
    let mut got = Vec::new();
    loop {
        match rx.recv_timeout(Duration::from_secs(5)).expect("event") {
            Ok(d) => got.extend(d),
            Err(err) => {
                assert_eq!(err, None, "orderly close expected");
                break;
            }
        }
    }
    assert_eq!(got, b"hello, then goodbye");
    assert_eq!(closed.load(Ordering::Relaxed), 1);
    stop(&client);
    stop(&server);
}

#[test]
fn listener_address_must_be_the_stack_address() {
    let (a, _b) = MemoryWire::new();
    let r = Engine::builder()
        .listen(
            Listener::udp(SocketAddr::from(([10, 9, 9, 9], 1)))
                .backend(backend(Device::Memory(a), A))
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build();
    assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::AddrNotAvailable);
}

#[test]
fn same_port_twice_is_refused() {
    let (a, _b) = MemoryWire::new();
    let r = Engine::builder()
        .listen(
            Listener::udp(SocketAddr::from((A, 9)))
                .backend(backend(Device::Memory(a.clone()), A))
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .listen(
            Listener::udp(SocketAddr::from((A, 9)))
                .backend(backend(Device::Memory(a), A))
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build();
    assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::AddrInUse);
}

#[test]
fn kcp_over_the_userspace_stack() {
    use flash_kcp::{KcpConfig, KcpHandler, KcpServer, Session};
    struct KEcho;
    impl KcpHandler for KEcho {
        fn on_message(&mut self, s: &Session, msg: Vec<u8>) {
            let _ = s.send(&msg);
        }
    }
    struct KClient(mpsc::Sender<Vec<u8>>);
    impl KcpHandler for KClient {
        fn on_message(&mut self, _s: &Session, msg: Vec<u8>) {
            let _ = self.0.send(msg);
        }
    }
    let (a, b) = MemoryWire::new();
    let kcfg = KcpConfig::fast();
    let server = Engine::builder()
        .config(cfg())
        .listen(
            Listener::udp(SocketAddr::from((A, 4000)))
                .backend(backend(Device::Memory(a), A))
                .serve(KcpServer::new(kcfg.clone(), |_s: &Session| KEcho).unwrap()),
        )
        .build()
        .unwrap();
    let client = Engine::builder()
        .config(cfg())
        .listen(
            Listener::udp(SocketAddr::from((B, 0)))
                .backend(backend(Device::Memory(b), B))
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build()
        .unwrap();
    server.start().unwrap();
    client.start().unwrap();
    let (tx, rx) = mpsc::channel();
    let s = flash_kcp::dial(&client, SocketAddr::from((A, 4000)), kcfg, KClient(tx)).unwrap();
    for i in 0..50 {
        let msg = format!("kcp message {i}").repeat(100); // several KCP segments each
        s.send(msg.as_bytes()).unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).expect("kcp echo"),
            msg.as_bytes()
        );
    }
    s.close();
    stop(&client);
    stop(&server);
}
