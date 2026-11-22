//! KCP sessions end to end over loopback.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use akio::{Engine, Listener};
use akio_kcp::{CloseReason, Crypt, KcpConfig, KcpHandler, KcpServer, Session};

struct Echo;
impl KcpHandler for Echo {
    fn on_message(&mut self, s: &Session, msg: Vec<u8>) {
        let _ = s.send(&msg);
    }
}

struct Collect(mpsc::Sender<Vec<u8>>, Option<mpsc::Sender<CloseReason>>);
impl KcpHandler for Collect {
    fn on_message(&mut self, _s: &Session, msg: Vec<u8>) {
        let _ = self.0.send(msg);
    }
    fn on_close(&mut self, _s: &Session, why: CloseReason) {
        if let Some(t) = self.1.take() {
            let _ = t.send(why);
        }
    }
}

fn engine(cfg: KcpConfig) -> (Arc<Engine>, SocketAddr) {
    // Echo never waits on the I/O thread, so its queue must hold whatever the client has in flight.
    let mut cfg = cfg;
    cfg.write_queue = 1 << 20;
    let server = KcpServer::new(cfg, |_s: &Session| Echo).unwrap();
    let e = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap())
                .threads(2)
                .serve(server),
        )
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    (Arc::new(e), addr)
}

fn echo_roundtrip(cfg: KcpConfig) {
    let (e, addr) = engine(cfg.clone());
    let (tx, rx) = mpsc::channel();
    let (ctx, crx) = mpsc::channel();
    let s = akio_kcp::dial(&e, addr, cfg, Collect(tx, Some(ctx))).unwrap();
    let msgs: Vec<Vec<u8>> = (0..200)
        .map(|i| vec![(i % 251) as u8; 1 + i * 97 % 20_000])
        .collect();
    for m in &msgs {
        loop {
            match s.send(m) {
                Ok(()) => break,
                Err(akio_kcp::KcpError::Full) => std::thread::sleep(Duration::from_millis(2)),
                Err(e) => panic!("send: {e}"),
            }
        }
    }
    for (i, m) in msgs.iter().enumerate() {
        let got = rx
            .recv_timeout(Duration::from_secs(10))
            .unwrap_or_else(|_| panic!("echo {i}, stats {:?}", s.stats()));
        assert_eq!(got.len(), m.len(), "message {i}");
        assert_eq!(&got, m);
    }
    s.close();
    assert_eq!(
        crx.recv_timeout(Duration::from_secs(2)).unwrap(),
        CloseReason::Closed
    );
    assert!(s.send(b"x").is_err());
    e.shutdown();
}

#[test]
fn echo_plain() {
    echo_roundtrip(KcpConfig::fast());
}

#[test]
fn echo_normal_mode() {
    echo_roundtrip(KcpConfig::default());
}

#[test]
fn echo_aes_with_fec() {
    echo_roundtrip({
        let mut v = KcpConfig::fast();
        v.crypt = Some(Arc::new(Crypt::new("aes", &[9; 32]).unwrap()));
        v.data_shards = 10;
        v.parity_shards = 3;
        v
    });
}

#[test]
fn echo_xor_gcm_and_stream() {
    echo_roundtrip({
        let mut v = KcpConfig::fast();
        v.crypt = Some(Arc::new(Crypt::new("xor", b"secret").unwrap()));
        v
    });
    echo_roundtrip({
        let mut v = KcpConfig::fast();
        v.crypt = Some(Arc::new(Crypt::new("aes-128-gcm", &[5; 16]).unwrap()));
        v.data_shards = 4;
        v.parity_shards = 2;
        v
    });
}

#[test]
fn stream_mode_carries_bytes() {
    let mut cfg = KcpConfig::fast();
    cfg.stream = true;
    let (e, addr) = engine(cfg.clone());
    let (tx, rx) = mpsc::channel();
    let s = akio_kcp::dial(&e, addr, cfg, Collect(tx, None)).unwrap();
    let mut want = Vec::new();
    for i in 0..100u32 {
        let m = vec![i as u8; 1 + (i as usize * 13) % 3000];
        want.extend_from_slice(&m);
        s.send(&m).unwrap();
    }
    let mut got = Vec::new();
    while got.len() < want.len() {
        got.extend(rx.recv_timeout(Duration::from_secs(10)).expect("bytes"));
    }
    assert_eq!(got, want);
    e.shutdown();
}

#[test]
fn mismatched_crypt_is_dropped_and_dead_link_closes() {
    let (e, addr) = engine({
        let mut v = KcpConfig::fast();
        v.crypt = Some(Arc::new(Crypt::new("aes-128", &[1; 16]).unwrap()));
        v
    });
    let (tx, rx) = mpsc::channel();
    let (ctx, crx) = mpsc::channel();
    let mut cfg = KcpConfig::fast();
    cfg.crypt = Some(Arc::new(Crypt::new("aes-128", &[2; 16]).unwrap()));
    cfg.dead_link = 4;
    let s = akio_kcp::dial(&e, addr, cfg, Collect(tx, Some(ctx))).unwrap();
    s.send(b"hello").unwrap();
    assert!(rx.recv_timeout(Duration::from_millis(500)).is_err());
    assert_eq!(
        crx.recv_timeout(Duration::from_secs(10)).unwrap(),
        CloseReason::DeadLink
    );
    e.shutdown();
}

/// Counts what arrives (messages and bytes) without answering.
struct Count(Arc<std::sync::atomic::AtomicUsize>);
impl KcpHandler for Count {
    fn on_message(&mut self, _s: &Session, msg: Vec<u8>) {
        self.0
            .fetch_add(msg.len(), std::sync::atomic::Ordering::Relaxed);
    }
}

/// Reports `on_writable` calls.
struct Writable(mpsc::Sender<()>);
impl KcpHandler for Writable {
    fn on_message(&mut self, _s: &Session, _msg: Vec<u8>) {}
    fn on_writable(&mut self, _s: &Session) {
        let _ = self.0.send(());
    }
}

#[test]
fn full_queue_then_writable() {
    let got = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let g = got.clone();
    let server = KcpServer::new(KcpConfig::fast(), move |_s: &Session| Count(g.clone())).unwrap();
    let e = Engine::builder()
        .listen(Listener::udp("127.0.0.1:0".parse().unwrap()).serve(server))
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let mut cfg = KcpConfig::fast();
    cfg.write_queue = 16;
    let (tx, rx) = mpsc::channel();
    let s = akio_kcp::dial(&e, addr, cfg, Writable(tx)).unwrap();
    let msg = vec![7u8; 1000];
    let (mut sent, mut fulls, mut wakes) = (0, 0, 0);
    while sent < 2000 {
        match s.send(&msg) {
            Ok(()) => sent += 1,
            Err(akio_kcp::KcpError::Full) => {
                fulls += 1;
                // `send` saw 16 waiting under the session lock; acknowledgements may have
                // drained some since, so the count is not checked here.
                // No polling: the session says when to go on.
                rx.recv_timeout(Duration::from_secs(10))
                    .expect("on_writable after Full");
                wakes += 1;
                assert!(s.wait_send() <= 8, "woken early: {}", s.wait_send());
            }
            Err(e) => panic!("send: {e}"),
        }
    }
    assert!(fulls > 0 && wakes == fulls);
    let end = std::time::Instant::now() + Duration::from_secs(10);
    while got.load(std::sync::atomic::Ordering::Relaxed) < 2000 * 1000 {
        assert!(std::time::Instant::now() < end, "not all delivered");
        std::thread::sleep(Duration::from_millis(5));
    }
    // One wake per refusal: nothing more arrives.
    assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());
    e.shutdown();
}

#[test]
fn sessions_beyond_the_limit_get_none() {
    assert_eq!(akio_kcp::DEFAULT_MAX_SESSIONS, 4096);
    let got = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let g = got.clone();
    let server = KcpServer::new(KcpConfig::fast(), move |_s: &Session| Count(g.clone()))
        .unwrap()
        .max_sessions(2);
    let e = Engine::builder()
        .listen(Listener::udp("127.0.0.1:0".parse().unwrap()).serve(server))
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let dial = || {
        let (tx, _rx) = mpsc::channel();
        akio_kcp::dial(&e, addr, KcpConfig::fast(), Collect(tx, None)).unwrap()
    };
    let wait_got = |n: usize| {
        let end = std::time::Instant::now() + Duration::from_secs(5);
        while got.load(std::sync::atomic::Ordering::Relaxed) < n {
            assert!(std::time::Instant::now() < end, "message not delivered");
            std::thread::sleep(Duration::from_millis(2));
        }
    };
    // Under and at the limit: served.
    let a = dial();
    a.send(b"1").unwrap();
    wait_got(1);
    let b = dial();
    b.send(b"2").unwrap();
    wait_got(2);
    // Over it: dropped.
    let c = dial();
    c.send(b"3").unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(got.load(std::sync::atomic::Ordering::Relaxed), 2);
    assert!(c.wait_send() > 0, "never acknowledged");
    e.shutdown();
}
