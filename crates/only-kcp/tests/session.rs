//! KCP sessions end to end over loopback.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use only::{Engine, Listener};
use only_kcp::{CloseReason, Crypt, KcpConfig, KcpHandler, KcpServer, Session};

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
    let s = only_kcp::dial(&e, addr, cfg, Collect(tx, Some(ctx))).unwrap();
    let msgs: Vec<Vec<u8>> = (0..200)
        .map(|i| vec![(i % 251) as u8; 1 + i * 97 % 20_000])
        .collect();
    for m in &msgs {
        loop {
            match s.send(m) {
                Ok(()) => break,
                Err(only_kcp::KcpError::Full) => std::thread::sleep(Duration::from_millis(2)),
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
    let s = only_kcp::dial(&e, addr, cfg, Collect(tx, None)).unwrap();
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
    let s = only_kcp::dial(&e, addr, cfg, Collect(tx, Some(ctx))).unwrap();
    s.send(b"hello").unwrap();
    assert!(rx.recv_timeout(Duration::from_millis(500)).is_err());
    assert_eq!(
        crx.recv_timeout(Duration::from_secs(10)).unwrap(),
        CloseReason::DeadLink
    );
    e.shutdown();
}
