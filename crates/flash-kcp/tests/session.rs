//! KCP sessions end to end over loopback.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use flash::{Engine, Listener};
use flash_kcp::{CloseReason, Config, Crypt, KcpHandler, KcpServer, Session};

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

fn engine(cfg: Config) -> (Arc<Engine>, SocketAddr) {
    // Echo never waits on the I/O thread, so its queue must hold whatever the client has in flight.
    let cfg = Config {
        write_queue: 1 << 20,
        ..cfg
    };
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

fn echo_roundtrip(cfg: Config) {
    let (e, addr) = engine(cfg.clone());
    let (tx, rx) = mpsc::channel();
    let (ctx, crx) = mpsc::channel();
    let s = flash_kcp::dial(&e, addr, cfg, Collect(tx, Some(ctx))).unwrap();
    let msgs: Vec<Vec<u8>> = (0..200)
        .map(|i| vec![(i % 251) as u8; 1 + i * 97 % 20_000])
        .collect();
    for m in &msgs {
        loop {
            match s.send(m) {
                Ok(()) => break,
                Err(flash_kcp::KcpError::Full) => std::thread::sleep(Duration::from_millis(2)),
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
    echo_roundtrip(Config::fast());
}

#[test]
fn echo_normal_mode() {
    echo_roundtrip(Config::default());
}

#[test]
fn echo_aes_with_fec() {
    echo_roundtrip(Config {
        crypt: Some(Arc::new(Crypt::new("aes", &[9; 32]).unwrap())),
        data_shards: 10,
        parity_shards: 3,
        ..Config::fast()
    });
}

#[test]
fn echo_xor_gcm_and_stream() {
    echo_roundtrip(Config {
        crypt: Some(Arc::new(Crypt::new("xor", b"secret").unwrap())),
        ..Config::fast()
    });
    echo_roundtrip(Config {
        crypt: Some(Arc::new(Crypt::new("aes-128-gcm", &[5; 16]).unwrap())),
        data_shards: 4,
        parity_shards: 2,
        ..Config::fast()
    });
}

#[test]
fn stream_mode_carries_bytes() {
    let cfg = Config {
        stream: true,
        ..Config::fast()
    };
    let (e, addr) = engine(cfg.clone());
    let (tx, rx) = mpsc::channel();
    let s = flash_kcp::dial(&e, addr, cfg, Collect(tx, None)).unwrap();
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
    let (e, addr) = engine(Config {
        crypt: Some(Arc::new(Crypt::new("aes-128", &[1; 16]).unwrap())),
        ..Config::fast()
    });
    let (tx, rx) = mpsc::channel();
    let (ctx, crx) = mpsc::channel();
    let cfg = Config {
        crypt: Some(Arc::new(Crypt::new("aes-128", &[2; 16]).unwrap())),
        dead_link: 4,
        ..Config::fast()
    };
    let s = flash_kcp::dial(&e, addr, cfg, Collect(tx, Some(ctx))).unwrap();
    s.send(b"hello").unwrap();
    assert!(rx.recv_timeout(Duration::from_millis(500)).is_err());
    assert_eq!(
        crx.recv_timeout(Duration::from_secs(10)).unwrap(),
        CloseReason::DeadLink
    );
    e.shutdown();
}
