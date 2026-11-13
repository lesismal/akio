//! KCP interop peer for tools/interop/kcp (kcp-go):
//!
//! ```text
//! kcp-interop server 127.0.0.1:9201 aes 10 3   echoes every message
//! kcp-interop client 127.0.0.1:9200 aes 10 3   sends 2 MiB, checks the echo
//! ```

use std::sync::{Arc, mpsc};
use std::time::Duration;

use flash::{Engine, Listener};
use flash_kcp::{Config, Crypt, KcpError, KcpHandler, KcpServer, Session};

fn crypt(name: &str) -> Option<Arc<Crypt>> {
    let key = match name {
        "plain" => return None,
        "none" => vec![],
        "xor" => b"flash-xor-key".to_vec(),
        "aes" => vec![0x42; 32],
        _ => vec![0x42; 16],
    };
    Some(Arc::new(Crypt::new(name, &key).expect("crypt")))
}

struct Echo;
impl KcpHandler for Echo {
    fn on_message(&mut self, s: &Session, msg: Vec<u8>) {
        // on_message runs on the I/O thread that reads the ACKs: never wait here for the queue
        // to drain. The echo is bounded by the client's window, so the queue is made large.
        let _ = s.send(&msg);
    }
}

struct Collect(mpsc::Sender<Vec<u8>>);
impl KcpHandler for Collect {
    fn on_message(&mut self, _s: &Session, msg: Vec<u8>) {
        let _ = self.0.send(msg);
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let addr = a[2].parse().expect("addr");
    let cfg = Config {
        crypt: crypt(&a[3]),
        data_shards: a[4].parse().expect("data shards"),
        parity_shards: a[5].parse().expect("parity shards"),
        send_window: 256,
        recv_window: 256,
        ..Config::fast()
    };
    if a[1] == "server" {
        let cfg = Config {
            write_queue: 1 << 20,
            ..cfg
        };
        let server = KcpServer::new(cfg, |_s: &Session| Echo).expect("config");
        let e = Engine::builder()
            .listen(Listener::udp(addr).serve(server))
            .build()
            .expect("engine");
        e.start().expect("start");
        println!("ready");
        e.wait();
        return;
    }
    let e = Engine::builder()
        .udp_client_threads(1)
        .build()
        .expect("engine");
    e.start().expect("start");
    let (tx, rx) = mpsc::channel();
    let s = flash_kcp::dial(&e, addr, cfg, Collect(tx)).expect("dial");
    let want: Vec<u8> = (0..2usize << 20)
        .map(|i| (i * 7 + (i >> 11)) as u8)
        .collect();
    let w = want.clone();
    let sender = s.clone();
    std::thread::spawn(move || {
        let mut off = 0;
        while off < w.len() {
            let n = (1 + (off * 31) % 6000).min(w.len() - off);
            match sender.send(&w[off..off + n]) {
                Ok(()) => off += n,
                Err(KcpError::Full) => std::thread::sleep(Duration::from_millis(1)),
                Err(e) => panic!("send: {e}"),
            }
        }
    });
    let mut got = Vec::with_capacity(want.len());
    while got.len() < want.len() {
        match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(m) => got.extend_from_slice(&m),
            Err(_) => {
                println!(
                    "FAIL: timed out at {} bytes, stats {:?}",
                    got.len(),
                    s.stats()
                );
                std::process::exit(1);
            }
        }
    }
    if got != want {
        println!("FAIL: echo differs");
        std::process::exit(1);
    }
    println!("ok: 2 MiB echoed, stats {:?}", s.stats());
}
