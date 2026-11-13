//! tokio reference server: `tokio-ref <tcp|tls|udp> <addr> <threads> [echo|block-inline|block-pool [ms]]`
//! (same handlers as flash's `bench-server`).

use std::{sync::Arc, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

#[derive(Clone, Copy)]
enum Mode {
    Echo,
    BlockInline(Duration),
    BlockPool(Duration),
}

async fn handle<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, mode: Mode) {
    let mut b = vec![0u8; 65536];
    loop {
        let n = match s.read(&mut b).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        let reply = match mode {
            Mode::Echo => b[..n].to_vec(),
            Mode::BlockInline(d) => {
                std::thread::sleep(d); // blocks the runtime worker, on purpose
                b[..n].to_vec()
            }
            Mode::BlockPool(d) => {
                let req = b[..n].to_vec();
                tokio::task::spawn_blocking(move || {
                    std::thread::sleep(d);
                    req
                })
                .await
                .unwrap()
            }
        };
        if s.write_all(&reply).await.is_err() {
            return;
        }
    }
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (proto, addr, threads) = (a[0].clone(), a[1].clone(), a[2].parse().unwrap());
    let ms: u64 = a.get(4).and_then(|s| s.parse().ok()).unwrap_or(5);
    let d = Duration::from_millis(ms);
    let mode = match a.get(3).map(String::as_str).unwrap_or("echo") {
        "block-inline" => Mode::BlockInline(d),
        "block-pool" => Mode::BlockPool(d),
        _ => Mode::Echo,
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .max_blocking_threads(4096)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        if proto == "udp" {
            let s = Arc::new(UdpSocket::bind(&addr).await.unwrap());
            // One task per socket, like a plain recv_from loop; replies on the same socket.
            let mut b = vec![0u8; 65536];
            loop {
                let (n, from) = s.recv_from(&mut b).await.unwrap();
                let _ = s.send_to(&b[..n], from).await;
            }
        }
        let l = TcpListener::bind(&addr).await.unwrap();
        let acceptor = (proto == "tls").then(|| {
            let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
            let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()),
            );
            let cfg = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![ck.cert.der().clone()], key)
                .unwrap();
            tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
        });
        loop {
            let (s, _) = l.accept().await.unwrap();
            s.set_nodelay(true).ok();
            match acceptor.clone() {
                Some(acc) => {
                    tokio::spawn(async move {
                        if let Ok(t) = acc.accept(s).await {
                            handle(t, mode).await;
                        }
                    });
                }
                None => {
                    tokio::spawn(handle(s, mode));
                }
            }
        }
    });
}
