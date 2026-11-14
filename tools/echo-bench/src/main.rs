//! Closed-loop echo load generator, so the same tool drives flash, fib, tokio...
//!
//! usage: `echo-bench <addr> [conns=64] [msg_bytes=64] [seconds=10] [threads=4] [mode=tcp]`
//!
//! `mode` is `tcp`, `udp`, or `tls` (build with `--features tls`; the server certificate is not
//! verified). Connections are spread over a few client threads; each thread sends one message on
//! every connection it owns, then reads all the replies, so the load stays closed-loop per
//! connection without a thread per connection (which would saturate the client first).
//! A server may answer after any delay: the reply only has to be `msg_bytes` long.

use std::{
    io::{self, Read, Write},
    net::{TcpStream, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

enum Sock {
    Tcp(TcpStream),
    #[cfg(feature = "tls")]
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
    Udp(UdpSocket),
}

impl Sock {
    fn send(&mut self, msg: &[u8]) -> io::Result<()> {
        match self {
            Sock::Tcp(s) => s.write_all(msg),
            #[cfg(feature = "tls")]
            Sock::Tls(s) => s.write_all(msg),
            Sock::Udp(s) => s.send(msg).map(drop),
        }
    }

    /// Reads one reply. `Ok(false)`: a UDP datagram was lost (timeout).
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<bool> {
        match self {
            Sock::Tcp(s) => s.read_exact(buf).map(|()| true),
            #[cfg(feature = "tls")]
            Sock::Tls(s) => s.read_exact(buf).map(|()| true),
            Sock::Udp(s) => match s.recv(buf) {
                Ok(_) => Ok(true),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    Ok(false)
                }
                Err(e) => Err(e),
            },
        }
    }
}

#[cfg(feature = "tls")]
mod tls {
    use std::sync::Arc;

    use rustls::{
        DigitallySignedStruct, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
    };

    #[derive(Debug)]
    struct NoVerify(Vec<SignatureScheme>);

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.clone()
        }
    }

    pub(crate) fn config() -> Arc<rustls::ClientConfig> {
        let provider = rustls::crypto::ring::default_provider();
        let schemes = provider
            .signature_verification_algorithms
            .supported_schemes();
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(schemes)))
            .with_no_client_auth();
        Arc::new(cfg)
    }
}

fn connect(addr: &str, mode: &str) -> Sock {
    match mode {
        "udp" => {
            let s = UdpSocket::bind(if addr.starts_with('[') {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            })
            .expect("bind");
            s.connect(addr).expect("connect");
            s.set_read_timeout(Some(Duration::from_millis(200))).ok();
            Sock::Udp(s)
        }
        #[cfg(feature = "tls")]
        "tls" => {
            let tcp = TcpStream::connect(addr).expect("connect");
            tcp.set_nodelay(true).ok();
            let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
            let conn = rustls::ClientConnection::new(tls::config(), name).expect("tls");
            let mut s = rustls::StreamOwned::new(conn, tcp);
            // Finish the handshake now so it is not part of the measurement.
            while s.conn.is_handshaking() {
                s.conn.complete_io(&mut s.sock).expect("handshake");
            }
            Sock::Tls(Box::new(s))
        }
        "tcp" => {
            let s = TcpStream::connect(addr).expect("connect");
            s.set_nodelay(true).ok();
            Sock::Tcp(s)
        }
        other => {
            eprintln!(
                "unknown mode {other} (tcp, udp{})",
                if cfg!(feature = "tls") {
                    ", tls"
                } else {
                    "; build with --features tls for tls"
                }
            );
            std::process::exit(2)
        }
    }
}

fn main() {
    let mut a = std::env::args().skip(1);
    let addr = a.next().unwrap_or_else(|| {
        eprintln!(
            "usage: echo-bench <addr> [conns=64] [msg_bytes=64] [seconds=10] [threads=4] [mode=tcp|udp|tls]"
        );
        std::process::exit(2)
    });
    let conns: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(64);
    let size: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(64);
    let secs: u64 = a.next().and_then(|s| s.parse().ok()).unwrap_or(10);
    let threads: usize = a
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4)
        .clamp(1, conns.max(1));
    let mode = a.next().unwrap_or_else(|| "tcp".into());

    let stop = Arc::new(AtomicBool::new(false));
    let total = Arc::new(AtomicU64::new(0));
    let lost = Arc::new(AtomicU64::new(0));
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let mine = conns / threads + usize::from(t < conns % threads);
            let (addr, mode) = (addr.clone(), mode.clone());
            let (stop, total, lost) = (stop.clone(), total.clone(), lost.clone());
            thread::spawn(move || {
                let mut socks: Vec<Sock> = (0..mine).map(|_| connect(&addr, &mode)).collect();
                let msg = vec![0xA5u8; size];
                let mut buf = vec![0u8; size.max(1)];
                let (mut n, mut l) = (0u64, 0u64);
                'run: while !stop.load(Ordering::Relaxed) {
                    for s in &mut socks {
                        if s.send(&msg).is_err() {
                            break 'run;
                        }
                    }
                    for s in &mut socks {
                        match s.recv(&mut buf) {
                            Ok(true) => n += 1,
                            Ok(false) => l += 1,
                            Err(_) => break 'run,
                        }
                    }
                }
                total.fetch_add(n, Ordering::Relaxed);
                lost.fetch_add(l, Ordering::Relaxed);
            })
        })
        .collect();

    let start = Instant::now();
    thread::sleep(Duration::from_secs(secs));
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }
    let el = start.elapsed().as_secs_f64();
    let n = total.load(Ordering::Relaxed) as f64;
    let loss = lost.load(Ordering::Relaxed);
    println!(
        "mode={mode} conns={conns} threads={threads} size={size}B  {:.0} req/s  {:.1} MiB/s (each way){}",
        n / el,
        n * size as f64 / el / 1048576.0,
        if mode == "udp" {
            format!("  lost={loss}")
        } else {
            String::new()
        }
    );
}
