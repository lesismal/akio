#![forbid(unsafe_code)]
//! Closed-loop echo load generator, so the same tool drives `only`, fib, tokio...
//!
//! usage: `echo-bench <addr> [conns=64] [msg_bytes=64] [seconds=10] [threads=4] [mode=tcp]`
//!
//! `mode` is `tcp`, `udp`, `ws` (WebSocket binary messages after an upgrade on `/ws`), `tls`, or
//! `tlshs` (build with `--features tls`; the server certificate is not verified). `tlshs`
//! measures full TLS handshakes per second instead: each of `conns` workers connects, completes a
//! handshake (no resumption), and closes, in a loop. Connections are spread over a few client threads; each thread sends one message on
//! every connection it owns, then reads all the replies, so the load stays closed-loop per
//! connection without a thread per connection (which would saturate the client first).
//! A server may answer after any delay: the reply only has to be `msg_bytes` long.
//!
//! Memory runs: mode `hold-<kind>` opens `conns` connections, spread over the comma-separated
//! `addr` list (several loopback addresses give more than 64k connections from one client),
//! takes each through `kind` once, prints `ready <n>` and keeps them all open, idle, for
//! `seconds`. Kinds: `tcp` (connect only), `echo` (one `msg_bytes` echo), `http` (one
//! keep-alive `GET /plaintext`), `ws` (upgrade on `/ws` + one echo), `tls` (handshake + one
//! echo; needs `--features tls`).

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
    /// WebSocket: the masked request frame is prepared once; the reply header length is known.
    Ws {
        s: TcpStream,
        frame: Vec<u8>,
        hdr: usize,
    },
}

impl Sock {
    fn send(&mut self, msg: &[u8]) -> io::Result<()> {
        match self {
            Sock::Tcp(s) => s.write_all(msg),
            #[cfg(feature = "tls")]
            Sock::Tls(s) => s.write_all(msg),
            Sock::Udp(s) => s.send(msg).map(drop),
            Sock::Ws { s, frame, .. } => s.write_all(frame),
        }
    }

    /// Reads one reply. `Ok(false)`: a UDP datagram was lost (timeout).
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<bool> {
        match self {
            Sock::Tcp(s) => s.read_exact(buf).map(|()| true),
            #[cfg(feature = "tls")]
            Sock::Tls(s) => s.read_exact(buf).map(|()| true),
            Sock::Ws { s, hdr, .. } => {
                let mut h = [0u8; 10];
                s.read_exact(&mut h[..*hdr])?;
                s.read_exact(buf).map(|()| true)
            }
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

    /// Like [`config`], without session resumption (every handshake is a full one).
    pub(crate) fn config_no_resume() -> Arc<rustls::ClientConfig> {
        let mut c = (*config()).clone();
        c.resumption = rustls::client::Resumption::disabled();
        Arc::new(c)
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

/// A WebSocket frame header for a payload of `n` bytes (`mask`: client-to-server).
fn ws_header(n: usize, mask: bool) -> Vec<u8> {
    let m = if mask { 0x80 } else { 0 };
    let mut h = vec![0x82];
    if n < 126 {
        h.push(m | n as u8);
    } else if n < 65536 {
        h.push(m | 126);
        h.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        h.push(m | 127);
        h.extend_from_slice(&(n as u64).to_be_bytes());
    }
    h
}

/// Opens a WebSocket on `/ws` and prepares the masked frame carrying `size` bytes.
fn ws_connect(addr: &str, size: usize) -> Sock {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_nodelay(true).ok();
    let req = format!(
        "GET /ws HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    s.write_all(req.as_bytes()).expect("upgrade request");
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut b).expect("upgrade response");
        head.push(b[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 101"), "upgrade refused");
    let key = [0x12u8, 0x34, 0x56, 0x78];
    let mut frame = ws_header(size, true);
    frame.extend_from_slice(&key);
    frame.extend((0..size).map(|i| 0xA5 ^ key[i % 4]));
    Sock::Ws {
        s,
        frame,
        hdr: ws_header(size, false).len(),
    }
}

/// One full TLS handshake: connect, handshake, close.
#[cfg(feature = "tls")]
fn tls_handshake(addr: &str, cfg: &Arc<rustls::ClientConfig>) -> io::Result<()> {
    let mut tcp = TcpStream::connect(addr)?;
    tcp.set_nodelay(true).ok();
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
    let mut conn = rustls::ClientConnection::new(cfg.clone(), name).map_err(io::Error::other)?;
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp)?;
    }
    // Flush the client Finished so the server completes too.
    while conn.wants_write() {
        conn.write_tls(&mut tcp)?;
    }
    Ok(())
}

fn connect(addr: &str, mode: &str, size: usize) -> Sock {
    match mode {
        "ws" => ws_connect(addr, size),
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
                "unknown mode {other} (tcp, udp, ws{})",
                if cfg!(feature = "tls") {
                    ", tls, tlshs"
                } else {
                    "; build with --features tls for tls, tlshs"
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

    if let Some(kind) = mode.strip_prefix("hold-") {
        return hold(&addr, conns, size, secs, threads, kind);
    }
    #[cfg(feature = "tls")]
    if mode == "tlshs" {
        return handshakes(&addr, conns, secs);
    }
    let stop = Arc::new(AtomicBool::new(false));
    let total = Arc::new(AtomicU64::new(0));
    let lost = Arc::new(AtomicU64::new(0));
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let mine = conns / threads + usize::from(t < conns % threads);
            let (addr, mode) = (addr.clone(), mode.clone());
            let (stop, total, lost) = (stop.clone(), total.clone(), lost.clone());
            thread::spawn(move || {
                let mut socks: Vec<Sock> = (0..mine).map(|_| connect(&addr, &mode, size)).collect();
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

/// `tlshs` mode: `workers` threads each doing full handshakes back to back for `secs`.
#[cfg(feature = "tls")]
fn handshakes(addr: &str, workers: usize, secs: u64) {
    let cfg = tls::config_no_resume();
    let stop = Arc::new(AtomicBool::new(false));
    let (total, failed) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let handles: Vec<_> = (0..workers)
        .map(|_| {
            let (addr, cfg) = (addr.to_string(), cfg.clone());
            let (stop, total, failed) = (stop.clone(), total.clone(), failed.clone());
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match tls_handshake(&addr, &cfg) {
                        Ok(()) => total.fetch_add(1, Ordering::Relaxed),
                        Err(_) => failed.fetch_add(1, Ordering::Relaxed),
                    };
                }
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
    println!(
        "mode=tlshs workers={workers}  {:.0} handshakes/s  failed={}",
        total.load(Ordering::Relaxed) as f64 / el,
        failed.load(Ordering::Relaxed)
    );
}

/// Reads until `buf` ends with `tail` (the end of one known response).
fn read_until(s: &mut impl Read, tail: &[u8]) -> io::Result<()> {
    let mut got = Vec::new();
    let mut b = [0u8; 4096];
    while !got.ends_with(tail) {
        let n = s.read(&mut b)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        got.extend_from_slice(&b[..n]);
    }
    Ok(())
}

/// Opens one held connection to `addr` and takes it through `kind` once.
fn hold_one(addr: &str, size: usize, kind: &str) -> io::Result<Box<dyn Send>> {
    let msg = vec![0xA5u8; size];
    let mut buf = vec![0u8; size];
    Ok(match kind {
        "tcp" => Box::new(TcpStream::connect(addr)?),
        "echo" => {
            let mut s = TcpStream::connect(addr)?;
            s.write_all(&msg)?;
            s.read_exact(&mut buf)?;
            Box::new(s)
        }
        "http" => {
            let mut s = TcpStream::connect(addr)?;
            s.write_all(b"GET /plaintext HTTP/1.1\r\nHost: bench\r\n\r\n")?;
            read_until(&mut s, b"Hello, World!")?;
            Box::new(s)
        }
        "ws" => {
            let mut s = ws_connect(addr, size);
            s.send(&msg)?;
            s.recv(&mut buf)?;
            Box::new(s)
        }
        #[cfg(feature = "tls")]
        "tls" => {
            let mut s = connect(addr, "tls", size);
            s.send(&msg)?;
            s.recv(&mut buf)?;
            Box::new(s)
        }
        other => {
            eprintln!("unknown hold kind {other}");
            std::process::exit(2)
        }
    })
}

/// `hold-<kind>` mode, see the crate docs.
fn hold(addrs: &str, conns: usize, size: usize, secs: u64, threads: usize, kind: &str) {
    let addrs: Vec<String> = addrs.split(',').map(str::to_string).collect();
    let failed = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let mine = conns / threads + usize::from(t < conns % threads);
            let (addrs, kind, failed) = (addrs.clone(), kind.to_string(), failed.clone());
            thread::spawn(move || {
                let mut held = Vec::with_capacity(mine);
                for i in 0..mine {
                    let a = &addrs[(i * threads + t) % addrs.len()];
                    match hold_one(a, size, &kind) {
                        Ok(s) => held.push(s),
                        Err(_) => {
                            failed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                held
            })
        })
        .collect();
    let held: Vec<_> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    println!(
        "ready {} failed={} in {:.1}s",
        held.len(),
        failed.load(Ordering::Relaxed),
        start.elapsed().as_secs_f64()
    );
    thread::sleep(Duration::from_secs(secs));
    drop(held);
}
