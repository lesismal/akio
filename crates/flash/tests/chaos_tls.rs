//! Chaos over TLS: seeded random clients against a TLS echo / ordered-pool server. Clients send
//! garbage, truncated handshakes, records cut in half, abort with RST mid-stream, end with or
//! without `close_notify`, and half-close with responses still being prepared on the pool.
//!
//! Checked per seed: no stalls, every `on_close` exactly once, the server still completes a
//! normal TLS exchange, shutdown finishes, descriptors are released.
//! `FLASH_CHAOS_SEEDS=1..50 cargo test -p flash --test chaos_tls` for more seeds;
//! `FLASH_TEST_BACKEND=uring` for io_uring.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    collections::HashMap,
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    os::fd::AsRawFd,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use flash::{
    Acceptor, Config, Conn, Engine, Error, Handler, Listener,
    tls::{Tls, rustls},
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};

const STALL: Duration = Duration::from_secs(15);

#[derive(Clone)]
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed ^ 0x5DEE_CE66_D1CE_4E5B)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below((hi - lo) as u64) as usize
    }
    fn bytes_in(&mut self, lo: usize, hi: usize) -> Vec<u8> {
        let n = self.range(lo, hi);
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn seeds(default: &[u64]) -> Vec<u64> {
    let Ok(s) = std::env::var("FLASH_CHAOS_SEEDS") else {
        return default.to_vec();
    };
    if let Some((a, b)) = s.split_once("..") {
        let (a, b): (u64, u64) = (a.trim().parse().unwrap(), b.trim().parse().unwrap());
        return (a..b).collect();
    }
    s.split(',').map(|x| x.trim().parse().unwrap()).collect()
}

fn open_fds() -> usize {
    let dir = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    std::fs::read_dir(dir).unwrap().count()
}

fn set_linger0(s: &TcpStream) {
    let l = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: valid fd, and `l` outlives the call with the size passed.
    unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&raw const l).cast(),
            size_of::<libc::linger>() as libc::socklen_t,
        );
    }
}

fn is_stall(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// Reads until EOF or error, retrying EINTR. Returns the bytes and whether it stalled.
fn drain<R: Read>(r: &mut R) -> (Vec<u8>, Option<io::Error>) {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match r.read(&mut buf) {
            Ok(0) => return (out, None),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return (out, Some(e)),
        }
    }
}

// ---- server ---------------------------------------------------------------------------------

#[derive(Default)]
struct Stats {
    opened: AtomicUsize,
    closed: AtomicUsize,
    closes: Mutex<HashMap<u64, u32>>,
    violations: Mutex<Vec<String>>,
    /// Clients run per kind.
    kinds: [AtomicUsize; 7],
}

impl Stats {
    fn violate(&self, s: String) {
        self.violations.lock().unwrap().push(s);
    }
}

/// First plaintext byte: `E` echoes inline, `P` answers each chunk in order from the pool.
struct Srv {
    st: Arc<Stats>,
    mode: u8,
    rng: Rng,
}

impl Handler for Srv {
    fn on_data(&mut self, c: &Conn<Self>, mut data: &[u8]) {
        if self.mode == 0 {
            self.mode = data[0];
            data = &data[1..];
        }
        if data.is_empty() {
            return;
        }
        match self.mode {
            b'E' => {
                let _ = c.send(data);
            }
            b'P' => {
                let Ok(slot) = c.reserve_response() else {
                    return;
                };
                let (d, chunk) = (self.rng.below(3), data.to_vec());
                let r = c.spawn_blocking(
                    move || {
                        thread::sleep(Duration::from_millis(d));
                        slot.fill(chunk);
                    },
                    |_h: &mut Srv, _c, ()| {},
                );
                if let Err(e) = r {
                    self.st.violate(format!("spawn_blocking: {e}"));
                }
            }
            m => {
                self.st.violate(format!("unknown mode {m}"));
                c.close();
            }
        }
    }
    fn on_close(&mut self, c: &Conn<Self>, _err: Option<Error>) {
        let mut m = self.st.closes.lock().unwrap();
        let n = m.entry(c.id()).or_insert(0);
        *n += 1;
        if *n != 1 {
            self.st.violate(format!("on_close #{n} for {}", c.id()));
        }
        drop(m);
        self.st.closed.fetch_add(1, Ordering::SeqCst);
    }
}

struct SrvAcceptor(Arc<Stats>);

impl Acceptor for SrvAcceptor {
    type Handler = Srv;
    fn on_open(&self, c: &Conn<Srv>) -> Srv {
        self.0.opened.fetch_add(1, Ordering::SeqCst);
        Srv {
            st: self.0.clone(),
            mode: 0,
            rng: Rng::new(c.id()),
        }
    }
}

struct Pki {
    server: Arc<ServerConfig>,
    client: Arc<ClientConfig>,
}

fn pki() -> Pki {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert: CertificateDer<'static> = ck.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Pki {
        server: Arc::new(server),
        client: Arc::new(client),
    }
}

// ---- clients --------------------------------------------------------------------------------

fn tls_connect(
    addr: SocketAddr,
    cfg: &Arc<ClientConfig>,
) -> StreamOwned<ClientConnection, TcpStream> {
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(STALL)).unwrap();
    tcp.set_write_timeout(Some(STALL)).unwrap();
    let conn =
        ClientConnection::new(cfg.clone(), ServerName::try_from("localhost").unwrap()).unwrap();
    StreamOwned::new(conn, tcp)
}

/// The first flight of a real handshake (a ClientHello), as raw bytes.
fn client_hello(cfg: &Arc<ClientConfig>) -> Vec<u8> {
    let mut c =
        ClientConnection::new(cfg.clone(), ServerName::try_from("localhost").unwrap()).unwrap();
    let mut out = Vec::new();
    while c.wants_write() {
        c.write_tls(&mut out).unwrap();
    }
    out
}

fn client(addr: SocketAddr, seed: u64, pki: &Pki, st: &Stats) {
    let mut r = Rng::new(seed);
    let kind = r.below(7);
    let tag = format!("seed {seed} kind {kind}");
    st.kinds[kind as usize].fetch_add(1, Ordering::Relaxed);
    match kind {
        // Random bytes that are not a TLS record: the server must hang up promptly.
        0 => {
            let mut s = TcpStream::connect(addr).unwrap();
            s.set_read_timeout(Some(STALL)).unwrap();
            let mut g = r.bytes_in(1, 4096);
            g[0] = b'G'; // never a handshake record type
            let _ = s.write_all(&g);
            let (got, err) = drain(&mut s);
            if err.as_ref().is_some_and(is_stall) {
                st.violate(format!("{tag}: garbage not rejected"));
            }
            if got.len() > 64 {
                st.violate(format!("{tag}: {} bytes in reply to garbage", got.len()));
            }
        }
        // A prefix of a real ClientHello, then FIN or RST.
        1 => {
            let mut s = TcpStream::connect(addr).unwrap();
            let hello = client_hello(&pki.client);
            let cut = r.range(0, hello.len());
            let _ = s.write_all(&hello[..cut]);
            if r.below(2) == 0 {
                set_linger0(&s);
            }
        }
        // Handshake, then a record cut in half, then RST.
        2 => {
            let mut c = tls_connect(addr, &pki.client);
            if c.write_all(b"E").is_err() || c.flush().is_err() {
                return;
            }
            let payload = r.bytes_in(100, 20_000);
            c.conn.writer().write_all(&payload).unwrap();
            let mut rec = Vec::new();
            while c.conn.wants_write() {
                c.conn.write_tls(&mut rec).unwrap();
            }
            let cut = r.range(1, rec.len());
            let _ = c.sock.write_all(&rec[..cut]);
            set_linger0(&c.sock);
        }
        // Echo, then end with close_notify / FIN only / RST.
        3..=5 => {
            let mode = if r.below(2) == 0 { b'E' } else { b'P' };
            let mut c = tls_connect(addr, &pki.client);
            let data = r.bytes_in(0, 256 << 10);
            if c.write_all(&[mode]).is_err() {
                st.violate(format!("{tag}: handshake failed"));
                return;
            }
            let mut got = Vec::with_capacity(data.len());
            let mut sent = 0;
            let mut buf = vec![0u8; 64 << 10];
            while got.len() < data.len() {
                if sent < data.len() {
                    let n = (data.len() - sent).min(r.range(1, 32 << 10));
                    c.write_all(&data[sent..sent + n]).unwrap();
                    sent += n;
                }
                while sent - got.len() >= 64 << 10 || (sent == data.len() && got.len() < data.len())
                {
                    match c.read(&mut buf) {
                        Ok(0) => {
                            st.violate(format!("{tag}: eof after {} bytes", got.len()));
                            return;
                        }
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => {
                            st.violate(format!("{tag}: read after {} bytes: {e}", got.len()));
                            return;
                        }
                    }
                }
            }
            if got != data {
                st.violate(format!("{tag}: echo corrupted"));
            }
            match kind {
                3 => {
                    c.conn.send_close_notify();
                    let _ = c.flush();
                    let _ = c.sock.shutdown(Shutdown::Write);
                    let (rest, err) = drain(&mut c);
                    if !rest.is_empty() || err.as_ref().is_some_and(is_stall) {
                        st.violate(format!("{tag}: no clean end after close_notify: {err:?}"));
                    }
                }
                4 => {
                    let _ = c.sock.shutdown(Shutdown::Write);
                    let (_, err) = drain(&mut c.sock);
                    if err.as_ref().is_some_and(is_stall) {
                        st.violate(format!("{tag}: server kept a half-closed connection"));
                    }
                }
                _ => set_linger0(&c.sock),
            }
        }
        // Half close right after the requests: every (pool-prepared) answer must still arrive,
        // followed by the server's close_notify.
        _ => {
            let mode = if r.below(2) == 0 { b'E' } else { b'P' };
            let mut c = tls_connect(addr, &pki.client);
            let data = r.bytes_in(1, 32 << 10);
            if c.write_all(&[mode]).is_err() || c.write_all(&data).is_err() {
                st.violate(format!("{tag}: write failed"));
                return;
            }
            c.conn.send_close_notify();
            let _ = c.flush();
            let _ = c.sock.shutdown(Shutdown::Write);
            let (got, err) = drain(&mut c);
            if got != data {
                st.violate(format!(
                    "{tag}: mode {} half close: {} of {} bytes ({err:?})",
                    mode as char,
                    got.len(),
                    data.len()
                ));
            }
        }
    }
}

fn run_seed(seed: u64, pki: &Pki, conns: usize) -> Vec<usize> {
    let baseline = open_fds();
    let st = Arc::new(Stats::default());
    let engine = Engine::builder()
        .config(Config {
            shutdown_timeout: Duration::from_millis(500),
            slow_callback_threshold: None,
            ..Config::default()
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(common::backend())
                .threads(2)
                .serve(Tls::server(pki.server.clone(), SrvAcceptor(st.clone()))),
        )
        .build()
        .unwrap();
    engine.start().unwrap();
    let addr = engine.local_addrs()[0];
    let next = AtomicUsize::new(0);
    thread::scope(|s| {
        for _ in 0..8 {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= conns {
                        break;
                    }
                    client(addr, seed * 10_007 + i as u64, pki, &st);
                }
            });
        }
    });
    let t = Instant::now();
    while st.closed.load(Ordering::SeqCst) != st.opened.load(Ordering::SeqCst) {
        assert!(
            t.elapsed() < Duration::from_secs(30),
            "seed {seed}: {} opened, {} closed",
            st.opened.load(Ordering::SeqCst),
            st.closed.load(Ordering::SeqCst)
        );
        thread::sleep(Duration::from_millis(5));
    }
    // Still serving.
    let mut c = tls_connect(addr, &pki.client);
    c.write_all(b"Eping").unwrap();
    let mut b = [0u8; 4];
    c.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"ping");
    drop(c);
    engine.shutdown();
    engine.wait();
    let v = st.violations.lock().unwrap().clone();
    assert!(v.is_empty(), "seed {seed}:\n{}", v.join("\n"));
    let (o, c) = (
        st.opened.load(Ordering::SeqCst),
        st.closed.load(Ordering::SeqCst),
    );
    assert_eq!(o, c, "seed {seed}: on_close count");
    assert!(st.closes.lock().unwrap().values().all(|&n| n == 1));
    drop(engine);
    let t = Instant::now();
    while open_fds() > baseline {
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "seed {seed}: fd leak"
        );
        thread::sleep(Duration::from_millis(5));
    }
    st.kinds.iter().map(|k| k.load(Ordering::Relaxed)).collect()
}

#[test]
fn chaos_tls() {
    let pki = pki();
    for seed in seeds(&[1, 2]) {
        let t = Instant::now();
        let kinds = run_seed(seed, &pki, 120);
        eprintln!(
            "chaos tls seed {seed}: ok in {:?}, clients per kind {kinds:?}",
            t.elapsed()
        );
    }
}
