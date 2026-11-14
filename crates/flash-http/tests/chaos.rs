//! Chaos for the HTTP/1 and WebSocket layers: seeded random clients pipeline requests answered
//! inline and from other threads (detached), split them at random byte boundaries, half-close
//! right after the last request, send partial heads, garbage, oversized heads and cut bodies,
//! reset mid-request, and upgrade to WebSocket then echo, send garbage frames or vanish.
//!
//! Checked per seed: pipelined responses arrive complete and in order (also after a half close),
//! bad input is answered or dropped (never a stall), every WebSocket `on_open` gets exactly one
//! `on_close`, the server still serves, shutdown finishes and descriptors are released.
//! `FLASH_CHAOS_SEEDS=1..50 cargo test -p flash-http --test chaos`; `FLASH_TEST_BACKEND=uring`.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
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

use flash::{Backend, Config, Engine, Listener, UringConfig};
use flash_http::{
    Context, HttpConfig, Response, Router, WsOptions, serve_with,
    ws::{Message, WsHandler, WsSender},
};

const STALL: Duration = Duration::from_secs(15);
const MAX_HEADER: usize = 8 << 10;

fn backend() -> Backend {
    match std::env::var("FLASH_TEST_BACKEND").as_deref() {
        Ok("uring") => Backend::IoUring({
            let mut v = UringConfig::default();
            v.strict = true;
            v
        }),
        _ => Backend::Epoll,
    }
}

#[derive(Clone)]
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed ^ 0x2545_F491_4F6C_DD1D)
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
    let l = libc_linger();
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

fn libc_linger() -> libc::linger {
    libc::linger {
        l_onoff: 1,
        l_linger: 0,
    }
}

fn is_stall(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

// ---- server ---------------------------------------------------------------------------------

#[derive(Default)]
struct Stats {
    ws_opened: AtomicUsize,
    ws_closed: AtomicUsize,
    violations: Mutex<Vec<String>>,
}

impl Stats {
    fn violate(&self, s: String) {
        self.violations.lock().unwrap().push(s);
    }
}

struct WsEcho {
    st: Arc<Stats>,
    closed: bool,
}

impl WsHandler for WsEcho {
    fn on_open(&mut self, _ws: &WsSender) {
        self.st.ws_opened.fetch_add(1, Ordering::SeqCst);
    }
    fn on_message(&mut self, ws: &WsSender, msg: Message) {
        let _ = match msg {
            Message::Text(t) => ws.send_text(&t),
            Message::Binary(b) => ws.send_binary(&b),
        };
    }
    fn on_close(&mut self, _code: Option<u16>, _reason: &str) {
        if self.closed {
            self.st.violate("websocket on_close twice".into());
        }
        self.closed = true;
        self.st.ws_closed.fetch_add(1, Ordering::SeqCst);
    }
}

fn app(st: Arc<Stats>) -> Router {
    Router::new()
        .get("/s/:id", |ctx: &mut Context| {
            let id = ctx.param("id").unwrap_or("").to_owned();
            ctx.text(200, id);
        })
        // Answered later from another thread, after a random delay.
        .get("/d/:id", |ctx: &mut Context| {
            let id = ctx.param("id").unwrap_or("").to_owned();
            let delay = id.bytes().map(u64::from).sum::<u64>() % 4;
            if let Some(d) = ctx.detach() {
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(delay));
                    d.respond(Response::text(200, id));
                });
            }
        })
        .post("/echo", |ctx: &mut Context| {
            let b = ctx.body().to_vec();
            ctx.bytes(200, "application/octet-stream", b);
        })
        .get("/ws", move |ctx: &mut Context| {
            let h = WsEcho {
                st: st.clone(),
                closed: false,
            };
            ctx.upgrade_websocket(h, &WsOptions::default());
        })
}

// ---- client helpers -------------------------------------------------------------------------

/// A buffered reader of HTTP responses / WebSocket frames over one stream.
struct Rd {
    s: TcpStream,
    buf: Vec<u8>,
}

impl Rd {
    fn fill(&mut self) -> io::Result<()> {
        let mut b = [0u8; 16 << 10];
        loop {
            match self.s.read(&mut b) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => {
                    self.buf.extend_from_slice(&b[..n]);
                    return Ok(());
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    fn take(&mut self, n: usize) -> io::Result<Vec<u8>> {
        while self.buf.len() < n {
            self.fill()?;
        }
        Ok(self.buf.drain(..n).collect())
    }

    /// One Content-Length framed response: (status, body).
    fn response(&mut self) -> io::Result<(u16, Vec<u8>)> {
        let end = loop {
            if let Some(i) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            self.fill()?;
        };
        let head = String::from_utf8_lossy(&self.buf[..end]).to_ascii_lowercase();
        self.buf.drain(..end);
        let status = head
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let len = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .map_or(0, |v| v.trim().parse().unwrap_or(0));
        Ok((status, self.take(len)?))
    }

    /// Reads to EOF; `Err` only for a stall.
    fn drain_to_eof(&mut self) -> Result<(), io::Error> {
        loop {
            match self.fill() {
                Ok(()) => self.buf.clear(),
                Err(e) if is_stall(&e) => return Err(e),
                Err(_) => return Ok(()),
            }
        }
    }

    /// One server (unmasked) WebSocket frame: (opcode, payload).
    fn frame(&mut self) -> io::Result<(u8, Vec<u8>)> {
        let h = self.take(2)?;
        let len = match h[1] & 0x7f {
            126 => u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as usize,
            127 => u64::from_be_bytes(self.take(8)?.try_into().unwrap()) as usize,
            n => n as usize,
        };
        Ok((h[0] & 0x0f, self.take(len)?))
    }
}

fn connect(addr: SocketAddr) -> Rd {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(STALL)).unwrap();
    s.set_write_timeout(Some(STALL)).unwrap();
    s.set_nodelay(true).unwrap();
    Rd { s, buf: Vec::new() }
}

/// Writes `data` split at random points with occasional tiny pauses.
fn write_split(s: &mut TcpStream, data: &[u8], r: &mut Rng) -> io::Result<()> {
    let mut off = 0;
    while off < data.len() {
        let n = r.range(1, 2048).min(data.len() - off);
        s.write_all(&data[off..off + n])?;
        off += n;
        if r.below(20) == 0 {
            thread::sleep(Duration::from_millis(1));
        }
    }
    Ok(())
}

fn ws_frame(opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let mut f = vec![0x80 | opcode];
    match payload.len() {
        n if n < 126 => f.push(0x80 | n as u8),
        n if n < 65_536 => {
            f.push(0x80 | 126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            f.push(0x80 | 127);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    f.extend_from_slice(&mask);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    f
}

// ---- clients --------------------------------------------------------------------------------

fn client(addr: SocketAddr, seed: u64, st: &Stats) {
    let mut r = Rng::new(seed);
    let kind = r.below(8);
    let tag = format!("seed {seed} kind {kind}");
    let mut c = connect(addr);
    match kind {
        // Pipelined batch (inline, detached and POST echo), then close, half-close or reset.
        0..=2 => {
            let n = r.range(1, 24);
            let mut req = Vec::new();
            let mut want = Vec::new();
            for i in 0..n {
                let id = format!("{seed}-{i}");
                match r.below(3) {
                    0 => req.extend_from_slice(
                        format!("GET /s/{id} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes(),
                    ),
                    1 => req.extend_from_slice(
                        format!("GET /d/{id} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes(),
                    ),
                    _ => {
                        req.extend_from_slice(
                            format!(
                                "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
                                id.len()
                            )
                            .as_bytes(),
                        );
                        req.extend_from_slice(id.as_bytes());
                    }
                }
                want.push(id);
            }
            let half = kind == 1;
            let mut w = c.s.try_clone().unwrap();
            let wseed = r.next();
            let writer = thread::spawn(move || {
                let mut r = Rng::new(wseed);
                let ok = write_split(&mut w, &req, &mut r).is_ok();
                if half {
                    let _ = w.shutdown(Shutdown::Write);
                }
                ok
            });
            for (i, id) in want.iter().enumerate() {
                match c.response() {
                    Ok((200, body)) if body == id.as_bytes() => {}
                    Ok((s, body)) => {
                        st.violate(format!(
                            "{tag}: response {i}: status {s}, body {:?}, want {id}",
                            String::from_utf8_lossy(&body)
                        ));
                        break;
                    }
                    Err(e) => {
                        st.violate(format!("{tag}: response {i} of {n} missing: {e}"));
                        break;
                    }
                }
            }
            let _ = writer.join();
            if half {
                if let Err(e) = c.drain_to_eof() {
                    st.violate(format!("{tag}: no EOF after half close: {e}"));
                }
            } else if kind == 2 {
                set_linger0(&c.s);
            }
        }
        // A prefix of a request head, sent slowly, then FIN or RST.
        3 => {
            let req = b"GET /s/partial HTTP/1.1\r\nHost: x\r\nX-Pad: aaaaaaaaaaaa\r\n\r\n";
            let cut = r.range(1, req.len() - 1);
            for b in &req[..cut] {
                if c.s.write_all(&[*b]).is_err() {
                    break;
                }
                if r.below(4) == 0 {
                    thread::sleep(Duration::from_millis(1));
                }
            }
            if r.below(2) == 0 {
                set_linger0(&c.s);
            }
        }
        // Garbage that ends a head: answered with an error and closed.
        4 => {
            let mut g: Vec<u8> = r
                .bytes_in(1, 512)
                .into_iter()
                .map(|b| b'!' + b % 90)
                .collect();
            g.extend_from_slice(b"\r\n\r\n");
            let _ = c.s.write_all(&g);
            if let Err(e) = c.drain_to_eof() {
                st.violate(format!("{tag}: garbage request not closed: {e}"));
            }
        }
        // An oversized head: 431 and close.
        5 => {
            let mut req = b"GET /s/big HTTP/1.1\r\nHost: x\r\n".to_vec();
            while req.len() <= MAX_HEADER + 1024 {
                req.extend_from_slice(b"X-Fill: 0123456789012345678901234567890123456789\r\n");
            }
            req.extend_from_slice(b"\r\n");
            let mut w = c.s.try_clone().unwrap();
            let writer = thread::spawn(move || {
                let _ = w.write_all(&req);
            });
            match c.response() {
                Ok((431, _)) => {}
                Ok((s, _)) => st.violate(format!("{tag}: oversized head answered {s}")),
                Err(e) if is_stall(&e) => st.violate(format!("{tag}: oversized head stalled")),
                Err(_) => {} // closed before the answer could be read: acceptable
            }
            let _ = writer.join();
            if let Err(e) = c.drain_to_eof() {
                st.violate(format!("{tag}: not closed after 431: {e}"));
            }
        }
        // A body cut short, then FIN (the server must give up) or RST.
        6 => {
            let len = r.range(10, 100_000);
            let head = format!("POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: {len}\r\n\r\n");
            let _ = c.s.write_all(head.as_bytes());
            let body = r.bytes_in(0, len);
            let _ = c.s.write_all(&body);
            if r.below(2) == 0 {
                set_linger0(&c.s);
            } else {
                let _ = c.s.shutdown(Shutdown::Write);
                if let Err(e) = c.drain_to_eof() {
                    st.violate(format!("{tag}: cut body: connection kept open: {e}"));
                }
            }
        }
        // WebSocket: echo, then a clean close, garbage, or a vanishing peer.
        _ => {
            let hs = "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                      Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
            if c.s.write_all(hs.as_bytes()).is_err() {
                return;
            }
            let end = loop {
                if let Some(i) = c.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i + 4;
                }
                if let Err(e) = c.fill() {
                    st.violate(format!("{tag}: ws handshake: {e}"));
                    return;
                }
            };
            if !c.buf.starts_with(b"HTTP/1.1 101") {
                st.violate(format!("{tag}: ws handshake refused"));
                return;
            }
            c.buf.drain(..end);
            let mask = (r.next() as u32).to_be_bytes();
            for _ in 0..r.range(0, 8) {
                let p = r.bytes_in(0, 20_000);
                if c.s.write_all(&ws_frame(0x2, &p, mask)).is_err() {
                    st.violate(format!("{tag}: ws write"));
                    return;
                }
                match c.frame() {
                    Ok((0x2, got)) if got == p => {}
                    Ok((op, got)) => {
                        st.violate(format!("{tag}: ws echo op {op} len {}", got.len()));
                        return;
                    }
                    Err(e) => {
                        st.violate(format!("{tag}: ws echo: {e}"));
                        return;
                    }
                }
            }
            match r.below(3) {
                0 => {
                    let _ = c.s.write_all(&ws_frame(0x8, &1000u16.to_be_bytes(), mask));
                    if let Err(e) = c.drain_to_eof() {
                        st.violate(format!("{tag}: ws close handshake: {e}"));
                    }
                }
                1 => {
                    // An unmasked frame with a reserved opcode: a protocol error.
                    let _ = c.s.write_all(&[0x83, 0x02, 0xde, 0xad]);
                    if let Err(e) = c.drain_to_eof() {
                        st.violate(format!("{tag}: ws garbage not closed: {e}"));
                    }
                }
                _ => set_linger0(&c.s),
            }
        }
    }
}

fn run_seed(seed: u64, conns: usize) {
    let baseline = open_fds();
    let st = Arc::new(Stats::default());
    let cfg = HttpConfig {
        max_header_bytes: MAX_HEADER,
        ..HttpConfig::default()
    };
    let engine = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(500);
            v.slow_callback_threshold = None;
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .threads(2)
                .serve(serve_with(cfg, app(st.clone()))),
        )
        .build()
        .unwrap();
    engine.start().unwrap();
    let addr = engine.local_addrs()[0];
    let next = AtomicUsize::new(0);
    thread::scope(|s| {
        for _ in 0..12 {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= conns {
                        break;
                    }
                    client(addr, seed * 100_003 + i as u64, &st);
                }
            });
        }
    });
    let t = Instant::now();
    while st.ws_closed.load(Ordering::SeqCst) != st.ws_opened.load(Ordering::SeqCst) {
        assert!(
            t.elapsed() < Duration::from_secs(30),
            "seed {seed}: websocket on_close missing"
        );
        thread::sleep(Duration::from_millis(5));
    }
    // Still serving.
    let mut c = connect(addr);
    c.s.write_all(b"GET /s/probe HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let (status, body) = c.response().unwrap();
    assert_eq!((status, body.as_slice()), (200, &b"probe"[..]));
    drop(c);
    let t = Instant::now();
    engine.shutdown();
    engine.wait();
    assert!(
        t.elapsed() < Duration::from_secs(5),
        "seed {seed}: slow shutdown"
    );
    let v = st.violations.lock().unwrap().clone();
    assert!(
        v.is_empty(),
        "seed {seed}: {} violation(s):\n{}",
        v.len(),
        v.join("\n")
    );
    assert_eq!(
        st.ws_opened.load(Ordering::SeqCst),
        st.ws_closed.load(Ordering::SeqCst),
        "seed {seed}: websocket on_close after shutdown"
    );
    drop(engine);
    let t = Instant::now();
    while open_fds() > baseline {
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "seed {seed}: fd leak"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn chaos_http_and_ws() {
    for seed in seeds(&[1, 2, 3]) {
        let t = Instant::now();
        run_seed(seed, 200);
        eprintln!("chaos http seed {seed}: ok in {:?}", t.elapsed());
    }
}
