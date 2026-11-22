//! Chaos tests for the engine: seeded, reproducible random clients that connect, stream, abort
//! with RST, half-close, read slowly or never, pipeline and flood, against server modes that echo
//! inline, close from other threads, close after send, hold reads, and answer in order from a
//! deliberately tiny logical pool (so it saturates with `Overloaded`). Each run then shuts the
//! engine down under load.
//!
//! Invariants checked after every seed: no handler panics or protocol violations, no client read
//! stalls (a stall would be a lost wake-up or a deadlock), every `on_close` ran exactly once for
//! every `on_open`, queued bytes stayed bounded, the server still serves afterwards, `wait()`
//! returns within the shutdown budget, and every descriptor is released.
//!
//! Fast (CI, default `cargo test`): a few fixed seeds, a few hundred connections each.
//! Reproduce a seed: `AKIO_CHAOS_SEEDS=17 cargo test -p akio --test chaos`
//! (also `AKIO_CHAOS_SEEDS=1..200`). Soak: `AKIO_CHAOS=1 AKIO_CHAOS_SECS=300 cargo test -p
//! `akio` --release --test chaos -- --nocapture` runs consecutive seeds with more connections
//! until the time is up. `AKIO_TEST_BACKEND=uring` selects io_uring as for the other tests.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    collections::{HashMap, HashSet},
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    os::fd::AsRawFd,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use akio::{Acceptor, Config, Conn, Engine, Error, Handler, Listener, PoolConfig};

const READ_BUF: usize = 16 << 10;
const HIGH: usize = 64 << 10;
const MAX_Q: usize = 256 << 10;
/// A client read that waits this long is a stall: every server mode either answers or closes.
const STALL: Duration = Duration::from_secs(15);

/// The fd baseline is process-wide, so the tests of this file must not overlap.
static SERIAL: Mutex<()> = Mutex::new(());

// ---- seeds and randomness ------------------------------------------------------------------

/// splitmix64: tiny, seedable, good enough to drive the scenarios.
#[derive(Clone)]
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed ^ 0x9E37_79B9_7F4A_7C15)
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
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

/// Seeds from `AKIO_CHAOS_SEEDS` ("7", "1,5,9" or "1..50"), else `default`.
fn seeds(default: &[u64]) -> Vec<u64> {
    let Ok(s) = std::env::var("AKIO_CHAOS_SEEDS") else {
        return default.to_vec();
    };
    if let Some((a, b)) = s.split_once("..") {
        let (a, b): (u64, u64) = (a.trim().parse().unwrap(), b.trim().parse().unwrap());
        return (a..b).collect();
    }
    s.split(',').map(|x| x.trim().parse().unwrap()).collect()
}

/// `AKIO_CHAOS=1`: soak for `AKIO_CHAOS_SECS` (default 300) seconds.
fn soak() -> Option<Duration> {
    if std::env::var("AKIO_CHAOS").ok().as_deref() != Some("1") {
        return None;
    }
    let secs = std::env::var("AKIO_CHAOS_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    Some(Duration::from_secs(secs))
}

// ---- process helpers -----------------------------------------------------------------------

fn open_fds() -> usize {
    let dir = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    std::fs::read_dir(dir).unwrap().count()
}

fn raise_nofile() {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid, writable rlimit for the duration of both calls.
    unsafe {
        libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut lim);
        lim.rlim_cur = lim.rlim_max.min(65_536);
        libc::setrlimit(libc::RLIMIT_NOFILE, &raw const lim);
    }
}

/// `SO_LINGER = 0`: closing sends RST (an abortive close) and leaves no TIME_WAIT behind.
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

fn wait_for(what: &str, limit: Duration, mut cond: impl FnMut() -> bool) {
    let t = Instant::now();
    while !cond() {
        assert!(t.elapsed() < limit, "timed out: {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

/// Aborts the whole process if not disarmed in time: a deadlock must fail loudly, with the seed.
struct Watchdog(Arc<AtomicBool>);

impl Watchdog {
    fn arm(what: String, limit: Duration) -> Watchdog {
        let done = Arc::new(AtomicBool::new(false));
        let d = done.clone();
        thread::spawn(move || {
            let t = Instant::now();
            while !d.load(Ordering::Acquire) {
                if t.elapsed() > limit {
                    eprintln!("chaos watchdog: {what} still running after {limit:?}: deadlock?");
                    std::process::abort();
                }
                thread::sleep(Duration::from_millis(50));
            }
        });
        Watchdog(done)
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Reads, retrying EINTR (io_uring in the same process interrupts blocking reads).
fn read_some(s: &mut TcpStream, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match s.read(buf) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            r => return r,
        }
    }
}

fn write_all_retry(s: &mut TcpStream, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        match s.write(data) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => data = &data[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// ---- server ---------------------------------------------------------------------------------

#[derive(Default)]
struct Stats {
    opened: AtomicUsize,
    closed: AtomicUsize,
    closes: Mutex<HashMap<u64, u32>>,
    violations: Mutex<Vec<String>>,
    overloaded: AtomicUsize,
    /// Peers whose connection the server closed because the pool was saturated.
    overloaded_peers: Mutex<HashSet<SocketAddr>>,
    /// Peers whose connection ran `on_close`: a close the client never heard of is not a stall.
    closed_peers: Mutex<HashSet<SocketAddr>>,
    max_echo_queue: AtomicUsize,
    /// Open connections and their mode, for diagnosing a connection that does not close.
    live: Mutex<HashMap<u64, (Conn<Srv>, u8)>>,
}

impl Stats {
    fn violate(&self, s: String) {
        self.violations.lock().unwrap().push(s);
    }
    fn was_overloaded(&self, peer: SocketAddr) -> bool {
        self.overloaded_peers.lock().unwrap().contains(&peer)
    }
    fn was_closed(&self, peer: SocketAddr) -> bool {
        self.closed_peers.lock().unwrap().contains(&peer)
    }
}

/// Server modes, chosen by the first byte the client sends.
const MODES: [u8; 5] = *b"EHKCP";

struct Srv {
    st: Arc<Stats>,
    mode: u8,
    buf: Vec<u8>,
    rng: Rng,
}

/// Splits one `[len: u16 BE][payload]` frame off the front of `buf`.
fn take_frame(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buf.len() < 2 {
        return None;
    }
    let n = 2 + u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < n {
        return None;
    }
    Some(buf.drain(..n).collect())
}

impl Handler for Srv {
    fn on_data(&mut self, c: &Conn<Self>, mut data: &[u8]) {
        if self.mode == 0 {
            self.mode = data[0];
            data = &data[1..];
            if let Some(e) = self.st.live.lock().unwrap().get_mut(&c.id()) {
                e.1 = self.mode;
            }
            if self.mode == b'K' {
                // Killed from another thread at a random moment.
                let (c2, d) = (c.clone(), self.rng.below(30));
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(d));
                    c2.close();
                });
            }
        }
        match self.mode {
            // Echo inline; `H` also pauses reading now and then from another thread.
            b'E' | b'H' => {
                match c.send(data) {
                    Ok(()) | Err(Error::Closed) => {}
                    Err(e) => self.st.violate(format!("echo send failed: {e}")),
                }
                let q = c.queued_bytes();
                self.st.max_echo_queue.fetch_max(q, Ordering::Relaxed);
                if self.mode == b'H' && self.rng.chance(20) {
                    c.hold_reads(true);
                    let (c2, d) = (c.clone(), self.rng.below(5));
                    thread::spawn(move || {
                        thread::sleep(Duration::from_millis(d));
                        c2.hold_reads(false);
                    });
                }
            }
            b'K' => {
                let _ = c.send(data);
            }
            // Echo the first chunk, then close once it is out.
            b'C' => {
                let _ = c.send(data);
                c.close_after_send();
            }
            // Pipelined frames answered in order from the pool, with random completion delays.
            b'P' => {
                self.buf.extend_from_slice(data);
                while let Some(frame) = take_frame(&mut self.buf) {
                    let Ok(slot) = c.reserve_response() else {
                        return;
                    };
                    let d = self.rng.below(3);
                    let r = c.spawn_blocking(
                        move || {
                            if d > 0 {
                                thread::sleep(Duration::from_millis(d));
                            }
                            slot.fill(frame);
                        },
                        |_h: &mut Srv, _c, ()| {},
                    );
                    match r {
                        Ok(()) => {}
                        // The rejected job dropped its slot, which closes the connection.
                        Err(Error::Overloaded) => {
                            self.st.overloaded.fetch_add(1, Ordering::Relaxed);
                            self.st
                                .overloaded_peers
                                .lock()
                                .unwrap()
                                .insert(c.peer_addr());
                            return;
                        }
                        Err(Error::Closed) => return,
                        Err(e) => {
                            self.st.violate(format!("spawn_blocking: {e}"));
                            return;
                        }
                    }
                }
            }
            m => {
                self.st.violate(format!("unknown mode {m}"));
                c.close();
            }
        }
    }

    fn on_close(&mut self, c: &Conn<Self>, err: Option<Error>) {
        if let Some(Error::Io(e)) = &err {
            if e.to_string().contains("max_queued_bytes") {
                // An ordered response did not fit the send queue: the core ends the connection.
                self.st.overloaded.fetch_add(1, Ordering::Relaxed);
                self.st
                    .overloaded_peers
                    .lock()
                    .unwrap()
                    .insert(c.peer_addr());
            }
        }
        let n = {
            let mut m = self.st.closes.lock().unwrap();
            let n = m.entry(c.id()).or_insert(0);
            *n += 1;
            *n
        };
        if n != 1 {
            self.st
                .violate(format!("on_close #{n} for connection {}", c.id()));
        }
        if c.is_open() {
            self.st.violate("is_open() inside on_close".into());
        }
        if c.send(b"x").is_ok() {
            self.st.violate("send succeeded inside on_close".into());
        }
        self.st.live.lock().unwrap().remove(&c.id());
        self.st.closed_peers.lock().unwrap().insert(c.peer_addr());
        self.st.closed.fetch_add(1, Ordering::SeqCst);
    }
}

struct SrvAcceptor(Arc<Stats>);

impl Acceptor for SrvAcceptor {
    type Handler = Srv;
    fn on_open(&self, c: &Conn<Srv>) -> Srv {
        self.0.opened.fetch_add(1, Ordering::SeqCst);
        self.0.live.lock().unwrap().insert(c.id(), (c.clone(), 0));
        Srv {
            st: self.0.clone(),
            mode: 0,
            buf: Vec::new(),
            rng: Rng::new(c.id()),
        }
    }
    fn on_shutdown(&self, c: &Conn<Srv>) {
        // A mix of shutdown policies: close now, close once flushed, or let the timeout force it.
        match c.id() % 3 {
            0 => c.close(),
            1 => c.close_after_send(),
            _ => {}
        }
    }
}

fn build_engine(st: &Arc<Stats>, shutdown_timeout: Duration) -> Engine {
    build_engine_q(st, shutdown_timeout, 16)
}

fn build_engine_q(st: &Arc<Stats>, shutdown_timeout: Duration, queue_capacity: usize) -> Engine {
    Engine::builder()
        .config({
            let mut v = Config::default();
            v.read_buffer = READ_BUF;
            v.write_high_watermark = HIGH;
            v.max_queued_bytes = MAX_Q;
            v.shutdown_timeout = shutdown_timeout;
            v.slow_callback_threshold = None;
            v
        })
        .pool({
            let mut v = PoolConfig::default();
            v.min_threads = 0;
            v.max_threads = 4;
            v.queue_capacity = queue_capacity;
            v.keep_alive = Duration::from_millis(200);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(common::backend())
                .threads(3)
                .serve(SrvAcceptor(st.clone())),
        )
        .build()
        .unwrap()
}

// ---- clients --------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
enum Act {
    /// Stream the body while reading the echo, then close.
    Normal,
    /// Stream the body, `shutdown(Write)`, read the rest and expect EOF.
    HalfClose,
    /// Send part of the body, then reset the connection.
    Abort,
    /// Flood without ever reading, then reset.
    NoRead,
    /// Read in tiny, slow pieces.
    Slow,
    /// Connect, send nothing, leave.
    Idle,
}

const ACTS: [Act; 6] = [
    Act::Normal,
    Act::HalfClose,
    Act::Abort,
    Act::NoRead,
    Act::Slow,
    Act::Idle,
];

fn body(rng: &mut Rng, mode: u8, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 64);
    if mode == b'P' {
        while out.len() < len {
            let n = rng.range(0, 32 << 10);
            out.extend_from_slice(&(n as u16).to_be_bytes());
            out.extend((0..n).map(|_| rng.next() as u8));
        }
    } else {
        out.extend((0..len).map(|_| rng.next() as u8));
    }
    out
}

#[derive(Default)]
struct ClientTally {
    full: AtomicUsize,
    cut: AtomicUsize,
    connect_errors: AtomicUsize,
}

/// One randomized client connection. Appends any invariant violation to `st`.
fn client(addr: SocketAddr, seed: u64, st: &Stats, tally: &ClientTally) {
    let mut r = Rng::new(seed);
    let mode = MODES[r.below(MODES.len() as u64) as usize];
    let act = ACTS[r.below(ACTS.len() as u64) as usize];
    let len = match act {
        Act::NoRead => r.range(64 << 10, 2 << 20),
        Act::Slow => r.range(0, 24 << 10),
        Act::Idle => 0,
        _ => r.range(0, 256 << 10),
    };
    let body = body(&mut r, mode, len);
    let tag = format!(
        "seed {seed} mode {} {act:?} len {}",
        mode as char,
        body.len()
    );
    let Ok(mut s) = TcpStream::connect(addr) else {
        tally.connect_errors.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let local = s.local_addr().unwrap();
    if std::env::var_os("AKIO_CHAOS_TRACE").is_some() {
        // Matches the peer address printed for a connection that never closed.
        eprintln!("chaos trace: {local} {tag}");
    }
    s.set_read_timeout(Some(STALL)).unwrap();

    match act {
        Act::Idle => {
            thread::sleep(Duration::from_millis(r.below(20)));
            if r.chance(50) {
                set_linger0(&s);
            }
            return;
        }
        Act::Abort => {
            let cut = r.range(0, body.len() + 1);
            let _ = write_all_retry(&mut s, &[mode]);
            let mut off = 0;
            while off < cut {
                let n = r.range(1, 8 << 10).min(cut - off);
                if write_all_retry(&mut s, &body[off..off + n]).is_err() {
                    break;
                }
                off += n;
            }
            if r.chance(50) {
                thread::sleep(Duration::from_millis(r.below(5)));
            }
            set_linger0(&s);
            return;
        }
        Act::NoRead => {
            s.set_write_timeout(Some(Duration::from_millis(r.range(50, 500) as u64)))
                .unwrap();
            let _ = write_all_retry(&mut s, &[mode]);
            let _ = write_all_retry(&mut s, &body);
            set_linger0(&s);
            return;
        }
        Act::Normal | Act::HalfClose | Act::Slow => {}
    }

    // Write on a thread, read here: a single-threaded blocking client deadlocks against
    // backpressure (and against macOS's small socket buffers).
    let mut w = s.try_clone().unwrap();
    let half = act == Act::HalfClose;
    let wseed = r.next();
    let wbody = body.clone();
    let writer = thread::spawn(move || {
        let mut r = Rng::new(wseed);
        let _ = write_all_retry(&mut w, &[mode]);
        let mut off = 0;
        while off < wbody.len() {
            let n = r.range(1, 32 << 10).min(wbody.len() - off);
            if write_all_retry(&mut w, &wbody[off..off + n]).is_err() {
                return;
            }
            off += n;
            if r.chance(5) {
                thread::sleep(Duration::from_millis(1));
            }
        }
        if half {
            let _ = w.shutdown(Shutdown::Write);
        }
    });

    let mut got: Vec<u8> = Vec::with_capacity(body.len());
    let mut buf = vec![0u8; 64 << 10];
    let mut eof = false;
    let mut err = None;
    while got.len() < body.len() {
        let want = if act == Act::Slow {
            r.range(1, 512)
        } else {
            buf.len()
        };
        match read_some(&mut s, &mut buf[..want]) {
            Ok(0) => {
                eof = true;
                break;
            }
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) => {
                err = Some(e);
                break;
            }
        }
        if act == Act::Slow && r.chance(10) {
            thread::sleep(Duration::from_millis(1));
        }
    }
    if let Some(e) = &err {
        if matches!(
            e.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ) {
            // A stall is a lost wake-up or a deadlock only if the server did not close the
            // connection within the stall limit. On macOS a server that closes with input still
            // unread (`K` kills at a random moment, mid-stream) amid a burst of resets sometimes
            // leaves the peer in FIN_WAIT_2 with neither FIN nor an accepted RST: all its data
            // and its FIN acknowledged, nothing left to send that would draw a new reset, so it
            // waits forever. A plain std server that drops its socket the same way does it too;
            // the kernel's RST and challenge-ACK rate limits (`net.inet.tcp.rst_rlc_enable`,
            // `challengeack_limit`) are the likely cause. Linux delivers the reset.
            let lost_close = cfg!(target_os = "macos") && st.was_closed(local);
            if lost_close {
                eprintln!(
                    "chaos {tag}: the server closed, the client never heard (after {} bytes)",
                    got.len()
                );
            } else {
                st.violate(format!("{tag}: read stalled after {} bytes", got.len()));
            }
        }
    }
    if got.len() > body.len() || got[..] != body[..got.len()] {
        let at = got.iter().zip(&body).position(|(a, b)| a != b);
        st.violate(format!(
            "{tag}: echo is not a prefix of what was sent (got {}, first mismatch at {at:?})",
            got.len()
        ));
    }
    let complete = got.len() == body.len();
    // `E`/`H` never close on their own; `P` only closes when the pool rejected work.
    let must_complete = matches!(mode, b'E' | b'H')
        || (mode == b'P' && !st.was_overloaded(local) && (eof || err.is_some()));
    if must_complete && !complete {
        // Recheck for `P`: the overload may be recorded just before the close we saw.
        if !(mode == b'P' && st.was_overloaded(local)) {
            st.violate(format!(
                "{tag}: connection ended early: {} of {} bytes (eof {eof}, err {err:?})",
                got.len(),
                body.len()
            ));
        }
    }
    if half && complete && matches!(mode, b'E' | b'H') {
        // After the echo, the server must finish the half-closed connection: EOF.
        match read_some(&mut s, &mut buf) {
            Ok(0) => {}
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
            Ok(n) => st.violate(format!("{tag}: {n} unexpected bytes after the echo")),
            Err(e) => st.violate(format!("{tag}: no EOF after half close: {e}")),
        }
    }
    if complete {
        tally.full.fetch_add(1, Ordering::Relaxed);
    } else {
        tally.cut.fetch_add(1, Ordering::Relaxed);
    }
    if r.chance(30) {
        set_linger0(&s);
    }
    drop(s);
    let _ = writer.join();
}

/// A plain round trip on a fresh connection: the server still serves.
fn probe(addr: SocketAddr) {
    let mut s = TcpStream::connect(addr).expect("probe connect");
    s.set_read_timeout(Some(STALL)).unwrap();
    write_all_retry(&mut s, b"Eping").unwrap();
    let mut got = [0u8; 4];
    let mut n = 0;
    while n < 4 {
        match read_some(&mut s, &mut got[n..]) {
            Ok(0) => panic!("probe: eof"),
            Ok(k) => n += k,
            Err(e) => panic!("probe: {e}"),
        }
    }
    assert_eq!(&got, b"ping");
}

fn wait_all_closed(st: &Stats, seed: u64) {
    let t = Instant::now();
    while st.closed.load(Ordering::SeqCst) != st.opened.load(Ordering::SeqCst) {
        if t.elapsed() > Duration::from_secs(30) {
            let live: Vec<String> = st
                .live
                .lock()
                .unwrap()
                .iter()
                .map(|(id, (c, m))| {
                    format!(
                        "id {id} mode {} queued {} open {} peer {} so_error {:?}",
                        *m as char,
                        c.queued_bytes(),
                        c.is_open(),
                        c.peer_addr(),
                        c.inner().stream().take_error()
                    )
                })
                .collect();
            panic!(
                "seed {seed}: connections never closed:\n{}",
                live.join("\n")
            );
        }
        thread::sleep(Duration::from_millis(5));
    }
}

// ---- the run --------------------------------------------------------------------------------

struct RunReport {
    conns: usize,
    full: usize,
    cut: usize,
    overloaded: usize,
    connect_errors: usize,
    elapsed: Duration,
}

fn run_seed(seed: u64, conns: usize, par: usize) -> RunReport {
    let t0 = Instant::now();
    let _dog = Watchdog::arm(format!("chaos seed {seed}"), Duration::from_secs(180));
    let baseline = open_fds();
    let st = Arc::new(Stats::default());
    let shutdown_timeout = Duration::from_millis(500);
    let engine = Arc::new(build_engine(&st, shutdown_timeout));
    engine.start().unwrap();
    let addr = engine.local_addrs()[0];

    // Phase 1: randomized clients.
    let tally = Arc::new(ClientTally::default());
    let next = Arc::new(AtomicUsize::new(0));
    let workers: Vec<_> = (0..par)
        .map(|_| {
            let (st, tally, next) = (st.clone(), tally.clone(), next.clone());
            thread::spawn(move || {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= conns {
                        break;
                    }
                    client(
                        addr,
                        seed.wrapping_mul(1_000_003).wrapping_add(i as u64),
                        &st,
                        &tally,
                    );
                }
            })
        })
        .collect();
    for w in workers {
        w.join().expect("client thread panicked");
    }
    let t_clients = t0.elapsed();

    // Every connection closes (threads that kill connections and pool jobs finish soon). A
    // reset sent into a zero window can be ignored by the peer's TCP until its next window
    // probe (about 5 s on macOS), so allow for that.
    wait_all_closed(&st, seed);
    let t_closed = t0.elapsed();
    probe(addr);
    wait_all_closed(&st, seed);

    // Phase 2: shut down under load: streaming, flooding and idle connections are open.
    let mut held = Vec::new();
    let mut r = Rng::new(seed ^ 0xD00D);
    for i in 0..24 {
        let Ok(mut s) = TcpStream::connect(addr) else {
            continue;
        };
        let _ = s.set_read_timeout(Some(STALL));
        let _ = s.set_write_timeout(Some(Duration::from_secs(3)));
        let mode = b"EHP"[i % 3];
        let _ = write_all_retry(&mut s, &[mode]);
        let len = r.range(0, 512 << 10);
        let b = body(&mut r, mode, len);
        let mut w = s.try_clone().unwrap();
        held.push(thread::spawn(move || {
            let _ = write_all_retry(&mut w, &b);
        }));
        held.push(thread::spawn(move || {
            // Drain until the server goes away; never block past the stall limit.
            let mut buf = vec![0u8; 16 << 10];
            while let Ok(n) = read_some(&mut s, &mut buf) {
                if n == 0 || i % 4 == 0 {
                    break; // every fourth stops reading at once and just holds the socket
                }
            }
            thread::sleep(Duration::from_millis(100));
        }));
    }
    wait_for("load connections open", Duration::from_secs(10), || {
        st.opened.load(Ordering::SeqCst) >= st.closed.load(Ordering::SeqCst) + 12
    });
    let t_stop = Instant::now();
    engine.shutdown();
    let (tx, rx) = mpsc::channel();
    let e2 = engine.clone();
    thread::spawn(move || {
        e2.wait();
        let _ = tx.send(());
    });
    rx.recv_timeout(shutdown_timeout + Duration::from_secs(10))
        .unwrap_or_else(|_| panic!("seed {seed}: wait() did not return after shutdown"));
    let stop_took = t_stop.elapsed();
    let t_held = Instant::now();
    for h in held {
        h.join().expect("load thread panicked");
    }
    let held_took = t_held.elapsed();

    // Invariants.
    let violations = st.violations.lock().unwrap().clone();
    assert!(
        violations.is_empty(),
        "seed {seed}: {} violation(s):\n{}",
        violations.len(),
        violations.join("\n")
    );
    let (opened, closed) = (
        st.opened.load(Ordering::SeqCst),
        st.closed.load(Ordering::SeqCst),
    );
    assert_eq!(opened, closed, "seed {seed}: on_close count after shutdown");
    {
        let m = st.closes.lock().unwrap();
        assert_eq!(m.len(), opened, "seed {seed}: closed connection ids");
        assert!(
            m.values().all(|&n| n == 1),
            "seed {seed}: on_close exactly once"
        );
    }
    let maxq = st.max_echo_queue.load(Ordering::Relaxed);
    assert!(
        maxq <= HIGH + READ_BUF,
        "seed {seed}: echo queue reached {maxq} bytes, over watermark + one read"
    );
    assert!(
        stop_took < shutdown_timeout + Duration::from_secs(3),
        "seed {seed}: shutdown took {stop_took:?}"
    );
    drop(engine);
    wait_for(
        &format!("seed {seed}: descriptors released"),
        Duration::from_secs(10),
        || open_fds() <= baseline,
    );
    if t0.elapsed() > Duration::from_secs(3) {
        eprintln!(
            "chaos seed {seed}: slow run: clients done {t_clients:?}, all closed {t_closed:?}, \
             shutdown {stop_took:?}, load threads joined +{held_took:?}"
        );
    }
    RunReport {
        conns,
        full: tally.full.load(Ordering::Relaxed),
        cut: tally.cut.load(Ordering::Relaxed),
        overloaded: st.overloaded.load(Ordering::Relaxed),
        connect_errors: tally.connect_errors.load(Ordering::Relaxed),
        elapsed: t0.elapsed(),
    }
}

fn print_report(seed: u64, r: &RunReport) {
    eprintln!(
        "chaos seed {seed}: {} conns ({} full, {} cut, {} connect errors), {} pool rejections, {:?}",
        r.conns, r.full, r.cut, r.connect_errors, r.overloaded, r.elapsed
    );
}

#[test]
fn chaos_engine() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    raise_nofile();
    if let Some(budget) = soak() {
        let start = Instant::now();
        let mut seed = seeds(&[1000])[0];
        let mut runs = 0;
        while start.elapsed() < budget {
            let r = run_seed(seed, 1500, 48);
            print_report(seed, &r);
            seed += 1;
            runs += 1;
        }
        eprintln!(
            "chaos soak: {runs} seeds in {:?}, no violations",
            start.elapsed()
        );
        return;
    }
    let mut overloaded = 0;
    for seed in seeds(&[1, 2, 3]) {
        let r = run_seed(seed, 300, 24);
        print_report(seed, &r);
        overloaded += r.overloaded;
    }
    let _ = overloaded;
}

// ---- targeted scenarios ---------------------------------------------------------------------

/// A pipelining client that stops reading while the pool keeps completing responses: the queue
/// passes `max_queued_bytes`. Whatever reaches the client must still be an in-order prefix of
/// the responses (a response may not silently go missing from the middle of the stream).
#[test]
fn pipelined_responses_over_queue_limit_never_leave_gaps() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let st = Arc::new(Stats::default());
    // A pool queue deep enough that nothing is rejected: only the send queue limit is in play.
    let engine = build_engine_q(&st, Duration::from_millis(300), 1 << 16);
    engine.start().unwrap();
    let addr = engine.local_addrs()[0];
    let mut r = Rng::new(77);
    // ~1.5 MiB of frames: far more than MAX_Q, pipelined in one go.
    let body = body(&mut r, b'P', 1536 << 10);
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(STALL)).unwrap();
    let mut w = s.try_clone().unwrap();
    let b2 = body.clone();
    let writer = thread::spawn(move || {
        w.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
        let _ = write_all_retry(&mut w, b"P");
        let _ = write_all_retry(&mut w, &b2);
    });
    // Do not read for a while: responses pile up on the server.
    thread::sleep(Duration::from_millis(500));
    let mut got = Vec::new();
    let mut buf = vec![0u8; 64 << 10];
    let mut stalled = None;
    while got.len() < body.len() {
        match read_some(&mut s, &mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                stalled = Some(e);
                break;
            }
            Err(_) => break,
        }
    }
    let _ = writer.join();
    let mismatch = got.iter().zip(&body).position(|(a, b)| a != b);
    assert!(
        got.len() <= body.len() && mismatch.is_none(),
        "responses out of order or missing: got {} bytes, first mismatch at {mismatch:?}",
        got.len()
    );
    // Either everything arrived, or the server ended the connection: never a silent stall.
    assert!(
        stalled.is_none(),
        "stalled after {} of {} response bytes: a response was dropped",
        got.len(),
        body.len()
    );
    engine.shutdown();
    engine.wait();
}

/// The peer half-closes right after pipelining requests that the pool answers later: every
/// response must still be delivered before the connection closes.
#[test]
fn half_close_waits_for_pending_ordered_responses() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let st = Arc::new(Stats::default());
    let engine = build_engine(&st, Duration::from_millis(300));
    engine.start().unwrap();
    let addr = engine.local_addrs()[0];
    for round in 0..20u64 {
        let mut r = Rng::new(round);
        let body = body(&mut r, b'P', 4 << 10);
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(STALL)).unwrap();
        write_all_retry(&mut s, b"P").unwrap();
        write_all_retry(&mut s, &body).unwrap();
        s.shutdown(Shutdown::Write).unwrap();
        let mut got = Vec::new();
        let mut buf = vec![0u8; 64 << 10];
        loop {
            match read_some(&mut s, &mut buf) {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(e) => panic!("round {round}: {e}"),
            }
        }
        assert!(
            got == body || st.was_overloaded(s.local_addr().unwrap()),
            "round {round}: {} of {} response bytes before EOF",
            got.len(),
            body.len()
        );
    }
    engine.shutdown();
    engine.wait();
}

/// Clients that send a little (often an incomplete request the server never answers) and vanish
/// with FIN or RST, many in parallel: sometimes before the server accepted them, sometimes right
/// after its read was armed. A reset arriving on an idle armed read must still close the
/// connection (io_uring: the multishot recv alone misses it on Linux 6.12).
#[test]
fn connect_send_and_vanish() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let st = Arc::new(Stats::default());
    let engine = build_engine(&st, Duration::from_millis(300));
    engine.start().unwrap();
    let addr = engine.local_addrs()[0];
    thread::scope(|s| {
        for t in 0..8u64 {
            s.spawn(move || {
                let mut r = Rng::new(t);
                for _ in 0..200 {
                    let Ok(mut c) = TcpStream::connect(addr) else {
                        continue;
                    };
                    if r.chance(50) {
                        // Let the server arm its read first: data and RST then arrive on a live read.
                        thread::sleep(Duration::from_millis(r.below(3)));
                    }
                    let mut msg = vec![b'E'; r.range(0, 600)];
                    msg.iter_mut()
                        .skip(1)
                        .for_each(|b| *b = r.next() as u8 | 0x80);
                    if r.chance(50) && !msg.is_empty() {
                        msg[0] = b'P'; // an incomplete frame: the server never answers
                    }
                    let _ = c.write_all(&msg);
                    if r.chance(50) {
                        set_linger0(&c);
                    }
                }
            });
        }
    });
    wait_all_closed(&st, 0);
    probe(addr);
    engine.shutdown();
    engine.wait();
    let v = st.violations.lock().unwrap().clone();
    assert!(v.is_empty(), "{}", v.join("\n"));
}
