//! Fuzzing support (feature `fuzzing`, not part of the public API): detached connections that
//! let protocol handlers be driven with arbitrary bytes without an engine.
//!
//! A detached connection writes into one shared loopback TCP socket whose far end a background
//! thread drains, so sends behave like on a real connection (direct writes, queueing on
//! `WouldBlock`). Its [`LoopLink`] does nothing: `close` only flips the state, there is no pool
//! (`spawn_blocking` fails with `Closed`) and posted tasks are dropped.

use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use crate::{Config, Conn, ConnInner, LoopLink, Task};

struct NullLink;

impl LoopLink for NullLink {
    fn wake_conn(&self, _id: u64) {}
    fn close_conn(&self, _id: u64, _err: Option<std::io::Error>) {}
    fn post_task(&self, _id: u64, _task: Task) {}
}

struct Shared {
    stream: TcpStream,
    local: SocketAddr,
    peer: SocketAddr,
    link: Arc<dyn LoopLink>,
    cfg: Arc<Config>,
}

fn shared() -> &'static Shared {
    static S: OnceLock<Shared> = OnceLock::new();
    S.get_or_init(|| {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let stream = TcpStream::connect(l.local_addr().expect("addr")).expect("connect");
        let (mut far, _) = l.accept().expect("accept");
        std::thread::Builder::new()
            .name("fuzz-drain".into())
            .spawn(move || {
                let mut buf = vec![0u8; 1 << 16];
                while matches!(far.read(&mut buf), Ok(n) if n > 0) {}
            })
            .expect("spawn drain thread");
        stream.set_nonblocking(true).expect("nonblocking");
        Shared {
            local: stream.local_addr().expect("local"),
            peer: stream.peer_addr().expect("peer"),
            stream,
            link: Arc::new(NullLink),
            cfg: Arc::new(Config::default()),
        }
    })
}

/// A new detached connection (its own id and send queue, the shared loopback socket).
pub fn conn_inner() -> Arc<ConnInner> {
    static NEXT: AtomicU64 = AtomicU64::new(1 << 62);
    let s = shared();
    ConnInner::new(
        NEXT.fetch_add(1, Ordering::Relaxed),
        s.stream.try_clone().expect("dup loopback socket"),
        s.local,
        s.peer,
        s.link.clone(),
        s.cfg.clone(),
    )
}

/// A typed handle to a new detached connection.
pub fn conn<H>() -> Conn<H> {
    Conn::new(conn_inner())
}

/// A typed handle to `inner`.
pub fn wrap<H>(inner: Arc<ConnInner>) -> Conn<H> {
    Conn::new(inner)
}

/// Splits a fuzz input into the pieces a reader would see: `data[0]` seeds the piece sizes
/// (`0`: everything in one piece; `s > 0`: pseudo-random sizes in `1..=s`), the rest is the
/// byte stream. Lets one corpus file exercise many read boundaries.
pub fn split(data: &[u8]) -> Vec<&[u8]> {
    let Some((&seed, mut rest)) = data.split_first() else {
        return Vec::new();
    };
    if seed == 0 {
        return if rest.is_empty() {
            Vec::new()
        } else {
            vec![rest]
        };
    }
    let mut x = u32::from(seed) | 0x9e37_7900;
    let mut out = Vec::new();
    while !rest.is_empty() {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        let n = (x as usize % usize::from(seed) + 1).min(rest.len());
        let (a, b) = rest.split_at(n);
        out.push(a);
        rest = b;
    }
    out
}

/// Every regular file under `dir`, for replaying a corpus in a unit test (empty if `dir` does
/// not exist).
pub fn corpus(dir: &str) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_file() {
                if let Ok(b) = std::fs::read(&p) {
                    out.push((p.display().to_string(), b));
                }
            }
        }
    }
    out.sort();
    out
}

/// Writes `seeds` into `dir` (created if needed), each named after a hash of its content so
/// regenerating is idempotent.
pub fn write_seeds(dir: &str, seeds: &[Vec<u8>]) {
    std::fs::create_dir_all(dir).expect("create corpus dir");
    for s in seeds {
        // FNV-1a: stable names, no extra dependency.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in s {
            h = (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3);
        }
        std::fs::write(format!("{dir}/seed-{h:016x}"), s).expect("write seed");
    }
}

/// Replays every file of `fuzz/corpus/<target>` (relative to the workspace root, given the
/// calling crate's manifest dir) through `f`, and returns how many there were.
pub fn replay(manifest_dir: &str, target: &str, f: impl Fn(&[u8])) -> usize {
    let files = corpus(&format!("{manifest_dir}/../../fuzz/corpus/{target}"));
    for (name, data) in &files {
        eprintln!("replay {name}");
        f(data);
    }
    files.len()
}

/// [`write_seeds`] into `fuzz/corpus/<target>` (see [`replay`]).
pub fn write_target_seeds(manifest_dir: &str, target: &str, seeds: &[Vec<u8>]) {
    write_seeds(&format!("{manifest_dir}/../../fuzz/corpus/{target}"), seeds);
}
