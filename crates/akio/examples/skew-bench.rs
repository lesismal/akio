//! A CPU-bound request/response benchmark for comparing the two scheduling modes (ADR-102).
//!
//! ```text
//! skew-bench server <addr> <loops|rounds> [threads|pollers:workers]
//! skew-bench client <addr> <conns> <depth> <work_us> <heavy_conns> <heavy_work_us> <secs>
//! ```
//!
//! Every request is 16 bytes (`work_us: u32`, padding, `sent_ns: u64`); the server spins
//! `work_us` microseconds of CPU in `on_data` and echoes the request. The client keeps `depth`
//! requests in flight on each of `conns` connections; the first `heavy_conns` connections ask
//! for `heavy_work_us` per request instead of `work_us`. It prints requests/s and latency
//! percentiles for all requests and for the light connections alone.
//!
//! With few connections per thread, thread-per-core loops leave some threads with more
//! connections than others (the kernel's `SO_REUSEPORT` hash), and the heavy connections pin
//! whichever threads they land on; rounds spread the work over every worker.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use akio::{Conn, Engine, Handler, Listener, RoundsConfig, Scheduling, fn_acceptor};

const FRAME: usize = 16;

/// Spins for `us` microseconds.
fn spin(us: u32) {
    if us == 0 {
        return;
    }
    let until = Instant::now() + Duration::from_micros(us as u64);
    let mut x = 0x9e37_79b9_7f4a_7c15_u64;
    loop {
        for _ in 0..64 {
            x = x.rotate_left(5) ^ x.wrapping_mul(0x2545_f491_4f6c_dd1d);
        }
        std::hint::black_box(x);
        if Instant::now() >= until {
            break;
        }
    }
}

#[derive(Default)]
struct Work {
    buf: Vec<u8>,
}

impl Handler for Work {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        self.buf.extend_from_slice(data);
        let whole = self.buf.len() / FRAME * FRAME;
        for f in self.buf[..whole].chunks_exact(FRAME) {
            let us = u32::from_le_bytes(f[..4].try_into().expect("4 bytes"));
            spin(us);
        }
        if whole > 0 {
            let _ = c.send(&self.buf[..whole]);
            self.buf.drain(..whole);
        }
    }
}

fn server(addr: SocketAddr, mode: &str, sizes: Option<&str>) {
    let cpus = thread::available_parallelism().map_or(1, |n| n.get());
    let mut l = Listener::tcp(addr).serve(fn_acceptor(|_c: &Conn<Work>| Work::default()));
    match mode {
        "rounds" => {
            let (p, w) = sizes
                .and_then(|s| s.split_once(':'))
                .map(|(p, w)| (p.parse().unwrap_or(0), w.parse().unwrap_or(0)))
                .unwrap_or((0, 0));
            l = l.scheduling(Scheduling::Rounds(RoundsConfig::new(p, w)));
        }
        _ => {
            let t = sizes.and_then(|s| s.parse().ok()).unwrap_or(cpus);
            l = l.scheduling(Scheduling::Loops).threads(t);
        }
    }
    let e = Engine::builder().listen(l).build().expect("build");
    e.start().expect("start");
    println!("skew-bench server on {} ({mode})", e.local_addrs()[0]);
    e.wait();
}

struct Stats {
    lat: Vec<u64>,
    light: Vec<u64>,
    done: u64,
}

#[allow(clippy::too_many_arguments)]
fn conn_loop(
    addr: SocketAddr,
    depth: usize,
    work: u32,
    heavy: bool,
    epoch: Instant,
    warm: Instant,
    stop: Arc<AtomicBool>,
) -> Stats {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_nodelay(true).ok();
    let mut r = s.try_clone().expect("clone");
    let frame = |now: Instant| {
        let mut f = [0u8; FRAME];
        f[..4].copy_from_slice(&work.to_le_bytes());
        f[8..].copy_from_slice(&(now.duration_since(epoch).as_nanos() as u64).to_le_bytes());
        f
    };
    let mut out = Vec::with_capacity(depth * FRAME);
    for _ in 0..depth {
        out.extend_from_slice(&frame(Instant::now()));
    }
    s.write_all(&out).expect("write");
    let mut st = Stats {
        lat: Vec::new(),
        light: Vec::new(),
        done: 0,
    };
    let mut f = [0u8; FRAME];
    while !stop.load(Ordering::Relaxed) {
        if r.read_exact(&mut f).is_err() {
            break;
        }
        let now = Instant::now();
        let sent = u64::from_le_bytes(f[8..].try_into().expect("8 bytes"));
        if now >= warm {
            let ns = now.duration_since(epoch).as_nanos() as u64 - sent;
            st.lat.push(ns);
            if !heavy {
                st.light.push(ns);
            }
            st.done += 1;
        }
        if s.write_all(&frame(now)).is_err() {
            break;
        }
    }
    let _ = s.shutdown(std::net::Shutdown::Both);
    st
}

fn pct(v: &mut [u64], p: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_unstable();
    let i = ((v.len() as f64 - 1.0) * p).round() as usize;
    v[i] as f64 / 1000.0
}

fn client(args: &[String]) {
    let addr: SocketAddr = args[0].parse().expect("addr");
    let conns: usize = args[1].parse().expect("conns");
    let depth: usize = args[2].parse().expect("depth");
    let work: u32 = args[3].parse().expect("work_us");
    let heavy: usize = args[4].parse().expect("heavy_conns");
    let heavy_work: u32 = args[5].parse().expect("heavy_work_us");
    let secs: u64 = args[6].parse().expect("secs");
    let epoch = Instant::now();
    let warm = epoch + Duration::from_secs(1);
    let stop = Arc::new(AtomicBool::new(false));
    let hs: Vec<_> = (0..conns)
        .map(|i| {
            let stop = stop.clone();
            let (w, h) = if i < heavy {
                (heavy_work, true)
            } else {
                (work, false)
            };
            thread::spawn(move || conn_loop(addr, depth, w, h, epoch, warm, stop))
        })
        .collect();
    thread::sleep(Duration::from_secs(1 + secs));
    stop.store(true, Ordering::Relaxed);
    let (mut lat, mut light, mut done) = (Vec::new(), Vec::new(), 0);
    let mut per_conn = Vec::new();
    for h in hs {
        let st = h.join().expect("join");
        per_conn.push(st.done);
        done += st.done;
        lat.extend(st.lat);
        light.extend(st.light);
    }
    let rps = done as f64 / secs as f64;
    println!(
        "rps={rps:.0} p50={:.0}us p99={:.0}us p999={:.0}us light_p50={:.0}us light_p99={:.0}us conn_min={} conn_max={}",
        pct(&mut lat, 0.5),
        pct(&mut lat, 0.99),
        pct(&mut lat, 0.999),
        pct(&mut light, 0.5),
        pct(&mut light, 0.99),
        per_conn.iter().min().copied().unwrap_or(0),
        per_conn.iter().max().copied().unwrap_or(0),
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("server") if args.len() >= 3 => server(
            args[1].parse().expect("addr"),
            &args[2],
            args.get(3).map(String::as_str),
        ),
        Some("client") if args.len() >= 8 => client(&args[1..]),
        _ => eprintln!(
            "usage: skew-bench server <addr> <loops|rounds> [threads|pollers:workers]\n       \
             skew-bench client <addr> <conns> <depth> <work_us> <heavy_conns> <heavy_work_us> <secs>"
        ),
    }
}
