//! A CPU-bound request/response benchmark for comparing the two scheduling modes (ADR-104).
//!
//! ```text
//! skew-bench server <addr> <loops|rounds> [threads|pollers:workers]
//! skew-bench client <addr> <conns> <depth> <work_us> <heavy_conns> <heavy_work_us> <secs>
//! skew-bench churn <addr> <conns> <requests_per_conn> <secs>
//! skew-bench rate <addr> <conns> <requests_per_sec> <secs>
//! ```
//!
//! `churn` keeps `conns` short-lived connections busy: each connects, sends `requests_per_conn`
//! requests one at a time and closes, then starts over (like HttpArena's `limited-conn` and
//! `echo-ws-limited`). `rate` sends a fixed total rate of requests spread over `conns` open
//! connections (like `latency-10k`); measure the server's CPU from outside to get the cost per
//! request at light load.
//!
//! Every request is 16 bytes (`work_us: u32`, `picked_us: u32`, `sent_ns: u64` of the system
//! clock); the server spins `work_us` microseconds of CPU in `on_data` and echoes the request,
//! with `picked_us` set to how long the request took from the client's send to the start of its
//! `on_data` (same host, same clock). So the client splits each latency into the way there
//! (`to_srv`: network, queueing, scheduling) and the way back (`back`: work, write, the client
//! thread's own wake-up). The client keeps `depth`
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

/// Nanoseconds of the system clock (shared by client and server processes on one host).
fn unix_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

/// Spins for `us` microseconds.
fn spin(us: u32) {
    if us == 0 {
        return;
    }
    let until = Instant::now() + Duration::from_micros(u64::from(us));
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
        for f in self.buf[..whole].chunks_exact_mut(FRAME) {
            let sent = u64::from_le_bytes(f[8..].try_into().expect("8 bytes"));
            let picked = (unix_ns().saturating_sub(sent) / 1000).min(u64::from(u32::MAX)) as u32;
            f[4..8].copy_from_slice(&picked.to_le_bytes());
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
                .map_or((0, 0), |(p, w)| {
                    (p.parse().unwrap_or(0), w.parse().unwrap_or(0))
                });
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
    to_srv: Vec<u64>,
    back: Vec<u64>,
    /// How long the client's own `write` of a request took (on loopback it delivers the data).
    send: Vec<u64>,
    light: Vec<u64>,
    done: u64,
}

#[allow(clippy::too_many_arguments)]
fn conn_loop(
    addr: SocketAddr,
    depth: usize,
    work: u32,
    heavy: bool,
    _epoch: Instant,
    warm: Instant,
    stop: Arc<AtomicBool>,
) -> Stats {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_nodelay(true).ok();
    let mut r = s.try_clone().expect("clone");
    let frame = |now: Instant| {
        let mut f = [0u8; FRAME];
        f[..4].copy_from_slice(&work.to_le_bytes());
        let _ = now;
        f[8..].copy_from_slice(&unix_ns().to_le_bytes());
        f
    };
    let mut out = Vec::with_capacity(depth * FRAME);
    for _ in 0..depth {
        out.extend_from_slice(&frame(Instant::now()));
    }
    s.write_all(&out).expect("write");
    let mut st = Stats {
        lat: Vec::new(),
        to_srv: Vec::new(),
        back: Vec::new(),
        send: Vec::new(),
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
            let ns = unix_ns().saturating_sub(sent);
            let to = u64::from(u32::from_le_bytes(f[4..8].try_into().expect("4 bytes"))) * 1000;
            st.lat.push(ns);
            st.to_srv.push(to);
            st.back.push(ns.saturating_sub(to));
            if !heavy {
                st.light.push(ns);
            }
            st.done += 1;
        }
        let t0 = unix_ns();
        if s.write_all(&frame(now)).is_err() {
            break;
        }
        if now >= warm {
            st.send.push(unix_ns().saturating_sub(t0));
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
    let (mut to_srv, mut back, mut send) = (Vec::new(), Vec::new(), Vec::new());
    let mut per_conn = Vec::new();
    for h in hs {
        let st = h.join().expect("join");
        per_conn.push(st.done);
        done += st.done;
        lat.extend(st.lat);
        light.extend(st.light);
        to_srv.extend(st.to_srv);
        back.extend(st.back);
        send.extend(st.send);
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
    println!(
        "  split: to_srv p50={:.0}us p99={:.0}us p999={:.0}us | back p50={:.0}us p99={:.0}us p999={:.0}us | client write p50={:.0}us p99={:.0}us p999={:.0}us",
        pct(&mut to_srv, 0.5),
        pct(&mut to_srv, 0.99),
        pct(&mut to_srv, 0.999),
        pct(&mut back, 0.5),
        pct(&mut back, 0.99),
        pct(&mut back, 0.999),
        pct(&mut send, 0.5),
        pct(&mut send, 0.99),
        pct(&mut send, 0.999),
    );
}

/// A zero-work request frame stamped with the system clock.
fn plain_frame() -> [u8; FRAME] {
    let mut f = [0u8; FRAME];
    f[8..].copy_from_slice(&unix_ns().to_le_bytes());
    f
}

fn churn(args: &[String]) {
    let addr: SocketAddr = args[0].parse().expect("addr");
    let conns: usize = args[1].parse().expect("conns");
    let reqs: usize = args[2].parse().expect("requests_per_conn");
    let secs: u64 = args[3].parse().expect("secs");
    let warm = Instant::now() + Duration::from_secs(1);
    let stop = Arc::new(AtomicBool::new(false));
    let hs: Vec<_> = (0..conns)
        .map(|_| {
            let stop = stop.clone();
            thread::spawn(move || {
                let (mut done, mut opened, mut failed) = (0u64, 0u64, 0u64);
                let mut lat = Vec::new();
                let mut f = [0u8; FRAME];
                'conn: while !stop.load(Ordering::Relaxed) {
                    let Ok(mut s) = TcpStream::connect(addr) else {
                        failed += 1;
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    };
                    s.set_nodelay(true).ok();
                    let counted = Instant::now() >= warm;
                    for _ in 0..reqs {
                        let t0 = Instant::now();
                        if s.write_all(&plain_frame()).is_err() || s.read_exact(&mut f).is_err() {
                            failed += 1;
                            continue 'conn;
                        }
                        if counted {
                            lat.push(t0.elapsed().as_nanos() as u64);
                            done += 1;
                        }
                    }
                    if counted {
                        opened += 1;
                    }
                }
                (done, opened, failed, lat)
            })
        })
        .collect();
    thread::sleep(Duration::from_secs(1 + secs));
    stop.store(true, Ordering::Relaxed);
    let (mut done, mut opened, mut failed, mut lat) = (0, 0, 0, Vec::new());
    for h in hs {
        let (d, o, f, l) = h.join().expect("join");
        done += d;
        opened += o;
        failed += f;
        lat.extend(l);
    }
    println!(
        "rps={:.0} conns_per_s={:.0} failed={failed} p50={:.0}us p99={:.0}us",
        done as f64 / secs as f64,
        opened as f64 / secs as f64,
        pct(&mut lat, 0.5),
        pct(&mut lat, 0.99),
    );
}

fn rate(args: &[String]) {
    let addr: SocketAddr = args[0].parse().expect("addr");
    let conns: usize = args[1].parse().expect("conns");
    let rate: f64 = args[2].parse().expect("requests_per_sec");
    let secs: u64 = args[3].parse().expect("secs");
    let threads = conns.clamp(1, 16);
    let interval = Duration::from_secs_f64(threads as f64 / rate);
    let start = Instant::now() + Duration::from_millis(500);
    let warm = start + Duration::from_secs(1);
    let end = warm + Duration::from_secs(secs);
    let hs: Vec<_> = (0..threads)
        .map(|t| {
            let mine = (t..conns).step_by(threads).count();
            thread::spawn(move || {
                let mut ss: Vec<TcpStream> = (0..mine)
                    .map(|_| {
                        let s = TcpStream::connect(addr).expect("connect");
                        s.set_nodelay(true).ok();
                        s
                    })
                    .collect();
                let mut lat = Vec::new();
                let mut f = [0u8; FRAME];
                // Threads start staggered so the total rate is even.
                let mut next = start + interval.mul_f64(t as f64 / threads as f64);
                let mut i = 0;
                while next < end {
                    let now = Instant::now();
                    if next > now {
                        thread::sleep(next - now);
                    }
                    let s = &mut ss[i % mine];
                    i += 1;
                    let t0 = Instant::now();
                    s.write_all(&plain_frame()).expect("write");
                    s.read_exact(&mut f).expect("read");
                    if t0 >= warm {
                        lat.push(t0.elapsed().as_nanos() as u64);
                    }
                    next += interval;
                }
                lat
            })
        })
        .collect();
    let mut lat = Vec::new();
    for h in hs {
        lat.extend(h.join().expect("join"));
    }
    println!(
        "done={} rps={:.0} p50={:.0}us p99={:.0}us p999={:.0}us",
        lat.len(),
        lat.len() as f64 / secs as f64,
        pct(&mut lat, 0.5),
        pct(&mut lat, 0.99),
        pct(&mut lat, 0.999),
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
        Some("churn") if args.len() >= 5 => churn(&args[1..]),
        Some("rate") if args.len() >= 5 => rate(&args[1..]),
        _ => eprintln!(
            "usage: skew-bench server <addr> <loops|rounds> [threads|pollers:workers]\n       \
             skew-bench client <addr> <conns> <depth> <work_us> <heavy_conns> <heavy_work_us> <secs>\n       \
             skew-bench churn <addr> <conns> <requests_per_conn> <secs>\n       \
             skew-bench rate <addr> <conns> <requests_per_sec> <secs>"
        ),
    }
}
