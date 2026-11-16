//! Measurement harness for io_uring features the engine does not use (test-only; see
//! docs/BENCHMARKS.md "io_uring features evaluation").
//!
//! A minimal HTTP/1.1 responder driven straight on [`Ring`]: multishot accept and recv with a
//! provided-buffer ring as in the reactor, and one fixed response (`EVAL_SIZE` body bytes) per
//! request (`\r\n\r\n`-terminated, no body: what `h2load --h1` sends). What changes between runs
//! is how the responses leave and how sockets are named:
//!
//! * `EVAL_MODE=write`: `write(2)` from the completion handler (the engine's way; one system
//!   call per connection and batch, `poll(POLLOUT)` when the socket is full);
//! * `EVAL_MODE=send`: `IORING_OP_SEND` entries, submitted together with the next wait;
//! * `EVAL_MODE=zc`: `IORING_OP_SEND_ZC` (zero-copy; a second, notification completion);
//! * `EVAL_FIXED=1` (send modes only): direct accept into a registered file table, and every
//!   entry names its socket by slot (`IOSQE_FIXED_FILE`).
//!
//! The responses come from one static buffer, so no mode ever waits for a buffer to be released
//! (the best case for `SEND_ZC`). `tools/bench/uring-eval.sh` runs the whole matrix; one server
//! by hand:
//!
//! ```sh
//! EVAL_ADDR=0.0.0.0:7600 EVAL_THREADS=4 EVAL_MODE=zc EVAL_SIZE=65536 EVAL_SECS=10 \
//!   cargo test -p only-uring --release --lib -- --ignored eval_server --nocapture
//! ```
//!
//! The registered ring fd and `MSG_RING` wake-ups were measured inside the engine itself (a
//! temporary patch of the reactor, A/B with the benchmark servers), not here.

use std::{
    collections::HashMap,
    io,
    net::TcpListener,
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

use only_sys::ffi;

use crate::reactor::{BGID, BUF_COUNT, BufRing, KernelBuf, make_ring};
use crate::ring::{Ring, Sqe, cqe_buffer, cqe_more, cqe_notif, notif_copied};

const OP_ACCEPT: u64 = 1;
const OP_RECV: u64 = 2;
const OP_SEND: u64 = 3;
const OP_POLL: u64 = 4;
const OP_OTHER: u64 = 5;
const TCP_NODELAY: i32 = 1;
const BUF_SIZE: usize = 4096;
/// Registered-file slots per ring (at most `RLIMIT_NOFILE`, 1024 by default).
const FILES: u32 = 1000;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Write,
    Send,
    Zc,
}

struct Conn {
    /// Descriptor, or registered-file slot with `fixed`.
    fd: i32,
    /// Response bytes owed, and how far into the current response we are.
    owed: u64,
    off: usize,
    /// Progress through `\r\n\r\n`.
    state: u8,
    send_inflight: bool,
    poll_inflight: bool,
    recv_armed: bool,
    dead: bool,
}

#[derive(Default, Debug)]
struct Counts {
    requests: u64,
    sends: u64,
    zc_notifs: u64,
    zc_copied: u64,
    enters: u64,
}

struct Server {
    ring: Ring,
    mode: Mode,
    fixed: bool,
    /// `K` responses back to back (static; one send takes up to `out.len() - off`).
    out: &'static [u8],
    resp: usize,
    conns: HashMap<u64, Conn>,
    next_id: u64,
    bufs: KernelBuf,
    buf_ring: BufRing,
    n: Counts,
}

fn ud(id: u64, op: u64) -> u64 {
    (id << 4) | op
}

impl Server {
    fn push(&mut self, e: Sqe) {
        loop {
            // SAFETY: entries refer to `out` (static), the provided buffers (owned by `self`,
            // leaked at the end rather than freed) or carry only integers.
            if unsafe { self.ring.push(&e) }.is_ok() {
                return;
            }
            let _ = self.ring.submit();
        }
    }

    fn sqe_fd(&self, e: Sqe) -> Sqe {
        if self.fixed { e.fixed() } else { e }
    }

    fn on_accept(&mut self, res: i32) {
        if res < 0 {
            return;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.conns.insert(
            id,
            Conn {
                fd: res,
                owed: 0,
                off: 0,
                state: 0,
                send_inflight: false,
                poll_inflight: false,
                recv_armed: true,
                dead: false,
            },
        );
        let e = self.sqe_fd(Sqe::recv_multi(res, BGID).user_data(ud(id, OP_RECV)));
        self.push(e);
    }

    fn on_recv(&mut self, id: u64, res: i32, flags: u32) {
        let bid = cqe_buffer(flags);
        let more = cqe_more(flags);
        let resp = self.resp as u64;
        if let Some(c) = self.conns.get_mut(&id) {
            if !more {
                c.recv_armed = false;
            }
            if res > 0 {
                if let Some(bid) = bid {
                    // SAFETY: the kernel handed buffer `bid` back in this completion and gets it
                    // again only below, after the last use of `data`.
                    let data = unsafe { self.bufs.slice(bid as usize * BUF_SIZE, res as usize) };
                    for &b in data {
                        c.state = match (c.state, b) {
                            (0 | 2, b'\r') => c.state + 1,
                            (1, b'\n') => 2,
                            (3, b'\n') => {
                                c.owed += resp;
                                self.n.requests += 1;
                                0
                            }
                            (_, b'\r') => 1,
                            _ => 0,
                        };
                    }
                }
            } else if res == -ffi::ENOBUFS {
                // Out of buffers: the multishot ended; re-armed below.
            } else {
                c.dead = true;
            }
        }
        if let Some(bid) = bid {
            self.buf_ring.give(&self.bufs, BUF_SIZE, bid);
            self.buf_ring.publish();
        }
        let rearm = match self.conns.get_mut(&id) {
            Some(c) if !c.recv_armed && !c.dead => {
                c.recv_armed = true;
                Some(c.fd)
            }
            _ => None,
        };
        if let Some(fd) = rearm {
            let e = self.sqe_fd(Sqe::recv_multi(fd, BGID).user_data(ud(id, OP_RECV)));
            self.push(e);
        }
        self.pump(id);
    }

    /// Sends what `id` owes (or closes it when it is dead and idle).
    fn pump(&mut self, id: u64) {
        let (out, resp, mode, fixed) = (self.out, self.resp, self.mode, self.fixed);
        loop {
            let Some(c) = self.conns.get_mut(&id) else {
                return;
            };
            if c.dead {
                if !c.send_inflight && !c.poll_inflight && !c.recv_armed {
                    let fd = c.fd;
                    self.conns.remove(&id);
                    if fixed {
                        self.push(Sqe::close_fixed(fd as u32).user_data(ud(0, OP_OTHER)));
                    } else {
                        // SAFETY: the connection's own descriptor; no entry refers to it now.
                        unsafe { ffi::close(fd) };
                    }
                }
                return;
            }
            if c.owed == 0 || c.send_inflight || c.poll_inflight {
                return;
            }
            let len = (c.owed as usize).min(out.len() - c.off);
            let ptr = out[c.off..].as_ptr();
            let fd = c.fd;
            self.n.sends += 1;
            if mode == Mode::Write {
                // SAFETY: `ptr..ptr + len` lies inside the static response buffer.
                let n = unsafe { ffi::write(fd, ptr.cast(), len) };
                if n > 0 {
                    c.owed -= n as u64;
                    c.off = (c.off + n as usize) % resp;
                    continue;
                }
                if n < 0 && io::Error::last_os_error().raw_os_error() == Some(ffi::EAGAIN) {
                    c.poll_inflight = true;
                    self.push(Sqe::poll_add(fd, ffi::POLLOUT as u32).user_data(ud(id, OP_POLL)));
                    return;
                }
                c.dead = true;
                continue;
            }
            c.send_inflight = true;
            let e = if mode == Mode::Zc {
                Sqe::send_zc(fd, ptr, len as u32)
            } else {
                Sqe::send(fd, ptr, len as u32)
            };
            let e = self.sqe_fd(e.user_data(ud(id, OP_SEND)));
            self.push(e);
            return;
        }
    }

    fn on_send(&mut self, id: u64, res: i32, flags: u32) {
        if cqe_notif(flags) {
            self.n.zc_notifs += 1;
            if notif_copied(res) {
                self.n.zc_copied += 1;
            }
            return;
        }
        let resp = self.resp;
        if let Some(c) = self.conns.get_mut(&id) {
            c.send_inflight = false;
            if res > 0 {
                c.owed -= res as u64;
                c.off = (c.off + res as usize) % resp;
            } else if res != -ffi::EAGAIN {
                c.dead = true;
            }
        }
        self.pump(id);
    }

    fn run(&mut self, listener: &TcpListener, until: Instant) -> io::Result<()> {
        let accept = if self.fixed {
            Sqe::accept_multi_direct(listener.as_raw_fd())
        } else {
            Sqe::accept_multi(listener.as_raw_fd())
        };
        self.push(accept.user_data(ud(0, OP_ACCEPT)));
        let mut cqes = Vec::with_capacity(4096);
        while Instant::now() < until {
            self.n.enters += 1;
            match self.ring.submit_with_timeout(1, Duration::from_millis(100)) {
                Ok(_) => {}
                Err(e) if matches!(e.raw_os_error(), Some(ffi::ETIME | ffi::EINTR)) => {}
                Err(e) => return Err(e),
            }
            cqes.clear();
            self.ring.reap_into(&mut cqes);
            for &(data, res, flags) in &cqes {
                let (id, op) = (data >> 4, data & 0xf);
                match op {
                    OP_ACCEPT => {
                        if !cqe_more(flags) {
                            self.push(accept.user_data(ud(0, OP_ACCEPT)));
                        }
                        self.on_accept(res);
                    }
                    OP_RECV => self.on_recv(id, res, flags),
                    OP_SEND => self.on_send(id, res, flags),
                    OP_POLL => {
                        if let Some(c) = self.conns.get_mut(&id) {
                            c.poll_inflight = false;
                        }
                        self.pump(id);
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

fn env<T: std::str::FromStr>(k: &str, d: T) -> T {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}

fn serve_thread(
    listener: TcpListener,
    mode: Mode,
    fixed: bool,
    out: &'static [u8],
    resp: usize,
    until: Instant,
) -> io::Result<Counts> {
    let (ring, needs_enable) = make_ring(4096, false)?;
    if needs_enable {
        ring.enable_rings()?;
    }
    if fixed {
        ring.register_files_sparse(FILES)?;
    }
    let bufs = KernelBuf::new(BUF_SIZE * BUF_COUNT as usize)?;
    let mut buf_ring = BufRing::new()?;
    buf_ring.register(&ring)?;
    for bid in 0..BUF_COUNT {
        buf_ring.give(&bufs, BUF_SIZE, bid);
    }
    buf_ring.publish();
    let mut s = Server {
        ring,
        mode,
        fixed,
        out,
        resp,
        conns: HashMap::new(),
        next_id: 1,
        bufs,
        buf_ring,
        n: Counts::default(),
    };
    let r = s.run(&listener, until);
    let n = std::mem::take(&mut s.n);
    // The kernel may still hold requests that point into the buffers: never free them (the
    // process ends right after the measurement).
    std::mem::forget(s);
    r.map(|()| n)
}

#[test]
#[ignore = "benchmark server; run by hand on the benchmark host (see the module docs)"]
fn eval_server() {
    let addr: std::net::SocketAddr = env("EVAL_ADDR", "0.0.0.0:7600".parse().unwrap());
    let threads: usize = env("EVAL_THREADS", 4);
    let size: usize = env("EVAL_SIZE", 13);
    let secs: u64 = env("EVAL_SECS", 10);
    let fixed = env("EVAL_FIXED", 0u8) == 1;
    let mode = match std::env::var("EVAL_MODE").as_deref() {
        Ok("send") => Mode::Send,
        Ok("zc") => Mode::Zc,
        _ => Mode::Write,
    };
    assert!(
        !(fixed && mode == Mode::Write),
        "EVAL_FIXED needs a send mode"
    );
    let mut one = format!(
        "HTTP/1.1 200 OK\r\nServer: e\r\nContent-Type: text/plain\r\nContent-Length: {size}\r\n\r\n"
    )
    .into_bytes();
    one.resize(one.len() + size, b'a');
    let resp = one.len();
    let k = (1usize << 20).div_ceil(resp).clamp(1, 16);
    let out: &'static [u8] = Vec::leak(one.repeat(k));
    let until = Instant::now() + Duration::from_secs(secs);
    let mut handles = Vec::new();
    for _ in 0..threads {
        let l = only_sys::listen(addr, true, 4096).expect("listen");
        let one: i32 = 1;
        // SAFETY: sets an int option on the listener from a live `i32` (accepted sockets
        // inherit `TCP_NODELAY`).
        unsafe {
            ffi::setsockopt(
                l.as_raw_fd(),
                ffi::IPPROTO_TCP,
                TCP_NODELAY,
                (&raw const one).cast(),
                4,
            )
        };
        handles.push(std::thread::spawn(move || {
            serve_thread(l, mode, fixed, out, resp, until)
        }));
    }
    eprintln!("eval_server: listening on {addr}");
    let mut total = Counts::default();
    for h in handles {
        let n = match h.join().expect("thread") {
            Ok(n) => n,
            Err(e) => panic!("eval_server: serve failed: {e}"),
        };
        total.requests += n.requests;
        total.sends += n.sends;
        total.zc_notifs += n.zc_notifs;
        total.zc_copied += n.zc_copied;
        total.enters += n.enters;
    }
    eprintln!("eval_server: {total:?}");
}
