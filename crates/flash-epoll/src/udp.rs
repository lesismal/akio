//! UDP: one loop per socket; every distinct peer address is a connection (`Conn`) with its own
//! handler, created on its first datagram and dropped after `Config::udp_idle_timeout` of silence.
//! `on_data` is called once per datagram, so message boundaries are preserved, and `send` sends
//! one datagram.
//!
//! A loop can also own *client* connections (`Cmd::DialUdp`): each has its own `connect`ed socket
//! (so its own local port, and ICMP "port unreachable" surfaces as a connection error) registered
//! in the poller under the connection id.
//!
//! Batching (Linux): datagrams are read with `recvmmsg` (server and dialed sockets alike). While
//! one receive batch is handled, the peers it touches are corked; at its end everything they sent
//! leaves together in as few `sendmmsg` calls as possible, and runs of equal-size datagrams to one
//! peer go out as a single UDP GSO send where the kernel supports it (`Conn::send_segments` asks
//! for that explicitly). With `Config::udp_gro`, coalesced GRO receives are split back into one
//! `on_data` per datagram. `Config::udp_max_peers` caps the peers of a listener.
//!
//! io_uring: a UDP listener on the io_uring backend is served here. With `recvmmsg`/`sendmmsg`/GSO
//! the syscall cost is already one per batch, so a ring buys little; a multishot `recvmsg` with
//! provided buffers (per-datagram headers in the buffer, GRO control data) would be a second
//! implementation of the same batching for no measurable gain, so it is not done for now.

use std::{
    collections::{HashMap, HashSet},
    io,
    net::{SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use flash_core::{
    Config, ConnInfo, ConnInner, DynAcceptor, DynHandler, Error, Group, LoopMeta, Pool, Task,
    UdpStats, telemetry::LoopCmd,
};
use flash_sys::{Event, Poller};
use flash_timer::{TimerId, Wheel};

use crate::reactor::{Cmd, LoopShared};

const WAKER: u64 = 0;
const SOCK: u64 = 1;
/// Datagrams taken from the socket per `recvmmsg`.
const BATCH: usize = 32;
const MAX_BATCHES_PER_EVENT: usize = 8;

static NEXT_ID: AtomicU64 = AtomicU64::new(1 << 40);

struct Peer {
    /// The connection's own connected socket (dialed clients); `None` for peers of the shared
    /// server socket.
    own: Option<Arc<UdpSocket>>,
    /// Write interest is registered for `own`.
    write_reg: bool,
    acceptor: Arc<dyn DynAcceptor>,
    inner: Arc<ConnInner>,
    handler: Box<dyn DynHandler>,
    addr: SocketAddr,
    last_active: u64,
    timer: Option<TimerId>,
    /// Tick when it opened, and bytes received (connection table).
    opened: u64,
    bytes_in: u64,
    /// Corked for the receive batch being processed (its replies leave together at the end).
    in_batch: bool,
}

/// Counters shared by the loops of one UDP group.
#[derive(Default)]
struct Stats {
    peers: AtomicUsize,
    rejected: AtomicU64,
}

struct UdpLoop {
    poller: Poller,
    shared: Arc<LoopShared>,
    /// The shared server socket (absent in a client-only group).
    sock: Option<Arc<UdpSocket>>,
    local: Option<SocketAddr>,
    acceptor: Option<Arc<dyn DynAcceptor>>,
    peers: HashMap<SocketAddr, u64>,
    conns: flash_core::IdMap<Peer>,
    /// Server-socket peers with datagrams waiting for socket space.
    blocked: HashSet<u64>,
    /// Dialed connections with datagrams waiting for socket space.
    blocked_own: HashSet<u64>,
    want_write: bool,
    /// Receive buffers, shared by the server socket and dialed sockets (created on first use).
    #[cfg(target_os = "linux")]
    batch: Option<flash_sys::RecvBatch>,
    #[cfg(not(target_os = "linux"))]
    scratch: Option<Vec<u8>>,
    /// Server-socket peers corked while the current receive batch is processed.
    touched: Vec<u64>,
    flush_out: Vec<io::Result<bool>>,
    stats: Arc<Stats>,
    cfg: Arc<Config>,
    draining: Option<Instant>,
    wheel: Wheel<u64>,
    epoch: Instant,
}

/// GRO is opt-in (`Config::udp_gro`) and coalesces up to 64 KiB into one receive: only safe
/// when a slot can hold that.
#[cfg(target_os = "linux")]
fn gro_ok(cfg: &Config) -> bool {
    cfg.udp_gro && cfg.read_buffer >= 65535 && flash_sys::gro_available()
}

#[cfg(target_os = "linux")]
fn new_batch(cfg: &Config) -> flash_sys::RecvBatch {
    flash_sys::RecvBatch::with_gro(BATCH, cfg.read_buffer, gro_ok(cfg))
}

fn panic_error() -> Error {
    Error::Io(io::Error::other("handler panicked"))
}

impl UdpLoop {
    fn new(
        poller: Poller,
        shared: Arc<LoopShared>,
        server: Option<(UdpSocket, Arc<dyn DynAcceptor>)>,
        cfg: Arc<Config>,
        stats: Arc<Stats>,
    ) -> io::Result<UdpLoop> {
        let (sock, local, acceptor) = match server {
            Some((sock, acceptor)) => {
                sock.set_nonblocking(true)?;
                #[cfg(target_os = "linux")]
                if gro_ok(&cfg) {
                    flash_sys::enable_gro(sock.as_raw_fd());
                }
                poller.add(sock.as_raw_fd(), SOCK, true, false)?;
                let local = sock.local_addr()?;
                (Some(Arc::new(sock)), Some(local), Some(acceptor))
            }
            None => (None, None, None),
        };
        let sock_present = sock.is_some();
        Ok(UdpLoop {
            poller,
            shared,
            sock,
            local,
            acceptor,
            peers: HashMap::new(),
            conns: Default::default(),
            blocked: HashSet::new(),
            blocked_own: HashSet::new(),
            want_write: false,
            #[cfg(target_os = "linux")]
            batch: sock_present.then(|| new_batch(&cfg)),
            #[cfg(not(target_os = "linux"))]
            scratch: sock_present.then(|| vec![0; cfg.read_buffer]),
            touched: Vec::new(),
            flush_out: Vec::new(),
            stats,
            cfg,
            draining: None,
            wheel: Wheel::new(0),
            epoch: Instant::now(),
        })
    }

    fn tick(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    fn idle_ms(&self) -> u64 {
        let d = self
            .cfg
            .idle_timeout
            .map_or(self.cfg.udp_idle_timeout, |i| {
                i.min(self.cfg.udp_idle_timeout)
            });
        d.as_millis().max(1) as u64
    }

    fn run(&mut self) {
        self.run_inner();
        self.shared.stats.set_running(false);
        drop(self.shared.take());
    }

    fn run_inner(&mut self) {
        crate::reactor::set_current_loop(&self.shared);
        let mut events: Vec<Event> = Vec::with_capacity(64);
        loop {
            let mut timeout = self.draining.map(|_| Duration::from_millis(50));
            if let Some(next) = self.wheel.next_deadline() {
                let wait = Duration::from_millis(next.saturating_sub(self.tick()) + 1);
                timeout = Some(timeout.map_or(wait, |t| t.min(wait)));
            }
            events.clear();
            if let Err(e) = self.poller.wait(&mut events, timeout) {
                eprintln!("flash: poller error: {e}");
                break;
            }
            self.shared.stats.iterations.add_local(1);
            self.shared.stats.events.add_local(events.len() as u64);
            for ev in &events {
                match ev.token {
                    WAKER => self.shared.waker().drain(),
                    SOCK => {
                        if ev.readable {
                            self.on_readable();
                        }
                        if ev.writable {
                            self.flush_blocked();
                        }
                    }
                    id => {
                        if ev.readable {
                            self.on_client_readable(id);
                        }
                        if ev.writable {
                            self.on_wake(id);
                        }
                    }
                }
            }
            self.drain_cmds();
            self.fire_timers();
            if let Some(deadline) = self.draining {
                // Datagrams have no stream to drain: once handlers had their `on_shutdown` and
                // nothing is waiting for socket space, everything left is closed.
                if (self.blocked.is_empty() && self.blocked_own.is_empty())
                    || Instant::now() >= deadline
                {
                    let ids: Vec<u64> = self.conns.keys().copied().collect();
                    for id in ids {
                        self.finalize(id, None);
                    }
                    break;
                }
            }
        }
    }

    // ---- receive --------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    fn on_readable(&mut self) {
        let Some(sock) = self.sock.clone() else {
            return;
        };
        let mut batch = self.batch.take().unwrap_or_else(|| new_batch(&self.cfg));
        let fd = sock.as_raw_fd();
        for _ in 0..MAX_BATCHES_PER_EVENT {
            let n = match batch.recv(fd) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    eprintln!("flash: recvmmsg: {e}");
                    break;
                }
            };
            for i in 0..n {
                if let Some((data, peer, seg)) = batch.get(i) {
                    if seg > 0 && seg < data.len() {
                        // GRO coalesced several datagrams of this peer: restore the boundaries.
                        for d in data.chunks(seg) {
                            self.on_datagram(peer, d);
                        }
                    } else {
                        self.on_datagram(peer, data);
                    }
                }
            }
            // Everything the handlers sent for this batch leaves in as few sendmmsg as possible.
            self.flush_touched();
            if n < BATCH {
                break;
            }
        }
        self.batch = Some(batch);
    }

    /// Uncorks the peers corked during a receive batch and flushes them together.
    fn flush_touched(&mut self) {
        if self.touched.is_empty() {
            return;
        }
        let mut ids = std::mem::take(&mut self.touched);
        ids.retain(|id| match self.conns.get_mut(id) {
            Some(p) => {
                p.in_batch = false;
                true
            }
            None => false,
        });
        let inners: Vec<Arc<ConnInner>> =
            ids.iter().map(|id| self.conns[id].inner.clone()).collect();
        let refs: Vec<&ConnInner> = inners.iter().map(|i| &**i).collect();
        let mut out = std::mem::take(&mut self.flush_out);
        ConnInner::flush_datagram_peers(&refs, &mut out);
        drop(refs);
        drop(inners);
        for (&id, r) in ids.iter().zip(out.drain(..)) {
            self.after_flush(id, r);
        }
        self.flush_out = out;
        ids.clear();
        self.touched = ids;
    }

    #[cfg(not(target_os = "linux"))]
    fn on_readable(&mut self) {
        let Some(sock) = self.sock.clone() else {
            return;
        };
        let mut buf = self.scratch.take().expect("scratch present");
        for _ in 0..MAX_BATCHES_PER_EVENT * BATCH {
            match sock.recv_from(&mut buf) {
                Ok((n, peer)) => self.on_datagram(peer, &buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    eprintln!("flash: recv_from: {e}");
                    break;
                }
            }
        }
        self.scratch = Some(buf);
        self.flush_touched();
    }

    fn on_datagram(&mut self, peer: SocketAddr, data: &[u8]) {
        if self.draining.is_some() {
            return;
        }
        let id = match self.peers.get(&peer) {
            Some(&id) => id,
            None => match self.open(peer) {
                Some(id) => id,
                None => return,
            },
        };
        let t0 = self.cfg.telemetry.timing();
        let now = self.tick();
        let Some(p) = self.conns.get_mut(&id) else {
            return;
        };
        p.last_active = now;
        p.bytes_in += data.len() as u64;
        self.shared.stats.datagram_in(data.len());
        if cfg!(target_os = "linux") && !p.in_batch {
            // Replies wait for the end of the receive batch (see `flush_touched`).
            p.in_batch = true;
            p.inner.set_corked(true);
            self.touched.push(id);
        }
        let r = catch_unwind(AssertUnwindSafe(|| p.handler.on_data(data)));
        self.check_slow("on_data", id, t0);
        if r.is_err() {
            self.finalize(id, Some(panic_error()));
        }
    }

    fn open(&mut self, peer: SocketAddr) -> Option<u64> {
        let (sock, local, acceptor) = (self.sock.clone()?, self.local?, self.acceptor.clone()?);
        // Admission: `udp_max_peers` bounds the peers of the whole listener (all its loops).
        let before = self.stats.peers.fetch_add(1, Ordering::Relaxed);
        if self.cfg.udp_max_peers.is_some_and(|max| before >= max) {
            self.stats.peers.fetch_sub(1, Ordering::Relaxed);
            self.stats.rejected.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        self.cfg.telemetry.conn_opened(false);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let inner = ConnInner::new_udp(
            id,
            sock,
            false,
            local,
            peer,
            self.shared.clone(),
            self.cfg.clone(),
        );
        let Ok(handler) = catch_unwind(AssertUnwindSafe(|| acceptor.on_open(&inner))) else {
            self.stats.peers.fetch_sub(1, Ordering::Relaxed);
            inner.mark_closed();
            self.cfg.telemetry.conn_closed();
            return None;
        };
        self.shared.stats.accepted.add_local(1);
        let now = self.tick();
        if self.wheel.is_empty() {
            self.wheel.advance(now, drop);
        }
        let timer = Some(self.wheel.schedule(now + self.idle_ms(), id));
        self.peers.insert(peer, id);
        self.conns.insert(
            id,
            Peer {
                own: None,
                write_reg: false,
                acceptor,
                inner,
                handler,
                addr: peer,
                last_active: now,
                timer,
                opened: now,
                bytes_in: 0,
                in_batch: false,
            },
        );
        // `on_open` may already have queued datagrams or closed the connection.
        self.on_wake(id);
        self.conns.contains_key(&id).then_some(id)
    }

    // ---- dialed clients -------------------------------------------------------------------

    fn open_client(&mut self, sock: UdpSocket, acceptor: Arc<dyn DynAcceptor>) {
        if self.draining.is_some() {
            return;
        }
        let (Ok(local), Ok(peer)) = (sock.local_addr(), sock.peer_addr()) else {
            return;
        };
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        #[cfg(target_os = "linux")]
        if gro_ok(&self.cfg) {
            flash_sys::enable_gro(sock.as_raw_fd());
        }
        if self.poller.add(sock.as_raw_fd(), id, true, false).is_err() {
            return;
        }
        let sock = Arc::new(sock);
        let inner = ConnInner::new_udp(
            id,
            sock.clone(),
            true,
            local,
            peer,
            self.shared.clone(),
            self.cfg.clone(),
        );
        let acc = acceptor.clone();
        let Ok(handler) = catch_unwind(AssertUnwindSafe(|| acc.on_open(&inner))) else {
            self.poller.delete(sock.as_raw_fd());
            inner.mark_closed();
            return;
        };
        self.cfg.telemetry.conn_opened(false);
        self.shared.stats.dialed.add_local(1);
        let now = self.tick();
        if self.wheel.is_empty() {
            self.wheel.advance(now, drop);
        }
        let timer = Some(self.wheel.schedule(now + self.idle_ms(), id));
        self.conns.insert(
            id,
            Peer {
                own: Some(sock),
                write_reg: false,
                acceptor,
                inner,
                handler,
                addr: peer,
                last_active: now,
                timer,
                opened: now,
                bytes_in: 0,
                in_batch: false,
            },
        );
        self.on_wake(id);
    }

    /// Datagrams arrived on a dialed connection's own socket.
    #[cfg(target_os = "linux")]
    fn on_client_readable(&mut self, id: u64) {
        let Some(p) = self.conns.get(&id) else {
            return;
        };
        let Some(sock) = p.own.clone() else {
            return;
        };
        // Replies to the whole batch leave together, in one sendmmsg (see `on_wake`).
        p.inner.set_corked(true);
        let mut batch = self.batch.take().unwrap_or_else(|| new_batch(&self.cfg));
        let mut err = None;
        'recv: for _ in 0..MAX_BATCHES_PER_EVENT {
            let n = match batch.recv(sock.as_raw_fd()) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                // ICMP "port unreachable" from the peer (or another socket error): it is over.
                Err(e) => {
                    err = Some(e);
                    break;
                }
            };
            for i in 0..n {
                let Some((data, _, seg)) = batch.get(i) else {
                    continue;
                };
                let seg = if seg > 0 { seg } else { data.len().max(1) };
                for d in data.chunks(seg) {
                    if !self.deliver(id, d) {
                        break 'recv;
                    }
                }
            }
            if n < BATCH {
                break;
            }
        }
        self.batch = Some(batch);
        if let Some(e) = err {
            self.finalize(id, Some(Error::Io(e)));
        } else if let Some(p) = self.conns.get(&id) {
            p.inner.set_corked(false);
            self.on_wake(id);
        }
    }

    /// Datagrams arrived on a dialed connection's own socket.
    #[cfg(not(target_os = "linux"))]
    fn on_client_readable(&mut self, id: u64) {
        let Some(sock) = self.conns.get(&id).and_then(|p| p.own.clone()) else {
            return;
        };
        let mut buf = self
            .scratch
            .take()
            .unwrap_or_else(|| vec![0u8; self.cfg.read_buffer]);
        for _ in 0..MAX_BATCHES_PER_EVENT * BATCH {
            match sock.recv(&mut buf) {
                Ok(n) => {
                    if !self.deliver(id, &buf[..n]) {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                // ICMP "port unreachable" from the peer (or another socket error): it is over.
                Err(e) => {
                    self.scratch = Some(buf);
                    self.finalize(id, Some(Error::Io(e)));
                    return;
                }
            }
        }
        self.scratch = Some(buf);
    }

    /// One datagram for dialed connection `id`. `false` when the connection is gone.
    fn deliver(&mut self, id: u64, data: &[u8]) -> bool {
        let t0 = self.cfg.telemetry.timing();
        let now = self.tick();
        let Some(p) = self.conns.get_mut(&id) else {
            return false;
        };
        p.last_active = now;
        p.bytes_in += data.len() as u64;
        self.shared.stats.datagram_in(data.len());
        let r = catch_unwind(AssertUnwindSafe(|| p.handler.on_data(data)));
        self.check_slow("on_data", id, t0);
        if r.is_err() {
            self.finalize(id, Some(panic_error()));
            return false;
        }
        true
    }

    // ---- writing --------------------------------------------------------------------------

    /// Flushes queued datagrams, applies `close_after_send`, tracks whether the socket is full.
    fn on_wake(&mut self, id: u64) {
        let Some(p) = self.conns.get_mut(&id) else {
            return;
        };
        let flushed = p.inner.flush_queue();
        self.after_flush(id, flushed);
    }

    /// Applies the outcome of flushing `id`: close on error or after `close_after_send`, and
    /// track whether it waits for socket space.
    fn after_flush(&mut self, id: u64, flushed: io::Result<bool>) {
        let Some(p) = self.conns.get(&id) else {
            return;
        };
        let own = p.own.clone();
        match flushed {
            Err(e) => self.finalize(id, Some(Error::Io(e))),
            Ok(empty) => {
                if empty && p.inner.close_after_send_requested() {
                    self.finalize(id, None);
                    return;
                }
                match own {
                    Some(sock) => {
                        if empty {
                            self.blocked_own.remove(&id);
                        } else {
                            self.blocked_own.insert(id);
                        }
                        if let Some(p) = self.conns.get_mut(&id) {
                            if p.write_reg == empty {
                                p.write_reg = !empty;
                                let _ = self.poller.modify(sock.as_raw_fd(), id, true, !empty);
                            }
                        }
                    }
                    None => {
                        if empty {
                            self.blocked.remove(&id);
                        } else {
                            self.blocked.insert(id);
                        }
                        self.update_interest();
                    }
                }
            }
        }
    }

    fn flush_blocked(&mut self) {
        let ids: Vec<u64> = self.blocked.iter().copied().collect();
        for id in ids {
            self.on_wake(id);
        }
    }

    fn update_interest(&mut self) {
        let want = !self.blocked.is_empty();
        if want != self.want_write {
            self.want_write = want;
            if let Some(sock) = &self.sock {
                let _ = self
                    .poller
                    .modify(sock.as_raw_fd(), SOCK, self.draining.is_none(), want);
            }
        }
    }

    // ---- lifecycle ------------------------------------------------------------------------

    fn finalize(&mut self, id: u64, err: Option<Error>) {
        let Some(mut p) = self.conns.remove(&id) else {
            return;
        };
        match &p.own {
            Some(sock) => {
                self.poller.delete(sock.as_raw_fd());
                self.blocked_own.remove(&id);
            }
            None => {
                self.peers.remove(&p.addr);
                self.blocked.remove(&id);
                self.stats.peers.fetch_sub(1, Ordering::Relaxed);
            }
        }
        if let Some(t) = p.timer.take() {
            self.wheel.cancel(t);
        }
        p.inner.mark_closed();
        let t0 = self.cfg.telemetry.timing();
        let _ = catch_unwind(AssertUnwindSafe(|| p.handler.on_close(err)));
        self.check_slow("on_close", id, t0);
        self.shared.stats.closed.add_local(1);
        self.cfg.telemetry.conn_closed();
        self.update_interest();
    }

    fn drain_cmds(&mut self) {
        loop {
            let cmds = self.shared.take();
            if cmds.is_empty() {
                return;
            }
            for cmd in cmds {
                match cmd {
                    Cmd::Wake(id) => self.on_wake(id),
                    Cmd::Close(id, err) => self.finalize(id, err.map(Error::Io)),
                    Cmd::Task(id, task) => self.on_task(id, task),
                    Cmd::Shutdown => self.begin_shutdown(),
                    Cmd::Core(LoopCmd::Inspect(reply)) => reply(self.inspect()),
                    Cmd::Core(LoopCmd::Reload) => {}
                    Cmd::DialUdp { sock, acceptor } => self.open_client(sock, acceptor),
                    Cmd::Dial { on_error, .. } => on_error(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "dial is not supported on a UDP listener",
                    )),
                }
            }
        }
    }

    /// The connection table rows of this loop.
    fn inspect(&self) -> Vec<ConnInfo> {
        let now = self.tick();
        self.conns
            .iter()
            .map(|(&id, p)| {
                let (bytes_out, queued_bytes, transport, udp) = p.inner.debug_state();
                ConnInfo {
                    id,
                    peer: p.addr,
                    local: p.inner.local_addr(),
                    owner: self.shared.stats.meta().clone(),
                    age: Duration::from_millis(now.saturating_sub(p.opened)),
                    idle: Duration::from_millis(now.saturating_sub(p.last_active)),
                    bytes_in: p.bytes_in,
                    bytes_out,
                    queued_bytes,
                    read_held: p.inner.read_held(),
                    backpressure: false,
                    transport,
                    udp,
                }
            })
            .collect()
    }

    fn begin_shutdown(&mut self) {
        if self.draining.is_some() {
            return;
        }
        self.draining = Some(Instant::now() + self.cfg.telemetry.live().shutdown_timeout());
        if let Some(sock) = &self.sock {
            self.poller.delete(sock.as_raw_fd());
            // Re-add for writing only if something is still waiting for socket space.
            self.want_write = false;
            if !self.blocked.is_empty() {
                let _ = self.poller.add(sock.as_raw_fd(), SOCK, false, true);
                self.want_write = true;
            }
        }
        let ids: Vec<u64> = self.conns.keys().copied().collect();
        for id in ids {
            let Some(p) = self.conns.get(&id) else {
                continue;
            };
            let (acc, inner) = (p.acceptor.clone(), p.inner.clone());
            if catch_unwind(AssertUnwindSafe(|| acc.on_shutdown(&inner))).is_err() {
                self.finalize(id, Some(panic_error()));
            } else {
                self.on_wake(id); // flush whatever on_shutdown sent
            }
        }
    }

    fn on_task(&mut self, id: u64, task: Task) {
        let t0 = self.cfg.telemetry.timing();
        let Some(p) = self.conns.get_mut(&id) else {
            return; // peer dropped meanwhile: the completion is skipped
        };
        let r = catch_unwind(AssertUnwindSafe(|| p.handler.run_task(task)));
        self.check_slow("spawn_blocking completion", id, t0);
        match r {
            Ok(()) => self.on_wake(id),
            Err(_) => self.finalize(id, Some(panic_error())),
        }
    }

    fn fire_timers(&mut self) {
        let idle = self.idle_ms();
        let now = self.tick();
        let mut due = Vec::new();
        self.wheel.advance(now, |id| due.push(id));
        for id in due {
            let Some(p) = self.conns.get_mut(&id) else {
                continue;
            };
            p.timer = None;
            let expires = p.last_active + idle;
            if expires <= now {
                self.shared.stats.idle_timeouts.add_local(1);
                let e = io::Error::new(io::ErrorKind::TimedOut, "idle timeout");
                self.finalize(id, Some(Error::Io(e)));
            } else {
                p.timer = Some(self.wheel.schedule(expires, id));
            }
        }
    }

    fn check_slow(&self, kind: &'static str, id: u64, started: Option<Instant>) {
        self.cfg
            .telemetry
            .callback_done(&self.shared.stats, kind, id, started);
    }
}

/// A group of UDP loops serving one address.
pub struct UdpGroup {
    addr: SocketAddr,
    /// Server socket fds in loop order when they form a `SO_REUSEPORT` group (Linux).
    fds: Vec<i32>,
    shared: Vec<Arc<LoopShared>>,
    pending: Mutex<Vec<UdpLoop>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    started: AtomicBool,
    rr: AtomicUsize,
    stats: Arc<Stats>,
}

impl std::fmt::Debug for UdpGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpGroup").finish_non_exhaustive()
    }
}

impl UdpGroup {
    /// Binds `addr` and prepares `threads` loops. On Linux every loop gets its own
    /// `SO_REUSEPORT` socket and the kernel keeps each peer on one loop; elsewhere UDP cannot be
    /// spread that way, so a single loop serves the socket.
    pub fn bind(
        listen: Option<(SocketAddr, Arc<dyn DynAcceptor>)>,
        threads: usize,
        cfg: Config,
        pool: Arc<Pool>,
    ) -> io::Result<UdpGroup> {
        let threads = match &listen {
            // Without SO_REUSEPORT spreading (non-Linux) one loop must own the server socket.
            Some(_) if !cfg!(target_os = "linux") => 1,
            _ => threads.max(1),
        };
        cfg.telemetry.bind(&cfg);
        let cfg = Arc::new(cfg);
        let mut bound = SocketAddr::from(([0, 0, 0, 0], 0));
        let mut socks: Vec<Option<(UdpSocket, Arc<dyn DynAcceptor>)>> =
            (0..threads).map(|_| None).collect();
        if let Some((addr, acceptor)) = listen {
            let first = flash_sys::listen_udp(addr, cfg!(target_os = "linux"))?;
            bound = first.local_addr()?;
            for slot in socks.iter_mut().skip(1) {
                *slot = Some((flash_sys::listen_udp(bound, true)?, acceptor.clone()));
            }
            socks[0] = Some((first, acceptor));
        }
        let fds = if cfg!(target_os = "linux") {
            socks
                .iter()
                .flatten()
                .map(|(s, _)| AsRawFd::as_raw_fd(s))
                .collect()
        } else {
            Vec::new()
        };
        let mut shared = Vec::new();
        let mut loops = Vec::new();
        let listener = (bound.port() != 0).then_some(bound);
        let stats = Arc::new(Stats::default());
        for (thread, server) in socks.into_iter().enumerate() {
            let poller = Poller::new()?;
            let meta = LoopMeta {
                backend: "udp",
                listener,
                thread,
            };
            let sh = LoopShared::new(&poller, pool.clone(), &cfg, meta)?;
            loops.push(UdpLoop::new(
                poller,
                sh.clone(),
                server,
                cfg.clone(),
                stats.clone(),
            )?);
            shared.push(sh);
        }
        Ok(UdpGroup {
            addr: bound,
            fds,
            shared,
            pending: Mutex::new(loops),
            threads: Mutex::new(Vec::new()),
            started: AtomicBool::new(false),
            rr: AtomicUsize::new(0),
            stats,
        })
    }
}

impl Group for UdpGroup {
    fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    fn listener_fds(&self) -> Vec<i32> {
        self.fds.clone()
    }
    fn udp_stats(&self) -> UdpStats {
        UdpStats {
            peers: self.stats.peers.load(Ordering::Relaxed),
            rejected: self.stats.rejected.load(Ordering::Relaxed),
        }
    }

    fn start(&self) -> io::Result<()> {
        if self.started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let loops = std::mem::take(&mut *self.pending.lock().unwrap_or_else(|p| p.into_inner()));
        // Running from now on: requests posted before a thread is first scheduled are queued.
        for s in &self.shared {
            s.stats.set_running(true);
        }
        let mut handles = self.threads.lock().unwrap_or_else(|p| p.into_inner());
        for (i, mut l) in loops.into_iter().enumerate() {
            handles.push(
                std::thread::Builder::new()
                    .name(format!("flash-udp-{i}"))
                    .spawn(move || l.run())?,
            );
        }
        Ok(())
    }

    fn shutdown(&self) {
        for s in &self.shared {
            s.post(Cmd::Shutdown);
        }
    }

    fn join(&self) {
        let handles = std::mem::take(&mut *self.threads.lock().unwrap_or_else(|p| p.into_inner()));
        for h in handles {
            let _ = h.join();
        }
    }

    fn dial(
        &self,
        _addr: SocketAddr,
        _acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        on_error(io::Error::new(
            io::ErrorKind::Unsupported,
            "use dial_udp for UDP groups",
        ));
    }

    fn dial_udp(
        &self,
        addr: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        // `connect` on a UDP socket only fixes the peer: it does not block or send anything.
        let local: SocketAddr = if addr.is_ipv4() {
            ([0, 0, 0, 0], 0).into()
        } else {
            ([0u16; 8], 0).into()
        };
        let sock = UdpSocket::bind(local)
            .and_then(|s| s.connect(addr).map(|()| s))
            .and_then(|s| s.set_nonblocking(true).map(|()| s));
        match sock {
            Ok(sock) => {
                let i = self.rr.fetch_add(1, Ordering::Relaxed) % self.shared.len();
                self.shared[i].post(Cmd::DialUdp { sock, acceptor });
            }
            Err(e) => on_error(e),
        }
    }
}
