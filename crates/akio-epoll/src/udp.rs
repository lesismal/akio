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
//! for that explicitly). With `Config::udp_gro` (the default), coalesced GRO receives are split
//! back into one `on_data` per datagram, by the segment size the kernel reports in the `UDP_GRO`
//! control message. `Config::udp_max_peers` caps the peers of a listener.
//!
//! Every connection that got datagrams in a receive batch (one `recvmmsg`, or up to `BATCH`
//! `recvmsg` calls elsewhere) gets one `on_batch_end` after the batch's last `on_data`, before
//! the batch's replies are flushed (akio-quic acknowledges and sends once per batch).
//!
//! Receive buffers are pooled slabs (`akio_buf::slab`, ADR-024). A handler that asks for owned
//! datagrams (`Handler::OWNED_DATA`, akio-quic) gets each one as a writable range cut off the
//! slab it was received into (`on_data_owned`), with no copy, and may keep it; the slot goes on
//! receiving into the rest of the slab. Other handlers read datagrams in place, as before.
//! Peer tables are keyed by addresses the peer chooses, so they hash with the keyed folded
//! multiply of `akio_core::hash` (not SipHash); tables of our own ids with `IdHasher`.
//!
//! Connectionless datagram listeners (`Listener::serve_datagrams`, ADR-065): a loop built with
//! `UdpLoop::with_port` has no peers; it polls one `akio_core::DatagramPort` under `SOCK`, which
//! does the batched receive, the handler call and the `sendmmsg` of its replies.
//!
//! io_uring: a UDP listener on the io_uring backend is served here. With `recvmmsg`/`sendmmsg`/GSO
//! the syscall cost is already one per batch, so a ring buys little; a multishot `recvmsg` with
//! provided buffers (per-datagram headers in the buffer, GRO control data) would be a second
//! implementation of the same batching for no measurable gain, so it is not done for now.

use std::{
    collections::HashSet,
    hash::BuildHasherDefault,
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

use akio_buf::slab::ChunkMut;
use akio_core::{
    Config, ConnInfo, ConnInner, DatagramPort, DatagramSender, DatagramsFactory, DynAcceptor,
    DynHandler, Error, Group, IdHasher, IdMap, LoopMeta, Pool, Task, UdpStats, hash::KeyedMap,
    telemetry::LoopCmd,
};
use akio_sys::{Event, Poller, RecvInfo};
use akio_timer::{TimerId, Wheel};

use crate::reactor::{Cmd, LoopShared};

const WAKER: u64 = 0;
const SOCK: u64 = 1;
/// macOS: the loop's ICMP sockets, reading the ICMP errors of its bound sockets.
#[cfg(target_os = "macos")]
const ICMP4: u64 = 2;
#[cfg(target_os = "macos")]
const ICMP6: u64 = 3;
/// Datagrams taken from the socket per `recvmmsg`.
const BATCH: usize = 32;
const MAX_BATCHES_PER_EVENT: usize = 8;

static NEXT_ID: AtomicU64 = AtomicU64::new(1 << 40);

/// A set of our own connection ids or poll tokens.
type IdSet = HashSet<u64, BuildHasherDefault<IdHasher>>;

/// One received datagram on its way to a handler: read in place, or cut off its receive slab.
enum Rx<'a> {
    Slice(&'a [u8]),
    Owned(ChunkMut),
}

impl Rx<'_> {
    fn len(&self) -> usize {
        match self {
            Rx::Slice(d) => d.len(),
            Rx::Owned(c) => c.len(),
        }
    }

    /// Hands the datagram to `h` the way it asked for (`owned`): an owned datagram is lent to a
    /// handler that reads in place, a borrowed one copied for a handler that wants ownership
    /// (only when a peer reopened under another acceptor in the middle of a GRO batch).
    fn deliver(self, h: &mut dyn DynHandler, owned: bool) {
        match self {
            Rx::Owned(c) if owned => h.on_data_owned(c),
            Rx::Owned(c) => h.on_data(&c),
            Rx::Slice(d) if owned => {
                let mut c = ChunkMut::new(d.len());
                c.copy_from_slice(d);
                h.on_data_owned(c);
            }
            Rx::Slice(d) => h.on_data(d),
        }
    }
}

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
    /// The handler takes datagrams owned (`DynHandler::wants_owned`, asked at open).
    owned: bool,
    /// The run-time bound socket (`Cmd::BindUdp`) this peer belongs to, if any.
    bind: Option<u64>,
}

/// An unconnected socket bound at run time (`Engine::bind_udp`), served like the listener
/// socket: one peer per remote address.
struct Bound {
    sock: Arc<UdpSocket>,
    local: SocketAddr,
    acceptor: Arc<dyn DynAcceptor>,
    /// Takes the socket's ICMP errors (`Engine::bind_udp_icmp`): read from its error queue on
    /// Linux, from the loop's ICMP sockets on macOS.
    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
    icmp: Option<akio_core::IcmpHandler>,
    peers: KeyedMap<SocketAddr, u64>,
    /// Peers with datagrams waiting for socket space.
    blocked: IdSet,
    write_reg: bool,
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
    peers: KeyedMap<SocketAddr, u64>,
    conns: IdMap<Peer>,
    /// Sockets bound at run time, by poll token.
    binds: IdMap<Bound>,
    /// Server-socket peers with datagrams waiting for socket space.
    blocked: IdSet,
    /// Dialed connections with datagrams waiting for socket space.
    blocked_own: IdSet,
    want_write: bool,
    /// Receive buffers, shared by the server socket and dialed sockets (created on first use).
    #[cfg(target_os = "linux")]
    batch: Option<akio_sys::RecvBatch>,
    #[cfg(not(target_os = "linux"))]
    scratch: Option<Scratch>,
    /// Server-socket peers corked while the current receive batch is processed.
    touched: Vec<u64>,
    flush_out: Vec<io::Result<bool>>,
    /// The connections `flush_touched` flushes, kept so a flush allocates nothing.
    flush_conns: Vec<Arc<ConnInner>>,
    stats: Arc<Stats>,
    cfg: Arc<Config>,
    draining: Option<Instant>,
    wheel: Wheel<u64>,
    epoch: Instant,
    /// The loop clock during a receive batch: read after each receive call and moved on by the
    /// end of each timed callback, which is also the start of the next one, so a datagram costs
    /// one clock read (for the slow-callback check) or none.
    clock: Instant,
    /// The command vector traded with `shared` (see `LoopShared::take_into`).
    spare_cmds: Vec<Cmd>,
    /// Size of each receive slot (`Config::read_buffer`, reloadable; see `slot_size`).
    rb: usize,
    /// A datagram listener's socket (ADR-065), polled under `SOCK` instead of `sock`, and the
    /// interest it is registered with.
    dgram: Option<DatagramPort>,
    dgram_interest: (bool, bool),
    /// macOS: ICMPv4 and ICMPv6 sockets, open while a bound socket of that family wants its
    /// ICMP errors, and those sockets by family and port.
    #[cfg(target_os = "macos")]
    icmp: [Option<akio_sys::IcmpListener>; 2],
    #[cfg(target_os = "macos")]
    icmp_binds: std::collections::HashMap<(bool, u16), Vec<u64>>,
}

/// GRO (`Config::udp_gro`, on by default) coalesces up to 64 KiB into one receive: only safe
/// when a slot can hold that.
#[cfg(target_os = "linux")]
fn gro_ok(cfg: &Config) -> bool {
    cfg.udp_gro && cfg.read_buffer >= 65535 && akio_sys::gro_available()
}

/// Size of one receive slot for a read buffer of `rb` bytes: sockets with GRO on (decided once,
/// from the configuration the engine was built with) need room for 64 KiB.
fn slot_size(cfg: &Config, rb: usize) -> usize {
    #[cfg(target_os = "linux")]
    if gro_ok(cfg) {
        return rb.max(65535);
    }
    let _ = cfg;
    rb
}

/// The receive buffer of the loops without `recvmmsg` (one datagram per `recv_from`): the free
/// tail of a pooled slab, so that a datagram can be cut off and handed out owned (see the module
/// docs) while the next one is received behind it.
#[cfg(not(target_os = "linux"))]
struct Scratch {
    free: ChunkMut,
    pool: akio_buf::slab::SlabPool,
    size: usize,
}

#[cfg(not(target_os = "linux"))]
impl Scratch {
    fn new(size: usize) -> Scratch {
        let mut pool = akio_buf::slab::SlabPool::new(size.saturating_mul(2), 4);
        Scratch {
            free: pool.take(),
            pool,
            size,
        }
    }

    /// Room for one datagram.
    fn buf(&mut self) -> &mut [u8] {
        if self.free.len() < self.size {
            self.pool.renew(&mut self.free);
        }
        &mut self.free[..self.size]
    }
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
                    akio_sys::enable_gro(sock.as_raw_fd());
                }
                akio_sys::enable_ecn(sock.as_raw_fd());
                poller.add(sock.as_raw_fd(), SOCK, true, false)?;
                let local = sock.local_addr()?;
                (Some(Arc::new(sock)), Some(local), Some(acceptor))
            }
            None => (None, None, None),
        };
        let sock_present = sock.is_some();
        let rb = slot_size(&cfg, cfg.telemetry.live().read_buffer());
        Ok(UdpLoop {
            poller,
            shared,
            sock,
            local,
            acceptor,
            peers: KeyedMap::default(),
            conns: Default::default(),
            binds: IdMap::default(),
            blocked: IdSet::default(),
            blocked_own: IdSet::default(),
            want_write: false,
            #[cfg(target_os = "linux")]
            batch: sock_present.then(|| akio_sys::RecvBatch::with_gro(BATCH, rb, gro_ok(&cfg))),
            #[cfg(not(target_os = "linux"))]
            scratch: sock_present.then(|| Scratch::new(rb)),
            touched: Vec::new(),
            flush_out: Vec::new(),
            flush_conns: Vec::new(),
            stats,
            cfg,
            draining: None,
            wheel: Wheel::new(0),
            epoch: Instant::now(),
            clock: Instant::now(),
            spare_cmds: Vec::new(),
            rb,
            dgram: None,
            dgram_interest: (false, false),
            #[cfg(target_os = "macos")]
            icmp: [None, None],
            #[cfg(target_os = "macos")]
            icmp_binds: std::collections::HashMap::new(),
        })
    }

    /// A loop serving the datagram listener socket of `port` (ADR-065).
    fn with_port(
        poller: Poller,
        shared: Arc<LoopShared>,
        port: DatagramPort,
        cfg: Arc<Config>,
        stats: Arc<Stats>,
    ) -> io::Result<UdpLoop> {
        poller.add(port.fd(), SOCK, true, false)?;
        let mut l = UdpLoop::new(poller, shared, None, cfg, stats)?;
        l.dgram = Some(port);
        l.dgram_interest = (true, false);
        Ok(l)
    }

    /// Readiness of the datagram listener socket.
    fn on_port(&mut self, readable: bool, writable: bool) {
        let Some(p) = &mut self.dgram else {
            return;
        };
        if writable {
            p.on_writable();
        }
        if readable && p.wants_read() {
            p.on_readable();
        }
        self.port_interest();
    }

    /// Polls the datagram listener socket for what its port wants.
    fn port_interest(&mut self) {
        let Some(p) = &self.dgram else {
            return;
        };
        let want = (p.wants_read() && self.draining.is_none(), p.wants_write());
        if want != self.dgram_interest {
            self.dgram_interest = want;
            let _ = self.poller.modify(p.fd(), SOCK, want.0, want.1);
        }
    }

    #[cfg(target_os = "linux")]
    fn new_batch(&self) -> akio_sys::RecvBatch {
        akio_sys::RecvBatch::with_gro(BATCH, self.rb, gro_ok(&self.cfg))
    }

    /// Live settings changed: the receive buffers take the new `read_buffer` (between two
    /// batches, so nothing borrows them), and peers' idle timers follow the new idle timeout.
    fn on_reload(&mut self) {
        if let Some(p) = &mut self.dgram {
            p.on_reload();
        }
        let rb = slot_size(&self.cfg, self.cfg.telemetry.live().read_buffer());
        if rb != self.rb {
            self.rb = rb;
            #[cfg(target_os = "linux")]
            if self.batch.is_some() {
                self.batch = Some(self.new_batch());
            }
            #[cfg(not(target_os = "linux"))]
            if self.scratch.is_some() {
                self.scratch = Some(Scratch::new(rb));
            }
        }
        let idle = self.idle_ms();
        let ids: Vec<u64> = self.conns.keys().copied().collect();
        for id in ids {
            if let Some(p) = self.conns.get_mut(&id) {
                if let Some(t) = p.timer.take() {
                    self.wheel.cancel(t);
                }
                p.timer = Some(self.wheel.schedule(p.last_active + idle, id));
            }
        }
    }

    fn tick(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// [`UdpLoop::tick`] of the loop clock (no clock read).
    fn clock_tick(&self) -> u64 {
        self.clock.saturating_duration_since(self.epoch).as_millis() as u64
    }

    /// The start of a callback during a receive batch: the loop clock, when callbacks are timed.
    fn timed_start(&self) -> Option<Instant> {
        self.cfg.telemetry.timing_enabled().then_some(self.clock)
    }

    /// The end of a callback started with [`UdpLoop::timed_start`]: accounted, reported if slow,
    /// and its end becomes the loop clock.
    fn timed_end(&mut self, kind: &'static str, id: u64, t0: Option<Instant>) {
        match t0 {
            Some(t0) => {
                self.clock = self
                    .cfg
                    .telemetry
                    .callback_done_at(&self.shared.stats, kind, id, t0);
            }
            None => self.shared.stats.callbacks.add_local(1),
        }
    }

    /// The peer idle timeout in force: `udp_idle_timeout`, or `idle_timeout` when set and
    /// shorter (both reloadable).
    fn idle_ms(&self) -> u64 {
        let live = self.cfg.telemetry.live();
        let udp = live.udp_idle_ms().max(1);
        match live.idle_ms() {
            0 => udp,
            i => i.min(udp),
        }
    }

    fn run(&mut self) {
        akio_core::timer::install();
        self.run_inner();
        akio_core::timer::uninstall();
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
            let timeout = akio_core::timer::poll_timeout(timeout);
            events.clear();
            if let Err(e) = self.poller.wait(&mut events, timeout) {
                eprintln!("akio: poller error: {e}");
                break;
            }
            self.shared.stats.iterations.add_local(1);
            self.shared.stats.events.add_local(events.len() as u64);
            for ev in &events {
                match ev.token {
                    WAKER => self.shared.waker().drain(),
                    SOCK if self.dgram.is_some() => self.on_port(ev.readable, ev.writable),
                    #[cfg(target_os = "macos")]
                    ICMP4 | ICMP6 => self.read_icmp(ev.token == ICMP6),
                    SOCK => {
                        if ev.readable {
                            self.recv_on(None);
                        }
                        if ev.writable {
                            self.flush_blocked();
                        }
                    }
                    id if self.binds.contains_key(&id) => {
                        if ev.readable {
                            self.recv_on(Some(id));
                        }
                        if ev.writable {
                            self.flush_bound(id);
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
            akio_core::timer::fire();
            self.drain_cmds();
            self.fire_timers();
            if let Some(deadline) = self.draining {
                // Datagrams have no stream to drain: once handlers had their `on_shutdown` and
                // nothing is waiting for socket space, everything left is closed.
                if (self.blocked.is_empty()
                    && self.blocked_own.is_empty()
                    && self.binds.values().all(|b| b.blocked.is_empty())
                    && self.dgram.as_ref().is_none_or(|p| !p.wants_write()))
                    || Instant::now() >= deadline
                {
                    let ids: Vec<u64> = self.conns.keys().copied().collect();
                    for id in ids {
                        self.finalize(id, None);
                    }
                    let binds: Vec<u64> = self.binds.keys().copied().collect();
                    for id in binds {
                        self.unbind(id);
                    }
                    break;
                }
            }
        }
    }

    // ---- receive --------------------------------------------------------------------------

    /// The socket datagrams of `src` arrive on: the listener socket (`None`) or a bound one.
    fn src_sock(&self, src: Option<u64>) -> Option<Arc<UdpSocket>> {
        match src {
            None => self.sock.clone(),
            Some(b) => self.binds.get(&b).map(|b| b.sock.clone()),
        }
    }

    #[cfg(target_os = "linux")]
    fn recv_on(&mut self, src: Option<u64>) {
        let Some(sock) = self.src_sock(src) else {
            return;
        };
        let recverr = src.is_some_and(|b| self.binds.get(&b).is_some_and(|b| b.icmp.is_some()));
        if recverr {
            if let Some(b) = src {
                self.drain_icmp(b);
            }
        }
        let mut batch = self.batch.take().unwrap_or_else(|| self.new_batch());
        let fd = sock.as_raw_fd();
        for _ in 0..MAX_BATCHES_PER_EVENT {
            let n = match batch.recv(fd) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                // `IP_RECVERR`: the error an ICMP message left pending comes out once, in
                // place of the datagrams; the message itself is on the error queue.
                Err(e) if recverr && akio_sys::is_icmp_error(&e) => continue,
                Err(e) => {
                    eprintln!("akio: recvmmsg: {e}");
                    break;
                }
            };
            self.clock = Instant::now();
            for i in 0..n {
                let Some(peer) = batch.addr(i) else {
                    continue;
                };
                let ip = batch.info(i);
                let Some(id) = self.admit(src, peer) else {
                    continue;
                };
                if self.conns.get(&id).is_some_and(|p| p.owned) {
                    let Some((mut data, _, seg)) = batch.take(i) else {
                        continue;
                    };
                    if seg > 0 && seg < data.len() {
                        // GRO coalesced several datagrams of this peer: restore the boundaries.
                        let mut first = Some(id);
                        while !data.is_empty() {
                            let d = data.split_to(seg.min(data.len()));
                            self.on_datagram(src, peer, first.take(), Rx::Owned(d), ip);
                        }
                    } else {
                        self.on_datagram(src, peer, Some(id), Rx::Owned(data), ip);
                    }
                } else if let Some((data, seg)) = batch.data(i) {
                    if seg > 0 && seg < data.len() {
                        // GRO coalesced several datagrams of this peer: restore the boundaries.
                        let mut first = Some(id);
                        for d in data.chunks(seg) {
                            self.on_datagram(src, peer, first.take(), Rx::Slice(d), ip);
                        }
                    } else {
                        self.on_datagram(src, peer, Some(id), Rx::Slice(data), ip);
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

    /// Ends a receive batch: tells the peers it touched (`on_batch_end`, while their replies are
    /// still corked), then uncorks and flushes them together.
    fn flush_touched(&mut self) {
        if self.touched.is_empty() {
            return;
        }
        let mut ids = std::mem::take(&mut self.touched);
        for &id in &ids {
            self.batch_end(id);
        }
        ids.retain(|id| match self.conns.get_mut(id) {
            Some(p) => {
                p.in_batch = false;
                true
            }
            None => false,
        });
        let mut inners = std::mem::take(&mut self.flush_conns);
        inners.extend(ids.iter().map(|id| self.conns[id].inner.clone()));
        let mut out = std::mem::take(&mut self.flush_out);
        ConnInner::flush_datagram_peers(&inners, &mut out);
        inners.clear();
        self.flush_conns = inners;
        for (&id, r) in ids.iter().zip(out.drain(..)) {
            self.after_flush(id, r);
        }
        self.flush_out = out;
        ids.clear();
        self.touched = ids;
    }

    /// `on_batch_end` for `id` (a panic closes the connection).
    fn batch_end(&mut self, id: u64) {
        let t0 = self.timed_start();
        let Some(p) = self.conns.get_mut(&id) else {
            return;
        };
        let r = catch_unwind(AssertUnwindSafe(|| p.handler.on_batch_end()));
        self.timed_end("on_batch_end", id, t0);
        if r.is_err() {
            self.finalize(id, Some(panic_error()));
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn recv_on(&mut self, src: Option<u64>) {
        let Some(sock) = self.src_sock(src) else {
            return;
        };
        let mut buf = self.scratch.take().unwrap_or_else(|| Scratch::new(self.rb));
        'event: for _ in 0..MAX_BATCHES_PER_EVENT {
            // A batch is up to BATCH datagrams, as with recvmmsg.
            for _ in 0..BATCH {
                match akio_sys::recv_from_info(sock.as_raw_fd(), buf.buf()) {
                    Ok((n, peer, ip)) => {
                        self.clock = Instant::now();
                        let Some(id) = self.admit(src, peer) else {
                            continue;
                        };
                        let rx = if self.conns.get(&id).is_some_and(|p| p.owned) {
                            Rx::Owned(buf.free.split_to(n))
                        } else {
                            Rx::Slice(&buf.free[..n])
                        };
                        self.on_datagram(src, peer, Some(id), rx, ip);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break 'event,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => {
                        eprintln!("akio: recv_from: {e}");
                        break 'event;
                    }
                }
            }
            self.flush_touched();
        }
        self.scratch = Some(buf);
        self.flush_touched();
    }

    /// The connection of `peer` on the server socket (`src` = `None`) or a bound one, opened on
    /// its first datagram. `None` while draining or when it cannot be opened.
    fn admit(&mut self, src: Option<u64>, peer: SocketAddr) -> Option<u64> {
        if self.draining.is_some() {
            return None;
        }
        let known = match src {
            None => self.peers.get(&peer).copied(),
            Some(b) => self.binds.get(&b).and_then(|b| b.peers.get(&peer).copied()),
        };
        match known {
            Some(id) => Some(id),
            None => self.open(src, peer),
        }
    }

    /// One datagram from `peer` with what the kernel reported with it, `ip` (traffic class
    /// byte, TTL / hop limit, arrival interface; each 0 when not reported), for connection `id` when the caller has just admitted it,
    /// else looked up (or opened) again.
    fn on_datagram(
        &mut self,
        src: Option<u64>,
        peer: SocketAddr,
        id: Option<u64>,
        data: Rx<'_>,
        ip: RecvInfo,
    ) {
        let Some(id) = id.or_else(|| self.admit(src, peer)) else {
            return;
        };
        let t0 = self.timed_start();
        let now = self.clock_tick();
        let Some(p) = self.conns.get_mut(&id) else {
            return;
        };
        let len = data.len();
        p.last_active = now;
        p.bytes_in += len as u64;
        self.shared.stats.datagram_in(len);
        if !p.in_batch {
            // `on_batch_end` follows at the end of the receive batch (see `flush_touched`), and
            // on Linux the replies wait for it, to leave together in few `sendmmsg` calls.
            p.in_batch = true;
            if cfg!(target_os = "linux") {
                p.inner.set_corked(true);
            }
            self.touched.push(id);
        }
        p.inner.set_rx_tos(ip.tos);
        p.inner.set_rx_ttl(ip.ttl);
        p.inner.set_rx_interface(ip.interface);
        let owned = p.owned;
        let h = &mut *p.handler;
        let r = catch_unwind(AssertUnwindSafe(|| data.deliver(h, owned)));
        self.timed_end("on_data", id, t0);
        if r.is_err() {
            self.finalize(id, Some(panic_error()));
        }
    }

    fn open(&mut self, bind: Option<u64>, peer: SocketAddr) -> Option<u64> {
        let acceptor = match bind {
            None => self.acceptor.clone()?,
            Some(b) => self.binds.get(&b)?.acceptor.clone(),
        };
        self.open_with(bind, peer, acceptor)
    }

    /// A peer of the server socket (`bind` = `None`) or of the socket bound under `bind`,
    /// served by `acceptor` (the socket's own, or one given to `Group::open_udp_peer`).
    fn open_with(
        &mut self,
        bind: Option<u64>,
        peer: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
    ) -> Option<u64> {
        let (sock, local) = match bind {
            None => (self.sock.clone()?, self.local?),
            Some(b) => {
                let b = self.binds.get(&b)?;
                (b.sock.clone(), b.local)
            }
        };
        // Admission: `udp_max_peers` bounds the peers of the whole listener (all its loops).
        if bind.is_none() {
            let before = self.stats.peers.fetch_add(1, Ordering::Relaxed);
            if self.cfg.udp_max_peers.is_some_and(|max| before >= max) {
                self.stats.peers.fetch_sub(1, Ordering::Relaxed);
                self.stats.rejected.fetch_add(1, Ordering::Relaxed);
                return None;
            }
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
            if bind.is_none() {
                self.stats.peers.fetch_sub(1, Ordering::Relaxed);
            }
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
        match bind.and_then(|b| self.binds.get_mut(&b)) {
            Some(b) => {
                b.peers.insert(peer, id);
            }
            None => {
                self.peers.insert(peer, id);
            }
        }
        let owned = handler.wants_owned();
        self.conns.insert(
            id,
            Peer {
                own: None,
                write_reg: false,
                acceptor,
                inner,
                handler,
                owned,
                addr: peer,
                last_active: now,
                timer,
                opened: now,
                bytes_in: 0,
                in_batch: false,
                bind,
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
            akio_sys::enable_gro(sock.as_raw_fd());
        }
        akio_sys::enable_ecn(sock.as_raw_fd());
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
        let owned = handler.wants_owned();
        self.conns.insert(
            id,
            Peer {
                own: Some(sock),
                write_reg: false,
                acceptor,
                inner,
                handler,
                owned,
                addr: peer,
                last_active: now,
                timer,
                opened: now,
                bytes_in: 0,
                in_batch: false,
                bind: None,
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
        let mut batch = self.batch.take().unwrap_or_else(|| self.new_batch());
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
            self.clock = Instant::now();
            for i in 0..n {
                let ip = batch.info(i);
                if self.conns.get(&id).is_some_and(|p| p.owned) {
                    let Some((mut data, _, seg)) = batch.take(i) else {
                        continue;
                    };
                    // GRO coalesced several datagrams: restore the boundaries.
                    let seg = if seg > 0 { seg } else { data.len().max(1) };
                    while !data.is_empty() {
                        let d = data.split_to(seg.min(data.len()));
                        if !self.deliver(id, Rx::Owned(d), ip) {
                            break 'recv;
                        }
                    }
                } else {
                    let Some((data, seg)) = batch.data(i) else {
                        continue;
                    };
                    // GRO coalesced several datagrams: restore the boundaries.
                    let seg = if seg > 0 { seg } else { data.len().max(1) };
                    for d in data.chunks(seg) {
                        if !self.deliver(id, Rx::Slice(d), ip) {
                            break 'recv;
                        }
                    }
                }
            }
            self.batch_end(id);
            if n < BATCH {
                break;
            }
            // More may be waiting: what this batch produced leaves first.
            let Some(p) = self.conns.get(&id) else {
                break;
            };
            p.inner.set_corked(false);
            self.on_wake(id);
            match self.conns.get(&id) {
                Some(p) => p.inner.set_corked(true),
                None => break,
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
        let mut buf = self.scratch.take().unwrap_or_else(|| Scratch::new(self.rb));
        let owned = self.conns.get(&id).is_some_and(|p| p.owned);
        let mut got = 0;
        for _ in 0..MAX_BATCHES_PER_EVENT * BATCH {
            match akio_sys::recv_from_info(sock.as_raw_fd(), buf.buf()) {
                Ok((n, _, ip)) => {
                    self.clock = Instant::now();
                    let rx = if owned {
                        Rx::Owned(buf.free.split_to(n))
                    } else {
                        Rx::Slice(&buf.free[..n])
                    };
                    if !self.deliver(id, rx, ip) {
                        self.scratch = Some(buf);
                        return;
                    }
                    got += 1;
                    if got % BATCH == 0 {
                        self.batch_end(id);
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
        if got % BATCH != 0 {
            self.batch_end(id);
        }
    }

    /// One datagram for dialed connection `id`. `false` when the connection is gone.
    fn deliver(&mut self, id: u64, data: Rx<'_>, ip: RecvInfo) -> bool {
        let t0 = self.timed_start();
        let now = self.clock_tick();
        let Some(p) = self.conns.get_mut(&id) else {
            return false;
        };
        let len = data.len();
        p.last_active = now;
        p.bytes_in += len as u64;
        self.shared.stats.datagram_in(len);
        p.inner.set_rx_tos(ip.tos);
        p.inner.set_rx_ttl(ip.ttl);
        p.inner.set_rx_interface(ip.interface);
        let owned = p.owned;
        let h = &mut *p.handler;
        let r = catch_unwind(AssertUnwindSafe(|| data.deliver(h, owned)));
        self.timed_end("on_data", id, t0);
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
                    None => match p.bind {
                        Some(b) => self.bound_blocked(b, id, !empty),
                        None => {
                            if empty {
                                self.blocked.remove(&id);
                            } else {
                                self.blocked.insert(id);
                            }
                            self.update_interest();
                        }
                    },
                }
            }
        }
    }

    /// Tracks whether bound-socket peer `id` waits for socket space, and the socket's write
    /// interest.
    fn bound_blocked(&mut self, bind: u64, id: u64, blocked: bool) {
        let Some(b) = self.binds.get_mut(&bind) else {
            return;
        };
        if blocked {
            b.blocked.insert(id);
        } else {
            b.blocked.remove(&id);
        }
        let want = !b.blocked.is_empty();
        if want != b.write_reg {
            b.write_reg = want;
            let _ = self
                .poller
                .modify(b.sock.as_raw_fd(), bind, self.draining.is_none(), want);
        }
    }

    fn flush_bound(&mut self, bind: u64) {
        let ids: Vec<u64> = match self.binds.get(&bind) {
            Some(b) => b.blocked.iter().copied().collect(),
            None => return,
        };
        for id in ids {
            self.on_wake(id);
        }
    }

    fn open_bound(
        &mut self,
        id: u64,
        sock: Arc<UdpSocket>,
        acceptor: Arc<dyn DynAcceptor>,
        icmp: Option<akio_core::IcmpHandler>,
    ) {
        if self.draining.is_some() {
            return;
        }
        let Ok(local) = sock.local_addr() else {
            return;
        };
        #[cfg(target_os = "linux")]
        if gro_ok(&self.cfg) {
            akio_sys::enable_gro(sock.as_raw_fd());
        }
        akio_sys::enable_ecn(sock.as_raw_fd());
        if self.poller.add(sock.as_raw_fd(), id, true, false).is_err() {
            return;
        }
        #[cfg(target_os = "macos")]
        if icmp.is_some() {
            self.watch_icmp(id, local);
        }
        self.binds.insert(
            id,
            Bound {
                sock,
                local,
                acceptor,
                icmp,
                peers: KeyedMap::default(),
                blocked: IdSet::default(),
                write_reg: false,
            },
        );
    }

    /// Reads the ICMP errors queued on bound socket `id` (`IP_RECVERR`) and hands them to its
    /// handler: until the queue is empty, since the socket polls readable while it is not.
    #[cfg(target_os = "linux")]
    fn drain_icmp(&self, id: u64) {
        let Some(b) = self.binds.get(&id) else {
            return;
        };
        let Some(on_icmp) = b.icmp.clone() else {
            return;
        };
        let (fd, local) = (b.sock.as_raw_fd(), b.local);
        // Bounded, as a receive is: a flood of errors waits for the next event.
        for _ in 0..BATCH * MAX_BATCHES_PER_EVENT {
            match akio_sys::recv_icmp(fd) {
                Ok(Some(r)) => {
                    let e = akio_core::IcmpError::new(
                        local,
                        r.dest,
                        r.from,
                        r.v6,
                        r.icmp_type,
                        r.code,
                        r.info,
                    );
                    if catch_unwind(AssertUnwindSafe(|| on_icmp(&e))).is_err() {
                        eprintln!("akio: ICMP handler panicked");
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    eprintln!("akio: reading ICMP errors: {e}");
                    break;
                }
            }
        }
    }

    /// macOS: bound socket `id` at `local` wants its ICMP errors: opens the loop's ICMP socket
    /// of its family if it is not open yet. Without one (refused) the socket gets none.
    #[cfg(target_os = "macos")]
    fn watch_icmp(&mut self, id: u64, local: SocketAddr) {
        let v6 = local.is_ipv6();
        let slot = usize::from(v6);
        if self.icmp[slot].is_none() {
            let token = if v6 { ICMP6 } else { ICMP4 };
            match akio_sys::IcmpListener::open(v6) {
                Ok(l) if self.poller.add(l.as_raw_fd(), token, true, false).is_ok() => {
                    self.icmp[slot] = Some(l);
                }
                Ok(_) => return,
                Err(e) => {
                    eprintln!("akio: no ICMP socket for {local}'s ICMP errors: {e}");
                    return;
                }
            }
        }
        self.icmp_binds
            .entry((v6, local.port()))
            .or_default()
            .push(id);
    }

    /// macOS: bound socket `id` at `local` is going: forgets it, and closes the ICMP socket of
    /// its family when no other socket of the loop wants it.
    #[cfg(target_os = "macos")]
    fn unwatch_icmp(&mut self, id: u64, local: SocketAddr) {
        let v6 = local.is_ipv6();
        let key = (v6, local.port());
        if let Some(ids) = self.icmp_binds.get_mut(&key) {
            ids.retain(|&i| i != id);
            if ids.is_empty() {
                self.icmp_binds.remove(&key);
            }
        }
        if !self.icmp_binds.keys().any(|k| k.0 == v6) {
            if let Some(l) = self.icmp[usize::from(v6)].take() {
                self.poller.delete(l.as_raw_fd());
            }
        }
    }

    /// macOS: the ICMP socket of family `v6` is readable: each error about a datagram one of
    /// the loop's bound sockets sent goes to that socket's handler; the rest (other sockets',
    /// other processes') is dropped. Bounded per event, as a receive is.
    #[cfg(target_os = "macos")]
    fn read_icmp(&self, v6: bool) {
        for _ in 0..BATCH * MAX_BATCHES_PER_EVENT {
            let Some(l) = &self.icmp[usize::from(v6)] else {
                return;
            };
            let (p, from) = match l.recv() {
                Ok(Some(r)) => r,
                Ok(None) => return,
                Err(e) => {
                    eprintln!("akio: reading ICMP errors: {e}");
                    return;
                }
            };
            let Some(ids) = self.icmp_binds.get(&(v6, p.source.port())) else {
                continue;
            };
            for id in ids {
                let Some(b) = self.binds.get(id) else {
                    continue;
                };
                let Some(on_icmp) = &b.icmp else {
                    continue;
                };
                if !akio_sys::icmp_source_matches(b.local, p.source) {
                    continue;
                }
                let e = akio_core::IcmpError::new(
                    b.local,
                    p.dest,
                    Some(from),
                    p.v6,
                    p.icmp_type,
                    p.code,
                    p.mtu,
                );
                if catch_unwind(AssertUnwindSafe(|| on_icmp(&e))).is_err() {
                    eprintln!("akio: ICMP handler panicked");
                }
            }
        }
    }

    fn unbind(&mut self, id: u64) {
        #[cfg(target_os = "macos")]
        if let Some(local) = self
            .binds
            .get(&id)
            .filter(|b| b.icmp.is_some())
            .map(|b| b.local)
        {
            self.unwatch_icmp(id, local);
        }
        let Some(b) = self.binds.get(&id) else {
            return;
        };
        let peers: Vec<u64> = b.peers.values().copied().collect();
        for p in peers {
            self.finalize(p, None);
        }
        if let Some(b) = self.binds.remove(&id) {
            self.poller.delete(b.sock.as_raw_fd());
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
            None => match p.bind.and_then(|b| self.binds.get_mut(&b)) {
                Some(b) => {
                    b.peers.remove(&p.addr);
                    b.blocked.remove(&id);
                }
                None if p.bind.is_some() => {}
                None => {
                    self.peers.remove(&p.addr);
                    self.blocked.remove(&id);
                    self.stats.peers.fetch_sub(1, Ordering::Relaxed);
                }
            },
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
        let mut batch = std::mem::take(&mut self.spare_cmds);
        loop {
            self.shared.take_into(&mut batch);
            if batch.is_empty() {
                break;
            }
            for cmd in batch.drain(..) {
                match cmd {
                    Cmd::Wake(id) => self.on_wake(id),
                    Cmd::Close(id, err) => self.finalize(id, err.map(Error::Io)),
                    Cmd::Task(id, task) => self.on_task(id, task),
                    Cmd::Shutdown => self.begin_shutdown(),
                    Cmd::Core(LoopCmd::Inspect(reply)) => reply(self.inspect()),
                    Cmd::Core(LoopCmd::Reload) => self.on_reload(),
                    // Thread resizing is not offered for UDP groups (ADR-028).
                    Cmd::AddListener(..)
                    | Cmd::GiveListener { .. }
                    | Cmd::Retire { .. }
                    | Cmd::Revive => {}
                    Cmd::DialUdp { sock, acceptor } => self.open_client(sock, acceptor),
                    Cmd::BindUdp {
                        id,
                        sock,
                        acceptor,
                        icmp,
                    } => self.open_bound(id, sock, acceptor, icmp),
                    Cmd::Unbind(id) => self.unbind(id),
                    Cmd::OpenPeer {
                        peer,
                        acceptor,
                        on_error,
                    } => {
                        if self.sock.is_none() || self.draining.is_some() {
                            on_error(io::Error::new(
                                io::ErrorKind::NotConnected,
                                "no UDP listener socket",
                            ));
                        } else if self.peers.contains_key(&peer) {
                            on_error(io::Error::new(
                                io::ErrorKind::AlreadyExists,
                                "the peer already has a connection",
                            ));
                        } else if self.open_with(None, peer, acceptor).is_none() {
                            on_error(io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                "peer refused (udp_max_peers, or on_open panicked or closed)",
                            ));
                        }
                    }
                    Cmd::Dial { on_error, .. } => on_error(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "dial is not supported on a UDP listener",
                    )),
                    // TCP groups only (accept-time balancing); never sent to a UDP loop.
                    Cmd::Adopt { .. } => {}
                }
            }
        }
        if batch.capacity() <= crate::reactor::MAX_SPARE_CMDS {
            self.spare_cmds = batch;
        }
    }

    /// The connection table rows of this loop.
    fn inspect(&self) -> Vec<ConnInfo> {
        let now = self.tick();
        self.conns
            .iter()
            .map(|(&id, p)| {
                let mut ci = ConnInfo::new(id, &p.inner, self.shared.stats.meta().clone());
                ci.peer = p.addr;
                ci.age = Duration::from_millis(now.saturating_sub(p.opened));
                ci.idle = Duration::from_millis(now.saturating_sub(p.last_active));
                ci.bytes_in = p.bytes_in;
                ci
            })
            .collect()
    }

    fn begin_shutdown(&mut self) {
        if self.draining.is_some() {
            return;
        }
        self.draining = Some(Instant::now() + self.cfg.telemetry.live().shutdown_timeout());
        if let Some(p) = &mut self.dgram {
            p.shutdown();
            self.port_interest();
        }
        if let Some(sock) = &self.sock {
            self.poller.delete(sock.as_raw_fd());
            // Re-add for writing only if something is still waiting for socket space.
            self.want_write = false;
            if !self.blocked.is_empty() {
                let _ = self.poller.add(sock.as_raw_fd(), SOCK, false, true);
                self.want_write = true;
            }
        }
        for (&id, b) in &mut self.binds {
            // Keep only write interest, for peers still waiting for socket space.
            b.write_reg = !b.blocked.is_empty();
            let _ = self
                .poller
                .modify(b.sock.as_raw_fd(), id, false, b.write_reg);
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
    /// CPU set per thread ([`Group::pin_threads`]), taken by `start`.
    pins: Mutex<Vec<Vec<usize>>>,
    rr: AtomicUsize,
    stats: Arc<Stats>,
    /// A datagram listener's sender (on thread 0's socket).
    sender: Option<DatagramSender>,
}

impl std::fmt::Debug for UdpGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpGroup").finish_non_exhaustive()
    }
}

impl UdpGroup {
    /// Registers `sock` (`Engine::bind_udp`) on a loop, with the handler of its ICMP errors
    /// (`Engine::bind_udp_icmp`, the socket already has `IP_RECVERR`).
    fn register_bound(
        &self,
        sock: UdpSocket,
        acceptor: Arc<dyn DynAcceptor>,
        icmp: Option<akio_core::IcmpHandler>,
    ) -> io::Result<akio_core::UdpBinding> {
        sock.set_nonblocking(true)?;
        let local = sock.local_addr()?;
        let sock = Arc::new(sock);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let i = self.rr.fetch_add(1, Ordering::Relaxed) % self.shared.len();
        let shared = self.shared[i].clone();
        shared.post(Cmd::BindUdp {
            id,
            sock: sock.clone(),
            acceptor,
            icmp,
        });
        let closed = AtomicBool::new(false);
        let closer = Arc::new(move || {
            if !closed.swap(true, Ordering::AcqRel) {
                shared.post(Cmd::Unbind(id));
            }
        });
        Ok(akio_core::UdpBinding::new(sock, local, closer))
    }

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
            let first = akio_sys::listen_udp(addr, cfg!(target_os = "linux"))?;
            bound = first.local_addr()?;
            for slot in socks.iter_mut().skip(1) {
                *slot = Some((akio_sys::listen_udp(bound, true)?, acceptor.clone()));
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
            let meta = LoopMeta::new("udp", listener, thread);
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
            pins: Mutex::new(Vec::new()),
            rr: AtomicUsize::new(0),
            stats,
            sender: None,
        })
    }

    /// Binds `addr` for a connectionless datagram listener (ADR-065): `threads` loops (one
    /// elsewhere than Linux, as for [`bind`](Self::bind)), each with its own `SO_REUSEPORT`
    /// socket on Linux served by a [`DatagramsHandler`](akio_core::DatagramsHandler) from
    /// `factory`. No peer table: `Config::udp_max_peers` and `udp_idle_timeout` do not apply.
    pub fn bind_datagrams(
        addr: SocketAddr,
        factory: DatagramsFactory,
        threads: usize,
        cfg: Config,
        pool: Arc<Pool>,
    ) -> io::Result<UdpGroup> {
        let threads = if cfg!(target_os = "linux") {
            threads.max(1)
        } else {
            1
        };
        cfg.telemetry.bind(&cfg);
        let cfg = Arc::new(cfg);
        let first = akio_sys::listen_udp(addr, cfg!(target_os = "linux"))?;
        let bound = first.local_addr()?;
        let mut socks = vec![first];
        for _ in 1..threads {
            socks.push(akio_sys::listen_udp(bound, true)?);
        }
        let fds = if cfg!(target_os = "linux") {
            socks.iter().map(AsRawFd::as_raw_fd).collect()
        } else {
            Vec::new()
        };
        let stats = Arc::new(Stats::default());
        let (mut shared, mut loops, mut sender) = (Vec::new(), Vec::new(), None);
        for (thread, sock) in socks.into_iter().enumerate() {
            let poller = Poller::new()?;
            let meta = LoopMeta::new("udp", Some(bound), thread);
            let sh = LoopShared::new(&poller, pool.clone(), &cfg, meta)?;
            let port = DatagramPort::new(sock, &factory, sh.stats.clone(), cfg.clone())?;
            sender.get_or_insert_with(|| port.sender());
            loops.push(UdpLoop::with_port(
                poller,
                sh.clone(),
                port,
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
            pins: Mutex::new(Vec::new()),
            rr: AtomicUsize::new(0),
            stats,
            sender,
        })
    }
}

impl Group for UdpGroup {
    fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    fn threads(&self) -> usize {
        self.shared.len()
    }

    fn listener_fds(&self) -> Vec<i32> {
        self.fds.clone()
    }
    fn datagram_sender(&self) -> Option<DatagramSender> {
        self.sender.clone()
    }
    fn udp_stats(&self) -> UdpStats {
        let mut s = UdpStats::default();
        s.peers = self.stats.peers.load(Ordering::Relaxed);
        s.rejected = self.stats.rejected.load(Ordering::Relaxed);
        s
    }

    fn pin_threads(&self, cpus: Vec<Vec<usize>>) {
        *self.pins.lock().unwrap_or_else(|p| p.into_inner()) = cpus;
    }

    fn start(&self) -> io::Result<()> {
        if self.started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let loops = std::mem::take(&mut *self.pending.lock().unwrap_or_else(|p| p.into_inner()));
        let pins = std::mem::take(&mut *self.pins.lock().unwrap_or_else(|p| p.into_inner()));
        // Running from now on: requests posted before a thread is first scheduled are queued.
        for s in &self.shared {
            s.stats.set_running(true);
        }
        let mut handles = self.threads.lock().unwrap_or_else(|p| p.into_inner());
        for (i, mut l) in loops.into_iter().enumerate() {
            // Best effort: a thread that cannot be pinned runs unpinned.
            let pin = pins.get(i).cloned().unwrap_or_default();
            handles.push(
                std::thread::Builder::new()
                    .name(format!("akio-udp-{i}"))
                    .spawn(move || {
                        akio_sys::process::pin_current_thread(&pin).ok();
                        l.run();
                    })?,
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

    fn bind_udp(
        &self,
        sock: UdpSocket,
        acceptor: Arc<dyn DynAcceptor>,
    ) -> io::Result<akio_core::UdpBinding> {
        self.register_bound(sock, acceptor, None)
    }

    fn bind_udp_icmp(
        &self,
        sock: UdpSocket,
        acceptor: Arc<dyn DynAcceptor>,
        on_icmp: akio_core::IcmpHandler,
    ) -> io::Result<akio_core::UdpBinding> {
        #[cfg(target_os = "linux")]
        if akio_sys::enable_recverr(sock.as_raw_fd()) {
            return self
                .register_bound(sock, acceptor, Some(on_icmp))
                .map(akio_core::UdpBinding::with_recverr);
        }
        // macOS: the loop reads ICMP errors from an ICMP socket of its own (no pending errors
        // on the bound socket).
        #[cfg(target_os = "macos")]
        return self.register_bound(sock, acceptor, Some(on_icmp));
        // No error queue here: a plain binding.
        #[cfg(not(target_os = "macos"))]
        {
            let _ = on_icmp;
            self.register_bound(sock, acceptor, None)
        }
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

    fn open_udp_peer(
        &self,
        peer: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        // Any loop: they all send from the listener's port. With SO_REUSEPORT the peer's
        // answers may reach another loop, which then opens a peer of its own through the
        // listener's acceptor.
        let i = self.rr.fetch_add(1, Ordering::Relaxed) % self.shared.len();
        self.shared[i].post(Cmd::OpenPeer {
            peer,
            acceptor,
            on_error,
        });
    }
}
