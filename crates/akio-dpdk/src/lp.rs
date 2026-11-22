//! One stack queue's I/O thread: polls the device, drives its [`Iface`] and runs the
//! connections of every group attached to it.
//!
//! Each iteration: run posted commands, receive a burst of frames into the stack, act on the
//! events it reports (accepts, readable connections, connects, closes, datagrams), move what
//! handlers queued into the stack, let the stack send (timers, data, ACKs coalesced per burst)
//! and transmit the burst. Work is driven by events and the stack's timer heap: nothing scans
//! every connection per iteration. Handlers run corked, so what one callback sends enters the
//! stack once, after it returns.

use std::{
    collections::{HashMap, HashSet},
    io,
    net::SocketAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use akio_core::{
    Config, ConnInfo, ConnInner, DynAcceptor, DynHandler, Error, IdMap, LoopStats, Task,
    telemetry::LoopCmd,
};

use crate::{
    Congestion, DpdkConfig,
    device::{Port, Rx},
    net::{self, CallError, Event, Iface, TcpError, TcpHandle},
    stack::{Cmd, GroupLink, GroupSpec, LoopShared, StackCtl},
};

static NEXT_ID: AtomicU64 = AtomicU64::new(1 << 41);

/// Empty iterations before an adaptive loop starts sleeping.
const SPIN: u32 = 256;
/// Longest sleep of an adaptive loop (bounds the latency of cross-thread sends on fd devices).
const MAX_SLEEP: Duration = Duration::from_millis(1);
/// Idle-timeout scan period.
const SCAN: Duration = Duration::from_millis(50);
/// Most reads per TCP connection per iteration (fairness).
const MAX_READS: usize = 8;
/// Frames received per iteration before the stack sends (ACKs are coalesced per burst).
const RX_BURST: usize = 64;

struct Settings {
    busy_poll: bool,
}

/// One group on this loop.
struct GroupRt {
    spec: Arc<GroupSpec>,
    link: Arc<GroupLink>,
    /// The listener's port and protocol, if it listens.
    listen: Option<(bool, u16)>,
    draining: Option<Instant>,
    conns: usize,
}

enum Kind {
    /// A UDP peer: of a listener (`own == false`), or a dialed connection with its own port.
    /// The peer is boxed: a `SocketAddr` would make every connection's `Kind` (TCP ones
    /// included) 36 bytes instead of 16.
    Udp {
        port: u16,
        peer: Box<SocketAddr>,
        own: bool,
    },
    Tcp {
        h: TcpHandle,
    },
}

struct LConn {
    gid: u64,
    acceptor: Arc<dyn DynAcceptor>,
    inner: Arc<ConnInner>,
    handler: Box<dyn DynHandler>,
    cfg: Arc<Config>,
    stats: Arc<LoopStats>,
    kind: Kind,
    opened: Instant,
    last_active: Instant,
    bytes_in: u64,
    /// TCP: the peer sent FIN; the connection ends once its output has drained.
    peer_eof: bool,
}

struct PendingDial {
    gid: u64,
    acceptor: Arc<dyn DynAcceptor>,
    on_error: Box<dyn FnOnce(io::Error) + Send>,
    deadline: Instant,
}

pub(crate) struct Loop {
    index: usize,
    shared: Arc<LoopShared>,
    ctl: Arc<StackCtl>,
    port: Port,
    iface: Iface,
    queues: usize,
    set: Settings,
    groups: IdMap<GroupRt>,
    conns: IdMap<LConn>,
    tcp_ids: HashMap<TcpHandle, u64>,
    /// UDP listener peers: (listener port, peer) -> connection.
    udp_peers: HashMap<(u16, SocketAddr), u64>,
    /// Dialed UDP connections by their local port.
    udp_dialed: HashMap<u16, u64>,
    /// Listener ports: (udp, port) -> group.
    listen_ports: HashMap<(bool, u16), u64>,
    dials: HashMap<TcpHandle, PendingDial>,
    /// Connections whose output must be moved into the stack.
    dirty: Vec<u64>,
    /// TCP connections with unread data held back (read paused, or the read budget used up).
    paused: HashSet<u64>,
    events: Vec<Event>,
    rxbuf: Vec<u8>,
    scratch: Vec<u8>,
    ids: Vec<u64>,
    last_scan: Instant,
}

fn panic_error() -> Error {
    Error::Io(io::Error::other("handler panicked"))
}

fn tcp_error(e: TcpError) -> io::Error {
    match e {
        TcpError::Refused => io::ErrorKind::ConnectionRefused.into(),
        TcpError::Reset => io::Error::new(io::ErrorKind::ConnectionReset, "connection reset"),
        TcpError::TimedOut => io::Error::new(io::ErrorKind::TimedOut, "connection timed out"),
        TcpError::Unreachable => {
            io::Error::new(io::ErrorKind::HostUnreachable, "destination unreachable")
        }
    }
}

impl Loop {
    pub(crate) fn new(
        index: usize,
        queues: usize,
        shared: Arc<LoopShared>,
        ctl: Arc<StackCtl>,
        port: Port,
        mac: [u8; 6],
        cfg: &DpdkConfig,
    ) -> Loop {
        let mtu = cfg.mtu.clamp(576, 9000);
        let tcp = net::Params {
            mss: (mtu - 40) as u16,
            rx_buf: cfg.tcp_buffer.max(1024),
            tx_buf: cfg.tcp_buffer.max(1024),
            cc: match cfg.congestion {
                Congestion::NewReno => net::CcKind::NewReno,
                _ => net::CcKind::Cubic,
            },
            keepalive: cfg.tcp_keepalive,
            time_wait: Duration::from_secs(60),
            wscale: true,
            timestamps: true,
            sack: true,
            ecn: cfg.tcp_ecn,
            accecn: cfg.tcp_accecn,
            pacing: cfg.tcp_pacing,
        };
        let icfg = net::Config {
            mac,
            ip: cfg.address,
            prefix_len: cfg.prefix_len,
            gateway: cfg.gateway,
            ip6: cfg.address6,
            prefix_len6: cfg.prefix_len6,
            gateway6: cfg.gateway6,
            slaac: cfg.ipv6_slaac,
            dad: cfg.ipv6_dad,
            mtu,
            tcp,
            backlog: cfg.tcp_backlog.max(1),
            syn_cookies: cfg.syn_cookies,
            udp_queue: cfg.udp_buffer.max(mtu),
            verify_checksums: !port.partial_checksums(),
            queue: index,
            queues,
            dial_first: crate::stack::EPHEMERAL_FIRST,
            seed: None,
        };
        Loop {
            index,
            shared,
            ctl,
            port,
            iface: Iface::new(icfg, Instant::now()),
            queues,
            set: Settings {
                busy_poll: cfg.busy_poll,
            },
            groups: IdMap::default(),
            conns: IdMap::default(),
            tcp_ids: HashMap::new(),
            udp_peers: HashMap::new(),
            udp_dialed: HashMap::new(),
            listen_ports: HashMap::new(),
            dials: HashMap::new(),
            dirty: Vec::new(),
            paused: HashSet::new(),
            events: Vec::new(),
            rxbuf: Vec::new(),
            scratch: vec![0; 64 << 10],
            ids: Vec::new(),
            last_scan: Instant::now(),
        }
    }

    pub(crate) fn run(&mut self) {
        self.port.on_thread_start();
        let mut idle: u32 = 0;
        loop {
            let mut busy = false;
            if self.shared.has_cmds() {
                busy = true;
                if self.drain_cmds() {
                    break;
                }
            }
            let now = Instant::now();
            for _ in 0..RX_BURST {
                let Some(rx) = self.port.recv(&mut self.rxbuf) else {
                    break;
                };
                busy = true;
                let frame: &[u8] = match &rx {
                    Rx::Buf => &self.rxbuf,
                    Rx::Mbuf(m) => m.data(),
                };
                self.iface.receive(now, frame, &mut self.port);
            }
            for (q, f) in self.iface.take_forward() {
                self.port.forward(q, f);
            }
            if self.iface.has_events() {
                busy = true;
                self.handle_events();
            }
            if !self.paused.is_empty() {
                busy |= self.retry_paused();
            }
            if self.flush_dirty() {
                busy = true;
            }
            let now = Instant::now();
            self.iface.poll(now, &mut self.port);
            if self.index == 0 {
                if let Some(a) = self.iface.ipv6_changed() {
                    *self.ctl.ipv6.lock().unwrap_or_else(|p| p.into_inner()) = a;
                }
            }
            for (q, f) in self.iface.take_forward() {
                self.port.forward(q, f);
            }
            if self.iface.has_events() {
                busy = true;
                self.handle_events();
                self.flush_dirty();
                self.iface.poll(now, &mut self.port);
            }
            self.port.flush();
            self.housekeeping();
            for rt in self.groups.values() {
                rt.link.stats.iterations.add_local(1);
            }
            if busy {
                idle = 0;
                continue;
            }
            idle = idle.saturating_add(1);
            if !self.set.busy_poll && idle > SPIN {
                let now = Instant::now();
                let delay = self
                    .iface
                    .next_deadline()
                    .map_or(MAX_SLEEP, |t| t.saturating_duration_since(now))
                    .min(MAX_SLEEP);
                if !delay.is_zero() && !self.shared.has_cmds() && !self.iface.has_dirty() {
                    self.port.wait(delay);
                }
            }
        }
        // The stack is closing: every group has finished; nothing should be left.
        let ids: Vec<u64> = self.conns.keys().copied().collect();
        for id in ids {
            self.finalize(id, None);
        }
        self.iface.poll(Instant::now(), &mut self.port);
        self.port.flush();
    }

    // ---- commands -------------------------------------------------------------------------

    /// Runs posted commands; `true` when the thread must exit.
    fn drain_cmds(&mut self) -> bool {
        for cmd in self.shared.take() {
            match cmd {
                Cmd::Wake(id) => self.dirty.push(id),
                Cmd::Close(id, err) => self.finalize(id, err.map(Error::Io)),
                Cmd::Task(id, task) => self.on_task(id, task),
                Cmd::Attach(spec) => self.attach(spec),
                Cmd::Shutdown(gid) => self.begin_shutdown(gid),
                Cmd::Core(gid, LoopCmd::Inspect(reply)) => reply(self.inspect(gid)),
                Cmd::Core(..) => {}
                Cmd::Dial {
                    gid,
                    addr,
                    udp,
                    acceptor,
                    on_error,
                } => self.dial(gid, addr, udp, acceptor, on_error),
                Cmd::Exit => return true,
            }
        }
        false
    }

    fn attach(&mut self, spec: Arc<GroupSpec>) {
        let link = spec.links[self.index].clone();
        let mut rt = GroupRt {
            spec: spec.clone(),
            link,
            listen: None,
            draining: None,
            conns: 0,
        };
        if let Some(l) = &spec.listen {
            rt.listen = Some((l.udp, l.port));
            if l.udp {
                self.iface.udp_bind(l.port);
            } else {
                self.iface.tcp_listen(l.port);
            }
            self.listen_ports.insert((l.udp, l.port), spec.gid);
        }
        rt.link.stats.set_running(true);
        self.groups.insert(spec.gid, rt);
    }

    fn begin_shutdown(&mut self, gid: u64) {
        let Some(rt) = self.groups.get_mut(&gid) else {
            return;
        };
        if rt.draining.is_some() {
            return;
        }
        rt.draining = Some(Instant::now() + rt.spec.cfg.telemetry.live().shutdown_timeout());
        if let Some((false, port)) = rt.listen {
            // No new connections; handshakes in progress are refused once they complete.
            self.iface.tcp_unlisten(port);
        }
        let ids: Vec<u64> = self
            .conns
            .iter()
            .filter(|(_, c)| c.gid == gid)
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            let Some(c) = self.conns.get(&id) else {
                continue;
            };
            let (acc, inner) = (c.acceptor.clone(), c.inner.clone());
            if catch_unwind(AssertUnwindSafe(|| acc.on_shutdown(&inner))).is_err() {
                self.finalize(id, Some(panic_error()));
            } else {
                self.dirty.push(id); // flush whatever on_shutdown sent
            }
        }
    }

    fn inspect(&self, gid: u64) -> Vec<ConnInfo> {
        let now = Instant::now();
        self.conns
            .iter()
            .filter(|(_, c)| c.gid == gid)
            .map(|(&id, c)| {
                let mut ci = ConnInfo::new(id, &c.inner, c.stats.meta().clone());
                ci.age = now.saturating_duration_since(c.opened);
                ci.idle = now.saturating_duration_since(c.last_active);
                ci.bytes_in = c.bytes_in;
                ci
            })
            .collect()
    }

    fn dial(
        &mut self,
        gid: u64,
        addr: SocketAddr,
        udp: bool,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        // The stack has one interface: a scope id (or flow label) means nothing to it.
        let remote = SocketAddr::new(addr.ip(), addr.port());
        if !self.iface.has_family(remote.ip()) {
            return on_error(io::Error::new(
                io::ErrorKind::Unsupported,
                "the userspace stack has no IPv6 (set DpdkConfig::address6 or ipv6_slaac)",
            ));
        }
        if self.groups.get(&gid).is_none_or(|rt| rt.draining.is_some()) {
            return on_error(io::Error::new(
                io::ErrorKind::NotConnected,
                "the engine is shutting down",
            ));
        }
        for _ in 0..256 {
            let local = self.ctl.ephemeral_for(udp, self.index, self.queues);
            if udp {
                if !self.iface.udp_bind(local) {
                    continue;
                }
                let kind = Kind::Udp {
                    port: local,
                    peer: Box::new(remote),
                    own: true,
                };
                let local = SocketAddr::new(self.iface.local_for(remote.ip()), local);
                match self.open(gid, acceptor, kind, local, remote, true) {
                    Some(id) => {
                        self.udp_dialed.insert(local.port(), id);
                    }
                    None => self.iface.udp_unbind(local.port()),
                }
                return;
            }
            if self.iface.tcp_in_use(local, remote) {
                continue;
            }
            match self.iface.tcp_connect(local, remote, Instant::now()) {
                Ok(h) => {
                    self.dials.insert(
                        h,
                        PendingDial {
                            gid,
                            acceptor,
                            on_error,
                            deadline: Instant::now() + crate::CONNECT_TIMEOUT,
                        },
                    );
                    return;
                }
                Err(CallError::AddrInUse) => continue,
                Err(_) => {
                    return on_error(io::Error::new(
                        io::ErrorKind::NetworkUnreachable,
                        "no route to the destination (set DpdkConfig::gateway)",
                    ));
                }
            }
        }
        on_error(io::Error::new(
            io::ErrorKind::AddrInUse,
            "no free local port",
        ));
    }

    // ---- connections ----------------------------------------------------------------------

    /// Creates the connection and runs `on_open`. Returns its id, or `None` when refused.
    fn open(
        &mut self,
        gid: u64,
        acceptor: Arc<dyn DynAcceptor>,
        kind: Kind,
        local: SocketAddr,
        peer: SocketAddr,
        dialed: bool,
    ) -> Option<u64> {
        let rt = self.groups.get_mut(&gid)?;
        let cfg = rt.spec.cfg.clone();
        let link = rt.link.clone();
        let udp = matches!(kind, Kind::Udp { .. });
        if !cfg.telemetry.conn_opened(!udp && !dialed) {
            link.stats.rejected.add_local(1);
            return None;
        }
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let inner = ConnInner::new_virtual(id, udp, local, peer, link.clone(), cfg.clone());
        let Ok(handler) = catch_unwind(AssertUnwindSafe(|| acceptor.on_open(&inner))) else {
            inner.mark_closed();
            cfg.telemetry.conn_closed();
            return None;
        };
        if dialed {
            link.stats.dialed.add_local(1);
        } else {
            link.stats.accepted.add_local(1);
        }
        rt.conns += 1;
        let now = Instant::now();
        match &kind {
            Kind::Udp {
                port,
                peer,
                own: false,
            } => {
                self.udp_peers.insert((*port, **peer), id);
            }
            Kind::Tcp { h } => {
                self.tcp_ids.insert(*h, id);
            }
            Kind::Udp { .. } => {}
        }
        self.conns.insert(
            id,
            LConn {
                gid,
                acceptor,
                inner,
                handler,
                stats: link.stats.clone(),
                cfg,
                kind,
                opened: now,
                last_active: now,
                bytes_in: 0,
                peer_eof: false,
            },
        );
        // `on_open` may already have sent something or closed the connection.
        self.dirty.push(id);
        Some(id)
    }

    /// Runs `f` on `id`'s handler, corked, with slow-callback accounting.
    fn call(&mut self, id: u64, kind: &'static str, f: impl FnOnce(&mut dyn DynHandler)) {
        let Some(c) = self.conns.get_mut(&id) else {
            return;
        };
        let t0 = c.cfg.telemetry.timing();
        c.inner.set_corked(true);
        let r = catch_unwind(AssertUnwindSafe(|| f(&mut *c.handler)));
        c.inner.set_corked(false);
        c.cfg.telemetry.callback_done(&c.stats, kind, id, t0);
        if r.is_err() {
            self.finalize(id, Some(panic_error()));
        } else {
            self.dirty.push(id);
        }
    }

    fn on_task(&mut self, id: u64, task: Task) {
        self.call(id, "spawn_blocking completion", |h| h.run_task(task));
    }

    /// Delivers `self.scratch[..n]` to `id`; a datagram arrived with ECN codepoint `ecn`.
    fn deliver(&mut self, id: u64, n: usize, ecn: u8) {
        let data = std::mem::take(&mut self.scratch);
        if let Some(c) = self.conns.get_mut(&id) {
            c.last_active = Instant::now();
            c.bytes_in += n as u64;
            if matches!(c.kind, Kind::Udp { .. }) {
                c.stats.datagram_in(n);
                c.inner.set_rx_ecn(ecn);
            } else {
                c.stats.bytes_in.add_local(n as u64);
                c.stats.reads.add_local(1);
            }
        }
        self.call(id, "on_data", |h| h.on_data(&data[..n]));
        self.scratch = data;
    }

    /// Acts on what the stack reported.
    fn handle_events(&mut self) {
        let mut events = std::mem::take(&mut self.events);
        self.iface.take_events(&mut events);
        for e in events.drain(..) {
            match e {
                Event::Accepted { port, h } => self.on_accept(port, h),
                Event::Connected(h) => self.on_connected(h),
                Event::ConnectFailed(h, err) => {
                    if let Some(d) = self.dials.remove(&h) {
                        (d.on_error)(tcp_error(err));
                    }
                }
                Event::Readable(h) => {
                    if let Some(&id) = self.tcp_ids.get(&h) {
                        self.read_tcp(id);
                    }
                }
                Event::Writable(h) => {
                    if let Some(&id) = self.tcp_ids.get(&h) {
                        self.dirty.push(id);
                    }
                }
                Event::Closed(h, err) => {
                    if let Some(id) = self.tcp_ids.remove(&h) {
                        self.finalize(id, err.map(|e| Error::Io(tcp_error(e))));
                    }
                }
                Event::UdpUnreachable { port, remote } => {
                    if let Some(&id) = self.udp_dialed.get(&port) {
                        let matches = self.conns.get(&id).is_some_and(
                            |c| matches!(&c.kind, Kind::Udp { peer, .. } if **peer == *remote),
                        );
                        if matches {
                            let e = io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                "port unreachable",
                            );
                            self.finalize(id, Some(Error::Io(e)));
                        }
                    }
                }
            }
        }
        self.events = events;
        // Datagrams.
        while let Some((port, from, n, ecn)) = self.iface.udp_recv_ecn(&mut self.scratch) {
            if let Some(&id) = self.udp_dialed.get(&port) {
                let ok = self
                    .conns
                    .get(&id)
                    .is_some_and(|c| matches!(&c.kind, Kind::Udp { peer, .. } if **peer == from));
                if ok {
                    self.deliver(id, n, ecn);
                }
                continue;
            }
            if let Some(&gid) = self.listen_ports.get(&(true, port)) {
                self.on_datagram(gid, port, from, n, ecn);
            }
        }
    }

    fn on_accept(&mut self, port: u16, h: TcpHandle) {
        let now = Instant::now();
        let target = self
            .listen_ports
            .get(&(false, port))
            .copied()
            .and_then(|gid| {
                let rt = self.groups.get(&gid)?;
                if rt.draining.is_some() {
                    return None;
                }
                Some((gid, rt.spec.listen.as_ref()?.acceptor.clone()))
            });
        let addrs = self.iface.tcp_local(h).zip(self.iface.tcp_peer(h));
        let (Some((gid, acceptor)), Some((local, peer))) = (target, addrs) else {
            self.iface.tcp_abort(h, now, &mut self.port);
            return;
        };
        match self.open(gid, acceptor, Kind::Tcp { h }, local, peer, false) {
            Some(id) => self.read_tcp(id),
            None => self.iface.tcp_abort(h, now, &mut self.port),
        }
    }

    fn on_connected(&mut self, h: TcpHandle) {
        let Some(d) = self.dials.remove(&h) else {
            // Nobody waits for it (timed out, group gone).
            self.iface.tcp_abort(h, Instant::now(), &mut self.port);
            return;
        };
        let (Some(local), Some(peer)) = (self.iface.tcp_local(h), self.iface.tcp_peer(h)) else {
            (d.on_error)(io::ErrorKind::ConnectionReset.into());
            return;
        };
        match self.open(d.gid, d.acceptor, Kind::Tcp { h }, local, peer, true) {
            Some(id) => self.read_tcp(id),
            None => {
                self.iface.tcp_abort(h, Instant::now(), &mut self.port);
                (d.on_error)(io::Error::other("connection refused locally"));
            }
        }
    }

    fn on_datagram(&mut self, gid: u64, port: u16, from: SocketAddr, n: usize, ecn: u8) {
        let id = match self.udp_peers.get(&(port, from)) {
            Some(&id) => id,
            None => {
                let Some(rt) = self.groups.get(&gid) else {
                    return;
                };
                if rt.draining.is_some() {
                    return;
                }
                let spec = rt.spec.clone();
                let before = spec.peers.fetch_add(1, Ordering::Relaxed);
                if spec.cfg.udp_max_peers.is_some_and(|max| before >= max) {
                    spec.peers.fetch_sub(1, Ordering::Relaxed);
                    spec.rejected.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                let Some(acceptor) = spec.listen.as_ref().map(|l| l.acceptor.clone()) else {
                    spec.peers.fetch_sub(1, Ordering::Relaxed);
                    return;
                };
                let kind = Kind::Udp {
                    port,
                    peer: Box::new(from),
                    own: false,
                };
                let local = SocketAddr::new(self.iface.local_for(from.ip()), port);
                match self.open(gid, acceptor, kind, local, from, false) {
                    Some(id) => id,
                    None => {
                        spec.peers.fetch_sub(1, Ordering::Relaxed);
                        return;
                    }
                }
            }
        };
        self.deliver(id, n, ecn);
    }

    /// Reads what a TCP connection has (within the read budget and backpressure), and notes the
    /// peer's FIN.
    fn read_tcp(&mut self, id: u64) {
        let Some(c) = self.conns.get(&id) else {
            return;
        };
        let Kind::Tcp { h } = c.kind else {
            return;
        };
        let watermark = c.cfg.telemetry.live().write_high_watermark();
        self.paused.remove(&id);
        for _ in 0..MAX_READS {
            let Some(c) = self.conns.get(&id) else {
                return;
            };
            if self.iface.tcp_readable(h) == 0 {
                break;
            }
            if c.inner.read_held()
                || (c.inner.write_backpressure() && c.inner.queued_bytes() >= watermark)
            {
                self.paused.insert(id);
                return;
            }
            let n = self.iface.tcp_recv(h, &mut self.scratch);
            if n == 0 {
                break;
            }
            self.deliver(id, n, 0);
        }
        let Some(c) = self.conns.get_mut(&id) else {
            return;
        };
        if self.iface.tcp_readable(h) > 0 {
            self.paused.insert(id); // budget used up: more next iteration
            return;
        }
        if !c.peer_eof && self.iface.tcp_eof(h) {
            // The peer sent FIN: end once our output has drained.
            c.peer_eof = true;
            self.dirty.push(id);
        }
    }

    /// Re-reads connections whose reads were held back. `true` if anything was read.
    fn retry_paused(&mut self) -> bool {
        let mut ids = std::mem::take(&mut self.ids);
        ids.clear();
        ids.extend(self.paused.iter().copied());
        let mut any = false;
        for &id in &ids {
            let Some(c) = self.conns.get(&id) else {
                self.paused.remove(&id);
                continue;
            };
            let watermark = c.cfg.telemetry.live().write_high_watermark();
            if c.inner.read_held()
                || (c.inner.write_backpressure() && c.inner.queued_bytes() >= watermark)
            {
                continue;
            }
            any = true;
            self.read_tcp(id);
        }
        self.ids = ids;
        any
    }

    /// Moves queued output of the dirty connections into the stack. `true` if any.
    fn flush_dirty(&mut self) -> bool {
        if self.dirty.is_empty() {
            return false;
        }
        let mut ids = std::mem::take(&mut self.dirty);
        ids.sort_unstable();
        ids.dedup();
        for &id in &ids {
            self.flush(id);
        }
        ids.clear();
        if self.dirty.is_empty() {
            self.dirty = ids;
        }
        true
    }

    fn flush(&mut self, id: u64) {
        let Some(c) = self.conns.get(&id) else {
            return;
        };
        let now = Instant::now();
        let iface = &mut self.iface;
        let r = match c.kind {
            Kind::Udp { port, ref peer, .. } => {
                let peer = **peer;
                let tx = &mut self.port;
                c.inner.drain_output_ecn(&mut |d, ecn| {
                    // A datagram that cannot be sent is dropped, as UDP does.
                    let _ = iface.udp_send_ecn(now, tx, port, peer, d, ecn);
                    d.len()
                })
            }
            Kind::Tcp { h } => c.inner.drain_output(&mut |d| iface.tcp_send(h, d)),
        };
        match r {
            Err(e) => self.finalize(id, Some(Error::Io(e))),
            // Partly queued: the stack reports `Writable` when space frees up.
            Ok(false) => {}
            Ok(true) => {
                if c.inner.close_after_send_requested() || c.peer_eof {
                    self.finalize(id, None);
                }
            }
        }
    }

    /// Ends connection `id`: TCP sends FIN (orderly) or RST (error), `on_close` runs.
    fn finalize(&mut self, id: u64, err: Option<Error>) {
        let Some(mut c) = self.conns.remove(&id) else {
            return;
        };
        self.paused.remove(&id);
        let now = Instant::now();
        match c.kind {
            Kind::Udp {
                port,
                ref peer,
                own,
            } => {
                if own {
                    self.iface.udp_unbind(port);
                    self.udp_dialed.remove(&port);
                } else {
                    self.udp_peers.remove(&(port, **peer));
                    if let Some(rt) = self.groups.get(&c.gid) {
                        rt.spec.peers.fetch_sub(1, Ordering::Relaxed);
                    }
                }
            }
            Kind::Tcp { h } => {
                self.tcp_ids.remove(&h);
                if err.is_none() {
                    self.iface.tcp_close(h, now);
                } else {
                    self.iface.tcp_abort(h, now, &mut self.port);
                }
            }
        }
        if let Some(rt) = self.groups.get_mut(&c.gid) {
            rt.conns = rt.conns.saturating_sub(1);
        }
        c.inner.mark_closed();
        let t0 = c.cfg.telemetry.timing();
        let _ = catch_unwind(AssertUnwindSafe(|| c.handler.on_close(err)));
        c.cfg.telemetry.callback_done(&c.stats, "on_close", id, t0);
        c.stats.closed.add_local(1);
        c.cfg.telemetry.conn_closed();
    }

    // ---- timers ---------------------------------------------------------------------------

    fn housekeeping(&mut self) {
        let now = Instant::now();
        // Draining groups: UDP peers end once flushed; everything ends at the deadline.
        let draining: Vec<(u64, Instant)> = self
            .groups
            .iter()
            .filter_map(|(&g, rt)| rt.draining.map(|d| (g, d)))
            .collect();
        for (gid, deadline) in draining {
            let ids: Vec<u64> = self
                .conns
                .iter()
                .filter(|(_, c)| {
                    c.gid == gid
                        && (now >= deadline
                            || (matches!(c.kind, Kind::Udp { .. }) && c.inner.queued_bytes() == 0))
                })
                .map(|(&id, _)| id)
                .collect();
            for id in ids {
                self.finalize(id, None);
            }
            if self.groups.get(&gid).is_some_and(|rt| rt.conns == 0) {
                self.finish_group(gid);
            }
        }
        if now.duration_since(self.last_scan) < SCAN {
            return;
        }
        self.last_scan = now;
        // Idle timeouts.
        let expired: Vec<u64> = self
            .conns
            .iter()
            .filter(|(_, c)| {
                let limit = match c.kind {
                    Kind::Udp { .. } => Some(
                        c.cfg
                            .telemetry
                            .live()
                            .idle_timeout()
                            .map_or(c.cfg.udp_idle_timeout, |i| i.min(c.cfg.udp_idle_timeout)),
                    ),
                    Kind::Tcp { .. } => c.cfg.telemetry.live().idle_timeout(),
                };
                limit.is_some_and(|l| now.saturating_duration_since(c.last_active) >= l)
            })
            .map(|(&id, _)| id)
            .collect();
        for id in expired {
            if let Some(c) = self.conns.get(&id) {
                c.stats.idle_timeouts.add_local(1);
            }
            let e = io::Error::new(io::ErrorKind::TimedOut, "idle timeout");
            self.finalize(id, Some(Error::Io(e)));
        }
        // Dials that take too long.
        let late: Vec<TcpHandle> = self
            .dials
            .iter()
            .filter(|(_, d)| now >= d.deadline)
            .map(|(&h, _)| h)
            .collect();
        for h in late {
            if let Some(d) = self.dials.remove(&h) {
                self.iface.tcp_abort(h, now, &mut self.port);
                (d.on_error)(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
            }
        }
    }

    /// Group `gid` has no connections left on this loop and is shutting down: release it.
    fn finish_group(&mut self, gid: u64) {
        let Some(rt) = self.groups.remove(&gid) else {
            return;
        };
        if let Some((udp, port)) = rt.listen {
            if udp {
                self.iface.udp_unbind(port);
            } else {
                self.iface.tcp_unlisten(port);
            }
            self.listen_ports.remove(&(udp, port));
        }
        let mine: Vec<TcpHandle> = self
            .dials
            .iter()
            .filter(|(_, d)| d.gid == gid)
            .map(|(&h, _)| h)
            .collect();
        for h in mine {
            if let Some(d) = self.dials.remove(&h) {
                self.iface.tcp_abort(h, Instant::now(), &mut self.port);
                (d.on_error)(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "the engine shut down",
                ));
            }
        }
        rt.link.stats.set_running(false);
        self.ctl.loop_done(&rt.spec);
    }
}
