//! One stack queue's I/O thread: polls the device through smoltcp and runs the connections of
//! every group attached to it.
//!
//! Each iteration: run posted commands, `Interface::poll` (rx burst -> protocol processing ->
//! tx), hand new data to handlers, move what they queued into smoltcp's socket buffers, poll
//! again for egress, transmit the burst. Handlers run corked, so everything a callback sends is
//! moved into the stack once, after it returns.

use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use only_core::{
    Config, ConnInfo, ConnInner, DynAcceptor, DynHandler, Error, IdMap, LoopStats, Task,
    telemetry::LoopCmd,
};
use smoltcp::{
    iface::{Config as IfaceConfig, Interface, PollResult, SocketHandle, SocketSet},
    socket::{tcp, udp},
    time::Instant as SInstant,
    wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint},
};

use crate::{
    DpdkConfig,
    device::Port,
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
/// A closed TCP socket is kept this long at most to finish its FIN/RST exchange.
const LINGER: Duration = Duration::from_secs(30);

struct Settings {
    tcp_buffer: usize,
    udp_buffer: usize,
    tcp_backlog: usize,
    busy_poll: bool,
}

/// One group on this loop.
struct GroupRt {
    spec: Arc<GroupSpec>,
    link: Arc<GroupLink>,
    /// The listener's UDP socket.
    udp: Option<SocketHandle>,
    /// The listener's TCP sockets waiting for a handshake.
    listening: Vec<SocketHandle>,
    port: u16,
    draining: Option<Instant>,
    conns: usize,
}

enum Kind {
    /// A UDP peer: of the listener's socket, or of a dialed connection's own socket (`own`).
    Udp {
        sock: SocketHandle,
        ep: IpEndpoint,
        own: bool,
    },
    Tcp {
        sock: SocketHandle,
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
    sock: SocketHandle,
    acceptor: Arc<dyn DynAcceptor>,
    on_error: Box<dyn FnOnce(io::Error) + Send>,
    deadline: Instant,
}

pub(crate) struct Loop {
    index: usize,
    shared: Arc<LoopShared>,
    ctl: Arc<StackCtl>,
    port: Port,
    iface: Interface,
    sockets: SocketSet<'static>,
    ip: Ipv4Addr,
    set: Settings,
    groups: IdMap<GroupRt>,
    conns: IdMap<LConn>,
    udp_peers: HashMap<(SocketHandle, IpEndpoint), u64>,
    /// Connections whose output must be moved into the stack.
    dirty: Vec<u64>,
    /// Connections whose socket buffer was full (retried every iteration).
    blocked: HashSet<u64>,
    lingering: Vec<(SocketHandle, Instant)>,
    dials: Vec<PendingDial>,
    scratch: Vec<u8>,
    ids: Vec<u64>,
    /// Re-examine every connection (reads, state) this iteration.
    recheck: bool,
    last_scan: Instant,
}

fn panic_error() -> Error {
    Error::Io(io::Error::other("handler panicked"))
}

fn to_sockaddr(ep: IpEndpoint) -> SocketAddr {
    let ip: IpAddr = match ep.addr {
        IpAddress::Ipv4(a) => IpAddr::V4(a),
    };
    SocketAddr::new(ip, ep.port)
}

fn now_s() -> SInstant {
    SInstant::now()
}

impl Loop {
    pub(crate) fn new(
        index: usize,
        shared: Arc<LoopShared>,
        ctl: Arc<StackCtl>,
        mut port: Port,
        mac: [u8; 6],
        cfg: &DpdkConfig,
    ) -> Loop {
        let mut ic = IfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
        ic.random_seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64)
            ^ (index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let mut iface = Interface::new(ic, &mut port, now_s());
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::Ipv4(cfg.address), cfg.prefix_len));
        });
        if let Some(gw) = cfg.gateway {
            let _ = iface.routes_mut().add_default_ipv4_route(gw);
        }
        Loop {
            index,
            shared,
            ctl,
            port,
            iface,
            sockets: SocketSet::new(Vec::new()),
            ip: cfg.address,
            set: Settings {
                tcp_buffer: cfg.tcp_buffer.max(1024),
                udp_buffer: cfg.udp_buffer.max(cfg.mtu),
                tcp_backlog: cfg.tcp_backlog.max(1),
                busy_poll: cfg.busy_poll,
            },
            groups: IdMap::default(),
            conns: IdMap::default(),
            udp_peers: HashMap::new(),
            dirty: Vec::new(),
            blocked: HashSet::new(),
            lingering: Vec::new(),
            dials: Vec::new(),
            scratch: vec![0; 64 << 10],
            ids: Vec::new(),
            recheck: false,
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
            let rx0 = self.port.rx_frames;
            let changed = self.iface.poll(now_s(), &mut self.port, &mut self.sockets)
                == PollResult::SocketStateChanged;
            if self.port.rx_frames != rx0 {
                busy = true;
            }
            if changed || std::mem::take(&mut self.recheck) {
                busy |= self.service();
            }
            if self.flush_dirty() {
                busy = true;
                self.iface.poll(now_s(), &mut self.port, &mut self.sockets);
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
                let delay = self
                    .iface
                    .poll_delay(now_s(), &self.sockets)
                    .map_or(MAX_SLEEP, Duration::from)
                    .min(MAX_SLEEP);
                if !delay.is_zero() && !self.shared.has_cmds() {
                    self.port.wait(delay);
                }
            }
        }
        // The stack is closing: every group has finished; nothing should be left.
        let ids: Vec<u64> = self.conns.keys().copied().collect();
        for id in ids {
            self.finalize(id, None);
        }
        self.port.flush();
    }

    // ---- commands -------------------------------------------------------------------------

    /// Runs posted commands; `true` when the thread must exit.
    fn drain_cmds(&mut self) -> bool {
        self.recheck = true;
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

    fn udp_socket(&self) -> udp::Socket<'static> {
        let n = (self.set.udp_buffer / 64).clamp(64, 4096);
        udp::Socket::new(
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; n],
                vec![0; self.set.udp_buffer],
            ),
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; n],
                vec![0; self.set.udp_buffer],
            ),
        )
    }

    fn tcp_socket(&self) -> tcp::Socket<'static> {
        let mut s = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; self.set.tcp_buffer]),
            tcp::SocketBuffer::new(vec![0; self.set.tcp_buffer]),
        );
        // Handlers already coalesce what one callback sends; Nagle would only add latency.
        s.set_nagle_enabled(false);
        s
    }

    fn listen_tcp(&mut self, port: u16) -> Option<SocketHandle> {
        let mut s = self.tcp_socket();
        s.listen(IpListenEndpoint { addr: None, port }).ok()?;
        Some(self.sockets.add(s))
    }

    fn attach(&mut self, spec: Arc<GroupSpec>) {
        let link = spec.links[self.index].clone();
        let mut rt = GroupRt {
            spec: spec.clone(),
            link,
            udp: None,
            listening: Vec::new(),
            port: 0,
            draining: None,
            conns: 0,
        };
        if let Some(l) = &spec.listen {
            rt.port = l.port;
            if l.udp {
                let mut s = self.udp_socket();
                if s.bind(IpListenEndpoint {
                    addr: None,
                    port: l.port,
                })
                .is_ok()
                {
                    rt.udp = Some(self.sockets.add(s));
                }
            } else {
                for _ in 0..self.set.tcp_backlog {
                    if let Some(h) = self.listen_tcp(l.port) {
                        rt.listening.push(h);
                    }
                }
            }
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
        for h in std::mem::take(&mut rt.listening) {
            self.sockets.remove(h);
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
        let SocketAddr::V4(v4) = addr else {
            return on_error(io::Error::new(
                io::ErrorKind::Unsupported,
                "the userspace stack is IPv4-only",
            ));
        };
        if !self.groups.contains_key(&gid) {
            return on_error(io::Error::new(
                io::ErrorKind::NotConnected,
                "the engine is shutting down",
            ));
        }
        let remote = IpEndpoint::new(IpAddress::Ipv4(*v4.ip()), v4.port());
        let local = self.ctl.ephemeral(udp);
        if udp {
            let mut s = self.udp_socket();
            if let Err(e) = s.bind(local) {
                return on_error(io::Error::other(format!("udp bind: {e}")));
            }
            let sock = self.sockets.add(s);
            if self
                .open(
                    gid,
                    acceptor,
                    Kind::Udp {
                        sock,
                        ep: remote,
                        own: true,
                    },
                    local,
                    addr,
                    true,
                )
                .is_none()
            {
                self.sockets.remove(sock);
            }
            return;
        }
        let mut s = self.tcp_socket();
        if let Err(e) = s.connect(self.iface.context(), remote, local) {
            return on_error(io::Error::other(format!("tcp connect: {e}")));
        }
        let sock = self.sockets.add(s);
        self.dials.push(PendingDial {
            gid,
            sock,
            acceptor,
            on_error,
            deadline: Instant::now() + crate::CONNECT_TIMEOUT,
        });
    }

    // ---- connections ----------------------------------------------------------------------

    /// Creates the connection and runs `on_open`. Returns its id, or `None` when refused.
    fn open(
        &mut self,
        gid: u64,
        acceptor: Arc<dyn DynAcceptor>,
        kind: Kind,
        local_port: u16,
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
        let local = SocketAddr::new(IpAddr::V4(self.ip), local_port);
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
        if let Kind::Udp {
            sock,
            ep,
            own: false,
        } = kind
        {
            self.udp_peers.insert((sock, ep), id);
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

    /// Delivers `self.scratch[..n]` to `id`.
    fn deliver(&mut self, id: u64, n: usize) {
        let data = std::mem::take(&mut self.scratch);
        if let Some(c) = self.conns.get_mut(&id) {
            c.last_active = Instant::now();
            c.bytes_in += n as u64;
            if matches!(c.kind, Kind::Udp { .. }) {
                c.stats.datagram_in(n);
            } else {
                c.stats.bytes_in.add_local(n as u64);
                c.stats.reads.add_local(1);
            }
        }
        self.call(id, "on_data", |h| h.on_data(&data[..n]));
        self.scratch = data;
    }

    /// Accepts, receives and checks connection state after a poll. `true` if anything happened.
    fn service(&mut self) -> bool {
        let mut busy = false;
        // Handshakes completed on listening sockets become connections; a fresh listening
        // socket takes their place.
        let gids: Vec<u64> = self.groups.keys().copied().collect();
        for &gid in &gids {
            let Some(rt) = self.groups.get(&gid) else {
                continue;
            };
            if rt.draining.is_some() || rt.listening.is_empty() {
                continue;
            }
            let (port, n) = (rt.port, rt.listening.len());
            for i in 0..n {
                let h = self.groups[&gid].listening[i];
                let s = self.sockets.get_mut::<tcp::Socket<'_>>(h);
                match s.state() {
                    tcp::State::Listen | tcp::State::SynReceived => continue,
                    tcp::State::Established | tcp::State::CloseWait => {}
                    _ => {
                        // Reset during the handshake: listen again.
                        s.abort();
                        let _ = s.listen(IpListenEndpoint { addr: None, port });
                        continue;
                    }
                }
                let peer = s.remote_endpoint().map(to_sockaddr);
                let Some(fresh) = self.listen_tcp(port) else {
                    continue;
                };
                self.groups.get_mut(&gid).expect("group present").listening[i] = fresh;
                busy = true;
                let acceptor = self.groups[&gid]
                    .spec
                    .listen
                    .as_ref()
                    .map(|l| l.acceptor.clone());
                let (Some(peer), Some(acceptor)) = (peer, acceptor) else {
                    self.sockets.remove(h);
                    continue;
                };
                if self
                    .open(gid, acceptor, Kind::Tcp { sock: h }, port, peer, false)
                    .is_none()
                {
                    self.sockets.get_mut::<tcp::Socket<'_>>(h).abort();
                    self.lingering.push((h, Instant::now()));
                }
            }
        }
        // Dialed TCP connections.
        let mut i = 0;
        while i < self.dials.len() {
            let s = self.sockets.get::<tcp::Socket<'_>>(self.dials[i].sock);
            match s.state() {
                tcp::State::Established | tcp::State::CloseWait => {
                    let local = s.local_endpoint().map_or(0, |e| e.port);
                    let peer = s.remote_endpoint().map(to_sockaddr);
                    let d = self.dials.swap_remove(i);
                    busy = true;
                    let Some(peer) = peer else { continue };
                    if self
                        .open(
                            d.gid,
                            d.acceptor,
                            Kind::Tcp { sock: d.sock },
                            local,
                            peer,
                            true,
                        )
                        .is_none()
                    {
                        self.sockets.get_mut::<tcp::Socket<'_>>(d.sock).abort();
                        self.lingering.push((d.sock, Instant::now()));
                        (d.on_error)(io::Error::other("connection refused locally"));
                    }
                }
                tcp::State::Closed | tcp::State::TimeWait => {
                    let d = self.dials.swap_remove(i);
                    self.sockets.remove(d.sock);
                    (d.on_error)(io::ErrorKind::ConnectionRefused.into());
                    busy = true;
                }
                _ => i += 1,
            }
        }
        // UDP listener sockets.
        for &gid in &gids {
            let Some(h) = self.groups.get(&gid).and_then(|rt| rt.udp) else {
                continue;
            };
            loop {
                let s = self.sockets.get_mut::<udp::Socket<'_>>(h);
                let Ok((n, meta)) = s.recv_slice(&mut self.scratch) else {
                    break;
                };
                busy = true;
                self.on_datagram(gid, h, meta.endpoint, n);
            }
        }
        // Connections: dialed UDP sockets, TCP reads and state.
        let mut ids = std::mem::take(&mut self.ids);
        ids.clear();
        ids.extend(self.conns.keys().copied());
        for &id in &ids {
            busy |= self.service_conn(id);
        }
        self.ids = ids;
        busy
    }

    fn on_datagram(&mut self, gid: u64, sock: SocketHandle, ep: IpEndpoint, n: usize) {
        let id = match self.udp_peers.get(&(sock, ep)) {
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
                let port = rt.port;
                let kind = Kind::Udp {
                    sock,
                    ep,
                    own: false,
                };
                match self.open(gid, acceptor, kind, port, to_sockaddr(ep), false) {
                    Some(id) => id,
                    None => {
                        spec.peers.fetch_sub(1, Ordering::Relaxed);
                        return;
                    }
                }
            }
        };
        self.deliver(id, n);
    }

    /// Reads and state checks of one connection. `true` if anything happened.
    fn service_conn(&mut self, id: u64) -> bool {
        let Some(c) = self.conns.get(&id) else {
            return false;
        };
        let mut busy = false;
        match c.kind {
            Kind::Udp {
                sock,
                ep,
                own: true,
            } => loop {
                let s = self.sockets.get_mut::<udp::Socket<'_>>(sock);
                let Ok((n, meta)) = s.recv_slice(&mut self.scratch) else {
                    break;
                };
                busy = true;
                if meta.endpoint == ep {
                    self.deliver(id, n);
                    if !self.conns.contains_key(&id) {
                        break;
                    }
                }
            },
            Kind::Udp { .. } => {}
            Kind::Tcp { sock } => {
                let watermark = c.cfg.telemetry.live().write_high_watermark();
                for _ in 0..MAX_READS {
                    let Some(c) = self.conns.get(&id) else {
                        return true;
                    };
                    if c.inner.read_held() || c.inner.queued_bytes() >= watermark {
                        break;
                    }
                    let s = self.sockets.get_mut::<tcp::Socket<'_>>(sock);
                    let n = match s.recv_slice(&mut self.scratch) {
                        Ok(n) if n > 0 => n,
                        _ => break,
                    };
                    busy = true;
                    self.deliver(id, n);
                }
                let Some(c) = self.conns.get_mut(&id) else {
                    return true;
                };
                let s = self.sockets.get::<tcp::Socket<'_>>(sock);
                if s.state() == tcp::State::Closed {
                    let e = io::Error::new(io::ErrorKind::ConnectionReset, "connection reset");
                    self.finalize(id, Some(Error::Io(e)));
                    return true;
                }
                if !c.peer_eof && !s.may_recv() && !s.can_recv() {
                    // The peer sent FIN: end once our output has drained.
                    c.peer_eof = true;
                    self.dirty.push(id);
                    busy = true;
                }
            }
        }
        busy
    }

    /// Moves queued output of the dirty (and previously blocked) connections into the stack.
    /// `true` if anything was moved.
    fn flush_dirty(&mut self) -> bool {
        if self.dirty.is_empty() && self.blocked.is_empty() {
            return false;
        }
        let mut ids = std::mem::take(&mut self.dirty);
        ids.extend(self.blocked.iter().copied());
        ids.sort_unstable();
        ids.dedup();
        let mut moved = false;
        for &id in &ids {
            moved |= self.flush(id);
        }
        ids.clear();
        if self.dirty.is_empty() {
            self.dirty = ids;
        }
        // Drained queues may let paused readers resume.
        self.recheck |= moved;
        moved
    }

    fn flush(&mut self, id: u64) -> bool {
        let Some(c) = self.conns.get(&id) else {
            self.blocked.remove(&id);
            return false;
        };
        let mut moved = false;
        let r = match c.kind {
            Kind::Udp { sock, ep, .. } => {
                let s = self.sockets.get_mut::<udp::Socket<'_>>(sock);
                c.inner.drain_output(&mut |d| {
                    if d.len() > s.payload_send_capacity() {
                        return d.len(); // can never fit: dropped, as UDP does
                    }
                    match s.send_slice(d, ep) {
                        Ok(()) => {
                            moved = true;
                            d.len()
                        }
                        Err(udp::SendError::BufferFull) => 0,
                        Err(_) => d.len(),
                    }
                })
            }
            Kind::Tcp { sock } => {
                let s = self.sockets.get_mut::<tcp::Socket<'_>>(sock);
                c.inner.drain_output(&mut |d| {
                    let n = s.send_slice(d).unwrap_or(0);
                    moved |= n > 0;
                    n
                })
            }
        };
        match r {
            Err(e) => self.finalize(id, Some(Error::Io(e))),
            Ok(false) => {
                self.blocked.insert(id);
            }
            Ok(true) => {
                self.blocked.remove(&id);
                if c.inner.close_after_send_requested() || c.peer_eof {
                    self.finalize(id, None);
                }
            }
        }
        moved
    }

    /// Ends connection `id`: TCP sends FIN (orderly) or RST (error), `on_close` runs.
    fn finalize(&mut self, id: u64, err: Option<Error>) {
        let Some(mut c) = self.conns.remove(&id) else {
            return;
        };
        self.blocked.remove(&id);
        match c.kind {
            Kind::Udp { sock, ep, own } => {
                if own {
                    self.sockets.remove(sock);
                } else {
                    self.udp_peers.remove(&(sock, ep));
                    if let Some(rt) = self.groups.get(&c.gid) {
                        rt.spec.peers.fetch_sub(1, Ordering::Relaxed);
                    }
                }
            }
            Kind::Tcp { sock } => {
                let s = self.sockets.get_mut::<tcp::Socket<'_>>(sock);
                if err.is_none() {
                    s.close();
                } else {
                    s.abort();
                }
                self.lingering.push((sock, Instant::now()));
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
        let mut i = 0;
        while i < self.dials.len() {
            if now >= self.dials[i].deadline {
                let d = self.dials.swap_remove(i);
                self.sockets.get_mut::<tcp::Socket<'_>>(d.sock).abort();
                self.lingering.push((d.sock, now));
                (d.on_error)(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
            } else {
                i += 1;
            }
        }
        // Closed TCP sockets that finished their exchange.
        let sockets = &mut self.sockets;
        self.lingering.retain(|&(h, since)| {
            let s = sockets.get::<tcp::Socket<'_>>(h);
            let done = matches!(s.state(), tcp::State::Closed | tcp::State::TimeWait)
                || now.duration_since(since) >= LINGER;
            if done {
                sockets.remove(h);
            }
            !done
        });
    }

    /// Group `gid` has no connections left on this loop and is shutting down: release it.
    fn finish_group(&mut self, gid: u64) {
        let Some(rt) = self.groups.remove(&gid) else {
            return;
        };
        if let Some(h) = rt.udp {
            self.sockets.remove(h);
        }
        for h in rt.listening {
            self.sockets.remove(h);
        }
        let mut i = 0;
        while i < self.dials.len() {
            if self.dials[i].gid == gid {
                let d = self.dials.swap_remove(i);
                self.sockets.remove(d.sock);
                (d.on_error)(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "the engine shut down",
                ));
            } else {
                i += 1;
            }
        }
        rt.link.stats.set_running(false);
        self.ctl.loop_done(&rt.spec);
    }
}
