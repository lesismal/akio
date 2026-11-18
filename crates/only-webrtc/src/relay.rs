//! TURN allocations of an [`Endpoint`](crate::Endpoint): relayed candidates shared by its peers.
//!
//! One [`Relay`] drives one [`only_turn::client::Client`], over the endpoint's UDP socket or
//! over a TCP or TLS connection of the engine ([`RelayServer`](crate::RelayServer)). Over UDP
//! the server's datagrams are read off the socket before peer routing; over a stream the
//! connection's messages are cut by [`FrameReader`]. Relayed data comes out as if it had
//! arrived on the relayed address, and whatever a peer sends from the relayed address goes to
//! the client (channels, permissions and refreshes are its business). Its timers run on the
//! shared WebRTC timer thread.
//!
//! An allocation that is lost after it was made (the connection closed, a refresh failed) is
//! made again, with a backoff from [`RETRY_MIN`] doubling to [`RETRY_MAX`], for as long as the
//! endpoint lives: the new relayed address replaces the old one in the endpoint's candidates
//! and is added to every open peer, whose agent checks it against the remote candidates it
//! knows. What a peer still sends from a retired relayed address is dropped.

use std::collections::VecDeque;
use std::mem;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use only::{Acceptor, Conn, Engine, Handler, tls};
use only_turn::client::{Client, ClientConfig, ClientEvent, ClientState};
use only_turn::framing::FrameReader;
use only_turn::stun;

use crate::{Hub, lock, timer};

/// What the waiter of an allocation gets: (relayed, mapped) or why it failed.
pub(crate) type Allocated = Result<(SocketAddr, Option<SocketAddr>), String>;

/// First wait before an allocation that was lost is made again.
pub(crate) const RETRY_MIN: Duration = Duration::from_secs(1);
/// Longest wait between two attempts.
pub(crate) const RETRY_MAX: Duration = Duration::from_secs(60);
/// Relayed data (ChannelData, Send indications) for a stream with more than this queued is
/// dropped: media goes stale, and DTLS, SCTP and RTP recover; requests always go.
pub(crate) const MAX_STREAM_QUEUE: usize = 256 * 1024;
/// Bytes waiting for a connection to open (the first Allocate, a few datagrams).
const MAX_CONNECTING: usize = 64 * 1024;
/// Retired relayed addresses remembered (what peers send from them is dropped).
const RETIRED: usize = 8;

/// How the client reaches the server.
#[derive(Clone)]
pub(crate) enum Wire {
    Udp,
    Tcp,
    /// TLS client configuration and server name.
    Tls(tls::ClientConfig, String),
}

impl Wire {
    pub(crate) fn is_stream(&self) -> bool {
        !matches!(self, Wire::Udp)
    }

    /// 0 UDP, 1 TCP, 2 TLS (an endpoint has one allocation per server and transport).
    pub(crate) fn code(&self) -> u8 {
        match self {
            Wire::Udp => 0,
            Wire::Tcp => 1,
            Wire::Tls(..) => 2,
        }
    }
}

enum Link {
    /// No connection (UDP, or a stream that is down).
    None,
    /// Dialing: what the client sent meanwhile.
    Connecting(Vec<Vec<u8>>),
    Open(Conn<TurnConn>),
}

/// Work done after the state lock is released (it calls into the hub, peers or the engine).
pub(crate) enum Deferred {
    /// Dial connection generation `.0`.
    Dial(u64),
    /// A new allocation replaced a lost one: swap the candidate, offer it to open peers.
    Reallocated(only_ice::Candidate),
    /// The allocation at this address is gone.
    Lost(SocketAddr),
    /// Close this connection (outside the lock: closing may call back).
    Close(Conn<TurnConn>),
}

struct State {
    client: Client,
    /// Waiting to make the allocation again (the client is not driven).
    down: bool,
    armed: Option<Instant>,
    retry_at: Option<Instant>,
    backoff: Duration,
    waiter: Option<mpsc::Sender<Allocated>>,
    link: Link,
    /// Connection generation: a handler or dial result of another one is stale.
    generation: u64,
    /// The local address the allocation is reached from (the candidate's base).
    base: Option<SocketAddr>,
    relayed: Option<SocketAddr>,
    retired: VecDeque<SocketAddr>,
    deferred: Vec<Deferred>,
}

pub(crate) struct Relay {
    pub(crate) server: SocketAddr,
    pub(crate) wire: Wire,
    cfg: ClientConfig,
    engine: Weak<Engine>,
    closed: AtomicBool,
    state: Mutex<State>,
    hub: Weak<Hub>,
    me: Weak<Relay>,
}

impl Relay {
    pub(crate) fn new(
        hub: &Arc<Hub>,
        engine: Weak<Engine>,
        wire: Wire,
        cfg: ClientConfig,
        waiter: mpsc::Sender<Allocated>,
    ) -> Arc<Relay> {
        let cfg = cfg.stream(wire.is_stream());
        Arc::new_cyclic(|me| Relay {
            server: cfg.server,
            wire,
            engine,
            closed: AtomicBool::new(false),
            state: Mutex::new(State {
                client: Client::new(cfg.clone(), Instant::now()),
                down: false,
                armed: None,
                retry_at: None,
                backoff: RETRY_MIN,
                waiter: Some(waiter),
                link: Link::None,
                generation: 0,
                base: None,
                relayed: None,
                retired: VecDeque::new(),
                deferred: Vec::new(),
            }),
            cfg,
            hub: Arc::downgrade(hub),
            me: me.clone(),
        })
    }

    /// Runs `f` on the state, then sends what the client produced, handles its events, arms
    /// the timer, releases the lock and runs the deferred work.
    fn with<R>(&self, f: impl FnOnce(&Relay, &mut State) -> R) -> R {
        let (r, d) = {
            let mut st = lock(&self.state);
            let r = f(self, &mut st);
            self.after(&mut st);
            (r, mem::take(&mut st.deferred))
        };
        self.run(d);
        r
    }

    /// Starts: the first Allocate goes out (over UDP), or the connection is dialed.
    pub(crate) fn start(&self) {
        self.with(|me, st| {
            if me.wire.is_stream() {
                me.dial(st);
            } else {
                st.base = me.udp_base();
            }
        });
    }

    /// Whether the allocation is gone for good (it failed before it was made, or the endpoint
    /// closed it).
    pub(crate) fn is_dead(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// `Some(true)` if `addr` is the current relayed address, `Some(false)` if it is a retired
    /// one.
    pub(crate) fn owns(&self, addr: SocketAddr) -> Option<bool> {
        let st = lock(&self.state);
        if st.relayed == Some(addr) {
            Some(true)
        } else if st.retired.contains(&addr) {
            Some(false)
        } else {
            None
        }
    }

    /// The candidate of relayed address `relayed` reached from `base`.
    pub(crate) fn candidate(&self, relayed: SocketAddr, base: SocketAddr) -> only_ice::Candidate {
        match &self.wire {
            Wire::Udp => only_ice::Candidate::relayed(relayed, base),
            Wire::Tcp => only_ice::Candidate::relayed_over_stream(relayed, base, false),
            Wire::Tls(..) => only_ice::Candidate::relayed_over_stream(relayed, base, true),
        }
    }

    /// The base of the current allocation.
    pub(crate) fn base(&self) -> Option<SocketAddr> {
        lock(&self.state).base
    }

    /// A datagram (or stream message) from the server: relayed data comes back as (peer,
    /// relayed address, data).
    pub(crate) fn input(&self, data: &[u8]) -> Option<(SocketAddr, SocketAddr, Vec<u8>)> {
        self.with(|_, st| {
            if st.down {
                return None;
            }
            let r = st
                .client
                .handle_input(Instant::now(), data)
                .map(|(p, d)| (p, d.to_vec()));
            let relayed = st.client.relayed_addr()?;
            r.map(|(p, d)| (p, relayed, d))
        })
    }

    /// Sends `data` to `peer` through the relay.
    pub(crate) fn send(&self, peer: SocketAddr, data: &[u8]) {
        self.with(|_, st| {
            if !st.down {
                let _ = st.client.send_to(Instant::now(), peer, data);
            }
        });
    }

    /// Deletes the allocation (best effort: the request goes out once, the answer is not
    /// awaited) and closes the connection.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.with(|me, st| {
            if !st.down {
                st.client.close(Instant::now());
                me.flush(st);
            }
            st.down = true;
            st.retry_at = None;
            st.waiter = None;
            if let Link::Open(c) = mem::replace(&mut st.link, Link::None) {
                st.deferred.push(Deferred::Close(c));
            }
            st.generation += 1;
        });
    }

    fn udp_base(&self) -> Option<SocketAddr> {
        let hub = self.hub.upgrade()?;
        let cs = lock(&hub.candidates);
        cs.iter()
            .find(|c| c.kind() == only_ice::CandidateKind::Host && c.tcp_type().is_none())
            .map(only_ice::Candidate::addr)
            .or_else(|| hub.binding().map(only::UdpBinding::local_addr))
    }

    /// A new connection (generation bumped) whose dial runs once the lock is released.
    fn dial(&self, st: &mut State) {
        st.generation += 1;
        st.link = Link::Connecting(Vec::new());
        st.deferred.push(Deferred::Dial(st.generation));
    }

    /// Sends one message from the client to the server.
    fn transmit(&self, st: &mut State, m: Vec<u8>) {
        match &mut st.link {
            Link::None if !self.wire.is_stream() => {
                if let Some(b) = self.hub.upgrade().as_ref().and_then(|h| h.binding()) {
                    let _ = b.send_to(&m, self.server);
                }
            }
            Link::None => {}
            Link::Connecting(q) => {
                if q.iter().map(Vec::len).sum::<usize>() + m.len() <= MAX_CONNECTING {
                    q.push(m);
                }
            }
            Link::Open(c) => {
                // Relayed data waits behind nothing: past the bound it is stale.
                if (!stun::is_stun(&m) || is_send_indication(&m))
                    && c.queued_bytes() > MAX_STREAM_QUEUE
                {
                    return;
                }
                let _ = c.send_owned(m);
            }
        }
    }

    fn flush(&self, st: &mut State) {
        while let Some(m) = st.client.poll_transmit() {
            self.transmit(st, m);
        }
    }

    /// The allocation is lost: forget it and try again later.
    fn lose(&self, st: &mut State, now: Instant) {
        if let Some(old) = st.relayed.take() {
            st.retired.push_back(old);
            if st.retired.len() > RETIRED {
                st.retired.pop_front();
            }
            st.deferred.push(Deferred::Lost(old));
        }
        if let Link::Open(c) = mem::replace(&mut st.link, Link::None) {
            st.deferred.push(Deferred::Close(c));
        }
        st.generation += 1;
        st.down = true;
        st.retry_at = Some(now + st.backoff);
        only_log::debug!(target: "only_webrtc", "turn {}: allocation lost, again in {:?}", self.server, st.backoff);
        st.backoff = (st.backoff * 2).min(RETRY_MAX);
    }

    /// Fails for good before the first allocation.
    fn fail(&self, st: &mut State, why: String) {
        if let Some(w) = st.waiter.take() {
            let _ = w.send(Err(why));
        }
        self.closed.store(true, Ordering::Release);
        st.down = true;
        st.retry_at = None;
        if let Link::Open(c) = mem::replace(&mut st.link, Link::None) {
            st.deferred.push(Deferred::Close(c));
        }
        st.generation += 1;
    }

    /// The connection (or the dial) of generation `g` ended.
    fn link_down(&self, g: u64, why: &str) {
        self.with(|me, st| {
            if g != st.generation || st.down {
                return;
            }
            if st.waiter.is_some() {
                me.fail(st, format!("turn {}: {why}", me.server));
            } else if !me.closed.load(Ordering::Acquire) {
                st.link = Link::None;
                me.lose(st, Instant::now());
            }
        });
    }

    /// The connection of generation `g` is up.
    fn link_up(&self, g: u64, c: &Conn<TurnConn>) -> bool {
        self.with(|me, st| {
            if g != st.generation || st.down || me.closed.load(Ordering::Acquire) {
                return false;
            }
            st.base = Some(c.local_addr());
            if let Link::Connecting(q) = mem::replace(&mut st.link, Link::Open(c.clone())) {
                for m in q {
                    let _ = c.send_owned(m);
                }
            }
            true
        })
    }

    /// Sends what the client produced, reports its events and arms its timer.
    fn after(&self, st: &mut State) {
        let now = Instant::now();
        if !st.down {
            self.flush(st);
            while let Some(e) = st.client.poll_event() {
                match e {
                    ClientEvent::Allocated {
                        relayed, mapped, ..
                    } => {
                        st.backoff = RETRY_MIN;
                        st.relayed = Some(relayed);
                        if let Some(w) = st.waiter.take() {
                            let _ = w.send(Ok((relayed, mapped)));
                        } else if let Some(base) = st.base {
                            only_log::debug!(target: "only_webrtc", "turn {}: allocated again: {relayed}", self.server);
                            st.deferred
                                .push(Deferred::Reallocated(self.candidate(relayed, base)));
                        }
                    }
                    ClientEvent::Failed(e) => {
                        only_log::debug!(target: "only_webrtc", "turn {}: {e}", self.server);
                        if st.waiter.is_some() {
                            self.fail(st, e.to_string());
                        } else if !self.closed.load(Ordering::Acquire) {
                            self.lose(st, now);
                        }
                        break;
                    }
                    ClientEvent::PeerFailed(p, e) => {
                        only_log::debug!(target: "only_webrtc", "turn {}: peer {p}: {e}", self.server);
                    }
                    _ => {}
                }
            }
        }
        let client_due = if st.down {
            None
        } else {
            st.client.poll_timeout()
        };
        let due = match (client_due, st.retry_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        if let Some(t) = due {
            if st.armed.is_none_or(|a| t < a) {
                st.armed = Some(t);
                let target: Weak<dyn timer::Due> = self.me.clone();
                timer::timer().schedule(t, target);
            }
        }
    }

    /// Makes the allocation again (after a loss).
    fn retry(&self, st: &mut State, now: Instant) {
        st.retry_at = None;
        st.down = false;
        st.client = Client::new(self.cfg.clone(), now);
        if self.wire.is_stream() {
            self.dial(st);
        } else {
            st.base = self.udp_base();
        }
    }

    fn run(&self, deferred: Vec<Deferred>) {
        for d in deferred {
            match d {
                Deferred::Dial(g) => self.dial_now(g),
                Deferred::Close(c) => c.close(),
                Deferred::Lost(old) => {
                    if let Some(h) = self.hub.upgrade() {
                        h.relay_lost(old);
                    }
                }
                Deferred::Reallocated(c) => {
                    if let Some(h) = self.hub.upgrade() {
                        h.relay_reallocated(c);
                    }
                }
            }
        }
    }

    fn dial_now(&self, g: u64) {
        let Some(engine) = self.engine.upgrade() else {
            self.link_down(g, "the engine is gone");
            return;
        };
        let acc = TurnDial {
            relay: self.me.clone(),
            generation: g,
        };
        let me = self.me.clone();
        let on_error = move |e: std::io::Error| {
            if let Some(r) = me.upgrade() {
                r.link_down(g, &format!("connect: {e}"));
            }
        };
        match &self.wire {
            Wire::Tls(cfg, name) => match tls::Tls::client(cfg.clone(), name, acc) {
                Ok(t) => engine.dial(self.server, t, on_error),
                Err(e) => self.link_down(g, &format!("tls: {e}")),
            },
            _ => engine.dial(self.server, acc, on_error),
        }
    }
}

/// A Send indication (relayed data over a permission, not a request).
fn is_send_indication(m: &[u8]) -> bool {
    // STUN type: method SEND (0x006) in the indication class is 0x0016.
    m.len() >= 2 && u16::from_be_bytes([m[0], m[1]]) == 0x0016
}

impl timer::Due for Relay {
    fn fire(&self, at: Instant) {
        self.with(|me, st| {
            if st.armed != Some(at) {
                return;
            }
            st.armed = None;
            let now = Instant::now();
            if st.retry_at.is_some_and(|t| t <= now) && !me.closed.load(Ordering::Acquire) {
                me.retry(st, now);
            }
            if !st.down {
                st.client.handle_timeout(now);
                if st.client.state() == ClientState::Closed {
                    st.down = true;
                }
            }
        });
    }
}

/// Dials the connection of one generation.
struct TurnDial {
    relay: Weak<Relay>,
    generation: u64,
}

impl Acceptor for TurnDial {
    type Handler = TurnConn;
    fn on_open(&self, c: &Conn<TurnConn>) -> TurnConn {
        let up = self
            .relay
            .upgrade()
            .is_some_and(|r| r.link_up(self.generation, c));
        if !up {
            c.close();
        }
        TurnConn {
            relay: self.relay.clone(),
            generation: self.generation,
            reader: FrameReader::new(),
        }
    }
}

/// The TCP or TLS connection of an allocation.
pub(crate) struct TurnConn {
    relay: Weak<Relay>,
    generation: u64,
    reader: FrameReader,
}

impl std::fmt::Debug for TurnConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnConn")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl Handler for TurnConn {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let Some(r) = self.relay.upgrade() else {
            c.close();
            return;
        };
        let hub = r.hub.upgrade();
        let res = self.reader.push(data, |m| {
            if let Some((peer, relayed, d)) = r.input(m) {
                if let Some(h) = &hub {
                    h.route(peer, relayed, &d);
                }
            }
        });
        if res.is_err() {
            c.close();
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, err: Option<only::Error>) {
        if let Some(r) = self.relay.upgrade() {
            let why = err.map_or_else(|| "connection closed".to_owned(), |e| e.to_string());
            r.link_down(self.generation, &why);
        }
    }
}

/// A TURN server an [`Endpoint`](crate::Endpoint) allocates a relayed candidate on
/// ([`Endpoint::gather_relay_via`](crate::Endpoint::gather_relay_via)): its address, the
/// transport (UDP from the endpoint's socket, or a TCP or TLS connection of the engine) and
/// long-term credentials.
#[derive(Clone)]
pub struct RelayServer {
    pub(crate) addr: SocketAddr,
    pub(crate) wire: Wire,
    pub(crate) username: String,
    pub(crate) password: String,
    /// `turns:` URL without a TLS configuration yet: its server name.
    pending_tls: Option<String>,
}

impl std::fmt::Debug for RelayServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayServer")
            .field("addr", &self.addr)
            .field("transport", &self.transport())
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl RelayServer {
    fn new(addr: SocketAddr, wire: Wire, username: &str, password: &str) -> RelayServer {
        RelayServer {
            addr,
            wire,
            username: username.to_owned(),
            password: password.to_owned(),
            pending_tls: None,
        }
    }

    /// TURN over UDP (`turn:host:port`), from the endpoint's own socket.
    pub fn udp(addr: SocketAddr, username: &str, password: &str) -> RelayServer {
        RelayServer::new(addr, Wire::Udp, username, password)
    }

    /// TURN over TCP (`turn:host:port?transport=tcp`): the allocation lives as long as the
    /// connection.
    pub fn tcp(addr: SocketAddr, username: &str, password: &str) -> RelayServer {
        RelayServer::new(addr, Wire::Tcp, username, password)
    }

    /// TURN over TLS (`turns:host:port`), verifying the server's certificate for
    /// `server_name` with `config`.
    pub fn tls(
        addr: SocketAddr,
        server_name: &str,
        config: tls::ClientConfig,
        username: &str,
        password: &str,
    ) -> RelayServer {
        RelayServer::new(
            addr,
            Wire::Tls(config, server_name.to_owned()),
            username,
            password,
        )
    }

    /// Parses an RFC 7065 URL, `turn:<host>[:<port>][?transport=udp|tcp]` or
    /// `turns:<host>[:<port>][?transport=tcp]` (ports 3478 and 5349 by default; an IPv6
    /// address in brackets), as browsers take it in `iceServers`. A host name is resolved
    /// here (blocking: not on a `only` I/O thread) and its first address used. A `turns:`
    /// server needs [`tls_config`](Self::tls_config) before use; the URL's host is the name
    /// its certificate is verified for.
    pub fn from_url(
        url: &str,
        username: &str,
        password: &str,
    ) -> Result<RelayServer, crate::Error> {
        let bad = |why: &str| crate::Error::Turn(format!("bad TURN URL {url:?}: {why}"));
        let u = parse_url(url).map_err(bad)?;
        let addr = std::net::ToSocketAddrs::to_socket_addrs(&(u.host, u.port))
            .map_err(|e| bad(&e.to_string()))?
            .next()
            .ok_or_else(|| bad("the host has no address"))?;
        Ok(RelayServer::from_parts(&u, addr, username, password))
    }

    pub(crate) fn from_parts(
        u: &TurnUrl<'_>,
        addr: SocketAddr,
        username: &str,
        password: &str,
    ) -> RelayServer {
        let mut s = if u.tcp {
            RelayServer::tcp(addr, username, password)
        } else {
            RelayServer::udp(addr, username, password)
        };
        if u.secure {
            s.pending_tls = Some(u.host.to_owned());
        }
        s
    }

    /// The TLS client configuration of a `turns:` server made by
    /// [`from_url`](Self::from_url) (it has no default: the roots are the application's). On
    /// another server, makes it TLS with the server's IP address as the name to verify.
    #[must_use]
    pub fn tls_config(mut self, config: tls::ClientConfig) -> Self {
        let name = match (self.pending_tls.take(), &self.wire) {
            (Some(n), _) => n,
            (None, Wire::Tls(_, n)) => n.clone(),
            (None, _) => self.addr.ip().to_string(),
        };
        self.wire = Wire::Tls(config, name);
        self
    }

    /// The server's address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `"udp"`, `"tcp"` or `"tls"`.
    pub fn transport(&self) -> &'static str {
        if self.pending_tls.is_some() {
            return "tls";
        }
        match self.wire {
            Wire::Udp => "udp",
            Wire::Tcp => "tcp",
            Wire::Tls(..) => "tls",
        }
    }

    /// Whether it is a `turns:` server still waiting for its TLS configuration.
    pub(crate) fn needs_tls_config(&self) -> bool {
        self.pending_tls.is_some()
    }
}

/// The parts of a `turn:` / `turns:` URL (RFC 7065).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TurnUrl<'a> {
    pub(crate) secure: bool,
    pub(crate) tcp: bool,
    pub(crate) host: &'a str,
    pub(crate) port: u16,
}

/// Parses a `turn:` / `turns:` URL without resolving its host.
pub(crate) fn parse_url(url: &str) -> Result<TurnUrl<'_>, &'static str> {
    let (secure, rest) = if let Some(r) = url.strip_prefix("turns:") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("turn:") {
        (false, r)
    } else {
        return Err("not turn: or turns:");
    };
    let (hostport, query) = rest.split_once('?').unwrap_or((rest, ""));
    let tcp = match query {
        "" => secure,
        "transport=tcp" => true,
        "transport=udp" if !secure => false,
        _ => return Err("transport must be udp or tcp (tcp for turns:)"),
    };
    let (host, port) = if let Some(r) = hostport.strip_prefix('[') {
        let (h, p) = r.split_once(']').ok_or("unclosed [")?;
        let p = match p {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or("junk after ]")?),
        };
        (h, p)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (hostport, None),
        }
    };
    if host.is_empty() || host.contains(['/', '@', ' ', '[', ']']) {
        return Err("bad host");
    }
    let port = match port {
        Some(p) => p.parse::<u16>().map_err(|_| "bad port")?,
        None if secure => 5349,
        None => 3478,
    };
    Ok(TurnUrl {
        secure,
        tcp,
        host,
        port,
    })
}
