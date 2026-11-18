//! The sans-IO SRT connection: feed it datagrams and the time, drain the datagrams it wants
//! sent and the events it produced.

use std::{
    collections::VecDeque,
    fmt,
    net::SocketAddr,
    time::{Duration, Instant},
};

use super::{
    crypto::{Cryptor, KM_HEADER_SIZE, KM_STATE_BADSECRET, KeyMaterial, derive_kek, random},
    packet::*,
};

/// Default TSBPD latency.
pub const DEFAULT_LATENCY: Duration = Duration::from_millis(120);
/// Largest payload of a data packet (1500-byte MTU minus IP, UDP and SRT headers).
pub const MAX_PAYLOAD_SIZE: usize = 1456;
/// The payload size live MPEG-TS uses: 7 transport stream packets.
pub const TS_PAYLOAD_SIZE: usize = 1316;

const MTU: u32 = 1500;
const HANDSHAKE_RETRY: i64 = 250_000;
const KEEPALIVE: i64 = 1_000_000;
const ACK_INTERVAL: i64 = 10_000;
const LIGHT_ACK_PACKETS: u32 = 64;
const MIN_NAK_INTERVAL: i64 = 20_000;
const MAX_NAK_RANGES: usize = 128;
const ACK_HISTORY: usize = 64;
const SND_DROP_MIN: i64 = 1_000_000;
const DRIFT_WINDOW: u32 = 1000;
const DRIFT_STEP: i64 = 1_000;
/// A rendezvous waits this many times `handshake_timeout` for its peer (as libsrt does).
const RENDEZVOUS_TIMEOUT_FACTOR: i64 = 10;

/// A connection's lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum State {
    /// Handshaking.
    Handshake,
    /// Connected: data flows.
    Connected,
    /// Closed.
    Closed,
}

/// A rejection reason (the handshake type minus 1000): SRT's own codes below 1000, the
/// access control (HTTP-like) ones from 1000 (`REJECT_NOT_FOUND` = 1404...).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RejectReason(pub u32);

impl RejectReason {
    /// Unknown reason.
    pub const UNKNOWN: RejectReason = RejectReason(0);
    /// System failure.
    pub const SYSTEM: RejectReason = RejectReason(1);
    /// Rejected by the peer.
    pub const PEER: RejectReason = RejectReason(2);
    /// Resources exhausted.
    pub const RESOURCE: RejectReason = RejectReason(3);
    /// Rogue (malformed) handshake.
    pub const ROGUE: RejectReason = RejectReason(4);
    /// The listener is closing.
    pub const CLOSE: RejectReason = RejectReason(7);
    /// Incompatible version.
    pub const VERSION: RejectReason = RejectReason(8);
    /// Wrong passphrase.
    pub const BAD_SECRET: RejectReason = RejectReason(10);
    /// One side encrypts, the other does not.
    pub const UNSECURE: RejectReason = RejectReason(11);
    /// The handshake timed out.
    pub const TIMEOUT: RejectReason = RejectReason(16);
    /// Malformed stream ID.
    pub const BAD_REQUEST: RejectReason = RejectReason(1400);
    /// Authentication needed.
    pub const UNAUTHORIZED: RejectReason = RejectReason(1401);
    /// Too many connections.
    pub const OVERLOAD: RejectReason = RejectReason(1402);
    /// Not allowed.
    pub const FORBIDDEN: RejectReason = RejectReason(1403);
    /// No such stream.
    pub const NOT_FOUND: RejectReason = RejectReason(1404);
    /// Unsupported mode.
    pub const BAD_MODE: RejectReason = RejectReason(1405);
    /// The stream already has a publisher.
    pub const CONFLICT: RejectReason = RejectReason(1409);
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "srt: connection rejected ({})", self.0)
    }
}

/// SRT errors.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SrtError {
    /// The connection is closed.
    Closed,
    /// Not connected yet.
    NotConnected,
    /// The peer sent SHUTDOWN.
    PeerClosed,
    /// Nothing heard from the peer for the idle timeout.
    PeerIdle,
    /// The handshake did not complete in time.
    HandshakeTimeout,
    /// A payload larger than the packet size.
    TooLarge,
    /// The send buffer is full.
    BufferFull,
    /// The peer (or the listener) rejected the connection.
    Rejected(RejectReason),
    /// A configuration value is out of range.
    Config(&'static str),
    /// The transport under the connection failed.
    Transport(String),
}

impl fmt::Display for SrtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SrtError::Closed => f.write_str("srt: connection closed"),
            SrtError::NotConnected => f.write_str("srt: not connected"),
            SrtError::PeerClosed => f.write_str("srt: peer shut down"),
            SrtError::PeerIdle => f.write_str("srt: peer idle timeout"),
            SrtError::HandshakeTimeout => f.write_str("srt: handshake timeout"),
            SrtError::TooLarge => f.write_str("srt: payload larger than the packet size"),
            SrtError::BufferFull => f.write_str("srt: send buffer full"),
            SrtError::Rejected(r) => r.fmt(f),
            SrtError::Config(what) => write!(f, "srt: bad configuration: {what}"),
            SrtError::Transport(e) => write!(f, "srt: transport: {e}"),
        }
    }
}

impl std::error::Error for SrtError {}

/// Configures a connection.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Config {
    /// The TSBPD latency this side wants; both sides use the larger of theirs.
    pub latency: Duration,
    /// Encrypts with this passphrase (10 to 79 bytes).
    pub passphrase: Option<String>,
    /// Key length when encrypting as a caller: 16, 24 or 32.
    pub pbkeylen: usize,
    /// The stream ID a caller sends.
    pub stream_id: String,
    /// Largest payload `write` takes.
    pub payload_size: usize,
    /// Receive buffer in packets (also the flow window offered).
    pub flow_window: usize,
    /// Send buffer in packets.
    pub send_buffer_packets: usize,
    /// How long a caller tries to connect.
    pub handshake_timeout: Duration,
    /// Silence after which the peer is taken as gone.
    pub peer_idle_timeout: Duration,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("latency", &self.latency)
            .field("encrypted", &self.passphrase.is_some())
            .field("pbkeylen", &self.pbkeylen)
            .field("stream_id", &self.stream_id)
            .field("payload_size", &self.payload_size)
            .field("flow_window", &self.flow_window)
            .finish_non_exhaustive()
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            latency: DEFAULT_LATENCY,
            passphrase: None,
            pbkeylen: 16,
            stream_id: String::new(),
            payload_size: MAX_PAYLOAD_SIZE,
            flow_window: 8192,
            send_buffer_packets: 8192,
            handshake_timeout: Duration::from_secs(3),
            peer_idle_timeout: Duration::from_secs(5),
        }
    }
}

impl Config {
    /// Sets the latency.
    #[must_use]
    pub fn latency(mut self, d: Duration) -> Config {
        self.latency = d;
        self
    }

    /// Sets the passphrase (encryption).
    #[must_use]
    pub fn passphrase(mut self, p: impl Into<String>) -> Config {
        self.passphrase = Some(p.into());
        self
    }

    /// Sets the stream ID.
    #[must_use]
    pub fn stream_id(mut self, id: impl Into<String>) -> Config {
        self.stream_id = id.into();
        self
    }

    pub(crate) fn check(&mut self) -> Result<(), SrtError> {
        if self.latency.is_zero() {
            self.latency = DEFAULT_LATENCY;
        }
        if let Some(p) = &self.passphrase {
            if !(10..=79).contains(&p.len()) {
                return Err(SrtError::Config("passphrase must be 10 to 79 bytes"));
            }
            if self.pbkeylen == 0 {
                self.pbkeylen = 16;
            }
            if !matches!(self.pbkeylen, 16 | 24 | 32) {
                return Err(SrtError::Config("pbkeylen must be 16, 24 or 32"));
            }
        }
        if self.stream_id.len() > MAX_STREAM_ID {
            return Err(SrtError::Config("stream ID longer than 512 bytes"));
        }
        if self.payload_size == 0 || self.payload_size > MAX_PAYLOAD_SIZE {
            self.payload_size = MAX_PAYLOAD_SIZE;
        }
        self.flow_window = self.flow_window.clamp(32, 1 << 20);
        self.send_buffer_packets = self.send_buffer_packets.max(32);
        if self.handshake_timeout.is_zero() {
            self.handshake_timeout = Duration::from_secs(3);
        }
        if self.peer_idle_timeout.is_zero() {
            self.peer_idle_timeout = Duration::from_secs(5);
        }
        Ok(())
    }
}

/// What a connection produced.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// The handshake completed.
    Connected,
    /// A payload, delivered at its TSBPD time.
    Data(Vec<u8>),
    /// The connection closed (`None`: closed locally).
    Closed(Option<SrtError>),
}

/// Counters of a connection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Stats {
    /// Data packets sent (first transmissions).
    pub packets_sent: u64,
    /// Payload bytes sent.
    pub bytes_sent: u64,
    /// Retransmissions.
    pub packets_retrans: u64,
    /// Packets the sender gave up on (too late).
    pub packets_send_drop: u64,
    /// Data packets received.
    pub packets_received: u64,
    /// Payload bytes received.
    pub bytes_received: u64,
    /// Packets found missing.
    pub packets_lost: u64,
    /// Packets skipped by the receiver (too late).
    pub packets_recv_drop: u64,
    /// Duplicates.
    pub packets_duplicate: u64,
    /// Packets that could not be decrypted.
    pub packets_undecrypt: u64,
    /// NAKs sent.
    pub naks_sent: u64,
    /// NAKs received.
    pub naks_received: u64,
    /// Smoothed round-trip time.
    pub rtt: Duration,
}

struct SndPacket {
    origin: i64,
    buf: Vec<u8>,
    queued: bool,
}

struct RcvPacket {
    ts: i64,
    payload: Option<Vec<u8>>,
}

#[derive(Clone, Copy)]
struct LossEntry {
    r: LossRange,
    last_nak: i64,
}

#[derive(Clone, Copy, Default)]
struct AckRecord {
    no: u32,
    seq: u32,
    sent: Option<i64>,
}

/// One SRT connection in live mode, without I/O (see the [module docs](super)).
pub struct Conn {
    pub(crate) cfg: Config,
    pub(crate) state: State,
    start: Instant,
    pub(crate) socket_id: u32,
    pub(crate) peer_id: u32,
    pub(crate) stream_id: String,
    pub(crate) rcv_latency: i64,
    pub(crate) snd_latency: i64,
    pub(crate) peer_flow_window: usize,
    peer_avail: usize,
    pub(crate) km: Option<KeyMaterial>,
    km_msg: Option<Vec<u8>>,
    pub(crate) crypt: Option<Cryptor>,
    pub(crate) kk: u8,
    pub(crate) isn: u32,
    cookie: u32,
    hs_start: i64,
    hs_next: i64,
    pub(crate) hs_resp: Option<Vec<u8>>,
    snd: VecDeque<SndPacket>,
    pub(crate) snd_base: u32,
    pub(crate) snd_next: u32,
    snd_sent: usize,
    snd_bytes: usize,
    msgno: u32,
    rexmit: VecDeque<u32>,
    last_send: i64,
    rcv: Vec<Option<RcvPacket>>,
    rcv_head: usize,
    pub(crate) rcv_base: u32,
    pub(crate) rcv_max: u32,
    rcv_count: usize,
    loss: Vec<LossEntry>,
    base: i64,
    ts_last: u32,
    ts_full: i64,
    have_ts: bool,
    drift_n: u32,
    drift_min: i64,
    next_deliver: Option<i64>,
    last_recv: i64,
    next_nak: i64,
    next_ack: i64,
    pub(crate) ack_acked: u32,
    avail_sent: usize,
    ack_no: u32,
    acks: [AckRecord; ACK_HISTORY],
    since_ack: u32,
    rate_count: u64,
    rate_bytes: u64,
    rate_since: i64,
    rtt: i64,
    rtt_var: i64,
    stats: Stats,
    out: Vec<Vec<u8>>,
    events: VecDeque<Event>,
    /// The rendezvous handshake in progress.
    rdv: Option<Box<Rendezvous>>,
}

/// Who completes a rendezvous handshake, decided by the cookie contest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RdvRole {
    /// No handshake from the peer yet (or the cookies drew).
    Waving,
    /// The larger cookie: sends HSREQ (and KMREQ), answers HSRSP with AGREEMENT.
    Initiator,
    /// The smaller cookie: answers HSREQ with HSRSP (and KMRSP), connects on AGREEMENT.
    Responder,
}

/// The state of a rendezvous handshake (draft-sharabayko-srt-01 4.3.2, HSv5 only).
#[derive(Debug)]
struct Rendezvous {
    cookie: u32,
    role: RdvRole,
    peer_ip: [u8; 16],
    /// The responder's HSRSP conclusion, once it answered an HSREQ.
    hsrsp: Option<Vec<u8>>,
}

impl fmt::Debug for Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Conn")
            .field("state", &self.state)
            .field("socket_id", &self.socket_id)
            .field("peer_id", &self.peer_id)
            .field("stream_id", &self.stream_id)
            .finish_non_exhaustive()
    }
}

pub(crate) fn socket_id_of(r: u32) -> u32 {
    match r & ((1 << 30) - 1) {
        0 => 1,
        id => id,
    }
}

pub(crate) fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    random(&mut b);
    u32::from_be_bytes(b)
}

impl Conn {
    pub(crate) fn new(cfg: Config, now: Instant) -> Conn {
        let fw = cfg.flow_window;
        let mut rcv = Vec::with_capacity(fw);
        rcv.resize_with(fw, || None);
        Conn {
            cfg,
            state: State::Handshake,
            start: now,
            socket_id: 0,
            peer_id: 0,
            stream_id: String::new(),
            rcv_latency: 0,
            snd_latency: 0,
            peer_flow_window: fw,
            peer_avail: fw,
            km: None,
            km_msg: None,
            crypt: None,
            kk: KK_NONE,
            isn: 0,
            cookie: 0,
            hs_start: 0,
            hs_next: 0,
            hs_resp: None,
            snd: VecDeque::new(),
            snd_base: 0,
            snd_next: 0,
            snd_sent: 0,
            snd_bytes: 0,
            msgno: 0,
            rexmit: VecDeque::new(),
            last_send: 0,
            rcv,
            rcv_head: 0,
            rcv_base: 0,
            rcv_max: 0,
            rcv_count: 0,
            loss: Vec::new(),
            base: 0,
            ts_last: 0,
            ts_full: 0,
            have_ts: false,
            drift_n: 0,
            drift_min: 0,
            next_deliver: None,
            last_recv: 0,
            next_nak: 0,
            next_ack: 0,
            ack_acked: 0,
            avail_sent: 0,
            ack_no: 0,
            acks: [AckRecord::default(); ACK_HISTORY],
            since_ack: 0,
            rate_count: 0,
            rate_bytes: 0,
            rate_since: 0,
            rtt: 100_000,
            rtt_var: 50_000,
            stats: Stats::default(),
            out: Vec::new(),
            events: VecDeque::new(),
            rdv: None,
        }
    }

    /// A caller: starts the handshake (the induction request is in the output right away).
    pub fn caller(mut cfg: Config, now: Instant) -> Result<Conn, SrtError> {
        cfg.check()?;
        let mut c = Conn::new(cfg, now);
        c.socket_id = socket_id_of(rand_u32());
        c.isn = rand_u32() & (MAX_SEQ - 1);
        c.snd_base = c.isn;
        c.snd_next = c.isn;
        c.stream_id = c.cfg.stream_id.clone();
        if let Some(p) = &c.cfg.passphrase {
            let km = KeyMaterial::generate(c.cfg.pbkeylen, p);
            c.km_msg = Some(km.encode());
            c.crypt = Cryptor::new(&km);
            c.km = Some(km);
            c.kk = KK_EVEN;
        }
        c.hs_start = 0;
        c.send_induction(0);
        Ok(c)
    }

    /// One side of a rendezvous with the peer at `remote` (both sides connect to each other
    /// from the port the other targets; draft-sharabayko-srt-01 4.3.2, version 5 only): waves
    /// at once (the first handshake is in the output), and the cookie contest decides which
    /// side sends the HSREQ (and, with a passphrase, generates the key: both sides need the
    /// same passphrase). The stream ID is not sent. The handshake gives up after ten times
    /// `handshake_timeout`, as libsrt waits for a rendezvous peer.
    pub fn rendezvous(mut cfg: Config, remote: SocketAddr, now: Instant) -> Result<Conn, SrtError> {
        cfg.check()?;
        let mut c = Conn::new(cfg, now);
        c.socket_id = socket_id_of(rand_u32());
        c.isn = rand_u32() & (MAX_SEQ - 1);
        c.snd_base = c.isn;
        c.snd_next = c.isn;
        if let Some(p) = &c.cfg.passphrase {
            let km = KeyMaterial::generate(c.cfg.pbkeylen, p);
            c.km_msg = Some(km.encode());
            c.crypt = Cryptor::new(&km);
            c.km = Some(km);
            c.kk = KK_EVEN;
        }
        let mut cookie = rand_u32();
        if cookie == 0 {
            cookie = 1;
        }
        c.rdv = Some(Box::new(Rendezvous {
            cookie,
            role: RdvRole::Waving,
            peer_ip: super::listener::peer_ip(remote),
            hsrsp: None,
        }));
        c.hs_start = 0;
        c.rdv_send(0);
        Ok(c)
    }

    /// Sets the rendezvous cookie (fuzzing: a fixed role against a recorded peer).
    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn set_rendezvous_cookie(&mut self, cookie: u32) {
        if let Some(r) = &mut self.rdv {
            r.cookie = cookie;
            // The wave already queued carried the old cookie.
            self.out.clear();
            self.rdv_send(self.hs_start);
        }
    }

    /// Whether this is a rendezvous connection.
    pub fn is_rendezvous(&self) -> bool {
        self.rdv.is_some()
    }

    fn handshake_deadline(&self) -> i64 {
        let t = self.cfg.handshake_timeout.as_micros() as i64;
        self.hs_start
            + if self.rdv.is_some() {
                t * RENDEZVOUS_TIMEOUT_FACTOR
            } else {
                t
            }
    }

    /// A rendezvous handshake of `typ` with this side's fields.
    fn rdv_handshake(&self, typ: u32) -> Handshake {
        let (cookie, peer_ip) = self
            .rdv
            .as_ref()
            .map_or((0, [0; 16]), |r| (r.cookie, r.peer_ip));
        Handshake {
            version: 5,
            isn: self.isn,
            mtu: MTU,
            flow_window: self.cfg.flow_window as u32,
            typ,
            socket_id: self.socket_id,
            cookie,
            peer_ip,
            ..Handshake::default()
        }
    }

    /// Sends what the rendezvous state calls for: a wave, the initiator's HSREQ conclusion,
    /// the responder's empty conclusion or its HSRSP.
    fn rdv_send(&mut self, now: i64) {
        let Some(r) = &self.rdv else { return };
        self.hs_next = now + HANDSHAKE_RETRY;
        match r.role {
            RdvRole::Waving => {
                let mut hs = self.rdv_handshake(HS_WAVEAHAND);
                if self.km_msg.is_some() {
                    hs.encryption = (self.cfg.pbkeylen / 8) as u16;
                }
                self.send_handshake(now, 0, &hs);
            }
            RdvRole::Initiator => {
                let lat = self.cfg.latency.as_millis().min(u128::from(u16::MAX)) as u16;
                let mut hs = self.rdv_handshake(HS_CONCLUSION);
                hs.ext_field = EXT_FLAG_HSREQ;
                hs.hs = Some(HsExt {
                    version: SRT_VERSION,
                    flags: Conn::srt_flags(),
                    rcv_delay: lat,
                    snd_delay: lat,
                });
                if let Some(km) = &self.km_msg {
                    hs.encryption = (self.cfg.pbkeylen / 8) as u16;
                    hs.ext_field |= EXT_FLAG_KMREQ;
                    hs.km = Some(km.clone());
                }
                self.send_handshake(now, self.peer_id, &hs);
            }
            RdvRole::Responder => match r.hsrsp.clone() {
                Some(b) => self.output(b, now),
                None => {
                    let hs = self.rdv_handshake(HS_CONCLUSION);
                    self.send_handshake(now, self.peer_id, &hs);
                }
            },
        }
    }

    /// A handshake from the rendezvous peer.
    fn handle_rdv_handshake(&mut self, h: &Header, cif: &[u8], now: i64) {
        let Some(hs) = Handshake::parse(cif) else {
            return;
        };
        if (HS_REJECT_BASE..HS_DONE).contains(&hs.typ) {
            self.close_with(Some(SrtError::Rejected(RejectReason(
                hs.typ - HS_REJECT_BASE,
            ))));
            return;
        }
        if hs.version < 5 {
            // An HSv4 (SRT before 1.3) rendezvous peer.
            self.close_with(Some(SrtError::Rejected(RejectReason::VERSION)));
            return;
        }
        if hs.socket_id == 0 || !matches!(hs.typ, HS_WAVEAHAND | HS_CONCLUSION | HS_AGREEMENT) {
            return;
        }
        let Some(r) = self.rdv.as_mut() else { return };
        if r.role == RdvRole::Waving {
            // The cookie contest, in 32-bit arithmetic as libsrt: the larger cookie initiates.
            let d = r.cookie.wrapping_sub(hs.cookie);
            if d == 0 {
                // A draw (or our own packet looped back): pick another cookie, wave again.
                r.cookie = match rand_u32() {
                    0 => 1,
                    c => c,
                };
                return;
            }
            r.role = if d & 0x8000_0000 != 0 {
                RdvRole::Responder
            } else {
                RdvRole::Initiator
            };
            self.peer_id = hs.socket_id;
            if r.role == RdvRole::Responder {
                // The initiator's key material is the session's.
                self.km_msg = None;
                self.km = None;
                self.crypt = None;
                self.kk = KK_NONE;
            }
        }
        if hs.socket_id != self.peer_id {
            return;
        }
        let role = r.role;
        match (role, hs.typ) {
            (RdvRole::Initiator, HS_CONCLUSION) if hs.hs_rsp && hs.hs.is_some() => {
                self.rdv_initiator_done(h, &hs, now);
            }
            (RdvRole::Responder, HS_CONCLUSION) if !hs.hs_rsp && hs.hs.is_some() => {
                self.rdv_responder_answer(&hs, now);
            }
            (RdvRole::Responder, HS_AGREEMENT) => {
                if self.rdv.as_ref().is_some_and(|r| r.hsrsp.is_some()) {
                    self.rdv_connected(h.ts, now);
                }
            }
            (_, HS_AGREEMENT) => {}
            _ => self.rdv_send(now),
        }
    }

    /// The initiator got the responder's HSRSP: connected, AGREEMENT out.
    fn rdv_initiator_done(&mut self, h: &Header, hs: &Handshake, now: i64) {
        let Some(ext) = hs.hs else { return };
        if self.km_msg.is_some() {
            match &hs.km {
                None => {
                    self.close_with(Some(SrtError::Rejected(RejectReason::UNSECURE)));
                    return;
                }
                Some(km) if km.len() < KM_HEADER_SIZE => {
                    self.close_with(Some(SrtError::Rejected(RejectReason::BAD_SECRET)));
                    return;
                }
                _ => {}
            }
        } else if hs.km.is_some() {
            self.close_with(Some(SrtError::Rejected(RejectReason::UNSECURE)));
            return;
        }
        self.set_peer(hs, ext);
        let agreement = self.rdv_handshake(HS_AGREEMENT);
        let mut b = Vec::with_capacity(HEADER_SIZE + HANDSHAKE_SIZE);
        Header {
            ctrl: true,
            typ: CTRL_HANDSHAKE,
            ts: self.timestamp(now),
            dst: self.peer_id,
            ..Header::default()
        }
        .write(&mut b);
        agreement.write(&mut b);
        // A responder that missed it sends its HSRSP again: answered from `hs_resp`.
        self.hs_resp = Some(b.clone());
        self.output(b, now);
        self.rdv = None;
        self.connected(now, h.ts);
    }

    /// The responder got the initiator's HSREQ: takes its key material and latencies, answers
    /// HSRSP (and KMRSP), and waits for the AGREEMENT.
    fn rdv_responder_answer(&mut self, hs: &Handshake, now: i64) {
        let Some(ext) = hs.hs else { return };
        if self.rdv.as_ref().is_some_and(|r| r.hsrsp.is_some()) {
            return self.rdv_send(now);
        }
        let reject = |c: &mut Conn, r: RejectReason| {
            let mut resp = c.rdv_handshake(HS_REJECT_BASE + r.0);
            resp.version = 5;
            c.send_handshake(now, c.peer_id, &resp);
            c.close_with(Some(SrtError::Rejected(r)));
        };
        match (self.cfg.passphrase.clone(), &hs.km) {
            (None, Some(_)) | (Some(_), None) => return reject(self, RejectReason::UNSECURE),
            (Some(pass), Some(km)) => {
                let Ok(km) = KeyMaterial::decode(km, |s, l| derive_kek(&pass, s, l)) else {
                    return reject(self, RejectReason::BAD_SECRET);
                };
                let Some(crypt) = Cryptor::new(&km) else {
                    return reject(self, RejectReason::BAD_SECRET);
                };
                self.kk = if km.even.is_some() { KK_EVEN } else { KK_ODD };
                self.cfg.pbkeylen = km.key_len;
                self.crypt = Some(crypt);
                self.km = Some(km);
            }
            (None, None) => {}
        }
        self.set_peer(hs, ext);
        let mut resp = self.rdv_handshake(HS_CONCLUSION);
        resp.ext_field = EXT_FLAG_HSREQ;
        resp.hs = Some(HsExt {
            version: SRT_VERSION,
            flags: Conn::srt_flags(),
            rcv_delay: (self.rcv_latency / 1000).min(i64::from(u16::MAX)) as u16,
            snd_delay: (self.snd_latency / 1000).min(i64::from(u16::MAX)) as u16,
        });
        resp.hs_rsp = true;
        if let Some(km) = &hs.km {
            resp.encryption = hs.encryption;
            resp.ext_field |= EXT_FLAG_KMREQ;
            resp.km = Some(km.clone());
            resp.km_rsp = true;
        }
        let mut b = Vec::new();
        Header {
            ctrl: true,
            typ: CTRL_HANDSHAKE,
            ts: self.timestamp(now),
            dst: self.peer_id,
            ..Header::default()
        }
        .write(&mut b);
        resp.write(&mut b);
        self.hs_resp = Some(b.clone());
        if let Some(r) = self.rdv.as_mut() {
            r.hsrsp = Some(b);
        }
        self.rdv_send(now);
    }

    /// The responder is connected (the AGREEMENT, or anything else from the initiator once
    /// it answered).
    fn rdv_connected(&mut self, peer_ts: u32, now: i64) {
        self.rdv = None;
        self.connected(now, peer_ts);
    }

    /// Takes the peer's handshake parameters (latencies, flow window, initial sequence).
    fn set_peer(&mut self, hs: &Handshake, ext: HsExt) {
        let mine = self.cfg.latency.as_micros() as i64;
        self.rcv_latency = (i64::from(ext.snd_delay) * 1000).max(mine);
        self.snd_latency = (i64::from(ext.rcv_delay) * 1000).max(mine);
        if hs.flow_window > 0 {
            self.peer_flow_window = hs.flow_window.min(1 << 20) as usize;
            self.peer_avail = self.peer_flow_window;
        }
        self.rcv_base = hs.isn;
        self.rcv_max = hs.isn;
        self.ack_acked = hs.isn;
    }

    fn us(&self, now: Instant) -> i64 {
        i64::try_from(now.saturating_duration_since(self.start).as_micros()).unwrap_or(i64::MAX)
    }

    fn at(&self, us: i64) -> Instant {
        self.start + Duration::from_micros(us.max(0) as u64)
    }

    /// The state.
    pub fn state(&self) -> State {
        self.state
    }

    /// The stream ID: the one sent (caller) or received (listener).
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    /// The agreed receive latency.
    pub fn latency(&self) -> Duration {
        Duration::from_micros(self.rcv_latency.max(0) as u64)
    }

    /// Whether payloads are encrypted.
    pub fn encrypted(&self) -> bool {
        self.crypt.is_some()
    }

    /// Payload bytes waiting in the send buffer (sent but not acknowledged, or not sent yet).
    pub fn send_backlog(&self) -> usize {
        self.snd_bytes
    }

    /// The counters.
    pub fn stats(&self) -> Stats {
        let mut s = self.stats.clone();
        s.rtt = Duration::from_micros(self.rtt.max(0) as u64);
        s
    }

    /// Takes the datagrams to send.
    pub fn take_output(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.out)
    }

    /// The next event, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    fn timestamp(&self, now: i64) -> u32 {
        now as u32
    }

    fn output(&mut self, b: Vec<u8>, now: i64) {
        self.last_send = now;
        self.out.push(b);
    }

    fn send_control(&mut self, now: i64, typ: u16, subtype: u16, info: u32, cif: &[u8]) {
        let mut b = Vec::with_capacity(HEADER_SIZE + cif.len());
        Header {
            ctrl: true,
            typ,
            subtype,
            info,
            ts: self.timestamp(now),
            dst: self.peer_id,
            ..Header::default()
        }
        .write(&mut b);
        b.extend_from_slice(cif);
        self.output(b, now);
    }

    fn send_handshake(&mut self, now: i64, dst: u32, hs: &Handshake) {
        let mut b = Vec::with_capacity(128);
        Header {
            ctrl: true,
            typ: CTRL_HANDSHAKE,
            ts: self.timestamp(now),
            dst,
            ..Header::default()
        }
        .write(&mut b);
        hs.write(&mut b);
        self.output(b, now);
    }

    fn send_induction(&mut self, now: i64) {
        self.hs_next = now + HANDSHAKE_RETRY;
        let hs = Handshake {
            version: 4,
            ext_field: 2,
            isn: self.isn,
            mtu: MTU,
            flow_window: self.cfg.flow_window as u32,
            typ: HS_INDUCTION,
            socket_id: self.socket_id,
            ..Handshake::default()
        };
        self.send_handshake(now, 0, &hs);
    }

    pub(crate) fn srt_flags() -> u32 {
        FLAG_TSBPD_SND
            | FLAG_TSBPD_RCV
            | FLAG_CRYPT
            | FLAG_TLPKTDROP
            | FLAG_PERIODIC_NAK
            | FLAG_REXMIT
    }

    fn send_conclusion(&mut self, now: i64) {
        self.hs_next = now + HANDSHAKE_RETRY;
        let lat = self.cfg.latency.as_millis().min(u128::from(u16::MAX)) as u16;
        let mut hs = Handshake {
            version: 5,
            ext_field: EXT_FLAG_HSREQ,
            isn: self.isn,
            mtu: MTU,
            flow_window: self.cfg.flow_window as u32,
            typ: HS_CONCLUSION,
            socket_id: self.socket_id,
            cookie: self.cookie,
            hs: Some(HsExt {
                version: SRT_VERSION,
                flags: Conn::srt_flags(),
                rcv_delay: lat,
                snd_delay: lat,
            }),
            ..Handshake::default()
        };
        if let Some(km) = &self.km_msg {
            hs.encryption = (self.cfg.pbkeylen / 8) as u16;
            hs.ext_field |= EXT_FLAG_KMREQ;
            hs.km = Some(km.clone());
        }
        if !self.stream_id.is_empty() {
            hs.ext_field |= EXT_FLAG_CONFIG;
            hs.stream_id = Some(self.stream_id.clone());
        }
        self.send_handshake(now, 0, &hs);
    }

    /// Closes the connection, sending SHUTDOWN when connected. No `Closed` event follows a
    /// local close... except the one this produces with `None`.
    pub fn close(&mut self, now: Instant) {
        let now = self.us(now);
        if self.state == State::Connected {
            self.send_control(now, CTRL_SHUTDOWN, 0, 0, &[0; 4]);
        }
        self.close_with(None);
    }

    pub(crate) fn close_with(&mut self, err: Option<SrtError>) {
        if self.state == State::Closed {
            return;
        }
        self.state = State::Closed;
        self.snd.clear();
        self.rexmit.clear();
        self.loss.clear();
        self.snd_bytes = 0;
        for s in &mut self.rcv {
            *s = None;
        }
        self.rcv_count = 0;
        self.events.push_back(Event::Closed(err));
    }

    pub(crate) fn connected_at(&mut self, now: Instant, peer_ts: u32) {
        let now = self.us(now);
        self.connected(now, peer_ts);
    }

    fn connected(&mut self, now: i64, peer_ts: u32) {
        self.state = State::Connected;
        self.last_recv = now;
        self.last_send = now;
        self.base = now - i64::from(peer_ts);
        self.ts_last = peer_ts;
        self.ts_full = i64::from(peer_ts);
        self.have_ts = true;
        self.next_ack = now + ACK_INTERVAL;
        self.rate_since = now;
        self.events.push_back(Event::Connected);
    }

    /// When [`handle_timeout`](Self::handle_timeout) should run next; `None` once closed.
    pub fn next_timeout(&self) -> Option<Instant> {
        match self.state {
            State::Closed => None,
            State::Handshake => Some(self.at(self.hs_next.min(self.handshake_deadline()))),
            State::Connected => {
                let mut t = (self.last_send + KEEPALIVE)
                    .min(self.last_recv + self.cfg.peer_idle_timeout.as_micros() as i64);
                if self.ack_due() {
                    t = t.min(self.next_ack);
                }
                if !self.loss.is_empty() {
                    t = t.min(self.next_nak);
                }
                if let Some(d) = self.next_deliver {
                    t = t.min(d);
                }
                if let Some(p) = self.snd.front() {
                    t = t.min(p.origin + self.snd_drop_age());
                }
                Some(self.at(t))
            }
        }
    }

    /// Runs the timers due at `now`.
    pub fn handle_timeout(&mut self, now: Instant) {
        let now = self.us(now);
        match self.state {
            State::Closed => {}
            State::Handshake => {
                if now >= self.handshake_deadline() {
                    self.close_with(Some(SrtError::HandshakeTimeout));
                    return;
                }
                if now >= self.hs_next {
                    if self.rdv.is_some() {
                        self.rdv_send(now);
                    } else if self.cookie == 0 {
                        self.send_induction(now);
                    } else {
                        self.send_conclusion(now);
                    }
                }
            }
            State::Connected => {
                if now >= self.last_recv + self.cfg.peer_idle_timeout.as_micros() as i64 {
                    self.close_with(Some(SrtError::PeerIdle));
                    return;
                }
                self.deliver(now, false);
                if self.state == State::Closed {
                    return;
                }
                if now >= self.next_ack {
                    if self.ack_due() {
                        self.send_ack(now);
                    }
                    self.next_ack = now + ACK_INTERVAL;
                }
                if !self.loss.is_empty() && now >= self.next_nak {
                    self.send_periodic_nak(now);
                }
                self.drop_too_late(now);
                if now >= self.last_send + KEEPALIVE {
                    self.send_control(now, CTRL_KEEPALIVE, 0, 0, &[0; 4]);
                }
            }
        }
    }

    /// Handles one datagram from the peer.
    pub fn handle(&mut self, b: &[u8], now: Instant) {
        let now = self.us(now);
        if self.state == State::Closed {
            return;
        }
        let Some(h) = Header::parse(b) else { return };
        if self.state == State::Handshake {
            if h.ctrl && h.typ == CTRL_HANDSHAKE {
                if self.rdv.is_some() {
                    self.handle_rdv_handshake(&h, &b[HEADER_SIZE..], now);
                } else {
                    self.handle_caller_handshake(&h, &b[HEADER_SIZE..], now);
                }
                return;
            }
            // A responder whose AGREEMENT was lost connects on the initiator's next packet.
            let answered = self.rdv.as_ref().is_some_and(|r| r.hsrsp.is_some());
            if !(answered && h.dst == self.socket_id) {
                return;
            }
            self.rdv_connected(h.ts, now);
        }
        if h.dst != self.socket_id && !(h.ctrl && h.typ == CTRL_HANDSHAKE) {
            return;
        }
        self.last_recv = now;
        if !h.ctrl {
            self.handle_data(&h, &b[HEADER_SIZE..], now);
            self.deliver(now, false);
            return;
        }
        let cif = &b[HEADER_SIZE..];
        match h.typ {
            CTRL_HANDSHAKE => {
                // A caller that missed our conclusion response sends its conclusion again.
                if let (Some(resp), Some(hs)) = (self.hs_resp.clone(), Handshake::parse(cif)) {
                    if hs.typ == HS_CONCLUSION && hs.socket_id == self.peer_id {
                        self.output(resp, now);
                    }
                }
            }
            CTRL_ACK => self.handle_ack(&h, cif, now),
            CTRL_NAK => self.handle_nak(cif, now),
            CTRL_ACKACK => self.handle_ackack(h.info, now),
            CTRL_SHUTDOWN => {
                self.deliver(now, true);
                self.close_with(Some(SrtError::PeerClosed));
            }
            CTRL_DROPREQ => {
                if cif.len() >= 8 {
                    let f = u32::from_be_bytes([cif[0], cif[1], cif[2], cif[3]]) & (MAX_SEQ - 1);
                    let l = u32::from_be_bytes([cif[4], cif[5], cif[6], cif[7]]) & (MAX_SEQ - 1);
                    self.handle_dropreq(f, l);
                }
            }
            CTRL_USER if h.subtype == EXT_KMREQ => self.handle_km_refresh(cif, now),
            _ => {}
        }
        self.deliver(now, false);
    }

    fn handle_caller_handshake(&mut self, h: &Header, cif: &[u8], now: i64) {
        let Some(hs) = Handshake::parse(cif) else {
            return;
        };
        if (HS_REJECT_BASE..HS_DONE).contains(&hs.typ) {
            self.close_with(Some(SrtError::Rejected(RejectReason(
                hs.typ - HS_REJECT_BASE,
            ))));
        } else if hs.typ == HS_INDUCTION && self.cookie == 0 {
            if hs.version < 5 || hs.ext_field != SRT_MAGIC {
                self.close_with(Some(SrtError::Rejected(RejectReason::VERSION)));
                return;
            }
            self.cookie = if hs.cookie == 0 { 1 } else { hs.cookie };
            self.send_conclusion(now);
        } else if hs.typ == HS_CONCLUSION && self.cookie != 0 && h.dst == self.socket_id {
            let Some(ext) = hs.hs.filter(|_| hs.hs_rsp) else {
                self.close_with(Some(SrtError::Rejected(RejectReason::VERSION)));
                return;
            };
            if self.km_msg.is_some() {
                match &hs.km {
                    None => {
                        self.close_with(Some(SrtError::Rejected(RejectReason::UNSECURE)));
                        return;
                    }
                    Some(km) if km.len() < KM_HEADER_SIZE => {
                        self.close_with(Some(SrtError::Rejected(RejectReason::BAD_SECRET)));
                        return;
                    }
                    _ => {}
                }
            }
            self.peer_id = hs.socket_id;
            let mine = self.cfg.latency.as_micros() as i64;
            self.rcv_latency = (i64::from(ext.snd_delay) * 1000).max(mine);
            self.snd_latency = (i64::from(ext.rcv_delay) * 1000).max(mine);
            if hs.flow_window > 0 {
                self.peer_flow_window = hs.flow_window.min(1 << 20) as usize;
                self.peer_avail = self.peer_flow_window;
            }
            self.rcv_base = hs.isn;
            self.rcv_max = hs.isn;
            self.ack_acked = hs.isn;
            self.connected(now, h.ts);
        }
    }

    fn snd_drop_age(&self) -> i64 {
        SND_DROP_MIN.max(self.snd_latency + self.snd_latency / 4 + 2 * ACK_INTERVAL)
    }

    /// Queues a payload for sending.
    pub fn write(&mut self, payload: &[u8], now: Instant) -> Result<(), SrtError> {
        let now = self.us(now);
        match self.state {
            State::Closed => return Err(SrtError::Closed),
            State::Handshake => return Err(SrtError::NotConnected),
            State::Connected => {}
        }
        if payload.len() > self.cfg.payload_size {
            return Err(SrtError::TooLarge);
        }
        self.drop_too_late(now);
        if self.snd.len() >= self.cfg.send_buffer_packets {
            return Err(SrtError::BufferFull);
        }
        self.msgno = self.msgno % MSGNO_MASK + 1;
        let mut buf = Vec::with_capacity(HEADER_SIZE + payload.len());
        Header {
            seq: self.snd_next,
            info: PP_SOLO | (u32::from(self.kk) << KK_SHIFT) | self.msgno,
            ts: self.timestamp(now),
            dst: self.peer_id,
            ..Header::default()
        }
        .write(&mut buf);
        buf.extend_from_slice(payload);
        if let Some(c) = &self.crypt {
            c.xor(self.kk, self.snd_next, &mut buf[HEADER_SIZE..]);
        }
        self.snd_next = seq_add(self.snd_next, 1);
        self.snd.push_back(SndPacket {
            origin: now,
            buf,
            queued: false,
        });
        self.snd_bytes += payload.len();
        self.try_send(now);
        Ok(())
    }

    fn try_send(&mut self, now: i64) {
        while let Some(seq) = self.rexmit.pop_front() {
            let i = seq_diff(seq, self.snd_base);
            if i < 0 || i as usize >= self.snd_sent {
                continue;
            }
            let p = &mut self.snd[i as usize];
            p.queued = false;
            let w = u32::from_be_bytes([p.buf[4], p.buf[5], p.buf[6], p.buf[7]]) | FLAG_REXMIT_PKT;
            p.buf[4..8].copy_from_slice(&w.to_be_bytes());
            let b = p.buf.clone();
            self.stats.packets_retrans += 1;
            self.output(b, now);
        }
        let window = self.peer_flow_window.min(self.peer_avail);
        while self.snd_sent < self.snd.len() && self.snd_sent < window {
            let b = self.snd[self.snd_sent].buf.clone();
            self.snd_sent += 1;
            self.stats.packets_sent += 1;
            self.stats.bytes_sent += (b.len() - HEADER_SIZE) as u64;
            self.output(b, now);
        }
    }

    fn pop_sent(&mut self, n: usize) {
        for _ in 0..n {
            if let Some(p) = self.snd.pop_front() {
                self.snd_bytes -= p.buf.len() - HEADER_SIZE;
            }
        }
        self.snd_sent = self.snd_sent.saturating_sub(n);
        self.snd_base = seq_add(self.snd_base, n as i64);
    }

    fn drop_too_late(&mut self, now: i64) {
        let age = self.snd_drop_age();
        let n = self
            .snd
            .iter()
            .take_while(|p| now >= p.origin + age)
            .count();
        if n == 0 {
            return;
        }
        let first = self.snd_base;
        let last = seq_add(self.snd_base, n as i64 - 1);
        let b = &self.snd[0].buf;
        let msgno = u32::from_be_bytes([b[4], b[5], b[6], b[7]]) & MSGNO_MASK;
        self.stats.packets_send_drop += n as u64;
        self.pop_sent(n);
        let mut cif = first.to_be_bytes().to_vec();
        cif.extend_from_slice(&last.to_be_bytes());
        self.send_control(now, CTRL_DROPREQ, 0, msgno, &cif);
    }

    fn handle_ack(&mut self, h: &Header, cif: &[u8], now: i64) {
        if cif.len() < 4 {
            return;
        }
        let w = |i: usize| u32::from_be_bytes([cif[i], cif[i + 1], cif[i + 2], cif[i + 3]]);
        let ack = w(0) & (MAX_SEQ - 1);
        let full = h.info != 0 && cif.len() >= 16;
        if full {
            self.send_control(now, CTRL_ACKACK, 0, h.info, &[0; 4]);
            let rtt = i64::from(w(4));
            if rtt > 0 {
                self.rtt = rtt;
                self.rtt_var = i64::from(w(8));
            }
        }
        let n = seq_diff(ack, self.snd_base);
        if n < 0 || n as usize > self.snd_sent {
            return;
        }
        self.pop_sent(n as usize);
        if full {
            self.peer_avail = w(12).min(1 << 20) as usize;
        }
        self.try_send(now);
    }

    fn handle_nak(&mut self, cif: &[u8], now: i64) {
        self.stats.naks_received += 1;
        let mut gone: Option<LossRange> = None;
        let base = self.snd_base;
        let sent = self.snd_sent as i64;
        let mut want = Vec::new();
        parse_loss_list(cif, |mut from, to| {
            if seq_diff(from, base) < 0 {
                let last = if seq_diff(to, base) >= 0 {
                    seq_add(base, -1)
                } else {
                    to
                };
                match &mut gone {
                    None => gone = Some(LossRange { from, to: last }),
                    Some(g) => g.to = last,
                }
                from = base;
                if seq_diff(to, from) < 0 {
                    return;
                }
            }
            let start = seq_diff(from, base);
            let end = seq_diff(to, base).min(sent - 1);
            let mut i = start;
            while i <= end {
                want.push(i as usize);
                i += 1;
            }
        });
        for i in want {
            if let Some(p) = self.snd.get_mut(i) {
                if !p.queued {
                    p.queued = true;
                    self.rexmit.push_back(seq_add(self.snd_base, i as i64));
                }
            }
        }
        if let Some(g) = gone {
            let mut b = g.from.to_be_bytes().to_vec();
            b.extend_from_slice(&g.to.to_be_bytes());
            self.send_control(now, CTRL_DROPREQ, 0, 0, &b);
        }
        self.try_send(now);
    }

    fn handle_km_refresh(&mut self, cif: &[u8], now: i64) {
        let Some(pass) = self.cfg.passphrase.clone() else {
            return;
        };
        let cur = self.km.clone();
        let res = KeyMaterial::decode(cif, |salt, len| match &cur {
            Some(k) if &k.salt == salt && k.key_len == len => k.kek.clone(),
            _ => derive_kek(&pass, salt, len),
        });
        let Ok(mut km) = res else {
            self.send_control(
                now,
                CTRL_USER,
                EXT_KMRSP,
                0,
                &KM_STATE_BADSECRET.to_be_bytes(),
            );
            return;
        };
        if let Some(c) = &cur {
            if c.salt == km.salt {
                if km.even.is_none() {
                    km.even.clone_from(&c.even);
                }
                if km.odd.is_none() {
                    km.odd.clone_from(&c.odd);
                }
            }
        }
        let Some(crypt) = Cryptor::new(&km) else {
            return;
        };
        self.km = Some(km);
        self.crypt = Some(crypt);
        self.send_control(now, CTRL_USER, EXT_KMRSP, 0, cif);
    }

    fn handle_data(&mut self, h: &Header, payload: &[u8], now: i64) {
        let seq = h.seq;
        let off = seq_diff(seq, self.rcv_base);
        if off < 0 {
            self.stats.packets_duplicate += 1;
            return;
        }
        if off as usize >= self.rcv.len() {
            self.stats.packets_recv_drop += 1;
            return;
        }
        let slot = (self.rcv_head + off as usize) % self.rcv.len();
        if self.rcv[slot].is_some() {
            self.stats.packets_duplicate += 1;
            return;
        }
        let rexmit = h.info & FLAG_REXMIT_PKT != 0;
        let d = seq_diff(seq, self.rcv_max);
        if d > 0 {
            let r = LossRange {
                from: self.rcv_max,
                to: seq_add(seq, -1),
            };
            self.loss.push(LossEntry { r, last_nak: now });
            self.stats.packets_lost += d as u64;
            self.send_nak(now, &[r]);
            self.rcv_max = seq_add(seq, 1);
        } else if d == 0 {
            self.rcv_max = seq_add(seq, 1);
        } else {
            self.remove_loss(seq);
        }
        let mut data = Some(payload.to_vec());
        let kk = ((h.info & KK_MASK) >> KK_SHIFT) as u8;
        if kk != KK_NONE {
            let ok = match (&self.crypt, data.as_mut()) {
                (Some(c), Some(d)) => c.xor(kk, seq, d),
                _ => false,
            };
            if !ok {
                self.stats.packets_undecrypt += 1;
                data = None;
            }
        }
        let ts = self.unwrap_ts(h.ts);
        self.rcv[slot] = Some(RcvPacket { ts, payload: data });
        self.rcv_count += 1;
        self.stats.packets_received += 1;
        self.stats.bytes_received += payload.len() as u64;
        self.rate_count += 1;
        self.rate_bytes += payload.len() as u64;
        if !rexmit {
            self.track_drift(ts, now);
        }
        self.since_ack += 1;
        if self.since_ack >= LIGHT_ACK_PACKETS {
            self.since_ack = 0;
            let a = self.ack_seq().to_be_bytes();
            self.send_control(now, CTRL_ACK, 0, 0, &a);
        }
    }

    fn unwrap_ts(&mut self, ts: u32) -> i64 {
        if !self.have_ts {
            self.ts_last = ts;
            self.ts_full = i64::from(ts);
            self.have_ts = true;
            return self.ts_full;
        }
        let full = self.ts_full + i64::from(ts.wrapping_sub(self.ts_last) as i32);
        if full > self.ts_full {
            self.ts_last = ts;
            self.ts_full = full;
        }
        full
    }

    fn track_drift(&mut self, ts: i64, now: i64) {
        let b = now - ts;
        if b < self.base {
            self.base = b;
        }
        if self.drift_n == 0 || b < self.drift_min {
            self.drift_min = b;
        }
        self.drift_n += 1;
        if self.drift_n >= DRIFT_WINDOW {
            let d = self.drift_min - self.base;
            if d > 0 {
                self.base += d.min(DRIFT_STEP);
            }
            self.drift_n = 0;
        }
    }

    fn remove_loss(&mut self, seq: u32) {
        for i in 0..self.loss.len() {
            let e = self.loss[i];
            if seq_diff(seq, e.r.from) < 0 || seq_diff(seq, e.r.to) > 0 {
                continue;
            }
            if e.r.from == e.r.to {
                self.loss.remove(i);
            } else if seq == e.r.from {
                self.loss[i].r.from = seq_add(e.r.from, 1);
            } else if seq == e.r.to {
                self.loss[i].r.to = seq_add(e.r.to, -1);
            } else {
                let tail = LossEntry {
                    r: LossRange {
                        from: seq_add(seq, 1),
                        to: e.r.to,
                    },
                    last_nak: e.last_nak,
                };
                self.loss[i].r.to = seq_add(seq, -1);
                self.loss.insert(i + 1, tail);
            }
            return;
        }
    }

    fn remove_loss_before(&mut self, seq: u32) {
        let n = self
            .loss
            .iter()
            .take_while(|e| seq_diff(e.r.to, seq) < 0)
            .count();
        self.loss.drain(..n);
        if let Some(e) = self.loss.first_mut() {
            if seq_diff(e.r.from, seq) < 0 {
                e.r.from = seq;
            }
        }
    }

    fn handle_dropreq(&mut self, first: u32, last: u32) {
        if seq_diff(last, first) < 0 || seq_diff(last, self.rcv_max) >= 0 {
            return;
        }
        let mut out = Vec::with_capacity(self.loss.len() + 1);
        for e in &self.loss {
            if seq_diff(e.r.to, first) < 0 || seq_diff(e.r.from, last) > 0 {
                out.push(*e);
                continue;
            }
            if seq_diff(e.r.from, first) < 0 {
                out.push(LossEntry {
                    r: LossRange {
                        from: e.r.from,
                        to: seq_add(first, -1),
                    },
                    last_nak: e.last_nak,
                });
            }
            if seq_diff(e.r.to, last) > 0 {
                out.push(LossEntry {
                    r: LossRange {
                        from: seq_add(last, 1),
                        to: e.r.to,
                    },
                    last_nak: e.last_nak,
                });
            }
        }
        self.loss = out;
    }

    fn ack_due(&self) -> bool {
        self.ack_seq() != self.ack_acked
            || (self.avail_sent < self.rcv.len() / 2 && self.avail() > self.avail_sent)
    }

    fn avail(&self) -> usize {
        let used = seq_diff(self.ack_seq(), self.rcv_base).max(0) as usize;
        self.rcv.len().saturating_sub(used)
    }

    fn ack_seq(&self) -> u32 {
        self.loss.first().map_or(self.rcv_max, |e| e.r.from)
    }

    fn send_ack(&mut self, now: i64) {
        let ack = self.ack_seq();
        self.since_ack = 0;
        self.ack_no = self.ack_no.wrapping_add(1);
        if self.ack_no == 0 {
            self.ack_no = 1;
        }
        self.acks[self.ack_no as usize % ACK_HISTORY] = AckRecord {
            no: self.ack_no,
            seq: ack,
            sent: Some(now),
        };
        let elapsed = now - self.rate_since;
        let (pps, bps) = if elapsed > 0 {
            (
                (self.rate_count as i64 * 1_000_000 / elapsed) as u32,
                (self.rate_bytes as i64 * 1_000_000 / elapsed) as u32,
            )
        } else {
            (0, 0)
        };
        self.rate_count = 0;
        self.rate_bytes = 0;
        self.rate_since = now;
        self.avail_sent = self.avail();
        let mut cif = Vec::with_capacity(28);
        for v in [
            ack,
            self.rtt as u32,
            self.rtt_var as u32,
            self.avail_sent as u32,
            pps,
            pps.max(1),
            bps,
        ] {
            cif.extend_from_slice(&v.to_be_bytes());
        }
        self.send_control(now, CTRL_ACK, 0, self.ack_no, &cif);
    }

    fn handle_ackack(&mut self, no: u32, now: i64) {
        let r = self.acks[no as usize % ACK_HISTORY];
        let Some(sent) = r.sent.filter(|_| r.no == no) else {
            return;
        };
        self.acks[no as usize % ACK_HISTORY] = AckRecord::default();
        self.ack_acked = r.seq;
        let sample = now - sent;
        let d = (self.rtt - sample).abs();
        self.rtt_var = (3 * self.rtt_var + d) / 4;
        self.rtt = (7 * self.rtt + sample) / 8;
    }

    fn nak_interval(&self) -> i64 {
        ((self.rtt + 4 * self.rtt_var) / 2).max(MIN_NAK_INTERVAL)
    }

    fn send_nak(&mut self, now: i64, ranges: &[LossRange]) {
        self.stats.naks_sent += 1;
        let mut cif = Vec::new();
        write_loss_list(&mut cif, ranges);
        self.send_control(now, CTRL_NAK, 0, 0, &cif);
        if !self.loss.is_empty() && self.next_nak < now {
            self.next_nak = now + self.nak_interval();
        }
    }

    fn send_periodic_nak(&mut self, now: i64) {
        let iv = self.nak_interval();
        let mut ranges = Vec::new();
        for e in &mut self.loss {
            if now - e.last_nak >= iv && ranges.len() < MAX_NAK_RANGES {
                ranges.push(e.r);
                e.last_nak = now;
            }
        }
        self.next_nak = now + iv;
        if !ranges.is_empty() {
            self.send_nak(now, &ranges);
        }
    }

    fn deliver(&mut self, now: i64, all: bool) {
        self.next_deliver = None;
        while self.rcv_count > 0 && self.state == State::Connected {
            let len = self.rcv.len();
            let mut skip = 0;
            if self.rcv[self.rcv_head].is_none() {
                let n = seq_diff(self.rcv_max, self.rcv_base).max(0) as usize;
                skip = 1;
                while skip < n && self.rcv[(self.rcv_head + skip) % len].is_none() {
                    skip += 1;
                }
                if skip >= n {
                    return;
                }
            }
            let ts = self.rcv[(self.rcv_head + skip) % len]
                .as_ref()
                .map_or(0, |p| p.ts);
            let at = self.base + ts + self.rcv_latency;
            if !all && now < at {
                self.next_deliver = Some(at);
                return;
            }
            if skip > 0 {
                self.stats.packets_recv_drop += skip as u64;
                self.advance(skip);
                self.remove_loss_before(self.rcv_base);
            }
            let p = self.rcv[self.rcv_head].take();
            self.rcv_count -= 1;
            self.advance(1);
            if !self.loss.is_empty() {
                self.remove_loss_before(self.rcv_base);
            }
            if let Some(Some(data)) = p.map(|p| p.payload) {
                self.events.push_back(Event::Data(data));
            }
        }
    }

    fn advance(&mut self, n: usize) {
        self.rcv_head = (self.rcv_head + n) % self.rcv.len();
        self.rcv_base = seq_add(self.rcv_base, n as i64);
        if seq_diff(self.rcv_max, self.rcv_base) < 0 {
            self.rcv_max = self.rcv_base;
        }
    }
}
