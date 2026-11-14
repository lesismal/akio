//! A QUIC connection as a sans-io state machine: datagrams in ([`Connection::handle_datagram`]),
//! datagrams out ([`Connection::poll_transmit`]), timers ([`Connection::poll_timeout`] /
//! [`Connection::handle_timeout`]), application events ([`Connection::poll_event`]) and
//! endpoint events (connection IDs, [`Connection::poll_endpoint_event`]).

mod recv;
mod send;
mod streams;

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use only_crypto::rand::ChaChaRng;
use only_tls::quic::{Event as TlsEvent, Keys as TlsKeys, Level, QuicTls};

use super::cid::{ConnectionId, LOCAL_CID_LEN, ResetToken, reset_token};
use super::crypto::{Keys, OneRtt, initial_keys};
use super::frame::{TransportError, code};
use super::params::TransportParams;
use super::ranges::RangeSet;
use super::recovery::{CcKind, Congestion, Pacer, Rtt};
use super::stream::{RecvBuf, SendBuf};
use crate::types::{Congestion as CcConfig, ConnectionError, ConnectionStats, Dir, Side, StreamId};
use crate::{Bytes, TransportConfig};

pub(crate) use streams::StreamState;

/// Our max_ack_delay.
const LOCAL_MAX_ACK_DELAY: Duration = Duration::from_millis(25);
/// Our ack_delay_exponent.
const LOCAL_ACK_DELAY_EXPONENT: u64 = 3;
/// Connection IDs we let the peer hold for us.
const LOCAL_CID_LIMIT: u64 = 4;
/// The max_udp_payload_size we advertise.
const LOCAL_MAX_UDP_PAYLOAD: u64 = 1472;
/// Largest datagram size path MTU discovery tries.
const MTU_PROBE_MAX: u16 = 1452;
/// Undecryptable packets kept until their keys arrive.
const MAX_BUFFERED_PACKETS: usize = 16;
/// Out-of-order CRYPTO bytes accepted per level.
const MAX_CRYPTO_BUFFER: u64 = 64 * 1024;
/// ACK ranges in one ACK frame.
const MAX_ACK_RANGES: usize = 32;
/// Packets sent with one key phase before this side starts a key update (well below the AEAD
/// confidentiality limits of RFC 9001 section 6.6).
const KEY_UPDATE_INTERVAL: u64 = 1 << 22;
/// Received datagram payload sizes accepted as DATAGRAM frames.
const MAX_DATAGRAM_FRAME: u64 = 65535;

/// A connection's packet number spaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum SpaceId {
    Initial = 0,
    Handshake = 1,
    Data = 2,
}

impl SpaceId {
    const ALL: [SpaceId; 3] = [SpaceId::Initial, SpaceId::Handshake, SpaceId::Data];

    fn level(self) -> Level {
        match self {
            SpaceId::Initial => Level::Initial,
            SpaceId::Handshake => Level::Handshake,
            SpaceId::Data => Level::Application,
        }
    }

    fn from_level(l: Level) -> Option<SpaceId> {
        match l {
            Level::Initial => Some(SpaceId::Initial),
            Level::Handshake => Some(SpaceId::Handshake),
            Level::Application => Some(SpaceId::Data),
            _ => None,
        }
    }
}

/// What a sent packet carried that matters when it is acknowledged or lost.
#[derive(Clone, Debug)]
pub(crate) enum SentFrame {
    Stream {
        id: u64,
        off: u64,
        len: u64,
        fin: bool,
    },
    Crypto {
        off: u64,
        len: u64,
    },
    Ack(u64),
    ResetStream(u64),
    StopSending(u64),
    MaxData,
    MaxStreamData(u64),
    MaxStreams(bool),
    DataBlocked,
    StreamDataBlocked,
    StreamsBlocked,
    NewCid(u64),
    RetireCid(u64),
    HandshakeDone,
    NewToken(Bytes),
    PathChallenge,
}

#[derive(Clone, Debug)]
pub(crate) struct Sent {
    time: Instant,
    size: u16,
    ack_eliciting: bool,
    in_flight: bool,
    mtu_probe: bool,
    frames: Vec<SentFrame>,
}

/// One packet number space.
pub(crate) struct Space {
    keys: Option<Keys>,
    next_pn: u64,
    largest_acked: Option<u64>,
    largest_acked_time: Option<Instant>,
    sent: BTreeMap<u64, Sent>,
    // Receiving.
    rx: RangeSet,
    seen: RangeSet,
    seen_floor: u64,
    largest_rx: Option<u64>,
    largest_rx_time: Option<Instant>,
    rx_new: bool,
    eliciting_since_ack: u32,
    ack_now: bool,
    ack_deadline: Option<Instant>,
    // CRYPTO.
    crypto_send: SendBuf,
    crypto_recv: RecvBuf,
    // Recovery.
    loss_time: Option<Instant>,
    last_eliciting_sent: Option<Instant>,
    eliciting_in_flight: u64,
    /// Probe packets owed after a PTO.
    probes: u8,
    discarded: bool,
}

impl Space {
    fn new() -> Space {
        Space {
            keys: None,
            next_pn: 0,
            largest_acked: None,
            largest_acked_time: None,
            sent: BTreeMap::new(),
            rx: RangeSet::new(),
            seen: RangeSet::new(),
            seen_floor: 0,
            largest_rx: None,
            largest_rx_time: None,
            rx_new: false,
            eliciting_since_ack: 0,
            ack_now: false,
            ack_deadline: None,
            crypto_send: SendBuf::default(),
            crypto_recv: RecvBuf::default(),
            loss_time: None,
            last_eliciting_sent: None,
            eliciting_in_flight: 0,
            probes: 0,
            discarded: false,
        }
    }

    /// Whether an ACK frame must go out now (not just piggyback).
    fn ack_due(&self, now: Instant) -> bool {
        self.rx_new && (self.ack_now || self.ack_deadline.is_some_and(|d| d <= now))
    }
}

/// The network path to the peer.
#[derive(Clone, Debug)]
pub(crate) struct Path {
    pub remote: SocketAddr,
    pub(crate) validated: bool,
    sent_bytes: u64,
    recv_bytes: u64,
    challenge: Option<[u8; 8]>,
    challenge_sent: Option<Instant>,
    challenge_deadline: Option<Instant>,
}

impl Path {
    fn new(remote: SocketAddr, validated: bool) -> Path {
        Path {
            remote,
            validated,
            sent_bytes: 0,
            recv_bytes: 0,
            challenge: None,
            challenge_sent: None,
            challenge_deadline: None,
        }
    }

    /// Bytes the anti-amplification limit (3x received) still allows.
    fn budget(&self) -> u64 {
        if self.validated {
            u64::MAX
        } else {
            (self.recv_bytes * 3).saturating_sub(self.sent_bytes)
        }
    }
}

/// Control frames waiting to be sent (in 1-RTT packets).
#[derive(Default, Debug)]
pub(crate) struct PendingCtl {
    max_data: bool,
    max_stream_data: HashSet<u64>,
    max_streams_bidi: bool,
    max_streams_uni: bool,
    reset_stream: HashSet<u64>,
    stop_sending: HashSet<u64>,
    new_cids: Vec<u64>,
    retire_cids: Vec<u64>,
    handshake_done: bool,
    new_token: Option<Bytes>,
    data_blocked: bool,
    stream_data_blocked: HashSet<u64>,
    streams_blocked_bidi: bool,
    streams_blocked_uni: bool,
    path_responses: VecDeque<(SocketAddr, [u8; 8])>,
    path_challenge: bool,
    ping: bool,
}

/// What the application learns.
#[derive(Debug)]
pub enum Event {
    Connected,
    StreamOpened(StreamId),
    StreamData(StreamId, Bytes, bool),
    StreamReset(StreamId, u64),
    StreamStopped(StreamId, u64),
    StreamsAvailable(Dir),
    Datagram(Bytes),
    Closed(ConnectionError),
}

/// What the endpoint must know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointEvent {
    /// Route packets for this connection ID here too.
    NewCid(ConnectionId),
    /// Stop routing this connection ID.
    RetireCid(ConnectionId),
    /// The handshake is confirmed: the client's original destination ID may be forgotten.
    HandshakeDone,
    /// A token for future connections to this server (client).
    NewToken(Vec<u8>),
    /// The connection is gone.
    Drained,
}

/// Datagrams to send to `dest`: one, or several of `segment_size` bytes each (the last may
/// be shorter) for one GSO send.
#[derive(Debug)]
pub struct Transmit {
    pub dest: SocketAddr,
    pub segment_size: Option<usize>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CloseKind {
    Transport {
        code: u64,
        frame: u64,
        reason: Vec<u8>,
    },
    App {
        code: u64,
        reason: Vec<u8>,
    },
}

#[derive(Debug)]
pub(crate) enum State {
    Handshake,
    Established,
    /// We closed: CONNECTION_CLOSE goes out in answer to anything until the deadline.
    Closing {
        until: Instant,
        close: CloseKind,
        resend: bool,
    },
    /// The peer closed: we stay quiet until the deadline.
    Draining {
        until: Instant,
    },
    Drained,
}

/// Per-connection settings derived from the endpoint configuration.
#[derive(Clone, Debug)]
pub(crate) struct ConnConfig {
    pub transport: TransportConfig,
    pub migration: bool,
    /// Forces this side to start a key update every `n` packets (tests).
    pub key_update_interval: u64,
}

impl ConnConfig {
    pub fn new(transport: TransportConfig, migration: bool) -> ConnConfig {
        ConnConfig {
            transport,
            migration,
            key_update_interval: KEY_UPDATE_INTERVAL,
        }
    }
}

/// Secrets shared by the endpoint and its connections.
pub(crate) struct EndpointKeys {
    pub reset_key: [u8; 32],
    pub token_key: super::crypto::TokenKey,
}

/// Remote connection IDs.
struct RemoteCid {
    cid: ConnectionId,
    token: Option<ResetToken>,
}

/// A QUIC connection.
pub struct Connection {
    side: Side,
    cfg: ConnConfig,
    keys: Arc<EndpointKeys>,
    rng: ChaChaRng,
    state: State,
    tls: QuicTls,
    tls_done: bool,
    confirmed: bool,
    params_done: bool,
    peer: TransportParams,
    pending_hs_keys: (Option<TlsKeys>, Option<TlsKeys>),
    pending_1rtt_keys: (Option<TlsKeys>, Option<TlsKeys>),
    spaces: [Space; 3],
    one_rtt: Option<OneRtt>,
    /// First packet number sent in the current key phase.
    phase_first_sent: u64,
    /// Whether a packet of the current phase was acknowledged (another update may start).
    phase_acked: bool,
    /// Lowest packet number received in the current remote key phase.
    phase_first_rx: Option<u64>,
    pub(crate) path: Path,
    prev_path: Option<Path>,
    // Connection IDs.
    local_cids: BTreeMap<u64, ConnectionId>,
    next_local_seq: u64,
    remote_cids: BTreeMap<u64, RemoteCid>,
    remote_seq: u64,
    remote_retire_prior_to: u64,
    /// The client's first destination connection ID (client) / the original one (server).
    orig_dcid: ConnectionId,
    /// The source connection ID of the peer's first Initial (client: server's SCID).
    peer_initial_scid: Option<ConnectionId>,
    pub(crate) retry_scid: Option<ConnectionId>,
    retry_token: Vec<u8>,
    got_server_packet: bool,
    // Recovery.
    rtt: Rtt,
    cc: Congestion,
    pacer: Pacer,
    bytes_in_flight: u64,
    pto_count: u32,
    first_rtt_sample: Option<Instant>,
    mtu: u16,
    mtu_probe: Option<(u16, u8)>,
    mtu_upper: u16,
    mtu_in_flight: Option<u64>,
    // Streams and flow control.
    pub(crate) streams: HashMap<u64, StreamState>,
    send_queue: VecDeque<u64>,
    next_local: [u64; 2],
    peer_max_streams: [u64; 2],
    peer_opened: [u64; 2],
    local_max_streams: [u64; 2],
    local_closed: [u64; 2],
    streams_blocked: [bool; 2],
    tx_max_data: u64,
    tx_data: u64,
    rx_max_data: u64,
    rx_data: u64,
    rx_delivered: u64,
    pending: PendingCtl,
    // Datagrams.
    dgram_queue: VecDeque<Bytes>,
    dgram_queued_bytes: usize,
    // Timers and bookkeeping.
    idle_deadline: Option<Instant>,
    last_rx: Instant,
    eliciting_since_rx: bool,
    last_eliciting_sent_any: Option<Instant>,
    pacing_until: Option<Instant>,
    buffered: Vec<(SocketAddr, Vec<u8>)>,
    replay: bool,
    events: VecDeque<Event>,
    ep_events: VecDeque<EndpointEvent>,
    stats: ConnectionStats,
    close_sent_count: u32,
}

impl Connection {
    #[allow(clippy::too_many_arguments)]
    fn base(
        side: Side,
        now: Instant,
        cfg: ConnConfig,
        keys: Arc<EndpointKeys>,
        mut rng: ChaChaRng,
        tls: QuicTls,
        remote: SocketAddr,
        local_cid: ConnectionId,
        orig_dcid: ConnectionId,
        remote_cid: ConnectionId,
    ) -> Connection {
        let t = &cfg.transport;
        let mtu = t.initial_mtu.max(1200);
        let kind = match t.congestion {
            CcConfig::NewReno => CcKind::NewReno,
            _ => CcKind::Cubic,
        };
        let rx_max_data = t.receive_window.unwrap_or(super::coding::VARINT_MAX);
        let local_max_streams = [
            u64::from(t.max_concurrent_bidi_streams),
            u64::from(t.max_concurrent_uni_streams),
        ];
        let mut local_cids = BTreeMap::new();
        local_cids.insert(0, local_cid);
        let mut remote_cids = BTreeMap::new();
        remote_cids.insert(
            0,
            RemoteCid {
                cid: remote_cid,
                token: None,
            },
        );
        let rng_seed = {
            let mut s = [0u8; 32];
            rng.fill(&mut s);
            s
        };
        let mut c = Connection {
            side,
            keys,
            rng: ChaChaRng::from_seed(rng_seed),
            state: State::Handshake,
            tls,
            tls_done: false,
            confirmed: false,
            params_done: false,
            peer: TransportParams::default(),
            pending_hs_keys: (None, None),
            pending_1rtt_keys: (None, None),
            spaces: [Space::new(), Space::new(), Space::new()],
            one_rtt: None,
            phase_first_sent: 0,
            phase_acked: false,
            phase_first_rx: None,
            path: Path::new(remote, side == Side::Client),
            prev_path: None,
            local_cids,
            next_local_seq: 1,
            remote_cids,
            remote_seq: 0,
            remote_retire_prior_to: 0,
            orig_dcid,
            peer_initial_scid: None,
            retry_scid: None,
            retry_token: Vec::new(),
            got_server_packet: false,
            rtt: Rtt::new(t.initial_rtt),
            cc: Congestion::new(kind, mtu),
            pacer: Pacer::new(),
            bytes_in_flight: 0,
            pto_count: 0,
            first_rtt_sample: None,
            mtu,
            mtu_probe: None,
            mtu_upper: if t.mtu_discovery {
                MTU_PROBE_MAX.max(mtu)
            } else {
                mtu
            },
            mtu_in_flight: None,
            streams: HashMap::new(),
            send_queue: VecDeque::new(),
            next_local: [0, 0],
            peer_max_streams: [0, 0],
            peer_opened: [0, 0],
            local_max_streams,
            local_closed: [0, 0],
            streams_blocked: [false, false],
            tx_max_data: 0,
            tx_data: 0,
            rx_max_data,
            rx_data: 0,
            rx_delivered: 0,
            pending: PendingCtl::default(),
            dgram_queue: VecDeque::new(),
            dgram_queued_bytes: 0,
            idle_deadline: None,
            last_rx: now,
            eliciting_since_rx: false,
            last_eliciting_sent_any: None,
            pacing_until: None,
            buffered: Vec::new(),
            replay: false,
            events: VecDeque::new(),
            ep_events: VecDeque::new(),
            stats: ConnectionStats::default(),
            close_sent_count: 0,
            cfg,
        };
        c.stats.current_mtu = mtu;
        c.reset_idle(now);
        c
    }

    /// Our transport parameters (without the connection IDs).
    fn local_params(cfg: &ConnConfig) -> TransportParams {
        let t = &cfg.transport;
        let stream = t.stream_receive_window.min(super::coding::VARINT_MAX);
        TransportParams {
            max_idle_timeout: t.max_idle_timeout.map_or(0, |d| {
                u64::try_from(d.as_millis())
                    .unwrap_or(u64::MAX)
                    .min(super::coding::VARINT_MAX)
            }),
            max_udp_payload_size: LOCAL_MAX_UDP_PAYLOAD,
            initial_max_data: t
                .receive_window
                .unwrap_or(super::coding::VARINT_MAX)
                .min(super::coding::VARINT_MAX),
            initial_max_stream_data_bidi_local: stream,
            initial_max_stream_data_bidi_remote: stream,
            initial_max_stream_data_uni: stream,
            initial_max_streams_bidi: u64::from(t.max_concurrent_bidi_streams),
            initial_max_streams_uni: u64::from(t.max_concurrent_uni_streams),
            ack_delay_exponent: LOCAL_ACK_DELAY_EXPONENT,
            max_ack_delay: LOCAL_MAX_ACK_DELAY.as_millis() as u64,
            disable_active_migration: !cfg.migration,
            active_connection_id_limit: LOCAL_CID_LIMIT,
            max_datagram_frame_size: if t.datagram_receive_buffer_size.is_some() {
                MAX_DATAGRAM_FRAME
            } else {
                0
            },
            ..TransportParams::default()
        }
    }

    /// A client connection to `remote`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn client(
        now: Instant,
        cfg: ConnConfig,
        keys: Arc<EndpointKeys>,
        mut rng: ChaChaRng,
        tls_cfg: &only_tls::ClientConfig,
        server_name: &str,
        remote: SocketAddr,
        token: Vec<u8>,
    ) -> Result<Connection, crate::Error> {
        let local = ConnectionId::random(&mut rng, LOCAL_CID_LEN);
        let dcid = ConnectionId::random(&mut rng, 8);
        let mut params = Connection::local_params(&cfg);
        params.initial_scid = Some(local);
        params.disable_active_migration = false;
        let tls = QuicTls::client(tls_cfg, server_name, params.encode())
            .map_err(|e| crate::Error::Connect(e.to_string()))?;
        let mut c = Connection::base(
            Side::Client,
            now,
            cfg,
            keys,
            rng,
            tls,
            remote,
            local,
            dcid,
            dcid,
        );
        c.spaces[0].keys = Some(initial_keys(&dcid, true));
        c.retry_token = token;
        c.drain_tls(now);
        Ok(c)
    }

    /// A server connection for a client's first Initial.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn server(
        now: Instant,
        cfg: ConnConfig,
        keys: Arc<EndpointKeys>,
        mut rng: ChaChaRng,
        tls_cfg: &only_tls::ServerConfig,
        remote: SocketAddr,
        initial_dcid: ConnectionId,
        client_scid: ConnectionId,
        orig_dcid: ConnectionId,
        retry_scid: Option<ConnectionId>,
        validated: bool,
    ) -> Connection {
        let local = ConnectionId::random(&mut rng, LOCAL_CID_LEN);
        let mut params = Connection::local_params(&cfg);
        params.original_dcid = Some(orig_dcid);
        params.initial_scid = Some(local);
        params.retry_scid = retry_scid;
        params.stateless_reset_token = Some(reset_token(&keys.reset_key, &local));
        let tls = QuicTls::server(tls_cfg, params.encode());
        let mut c = Connection::base(
            Side::Server,
            now,
            cfg,
            keys,
            rng,
            tls,
            remote,
            local,
            orig_dcid,
            client_scid,
        );
        c.spaces[0].keys = Some(initial_keys(&initial_dcid, false));
        c.peer_initial_scid = Some(client_scid);
        c.retry_scid = retry_scid;
        c.path.validated = validated;
        c
    }

    // ---- introspection ----

    pub fn remote_addr(&self) -> SocketAddr {
        self.path.remote
    }

    pub fn local_cid(&self) -> ConnectionId {
        self.local_cids.values().next().copied().unwrap_or_default()
    }

    pub fn alpn(&self) -> Option<Vec<u8>> {
        self.tls.alpn().map(<[u8]>::to_vec)
    }

    pub fn server_name(&self) -> Option<String> {
        self.tls.server_name().map(str::to_string)
    }

    pub fn rtt(&self) -> Duration {
        self.rtt.smoothed
    }

    pub fn is_handshaking(&self) -> bool {
        matches!(self.state, State::Handshake)
    }

    pub fn is_closed(&self) -> bool {
        matches!(
            self.state,
            State::Closing { .. } | State::Draining { .. } | State::Drained
        )
    }

    pub fn is_drained(&self) -> bool {
        matches!(self.state, State::Drained)
    }

    /// Whether the session was resumed from a ticket.
    #[cfg(test)]
    pub fn resumed(&self) -> bool {
        self.tls.resumed()
    }

    pub fn stats(&self) -> ConnectionStats {
        let mut s = self.stats;
        s.rtt = self.rtt.smoothed;
        s.min_rtt = self.rtt.min;
        s.cwnd = self.cc.window;
        s.congestion_events = self.cc.events;
        s.current_mtu = self.mtu;
        s
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub fn poll_endpoint_event(&mut self) -> Option<EndpointEvent> {
        self.ep_events.pop_front()
    }

    /// Starts a key update now (tests); `false` if one is not allowed yet.
    #[cfg(test)]
    pub(crate) fn force_key_update(&mut self, now: Instant) -> bool {
        self.start_key_update(now)
    }

    #[cfg(test)]
    pub(crate) fn key_phase(&self) -> Option<bool> {
        self.one_rtt.as_ref().map(|k| k.phase)
    }

    // ---- TLS ----

    /// Applies what the TLS handshake produced.
    fn drain_tls(&mut self, now: Instant) {
        while let Some(e) = self.tls.poll_event() {
            match e {
                TlsEvent::Data(l, b) => {
                    if let Some(s) = SpaceId::from_level(l) {
                        self.spaces[s as usize].crypto_send.write(Bytes::from(b));
                    }
                }
                TlsEvent::ReadKeys(l, k) => self.install_keys(now, l, Some(k), None),
                TlsEvent::WriteKeys(l, k) => self.install_keys(now, l, None, Some(k)),
                TlsEvent::Done => self.on_tls_done(now),
            }
        }
        if !self.params_done {
            if let Some(p) = self.tls.peer_transport_params() {
                let p = p.to_vec();
                if let Err(e) = self.apply_peer_params(&p) {
                    self.close_transport(now, e);
                }
            }
        }
    }

    fn install_keys(
        &mut self,
        now: Instant,
        l: Level,
        read: Option<TlsKeys>,
        write: Option<TlsKeys>,
    ) {
        let slot = match l {
            Level::Handshake => &mut self.pending_hs_keys,
            Level::Application => &mut self.pending_1rtt_keys,
            _ => return,
        };
        if read.is_some() {
            slot.0 = read;
        }
        if write.is_some() {
            slot.1 = write;
        }
        let (Some(TlsKeys::Tls13 { suite, secret: rs }), Some(TlsKeys::Tls13 { secret: ws, .. })) =
            (&slot.0, &slot.1)
        else {
            return;
        };
        let (suite, rs, ws) = (*suite, rs.clone(), ws.clone());
        *slot = (None, None);
        match l {
            Level::Handshake => {
                self.spaces[1].keys = Some(Keys {
                    local: super::crypto::DirKeys::from_secret(suite, &ws),
                    remote: super::crypto::DirKeys::from_secret(suite, &rs),
                });
            }
            _ => {
                self.one_rtt = Some(OneRtt::new(suite, ws, rs));
            }
        }
        // Packets that arrived before their keys get another try.
        self.replay = !self.buffered.is_empty();
        let _ = now;
    }

    fn on_tls_done(&mut self, now: Instant) {
        if self.tls_done {
            return;
        }
        self.tls_done = true;
        if matches!(self.state, State::Handshake) {
            self.state = State::Established;
        }
        self.events.push_back(Event::Connected);
        if self.side == Side::Server {
            // The server's handshake is confirmed once complete (RFC 9001 section 4.1.2).
            self.pending.handshake_done = true;
            let tok = self.new_token();
            self.pending.new_token = Some(tok);
            self.confirm(now);
        }
    }

    fn confirm(&mut self, now: Instant) {
        if self.confirmed {
            return;
        }
        self.confirmed = true;
        self.discard_space(now, SpaceId::Handshake);
        self.ep_events.push_back(EndpointEvent::HandshakeDone);
        self.issue_cids();
        if self.mtu_upper > self.mtu {
            self.mtu_probe = Some((self.next_probe_size(), 0));
        }
    }

    fn new_token(&mut self) -> Bytes {
        let mut plain = Vec::with_capacity(32);
        plain.extend_from_slice(&unix_secs().to_be_bytes());
        push_ip(&mut plain, self.path.remote);
        Bytes::from(
            self.keys
                .token_key
                .seal(&mut self.rng, super::endpoint::TOKEN_NEW, &plain),
        )
    }

    fn apply_peer_params(&mut self, raw: &[u8]) -> Result<(), TransportError> {
        self.params_done = true;
        let p = TransportParams::decode(raw, self.side == Side::Client)?;
        let perr = |r: &str| TransportError::new(code::TRANSPORT_PARAMETER_ERROR, r);
        if p.initial_scid != self.peer_initial_scid {
            return Err(perr("initial_source_connection_id mismatch"));
        }
        if self.side == Side::Client {
            if p.original_dcid != Some(self.orig_dcid) {
                return Err(perr("original_destination_connection_id mismatch"));
            }
            if p.retry_scid != self.retry_scid {
                return Err(perr("retry_source_connection_id mismatch"));
            }
            if let Some(t) = p.stateless_reset_token {
                if let Some(r) = self.remote_cids.get_mut(&0) {
                    r.token = Some(t);
                }
            }
        }
        self.peer_max_streams = [p.initial_max_streams_bidi, p.initial_max_streams_uni];
        self.tx_max_data = p.initial_max_data;
        // Streams opened before the parameters (none in practice) get their limits.
        let side = self.side;
        for (id, s) in &mut self.streams {
            if let Some(snd) = s.send.as_mut() {
                let sid = StreamId::from_raw(*id);
                snd.max_data = initial_send_window(&p, side, sid);
            }
        }
        if p.max_udp_payload_size < u64::from(self.mtu_upper) {
            self.mtu_upper = (p.max_udp_payload_size as u16).max(self.mtu);
        }
        self.peer = p;
        Ok(())
    }

    // ---- connection IDs ----

    fn issue_cids(&mut self) {
        if self
            .remote_cids
            .values()
            .next()
            .is_some_and(|r| r.cid.is_empty())
            && self.side == Side::Server
        {
            // A peer with zero-length IDs cannot use more of ours either way; still issue some
            // so it can migrate.
        }
        let limit = self.peer.active_connection_id_limit.min(LOCAL_CID_LIMIT);
        while (self.local_cids.len() as u64) < limit {
            let cid = ConnectionId::random(&mut self.rng, LOCAL_CID_LEN);
            let seq = self.next_local_seq;
            self.next_local_seq += 1;
            self.local_cids.insert(seq, cid);
            self.pending.new_cids.push(seq);
            self.ep_events.push_back(EndpointEvent::NewCid(cid));
        }
    }

    fn reset_token_for(&self, cid: &ConnectionId) -> ResetToken {
        reset_token(&self.keys.reset_key, cid)
    }

    fn remote_cid(&self) -> ConnectionId {
        self.remote_cids
            .get(&self.remote_seq)
            .map(|r| r.cid)
            .unwrap_or_default()
    }

    /// Whether the last 16 bytes of `data` are a reset token the peer gave us.
    fn is_stateless_reset(&self, data: &[u8]) -> bool {
        if data.len() < 21 {
            return false;
        }
        let tail = &data[data.len() - 16..];
        self.remote_cids
            .values()
            .any(|r| r.token.is_some_and(|t| only_crypto::ct_eq(&t, tail)))
    }

    // ---- lifecycle ----

    fn reset_idle(&mut self, now: Instant) {
        let local = self.cfg.transport.max_idle_timeout;
        let peer = (self.peer.max_idle_timeout > 0)
            .then(|| Duration::from_millis(self.peer.max_idle_timeout));
        let t = match (local, peer) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.idle_deadline = t.map(|t| now + t.max(self.pto() * 3));
    }

    /// The probe timeout without backoff.
    fn pto(&self) -> Duration {
        let mut d = self.rtt.pto_base();
        if self.confirmed {
            d += Duration::from_millis(self.peer.max_ack_delay);
        }
        d
    }

    /// Closes with an application error code.
    pub fn close(&mut self, now: Instant, code: u64, reason: &[u8]) {
        if self.is_closed() {
            return;
        }
        self.enter_closing(
            now,
            CloseKind::App {
                code,
                reason: reason.to_vec(),
            },
        );
        self.events
            .push_back(Event::Closed(ConnectionError::LocallyClosed));
    }

    /// Closes with a transport error we detected.
    fn close_transport(&mut self, now: Instant, e: TransportError) {
        if self.is_closed() {
            return;
        }
        self.enter_closing(
            now,
            CloseKind::Transport {
                code: e.code,
                frame: e.frame.unwrap_or(0),
                reason: e.reason.as_bytes().to_vec(),
            },
        );
        self.events
            .push_back(Event::Closed(ConnectionError::TransportError {
                code: e.code,
                reason: e.reason,
            }));
    }

    fn enter_closing(&mut self, now: Instant, close: CloseKind) {
        self.state = State::Closing {
            until: now + self.pto() * 3,
            close,
            resend: true,
        };
        self.drop_all_state();
    }

    fn enter_draining(&mut self, now: Instant, reason: ConnectionError) {
        if !self.is_closed() {
            self.events.push_back(Event::Closed(reason));
        }
        if !matches!(self.state, State::Draining { .. } | State::Drained) {
            self.state = State::Draining {
                until: now + self.pto() * 3,
            };
        }
        self.drop_all_state();
    }

    /// Ends the connection right away (idle timeout, stateless reset).
    fn drain_now(&mut self, reason: ConnectionError) {
        if !self.is_closed() {
            self.events.push_back(Event::Closed(reason));
        }
        self.state = State::Drained;
        self.drop_all_state();
        self.ep_events.push_back(EndpointEvent::Drained);
    }

    fn drop_all_state(&mut self) {
        self.streams.clear();
        self.send_queue.clear();
        self.dgram_queue.clear();
        self.dgram_queued_bytes = 0;
        self.pending = PendingCtl::default();
        for s in &mut self.spaces {
            s.sent.clear();
            s.loss_time = None;
            s.eliciting_in_flight = 0;
            s.probes = 0;
        }
        self.bytes_in_flight = 0;
        self.buffered.clear();
    }

    /// Discards a packet number space's keys and state (RFC 9002 section 6.4).
    fn discard_space(&mut self, _now: Instant, id: SpaceId) {
        let s = &mut self.spaces[id as usize];
        if s.discarded {
            return;
        }
        s.discarded = true;
        s.keys = None;
        let mut flight = 0;
        for p in s.sent.values() {
            if p.in_flight {
                flight += u64::from(p.size);
            }
        }
        s.sent.clear();
        s.loss_time = None;
        s.eliciting_in_flight = 0;
        s.probes = 0;
        s.rx_new = false;
        s.ack_now = false;
        s.ack_deadline = None;
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(flight);
        self.pto_count = 0;
    }

    // ---- timers ----

    pub fn poll_timeout(&self) -> Option<Instant> {
        match &self.state {
            State::Closing { until, .. } | State::Draining { until } => return Some(*until),
            State::Drained => return None,
            _ => {}
        }
        let mut t: Option<Instant> = None;
        let mut min = |x: Option<Instant>| {
            if let Some(x) = x {
                t = Some(t.map_or(x, |t: Instant| t.min(x)));
            }
        };
        min(self.idle_deadline);
        min(self.loss_timer().map(|x| x.0));
        for s in &self.spaces {
            if s.rx_new {
                min(s.ack_deadline);
            }
        }
        min(self.pacing_until);
        if let Some(k) = self.cfg.transport.keep_alive_interval {
            if self.tls_done {
                min(self.last_eliciting_sent_any.map(|l| l + k));
            }
        }
        min(self.path.challenge_deadline);
        if let Some((_, until)) = self.one_rtt.as_ref().and_then(|k| k.prev_remote.as_ref()) {
            min(Some(*until));
        }
        t
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        match &self.state {
            State::Closing { until, .. } | State::Draining { until } => {
                if now >= *until {
                    self.state = State::Drained;
                    self.ep_events.push_back(EndpointEvent::Drained);
                }
                return;
            }
            State::Drained => return,
            _ => {}
        }
        if self.idle_deadline.is_some_and(|d| now >= d) {
            self.drain_now(ConnectionError::TimedOut);
            return;
        }
        if self.pacing_until.is_some_and(|p| now >= p) {
            self.pacing_until = None;
        }
        if let Some(k) = self.cfg.transport.keep_alive_interval {
            if self.tls_done && self.last_eliciting_sent_any.is_some_and(|l| now >= l + k) {
                self.pending.ping = true;
                // Not again until the ping goes out.
                self.last_eliciting_sent_any = Some(now);
            }
        }
        if self.path.challenge_deadline.is_some_and(|d| now >= d) {
            self.on_path_validation_timeout(now);
        }
        if let Some(k) = self.one_rtt.as_mut() {
            if k.prev_remote.as_ref().is_some_and(|(_, u)| now >= *u) {
                k.prev_remote = None;
            }
        }
        if let Some((at, space)) = self.loss_timer() {
            if now >= at {
                self.on_loss_timer(now, space);
            }
        }
    }

    fn on_path_validation_timeout(&mut self, now: Instant) {
        let p = &mut self.path;
        let tries_left = p
            .challenge_sent
            .is_some_and(|s| now < s + self.rtt.pto_base() * 3 * 3);
        if tries_left && !p.validated {
            // Resend the challenge.
            self.pending.path_challenge = true;
            p.challenge_deadline = Some(now + self.rtt.pto_base() * 2);
            return;
        }
        p.challenge_deadline = None;
        p.challenge = None;
        if !p.validated {
            // Validation failed: back to the old path if there is one.
            if let Some(old) = self.prev_path.take() {
                self.path = old;
            }
        }
    }
}

/// The send window the peer's parameters give a stream we can send on.
fn initial_send_window(p: &TransportParams, side: Side, id: StreamId) -> u64 {
    match (id.dir(), id.initiator() == side) {
        (Dir::Uni, _) => p.initial_max_stream_data_uni,
        // Our bidi stream: the peer's limit for streams it did not open.
        (Dir::Bi, true) => p.initial_max_stream_data_bidi_remote,
        (Dir::Bi, false) => p.initial_max_stream_data_bidi_local,
    }
}

pub(crate) fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub(crate) fn push_ip(out: &mut Vec<u8>, a: SocketAddr) {
    match a.ip() {
        std::net::IpAddr::V4(v) => {
            out.push(4);
            out.extend_from_slice(&v.octets());
        }
        std::net::IpAddr::V6(v) => {
            out.push(6);
            out.extend_from_slice(&v.octets());
        }
    }
}
