//! A QUIC connection as a sans-io state machine: datagrams in ([`Connection::handle_datagram`]),
//! datagrams out ([`Connection::poll_transmit`]), timers ([`Connection::poll_timeout`] /
//! [`Connection::handle_timeout`]), application events ([`Connection::poll_event`]) and
//! endpoint events (connection IDs, [`Connection::poll_endpoint_event`]).

mod ecn;
mod migrate;
mod recv;
mod send;
mod sent;
mod streams;

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use akio_crypto::rand::ChaChaRng;
use akio_tls::quic::{EarlyData, Event as TlsEvent, Keys as TlsKeys, Level, QuicTls};

use super::cid::{ConnectionId, LOCAL_CID_LEN, ResetToken, reset_token};
use super::crypto::{DirKeys, Keys, OneRtt, initial_keys};
use super::frame::{TransportError, code};
use super::packet::supported;
use super::params::TransportParams;
use super::ranges::RangeSet;
use super::recovery::{CcKind, Congestion, Pacer, Rtt};
use super::stream::{RecvBuf, SendBuf};
use super::{IdMap, IdSet};
use crate::types::{Congestion as CcConfig, ConnectionError, ConnectionStats, Dir, Side, StreamId};
use crate::{Bytes, TransportConfig};

use ecn::Ecn;
#[cfg(test)]
pub(crate) use migrate::MigrateError;
use sent::SentPackets;
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

/// Spare frame lists kept however few packets are in flight (see `recycle_frames`).
const SPARE_FRAMES_MIN: usize = 64;
/// The largest acknowledgment list kept for the next acknowledgment, in packets.
const ACKED_SCRATCH_MAX: usize = 1024;

#[derive(Clone, Debug)]
pub(crate) struct Sent {
    time: Instant,
    size: u16,
    ack_eliciting: bool,
    in_flight: bool,
    mtu_probe: bool,
    /// Sent ECT(0).
    ecn: bool,
    /// Delivery-rate sampling state when it was sent (see [`Delivery`]): bytes delivered, and
    /// how long before `time` the last delivery and the flight's first send were, in
    /// microseconds (kept small: one of these per packet in flight).
    delivered: u64,
    delivered_age: u32,
    first_sent_age: u32,
    app_limited: bool,
    frames: Vec<SentFrame>,
}

/// Delivery-rate estimation (draft-cheng-iccrg-delivery-rate-estimation): bytes delivered so
/// far and when, recorded in every packet sent, so an acknowledgment can tell the rate at which
/// data got through over the packet's flight. BBR's bandwidth samples.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Delivery {
    delivered: u64,
    delivered_time: Instant,
    first_sent: Instant,
    /// Non-zero while the samples are application-limited: until `delivered` passes it.
    app_limited_until: u64,
}

/// Microseconds from `then` to `now` (saturating).
fn age_us(now: Instant, then: Instant) -> u32 {
    u32::try_from(now.saturating_duration_since(then).as_micros()).unwrap_or(u32::MAX)
}

impl Delivery {
    fn new(now: Instant) -> Delivery {
        Delivery {
            delivered: 0,
            delivered_time: now,
            first_sent: now,
            app_limited_until: 0,
        }
    }
}

/// One packet number space.
pub(crate) struct Space {
    keys: Option<Keys>,
    next_pn: u64,
    largest_acked: Option<u64>,
    largest_acked_time: Option<Instant>,
    sent: SentPackets,
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
            sent: SentPackets::default(),
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
    max_stream_data: IdSet,
    max_streams_bidi: bool,
    max_streams_uni: bool,
    reset_stream: IdSet,
    stop_sending: IdSet,
    new_cids: Vec<u64>,
    retire_cids: Vec<u64>,
    handshake_done: bool,
    new_token: Option<Bytes>,
    data_blocked: bool,
    stream_data_blocked: IdSet,
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
    /// A stream refused a write (or reported no room) and has room again.
    StreamWritable(StreamId),
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
    NewToken(ClientToken),
    /// The probed path was validated: the connection moved to it (client; send the transmits
    /// over the probe's socket from now on and close the old one).
    Migrated { remote: SocketAddr },
    /// The probed path did not answer: the connection stays where it was (close the probe's
    /// socket).
    MigrationFailed,
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
    /// The ECN codepoint to send the datagrams with (0: not ECN-capable).
    pub ecn: u8,
    /// Send over the socket of the path being probed (client migration), not the current one.
    pub probe: bool,
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
    /// The I/O layer can send ECN codepoints (with `transport.ecn`, packets are marked).
    pub ecn_io: bool,
    /// The addresses a server offers as its preferred address (RFC 9000 section 9.6).
    pub preferred_address: (
        Option<std::net::SocketAddrV4>,
        Option<std::net::SocketAddrV6>,
    ),
    /// The QUIC version a client starts with (a server answers in the client's).
    pub version: u32,
    /// The versions this side speaks: a server accepts them, a client may start over in them
    /// after Version Negotiation or switch to them when the server negotiates one compatibly.
    pub versions: Vec<u32>,
    /// A server switches clients that start in another version and list this one as
    /// available to it within the handshake (compatible version negotiation, RFC 9368
    /// section 4). `None`: it answers in the client's version.
    pub prefer_version: Option<u32>,
    /// 0-RTT: a client sends stream data in 0-RTT packets when a ticket allows it, a server
    /// accepts them (RFC 9001 section 4.6).
    pub zero_rtt: bool,
    /// A server drops a connection whose handshake is not confirmed this long after it began
    /// (`None`: only the idle timeout bounds it).
    pub handshake_timeout: Option<Duration>,
}

impl ConnConfig {
    pub fn new(transport: TransportConfig, migration: bool) -> ConnConfig {
        ConnConfig {
            transport,
            migration,
            key_update_interval: KEY_UPDATE_INTERVAL,
            ecn_io: true,
            preferred_address: (None, None),
            version: super::packet::VERSION_1,
            versions: vec![super::packet::VERSION_1, super::packet::VERSION_2],
            prefer_version: None,
            zero_rtt: false,
            handshake_timeout: None,
        }
    }

    /// Whether packets are sent ECN-marked (validation permitting).
    fn ecn(&self) -> bool {
        self.transport.ecn && self.ecn_io
    }
}

/// A NEW_TOKEN token a client keeps for later connections, with the QUIC version of the
/// connection it came on: it is presented only by a connection starting in that version
/// (RFC 9369 section 5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientToken {
    pub version: u32,
    pub data: Vec<u8>,
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

/// A server's pending compatible version negotiation (RFC 9368 section 4).
struct Compat {
    /// The version to switch to.
    to: u32,
    tls: akio_tls::ServerConfig,
    params: TransportParams,
    early_ctx: Option<Vec<u8>>,
    /// The Initial CRYPTO stream received so far.
    hello: Vec<u8>,
}

/// The most of a ClientHello held back for compatible version negotiation.
const MAX_COMPAT_HELLO: usize = 16 * 1024;

/// A QUIC connection.
pub struct Connection {
    side: Side,
    cfg: ConnConfig,
    keys: Arc<EndpointKeys>,
    rng: ChaChaRng,
    state: State,
    tls: QuicTls,
    /// What wakes the connection when its TLS handshake can go on after a suspension (an
    /// asynchronous anti-replay store, ADR-062).
    tls_waker: Option<Arc<dyn Fn() + Send + Sync>>,
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
    dlv: Delivery,
    pacer: Pacer,
    bytes_in_flight: u64,
    /// The sender last stopped for lack of data, not because of the congestion window (the
    /// window does not grow then, RFC 9002 section 7.8).
    app_limited: bool,
    pto_count: u32,
    first_rtt_sample: Option<Instant>,
    mtu: u16,
    mtu_probe: Option<(u16, u8)>,
    mtu_upper: u16,
    mtu_in_flight: Option<u64>,
    // Streams and flow control.
    pub(crate) streams: IdMap<StreamState>,
    send_queue: VecDeque<u64>,
    next_local: [u64; 2],
    peer_max_streams: [u64; 2],
    peer_opened: [u64; 2],
    local_max_streams: [u64; 2],
    /// The MAX_STREAMS values the peer last got.
    local_advertised: [u64; 2],
    local_closed: [u64; 2],
    streams_blocked: [bool; 2],
    tx_max_data: u64,
    tx_data: u64,
    /// Stream bytes sent and not acknowledged (bounded by `TransportConfig::send_window`).
    pub(crate) stream_unacked: u64,
    /// New stream data waits for the send window.
    window_blocked: bool,
    /// Stream bytes held in send buffers (written, not acknowledged from the front), on all
    /// streams; bounded by `TransportConfig::send_buffer`.
    pub(crate) send_held: u64,
    /// Streams waiting for room in their send buffer (`Event::StreamWritable`).
    pub(crate) writable_wait: Vec<u64>,
    rx_max_data: u64,
    rx_data: u64,
    rx_delivered: u64,
    pending: PendingCtl,
    // Datagrams.
    dgram_queue: VecDeque<Bytes>,
    dgram_queued_bytes: usize,
    // Timers and bookkeeping.
    idle_deadline: Option<Instant>,
    /// Server: the handshake must be confirmed by then (`ConnConfig::handshake_timeout`).
    handshake_deadline: Option<Instant>,
    last_rx: Instant,
    eliciting_since_rx: bool,
    last_eliciting_sent_any: Option<Instant>,
    pacing_until: Option<Instant>,
    /// Packets that arrived before their keys: sender, ECN codepoint, packet.
    buffered: Vec<(SocketAddr, u8, crate::bytes::PktBuf)>,
    /// ECN state of the current path.
    ecn: Ecn,
    /// The ECN codepoint of the datagram being processed.
    rx_ecn: u8,
    /// The ECN marking decided for the datagrams being written.
    tx_ecn: bool,
    /// A path being probed for an active migration (client).
    probe: Option<migrate::Probe>,
    /// The connection moved to the server's preferred address.
    on_preferred: bool,
    /// Remote connection IDs used to answer probes from other peer addresses (RFC 9000 9.5).
    path_cids: Vec<(SocketAddr, u64)>,
    /// The QUIC version of the long headers and keys.
    version: u32,
    /// What a client needs to start over in another version after Version Negotiation (once).
    restart_with: Option<(akio_tls::ClientConfig, String)>,
    /// The version a client gave up after Version Negotiation (downgrade check).
    vn_from: Option<u32>,
    /// The version of the client's first flight, when compatible version negotiation moved
    /// the connection to `version` (RFC 9368 section 4): the client's 0-RTT packets stay in
    /// it, and a server still reads the client's Initial packets in it.
    orig_version: Option<u32>,
    /// The Initial keys of `orig_version` (server: until the Initial space goes; client: while
    /// a packet of the new version is tried).
    orig_initial: Option<Keys>,
    /// A server that may switch versions: the client's first ClientHello, held back from TLS
    /// until it is complete, and what is needed to start TLS again in the other version.
    compat: Option<Box<Compat>>,
    /// Frame lists of acknowledged or lost packets, reused for new packets.
    spare_frames: Vec<Vec<SentFrame>>,
    /// The list an acknowledgment collects its packets in, kept for the next one.
    acked_scratch: Vec<(u64, Sent)>,
    /// 0-RTT packet protection: the client's write keys, the server's read keys.
    zero_rtt: Option<DirKeys>,
    /// The server's transport parameters remembered with the ticket (client, 0-RTT).
    remembered: Option<TransportParams>,
    /// The last packet number sent in a 0-RTT packet (client) or a 0.5-RTT one (server).
    zero_rtt_last_pn: Option<u64>,
    /// The packet being processed is a 0-RTT packet (server).
    rx_early: bool,
    /// The 1-RTT read keys are in place (a server answering 0-RTT writes 1-RTT packets
    /// first, RFC 9001 section 4.1.1's 0.5-RTT data).
    one_rtt_read: bool,
    /// The datagram being processed was buffered until its keys arrived.
    rx_late: bool,
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
            CcConfig::Bbr => CcKind::Bbr,
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
            tls_waker: None,
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
            cc: Congestion::new(kind, mtu, t.initial_rtt),
            dlv: Delivery::new(now),
            pacer: Pacer::new(),
            bytes_in_flight: 0,
            app_limited: true,
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
            streams: IdMap::default(),
            send_queue: VecDeque::new(),
            next_local: [0, 0],
            peer_max_streams: [0, 0],
            peer_opened: [0, 0],
            local_max_streams,
            local_advertised: local_max_streams,
            local_closed: [0, 0],
            streams_blocked: [false, false],
            tx_max_data: 0,
            tx_data: 0,
            stream_unacked: 0,
            window_blocked: false,
            send_held: 0,
            writable_wait: Vec::new(),
            rx_max_data,
            rx_data: 0,
            rx_delivered: 0,
            pending: PendingCtl::default(),
            dgram_queue: VecDeque::new(),
            dgram_queued_bytes: 0,
            idle_deadline: None,
            handshake_deadline: match side {
                Side::Server => cfg.handshake_timeout.map(|t| now + t),
                Side::Client => None,
            },
            last_rx: now,
            eliciting_since_rx: false,
            last_eliciting_sent_any: None,
            pacing_until: None,
            buffered: Vec::new(),
            ecn: Ecn::new(cfg.ecn()),
            rx_ecn: 0,
            tx_ecn: false,
            probe: None,
            on_preferred: false,
            path_cids: Vec::new(),
            version: cfg.version,
            restart_with: None,
            vn_from: None,
            orig_version: None,
            orig_initial: None,
            compat: None,
            spare_frames: Vec::new(),
            acked_scratch: Vec::new(),
            zero_rtt: None,
            remembered: None,
            zero_rtt_last_pn: None,
            rx_early: false,
            one_rtt_read: false,
            rx_late: false,
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
            // The chosen version first among the available ones (RFC 9368).
            version_info: Some({
                let mut avail = vec![cfg.version];
                avail.extend(cfg.versions.iter().filter(|&&v| v != cfg.version));
                (cfg.version, avail)
            }),
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
        tls_cfg: &akio_tls::ClientConfig,
        server_name: &str,
        remote: SocketAddr,
        token: Option<ClientToken>,
    ) -> Result<Connection, crate::Error> {
        let local = ConnectionId::random(&mut rng, LOCAL_CID_LEN);
        let mut cfg = cfg;
        cfg.version = start_version(&cfg, tls_cfg, server_name, token.as_ref());
        let token = token
            .filter(|t| t.version == cfg.version)
            .map(|t| t.data)
            .unwrap_or_default();
        Connection::client_with(
            now,
            cfg,
            keys,
            rng,
            tls_cfg,
            server_name,
            remote,
            token,
            local,
        )
    }

    /// [`Connection::client`] with the source connection ID `local`.
    #[allow(clippy::too_many_arguments)]
    fn client_with(
        now: Instant,
        cfg: ConnConfig,
        keys: Arc<EndpointKeys>,
        mut rng: ChaChaRng,
        tls_cfg: &akio_tls::ClientConfig,
        server_name: &str,
        remote: SocketAddr,
        token: Vec<u8>,
        local: ConnectionId,
    ) -> Result<Connection, crate::Error> {
        let dcid = ConnectionId::random(&mut rng, 8);
        let mut params = Connection::local_params(&cfg);
        params.initial_scid = Some(local);
        params.disable_active_migration = false;
        // Only a ticket of the version we start in is offered (RFC 9369 section 5).
        let tls = QuicTls::client_versioned(
            tls_cfg,
            server_name,
            params.encode(),
            cfg.zero_rtt,
            cfg.version,
        )
        .map_err(|e| crate::Error::Connect(e.to_string()))?;
        // 0-RTT starts from the limits the server gave last time (RFC 9000 section 7.4.1).
        let remembered = tls
            .early_params()
            .and_then(|p| TransportParams::decode(p, true).ok())
            .map(|p| p.remembered());
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
        c.spaces[0].keys = Some(initial_keys(&dcid, true, c.version));
        if let Some(r) = remembered {
            c.peer_max_streams = [r.initial_max_streams_bidi, r.initial_max_streams_uni];
            c.tx_max_data = r.initial_max_data;
            c.peer = r.clone();
            c.remembered = Some(r);
        }
        c.retry_token = token;
        c.restart_with = Some((tls_cfg.clone(), server_name.to_string()));
        c.drain_tls(now);
        Ok(c)
    }

    /// Starts over in `version` after a Version Negotiation packet that does not list ours but
    /// lists that one (RFC 9000 section 6.2, incompatible negotiation of RFC 9368 section
    /// 2.1): a new handshake under the same source connection ID. Once per connection.
    pub(super) fn restart(&mut self, now: Instant, version: u32) -> bool {
        let Some((tls, name)) = self.restart_with.take() else {
            return false;
        };
        let mut cfg = self.cfg.clone();
        cfg.version = version;
        let mut seed = [0u8; 32];
        self.rng.fill(&mut seed);
        let local = self.local_cid();
        let Ok(mut c) = Connection::client_with(
            now,
            cfg,
            self.keys.clone(),
            ChaChaRng::from_seed(seed),
            &tls,
            &name,
            self.path.remote,
            Vec::new(),
            local,
        ) else {
            return false;
        };
        c.restart_with = None;
        c.vn_from = Some(self.version);
        // Streams opened already (0-RTT) carry over, their data all to be sent again.
        self.requeue_zero_rtt();
        c.streams = std::mem::take(&mut self.streams);
        c.send_queue = std::mem::take(&mut self.send_queue);
        c.next_local = self.next_local;
        c.tx_data = self.tx_data;
        c.send_held = self.send_held;
        c.writable_wait = std::mem::take(&mut self.writable_wait);
        for (id, s) in &mut c.streams {
            s.queued = false;
            if let Some(snd) = s.send.as_mut() {
                snd.max_data = initial_send_window(&c.peer, Side::Client, StreamId::from_raw(*id));
            }
        }
        for id in c.send_queue.clone() {
            if let Some(s) = c.streams.get_mut(&id) {
                s.queued = true;
            }
        }
        c.events = std::mem::take(&mut self.events);
        c.ep_events = std::mem::take(&mut self.ep_events);
        c.stats = self.stats;
        *self = c;
        true
    }

    /// The QUIC version in use.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The version the client started in, when compatible version negotiation moved the
    /// connection to another one.
    #[cfg(test)]
    pub(crate) fn orig_version(&self) -> Option<u32> {
        self.orig_version
    }

    /// The DCID the Initial keys come from: the client's first, or the Retry's source.
    fn initial_key_dcid(&self) -> ConnectionId {
        self.retry_scid.unwrap_or(self.orig_dcid)
    }

    /// Moves the connection to version `v`, compatible with the current one (RFC 9368
    /// section 2.3): new Initial keys, the old ones kept to read the client's late Initials.
    fn switch_version(&mut self, v: u32) {
        let dcid = self.initial_key_dcid();
        let keys = initial_keys(&dcid, self.side == Side::Client, v);
        self.orig_initial = self.spaces[0].keys.replace(keys);
        self.orig_version = Some(self.version);
        self.version = v;
        self.cfg.version = v;
        // Tickets from now on belong to the negotiated version (RFC 9369 section 5).
        self.tls.set_ticket_version(v);
    }

    /// Undoes a client's [`switch_version`](Self::switch_version) for a packet of the new
    /// version that did not decrypt.
    fn unswitch_version(&mut self) {
        if let Some(v) = self.orig_version.take() {
            self.version = v;
            self.cfg.version = v;
            self.spaces[0].keys = self.orig_initial.take();
            self.tls.set_ticket_version(v);
        }
    }

    /// A server choosing whether to switch versions: holds the Initial CRYPTO stream back
    /// until the ClientHello is complete, then reads the client's version_information and, if
    /// it lists the preferred version as available, switches to it and starts TLS again with
    /// that version chosen in our transport parameters. Returns what TLS gets now.
    fn compat_hold(&mut self, chunk: &[u8]) -> Option<Vec<u8>> {
        let c = self.compat.as_mut()?;
        c.hello.extend_from_slice(chunk);
        let need = akio_tls::quic::client_hello_len(&c.hello)?;
        if c.hello.len() < need && c.hello.len() <= MAX_COMPAT_HELLO {
            return None;
        }
        let mut c = self.compat.take()?;
        let avail = akio_tls::quic::client_hello_transport_params(&c.hello)
            .and_then(|raw| TransportParams::decode(raw, false).ok())
            .and_then(|p| p.version_info);
        if let Some((chosen, avail)) = avail {
            if chosen == self.version && avail.contains(&c.to) {
                let from = self.version;
                let mut list = vec![c.to];
                list.extend(self.cfg.versions.iter().filter(|&&v| v != c.to));
                c.params.version_info = Some((c.to, list));
                // The client's ticket was issued in the version it started in; the ones we
                // issue belong to the negotiated version (RFC 9369 section 5).
                self.tls =
                    QuicTls::server_versioned(&c.tls, c.params.encode(), c.early_ctx.take(), from);
                if let Some(w) = &self.tls_waker {
                    self.tls.set_waker(w.clone());
                }
                self.switch_version(c.to);
            }
        }
        Some(std::mem::take(&mut c.hello))
    }

    /// A server connection for a client's first Initial.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn server(
        now: Instant,
        cfg: ConnConfig,
        keys: Arc<EndpointKeys>,
        mut rng: ChaChaRng,
        tls_cfg: &akio_tls::ServerConfig,
        remote: SocketAddr,
        initial_dcid: ConnectionId,
        client_scid: ConnectionId,
        orig_dcid: ConnectionId,
        retry_scid: Option<ConnectionId>,
        validated: bool,
        version: u32,
    ) -> Connection {
        let mut cfg = cfg;
        // The server answers in the client's version.
        cfg.version = version;
        let local = ConnectionId::random(&mut rng, LOCAL_CID_LEN);
        let mut params = Connection::local_params(&cfg);
        params.original_dcid = Some(orig_dcid);
        params.initial_scid = Some(local);
        params.retry_scid = retry_scid;
        params.stateless_reset_token = Some(reset_token(&keys.reset_key, &local));
        // The preferred address comes with connection ID sequence number 1.
        let preferred = match cfg.preferred_address {
            (None, None) => None,
            (v4, v6) => {
                let cid = ConnectionId::random(&mut rng, LOCAL_CID_LEN);
                params.preferred_address = Some(super::params::PreferredAddress {
                    v4,
                    v6,
                    cid,
                    token: reset_token(&keys.reset_key, &cid),
                });
                Some(cid)
            }
        };
        // 0-RTT is accepted with tickets issued under the same limits (RFC 9001 section 4.6.2).
        let early_ctx = cfg.zero_rtt.then(|| params.remembered().encode());
        let compat = cfg
            .prefer_version
            .filter(|&v| v != version && supported(v) && cfg.versions.contains(&v))
            .map(|to| {
                Box::new(Compat {
                    to,
                    tls: tls_cfg.clone(),
                    params: params.clone(),
                    early_ctx: early_ctx.clone(),
                    hello: Vec::new(),
                })
            });
        // Tickets are bound to the version (RFC 9369 section 5).
        let tls = QuicTls::server_versioned(tls_cfg, params.encode(), early_ctx, version);
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
        c.spaces[0].keys = Some(initial_keys(&initial_dcid, false, version));
        c.compat = compat;
        c.peer_initial_scid = Some(client_scid);
        c.retry_scid = retry_scid;
        c.path.validated = validated;
        if let Some(cid) = preferred {
            c.local_cids.insert(1, cid);
            c.next_local_seq = 2;
            c.ep_events.push_back(EndpointEvent::NewCid(cid));
        }
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

    pub fn peer_certificates(&self) -> Option<Vec<Vec<u8>>> {
        (!self.is_handshaking()).then(|| self.tls.peer_certificates().to_vec())
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

    #[cfg(test)]
    pub(crate) fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    /// What happened to 0-RTT.
    pub fn early_data(&self) -> EarlyData {
        self.tls.early_data()
    }

    pub fn stats(&self) -> ConnectionStats {
        let mut s = self.stats;
        s.rtt = self.rtt.smoothed;
        s.min_rtt = self.rtt.min;
        s.cwnd = self.cc.window;
        s.congestion_events = self.cc.events;
        s.current_mtu = self.mtu;
        s.ecn_capable = self.ecn.phase == ecn::Phase::Capable;
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

    /// The congestion controller's state, for traces.
    #[cfg(test)]
    pub(crate) fn cc_debug(&self) -> String {
        match self.cc.bbr() {
            Some(b) => format!(
                "{:?} bw {:.0} cwnd {} pacing {} hi {} inflight {}",
                b.mode,
                b.bandwidth(),
                b.cwnd,
                b.pacing_rate(),
                b.inflight_hi,
                self.bytes_in_flight
            ),
            None => format!("cwnd {} inflight {}", self.cc.window, self.bytes_in_flight),
        }
    }

    #[cfg(test)]
    pub(crate) fn key_phase(&self) -> Option<bool> {
        self.one_rtt.as_ref().map(|k| k.phase)
    }

    // ---- TLS ----

    /// Sets what to call, from any thread, when the TLS handshake can go on after waiting
    /// for an asynchronous anti-replay answer; the connection is then driven
    /// ([`poll_transmit`](Self::poll_transmit) takes the handshake up again).
    pub fn set_tls_waker(&mut self, w: Arc<dyn Fn() + Send + Sync>) {
        self.tls.set_waker(w.clone());
        self.tls_waker = Some(w);
    }

    /// Takes a suspended TLS handshake up again once its anti-replay answer is in.
    pub(crate) fn resume_tls(&mut self, now: Instant) {
        if !self.tls.suspended() {
            return;
        }
        match self.tls.resume() {
            Ok(true) => {
                self.drain_tls(now);
                // 0-RTT packets that came meanwhile waited for the keys just installed.
                self.replay_buffered(now);
            }
            Ok(false) => {}
            Err(e) => self.close_transport(
                now,
                TransportError::new(
                    code::CRYPTO_ERROR + u64::from(e.alert.code()),
                    e.to_string(),
                ),
            ),
        }
    }

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
            Level::EarlyData => {
                // One direction only: the client writes 0-RTT packets, the server reads them.
                if let Some(TlsKeys::Tls13 { suite, secret }) = read.or(write) {
                    // In the client's first version (RFC 9369 section 4.1).
                    let v = self.orig_version.unwrap_or(self.version);
                    self.zero_rtt = Some(DirKeys::from_secret(suite, &secret, v));
                    self.replay = !self.buffered.is_empty();
                }
                return;
            }
            Level::Initial => return,
        };
        if read.is_some() {
            slot.0 = read;
        }
        if write.is_some() {
            slot.1 = write;
        }
        if l == Level::Application && self.side == Side::Server && self.tls.early_data_accepted() {
            // Accepted 0-RTT is answered right away: write 1-RTT before the client's Finished
            // brings the read keys (until then 1-RTT packets wait, as without keys).
            if let Some(TlsKeys::Tls13 { suite, secret }) = slot.1.take() {
                self.one_rtt = Some(OneRtt::new(suite, secret.clone(), secret, self.version));
            }
            if let (Some(TlsKeys::Tls13 { secret, .. }), Some(k)) =
                (slot.0.take(), self.one_rtt.as_mut())
            {
                k.set_remote(secret);
                self.one_rtt_read = true;
                self.replay = !self.buffered.is_empty();
            }
            return;
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
                    local: DirKeys::from_secret(suite, &ws, self.version),
                    remote: DirKeys::from_secret(suite, &rs, self.version),
                });
            }
            _ => {
                self.one_rtt = Some(OneRtt::new(suite, ws, rs, self.version));
                self.one_rtt_read = true;
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
        if self.side == Side::Client {
            // 1-RTT from now on (RFC 9001 section 4.6.1); rejected 0-RTT data goes again.
            self.zero_rtt = None;
            if self.tls.early_data() == EarlyData::Rejected {
                self.requeue_zero_rtt();
            }
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
        self.handshake_deadline = None;
        // The server has the client's Finished: 0-RTT is over (late packets are lost and come
        // again in 1-RTT).
        self.zero_rtt = None;
        self.discard_space(now, SpaceId::Handshake);
        self.ep_events.push_back(EndpointEvent::HandshakeDone);
        self.issue_cids();
        if self.mtu_upper > self.mtu {
            self.mtu_probe = Some((self.next_probe_size(), 0));
        }
        self.try_start_probe(now);
    }

    fn new_token(&mut self) -> Bytes {
        let mut plain = Vec::with_capacity(32);
        plain.extend_from_slice(&unix_secs().to_be_bytes());
        // Issued in the negotiated version, valid only for connections starting in it
        // (RFC 9369 section 5).
        plain.extend_from_slice(&self.version.to_be_bytes());
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
        // Version negotiation (RFC 9368 section 4): the chosen version is the one in use (the
        // client's: the one it started in, before a compatible switch), and a server that
        // lists the version a client gave up after Version Negotiation did not send that
        // Version Negotiation packet (a downgrade).
        if let Some((chosen, avail)) = &p.version_info {
            let verr = |r: &str| TransportError::new(code::VERSION_NEGOTIATION_ERROR, r);
            let expect = match self.side {
                Side::Server => self.orig_version.unwrap_or(self.version),
                Side::Client => self.version,
            };
            if *chosen != expect {
                return Err(verr("version_information chosen version mismatch"));
            }
            if self.vn_from.is_some_and(|v| avail.contains(&v)) {
                return Err(verr("version downgrade"));
            }
        }
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
            // The preferred address's connection ID is sequence number 1 (RFC 9000 5.1.1).
            if let Some(pa) = &p.preferred_address {
                self.remote_cids.insert(
                    1,
                    RemoteCid {
                        cid: pa.cid,
                        token: Some(pa.token),
                    },
                );
            }
        }
        // Accepted 0-RTT: the server may not lower what the client used (RFC 9000 7.4.1).
        if let Some(r) = &self.remembered {
            if self.tls.early_data() == EarlyData::Accepted && !p.keeps_limits_of(r) {
                return Err(TransportError::new(
                    code::PROTOCOL_VIOLATION,
                    "0-RTT accepted with lower transport parameters",
                ));
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

    pub(crate) fn remote_cid(&self) -> ConnectionId {
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
            .any(|r| r.token.is_some_and(|t| akio_crypto::ct_eq(&t, tail)))
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
        self.stream_unacked = 0;
        self.send_held = 0;
        self.writable_wait.clear();
        self.buffered.clear();
    }

    /// The 0-RTT packets sent (client) are gone: rejected by the server, discarded after a
    /// Retry or a Version Negotiation. Their data goes again (in 0-RTT after a Retry, else in
    /// 1-RTT); they are not losses for congestion control.
    pub(super) fn requeue_zero_rtt(&mut self) {
        let Some(last) = self.zero_rtt_last_pn.take() else {
            return;
        };
        let pns: Vec<u64> = self.spaces[2].sent.up_to(last).map(|(pn, _)| pn).collect();
        for pn in pns {
            let Some(mut p) = self.spaces[2].sent.remove(pn) else {
                continue;
            };
            if p.in_flight {
                self.bytes_in_flight = self.bytes_in_flight.saturating_sub(u64::from(p.size));
                if p.ack_eliciting {
                    let sp = &mut self.spaces[2];
                    sp.eliciting_in_flight = sp.eliciting_in_flight.saturating_sub(1);
                }
            }
            for f in std::mem::take(&mut p.frames) {
                self.on_frame_lost(SpaceId::Data, f);
            }
        }
    }

    /// Discards a packet number space's keys and state (RFC 9002 section 6.4).
    fn discard_space(&mut self, _now: Instant, id: SpaceId) {
        let s = &mut self.spaces[id as usize];
        if s.discarded {
            return;
        }
        s.discarded = true;
        s.keys = None;
        if id == SpaceId::Initial {
            self.orig_initial = None;
        }
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
        min(self.handshake_deadline);
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
        min(self.probe_timeout());
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
        if self.handshake_deadline.is_some_and(|d| now >= d) {
            // Dropped without a word, as an idle connection is: a client that is still there
            // starts over (or gives up on its own timeout).
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
        if self.probe_timeout().is_some_and(|d| now >= d) {
            self.on_probe_timer(now);
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

/// The version a client starts in: the one its newest session ticket for `server_name` was
/// issued in, else its token's, else the configured one, as long as it speaks it. Tickets
/// and tokens are bound to the version of the connection that issued them, and one moved
/// to another version by compatible negotiation got them in that version (RFC 9369 section
/// 5): starting there lets them be used, and the server would move it there again anyway.
fn start_version(
    cfg: &ConnConfig,
    tls: &akio_tls::ClientConfig,
    server_name: &str,
    token: Option<&ClientToken>,
) -> u32 {
    let usable = |v: &u32| supported(*v) && cfg.versions.contains(v);
    akio_tls::quic::ticket_version(tls, server_name)
        .filter(usable)
        .or_else(|| token.map(|t| t.version).filter(usable))
        .unwrap_or(cfg.version)
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
