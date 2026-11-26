//! This crate's own QUIC types: stream ids, connection errors, statistics and configuration.

use std::collections::HashMap;
use std::fmt;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::Error;

/// Which side opened a stream or a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    /// The side that dialed.
    Client,
    /// The side that accepted.
    Server,
}

/// Whether a stream carries data both ways or one way.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Dir {
    /// Bidirectional.
    Bi,
    /// Unidirectional (from the side that opened it).
    Uni,
}

/// A stream id (RFC 9000 section 2.1): who opened it, its direction and its index.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(u64);

impl StreamId {
    /// The `index`-th stream of direction `dir` opened by `initiator`.
    pub fn new(initiator: Side, dir: Dir, index: u64) -> StreamId {
        let side = match initiator {
            Side::Client => 0,
            Side::Server => 1,
        };
        let d = match dir {
            Dir::Bi => 0,
            Dir::Uni => 2,
        };
        StreamId((index << 2) | d | side)
    }

    /// The side that opened the stream.
    pub fn initiator(self) -> Side {
        if self.0 & 1 == 0 {
            Side::Client
        } else {
            Side::Server
        }
    }

    /// The stream's direction.
    pub fn dir(self) -> Dir {
        if self.0 & 2 == 0 { Dir::Bi } else { Dir::Uni }
    }

    /// The stream's index among those of its initiator and direction.
    pub fn index(self) -> u64 {
        self.0 >> 2
    }

    /// The id with this wire value.
    pub(crate) fn from_raw(v: u64) -> StreamId {
        StreamId(v)
    }
}

impl From<StreamId> for u64 {
    /// The id as sent on the wire.
    fn from(id: StreamId) -> u64 {
        id.0
    }
}

impl fmt::Debug for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StreamId({:?} {:?} {})",
            self.initiator(),
            self.dir(),
            self.index()
        )
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Why a connection ended.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionError {
    /// The peer does not implement a supported QUIC version.
    VersionMismatch,
    /// The peer violated the protocol (a transport error code, RFC 9000 section 20.1).
    TransportError {
        /// The transport error code.
        code: u64,
        /// What went wrong.
        reason: String,
    },
    /// The peer's QUIC stack closed the connection with a transport error code.
    ConnectionClosed {
        /// The transport error code.
        code: u64,
        /// The peer's reason phrase.
        reason: Vec<u8>,
    },
    /// The peer's application closed the connection.
    ApplicationClosed {
        /// The application's error code.
        code: u64,
        /// The peer's reason phrase.
        reason: Vec<u8>,
    },
    /// The peer reset the connection (stateless reset), usually after restarting.
    Reset,
    /// Nothing heard from the peer for longer than the idle timeout, or the socket failed.
    TimedOut,
    /// This side closed the connection.
    LocallyClosed,
    /// Not enough connection ids were available.
    CidsExhausted,
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionError::VersionMismatch => f.write_str("peer supports no common version"),
            ConnectionError::TransportError { code, reason } => {
                write!(f, "transport error {code:#x}: {reason}")
            }
            ConnectionError::ConnectionClosed { code, reason } => write!(
                f,
                "aborted by peer: error {code:#x}: {}",
                String::from_utf8_lossy(reason)
            ),
            ConnectionError::ApplicationClosed { code, reason } => write!(
                f,
                "closed by peer: error {code}: {}",
                String::from_utf8_lossy(reason)
            ),
            ConnectionError::Reset => f.write_str("reset by peer"),
            ConnectionError::TimedOut => f.write_str("timed out"),
            ConnectionError::LocallyClosed => f.write_str("closed"),
            ConnectionError::CidsExhausted => f.write_str("connection ids exhausted"),
        }
    }
}

impl std::error::Error for ConnectionError {}

/// Datagram counters of one direction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct UdpStats {
    /// UDP datagrams.
    pub datagrams: u64,
    /// Bytes in them.
    pub bytes: u64,
    /// I/O calls (several datagrams may go out in one with GSO).
    pub ios: u64,
}

/// Statistics of a connection; see [`Connection::stats`](crate::Connection::stats).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConnectionStats {
    /// Datagrams sent.
    pub udp_tx: UdpStats,
    /// Datagrams received.
    pub udp_rx: UdpStats,
    /// Smoothed round-trip time.
    pub rtt: Duration,
    /// Smallest round-trip time seen.
    pub min_rtt: Duration,
    /// Congestion window, in bytes.
    pub cwnd: u64,
    /// Congestion events.
    pub congestion_events: u64,
    /// Packets sent.
    pub sent_packets: u64,
    /// Packets declared lost.
    pub lost_packets: u64,
    /// Bytes declared lost.
    pub lost_bytes: u64,
    /// The path MTU in use.
    pub current_mtu: u16,
    /// The path passed ECN validation and packets are sent ECT(0) (see
    /// [`TransportConfig::ecn`]).
    pub ecn_capable: bool,
    /// Congestion events signalled by ECN-CE marks the peer reported.
    pub ecn_ce_events: u64,
}

/// A QUIC version.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Version {
    /// QUIC version 1 (RFC 9000), the default.
    #[default]
    V1,
    /// QUIC version 2 (RFC 9369): version 1 with other wire constants (salts, labels, packet
    /// type bits), against ossification.
    V2,
}

impl Version {
    /// The version number on the wire.
    pub fn wire(self) -> u32 {
        match self {
            Version::V1 => crate::proto::packet::VERSION_1,
            Version::V2 => crate::proto::packet::VERSION_2,
        }
    }

    pub(crate) fn from_wire(v: u32) -> Version {
        if v == crate::proto::packet::VERSION_2 {
            Version::V2
        } else {
            Version::V1
        }
    }
}

/// The congestion controller of a connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Congestion {
    /// CUBIC (RFC 9438), the default.
    #[default]
    Cubic,
    /// NewReno (RFC 9002).
    NewReno,
    /// BBR (experimental): paces at the estimated bottleneck bandwidth with a window of about
    /// two bandwidth-delay products, instead of backing off on every loss; BBRv1's model and
    /// state machine with the loss and ECN bound of BBRv2/v3 (a round losing more than 2%
    /// caps the data in flight).
    Bbr,
}

/// Transport parameters and limits of connections. Start from `Default::default()` and set
/// fields.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TransportConfig {
    /// Bidirectional streams the peer may have open at once (default 100).
    pub max_concurrent_bidi_streams: u32,
    /// Unidirectional streams the peer may have open at once (default 100).
    pub max_concurrent_uni_streams: u32,
    /// Closes a connection idle this long (default 30 s; `None` never; the smaller of both
    /// sides' values applies).
    pub max_idle_timeout: Option<Duration>,
    /// Sends keep-alive packets this often (default `None`); set it below the idle timeout to
    /// keep quiet connections open.
    pub keep_alive_interval: Option<Duration>,
    /// Bytes the peer may send on one stream ahead of the application reading them (default
    /// 1.25 MB).
    pub stream_receive_window: u64,
    /// Bytes the peer may send on all streams together ahead of the application (default
    /// 10 MB, eight times `stream_receive_window`; `None` lifts the limit).
    pub receive_window: Option<u64>,
    /// Bytes sent but not yet acknowledged, on all streams (default 10 MB).
    pub send_window: u64,
    /// Bytes one stream holds for sending: written and not yet acknowledged (default 16 MiB,
    /// the same as `send_buffer`, so one bulk stream can use the whole connection buffer).
    /// While a stream holds this much, [`Connection::send`](crate::Connection::send) fails with
    /// [`Error::Overloaded`](crate::Error::Overloaded) and
    /// [`QuicHandler::on_stream_writable`](crate::QuicHandler::on_stream_writable) follows once
    /// it is down to three quarters; a write accepted below the limit may pass it, so a stream
    /// holds at most the limit plus one write. `u64::MAX` lifts the limit.
    pub stream_send_buffer: u64,
    /// Bytes all streams of a connection hold for sending together, as `stream_send_buffer`
    /// does for one (default 16 MiB, above `send_window` so a full window can be in flight
    /// with data waiting behind it). `u64::MAX` lifts the limit.
    pub send_buffer: u64,
    /// Round-trip time assumed before it is measured (default 333 ms).
    pub initial_rtt: Duration,
    /// UDP payload size used before path MTU discovery (default 1200, the minimum).
    pub initial_mtu: u16,
    /// Path MTU discovery (default on).
    pub mtu_discovery: bool,
    /// Bytes of received unreliable datagrams buffered for the application; `None` refuses
    /// datagrams (default 1.25 MB).
    pub datagram_receive_buffer_size: Option<usize>,
    /// Bytes of outgoing unreliable datagrams buffered (default 1 MiB).
    pub datagram_send_buffer_size: usize,
    /// The congestion controller (default CUBIC).
    pub congestion: Congestion,
    /// Explicit Congestion Notification (RFC 9000 section 13.4; default on): packets are sent
    /// ECT(0) where the platform can set the codepoint (Linux), the path and the peer are
    /// validated with the first packets and the ACK_ECN counts, and CE marks are congestion
    /// signals like losses. A path that fails validation (bleaching or dropping marked packets,
    /// wrong counts) falls back to unmarked packets. Received codepoints are always reported.
    pub ecn: bool,
}

const STREAM_RWND: u64 = 12_500 * 100;

impl Default for TransportConfig {
    fn default() -> Self {
        TransportConfig {
            max_concurrent_bidi_streams: 100,
            max_concurrent_uni_streams: 100,
            max_idle_timeout: Some(Duration::from_secs(30)),
            keep_alive_interval: None,
            stream_receive_window: STREAM_RWND,
            receive_window: Some(8 * STREAM_RWND),
            send_window: 8 * STREAM_RWND,
            stream_send_buffer: 16 << 20,
            send_buffer: 16 << 20,
            initial_rtt: Duration::from_millis(333),
            initial_mtu: 1200,
            mtu_discovery: true,
            datagram_receive_buffer_size: Some(STREAM_RWND as usize),
            datagram_send_buffer_size: 1024 * 1024,
            congestion: Congestion::Cubic,
            ecn: true,
        }
    }
}

// ---- endpoint configurations ----

/// Address-validation tokens (NEW_TOKEN) a client keeps per server name for later
/// connections, each with the QUIC version it was issued in.
pub(crate) type TokenStore = Arc<Mutex<HashMap<String, crate::proto::ClientToken>>>;

/// A QUIC server configuration: TLS (see [`server_config`](crate::server_config)) plus
/// transport settings. Cheap to clone.
#[derive(Clone)]
pub struct ServerConfig(pub(crate) ServerInner);

#[derive(Clone)]
pub(crate) struct ServerInner {
    pub(crate) tls: akio_tls::ServerConfig,
    pub(crate) transport: TransportConfig,
    pub(crate) migration: bool,
    pub(crate) retry: bool,
    pub(crate) key_update: Option<u64>,
    pub(crate) preferred: (Option<SocketAddrV4>, Option<SocketAddrV6>),
    pub(crate) versions: Vec<u32>,
    pub(crate) prefer_version: Option<u32>,
    pub(crate) zero_rtt: bool,
    pub(crate) max_connections: usize,
    pub(crate) max_handshakes: usize,
    pub(crate) handshake_timeout: Option<Duration>,
}

/// Connections a server endpoint holds at once by default (see
/// [`ServerConfig::max_connections`]).
pub const DEFAULT_MAX_CONNECTIONS: usize = 10_000;

/// Handshakes a server endpoint has in progress at once by default (see
/// [`ServerConfig::max_handshakes`]): clients prove their address with a Retry from half of it
/// on.
pub const DEFAULT_MAX_HANDSHAKES: usize = 8192;

/// How long a client's handshake may take by default (see
/// [`ServerConfig::handshake_timeout`]).
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig").finish_non_exhaustive()
    }
}

impl ServerConfig {
    pub(crate) fn new(tls: akio_tls::ServerConfig) -> ServerConfig {
        ServerConfig(ServerInner {
            tls,
            transport: TransportConfig::default(),
            migration: true,
            retry: false,
            key_update: None,
            preferred: (None, None),
            versions: vec![Version::V1.wire(), Version::V2.wire()],
            prefer_version: None,
            zero_rtt: false,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_handshakes: DEFAULT_MAX_HANDSHAKES,
            handshake_timeout: Some(DEFAULT_HANDSHAKE_TIMEOUT),
        })
    }

    /// Connections the server holds at once, handshaking, open or closing (default 10,000;
    /// `usize::MAX` lifts the limit). A client starting a connection beyond it is refused at
    /// once with `CONNECTION_REFUSED` in an Initial packet (RFC 9000 section 5.2.2), without any
    /// state kept for it; these answers are rate limited like stateless resets. A clone of the
    /// [`QuicServer`](crate::QuicServer) serving several listeners shares the limit.
    #[must_use]
    pub fn max_connections(mut self, n: usize) -> Self {
        self.0.max_connections = n;
        self
    }

    /// Handshakes the server has in progress at once (default 8,192; `usize::MAX` lifts the
    /// limit; 0 is taken as 1): a connection counts from a client's first Initial until its
    /// handshake completes or it goes. From half of them on, a client whose Initial carries no
    /// valid token (a Retry's, or a NEW_TOKEN one from an earlier connection) is answered with
    /// a Retry instead, keeping no state, so that Initials from forged addresses, which cost
    /// their sender nothing, hold at most half; a client that answers its Retry gets one of the
    /// rest. At the limit, a new client's Initial is dropped unanswered, with nothing kept:
    /// the client sends it again and gets in once a handshake is over (counted by
    /// [`QuicServer::refused_connections`](crate::QuicServer::refused_connections)). A clone
    /// of the [`QuicServer`](crate::QuicServer) serving several listeners shares the count.
    #[must_use]
    pub fn max_handshakes(mut self, n: usize) -> Self {
        self.0.max_handshakes = n.max(1);
        self
    }

    /// How long a client's handshake may take, from its first Initial to the handshake's
    /// completion (default 10 s; `None`: only the idle timeout bounds it). A connection whose
    /// handshake is not done by then is dropped without a word (no `CONNECTION_CLOSE`), as an
    /// idle one is, and its handler's `on_close` gets [`ConnectionError::TimedOut`]; its place
    /// among [`max_handshakes`](Self::max_handshakes) is free again. A client that answered a
    /// Retry starts its count over with the connection the Retry led to.
    #[must_use]
    pub fn handshake_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.0.handshake_timeout = timeout;
        self
    }

    /// Accepts 0-RTT (RFC 9001 section 4.6; default off): clients resuming with a ticket from
    /// this server may send stream data in their first flight, saving a round trip. Tickets
    /// issued from then on allow it (0xffffffff bytes, as QUIC requires), and 0-RTT is
    /// accepted only under the same transport limits as when the ticket was issued.
    ///
    /// **0-RTT data can be replayed** by an attacker who recorded it, and it is processed
    /// before the handshake completes. Replays of a ClientHello are refused within this server
    /// (the TLS layer keeps a bounded record of recent ClientHellos and a 10-second freshness
    /// window; see `akio_tls::ServerConfigBuilder::early_data`); servers sharing tickets
    /// share it through `akio_tls::ServerConfigBuilder::anti_replay_store`. Check
    /// [`Connection::is_early`](crate::Connection::is_early) and act only on requests safe to
    /// repeat.
    #[must_use]
    pub fn zero_rtt(mut self, yes: bool) -> Self {
        self.0.zero_rtt = yes;
        self
    }

    /// The QUIC versions accepted (default: 1 and 2); clients starting with another one get a
    /// Version Negotiation packet listing these. An empty list keeps the default.
    #[must_use]
    pub fn versions(mut self, versions: &[Version]) -> Self {
        if !versions.is_empty() {
            self.0.versions = versions.iter().map(|v| v.wire()).collect();
        }
        self
    }

    /// Moves clients that start in another version, and list `version` among the versions
    /// they support, to `version` within the handshake, without a round trip (compatible
    /// version negotiation, RFC 9368 section 4; versions 1 and 2 are compatible both ways).
    /// Default none: the server answers in the version the client started in. `version` must
    /// also be accepted (see [`versions`](Self::versions)), or this has no effect.
    ///
    /// The client's 0-RTT packets stay in its first version, the rest of the connection is in
    /// `version`; [`Connection::version`](crate::Connection::version) tells which one a
    /// connection ended up in. Clients of this crate, quic-go and other implementations of RFC
    /// 9368 follow the switch; clients that do not send the version_information transport
    /// parameter are never switched.
    #[must_use]
    pub fn prefer_version(mut self, version: Version) -> Self {
        self.0.prefer_version = Some(version.wire());
        self
    }

    /// Uses `transport` for every connection.
    #[must_use]
    pub fn transport(mut self, transport: &TransportConfig) -> Self {
        self.0.transport = transport.clone();
        self
    }

    /// Whether clients may migrate to a new address (default `true`).
    #[must_use]
    pub fn migration(mut self, yes: bool) -> Self {
        self.0.migration = yes;
        self
    }

    /// Offers `addr` as the server's preferred address (RFC 9000 section 9.6; call once per
    /// address family): clients may move their connections there with
    /// [`Connection::migrate`](crate::Connection::migrate). The server must serve it too:
    /// listen on it with a clone of the same [`QuicServer`](crate::QuicServer), so the
    /// connections are found whichever address their packets arrive at.
    #[must_use]
    pub fn preferred_address(mut self, addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(a) => self.0.preferred.0 = Some(a),
            SocketAddr::V6(a) => self.0.preferred.1 = Some(a),
        }
        self
    }

    /// Validates every client address with a Retry round trip before accepting it (default:
    /// from half of [`max_handshakes`](Self::max_handshakes) in progress on). Hidden: for tests
    /// and interop runs.
    #[doc(hidden)]
    #[must_use]
    pub fn retry(mut self, yes: bool) -> Self {
        self.0.retry = yes;
        self
    }

    /// Starts a 1-RTT key update every `packets` packets (default about four million).
    /// Hidden: for tests and interop runs.
    #[doc(hidden)]
    #[must_use]
    pub fn key_update_interval(mut self, packets: u64) -> Self {
        self.0.key_update = Some(packets.max(1));
        self
    }
}

/// A QUIC client configuration: TLS (see [`client_config`](crate::client_config)) plus
/// transport settings. Cheap to clone; clones share the address-validation tokens servers
/// hand out (NEW_TOKEN), which later connections to the same server name present.
#[derive(Clone)]
pub struct ClientConfig(pub(crate) ClientInner);

#[derive(Clone)]
pub(crate) struct ClientInner {
    pub(crate) tls: akio_tls::ClientConfig,
    pub(crate) transport: TransportConfig,
    pub(crate) tokens: TokenStore,
    pub(crate) key_update: Option<u64>,
    pub(crate) version: Version,
    pub(crate) zero_rtt: bool,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig").finish_non_exhaustive()
    }
}

impl ClientConfig {
    pub(crate) fn new(tls: akio_tls::ClientConfig) -> ClientConfig {
        ClientConfig(ClientInner {
            tls,
            transport: TransportConfig::default(),
            tokens: Arc::new(Mutex::new(HashMap::new())),
            key_update: None,
            version: Version::V1,
            zero_rtt: false,
        })
    }

    /// Sends 0-RTT data when resuming with a ticket that allows it (default off): streams
    /// open right after [`dial`](crate::dial), under the limits the server gave on the
    /// connection the ticket came from, and their data goes out with the first flight. If the
    /// server rejects 0-RTT, the data is sent again once the handshake completes;
    /// [`Connection::early_data`](crate::Connection::early_data) tells which happened.
    ///
    /// 0-RTT data can be **replayed** and is not forward secret: only send requests that are
    /// safe to repeat before the handshake completes.
    #[must_use]
    pub fn zero_rtt(mut self, yes: bool) -> Self {
        self.0.zero_rtt = yes;
        self
    }

    /// The QUIC version connections start with (default 1). A server that does not speak it
    /// answers with Version Negotiation and the connection starts over in the other version,
    /// once, guarded against downgrades by the version_information transport parameter
    /// (RFC 9368). A server preferring the other version may also move the connection to it
    /// within the handshake (compatible negotiation, RFC 9368 section 4), which the client
    /// follows.
    ///
    /// Session tickets and address-validation tokens belong to the version of the connection
    /// that issued them (RFC 9369 section 5): when this configuration holds one for the server
    /// name, the connection starts in its version instead, so it can be used (a server that
    /// moved the last connection to version 2 gets the next one in version 2 directly).
    #[must_use]
    pub fn version(mut self, version: Version) -> Self {
        self.0.version = version;
        self
    }

    /// Uses `transport` for connections dialed with this configuration.
    #[must_use]
    pub fn transport(mut self, transport: &TransportConfig) -> Self {
        self.0.transport = transport.clone();
        self
    }

    /// Starts a 1-RTT key update every `packets` packets (default about four million).
    /// Hidden: for tests and interop runs.
    #[doc(hidden)]
    #[must_use]
    pub fn key_update_interval(mut self, packets: u64) -> Self {
        self.0.key_update = Some(packets.max(1));
        self
    }
}

pub(crate) fn config_err(e: impl fmt::Display) -> Error {
    Error::Config(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_ids_round_trip() {
        for side in [Side::Client, Side::Server] {
            for dir in [Dir::Bi, Dir::Uni] {
                let id = StreamId::new(side, dir, 7);
                assert_eq!((id.initiator(), id.dir(), id.index()), (side, dir, 7));
                assert_eq!(StreamId::from_raw(u64::from(id)), id);
                assert_eq!(id.to_string(), u64::from(id).to_string());
            }
        }
        // RFC 9000 section 2.1: the two low bits.
        assert_eq!(u64::from(StreamId::new(Side::Client, Dir::Bi, 0)), 0);
        assert_eq!(u64::from(StreamId::new(Side::Server, Dir::Bi, 0)), 1);
        assert_eq!(u64::from(StreamId::new(Side::Client, Dir::Uni, 0)), 2);
        assert_eq!(u64::from(StreamId::new(Side::Server, Dir::Uni, 1)), 7);
        assert_eq!(
            format!("{:?}", StreamId::new(Side::Server, Dir::Uni, 3)),
            "StreamId(Server Uni 3)"
        );
    }

    #[test]
    fn errors_display() {
        for (e, s) in [
            (
                ConnectionError::VersionMismatch,
                "peer supports no common version",
            ),
            (ConnectionError::Reset, "reset by peer"),
            (ConnectionError::LocallyClosed, "closed"),
            (ConnectionError::TimedOut, "timed out"),
            (ConnectionError::CidsExhausted, "connection ids exhausted"),
        ] {
            assert_eq!(e.to_string(), s);
        }
        let e = ConnectionError::ApplicationClosed {
            code: 7,
            reason: b"bye".to_vec(),
        };
        assert_eq!(e.to_string(), "closed by peer: error 7: bye");
        let e = ConnectionError::ConnectionClosed {
            code: 10,
            reason: b"x".to_vec(),
        };
        assert_eq!(e.to_string(), "aborted by peer: error 0xa: x");
        let e = ConnectionError::TransportError {
            code: 1,
            reason: "bad".into(),
        };
        assert_eq!(e.to_string(), "transport error 0x1: bad");
        assert_eq!(ConnectionStats::default().udp_tx, UdpStats::default());
        assert_eq!(TransportConfig::default().congestion, Congestion::Cubic);
    }
}
