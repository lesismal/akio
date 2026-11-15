//! This crate's own QUIC types: stream ids, connection errors, statistics and configuration.

use std::collections::HashMap;
use std::fmt;
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

/// The congestion controller of a connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Congestion {
    /// CUBIC (RFC 9438), the default.
    #[default]
    Cubic,
    /// NewReno (RFC 9002).
    NewReno,
    /// BBR (experimental; runs CUBIC for now).
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
    /// `None`: unlimited).
    pub receive_window: Option<u64>,
    /// Bytes sent but not yet acknowledged, on all streams (default 10 MB).
    pub send_window: u64,
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
            receive_window: None,
            send_window: 8 * STREAM_RWND,
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
/// connections.
pub(crate) type TokenStore = Arc<Mutex<HashMap<String, Vec<u8>>>>;

/// A QUIC server configuration: TLS (see [`server_config`](crate::server_config)) plus
/// transport settings. Cheap to clone.
#[derive(Clone)]
pub struct ServerConfig(pub(crate) ServerInner);

#[derive(Clone)]
pub(crate) struct ServerInner {
    pub(crate) tls: only_tls::ServerConfig,
    pub(crate) transport: TransportConfig,
    pub(crate) migration: bool,
    pub(crate) retry: bool,
    pub(crate) key_update: Option<u64>,
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig").finish_non_exhaustive()
    }
}

impl ServerConfig {
    pub(crate) fn new(tls: only_tls::ServerConfig) -> ServerConfig {
        ServerConfig(ServerInner {
            tls,
            transport: TransportConfig::default(),
            migration: true,
            retry: false,
            key_update: None,
        })
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

    /// Validates every client address with a Retry round trip before accepting it (default:
    /// only under handshake load). Hidden: for tests and interop runs.
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
    pub(crate) tls: only_tls::ClientConfig,
    pub(crate) transport: TransportConfig,
    pub(crate) tokens: TokenStore,
    pub(crate) key_update: Option<u64>,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig").finish_non_exhaustive()
    }
}

impl ClientConfig {
    pub(crate) fn new(tls: only_tls::ClientConfig) -> ClientConfig {
        ClientConfig(ClientInner {
            tls,
            transport: TransportConfig::default(),
            tokens: Arc::new(Mutex::new(HashMap::new())),
            key_update: None,
        })
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
