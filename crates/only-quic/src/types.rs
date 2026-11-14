//! This crate's own QUIC types: stream ids, connection errors, statistics and configuration.
//! They hide quinn-proto, so it can be upgraded or replaced without breaking this API; raw
//! access is behind the `unstable` cargo feature.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use quinn_proto as qp;

use crate::Error;

/// Conversions between this crate's types and the wrapped implementation's (crate-private, so
/// they stay out of the public API).
pub(crate) trait Own<T> {
    fn own(self) -> T;
}

/// Which side opened a stream or a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    /// The side that dialed.
    Client,
    /// The side that accepted.
    Server,
}

impl Own<Side> for qp::Side {
    fn own(self) -> Side {
        let s = self;
        match s {
            qp::Side::Client => Side::Client,
            qp::Side::Server => Side::Server,
        }
    }
}

impl Own<qp::Side> for Side {
    fn own(self) -> qp::Side {
        let s = self;
        match s {
            Side::Client => qp::Side::Client,
            Side::Server => qp::Side::Server,
        }
    }
}

/// Whether a stream carries data both ways or one way.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Dir {
    /// Bidirectional.
    Bi,
    /// Unidirectional (from the side that opened it).
    Uni,
}

impl Own<Dir> for qp::Dir {
    fn own(self) -> Dir {
        let d = self;
        match d {
            qp::Dir::Bi => Dir::Bi,
            qp::Dir::Uni => Dir::Uni,
        }
    }
}

impl Own<qp::Dir> for Dir {
    fn own(self) -> qp::Dir {
        let d = self;
        match d {
            Dir::Bi => qp::Dir::Bi,
            Dir::Uni => qp::Dir::Uni,
        }
    }
}

/// A stream id (RFC 9000 section 2.1): who opened it, its direction and its index.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(u64);

impl StreamId {
    /// The `index`-th stream of direction `dir` opened by `initiator`.
    pub fn new(initiator: Side, dir: Dir, index: u64) -> StreamId {
        StreamId(u64::from(qp::StreamId::new(
            initiator.own(),
            dir.own(),
            index,
        )))
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

    pub(crate) fn q(self) -> qp::StreamId {
        qp::StreamId::new(self.initiator().own(), self.dir().own(), self.index())
    }
}

impl Own<StreamId> for qp::StreamId {
    fn own(self) -> StreamId {
        let id = self;
        StreamId(u64::from(id))
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

impl Own<ConnectionError> for qp::ConnectionError {
    fn own(self) -> ConnectionError {
        let e = self;
        match e {
            qp::ConnectionError::VersionMismatch => ConnectionError::VersionMismatch,
            qp::ConnectionError::TransportError(t) => ConnectionError::TransportError {
                code: u64::from(t.code),
                reason: t.reason,
            },
            qp::ConnectionError::ConnectionClosed(c) => ConnectionError::ConnectionClosed {
                code: u64::from(c.error_code),
                reason: c.reason.to_vec(),
            },
            qp::ConnectionError::ApplicationClosed(c) => ConnectionError::ApplicationClosed {
                code: c.error_code.into_inner(),
                reason: c.reason.to_vec(),
            },
            qp::ConnectionError::Reset => ConnectionError::Reset,
            qp::ConnectionError::TimedOut => ConnectionError::TimedOut,
            qp::ConnectionError::LocallyClosed => ConnectionError::LocallyClosed,
            qp::ConnectionError::CidsExhausted => ConnectionError::CidsExhausted,
        }
    }
}

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

impl Own<UdpStats> for qp::UdpStats {
    fn own(self) -> UdpStats {
        let s = self;
        UdpStats {
            datagrams: s.datagrams,
            bytes: s.bytes,
            ios: s.ios,
        }
    }
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
}

impl Own<ConnectionStats> for qp::ConnectionStats {
    fn own(self) -> ConnectionStats {
        let s = self;
        ConnectionStats {
            udp_tx: s.udp_tx.own(),
            udp_rx: s.udp_rx.own(),
            rtt: s.path.rtt,
            min_rtt: s.path.min_rtt,
            cwnd: s.path.cwnd,
            congestion_events: s.path.congestion_events,
            sent_packets: s.path.sent_packets,
            lost_packets: s.path.lost_packets,
            lost_bytes: s.path.lost_bytes,
            current_mtu: s.path.current_mtu,
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
    /// BBR (experimental).
    Bbr,
}

/// Transport parameters and limits of connections. Start from `Default::default()` (quinn's
/// defaults) and set fields.
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
        }
    }
}

fn varint(v: u64) -> qp::VarInt {
    qp::VarInt::from_u64(v).unwrap_or(qp::VarInt::MAX)
}

impl TransportConfig {
    /// The quinn configuration (out-of-range values are clamped).
    pub(crate) fn to_quinn(&self) -> qp::TransportConfig {
        let mut t = qp::TransportConfig::default();
        t.max_concurrent_bidi_streams(self.max_concurrent_bidi_streams.into())
            .max_concurrent_uni_streams(self.max_concurrent_uni_streams.into())
            .max_idle_timeout(self.max_idle_timeout.map(|d| {
                qp::IdleTimeout::try_from(d)
                    .unwrap_or_else(|_| qp::IdleTimeout::from(qp::VarInt::MAX))
            }))
            .keep_alive_interval(self.keep_alive_interval)
            .stream_receive_window(varint(self.stream_receive_window))
            .receive_window(self.receive_window.map_or(qp::VarInt::MAX, varint))
            .send_window(self.send_window)
            .initial_rtt(self.initial_rtt)
            .initial_mtu(self.initial_mtu.max(1200))
            .datagram_receive_buffer_size(self.datagram_receive_buffer_size)
            .datagram_send_buffer_size(self.datagram_send_buffer_size);
        if !self.mtu_discovery {
            t.mtu_discovery_config(None);
        }
        match self.congestion {
            Congestion::Cubic => {}
            Congestion::NewReno => {
                t.congestion_controller_factory(Arc::new(qp::congestion::NewRenoConfig::default()));
            }
            Congestion::Bbr => {
                t.congestion_controller_factory(Arc::new(qp::congestion::BbrConfig::default()));
            }
        }
        t
    }
}

// ---- endpoint configurations ----

/// A QUIC server configuration: TLS (see [`server_config`](crate::server_config)) plus
/// transport settings. Cheap to clone.
#[derive(Clone)]
pub struct ServerConfig(pub(crate) qp::ServerConfig);

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig").finish_non_exhaustive()
    }
}

impl ServerConfig {
    /// Uses `transport` for every connection.
    #[must_use]
    pub fn transport(mut self, transport: &TransportConfig) -> Self {
        self.0.transport_config(Arc::new(transport.to_quinn()));
        self
    }

    /// Whether clients may migrate to a new address (default `true`).
    #[must_use]
    pub fn migration(mut self, yes: bool) -> Self {
        self.0.migration(yes);
        self
    }

    /// Wraps a quinn-proto configuration. **Unstable** (cargo feature `unstable`, outside the
    /// semver promise).
    #[cfg(feature = "unstable")]
    pub fn from_quinn(config: qp::ServerConfig) -> ServerConfig {
        ServerConfig(config)
    }

    /// The quinn-proto configuration. **Unstable** (cargo feature `unstable`).
    #[cfg(feature = "unstable")]
    pub fn as_quinn_mut(&mut self) -> &mut qp::ServerConfig {
        &mut self.0
    }
}

/// A QUIC client configuration: TLS (see [`client_config`](crate::client_config)) plus
/// transport settings. Cheap to clone.
#[derive(Clone)]
pub struct ClientConfig(pub(crate) qp::ClientConfig);

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig").finish_non_exhaustive()
    }
}

impl ClientConfig {
    /// Uses `transport` for connections dialed with this configuration.
    #[must_use]
    pub fn transport(mut self, transport: &TransportConfig) -> Self {
        self.0.transport_config(Arc::new(transport.to_quinn()));
        self
    }

    /// Wraps a quinn-proto configuration. **Unstable** (cargo feature `unstable`, outside the
    /// semver promise).
    #[cfg(feature = "unstable")]
    pub fn from_quinn(config: qp::ClientConfig) -> ClientConfig {
        ClientConfig(config)
    }

    /// The quinn-proto configuration. **Unstable** (cargo feature `unstable`).
    #[cfg(feature = "unstable")]
    pub fn as_quinn_mut(&mut self) -> &mut qp::ClientConfig {
        &mut self.0
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
                let q = id.q();
                let back: qp::Side = side.own();
                assert_eq!(back, q.initiator());
                let back: qp::Dir = dir.own();
                assert_eq!(back, q.dir());
                assert_eq!(Own::<StreamId>::own(q), id);
                assert_eq!(u64::from(id), u64::from(q));
                assert_eq!(Own::<Side>::own(q.initiator()), side);
                assert_eq!(Own::<Dir>::own(q.dir()), dir);
                assert_eq!(id.to_string(), u64::from(id).to_string());
            }
        }
        assert_eq!(
            format!("{:?}", StreamId::new(Side::Server, Dir::Uni, 3)),
            "StreamId(Server Uni 3)"
        );
    }

    #[test]
    fn errors_map_and_display() {
        let e: ConnectionError = qp::ConnectionError::TimedOut.own();
        assert_eq!(e, ConnectionError::TimedOut);
        for (q, s) in [
            (
                qp::ConnectionError::VersionMismatch,
                "peer supports no common version",
            ),
            (qp::ConnectionError::Reset, "reset by peer"),
            (qp::ConnectionError::LocallyClosed, "closed"),
            (
                qp::ConnectionError::CidsExhausted,
                "connection ids exhausted",
            ),
        ] {
            assert_eq!(Own::<ConnectionError>::own(q).to_string(), s);
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
    }

    #[test]
    fn transport_config_converts() {
        let mut t = TransportConfig::default();
        let _ = t.to_quinn();
        t.max_idle_timeout = Some(Duration::from_secs(u64::MAX / 2));
        t.receive_window = Some(u64::MAX);
        t.mtu_discovery = false;
        t.initial_mtu = 0;
        for c in [Congestion::Cubic, Congestion::NewReno, Congestion::Bbr] {
            t.congestion = c;
            let _ = t.to_quinn();
        }
        let s: ConnectionStats = qp::ConnectionStats::default().own();
        assert_eq!(s.udp_tx, UdpStats::default());
    }
}
