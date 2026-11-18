#![forbid(unsafe_code)]
#![warn(clippy::unwrap_used)]
//! Sans-io SCTP over DTLS (RFC 8261) with WebRTC data channels (RFC 8831, RFC 8832) for the
//! `only` WebRTC stack, on [`only_crypto`] with no other dependencies.
//!
//! An [`Association`] is a state machine without I/O, threads or clocks of its own: the
//! caller passes in every DTLS application-data record (one SCTP packet each) with
//! [`Association::handle_packet`], sends every packet from [`Association::poll_transmit`] as
//! one DTLS record, calls [`Association::handle_timeout`] at [`Association::poll_timeout`]
//! and reads [`Event`]s from [`Association::poll_event`].
//!
//! - Packets (RFC 9260 §3): common header with CRC-32C (stored little-endian, as usrsctp and
//!   pion do), chunk bundling up to [`Config::mtu`], unknown chunks handled by their
//!   high-order type bits (skipped / reported in an ERROR chunk).
//! - Handshake (§5): INIT / INIT ACK / COOKIE ECHO / COOKIE ACK with an HMAC-SHA-256 signed,
//!   self-contained state cookie; INIT and COOKIE ECHO retransmission with backoff; INIT
//!   collisions (both sides calling [`Association::connect`]) converge on one association
//!   because each side uses a single verification tag; duplicate COOKIE ECHOs are
//!   acknowledged. Supported Extensions advertise RE-CONFIG, FORWARD TSN and (with
//!   [`Config::message_interleaving`]) I-DATA and I-FORWARD-TSN; no AUTH or ASCONF.
//! - Data transfer (§6-7): DATA fragmentation to the MTU and reassembly, ordered delivery per
//!   stream SSN and unordered delivery, SACK with gap blocks and duplicate TSNs (delayed:
//!   every second packet or 200 ms; immediate on gaps and duplicates), slow start /
//!   congestion avoidance, the peer's receiver window, T3-rtx with RTO from SRTT / RTTVAR,
//!   fast retransmit on three miss indications and fast recovery; association failure after
//!   `max_retransmissions` consecutive timeouts.
//! - Message interleaving (RFC 8260 §2): when both sides offer I-DATA, messages travel in
//!   I-DATA chunks (32-bit message identifiers, fragment sequence numbers) and fragments of
//!   messages on different streams interleave, so a large message no longer blocks small
//!   ones on other channels. Otherwise DATA chunks as before.
//! - Stream schedulers (RFC 8260 §3, [`Scheduler`]): first come first served, round robin,
//!   round robin per packet, priority, fair capacity and weighted fair queueing (the
//!   default) by channel priority, chosen per association.
//! - Partial reliability (RFC 3758): per-message retransmission limit or lifetime (from the
//!   [`Association::send`] call), FORWARD TSN with stream / SSN pairs (I-FORWARD-TSN with
//!   stream / MID entries under I-DATA), both directions. Only used when the peer offers it;
//!   otherwise such channels are reliable.
//! - Stream reset (RFC 6525): Outgoing SSN Reset Requests and Re-configuration Responses
//!   ("performed", "in progress" with retry). Add-streams requests are accepted; incoming and
//!   SSN/TSN reset requests are denied.
//! - HEARTBEAT is answered; ABORT, graceful SHUTDOWN in both roles (§9).
//! - Data channels (RFC 8831 / 8832): DCEP DATA_CHANNEL_OPEN / ACK, all channel types,
//!   negotiated channels, PPIDs 51 / 53 and the empty-message PPIDs 56 / 57, deprecated
//!   partial PPIDs 52 / 54 accepted, stream id parity from the DTLS role, closing by stream
//!   reset in both directions, per-channel buffered amount with a low-water event.
//!
//! Not implemented: multi-homing and path management,
//! sending HEARTBEATs, peer restart (an INIT with a new tag on a live association is
//! ignored), AUTH (RFC 4895), ASCONF, ECN, zero checksum (RFC 9653), incoming SSN reset and
//! SSN/TSN reset requests.
//!
//! ```
//! use std::time::Instant;
//! use only_sctp::{Association, ChannelOptions, Config, Event};
//!
//! let now = Instant::now();
//! let mut client = Association::new(Config::new(true), now);
//! let mut server = Association::new(Config::new(false), now);
//! client.connect(now);
//! let chat = client.open_channel(now, ChannelOptions::new("chat"))?;
//! client.send(now, chat, b"hello", false)?;
//! for _ in 0..8 {
//!     while let Some(p) = client.poll_transmit(now) {
//!         server.handle_packet(now, &p); // in WebRTC: one DTLS record each way
//!     }
//!     while let Some(p) = server.poll_transmit(now) {
//!         client.handle_packet(now, &p);
//!     }
//! }
//! assert!(client.is_established() && server.is_established());
//! assert_eq!(server.poll_event(), Some(Event::Connected));
//! assert!(matches!(server.poll_event(), Some(Event::ChannelOpen { stream: 0, .. })));
//! assert_eq!(
//!     server.poll_event(),
//!     Some(Event::ChannelData { stream: 0, data: b"hello".to_vec(), binary: false })
//! );
//! # Ok::<(), only_sctp::Error>(())
//! ```
//!
//! This is an implementation crate of `only` (docs/api-stability.md, Internal tier): its API
//! follows the needs of the WebRTC stack and may change in any release.

use std::fmt;
use std::time::Duration;

mod assoc;
mod dcep;
mod packet;
mod recv;
mod sched;
mod send;

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

pub use assoc::Association;

/// Association settings. [`Config::new`] gives the WebRTC defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Our SCTP port (SDP `a=sctp-port`, default 5000). Ports of received packets are not
    /// checked: there is one association per DTLS connection.
    pub local_port: u16,
    /// The peer's SCTP port (default 5000).
    pub remote_port: u16,
    /// Largest SCTP packet we send (default 1200; at least 128).
    pub mtu: usize,
    /// Largest message [`Association::send`] accepts: the remote `a=max-message-size`
    /// (default 262144).
    pub max_message_size: usize,
    /// Largest message we reassemble (default 262144). A peer that sends a larger one gets an
    /// ABORT (protocol violation) and the association closes.
    pub max_receive_message_size: usize,
    /// Per-channel buffered amount above which [`Association::send`] returns `Ok(false)`
    /// (default 1 MiB).
    pub max_buffered_amount: usize,
    /// Our advertised receiver window, a_rwnd (default 1 MiB).
    pub receive_window: u32,
    /// Whether we are the DTLS client: it uses even stream ids, the server odd ones
    /// (RFC 8832 §6).
    pub dtls_client: bool,
    /// Association.Max.Retrans: consecutive retransmission timeouts before the association
    /// fails (default 10).
    pub max_retransmissions: u32,
    /// Max.Init.Retransmits for INIT and COOKIE ECHO (default 8).
    pub max_init_retransmissions: u32,
    /// RTO.Initial (default 1 s).
    pub rto_initial: Duration,
    /// RTO.Min (default 200 ms, lower than RFC 9260's 1 s as usual for WebRTC).
    pub rto_min: Duration,
    /// RTO.Max (default 10 s, lower than RFC 9260's 60 s so that a vanished peer is noticed
    /// within about 85 s).
    pub rto_max: Duration,
    /// Offer I-DATA / I-FORWARD-TSN (RFC 8260, default `true`). When the peer offers them
    /// too, messages are sent as I-DATA chunks and the scheduler interleaves fragments of
    /// messages on different streams, so that a large message does not hold up small ones
    /// on other channels; otherwise DATA chunks are used and a message, once started, goes
    /// out whole. [`Association::message_interleaving`] tells which.
    pub message_interleaving: bool,
    /// How streams with queued messages share the association (RFC 8260 §3; default
    /// [`Scheduler::WeightedFairQueueing`] by channel priority).
    pub scheduler: Scheduler,
}

/// Stream schedulers (RFC 8260 §3): which channel's queued message the next chunk comes
/// from. The unit served is a chunk when I-DATA is in use and a whole message otherwise.
/// Retransmissions always go first. Priorities are the channels'
/// ([`ChannelOptions::priority`], [`Association::set_channel_priority`]): as in RFC 8832,
/// higher values are more important (WebRTC: very-low 128, low 256, medium 512, high 1024;
/// 0, which some stacks send when no priority is set, counts as 256).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Scheduler {
    /// First come, first served (§3.1): messages in the order they were queued, across
    /// channels.
    FirstComeFirstServed,
    /// Round robin (§3.2): channels with queued data take turns, one unit each.
    RoundRobin,
    /// Round robin per packet (§3.3): like round robin, but a packet is filled from one
    /// channel and the turn passes with each packet.
    RoundRobinPerPacket,
    /// Priority (§3.4): the channels with the highest priority are served first (round robin
    /// among equals); lower ones only when those have nothing queued.
    Priority,
    /// Fair capacity (§3.5): every channel with queued data gets the same share of bytes.
    FairCapacity,
    /// Weighted fair queueing (§3.6): channels get shares of bytes in proportion to their
    /// priorities (a channel with priority 512 gets twice the share of one with 256).
    #[default]
    WeightedFairQueueing,
}

impl Config {
    /// WebRTC defaults; `dtls_client` picks the stream id parity.
    #[must_use]
    pub fn new(dtls_client: bool) -> Config {
        Config {
            local_port: 5000,
            remote_port: 5000,
            mtu: 1200,
            max_message_size: 262_144,
            max_receive_message_size: 262_144,
            max_buffered_amount: 1 << 20,
            receive_window: 1 << 20,
            dtls_client,
            max_retransmissions: 10,
            max_init_retransmissions: 8,
            rto_initial: Duration::from_secs(1),
            rto_min: Duration::from_millis(200),
            rto_max: Duration::from_secs(10),
            message_interleaving: true,
            scheduler: Scheduler::WeightedFairQueueing,
        }
    }

    /// Sets both SCTP ports.
    #[must_use]
    pub fn with_ports(mut self, local: u16, remote: u16) -> Config {
        self.local_port = local;
        self.remote_port = remote;
        self
    }

    /// Sets [`Config::mtu`].
    #[must_use]
    pub fn with_mtu(mut self, mtu: usize) -> Config {
        self.mtu = mtu;
        self
    }

    /// Sets [`Config::max_message_size`].
    #[must_use]
    pub fn with_max_message_size(mut self, bytes: usize) -> Config {
        self.max_message_size = bytes;
        self
    }

    /// Sets [`Config::max_receive_message_size`].
    #[must_use]
    pub fn with_max_receive_message_size(mut self, bytes: usize) -> Config {
        self.max_receive_message_size = bytes;
        self
    }

    /// Sets [`Config::max_buffered_amount`].
    #[must_use]
    pub fn with_max_buffered_amount(mut self, bytes: usize) -> Config {
        self.max_buffered_amount = bytes;
        self
    }

    /// Sets [`Config::receive_window`].
    #[must_use]
    pub fn with_receive_window(mut self, bytes: u32) -> Config {
        self.receive_window = bytes;
        self
    }

    /// Sets [`Config::message_interleaving`].
    #[must_use]
    pub fn with_message_interleaving(mut self, on: bool) -> Config {
        self.message_interleaving = on;
        self
    }

    /// Sets [`Config::scheduler`].
    #[must_use]
    pub fn with_scheduler(mut self, scheduler: Scheduler) -> Config {
        self.scheduler = scheduler;
        self
    }
}

impl Default for Config {
    /// [`Config::new`] as the DTLS server.
    fn default() -> Config {
        Config::new(false)
    }
}

/// Delivery guarantee of a channel (RFC 8832 §5.1 channel types).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Reliability {
    /// Every message arrives.
    #[default]
    Reliable,
    /// A message is retransmitted at most this many times, then abandoned.
    MaxRetransmits(u16),
    /// A message is abandoned this many milliseconds after it was queued.
    MaxLifetime(u16),
}

/// Parameters of [`Association::open_channel`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelOptions {
    /// Channel label.
    pub label: String,
    /// Sub-protocol (may be empty).
    pub protocol: String,
    /// In-order delivery.
    pub ordered: bool,
    /// Delivery guarantee.
    pub reliability: Reliability,
    /// `Some(id)`: a negotiated channel on stream `id` (no DCEP; both sides open it).
    pub negotiated: Option<u16>,
    /// Priority (default 256): sent in DATA_CHANNEL_OPEN and used by the
    /// [`Scheduler`] for our side of the channel. Higher is more important.
    pub priority: u16,
}

impl ChannelOptions {
    /// An ordered, reliable channel with this label.
    #[must_use]
    pub fn new(label: &str) -> ChannelOptions {
        ChannelOptions {
            label: label.to_owned(),
            ..ChannelOptions::default()
        }
    }

    /// Sets ordered / unordered delivery.
    #[must_use]
    pub fn with_ordered(mut self, ordered: bool) -> ChannelOptions {
        self.ordered = ordered;
        self
    }

    /// Sets the delivery guarantee.
    #[must_use]
    pub fn with_reliability(mut self, reliability: Reliability) -> ChannelOptions {
        self.reliability = reliability;
        self
    }

    /// Makes it a negotiated channel on stream `id`.
    #[must_use]
    pub fn with_negotiated(mut self, id: u16) -> ChannelOptions {
        self.negotiated = Some(id);
        self
    }

    /// Sets the sub-protocol.
    #[must_use]
    pub fn with_protocol(mut self, protocol: &str) -> ChannelOptions {
        protocol.clone_into(&mut self.protocol);
        self
    }

    /// Sets [`ChannelOptions::priority`].
    #[must_use]
    pub fn with_priority(mut self, priority: u16) -> ChannelOptions {
        self.priority = priority;
        self
    }
}

impl Default for ChannelOptions {
    fn default() -> ChannelOptions {
        ChannelOptions {
            label: String::new(),
            protocol: String::new(),
            ordered: true,
            reliability: Reliability::Reliable,
            negotiated: None,
            priority: 256,
        }
    }
}

/// What [`Association::channel`] reports about a channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelInfo {
    /// Channel label.
    pub label: String,
    /// Sub-protocol.
    pub protocol: String,
    /// In-order delivery.
    pub ordered: bool,
    /// Delivery guarantee.
    pub reliability: Reliability,
    /// Negotiated out of band (no DCEP).
    pub negotiated: bool,
    /// Priority: from DATA_CHANNEL_OPEN, or as last set with
    /// [`Association::set_channel_priority`]; the scheduler uses it for our sending side.
    pub priority: u16,
}

/// Something that happened on the association.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The association is established.
    Connected,
    /// A channel is open: opened by the peer (its DATA_CHANNEL_OPEN arrived and we
    /// acknowledged it) or by us (once the association is established; negotiated channels
    /// on both sides then).
    ChannelOpen {
        /// Stream id.
        stream: u16,
        /// Label.
        label: String,
        /// Sub-protocol.
        protocol: String,
    },
    /// A message arrived.
    ChannelData {
        /// Stream id.
        stream: u16,
        /// Payload (empty for PPID 56 / 57).
        data: Vec<u8>,
        /// Binary (PPID 53 / 57) or string (51 / 56).
        binary: bool,
    },
    /// A channel closed: both directions of its stream are reset, or the association closed.
    /// The stream id may be reused afterwards.
    ChannelClose {
        /// Stream id.
        stream: u16,
    },
    /// The channel's buffered amount dropped to or below its low threshold.
    BufferedAmountLow {
        /// Stream id.
        stream: u16,
    },
    /// The association shut down, was aborted or failed. Always the last event.
    Closed,
}

/// Errors from the channel API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The association is closed or shutting down.
    AssociationClosed,
    /// No channel on this stream.
    UnknownChannel(u16),
    /// The channel is closing.
    ChannelClosed(u16),
    /// The message is larger than [`Config::max_message_size`].
    MessageTooLarge {
        /// Message size.
        size: usize,
        /// The limit.
        max: usize,
    },
    /// The negotiated stream id is taken.
    StreamInUse(u16),
    /// Every stream id of our parity is taken.
    NoStreamAvailable,
    /// The label or protocol is longer than 65535 bytes.
    LabelTooLong,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AssociationClosed => f.write_str("SCTP association closed"),
            Error::UnknownChannel(s) => write!(f, "no data channel on stream {s}"),
            Error::ChannelClosed(s) => write!(f, "data channel on stream {s} is closing"),
            Error::MessageTooLarge { size, max } => {
                write!(f, "message of {size} bytes exceeds the maximum of {max}")
            }
            Error::StreamInUse(s) => write!(f, "stream {s} is already in use"),
            Error::NoStreamAvailable => f.write_str("no free stream id"),
            Error::LabelTooLong => f.write_str("data channel label or protocol too long"),
        }
    }
}

impl std::error::Error for Error {}
