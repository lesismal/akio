//! This crate's own WebRTC types: ids, media descriptions, events, candidates, the per-peer
//! configuration and the SDP change set.

use std::fmt;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::Error;

// ---- ids ----

/// A data channel id.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelId(pub(crate) usize);

impl fmt::Debug for ChannelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChannelId({})", self.0)
    }
}

/// The longest media line id this crate keeps (longer remote ids are truncated).
pub(crate) const MID_MAX: usize = 16;

/// A media line id (`a=mid:` in the SDP).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Mid(MidBytes);

/// The inline text of a [`Mid`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct MidBytes {
    bytes: [u8; MID_MAX],
    len: u8,
}

impl Mid {
    /// The id as it appears in the SDP.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0.bytes[..usize::from(self.0.len)]).unwrap_or("")
    }

    /// A mid from SDP text (truncated to 16 bytes at a character boundary).
    pub(crate) fn new(s: &str) -> Mid {
        let mut end = s.len().min(MID_MAX);
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        let mut bytes = [0u8; MID_MAX];
        bytes[..end].copy_from_slice(&s.as_bytes()[..end]);
        Mid(MidBytes {
            bytes,
            len: end as u8,
        })
    }
}

impl PartialOrd for Mid {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

impl Ord for Mid {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(o.as_str())
    }
}

impl fmt::Debug for Mid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mid({})", self.as_str())
    }
}

impl fmt::Display for Mid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An RTP payload type (negotiated per media line; see [`Peer::payload_type`](crate::Peer::payload_type)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pt(u8);

impl Pt {
    /// The payload type number.
    pub fn get(self) -> u8 {
        self.0
    }
}

impl From<u8> for Pt {
    fn from(v: u8) -> Pt {
        Pt(v)
    }
}

impl From<Pt> for u8 {
    fn from(p: Pt) -> u8 {
        p.0
    }
}

// ---- data channels ----

/// Delivery guarantees of a data channel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reliability {
    /// Every message arrives (retransmitted as needed). The default.
    #[default]
    Reliable,
    /// A message is dropped once it is this old.
    MaxPacketLifetime {
        /// Lifetime in milliseconds.
        lifetime: u16,
    },
    /// A message is dropped after this many retransmissions.
    MaxRetransmits {
        /// Retransmissions before giving up (0: send once).
        retransmits: u16,
    },
}

/// How to open a data channel. Start from `Default::default()` and set fields.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ChannelConfig {
    /// The label the other side sees.
    pub label: String,
    /// In-order delivery (default `true`).
    pub ordered: bool,
    /// Retransmission policy (default reliable).
    pub reliability: Reliability,
    /// Out-of-band negotiated channel with this SCTP stream id; `None` (default) negotiates
    /// in-band (DCEP).
    pub negotiated: Option<u16>,
    /// Sub-protocol name (default empty).
    pub protocol: String,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        ChannelConfig {
            label: String::new(),
            ordered: true,
            reliability: Reliability::Reliable,
            negotiated: None,
            protocol: String::new(),
        }
    }
}

impl ChannelConfig {
    /// A reliable, ordered channel labelled `label`.
    pub fn new(label: impl Into<String>) -> ChannelConfig {
        ChannelConfig {
            label: label.into(),
            ..Default::default()
        }
    }

    pub(crate) fn to_sctp(&self) -> only_sctp::ChannelOptions {
        let mut o = only_sctp::ChannelOptions::new(&self.label)
            .with_ordered(self.ordered)
            .with_protocol(&self.protocol)
            .with_reliability(match self.reliability {
                Reliability::Reliable => only_sctp::Reliability::Reliable,
                Reliability::MaxPacketLifetime { lifetime } => {
                    only_sctp::Reliability::MaxLifetime(lifetime)
                }
                Reliability::MaxRetransmits { retransmits } => {
                    only_sctp::Reliability::MaxRetransmits(retransmits)
                }
            });
        if let Some(id) = self.negotiated {
            o = o.with_negotiated(id);
        }
        o
    }
}

// ---- media ----

/// Audio or video.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MediaKind {
    /// Audio.
    Audio,
    /// Video.
    Video,
}

impl MediaKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            MediaKind::Audio => "audio",
            MediaKind::Video => "video",
        }
    }
}

/// The direction of a media line, from this side.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Neither sends.
    Inactive,
    /// This side only receives.
    RecvOnly,
    /// This side only sends.
    SendOnly,
    /// Both ways.
    SendRecv,
}

impl Direction {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Direction::Inactive => "inactive",
            Direction::RecvOnly => "recvonly",
            Direction::SendOnly => "sendonly",
            Direction::SendRecv => "sendrecv",
        }
    }

    pub(crate) fn parse(s: &str) -> Option<Direction> {
        Some(match s {
            "inactive" => Direction::Inactive,
            "recvonly" => Direction::RecvOnly,
            "sendonly" => Direction::SendOnly,
            "sendrecv" => Direction::SendRecv,
            _ => return None,
        })
    }

    /// The direction seen from the other side.
    pub(crate) fn reverse(self) -> Direction {
        match self {
            Direction::RecvOnly => Direction::SendOnly,
            Direction::SendOnly => Direction::RecvOnly,
            d => d,
        }
    }

    pub(crate) fn sends(self) -> bool {
        matches!(self, Direction::SendOnly | Direction::SendRecv)
    }

    pub(crate) fn receives(self) -> bool {
        matches!(self, Direction::RecvOnly | Direction::SendRecv)
    }

    /// Both `self` and `o` allow it.
    pub(crate) fn intersect(self, o: Direction) -> Direction {
        match (self.sends() && o.sends(), self.receives() && o.receives()) {
            (true, true) => Direction::SendRecv,
            (true, false) => Direction::SendOnly,
            (false, true) => Direction::RecvOnly,
            (false, false) => Direction::Inactive,
        }
    }
}

/// A media codec.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Codec {
    /// Opus.
    Opus,
    /// G.711 µ-law.
    Pcmu,
    /// G.711 A-law.
    Pcma,
    /// G.722.
    G722,
    /// H.264.
    H264,
    /// H.265.
    H265,
    /// VP8.
    Vp8,
    /// VP9.
    Vp9,
    /// AV1.
    Av1,
}

impl Codec {
    pub(crate) const ALL: [Codec; 9] = [
        Codec::Opus,
        Codec::Pcmu,
        Codec::Pcma,
        Codec::G722,
        Codec::H264,
        Codec::H265,
        Codec::Vp8,
        Codec::Vp9,
        Codec::Av1,
    ];

    /// The `a=rtpmap` encoding name.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Codec::Opus => "opus",
            Codec::Pcmu => "PCMU",
            Codec::Pcma => "PCMA",
            Codec::G722 => "G722",
            Codec::H264 => "H264",
            Codec::H265 => "H265",
            Codec::Vp8 => "VP8",
            Codec::Vp9 => "VP9",
            Codec::Av1 => "AV1",
        }
    }

    pub(crate) fn from_name(s: &str) -> Option<Codec> {
        Codec::ALL
            .into_iter()
            .find(|c| c.name().eq_ignore_ascii_case(s))
            .or_else(|| s.eq_ignore_ascii_case("AV1X").then_some(Codec::Av1))
    }

    pub(crate) fn kind(self) -> MediaKind {
        match self {
            Codec::Opus | Codec::Pcmu | Codec::Pcma | Codec::G722 => MediaKind::Audio,
            _ => MediaKind::Video,
        }
    }

    pub(crate) fn rtp(self) -> only_rtp::codec::CodecKind {
        use only_rtp::codec::CodecKind as K;
        match self {
            Codec::Opus => K::Opus,
            Codec::Pcmu => K::Pcmu,
            Codec::Pcma => K::Pcma,
            Codec::G722 => K::G722,
            Codec::H264 => K::H264,
            Codec::H265 => K::H265,
            Codec::Vp8 => K::Vp8,
            Codec::Vp9 => K::Vp9,
            Codec::Av1 => K::Av1,
        }
    }
}

/// A clock rate, in Hz.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Frequency(NonZeroU32);

impl Frequency {
    /// 90 kHz, the RTP clock of video.
    pub const NINETY_KHZ: Frequency = Frequency(NonZeroU32::new(90_000).expect("non-zero"));
    /// 48 kHz, the RTP clock of Opus.
    pub const FORTY_EIGHT_KHZ: Frequency = Frequency(NonZeroU32::new(48_000).expect("non-zero"));
    /// 8 kHz, the RTP clock of G.711 and G.722.
    pub const EIGHT_KHZ: Frequency = Frequency(NonZeroU32::new(8_000).expect("non-zero"));

    /// `hz`, unless it is zero.
    pub fn new(hz: u32) -> Option<Frequency> {
        NonZeroU32::new(hz).map(Frequency)
    }

    /// The rate in Hz.
    pub fn get(self) -> u32 {
        self.0.get()
    }
}

/// A media timestamp: ticks of a clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MediaTime {
    ticks: u64,
    rate: Frequency,
}

impl MediaTime {
    /// `ticks` of a `rate` clock.
    pub fn new(ticks: u64, rate: Frequency) -> MediaTime {
        MediaTime { ticks, rate }
    }

    /// The ticks.
    pub fn ticks(self) -> u64 {
        self.ticks
    }

    /// The clock rate.
    pub fn rate(self) -> Frequency {
        self.rate
    }

    /// The time as a duration since the clock's origin.
    pub fn as_duration(self) -> Duration {
        let hz = u64::from(self.rate.get());
        let secs = self.ticks / hz;
        let rem = self.ticks % hz;
        Duration::from_secs(secs) + Duration::from_nanos(rem * 1_000_000_000 / hz)
    }

    /// The ticks in another clock.
    pub(crate) fn ticks_at(self, rate: u32) -> u64 {
        if rate == self.rate.get() {
            return self.ticks;
        }
        (u128::from(self.ticks) * u128::from(rate) / u128::from(self.rate.get())) as u64
    }
}

/// A keyframe request from the remote receiver.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyframeRequestKind {
    /// Picture Loss Indication.
    Pli,
    /// Full Intra Request.
    Fir,
}

/// The remote peer asks for a keyframe on a media line.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyframeRequest {
    /// The media line.
    pub mid: Mid,
    /// The simulcast layer, if any.
    pub rid: Option<String>,
    /// PLI or FIR.
    pub kind: KeyframeRequestKind,
}

/// A media line was added (by the remote offer or ours).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct MediaAdded {
    /// The media line.
    pub mid: Mid,
    /// Audio or video.
    pub kind: MediaKind,
    /// Its direction, from this side.
    pub direction: Direction,
}

/// A depacketized media sample (a frame).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct MediaData {
    /// The media line.
    pub mid: Mid,
    /// The payload type.
    pub pt: Pt,
    /// The simulcast layer, if any.
    pub rid: Option<String>,
    /// The codec, when it is one of [`Codec`].
    pub codec: Option<Codec>,
    /// RTP time of the sample, in the codec's clock.
    pub time: MediaTime,
    /// When its first packet arrived.
    pub network_time: Instant,
    /// No packets are missing since the previous sample.
    pub contiguous: bool,
    /// The sample.
    pub data: Arc<[u8]>,
}

/// A received RTP packet (RTP mode, [`RtcConfig::set_rtp_mode`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RtpPacket {
    /// Extended (64-bit, rollover-corrected) sequence number.
    pub seq_no: u64,
    /// Synchronization source.
    pub ssrc: u32,
    /// Payload type.
    pub pt: Pt,
    /// The marker bit (end of a frame for video).
    pub marker: bool,
    /// The RTP timestamp as sent.
    pub rtp_time: u32,
    /// Extended media time.
    pub time: MediaTime,
    /// When the packet arrived.
    pub received: Instant,
    /// The payload.
    pub payload: Arc<[u8]>,
}

// ---- ICE ----

/// The ICE connection state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IceConnectionState {
    /// Waiting for candidates.
    New,
    /// Checking candidate pairs.
    Checking,
    /// A working pair was found; checks may continue.
    Connected,
    /// Checks are done.
    Completed,
    /// Connectivity was lost (consent freshness failed).
    Disconnected,
}

impl IceConnectionState {
    pub(crate) fn from_ice(s: only_ice::IceState) -> IceConnectionState {
        use only_ice::IceState as S;
        match s {
            S::New => IceConnectionState::New,
            S::Checking => IceConnectionState::Checking,
            S::Connected => IceConnectionState::Connected,
            S::Completed => IceConnectionState::Completed,
            S::Disconnected | S::Failed => IceConnectionState::Disconnected,
        }
    }
}

/// An ICE candidate: UDP, or TCP ([`Endpoint::listen_tcp`](crate::Endpoint::listen_tcp) adds a
/// passive one; parsed remote TCP candidates are kept as they are).
#[derive(Clone, PartialEq, Eq)]
pub struct Candidate(pub(crate) only_ice::Candidate);

fn check_addr(addr: SocketAddr) -> Result<(), Error> {
    if addr.ip().is_unspecified() || addr.port() == 0 {
        return Err(Error::InvalidCandidate(format!(
            "{addr}: unspecified address or port"
        )));
    }
    Ok(())
}

impl Candidate {
    /// A host candidate: an address of a local socket.
    pub fn host(addr: SocketAddr) -> Result<Candidate, Error> {
        check_addr(addr)?;
        Ok(Candidate(only_ice::Candidate::host(addr)))
    }

    /// A server-reflexive candidate: `addr` as a STUN server saw the local socket `base`.
    pub fn server_reflexive(addr: SocketAddr, base: SocketAddr) -> Result<Candidate, Error> {
        check_addr(addr)?;
        Ok(Candidate(only_ice::Candidate::server_reflexive(addr, base)))
    }

    /// A relayed candidate: `addr` allocated on a TURN server for the local socket `base`.
    pub fn relayed(addr: SocketAddr, base: SocketAddr) -> Result<Candidate, Error> {
        check_addr(addr)?;
        Ok(Candidate(only_ice::Candidate::relayed(addr, base)))
    }

    /// Parses an SDP candidate (`candidate:...`, with or without `a=`).
    pub fn parse(sdp: &str) -> Result<Candidate, Error> {
        let s = sdp.trim();
        let s = s.strip_prefix("a=").unwrap_or(s);
        only_ice::Candidate::parse(s)
            .map(Candidate)
            .map_err(|e| Error::Sdp(e.to_string()))
    }

    /// The candidate's address.
    pub fn addr(&self) -> SocketAddr {
        self.0.addr()
    }

    /// The SDP form (`candidate:...`).
    pub fn to_sdp(&self) -> String {
        self.0.to_sdp()
    }

    /// The type as the SDP writes it: `"host"`, `"srflx"`, `"prflx"` or `"relay"`.
    pub fn kind(&self) -> &'static str {
        self.0.kind().as_str()
    }

    /// `"udp"`, or `"tcp"` for an ICE-TCP candidate (a relayed candidate is UDP whatever
    /// the transport to its TURN server).
    pub fn transport(&self) -> &'static str {
        if self.0.tcp_type().is_some() {
            "tcp"
        } else {
            "udp"
        }
    }
}

impl fmt::Debug for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Candidate({})", self.to_sdp())
    }
}

// ---- events ----

/// Events without a dedicated [`PeerHandler`](crate::PeerHandler) callback.
#[derive(Debug)]
#[non_exhaustive]
pub enum Event {
    /// The channel's send buffer drained below its low mark: [`Peer::send`](crate::Peer::send)
    /// accepts data again.
    ChannelBufferedAmountLow(ChannelId),
    /// Anything else the WebRTC stack reports (statistics, bandwidth estimates, sender
    /// reports ...). Its `Debug` output describes it; the details are not part of the stable
    /// API.
    Other(OtherEvent),
}

/// An event without a stable representation; see [`Event::Other`].
pub struct OtherEvent(pub(crate) Box<Other>);

impl fmt::Debug for OtherEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

/// The events behind [`OtherEvent`] (crate-private: their shape is not promised).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Other {
    /// The send-side bandwidth estimate changed (bits per second).
    EgressBitrateEstimate(u64),
    /// Periodic statistics ([`RtcConfig::set_stats_interval`]).
    PeerStats {
        bytes_sent: u64,
        bytes_received: u64,
        packets_sent: u64,
        packets_received: u64,
        rtt_ms: Option<u64>,
        /// Round-trip time measured as a receiver (RTCP XR DLRR).
        xr_rtt_ms: Option<u64>,
        /// FEC packets sent.
        fec_sent: u64,
        /// FEC packets received.
        fec_received: u64,
        /// Media packets rebuilt from FEC.
        fec_recovered: u64,
        /// RFC 8888 congestion control feedback is in use instead of transport-wide feedback.
        ccfb: bool,
        /// The DTLS version of the connection (`None` before it is up).
        dtls: Option<&'static str>,
        /// RTP packets received with cryptex (RFC 9335) encrypted headers.
        cryptex_received: u64,
        /// Packets received as redundancy in Opus RED that stood in for a lost one.
        red_recovered: u64,
    },
    /// A sender report arrived for a received stream.
    SenderReport {
        mid: Mid,
        ssrc: u32,
        ntp_time: u64,
        rtp_time: u32,
    },
    /// The remote's selected ICE pair changed.
    IcePair {
        local: SocketAddr,
        remote: SocketAddr,
    },
    /// The remote receivers' TMMBR bounding set limits a sent stream (bits per second;
    /// `None`: no limit any more).
    MaxBitrateRequest {
        mid: Mid,
        ssrc: u32,
        bitrate: Option<u64>,
    },
    /// The remote sender acknowledged a TMMBR with this bounding set (bits per second per
    /// owner SSRC).
    MaxBitrateNotification { ssrc: u32, entries: Vec<(u32, u64)> },
}

// ---- configuration ----

/// The settings behind [`RtcConfig`].
#[derive(Clone, Debug)]
pub(crate) struct ConfigInner {
    pub(crate) codecs: Vec<Codec>,
    pub(crate) rtp_mode: bool,
    pub(crate) stats_interval: Option<Duration>,
    pub(crate) bwe: Option<u64>,
    pub(crate) reorder_audio: usize,
    pub(crate) reorder_video: usize,
    pub(crate) sctp_max_buffered: usize,
    pub(crate) fec: Option<FecMechanism>,
    pub(crate) fec_min: u8,
    pub(crate) fec_max: u8,
    pub(crate) ccfb: bool,
    pub(crate) xr: bool,
    pub(crate) tmmbr: bool,
    pub(crate) ice_renomination: bool,
    pub(crate) ice_aggressive: bool,
    /// DTLS 1.3 offered (with DTLS 1.2 as the fallback).
    pub(crate) dtls13: bool,
    /// Cryptex (RFC 9335) offered and accepted.
    pub(crate) cryptex: bool,
    /// RFC 6904 encrypted header extensions offered and accepted.
    pub(crate) encrypt_ext: bool,
    /// Opus RED (RFC 2198): `None` off, else the redundant blocks sent (0..=2).
    pub(crate) opus_red: Option<u8>,
}

impl Default for ConfigInner {
    fn default() -> Self {
        ConfigInner {
            codecs: vec![
                Codec::Opus,
                Codec::Pcmu,
                Codec::Pcma,
                Codec::Vp8,
                Codec::H264,
                Codec::Vp9,
                Codec::Av1,
            ],
            rtp_mode: false,
            stats_interval: None,
            bwe: None,
            reorder_audio: 15,
            reorder_video: 30,
            sctp_max_buffered: 1 << 20,
            fec: None,
            fec_min: 0,
            fec_max: 128,
            ccfb: false,
            xr: false,
            tmmbr: false,
            ice_renomination: false,
            ice_aggressive: false,
            dtls13: true,
            cryptex: false,
            encrypt_ext: false,
            opus_red: None,
        }
    }
}

/// The configuration of each peer: codecs, RTP mode, bandwidth estimation, statistics ...
/// Start from [`rtc_config`](crate::rtc_config).
pub struct RtcConfig(pub(crate) ConfigInner);

impl fmt::Debug for RtcConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtcConfig")
            .field("codecs", &self.0.codecs)
            .field("rtp_mode", &self.0.rtp_mode)
            .field("stats_interval", &self.0.stats_interval)
            .field("fec", &self.0.fec)
            .field("ccfb", &self.0.ccfb)
            .field("rtcp_xr", &self.0.xr)
            .field("tmmbr", &self.0.tmmbr)
            .field("ice_renomination", &self.0.ice_renomination)
            .field("ice_aggressive_nomination", &self.0.ice_aggressive)
            .field("dtls13", &self.0.dtls13)
            .field("cryptex", &self.0.cryptex)
            .field("encrypted_header_extensions", &self.0.encrypt_ext)
            .field("opus_red", &self.0.opus_red)
            .finish_non_exhaustive()
    }
}

macro_rules! codec_switch {
    ($(#[$doc:meta] $name:ident => $codec:expr;)*) => {
        $(
            #[$doc]
            #[must_use]
            pub fn $name(self, enabled: bool) -> Self {
                self.switch($codec, enabled)
            }
        )*
    };
}

impl RtcConfig {
    fn switch(mut self, c: Codec, on: bool) -> Self {
        self.0.codecs.retain(|x| *x != c);
        if on {
            self.0.codecs.push(c);
        }
        self
    }

    /// Removes every codec (then enable the ones wanted).
    #[must_use]
    pub fn clear_codecs(mut self) -> Self {
        self.0.codecs.clear();
        self
    }

    codec_switch! {
        /// Offers or accepts Opus.
        enable_opus => Codec::Opus;
        /// Offers or accepts G.711 µ-law.
        enable_pcmu => Codec::Pcmu;
        /// Offers or accepts G.711 A-law.
        enable_pcma => Codec::Pcma;
        /// Offers or accepts VP8.
        enable_vp8 => Codec::Vp8;
        /// Offers or accepts VP9.
        enable_vp9 => Codec::Vp9;
        /// Offers or accepts H.264.
        enable_h264 => Codec::H264;
        /// Offers or accepts H.265.
        enable_h265 => Codec::H265;
        /// Offers or accepts AV1.
        enable_av1 => Codec::Av1;
    }

    /// Delivers received RTP packets ([`PeerHandler::on_rtp`](crate::PeerHandler::on_rtp))
    /// instead of depacketized samples.
    #[must_use]
    pub fn set_rtp_mode(mut self, enabled: bool) -> Self {
        self.0.rtp_mode = enabled;
        self
    }

    /// How often statistics events are produced (`None`, the default, never).
    #[must_use]
    pub fn set_stats_interval(mut self, interval: Option<Duration>) -> Self {
        self.0.stats_interval = interval;
        self
    }

    /// Enables send-side bandwidth estimation, starting from `initial_bps` (bits per second).
    #[must_use]
    pub fn enable_bwe(mut self, initial_bps: Option<u64>) -> Self {
        self.0.bwe = Some(initial_bps.unwrap_or(300_000));
        self
    }

    /// Packets held to reorder audio (default 15) and video (default 30).
    #[must_use]
    pub fn set_reordering_size(mut self, audio: usize, video: usize) -> Self {
        self.0.reorder_audio = audio.max(1);
        self.0.reorder_video = video.max(1);
        self
    }

    /// Bytes a data channel may buffer before [`Peer::send`](crate::Peer::send) refuses more.
    #[must_use]
    pub fn set_sctp_max_buffered_amount(mut self, bytes: usize) -> Self {
        self.0.sctp_max_buffered = bytes;
        self
    }

    /// Forward error correction on video lines (`None`, the default, offers and accepts
    /// none). [`FecMechanism::FlexFec`] negotiates `flexfec-03` with an
    /// `a=ssrc-group:FEC-FR` FEC stream, [`FecMechanism::Ulpfec`] negotiates `red` (with its
    /// RTX) and `ulpfec`; either way received FEC repairs lost packets before the
    /// jitter buffer and NACK, and sent video is protected at a rate that follows the loss
    /// the remote receiver reports (see [`set_fec_protection`](Self::set_fec_protection)).
    /// On a simulcast line ULPFEC protects each encoding on its own (its RED stream carries
    /// the encoding's RID), as Chrome sends it; FlexFEC needs an SSRC-signaled FEC stream, which
    /// RID-based simulcast does not have, so simulcast lines get no FlexFEC.
    #[must_use]
    pub fn enable_fec(mut self, mechanism: Option<FecMechanism>) -> Self {
        self.0.fec = mechanism;
        self
    }

    /// Bounds of the FEC protection factor, in FEC packets per 256 media packets (at least
    /// one FEC packet protects each frame while the factor is not 0). Within them the
    /// factor is three times the loss fraction the remote's receiver reports give (smoothed),
    /// 0 below 1 % loss. Defaults: 0 and 128 (at most 50 % overhead).
    #[must_use]
    pub fn set_fec_protection(mut self, min: u8, max: u8) -> Self {
        self.0.fec_min = min.min(max);
        self.0.fec_max = max.max(min);
        self
    }

    /// RTP congestion control feedback (RFC 8888): offers and accepts `a=rtcp-fb:* ack
    /// ccfb`. Once negotiated, received media is acknowledged with RFC 8888 feedback instead
    /// of transport-wide feedback, and the bandwidth estimator ([`enable_bwe`](Self::enable_bwe))
    /// runs on the feedback of that kind. Default off.
    #[must_use]
    pub fn enable_ccfb(mut self, enabled: bool) -> Self {
        self.0.ccfb = enabled;
        self
    }

    /// RTCP extended reports for a receiver's round-trip time (RFC 3611): offers and accepts
    /// `a=rtcp-xr:rcvr-rtt=all` (and libwebrtc's `rrtr` feedback on video); once negotiated
    /// the receiver reports carry a receiver reference time, the sender's DLRR answer gives
    /// the RTT that paces NACKs even on lines that send nothing. A received reference time
    /// is always answered. Default off.
    #[must_use]
    pub fn enable_rtcp_xr(mut self, enabled: bool) -> Self {
        self.0.xr = enabled;
        self
    }

    /// TMMBR / TMMBN (RFC 5104): offers and accepts `a=rtcp-fb:<pt> ccm tmmbr` on video.
    /// Received requests are always answered with a TMMBN and cap the bandwidth estimate;
    /// [`Peer::request_max_bitrate`](crate::Peer::request_max_bitrate) sends them. Default
    /// off.
    #[must_use]
    pub fn enable_tmmbr(mut self, enabled: bool) -> Self {
        self.0.tmmbr = enabled;
        self
    }

    /// ICE renomination (draft-thatcher-ice-renomination): advertises
    /// `a=ice-options:trickle renomination`; when the remote advertises it too and this peer
    /// is controlling (the offerer, or against an ICE-lite remote), checks of better pairs go
    /// on after nomination and a better pair that works later is nominated again (STUN
    /// NOMINATION attribute), e.g. one made of a candidate trickled late. A controlled peer
    /// always follows the highest NOMINATION value it receives. Default off.
    #[must_use]
    pub fn enable_ice_renomination(mut self, enabled: bool) -> Self {
        self.0.ice_renomination = enabled;
        self
    }

    /// ICE aggressive nomination (RFC 5245 §8.1.1.2) when this peer is controlling: every
    /// connectivity check carries USE-CANDIDATE, the first pair that works is used at once
    /// and the best one that works in the end replaces it (on both sides). Peers expecting
    /// RFC 5245 agents may want it; a controlled peer always selects the best nominated pair.
    /// Default off (regular nomination, RFC 8445).
    #[must_use]
    pub fn enable_ice_aggressive_nomination(mut self, enabled: bool) -> Self {
        self.0.ice_aggressive = enabled;
        self
    }

    /// DTLS 1.3 (RFC 9147) for the DTLS-SRTP handshake: a client sends a DTLS 1.3 ClientHello
    /// that DTLS 1.2 servers answer with DTLS 1.2, a server picks DTLS 1.3 when the client
    /// offers it and DTLS 1.2 otherwise. Nothing changes in SDP (the version is negotiated in
    /// the handshake; Chrome 157 negotiates DTLS 1.3 in either role). Default on; `false`
    /// speaks DTLS 1.2 only.
    #[must_use]
    pub fn enable_dtls13(mut self, enabled: bool) -> Self {
        self.0.dtls13 = enabled;
        self
    }

    /// Cryptex (RFC 9335): offers `a=cryptex` and accepts it in a remote offer. Once both
    /// sides signaled it, every sent RTP packet with header extensions or CSRCs has them
    /// encrypted (`0xC0DE` / `0xC2DE`); received packets are decrypted either way. Chrome 157
    /// offers it with `rtpHeaderEncryptionPolicy` (behind
    /// `--enable-experimental-web-platform-features`). Default off.
    #[must_use]
    pub fn enable_cryptex(mut self, enabled: bool) -> Self {
        self.0.cryptex = enabled;
        self
    }

    /// RFC 6904 encrypted header extensions: offers the audio level extension (RFC 6464) also
    /// as `urn:ietf:params:rtp-hdrext:encrypt`, and answers an offer's encrypted variant of
    /// any extension with that variant. Negotiated extensions so marked have their values
    /// encrypted in SRTP (on packets not sent with cryptex). Browsers do not offer it.
    /// Default off.
    #[must_use]
    pub fn enable_encrypted_header_extensions(mut self, enabled: bool) -> Self {
        self.0.encrypt_ext = enabled;
        self
    }

    /// Opus RED (RFC 2198, `red/48000/2` with `fmtp <red> <opus>/<opus>`), offered after Opus
    /// as Chrome does and accepted when offered. `None` (the default) negotiates no RED.
    /// With `Some(n)`, received RED is split: a redundant copy of a lost packet stands in for
    /// it (duplicates are dropped); sent Opus goes in RED with up to `n` (at most 2) earlier
    /// packets as redundancy, or plain with `Some(0)`. Chrome sends RED whenever it is
    /// negotiated.
    #[must_use]
    pub fn enable_opus_red(mut self, redundancy: Option<u8>) -> Self {
        self.0.opus_red = redundancy.map(|n| n.min(2));
        self
    }
}

/// A forward error correction scheme for video ([`RtcConfig::enable_fec`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FecMechanism {
    /// FlexFEC as libwebrtc sends it (`flexfec-03`): a separate FEC stream signaled with
    /// `a=ssrc-group:FEC-FR`. Chrome needs the field trials `WebRTC-FlexFEC-03-Advertised`
    /// (to offer it) and `WebRTC-FlexFEC-03` (to send it).
    FlexFec,
    /// ULPFEC (RFC 5109) carried in RED (RFC 2198) on the media stream; browsers offer it
    /// by default.
    Ulpfec,
}

/// One change requested through [`SdpChanges`].
#[derive(Debug, Clone)]
pub(crate) enum Change {
    AddChannel(ChannelId, ChannelConfig),
    AddMedia {
        mid: Mid,
        kind: MediaKind,
        dir: Direction,
        stream_id: Option<String>,
        track_id: Option<String>,
        /// Simulcast RIDs (empty: no simulcast).
        rids: Vec<String>,
    },
    SetDirection(Mid, Direction),
    StopMedia(Mid),
    IceRestart(bool),
}

/// The pending change set behind [`SdpChanges`].
#[derive(Debug)]
pub(crate) struct Changes<'b> {
    pub(crate) next_channel: usize,
    pub(crate) next_mid: usize,
    pub(crate) ops: Vec<Change>,
    pub(crate) _rtc: PhantomData<&'b ()>,
}

/// Changes to a session, made in the closure of `create_offer` or
/// [`Peer::renegotiate`](crate::Peer::renegotiate): add media lines and data channels, change
/// directions, restart ICE.
pub struct SdpChanges<'a, 'b>(pub(crate) &'a mut Changes<'b>);

impl fmt::Debug for SdpChanges<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SdpChanges")
            .field("has_changes", &self.has_changes())
            .finish()
    }
}

impl SdpChanges<'_, '_> {
    /// Adds a reliable, ordered data channel.
    pub fn add_channel(&mut self, label: impl Into<String>) -> ChannelId {
        self.add_channel_with_config(&ChannelConfig::new(label))
    }

    /// Adds a data channel configured by `cfg`.
    pub fn add_channel_with_config(&mut self, cfg: &ChannelConfig) -> ChannelId {
        let id = ChannelId(self.0.next_channel);
        self.0.next_channel += 1;
        self.0.ops.push(Change::AddChannel(id, cfg.clone()));
        id
    }

    /// Adds a media line; `stream_id` and `track_id` go into its `a=msid`.
    pub fn add_media(
        &mut self,
        kind: MediaKind,
        dir: Direction,
        stream_id: Option<String>,
        track_id: Option<String>,
    ) -> Mid {
        let mid = Mid::new(&self.0.next_mid.to_string());
        self.0.next_mid += 1;
        self.0.ops.push(Change::AddMedia {
            mid,
            kind,
            dir,
            stream_id,
            track_id,
            rids: Vec::new(),
        });
        mid
    }

    /// Adds a media line that sends simulcast (RFC 8853): one RTP stream per RID in `rids`
    /// (highest quality first, as browsers order them; 1 to 8 RIDs of letters, digits, `-`
    /// and `_`, at most 16 characters each), identified by the RTP stream id header extension
    /// and each with its own RTX stream. The offer lists them with `a=rid:<id> send` and
    /// `a=simulcast:send`; the answer's `a=simulcast:recv` decides which are sent (only the
    /// first when it has none). Write each encoding's samples with
    /// [`Peer::write_simulcast`](crate::Peer::write_simulcast). `dir` must send.
    pub fn add_simulcast_media(
        &mut self,
        kind: MediaKind,
        dir: Direction,
        rids: &[&str],
        stream_id: Option<String>,
        track_id: Option<String>,
    ) -> Result<Mid, Error> {
        if !dir.sends() {
            return Err(Error::Sdp("simulcast needs a sending direction".into()));
        }
        if rids.is_empty() || rids.len() > crate::rtc::MAX_SIMULCAST {
            return Err(Error::Sdp("simulcast needs 1 to 8 RIDs".into()));
        }
        for (i, r) in rids.iter().enumerate() {
            if !crate::rtc::valid_rid(r) || rids[..i].contains(r) {
                return Err(Error::Sdp(format!("bad or repeated RID {r:?}")));
            }
        }
        let mid = Mid::new(&self.0.next_mid.to_string());
        self.0.next_mid += 1;
        self.0.ops.push(Change::AddMedia {
            mid,
            kind,
            dir,
            stream_id,
            track_id,
            rids: rids.iter().map(|r| (*r).to_owned()).collect(),
        });
        Ok(mid)
    }

    /// Changes the direction of a media line.
    pub fn set_direction(&mut self, mid: Mid, dir: Direction) {
        self.0.ops.push(Change::SetDirection(mid, dir));
    }

    /// Stops a media line.
    pub fn stop_media(&mut self, mid: Mid) {
        self.0.ops.push(Change::StopMedia(mid));
    }

    /// Restarts ICE with new credentials.
    pub fn ice_restart(&mut self, keep_local_candidates: bool) {
        self.0.ops.push(Change::IceRestart(keep_local_candidates));
    }

    /// Whether anything was changed.
    pub fn has_changes(&self) -> bool {
        !self.0.ops.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_time_and_frequency() {
        let t = MediaTime::new(96_000, Frequency::FORTY_EIGHT_KHZ);
        assert_eq!(t.as_duration(), Duration::from_secs(2));
        assert_eq!((t.ticks(), t.rate().get()), (96_000, 48_000));
        assert_eq!(t.ticks_at(90_000), 180_000);
        assert_eq!(
            MediaTime::new(45_000, Frequency::NINETY_KHZ).as_duration(),
            Duration::from_millis(500)
        );
        assert!(Frequency::new(0).is_none());
        assert_eq!(Frequency::new(8000), Some(Frequency::EIGHT_KHZ));
    }

    #[test]
    fn ids_and_codecs() {
        let m = Mid::new("audio-0123456789-too-long");
        assert_eq!(m.as_str().len(), MID_MAX);
        assert!(Mid::new("a") < Mid::new("b"));
        assert_eq!(Mid::new("x").to_string(), "x");
        assert!(format!("{:?}", Mid::new("x")).starts_with("Mid("));
        let p = Pt::from(111);
        assert_eq!(u8::from(p), p.get());
        for c in Codec::ALL {
            assert_eq!(Codec::from_name(c.name()), Some(c));
        }
        assert_eq!(Codec::from_name("rtx"), None);
        assert_eq!(
            Direction::SendRecv.intersect(Direction::RecvOnly.reverse()),
            Direction::SendOnly
        );
        let cfg = ChannelConfig {
            reliability: Reliability::MaxPacketLifetime { lifetime: 5 },
            ..ChannelConfig::new("x")
        };
        assert_eq!(cfg.to_sctp().label, "x");
    }

    #[test]
    fn candidates() {
        let a: SocketAddr = "192.0.2.1:5000".parse().unwrap();
        let b: SocketAddr = "198.51.100.1:6000".parse().unwrap();
        let h = Candidate::host(a).unwrap();
        assert_eq!(h.addr(), a);
        let parsed = Candidate::parse(&format!("a={}", h.to_sdp())).unwrap();
        assert_eq!(parsed.addr(), a);
        assert!(format!("{h:?}").starts_with("Candidate(candidate:"));
        assert_eq!(Candidate::server_reflexive(b, a).unwrap().addr(), b);
        assert_eq!(Candidate::relayed(b, a).unwrap().addr(), b);
        assert!(Candidate::parse("nonsense").is_err());
        assert!(Candidate::host("0.0.0.0:1".parse().unwrap()).is_err());
    }

    #[test]
    fn rtc_config_switches() {
        let cfg = crate::rtc_config()
            .clear_codecs()
            .enable_opus(true)
            .enable_pcmu(true)
            .enable_pcma(false)
            .enable_vp8(true)
            .enable_vp9(false)
            .enable_h264(true)
            .enable_h265(false)
            .enable_av1(false)
            .set_rtp_mode(false)
            .set_stats_interval(Some(Duration::from_secs(1)))
            .enable_bwe(Some(1_000_000))
            .set_reordering_size(10, 20)
            .set_sctp_max_buffered_amount(1 << 20);
        assert!(format!("{cfg:?}").contains("rtp_mode"));
        assert_eq!(
            cfg.0.codecs,
            vec![Codec::Opus, Codec::Pcmu, Codec::Vp8, Codec::H264]
        );
        let mut ch = Changes {
            next_channel: 0,
            next_mid: 0,
            ops: Vec::new(),
            _rtc: PhantomData,
        };
        let mut api = SdpChanges(&mut ch);
        assert!(!api.has_changes());
        let mid = api.add_media(MediaKind::Audio, Direction::SendRecv, None, None);
        api.set_direction(mid, Direction::SendOnly);
        let c = api.add_channel("c");
        let d = api.add_channel_with_config(&ChannelConfig::new("d"));
        assert_ne!(c, d);
        assert!(api.has_changes());
        assert!(format!("{api:?}").contains("true"));
        api.ice_restart(true);
        api.stop_media(mid);
        assert_eq!(mid.as_str(), "0");
    }
}
