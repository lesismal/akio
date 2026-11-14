//! This crate's own WebRTC types: ids, media descriptions, events, candidates, the per-peer
//! configuration and the SDP change set. They hide str0m, so it can be upgraded or replaced
//! without breaking this API; raw access is behind the `unstable` cargo feature.

use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use str0m::change::SdpApi;

use crate::Error;

/// Conversions between this crate's types and the wrapped implementation's (crate-private, so
/// they stay out of the public API).
pub(crate) trait Own<T> {
    fn own(self) -> T;
}

// ---- ids ----

/// A data channel id.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelId(pub(crate) str0m::channel::ChannelId);

impl fmt::Debug for ChannelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChannelId({:?})", self.0)
    }
}

/// A media line id (`a=mid:` in the SDP).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Mid(pub(crate) str0m::media::Mid);

impl Mid {
    /// The id as it appears in the SDP.
    pub fn as_str(&self) -> &str {
        &self.0
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

impl Own<Pt> for str0m::media::Pt {
    fn own(self) -> Pt {
        let p = self;
        Pt(*p)
    }
}

impl Own<str0m::media::Pt> for Pt {
    fn own(self) -> str0m::media::Pt {
        let p = self;
        str0m::media::Pt::from(p.0)
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

    pub(crate) fn to_str0m(&self) -> str0m::channel::ChannelConfig {
        str0m::channel::ChannelConfig {
            label: self.label.clone(),
            ordered: self.ordered,
            reliability: match self.reliability {
                Reliability::Reliable => str0m::channel::Reliability::Reliable,
                Reliability::MaxPacketLifetime { lifetime } => {
                    str0m::channel::Reliability::MaxPacketLifetime { lifetime }
                }
                Reliability::MaxRetransmits { retransmits } => {
                    str0m::channel::Reliability::MaxRetransmits { retransmits }
                }
            },
            negotiated: self.negotiated,
            protocol: self.protocol.clone(),
        }
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

impl Own<str0m::media::MediaKind> for MediaKind {
    fn own(self) -> str0m::media::MediaKind {
        let k = self;
        match k {
            MediaKind::Audio => str0m::media::MediaKind::Audio,
            MediaKind::Video => str0m::media::MediaKind::Video,
        }
    }
}

impl Own<MediaKind> for str0m::media::MediaKind {
    fn own(self) -> MediaKind {
        let k = self;
        match k {
            str0m::media::MediaKind::Audio => MediaKind::Audio,
            str0m::media::MediaKind::Video => MediaKind::Video,
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

impl Own<str0m::media::Direction> for Direction {
    fn own(self) -> str0m::media::Direction {
        let d = self;
        match d {
            Direction::Inactive => str0m::media::Direction::Inactive,
            Direction::RecvOnly => str0m::media::Direction::RecvOnly,
            Direction::SendOnly => str0m::media::Direction::SendOnly,
            Direction::SendRecv => str0m::media::Direction::SendRecv,
        }
    }
}

impl Own<Direction> for str0m::media::Direction {
    fn own(self) -> Direction {
        let d = self;
        match d {
            str0m::media::Direction::Inactive => Direction::Inactive,
            str0m::media::Direction::RecvOnly => Direction::RecvOnly,
            str0m::media::Direction::SendOnly => Direction::SendOnly,
            str0m::media::Direction::SendRecv => Direction::SendRecv,
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
    fn to_str0m(self) -> str0m::format::Codec {
        use str0m::format::Codec as C;
        match self {
            Codec::Opus => C::Opus,
            Codec::Pcmu => C::PCMU,
            Codec::Pcma => C::PCMA,
            Codec::G722 => C::G722,
            Codec::H264 => C::H264,
            Codec::H265 => C::H265,
            Codec::Vp8 => C::Vp8,
            Codec::Vp9 => C::Vp9,
            Codec::Av1 => C::Av1,
        }
    }

    pub(crate) fn matches(self, c: str0m::format::Codec) -> bool {
        self.to_str0m() == c
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

    pub(crate) fn to_str0m(self) -> str0m::media::MediaTime {
        str0m::media::MediaTime::new(
            self.ticks,
            str0m::media::Frequency::from_nonzero(self.rate.0),
        )
    }
}

impl Own<MediaTime> for str0m::media::MediaTime {
    fn own(self) -> MediaTime {
        let t = self;
        MediaTime {
            ticks: t.numer(),
            rate: Frequency(t.frequency().nonzero()),
        }
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

impl Own<str0m::media::KeyframeRequestKind> for KeyframeRequestKind {
    fn own(self) -> str0m::media::KeyframeRequestKind {
        let k = self;
        match k {
            KeyframeRequestKind::Pli => str0m::media::KeyframeRequestKind::Pli,
            KeyframeRequestKind::Fir => str0m::media::KeyframeRequestKind::Fir,
        }
    }
}

impl Own<KeyframeRequestKind> for str0m::media::KeyframeRequestKind {
    fn own(self) -> KeyframeRequestKind {
        let k = self;
        match k {
            str0m::media::KeyframeRequestKind::Pli => KeyframeRequestKind::Pli,
            str0m::media::KeyframeRequestKind::Fir => KeyframeRequestKind::Fir,
        }
    }
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

impl Own<KeyframeRequest> for str0m::media::KeyframeRequest {
    fn own(self) -> KeyframeRequest {
        let k = self;
        KeyframeRequest {
            mid: Mid(k.mid),
            rid: k.rid.map(|r| r.to_string()),
            kind: k.kind.own(),
        }
    }
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

impl Own<MediaAdded> for str0m::media::MediaAdded {
    fn own(self) -> MediaAdded {
        let m = self;
        MediaAdded {
            mid: Mid(m.mid),
            kind: m.kind.own(),
            direction: m.direction.own(),
        }
    }
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

fn own_codec(c: str0m::format::Codec) -> Option<Codec> {
    [
        Codec::Opus,
        Codec::Pcmu,
        Codec::Pcma,
        Codec::G722,
        Codec::H264,
        Codec::H265,
        Codec::Vp8,
        Codec::Vp9,
        Codec::Av1,
    ]
    .into_iter()
    .find(|o| o.matches(c))
}

impl Own<MediaData> for str0m::media::MediaData {
    fn own(self) -> MediaData {
        let d = self;
        MediaData {
            mid: Mid(d.mid),
            pt: d.pt.own(),
            rid: d.rid.map(|r| r.to_string()),
            codec: own_codec(d.params.spec().codec),
            time: d.time.own(),
            network_time: d.network_time,
            contiguous: d.contiguous,
            data: d.data,
        }
    }
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

impl Own<RtpPacket> for str0m::rtp::RtpPacket {
    fn own(self) -> RtpPacket {
        let p = self;
        RtpPacket {
            seq_no: *p.seq_no,
            ssrc: *p.header.ssrc,
            pt: p.header.payload_type.own(),
            marker: p.header.marker,
            rtp_time: p.header.timestamp,
            time: p.time.own(),
            received: p.timestamp,
            payload: p.payload,
        }
    }
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

impl Own<IceConnectionState> for str0m::IceConnectionState {
    fn own(self) -> IceConnectionState {
        let s = self;
        match s {
            str0m::IceConnectionState::New => IceConnectionState::New,
            str0m::IceConnectionState::Checking => IceConnectionState::Checking,
            str0m::IceConnectionState::Connected => IceConnectionState::Connected,
            str0m::IceConnectionState::Completed => IceConnectionState::Completed,
            str0m::IceConnectionState::Disconnected => IceConnectionState::Disconnected,
        }
    }
}

/// A local ICE candidate (UDP).
#[derive(Clone, PartialEq, Eq)]
pub struct Candidate(pub(crate) str0m::Candidate);

impl Candidate {
    /// A host candidate: an address of a local socket.
    pub fn host(addr: SocketAddr) -> Result<Candidate, Error> {
        str0m::Candidate::host(addr, "udp")
            .map(Candidate)
            .map_err(|e| Error::InvalidCandidate(e.to_string()))
    }

    /// A server-reflexive candidate: `addr` as a STUN server saw the local socket `base`.
    pub fn server_reflexive(addr: SocketAddr, base: SocketAddr) -> Result<Candidate, Error> {
        str0m::Candidate::server_reflexive(addr, base, "udp")
            .map(Candidate)
            .map_err(|e| Error::InvalidCandidate(e.to_string()))
    }

    /// A relayed candidate: `addr` allocated on a TURN server for the local socket `base`.
    pub fn relayed(addr: SocketAddr, base: SocketAddr) -> Result<Candidate, Error> {
        str0m::Candidate::relayed(addr, base, "udp")
            .map(Candidate)
            .map_err(|e| Error::InvalidCandidate(e.to_string()))
    }

    /// Parses an SDP candidate (`candidate:...`, with or without `a=`).
    pub fn parse(sdp: &str) -> Result<Candidate, Error> {
        let s = sdp.trim().trim_start_matches("a=");
        str0m::Candidate::from_sdp_string(s)
            .map(Candidate)
            .map_err(|e| Error::Sdp(e.to_string()))
    }

    /// The candidate's address.
    pub fn addr(&self) -> SocketAddr {
        self.0.addr()
    }

    /// The SDP form (`candidate:...`).
    pub fn to_sdp(&self) -> String {
        self.0.to_sdp_string()
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
pub struct OtherEvent(pub(crate) Box<str0m::Event>);

impl OtherEvent {
    /// The str0m event. **Unstable** (cargo feature `unstable`, outside the semver promise).
    #[cfg(feature = "unstable")]
    pub fn as_str0m(&self) -> &str0m::Event {
        &self.0
    }
}

impl fmt::Debug for OtherEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

// ---- configuration ----

/// The configuration of each peer: codecs, RTP mode, bandwidth estimation, statistics ...
/// Start from [`rtc_config`](crate::rtc_config).
pub struct RtcConfig(pub(crate) str0m::RtcConfig);

impl fmt::Debug for RtcConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtcConfig")
            .field("rtp_mode", &self.0.rtp_mode())
            .field("stats_interval", &self.0.stats_interval())
            .finish_non_exhaustive()
    }
}

macro_rules! codec_switch {
    ($(#[$doc:meta] $name:ident => $inner:ident $(, $red:expr)?;)*) => {
        $(
            #[$doc]
            #[must_use]
            pub fn $name(self, enabled: bool) -> Self {
                RtcConfig(self.0.$inner(enabled $(, $red)?))
            }
        )*
    };
}

impl RtcConfig {
    /// Removes every codec (then enable the ones wanted).
    #[must_use]
    pub fn clear_codecs(self) -> Self {
        RtcConfig(self.0.clear_codecs())
    }

    codec_switch! {
        /// Offers or accepts Opus.
        enable_opus => enable_opus, false;
        /// Offers or accepts G.711 µ-law.
        enable_pcmu => enable_pcmu, false;
        /// Offers or accepts G.711 A-law.
        enable_pcma => enable_pcma, false;
        /// Offers or accepts VP8.
        enable_vp8 => enable_vp8;
        /// Offers or accepts VP9.
        enable_vp9 => enable_vp9;
        /// Offers or accepts H.264.
        enable_h264 => enable_h264;
        /// Offers or accepts H.265.
        enable_h265 => enable_h265;
        /// Offers or accepts AV1.
        enable_av1 => enable_av1;
    }

    /// Delivers received RTP packets ([`PeerHandler::on_rtp`](crate::PeerHandler::on_rtp))
    /// instead of depacketized samples, and sends packets the application builds.
    #[must_use]
    pub fn set_rtp_mode(self, enabled: bool) -> Self {
        RtcConfig(self.0.set_rtp_mode(enabled))
    }

    /// How often statistics events are produced (`None`, the default, never).
    #[must_use]
    pub fn set_stats_interval(self, interval: Option<Duration>) -> Self {
        RtcConfig(self.0.set_stats_interval(interval))
    }

    /// Enables send-side bandwidth estimation, starting from `initial_bps` (bits per second).
    #[must_use]
    pub fn enable_bwe(self, initial_bps: Option<u64>) -> Self {
        RtcConfig(self.0.enable_bwe(initial_bps.map(str0m::bwe::Bitrate::bps)))
    }

    /// Packets held to reorder audio (default 15) and video (default 30).
    #[must_use]
    pub fn set_reordering_size(self, audio: usize, video: usize) -> Self {
        RtcConfig(
            self.0
                .set_reordering_size_audio(audio)
                .set_reordering_size_video(video),
        )
    }

    /// Bytes a data channel may buffer before [`Peer::send`](crate::Peer::send) refuses more.
    #[must_use]
    pub fn set_sctp_max_buffered_amount(self, bytes: usize) -> Self {
        RtcConfig(self.0.set_sctp_max_buffered_amount(bytes))
    }

    /// Changes the str0m configuration. **Unstable** (cargo feature `unstable`, outside the
    /// semver promise).
    #[cfg(feature = "unstable")]
    #[must_use]
    pub fn with_str0m(self, f: impl FnOnce(str0m::RtcConfig) -> str0m::RtcConfig) -> Self {
        RtcConfig(f(self.0))
    }
}

/// Changes to a session, made in the closure of `create_offer` or
/// [`Peer::renegotiate`](crate::Peer::renegotiate): add media lines and data channels, change
/// directions, restart ICE.
pub struct SdpChanges<'a, 'b>(pub(crate) &'a mut SdpApi<'b>);

impl fmt::Debug for SdpChanges<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SdpChanges")
            .field("has_changes", &self.0.has_changes())
            .finish()
    }
}

impl SdpChanges<'_, '_> {
    /// Adds a reliable, ordered data channel.
    pub fn add_channel(&mut self, label: impl Into<String>) -> ChannelId {
        ChannelId(self.0.add_channel(label.into()))
    }

    /// Adds a data channel configured by `cfg`.
    pub fn add_channel_with_config(&mut self, cfg: &ChannelConfig) -> ChannelId {
        ChannelId(self.0.add_channel_with_config(cfg.to_str0m()))
    }

    /// Adds a media line; `stream_id` and `track_id` go into its `a=msid`.
    pub fn add_media(
        &mut self,
        kind: MediaKind,
        dir: Direction,
        stream_id: Option<String>,
        track_id: Option<String>,
    ) -> Mid {
        Mid(self
            .0
            .add_media(kind.own(), dir.own(), stream_id, track_id, None))
    }

    /// Changes the direction of a media line.
    pub fn set_direction(&mut self, mid: Mid, dir: Direction) {
        self.0.set_direction(mid.0, dir.own());
    }

    /// Stops a media line.
    pub fn stop_media(&mut self, mid: Mid) {
        self.0.stop_media(mid.0);
    }

    /// Restarts ICE with new credentials.
    pub fn ice_restart(&mut self, keep_local_candidates: bool) {
        let _ = self.0.ice_restart(keep_local_candidates);
    }

    /// Whether anything was changed.
    pub fn has_changes(&self) -> bool {
        self.0.has_changes()
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
        assert_eq!(Own::<MediaTime>::own(t.to_str0m()), t);
        assert_eq!(
            MediaTime::new(45_000, Frequency::NINETY_KHZ).as_duration(),
            Duration::from_millis(500)
        );
        assert!(Frequency::new(0).is_none());
        assert_eq!(Frequency::new(8000), Some(Frequency::EIGHT_KHZ));
    }

    /// Converts to the wrapped type and back.
    fn rt<A: Own<B>, B: Own<A>>(a: A) -> A {
        a.own().own()
    }

    #[test]
    fn conversions_round_trip() {
        for k in [MediaKind::Audio, MediaKind::Video] {
            assert_eq!(rt::<_, str0m::media::MediaKind>(k), k);
        }
        for d in [
            Direction::Inactive,
            Direction::RecvOnly,
            Direction::SendOnly,
            Direction::SendRecv,
        ] {
            assert_eq!(rt::<_, str0m::media::Direction>(d), d);
        }
        for k in [KeyframeRequestKind::Pli, KeyframeRequestKind::Fir] {
            assert_eq!(rt::<_, str0m::media::KeyframeRequestKind>(k), k);
        }
        let p = Pt::from(111);
        assert_eq!(rt::<_, str0m::media::Pt>(p), p);
        assert_eq!(u8::from(p), p.get());
        for c in [
            Codec::Opus,
            Codec::Pcmu,
            Codec::Pcma,
            Codec::G722,
            Codec::H264,
            Codec::H265,
            Codec::Vp8,
            Codec::Vp9,
            Codec::Av1,
        ] {
            assert_eq!(own_codec(c.to_str0m()), Some(c));
        }
        assert_eq!(own_codec(str0m::format::Codec::Rtx), None);
        let cfg = ChannelConfig {
            reliability: Reliability::MaxPacketLifetime { lifetime: 5 },
            ..ChannelConfig::new("x")
        };
        assert_eq!(cfg.to_str0m().label, "x");
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
    }

    #[test]
    fn rtc_config_and_sdp_changes() {
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
        let mut rtc = cfg.0.build(Instant::now());
        let mut api = rtc.sdp_api();
        let mut ch = SdpChanges(&mut api);
        assert!(!ch.has_changes());
        let mid = ch.add_media(
            MediaKind::Audio,
            Direction::SendRecv,
            Some("s".into()),
            Some("t".into()),
        );
        ch.set_direction(mid, Direction::SendOnly);
        let _ = ch.add_channel("c");
        let _ = ch.add_channel_with_config(&ChannelConfig::new("d"));
        assert!(ch.has_changes());
        assert!(format!("{ch:?}").contains("true"));
        ch.ice_restart(true);
        assert!(!mid.as_str().is_empty());
        assert_eq!(mid.to_string(), mid.as_str());
        assert!(format!("{mid:?}").starts_with("Mid("));
    }
}
