#![forbid(unsafe_code)]
//! WebRTC for `only`: an in-house, sans-io WebRTC stack driven by `only` UDP sockets, with no
//! third-party dependencies.
//!
//! The protocol layers are crates of their own: ICE (full agent and ICE-lite, consent
//! freshness, trickle, restarts: `only-ice`), DTLS 1.3 (falling back to DTLS 1.2) with
//! DTLS-SRTP and certificate fingerprint verification (`only-dtls`), SRTP/SRTCP with
//! AES-CM-HMAC-SHA1-80/32 and AEAD-AES-128/256-GCM, cryptex and encrypted header extensions
//! (`only-srtp`), RTP/RTCP with packetization of Opus, G.711, G.722, VP8,
//! VP9, H.264, H.265 and AV1, NACK and RTX, PLI/FIR, sender and receiver reports, TWCC and
//! bandwidth estimation (`only-rtp`), and SCTP data channels with DCEP (reliable or not,
//! ordered or not: `only-sctp`). This crate adds SDP offer/answer (BUNDLE, rtcp-mux,
//! codec/extension negotiation, renegotiation), drives the peers with `only` I/O threads and a
//! shared timer thread, and keeps the per-peer callback ordering.
//!
//! Two ways to put peers on the network:
//!
//! - [`RtcServer`] serves a [`only::Listener::udp`]: every peer of the server shares the one
//!   port. It runs ICE-lite by default (the server only answers connectivity checks, which is
//!   what an SFU, a WHIP/WHEP endpoint or any publicly reachable server wants) and demultiplexes
//!   datagrams by the ICE username, then by source address.
//! - [`Endpoint`] owns a UDP socket bound at run time ([`only::Engine::bind_udp`]) and runs a
//!   full ICE agent: it sends connectivity checks to remote candidates, can learn its
//!   server-reflexive address from a STUN server ([`Endpoint::gather_srflx`]), and talks to
//!   ICE-lite servers, browsers, pion or another `Endpoint`.
//!
//! Each peer is a [`Peer`] (cheap to clone, usable from any thread) with a [`PeerHandler`].
//! A peer's callbacks run one at a time, in order, on the I/O thread that read the datagram, on
//! the timer thread or on the thread that called a [`Peer`] method; they must not block.
//!
//! The API uses this crate's own types ([`ChannelId`], [`Mid`], [`MediaData`], [`RtcConfig`],
//! [`SdpChanges`] ...); the `unstable` cargo feature adds nothing today.
//!
//! ```no_run
//! use only::{Engine, Listener};
//! use only_webrtc::{ChannelId, Peer, PeerHandler, RtcServer};
//!
//! struct Echo;
//! impl PeerHandler for Echo {
//!     fn on_channel_data(&mut self, p: &Peer, id: ChannelId, data: &[u8], binary: bool) {
//!         let _ = p.send(id, data, binary);
//!     }
//! }
//!
//! // The address browsers reach the listener at goes into the SDP as the host candidate.
//! let server = RtcServer::new(vec!["203.0.113.7:3478".parse().unwrap()]);
//! let engine = Engine::builder()
//!     .listen(Listener::udp("0.0.0.0:3478".parse().unwrap()).serve(server.clone()))
//!     .build()
//!     .unwrap();
//! engine.start().unwrap();
//! // From the signalling (an HTTP handler, WHIP/WHEP, a WebSocket ...):
//! # let offer_sdp = String::new();
//! let (_peer, answer_sdp) = server.accept_offer(&offer_sdp, Echo).unwrap();
//! # let _ = answer_sdp;
//! ```
//!
//! Guide: [WebRTC, STUN and TURN](https://lesismal.github.io/only/en/protocols/webrtc.html)
//! (中文: [WebRTC、STUN 与 TURN](https://lesismal.github.io/only/zh-CN/protocols/webrtc.html)).
#![warn(clippy::unwrap_used)]

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
mod mdns;
mod relay;
mod rtc;
mod sdp;
mod tcp;
mod timer;
mod types;

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::time::{Duration, Instant};

pub use crate::relay::RelayServer;
use crate::rtc::{Output, Rtc, RtcErr, RtcEvent};
pub use crate::tcp::{IceTcp, RtcTcp};
use crate::types::ConfigInner;
pub use crate::types::{
    BundlePolicy, Candidate, ChannelConfig, ChannelId, ChannelPriority, ChannelScheduler, Codec,
    Direction, EcnMarking, Event, FecMask, FecMechanism, Frequency, IceConnectionState,
    KeyframeRequest, KeyframeRequestKind, Latching, MediaAdded, MediaData, MediaKind, MediaTime,
    Mid, OtherEvent, Pt, Reliability, RtcConfig, RtcpMuxPolicy, RtpPacket, SdpChanges, XrBlocks,
};
use only::{Acceptor, Conn, Engine, Handler, UdpBinding};
use only_turn::stun;
/// The WebRTC stack refused an operation.
pub struct RtcError(String);

impl fmt::Debug for RtcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for RtcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for RtcError {}

pub(crate) fn rtc_err(e: RtcErr) -> Error {
    Error::Rtc(RtcError(e.0))
}

/// Errors of [`Peer`], [`RtcServer`] and [`Endpoint`] calls.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An SDP offer or answer did not parse.
    Sdp(String),
    /// The WebRTC stack refused the operation.
    Rtc(RtcError),
    /// The peer is closed.
    Closed,
    /// No such data channel (or it is not open).
    UnknownChannel,
    /// No such media (`Mid`), or it cannot send.
    UnknownMedia,
    /// [`Peer::accept_answer`] without an offer pending.
    NoPendingOffer,
    /// A socket error.
    Io(io::Error),
    /// No answer from the STUN server in time.
    Timeout,
    /// A candidate could not be made from these addresses.
    InvalidCandidate(String),
    /// The server or endpoint already has its maximum of peers
    /// ([`RtcServer::max_peers`], [`Endpoint::max_peers`]).
    TooManyPeers,
    /// A TURN server refused the allocation, or the endpoint has its maximum of TURN
    /// allocations ([`Endpoint::gather_relay`]).
    Turn(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Sdp(e) => write!(f, "webrtc: bad SDP: {e}"),
            Error::Rtc(e) => write!(f, "webrtc: {e}"),
            Error::Closed => f.write_str("webrtc: peer closed"),
            Error::UnknownChannel => f.write_str("webrtc: unknown data channel"),
            Error::UnknownMedia => f.write_str("webrtc: unknown media"),
            Error::NoPendingOffer => f.write_str("webrtc: no offer pending"),
            Error::Io(e) => write!(f, "webrtc: {e}"),
            Error::Timeout => f.write_str("webrtc: timed out"),
            Error::InvalidCandidate(e) => write!(f, "webrtc: invalid candidate: {e}"),
            Error::TooManyPeers => f.write_str("webrtc: too many peers"),
            Error::Turn(e) => write!(f, "webrtc: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Rtc(e) => Some(e),
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

pub(crate) fn fill_random(buf: &mut [u8]) {
    if only_crypto::rand::fill_random(buf).is_err() {
        let mut x = Instant::now().elapsed().as_nanos() as u64 ^ 0x9e37_79b9_7f4a_7c15;
        for b in buf {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The default peer configuration: the starting point for [`RtcServer::config`] and
/// [`Endpoint::config`] (codecs, RTP mode, BWE, ...).
pub fn rtc_config() -> RtcConfig {
    RtcConfig(ConfigInner::default())
}

/// The application side of a peer. Every method has a default.
pub trait PeerHandler: Send + 'static {
    /// The ICE connection state changed. On [`IceConnectionState::Disconnected`] (consent
    /// lost) the peer is closed right after, unless the server or endpoint was configured
    /// otherwise ([`RtcServer::close_on_disconnect`]).
    fn on_ice_state(&mut self, _p: &Peer, _state: IceConnectionState) {}
    /// ICE and DTLS are up: media and data channels can flow.
    fn on_connected(&mut self, _p: &Peer) {}
    /// A data channel opened (by either side).
    fn on_channel_open(&mut self, _p: &Peer, _id: ChannelId, _label: &str) {}
    /// A message on a data channel.
    fn on_channel_data(&mut self, _p: &Peer, _id: ChannelId, _data: &[u8], _binary: bool) {}
    /// A data channel closed.
    fn on_channel_close(&mut self, _p: &Peer, _id: ChannelId) {}
    /// A media line was added by the remote peer's offer (or ours).
    fn on_media_added(&mut self, _p: &Peer, _media: &MediaAdded) {}
    /// A depacketized media sample (frame mode, the default).
    fn on_media_data(&mut self, _p: &Peer, _data: &MediaData) {}
    /// A received RTP packet (RTP mode, [`RtcConfig::set_rtp_mode`]).
    fn on_rtp(&mut self, _p: &Peer, _packet: &RtpPacket) {}
    /// The remote peer asks for a keyframe (PLI or FIR).
    fn on_keyframe_request(&mut self, _p: &Peer, _req: &KeyframeRequest) {}
    /// Any other event: buffered amount low, statistics, bandwidth estimates ...
    fn on_event(&mut self, _p: &Peer, _event: &Event) {}
    /// The peer is closed; called once, last.
    fn on_close(&mut self, _p: &Peer) {}
}

// ---- the peer ----

struct State {
    rtc: Rtc,
    armed: Option<Instant>,
    closed: bool,
    /// Closed if not connected by then (cleared once connected).
    connect_by: Option<Instant>,
    /// Remote addresses this peer was reached at over ICE-TCP: transmits to them go over the
    /// connection (at most [`ADDRS_PER_PEER`]). Kept here, under the peer's own lock, so that
    /// the UDP path of a hub with TCP candidates takes no shared lock.
    tcp_remotes: Vec<SocketAddr>,
    /// Registered with the hub for datagrams from unknown sources (latching media without
    /// ICE, ADR-077).
    latching: bool,
}

struct Shared {
    id: u64,
    hub: Weak<Hub>,
    me: Weak<Shared>,
    state: Mutex<State>,
    events: Mutex<VecDeque<Ev>>,
    handler: Mutex<Option<Box<dyn PeerHandler>>>,
    done: AtomicBool,
    ufrag: String,
}

enum Ev {
    Rtc(Box<RtcEvent>),
    Close,
}

/// A WebRTC peer connection. Cheap to clone and usable from any thread.
#[derive(Clone)]
pub struct Peer(Arc<Shared>);

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peer")
            .field("id", &self.0.id)
            .field("ufrag", &self.0.ufrag)
            .finish_non_exhaustive()
    }
}

static NEXT_PEER: AtomicU64 = AtomicU64::new(1);

impl Peer {
    fn new(hub: &Arc<Hub>, rtc: Rtc, handler: Box<dyn PeerHandler>) -> Peer {
        let ufrag = rtc.local_ufrag();
        Peer(Arc::new_cyclic(|me| Shared {
            id: NEXT_PEER.fetch_add(1, Ordering::Relaxed),
            hub: Arc::downgrade(hub),
            me: me.clone(),
            state: Mutex::new(State {
                rtc,
                armed: None,
                closed: false,
                connect_by: (*lock(&hub.connect_timeout)).map(|d| Instant::now() + d),
                tcp_remotes: Vec::new(),
                latching: false,
            }),
            events: Mutex::new(VecDeque::new()),
            handler: Mutex::new(Some(handler)),
            done: AtomicBool::new(false),
            ufrag,
        }))
    }

    /// A process-unique id.
    pub fn id(&self) -> u64 {
        self.0.id
    }

    /// The local ICE username fragment.
    pub fn local_ufrag(&self) -> &str {
        &self.0.ufrag
    }

    /// Whether ICE and DTLS are up.
    pub fn is_connected(&self) -> bool {
        lock(&self.0.state).rtc.is_connected()
    }

    /// Whether the peer is closed.
    pub fn is_closed(&self) -> bool {
        lock(&self.0.state).closed
    }

    fn with_rtc_inner<R>(&self, f: impl FnOnce(&mut Rtc) -> R) -> Result<R, Error> {
        let r = {
            let mut st = lock(&self.0.state);
            if st.closed {
                return Err(Error::Closed);
            }
            f(&mut st.rtc)
        };
        self.drive();
        Ok(r)
    }

    /// Sends a message on data channel `id` (`binary`, or UTF-8 text). `Ok(false)` when the
    /// channel's buffer is full (see `ChannelBufferedAmountLow` in [`PeerHandler::on_event`]).
    pub fn send(&self, id: ChannelId, data: &[u8], binary: bool) -> Result<bool, Error> {
        self.with_rtc_inner(
            |rtc| match rtc.send_channel(Instant::now(), id, data, binary) {
                Ok(Some(b)) => Ok(b),
                Ok(None) => Err(Error::UnknownChannel),
                Err(e) => Err(rtc_err(e)),
            },
        )?
    }

    /// The priority of data channel `id` ([`ChannelConfig::priority`]; for a channel the
    /// remote opened, the one its DCEP open message carried).
    pub fn channel_priority(&self, id: ChannelId) -> Result<ChannelPriority, Error> {
        self.with_rtc_inner(|rtc| rtc.channel_priority(id))?
            .ok_or(Error::UnknownChannel)
    }

    /// Changes how the SCTP stream scheduler ([`RtcConfig::set_sctp_scheduler`]) weighs data
    /// channel `id` against the others on this side; the remote keeps the priority it was told
    /// when the channel opened (DCEP has no update message).
    pub fn set_channel_priority(
        &self,
        id: ChannelId,
        priority: ChannelPriority,
    ) -> Result<(), Error> {
        if self.with_rtc_inner(|rtc| rtc.set_channel_priority(id, priority))? {
            Ok(())
        } else {
            Err(Error::UnknownChannel)
        }
    }

    /// Opens a data channel with `cfg` (label, ordered or not, reliable or not). On a
    /// connection that already has an SCTP association (any data channel negotiated) it opens
    /// at once and the result carries no offer; otherwise the returned SDP offer must reach
    /// the remote peer and its answer come back through [`accept_answer`](Self::accept_answer).
    pub fn open_channel(&self, cfg: &ChannelConfig) -> Result<(ChannelId, Option<String>), Error> {
        let mut id = None;
        let offer = self.renegotiate(|api| id = Some(api.add_channel_with_config(cfg)))?;
        Ok((id.ok_or(Error::Closed)?, offer))
    }

    /// Changes the session (add media or channels, change directions, ICE restart ...).
    /// Returns the offer to send when the change needs negotiation (then call
    /// [`accept_answer`](Self::accept_answer) with the answer), `None` when it applied
    /// directly.
    pub fn renegotiate(
        &self,
        f: impl FnOnce(&mut SdpChanges<'_, '_>),
    ) -> Result<Option<String>, Error> {
        let offer = {
            let mut st = lock(&self.0.state);
            if st.closed {
                return Err(Error::Closed);
            }
            let mut ch = st.rtc.changes();
            f(&mut SdpChanges(&mut ch));
            st.rtc.apply(Instant::now(), ch).map_err(rtc_err)?
        };
        self.drive();
        Ok(offer)
    }

    /// Applies the remote answer to the offer this peer made.
    pub fn accept_answer(&self, answer: &str) -> Result<(), Error> {
        let r = {
            let mut st = lock(&self.0.state);
            if st.closed {
                return Err(Error::Closed);
            }
            st.rtc.accept_answer(Instant::now(), answer)
        };
        self.drive();
        r.map_err(sdp_err)
    }

    /// Accepts a (re-)offer from the remote peer and returns the answer.
    pub fn accept_offer(&self, offer: &str) -> Result<String, Error> {
        let r = {
            let mut st = lock(&self.0.state);
            if st.closed {
                return Err(Error::Closed);
            }
            st.rtc.accept_offer(Instant::now(), offer)
        };
        self.drive();
        r.map_err(sdp_err)
    }

    /// Adds a trickled remote ICE candidate (`candidate:...` or `a=candidate:...`). One
    /// whose address is an mDNS name (`<uuid>.local`, as browsers conceal their host
    /// addresses) is resolved first when the endpoint resolves them
    /// ([`Endpoint::resolve_mdns`]), else refused like any name.
    pub fn add_remote_candidate(&self, candidate: &str) -> Result<(), Error> {
        let s = candidate.trim();
        let s = s.strip_prefix("a=").unwrap_or(s);
        let resolving = self.0.hub.upgrade().is_some_and(|h| h.mdns.get().is_some());
        match only_ice::Candidate::parse(s) {
            Ok(c) => self.with_rtc_inner(|rtc| rtc.add_remote_candidate(c)),
            Err(only_ice::ParseError::Mdns) if resolving => self.with_rtc_inner(|rtc| {
                let _ = rtc.add_remote_candidate_line(s);
            }),
            Err(e) => Err(Error::Sdp(e.to_string())),
        }
    }

    /// [`add_remote_candidate`](Self::add_remote_candidate) for the media section `mid`
    /// (`sdpMid`): in a session without BUNDLE each section has its own ICE agent, and the
    /// candidate goes to the one of `mid` (with BUNDLE, or for a mid the session does not
    /// have, to the shared one, as `add_remote_candidate` does).
    pub fn add_remote_candidate_in(&self, mid: Mid, candidate: &str) -> Result<(), Error> {
        let s = candidate.trim();
        let s = s.strip_prefix("a=").unwrap_or(s);
        let resolving = self.0.hub.upgrade().is_some_and(|h| h.mdns.get().is_some());
        match only_ice::Candidate::parse(s) {
            Ok(_) => self.with_rtc_inner(|rtc| {
                rtc.add_remote_candidate_in(mid, s)
                    .map_err(|e| Error::Sdp(e.to_string()))
            })?,
            Err(only_ice::ParseError::Mdns) if resolving => self.with_rtc_inner(|rtc| {
                let _ = rtc.add_remote_candidate_in(mid, s);
            }),
            Err(e) => Err(Error::Sdp(e.to_string())),
        }
    }

    /// Writes one media sample (a frame: an Opus packet, a VP8 frame, H.264 access unit ...)
    /// on `mid` with payload type `pt`; it is packetized here. `rtp_time` is in the codec's clock
    /// (90 kHz video, 48 kHz Opus), `wallclock` when it was captured. Dropped before the peer
    /// is connected.
    pub fn write_media(
        &self,
        mid: Mid,
        pt: Pt,
        wallclock: Instant,
        rtp_time: MediaTime,
        data: &[u8],
    ) -> Result<(), Error> {
        self.write_rid(mid, None, pt, wallclock, rtp_time, data)
    }

    /// [`write_media`](Self::write_media) for the simulcast encoding `rid` of a line added
    /// with [`SdpChanges::add_simulcast_media`]: each encoding is its own RTP stream (the
    /// application encodes each at its own resolution and bitrate). Samples for an encoding
    /// the answer did not accept are dropped; an unknown `rid` is [`Error::UnknownMedia`].
    pub fn write_simulcast(
        &self,
        mid: Mid,
        rid: &str,
        pt: Pt,
        wallclock: Instant,
        rtp_time: MediaTime,
        data: &[u8],
    ) -> Result<(), Error> {
        self.write_rid(mid, Some(rid), pt, wallclock, rtp_time, data)
    }

    fn write_rid(
        &self,
        mid: Mid,
        rid: Option<&str>,
        pt: Pt,
        wallclock: Instant,
        rtp_time: MediaTime,
        data: &[u8],
    ) -> Result<(), Error> {
        let _ = wallclock;
        self.with_rtc_inner(|rtc| {
            match rtc.write_media(Instant::now(), mid, rid, pt, rtp_time, data) {
                Ok(true) => Ok(()),
                Ok(false) => Err(Error::UnknownMedia),
                Err(e) => Err(rtc_err(e)),
            }
        })?
    }

    /// The payload type negotiated on `mid` for a codec, e.g. [`Codec::Vp8`].
    pub fn payload_type(&self, mid: Mid, codec: Codec) -> Option<Pt> {
        lock(&self.0.state).rtc.payload_type(mid, codec)
    }

    /// Asks the remote sender of `mid` for a keyframe (PLI or FIR).
    pub fn request_keyframe(&self, mid: Mid, kind: KeyframeRequestKind) -> Result<(), Error> {
        self.with_rtc_inner(|rtc| {
            if rtc.request_keyframe(mid, kind) {
                Ok(())
            } else {
                Err(Error::UnknownMedia)
            }
        })?
    }

    /// Asks the remote sender of the simulcast encoding `rid` received on `mid` for a
    /// keyframe: what an SFU switching a viewer to that layer needs (the other encodings are
    /// left alone). [`Error::UnknownMedia`] when no stream of that RID has arrived on `mid`.
    pub fn request_layer_keyframe(
        &self,
        mid: Mid,
        rid: &str,
        kind: KeyframeRequestKind,
    ) -> Result<(), Error> {
        self.with_rtc_inner(|rtc| {
            if rtc.request_keyframe_of(mid, Some(rid), kind) {
                Ok(())
            } else {
                Err(Error::UnknownMedia)
            }
        })?
    }

    /// Asks the remote sender of `mid` to send at most `bitrate` bits per second, with a TMMBR
    /// (RFC 5104) about each stream received on it, repeated with every RTCP report so that
    /// it does not time out; `None` stops repeating it and sends a TMMBR of 0 once (which RFC
    /// 5104 handlers take as a withdrawal; libwebrtc ignores it and drops the request 25 s after
    /// the last one). libwebrtc honours TMMBR without `ccm tmmbr` in the SDP; see
    /// [`RtcConfig::enable_tmmbr`]. [`Error::UnknownMedia`] when there is no such line.
    pub fn request_max_bitrate(&self, mid: Mid, bitrate: Option<u64>) -> Result<(), Error> {
        self.with_rtc_inner(|rtc| {
            if rtc.request_max_bitrate(mid, bitrate) {
                Ok(())
            } else {
                Err(Error::UnknownMedia)
            }
        })?
    }

    /// Changes the bounds of the bandwidth estimate (bits per second; see
    /// [`RtcConfig::set_bwe_bounds`]): a maximum raised above the estimate is probed at once.
    /// Nothing happens without the estimator ([`RtcConfig::enable_bwe`]).
    pub fn set_bitrate_bounds(&self, min_bps: u64, max_bps: u64) {
        let _ = self.with_rtc_inner(|rtc| rtc.set_bitrate_bounds(Instant::now(), min_bps, max_bps));
    }

    /// Closes the peer (DTLS close notify, SCTP shutdown where possible); `on_close` follows.
    pub fn close(&self) {
        {
            let mut st = lock(&self.0.state);
            if st.closed {
                return;
            }
            st.rtc.close(Instant::now());
        }
        self.drive();
        let first = {
            let mut st = lock(&self.0.state);
            !std::mem::replace(&mut st.closed, true)
        };
        if first {
            self.finish();
        }
    }

    fn finish(&self) {
        if let Some(hub) = self.0.hub.upgrade() {
            hub.remove(self.0.id);
        }
        lock(&self.0.events).push_back(Ev::Close);
        self.deliver();
    }

    /// One datagram for this peer (`tcp`: a frame from an ICE-TCP connection) that arrived
    /// with ECN codepoint `ecn` (0 when not ECN-capable or not known).
    fn input(&self, source: SocketAddr, destination: SocketAddr, data: &[u8], tcp: bool, ecn: u8) {
        {
            let mut st = lock(&self.0.state);
            if st.closed {
                return;
            }
            if tcp && !st.tcp_remotes.contains(&source) && st.tcp_remotes.len() < ADDRS_PER_PEER {
                st.tcp_remotes.push(source);
            }
            st.rtc.set_rx_ecn(ecn);
            st.rtc
                .handle_receive(Instant::now(), source, destination, data);
        }
        self.drive();
    }

    /// A datagram from `source`, which no peer is known at, offered for latching (ADR-077):
    /// `true` if it authenticated as this peer's RTP or RTCP (it was then taken).
    fn try_latch(&self, source: SocketAddr, destination: SocketAddr, data: &[u8], ecn: u8) -> bool {
        let took = {
            let mut st = lock(&self.0.state);
            if st.closed {
                return false;
            }
            st.rtc.set_rx_ecn(ecn);
            st.rtc
                .latch_receive(Instant::now(), source, destination, data)
        };
        if took {
            self.drive();
        }
        took
    }

    /// Polls the peer until it returns a timeout: datagrams are sent, events delivered, the timer
    /// armed.
    ///
    /// Datagrams are sent and events queued while the state lock is held: two threads driving
    /// one peer (an I/O thread with a datagram, an application thread sending) must not reorder
    /// what the stack produced in order.
    fn drive(&self) {
        let hub = self.0.hub.upgrade();
        let mut evs = Vec::new();
        let mut died = false;
        let close_on_disconnect = hub
            .as_ref()
            .is_some_and(|h| h.close_on_disconnect.load(Ordering::Relaxed));
        let mdns_wanted;
        {
            let mut st = lock(&self.0.state);
            if st.closed {
                return;
            }
            mdns_wanted = st.rtc.take_mdns();
            // Media without ICE: datagrams from the remote's plain addresses are this peer's
            // before it sends anything there.
            let plain = st.rtc.take_plain_remotes();
            let gone = st.rtc.take_gone_remotes();
            if let (false, Some(hub)) = (plain.is_empty() && gone.is_empty(), &hub) {
                let mut by_addr = lock(&hub.by_addr);
                for a in gone {
                    if by_addr.get(&a) == Some(&self.0.id) {
                        by_addr.remove(&a);
                    }
                }
                for a in plain {
                    by_addr.insert(a, self.0.id);
                }
            }
            // Latching: the hub offers datagrams from unknown sources while a transport may
            // still move.
            let wanted = st.rtc.latch_wanted();
            if wanted != st.latching {
                if let Some(hub) = &hub {
                    st.latching = wanted;
                    hub.set_latching(self.0.id, wanted);
                }
            }
            if st.rtc.is_connected() {
                st.connect_by = None;
            } else if st.connect_by.is_some_and(|d| d <= Instant::now()) {
                only_log::debug!(target: "only_webrtc", "peer {}: not connected in time", self.0.id);
                died = true;
            }
            while !died {
                match st.rtc.poll_output(Instant::now()) {
                    Output::Timeout(t) => {
                        let t = st.connect_by.map_or(t, |d| d.min(t));
                        if st.armed.is_none_or(|a| t < a) {
                            st.armed = Some(t);
                            let target: Weak<dyn timer::Due> = self.0.me.clone();
                            timer::timer().schedule(t, target);
                        }
                        break;
                    }
                    Output::Transmit(src, dest, contents, ecn) => {
                        if let Some(hub) = &hub {
                            let tcp = !st.tcp_remotes.is_empty() && st.tcp_remotes.contains(&dest);
                            hub.transmit(self.0.id, src, dest, &contents, tcp, ecn);
                        }
                    }
                    Output::Event(e) => {
                        let dead = matches!(e, RtcEvent::Closed)
                            || (close_on_disconnect
                                && matches!(
                                    e,
                                    RtcEvent::IceState(IceConnectionState::Disconnected)
                                ));
                        evs.push(Ev::Rtc(Box::new(e)));
                        if dead {
                            died = true;
                            break;
                        }
                    }
                }
            }
            if !st.rtc.is_alive() {
                died = true;
            }
            if died {
                st.closed = true;
            }
            if !evs.is_empty() {
                lock(&self.0.events).extend(evs);
            }
        }
        if let Some((names, ufrag)) = mdns_wanted {
            if let Some(m) = hub.as_ref().and_then(|h| h.mdns.get()) {
                for (name, line) in names {
                    m.resolve(self.0.id, &ufrag, name, line);
                }
            }
        }
        if died {
            self.finish();
        } else {
            self.deliver();
        }
    }

    /// Runs queued events through the handler, one deliverer at a time (a nested or concurrent
    /// call finds the handler taken and leaves its events to the one running).
    fn deliver(&self) {
        loop {
            if lock(&self.0.events).is_empty() {
                return;
            }
            let Some(mut h) = lock(&self.0.handler).take() else {
                if self.0.done.load(Ordering::Acquire) {
                    lock(&self.0.events).clear();
                }
                return;
            };
            let mut closed = false;
            loop {
                let ev = lock(&self.0.events).pop_front();
                let Some(ev) = ev else { break };
                match ev {
                    Ev::Close => {
                        self.0.done.store(true, Ordering::Release);
                        h.on_close(self);
                        closed = true;
                        break;
                    }
                    Ev::Rtc(e) => self.dispatch(&mut *h, *e),
                }
            }
            if closed {
                lock(&self.0.events).clear();
                return;
            }
            *lock(&self.0.handler) = Some(h);
        }
    }

    fn dispatch(&self, h: &mut dyn PeerHandler, e: RtcEvent) {
        match e {
            RtcEvent::IceState(s) => h.on_ice_state(self, s),
            RtcEvent::Connected => h.on_connected(self),
            RtcEvent::ChannelOpen(id, label) => h.on_channel_open(self, id, &label),
            RtcEvent::ChannelData(id, data, binary) => h.on_channel_data(self, id, &data, binary),
            RtcEvent::ChannelClose(id) => h.on_channel_close(self, id),
            RtcEvent::MediaAdded(m) => h.on_media_added(self, &m),
            RtcEvent::MediaData(d) => h.on_media_data(self, &d),
            RtcEvent::Rtp(p) => h.on_rtp(self, &p),
            RtcEvent::Keyframe(k) => h.on_keyframe_request(self, &k),
            RtcEvent::BufferedLow(id) => {
                h.on_event(self, &Event::ChannelBufferedAmountLow(id));
            }
            RtcEvent::Other(o) => h.on_event(self, &Event::Other(OtherEvent(Box::new(o)))),
            RtcEvent::Closed => {}
        }
    }
}

impl timer::Due for Shared {
    fn fire(&self, at: Instant) {
        let Some(me) = self.me.upgrade() else { return };
        {
            let mut st = lock(&self.state);
            if st.armed != Some(at) || st.closed {
                return;
            }
            st.armed = None;
            st.rtc.handle_timeout(Instant::now());
        }
        Peer(me).drive();
    }
}

// ---- the hub: peers sharing one UDP port ----

type ConfigFn = dyn Fn() -> RtcConfig + Send + Sync;

/// Where the mapped address of a STUN transaction goes (with its transaction id).
type StunWaiter = mpsc::Sender<([u8; 12], SocketAddr)>;

enum Tx {
    /// A listener: datagrams go out through the peer address's connection.
    Listener(Mutex<HashMap<SocketAddr, Conn<RtcUdp>>>),
    /// A bound socket: datagrams go out with `send_to`.
    Bound(OnceLock<UdpBinding>),
}

/// Default most peers of an [`RtcServer`] or [`Endpoint`]: each holds ICE, DTLS and SRTP state,
/// and offers come from the network (signalling), so the table needs a bound.
pub const DEFAULT_MAX_PEERS: usize = 1024;

/// Source addresses remembered per peer: a peer's ICE candidates plus a margin. Connectivity
/// checks naming a peer's ufrag from more addresses than this are not remembered (they still
/// reach the peer through the ufrag lookup).
const ADDRS_PER_PEER: usize = 16;

struct Hub {
    tx: Tx,
    ice_lite: bool,
    /// Atomic so it can be set after an [`Endpoint`] is bound (its socket holds a reference).
    max_peers: AtomicUsize,
    // Settings behind interior mutability: an `Endpoint`'s socket holds a reference to the hub
    // from `bind` on, so they cannot be set through `Arc::get_mut`.
    close_on_disconnect: AtomicBool,
    connect_timeout: Mutex<Option<Duration>>,
    config: Mutex<Arc<ConfigFn>>,
    candidates: Mutex<Vec<only_ice::Candidate>>,
    peers: Mutex<HashMap<u64, Peer>>,
    by_ufrag: Mutex<HashMap<String, u64>>,
    by_addr: Mutex<HashMap<SocketAddr, u64>>,
    stun_waiters: Mutex<HashMap<[u8; 12], StunWaiter>>,
    /// TURN allocations ([`Endpoint::gather_relay`]), at most [`MAX_RELAYS`].
    relays: Mutex<Vec<Arc<relay::Relay>>>,
    /// `relays.len()`, read without the lock on every datagram (endpoints without TURN
    /// allocations never take it).
    relay_count: AtomicUsize,
    /// The ICE-TCP side: passive and active candidates ([`Endpoint::listen_tcp`],
    /// [`Endpoint::dial_tcp`], [`RtcServer::tcp`]).
    tcp: OnceLock<Arc<tcp::TcpSide>>,
    /// Which local candidates new peers use ([`Endpoint::candidate_filter`]).
    filter: Mutex<Option<Arc<CandidateFilter>>>,
    /// The mDNS resolver and responder ([`Endpoint::resolve_mdns`]).
    mdns: OnceLock<Arc<mdns::Mdns>>,
    /// New peers conceal host addresses behind mDNS names
    /// ([`Endpoint::conceal_host_candidates`]).
    conceal: AtomicBool,
    /// The interfaces (scope ids) of remote link-local IPv6 addresses: SDP carries none, so
    /// remote addresses go to ICE without one and get it back on the way out. Learnt from
    /// the datagrams they send and from mDNS answers. Endpoints that see no link-local
    /// traffic never touch it.
    scopes: Mutex<HashMap<std::net::Ipv6Addr, u32>>,
    /// The socket of ICE component 2 (RTCP without rtcp-mux, [`Endpoint::bind_rtcp`]).
    rtcp: OnceLock<UdpBinding>,
    /// An [`RtcServer`]'s RTCP listener ([`RtcServer::rtcp_candidates`]): its component-2
    /// host addresses and its connections by peer address. `rtcp_listener` is read without
    /// a lock on every datagram sent (servers without one never take the locks).
    rtcp_listener: AtomicBool,
    rtcp_bases: Mutex<Vec<SocketAddr>>,
    rtcp_conns: Mutex<HashMap<SocketAddr, Conn<RtcUdp>>>,
    /// Sockets of the transports beyond the first (no BUNDLE,
    /// [`Endpoint::bind_transport_socket`]) and their host candidates; `tp_count` is read
    /// without a lock on every datagram sent.
    tp_socks: Mutex<Vec<(UdpBinding, only_ice::Candidate)>>,
    tp_count: AtomicUsize,
    /// Peers latching media without ICE (ADR-077): datagrams from unknown sources are
    /// offered to them; `latch_count` is read without a lock on every unrouted datagram.
    latching: Mutex<Vec<u64>>,
    latch_count: AtomicUsize,
    /// Where the next offer starts (fairness among many latching peers).
    latch_next: AtomicUsize,
}

/// Latching peers a datagram from an unknown source is offered to at most.
const MAX_LATCH_TRIES: usize = 64;

/// Link-local addresses whose interface is remembered.
const MAX_SCOPES: usize = 256;

type CandidateFilter = dyn Fn(&Candidate) -> bool + Send + Sync;

/// Most TURN allocations of one [`Endpoint`] per ICE component.
const MAX_RELAYS: usize = 4;

impl Hub {
    fn new(tx: Tx, ice_lite: bool, candidates: Vec<only_ice::Candidate>) -> Hub {
        Hub {
            tx,
            ice_lite,
            max_peers: AtomicUsize::new(DEFAULT_MAX_PEERS),
            close_on_disconnect: AtomicBool::new(true),
            connect_timeout: Mutex::new(Some(Duration::from_secs(30))),
            config: Mutex::new(Arc::new(rtc_config)),
            candidates: Mutex::new(candidates),
            peers: Mutex::new(HashMap::new()),
            by_ufrag: Mutex::new(HashMap::new()),
            by_addr: Mutex::new(HashMap::new()),
            stun_waiters: Mutex::new(HashMap::new()),
            relays: Mutex::new(Vec::new()),
            relay_count: AtomicUsize::new(0),
            tcp: OnceLock::new(),
            filter: Mutex::new(None),
            mdns: OnceLock::new(),
            conceal: AtomicBool::new(false),
            scopes: Mutex::new(HashMap::new()),
            rtcp: OnceLock::new(),
            rtcp_listener: AtomicBool::new(false),
            rtcp_bases: Mutex::new(Vec::new()),
            rtcp_conns: Mutex::new(HashMap::new()),
            tp_socks: Mutex::new(Vec::new()),
            tp_count: AtomicUsize::new(0),
            latching: Mutex::new(Vec::new()),
            latch_count: AtomicUsize::new(0),
            latch_next: AtomicUsize::new(0),
        }
    }

    /// Remembers that link-local `ip` is reached through interface `scope`.
    fn learn_scope(&self, ip: std::net::Ipv6Addr, scope: u32) {
        let mut m = lock(&self.scopes);
        if m.len() < MAX_SCOPES || m.contains_key(&ip) {
            m.insert(ip, scope);
        }
    }

    /// `a` without its scope id when it is a link-local IPv6 address (the interface is
    /// remembered).
    fn unscope(&self, a: SocketAddr) -> SocketAddr {
        match a {
            SocketAddr::V6(v) if v.scope_id() != 0 && mdns::is_link_local(v.ip()) => {
                self.learn_scope(*v.ip(), v.scope_id());
                SocketAddr::V6(std::net::SocketAddrV6::new(
                    *v.ip(),
                    v.port(),
                    v.flowinfo(),
                    0,
                ))
            }
            a => a,
        }
    }

    /// `a` with the interface of a link-local IPv6 address that has none: the one learnt for
    /// it, else the socket's own when it is bound to a link-local address (same link).
    fn rescope(&self, a: SocketAddr) -> SocketAddr {
        match a {
            SocketAddr::V6(v) if v.scope_id() == 0 && mdns::is_link_local(v.ip()) => {
                let learnt = lock(&self.scopes).get(v.ip()).copied();
                let own = || match self.binding().map(UdpBinding::local_addr) {
                    Some(SocketAddr::V6(l)) if l.scope_id() != 0 => Some(l.scope_id()),
                    _ => None,
                };
                match learnt.or_else(own) {
                    Some(s) => SocketAddr::V6(std::net::SocketAddrV6::new(
                        *v.ip(),
                        v.port(),
                        v.flowinfo(),
                        s,
                    )),
                    None => a,
                }
            }
            a => a,
        }
    }

    /// Whether new peers use local candidate `c`.
    fn uses(&self, c: &only_ice::Candidate) -> bool {
        let f = lock(&self.filter).clone();
        f.is_none_or(|f| f(&Candidate(c.clone())))
    }

    fn peer_by_ufrag(&self, ufrag: &str) -> Option<u64> {
        lock(&self.by_ufrag).get(ufrag).copied()
    }

    /// Peer `id`, if open.
    fn peer(&self, id: u64) -> Option<Peer> {
        lock(&self.peers).get(&id).cloned()
    }

    fn binding(&self) -> Option<&UdpBinding> {
        match &self.tx {
            Tx::Bound(b) => b.get(),
            Tx::Listener(_) => None,
        }
    }

    /// The relay whose allocation has, or had, the relayed address `addr`, and whether it is
    /// the current one.
    fn relay_at(&self, addr: SocketAddr) -> Option<(Arc<relay::Relay>, bool)> {
        if self.relay_count.load(Ordering::Acquire) == 0 {
            return None;
        }
        lock(&self.relays)
            .iter()
            .find_map(|r| r.owns(addr).map(|cur| (r.clone(), cur)))
    }

    /// The UDP or DTLS relay whose TURN server is at `addr`, on the socket at `local` (the
    /// RTCP socket's allocations are component 2's).
    fn relay_of_server(&self, addr: SocketAddr, local: SocketAddr) -> Option<Arc<relay::Relay>> {
        if self.relay_count.load(Ordering::Acquire) == 0 {
            return None;
        }
        let rtcp = self.rtcp.get().is_some_and(|r| r.local_addr() == local);
        lock(&self.relays)
            .iter()
            .find(|r| r.server == addr && !r.wire.is_stream() && r.rtcp == rtcp)
            .cloned()
    }

    /// A relayed allocation is gone: new peers no longer get its candidate.
    fn relay_lost(&self, relayed: SocketAddr) {
        lock(&self.candidates)
            .retain(|c| c.kind() != only_ice::CandidateKind::Relayed || c.addr() != relayed);
    }

    /// A lost allocation was made again: new peers get the new candidate, and so do the open
    /// ones (their agents check it against the remote candidates they know).
    fn relay_reallocated(&self, c: only_ice::Candidate) {
        {
            let mut cs = lock(&self.candidates);
            if !cs.iter().any(|x| x.addr() == c.addr()) {
                cs.push(c.clone());
            }
        }
        if !self.uses(&c) {
            return;
        }
        let c = self.concealed(c);
        let peers: Vec<Peer> = lock(&self.peers).values().cloned().collect();
        for p in peers {
            let _ = p.with_rtc_inner(|rtc| rtc.add_local_candidate(c.clone()));
        }
    }

    /// Changes the relay list, keeping `relay_count` in step.
    fn with_relays<R>(&self, f: impl FnOnce(&mut Vec<Arc<relay::Relay>>) -> R) -> R {
        let mut relays = lock(&self.relays);
        let r = f(&mut relays);
        self.relay_count.store(relays.len(), Ordering::Release);
        r
    }

    /// The TCP side, made on first use.
    fn tcp_side(self: &Arc<Hub>) -> Arc<tcp::TcpSide> {
        let server = matches!(self.tx, Tx::Listener(_));
        self.tcp
            .get_or_init(|| tcp::TcpSide::new(self, server))
            .clone()
    }

    fn new_rtc(&self) -> Result<Rtc, Error> {
        let config = lock(&self.config).clone();
        let mut rtc = Rtc::new(config().0, self.ice_lite, Instant::now()).map_err(rtc_err)?;
        let cs = lock(&self.candidates).clone();
        for c in cs {
            if self.uses(&c) {
                rtc.add_local_candidate(self.concealed(c));
            }
        }
        if self.tp_count.load(Ordering::Acquire) != 0 {
            for (k, (_, c)) in lock(&self.tp_socks).iter().enumerate() {
                rtc.add_transport_candidate(k + 1, self.concealed(c.clone()));
            }
        }
        Ok(rtc)
    }

    /// `c` as new peers signal it: with host addresses concealed
    /// ([`Endpoint::conceal_host_candidates`]), a host candidate under its mDNS name and the
    /// related address of the others as `0.0.0.0:0`.
    fn concealed(&self, c: only_ice::Candidate) -> only_ice::Candidate {
        if !self.conceal.load(Ordering::Relaxed) {
            return c;
        }
        let Some(m) = self.mdns.get() else { return c };
        if c.kind() == only_ice::CandidateKind::Host {
            match m.name_for(c.addr().ip()) {
                Some(n) => c.with_hostname(n),
                None => c,
            }
        } else if c.related().is_some() {
            let any = if c.addr().is_ipv4() {
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            };
            c.with_related(Some(SocketAddr::new(any, 0)))
        } else {
            c
        }
    }

    fn full(&self) -> bool {
        let max = self.max_peers.load(Ordering::Relaxed);
        max != 0 && lock(&self.peers).len() >= max
    }

    fn register(self: &Arc<Hub>, rtc: Rtc, handler: Box<dyn PeerHandler>) -> Result<Peer, Error> {
        let max = self.max_peers.load(Ordering::Relaxed);
        let mut peers = lock(&self.peers);
        if max != 0 && peers.len() >= max {
            return Err(Error::TooManyPeers);
        }
        let p = Peer::new(self, rtc, handler);
        peers.insert(p.0.id, p.clone());
        drop(peers);
        lock(&self.by_ufrag).insert(p.0.ufrag.clone(), p.0.id);
        Ok(p)
    }

    fn accept_offer(
        self: &Arc<Hub>,
        offer: &str,
        handler: Box<dyn PeerHandler>,
    ) -> Result<(Peer, String), Error> {
        if self.full() {
            return Err(Error::TooManyPeers); // before paying for the DTLS identity and SDP
        }
        let mut rtc = self.new_rtc()?;
        let answer = rtc.accept_offer(Instant::now(), offer).map_err(sdp_err)?;
        let p = self.register(rtc, handler)?;
        p.drive();
        Ok((p, answer))
    }

    fn create_offer(
        self: &Arc<Hub>,
        handler: Box<dyn PeerHandler>,
        f: impl FnOnce(&mut SdpChanges<'_, '_>),
    ) -> Result<(Peer, String), Error> {
        if self.full() {
            return Err(Error::TooManyPeers);
        }
        let mut rtc = self.new_rtc()?;
        let mut ch = rtc.changes();
        f(&mut SdpChanges(&mut ch));
        let offer = rtc
            .apply(Instant::now(), ch)
            .map_err(rtc_err)?
            .ok_or_else(|| Error::Sdp("an offer needs at least one media or channel".into()))?;
        let p = self.register(rtc, handler)?;
        p.drive();
        Ok((p, offer))
    }

    /// Registers (or not) peer `id` for datagrams from unknown sources.
    fn set_latching(&self, id: u64, on: bool) {
        let mut l = lock(&self.latching);
        l.retain(|x| *x != id);
        if on {
            l.push(id);
        }
        self.latch_count.store(l.len(), Ordering::Relaxed);
    }

    fn remove(&self, id: u64) {
        self.set_latching(id, false);
        let p = lock(&self.peers).remove(&id);
        if let Some(p) = p {
            lock(&self.by_ufrag).remove(&p.0.ufrag);
        }
        lock(&self.by_addr).retain(|_, v| *v != id);
        if let Some(t) = self.tcp.get() {
            t.close_peer(id);
        }
    }

    /// Sends a datagram of peer `id`; `tcp` when `dest` reached the peer over ICE-TCP.
    /// `ecn`: the ECN codepoint for UDP (0: Not-ECT; relays and ICE-TCP send none).
    fn transmit(
        &self,
        id: u64,
        src: SocketAddr,
        dest: SocketAddr,
        data: &[u8],
        tcp: bool,
        ecn: u8,
    ) {
        // ICE-TCP: to a remote that came over a connection, or from the active candidate (a
        // server's TCP and UDP candidates may share an address, so `src` alone does not tell).
        if let Some(t) = self.tcp.get() {
            if tcp || t.is_active(src) {
                t.send(id, src, dest, data);
                return;
            }
        }
        // Replies from where we send belong to this peer (full ICE agents send first).
        lock(&self.by_addr).entry(dest).or_insert(id);
        if let Some((r, current)) = self.relay_at(src) {
            if current {
                r.send(dest, data);
            }
            return;
        }
        let dest = self.rescope(dest);
        match &self.tx {
            Tx::Listener(conns) => {
                // Component 2's candidates send through the RTCP listener.
                let c = if self.rtcp_listener.load(Ordering::Relaxed)
                    && lock(&self.rtcp_bases).contains(&src)
                {
                    lock(&self.rtcp_conns).get(&dest).cloned()
                } else {
                    lock(conns).get(&dest).cloned()
                };
                if let Some(c) = c {
                    let _ = if ecn == 0 {
                        c.send(data)
                    } else {
                        c.send_segments_ecn(data.to_vec(), 0, ecn)
                    };
                }
            }
            Tx::Bound(b) => {
                // Component 2's candidates send from the RTCP socket (its own port), those of
                // other transports from theirs.
                if let Some(r) = self.rtcp.get().filter(|r| rtcp_source(r.local_addr(), src)) {
                    let _ = r.send_to_ecn(data, dest, ecn);
                    return;
                }
                if self.tp_count.load(Ordering::Relaxed) != 0 {
                    let socks = lock(&self.tp_socks);
                    let s = socks
                        .iter()
                        .find(|(s, c)| c.addr() == src || rtcp_source(s.local_addr(), src));
                    if let Some((s, _)) = s {
                        let _ = s.send_to_ecn(data, dest, ecn);
                        return;
                    }
                }
                if let Some(b) = b.get() {
                    let _ = if ecn == 0 {
                        b.send_to(data, dest)
                    } else {
                        b.send_to_ecn(data, dest, ecn)
                    };
                }
            }
        }
    }

    /// The local address a datagram reached: the host candidate when the socket is bound to
    /// the unspecified address.
    fn destination(&self, local: SocketAddr) -> SocketAddr {
        if !local.ip().is_unspecified() {
            return local;
        }
        let found = lock(&self.candidates)
            .iter()
            .map(only_ice::Candidate::addr)
            .find(|a| a.port() == local.port() && a.is_ipv4() == local.is_ipv4());
        found
            .or_else(|| {
                lock(&self.tp_socks)
                    .iter()
                    .map(|(_, c)| c.addr())
                    .find(|a| a.port() == local.port() && a.is_ipv4() == local.is_ipv4())
            })
            .unwrap_or(local)
    }

    fn on_datagram(&self, source: SocketAddr, local: SocketAddr, data: &[u8], ecn: u8) {
        let source = self.unscope(source);
        let is_stun = stun::is_stun(data);
        if is_stun && !lock(&self.stun_waiters).is_empty() {
            if let Ok(m) = stun::Message::parse(data) {
                let tx = lock(&self.stun_waiters).remove(&m.transaction_id());
                if let Some(tx) = tx {
                    if let Some(a) = stun::parse_binding_response(data, &m.transaction_id()) {
                        let _ = tx.send((m.transaction_id(), a));
                    }
                    return;
                }
            }
        }
        if let Some(r) = self.relay_of_server(source, local) {
            for (peer, relayed, data) in r.input(data) {
                self.route(peer, relayed, &data, 0);
            }
            return;
        }
        self.route(source, self.destination(local), data, ecn);
    }

    /// A datagram from `source` that arrived on the local address `destination`, for a peer.
    fn route(&self, source: SocketAddr, destination: SocketAddr, data: &[u8], ecn: u8) {
        let is_stun = stun::is_stun(data);
        let mut id = lock(&self.by_addr).get(&source).copied();
        if id.is_none() && is_stun {
            // A connectivity check: USERNAME is "<our ufrag>:<their ufrag>".
            if let Ok(m) = stun::Message::parse(data) {
                if let Some(u) = m.get_str(stun::attr::USERNAME) {
                    let ours = u.split(':').next().unwrap_or("");
                    id = {
                        // A transport of its own per section (no BUNDLE) has the peer's ufrag
                        // followed by a digit.
                        let m = lock(&self.by_ufrag);
                        m.get(ours)
                            .or_else(|| ours.get(..8).and_then(|b| m.get(b)))
                            .copied()
                    };
                    if let Some(i) = id {
                        // The ufrag is public (it is in the SDP): checks from spoofed sources
                        // must not grow the address table without bound.
                        let cap = lock(&self.peers).len().max(1) * ADDRS_PER_PEER;
                        let mut by_addr = lock(&self.by_addr);
                        if by_addr.len() < cap {
                            by_addr.insert(source, i);
                        }
                    }
                }
            }
        }
        let Some(id) = id else {
            if !is_stun
                && self.latch_count.load(Ordering::Relaxed) != 0
                && matches!(data.first(), Some(128..=191))
            {
                self.latch(source, destination, data, ecn);
            }
            return;
        };
        let p = lock(&self.peers).get(&id).cloned();
        if let Some(p) = p {
            p.input(source, destination, data, false, ecn);
        }
    }

    /// An RTP / RTCP datagram from an unknown source, offered to the latching peers (at most
    /// [`MAX_LATCH_TRIES`], starting where the last offer stopped) until one authenticates
    /// it; that peer then routes the source to itself if it latched.
    fn latch(&self, source: SocketAddr, destination: SocketAddr, data: &[u8], ecn: u8) {
        let ids: Vec<u64> = lock(&self.latching).clone();
        if ids.is_empty() {
            return;
        }
        let start = self.latch_next.fetch_add(1, Ordering::Relaxed) % ids.len();
        let peers: Vec<Peer> = {
            let all = lock(&self.peers);
            (0..ids.len().min(MAX_LATCH_TRIES))
                .filter_map(|i| all.get(&ids[(start + i) % ids.len()]).cloned())
                .collect()
        };
        for p in peers {
            if p.try_latch(source, destination, data, ecn) {
                return;
            }
        }
    }

    fn close_all(&self) {
        let all: Vec<Peer> = lock(&self.peers).values().cloned().collect();
        for p in all {
            p.close();
        }
    }
}

/// The UDP connection handler under an [`RtcServer`] or [`Endpoint`] (internal).
#[doc(hidden)]
pub struct RtcUdp {
    hub: Weak<Hub>,
    /// A connection of an [`RtcServer`]'s RTCP listener.
    rtcp: bool,
}

impl fmt::Debug for RtcUdp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtcUdp").finish_non_exhaustive()
    }
}

impl Handler for RtcUdp {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if let Some(hub) = self.hub.upgrade() {
            hub.on_datagram(c.peer_addr(), c.local_addr(), data, c.rx_ecn());
        }
    }

    fn on_close(&mut self, c: &Conn<Self>, _err: Option<only::Error>) {
        if let Some(hub) = self.hub.upgrade() {
            if let Tx::Listener(conns) = &hub.tx {
                let mut conns = if self.rtcp {
                    lock(&hub.rtcp_conns)
                } else {
                    lock(conns)
                };
                if conns.get(&c.peer_addr()).is_some_and(|x| x.id() == c.id()) {
                    conns.remove(&c.peer_addr());
                }
            }
        }
    }
}

/// Whether a datagram from local candidate base `src` goes out through the RTCP socket bound
/// at `rtcp` (its address, or its port and family when bound to the unspecified address).
fn rtcp_source(rtcp: SocketAddr, src: SocketAddr) -> bool {
    rtcp == src
        || (rtcp.ip().is_unspecified()
            && rtcp.port() == src.port()
            && rtcp.is_ipv4() == src.is_ipv4())
}

fn host_candidates(addrs: &[SocketAddr]) -> Vec<only_ice::Candidate> {
    addrs
        .iter()
        .filter(|a| !a.ip().is_unspecified() && a.port() != 0)
        .map(|a| only_ice::Candidate::host(*a))
        .collect()
}

/// An SDP the stack refused: a parse error is [`Error::Sdp`].
fn sdp_err(e: RtcErr) -> Error {
    Error::Sdp(e.0)
}

// ---- RtcServer ----

/// WebRTC peers on a [`only::Listener::udp`]: an [`Acceptor`] sharing the listener's port
/// among all its peers (ICE-lite by default). Clone it to keep a handle.
#[derive(Clone)]
pub struct RtcServer(Arc<Hub>);

impl fmt::Debug for RtcServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtcServer")
            .field("peers", &self.peers())
            .finish_non_exhaustive()
    }
}

impl RtcServer {
    /// A server whose host candidates are `addrs`: the addresses (IP and the listener's port)
    /// remote peers reach the listener at. They go into every answer and offer.
    pub fn new(addrs: Vec<SocketAddr>) -> RtcServer {
        RtcServer(Arc::new(Hub::new(
            Tx::Listener(Mutex::new(HashMap::new())),
            true,
            host_candidates(&addrs),
        )))
    }

    fn hub_mut(&mut self) -> &mut Hub {
        Arc::get_mut(&mut self.0).expect("configure the server before cloning it")
    }

    /// Builds every peer's configuration with `f` (start from [`rtc_config`]); the crypto
    /// provider and the ICE mode are set over it. Call before cloning the server.
    #[must_use]
    pub fn config(self, f: impl Fn() -> RtcConfig + Send + Sync + 'static) -> Self {
        *lock(&self.0.config) = Arc::new(f);
        self
    }

    /// Runs a full ICE agent instead of ICE-lite (the server then also sends checks; replies
    /// reach only peers that have sent it something). Call before cloning the server.
    #[must_use]
    pub fn ice_lite(mut self, yes: bool) -> Self {
        self.hub_mut().ice_lite = yes;
        self
    }

    /// Whether a peer whose ICE goes `Disconnected` (consent freshness lost) is closed
    /// (default `true`). Call before cloning the server.
    #[must_use]
    pub fn close_on_disconnect(self, yes: bool) -> Self {
        self.0.close_on_disconnect.store(yes, Ordering::Relaxed);
        self
    }

    /// Closes a peer that is not connected (ICE and DTLS up) this long after it was created
    /// (default 30 seconds; `None` waits forever). Call before cloning.
    #[must_use]
    pub fn connect_timeout(self, t: Option<Duration>) -> Self {
        *lock(&self.0.connect_timeout) = t;
        self
    }

    /// Most peers at once (default [`DEFAULT_MAX_PEERS`]); offers past it fail with
    /// [`Error::TooManyPeers`]. 0 removes the limit.
    #[must_use]
    pub fn max_peers(self, n: usize) -> Self {
        self.0.max_peers.store(n, Ordering::Relaxed);
        self
    }

    /// Passive ICE-TCP (RFC 6544): adds passive TCP host candidates `addrs` (the addresses
    /// remote peers reach the server's TCP listener at) to every answer and offer. Serve
    /// that listener with [`tcp`](Self::tcp). Remote agents with active TCP candidates
    /// (browsers, pion) connect and run checks, DTLS and media over the connection (RFC 4571
    /// framing); with ICE-lite the server only answers, as over UDP. A connection whose first
    /// frame is not a check for one of the server's peers within 10 seconds is closed, and so
    /// are a peer's connections when it closes; at most twice [`max_peers`](Self::max_peers)
    /// connections at once (at least 256; 4096 without a peer limit). Call before cloning the
    /// server.
    #[must_use]
    pub fn tcp_candidates(self, addrs: Vec<SocketAddr>) -> Self {
        let addrs: Vec<SocketAddr> = addrs
            .into_iter()
            .filter(|a| !a.ip().is_unspecified() && a.port() != 0)
            .collect();
        self.0.tcp_side().add_passive(&addrs);
        lock(&self.0.candidates).extend(
            addrs
                .iter()
                .map(|a| only_ice::Candidate::host_tcp(*a, only_ice::TcpType::Passive)),
        );
        self
    }

    /// The acceptor for the server's TCP listener (`Listener::tcp(addr).serve(server.tcp())`),
    /// whose addresses were given to [`tcp_candidates`](Self::tcp_candidates).
    pub fn tcp(&self) -> RtcTcp {
        RtcTcp(Arc::downgrade(&self.0.tcp_side()))
    }

    /// RTCP on its own port (RFC 5761 without rtcp-mux, ICE component 2, ADR-058): adds
    /// component-2 host candidates `addrs` (the addresses remote peers reach a second UDP
    /// listener at, served with [`rtcp`](Self::rtcp)) for new peers. Offers without
    /// `a=rtcp-mux` (SIP endpoints, older RTP stacks) are then answered with `a=rtcp` and RTCP
    /// on that listener, and [`RtcConfig::set_rtcp_mux_policy`] can offer it; offers with
    /// `a=rtcp-mux` (browsers) are answered as before. The listener's port must differ from
    /// the main one's. Call before cloning the server.
    #[must_use]
    pub fn rtcp_candidates(self, addrs: Vec<SocketAddr>) -> Self {
        let addrs: Vec<SocketAddr> = addrs
            .into_iter()
            .filter(|a| !a.ip().is_unspecified() && a.port() != 0)
            .collect();
        lock(&self.0.rtcp_bases).extend(&addrs);
        self.0
            .rtcp_listener
            .store(!lock(&self.0.rtcp_bases).is_empty(), Ordering::Relaxed);
        lock(&self.0.candidates).extend(
            addrs
                .iter()
                .map(|a| only_ice::Candidate::host(*a).with_component(2)),
        );
        self
    }

    /// The acceptor for the server's RTCP listener (`Listener::udp(addr).serve(server.rtcp())`),
    /// whose addresses were given to [`rtcp_candidates`](Self::rtcp_candidates).
    pub fn rtcp(&self) -> RtcRtcp {
        RtcRtcp(Arc::downgrade(&self.0))
    }

    /// Accepts a remote SDP offer for a new peer served by `handler`; returns the peer and
    /// the SDP answer (with this server's candidates) for the signalling to send back.
    pub fn accept_offer<H: PeerHandler>(
        &self,
        offer: &str,
        handler: H,
    ) -> Result<(Peer, String), Error> {
        self.0.accept_offer(offer, Box::new(handler))
    }

    /// Starts a new peer with an offer made by `f` (add media, data channels); returns the
    /// peer and the SDP offer. Hand the answer to [`Peer::accept_answer`].
    pub fn create_offer<H: PeerHandler>(
        &self,
        handler: H,
        f: impl FnOnce(&mut SdpChanges<'_, '_>),
    ) -> Result<(Peer, String), Error> {
        self.0.create_offer(Box::new(handler), f)
    }

    /// Open peers.
    pub fn peers(&self) -> usize {
        lock(&self.0.peers).len()
    }

    /// Closes every peer.
    pub fn close_all(&self) {
        self.0.close_all();
    }
}

impl Acceptor for RtcServer {
    type Handler = RtcUdp;
    fn on_open(&self, c: &Conn<RtcUdp>) -> RtcUdp {
        if let Tx::Listener(conns) = &self.0.tx {
            lock(conns).insert(c.peer_addr(), c.clone());
        }
        RtcUdp {
            hub: Arc::downgrade(&self.0),
            rtcp: false,
        }
    }

    fn on_shutdown(&self, _c: &Conn<RtcUdp>) {
        self.0.close_all();
    }
}

/// The acceptor of an [`RtcServer`]'s RTCP listener: ICE component 2 for peers without
/// rtcp-mux ([`RtcServer::rtcp_candidates`], [`RtcServer::rtcp`]).
#[derive(Clone)]
pub struct RtcRtcp(Weak<Hub>);

impl fmt::Debug for RtcRtcp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtcRtcp").finish_non_exhaustive()
    }
}

impl Acceptor for RtcRtcp {
    type Handler = RtcUdp;
    fn on_open(&self, c: &Conn<RtcUdp>) -> RtcUdp {
        if let Some(hub) = self.0.upgrade() {
            lock(&hub.rtcp_conns).insert(c.peer_addr(), c.clone());
        }
        RtcUdp {
            hub: self.0.clone(),
            rtcp: true,
        }
    }
}

// ---- Endpoint ----

/// A full ICE agent on a UDP socket of its own (bound at run time on a `only` engine), hosting
/// any number of peers that share its port. Clone it to keep a handle.
#[derive(Clone)]
pub struct Endpoint(Arc<Hub>);

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Endpoint")
            .field("local", &self.local_addr())
            .finish_non_exhaustive()
    }
}

struct BoundAcceptor(Weak<Hub>);

impl Acceptor for BoundAcceptor {
    type Handler = RtcUdp;
    fn on_open(&self, _c: &Conn<RtcUdp>) -> RtcUdp {
        RtcUdp {
            hub: self.0.clone(),
            rtcp: false,
        }
    }
}

/// The address of the interface that routes to the Internet (no packet is sent), else
/// loopback.
fn primary_ip(v6: bool) -> IpAddr {
    let (bind, probe): (SocketAddr, SocketAddr) = if v6 {
        (
            ([0u16; 8], 0).into(),
            "[2001:db8::1]:9"
                .parse()
                .unwrap_or_else(|_| ([0u16; 8], 9).into()),
        )
    } else {
        (([0, 0, 0, 0], 0).into(), ([192, 0, 2, 1], 9).into())
    };
    UdpSocket::bind(bind)
        .and_then(|s| s.connect(probe).and_then(|()| s.local_addr()))
        .map(|a| a.ip())
        .ok()
        .filter(|ip| !ip.is_unspecified())
        .unwrap_or(if v6 {
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        } else {
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        })
}

impl Endpoint {
    /// Binds `addr` on `engine` (which needs UDP I/O threads:
    /// [`only::EngineBuilder::udp_client_threads`] or a UDP listener, and must be started).
    /// The host candidate is `addr`, or, when it is the unspecified address, the address of
    /// the interface that routes to the Internet (loopback without one); add others with
    /// [`add_candidate`](Self::add_candidate).
    pub fn bind(engine: &Engine, addr: SocketAddr) -> Result<Endpoint, Error> {
        let hub = Arc::new(Hub::new(Tx::Bound(OnceLock::new()), false, Vec::new()));
        let b = engine
            .bind_udp(addr, BoundAcceptor(Arc::downgrade(&hub)))
            .map_err(Error::Io)?;
        let local = b.local_addr();
        let host = if local.ip().is_unspecified() {
            SocketAddr::new(primary_ip(local.is_ipv6()), local.port())
        } else {
            local
        };
        lock(&hub.candidates).extend(host_candidates(&[host]));
        if let Tx::Bound(cell) = &hub.tx {
            let _ = cell.set(b);
        }
        Ok(Endpoint(hub))
    }

    fn binding(&self) -> Option<&UdpBinding> {
        self.0.binding()
    }

    /// Binds a second socket at `addr` on `engine` for RTCP on its own port, as ICE
    /// component 2 (RFC 5761 without rtcp-mux, ADR-058), and returns its address; its host
    /// candidate (with the same rule for the unspecified address as [`bind`](Self::bind)) is
    /// given to new peers. With it, peers answer offers without `a=rtcp-mux` (SIP endpoints,
    /// older RTP stacks) with RTCP on that socket, and offer it with
    /// [`RtcConfig::set_rtcp_mux_policy`]; offers with `a=rtcp-mux` (browsers) are answered
    /// with it as before. Bind it before gathering: [`gather_srflx`](Self::gather_srflx),
    /// [`gather_relay`](Self::gather_relay) and [`gather_relay_via`](Self::gather_relay_via)
    /// then also gather component 2's server-reflexive and relayed candidates from it. Once
    /// per endpoint: [`Error::Io`] otherwise.
    pub fn bind_rtcp(&self, engine: &Engine, addr: SocketAddr) -> Result<SocketAddr, Error> {
        if self.0.rtcp.get().is_some() {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "the RTCP socket is bound already",
            )));
        }
        let b = engine
            .bind_udp(addr, BoundAcceptor(Arc::downgrade(&self.0)))
            .map_err(Error::Io)?;
        let local = b.local_addr();
        let host = if local.ip().is_unspecified() {
            SocketAddr::new(primary_ip(local.is_ipv6()), local.port())
        } else {
            local
        };
        if self.0.rtcp.set(b).is_err() {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "the RTCP socket is bound already",
            )));
        }
        lock(&self.0.candidates).push(only_ice::Candidate::host(host).with_component(2));
        Ok(local)
    }

    /// Binds another socket at `addr` on `engine` for a transport of its own (ADR-072) and
    /// returns its address. A session without BUNDLE ([`RtcConfig::set_bundle_policy`], or a
    /// remote that does not bundle) runs an ICE agent, DTLS association and SRTP keys per
    /// section; the first section uses the endpoint's socket, and the n-th one after it the
    /// n-th socket bound here (or the endpoint's when there are fewer), with that socket's host
    /// candidate (server-reflexive and relayed candidates stay the endpoint's). Transports on
    /// one socket are told apart by the remote's addresses, which is enough toward peers with
    /// an address per section (browsers, SIP endpoints); a remote that is also one socket per
    /// session (this stack without these sockets) needs them on one side. Component 2 (RTCP
    /// without rtcp-mux) of every transport stays on [`bind_rtcp`](Self::bind_rtcp)'s socket.
    pub fn bind_transport_socket(
        &self,
        engine: &Engine,
        addr: SocketAddr,
    ) -> Result<SocketAddr, Error> {
        let b = engine
            .bind_udp(addr, BoundAcceptor(Arc::downgrade(&self.0)))
            .map_err(Error::Io)?;
        let local = b.local_addr();
        let host = if local.ip().is_unspecified() {
            SocketAddr::new(primary_ip(local.is_ipv6()), local.port())
        } else {
            local
        };
        let mut socks = lock(&self.0.tp_socks);
        socks.push((b, only_ice::Candidate::host(host)));
        self.0.tp_count.store(socks.len(), Ordering::Release);
        Ok(local)
    }

    /// The address of the RTCP socket ([`bind_rtcp`](Self::bind_rtcp)).
    pub fn rtcp_addr(&self) -> Option<SocketAddr> {
        self.0.rtcp.get().map(UdpBinding::local_addr)
    }

    /// The bound address.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.binding().map(UdpBinding::local_addr)
    }

    /// The local candidates new peers start with.
    pub fn candidates(&self) -> Vec<Candidate> {
        lock(&self.0.candidates)
            .iter()
            .cloned()
            .map(Candidate)
            .collect()
    }

    /// Adds a local candidate for new peers (another host address of the socket, or a
    /// server-reflexive or relayed one learnt elsewhere).
    pub fn add_candidate(&self, c: Candidate) {
        lock(&self.0.candidates).push(c.0);
    }

    /// Asks the STUN server at `stun_server` for this socket's public (server-reflexive)
    /// address, waiting up to `timeout` (retransmitting every 250 ms), and adds it as a
    /// candidate for new peers. With an RTCP socket ([`bind_rtcp`](Self::bind_rtcp), bound
    /// before), its public address is asked for at the same time and added as a component-2
    /// candidate (RTCP without rtcp-mux); both must answer. Returns the main socket's.
    /// Blocks: do not call it from a `only` I/O thread or a callback.
    pub fn gather_srflx(
        &self,
        stun_server: SocketAddr,
        timeout: Duration,
    ) -> Result<SocketAddr, Error> {
        let b = self.binding().ok_or(Error::Closed)?.clone();
        let mut socks = vec![(b, 1u16)];
        if let Some(r) = self.0.rtcp.get() {
            socks.push((r.clone(), 2));
        }
        let (tx, rx) = mpsc::channel();
        let mut asks = Vec::new();
        for (sock, comp) in socks {
            let tid = stun::transaction_id();
            lock(&self.0.stun_waiters).insert(tid, tx.clone());
            asks.push((sock, comp, tid, stun::binding_request(tid), None));
        }
        drop(tx);
        let deadline = Instant::now() + timeout;
        let r = loop {
            for (sock, _, _, req, got) in &asks {
                if got.is_none() {
                    let _ = sock.send_to(req, stun_server);
                }
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break Err(Error::Timeout);
            }
            match rx.recv_timeout(left.min(Duration::from_millis(250))) {
                Ok((tid, a)) => {
                    if let Some(x) = asks.iter_mut().find(|x| x.2 == tid) {
                        x.4 = Some(a);
                    }
                    if asks.iter().all(|x| x.4.is_some()) {
                        break Ok(());
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break Err(Error::Closed),
            }
        };
        {
            let mut w = lock(&self.0.stun_waiters);
            for x in &asks {
                w.remove(&x.2);
            }
        }
        r?;
        let mut mapped1 = None;
        for (sock, comp, _, _, got) in asks {
            let Some(mapped) = got else { continue };
            let mut cs = lock(&self.0.candidates);
            let base = cs
                .iter()
                .find(|c| c.kind() == only_ice::CandidateKind::Host && c.component() == comp)
                .map_or_else(|| sock.local_addr(), only_ice::Candidate::addr);
            if comp == 1 {
                mapped1 = Some(mapped);
            }
            if !cs
                .iter()
                .any(|x| x.addr() == mapped && x.component() == comp)
            {
                cs.push(only_ice::Candidate::server_reflexive(mapped, base).with_component(comp));
            }
        }
        mapped1.ok_or(Error::Timeout)
    }

    /// Allocates a relayed address on the TURN server at `turn_server` (over UDP from this
    /// endpoint's socket, long-term credentials `username` / `password`), waiting up to
    /// `timeout`, and adds it as a relayed candidate for new peers; the server-reflexive
    /// address the server saw is added too when it differs from the host candidates. The
    /// allocation, its permissions and channels are refreshed while the endpoint lives, and
    /// shared by every peer; one that is lost is made again (see
    /// [`gather_relay_via`](Self::gather_relay_via)). With an RTCP socket
    /// ([`bind_rtcp`](Self::bind_rtcp)), a second allocation is made at the same time from it
    /// for ICE component 2 (RTCP without rtcp-mux), with its own relayed and server-reflexive
    /// candidates; both must succeed. At most 4 allocations per endpoint and component.
    /// Blocks: do not call it from a `only` I/O thread or a callback.
    pub fn gather_relay(
        &self,
        turn_server: SocketAddr,
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> Result<SocketAddr, Error> {
        self.gather(
            Weak::new(),
            &RelayServer::udp(turn_server, username, password),
            timeout,
        )
    }

    /// [`gather_relay`](Self::gather_relay) on `server`, over UDP, DTLS, TCP or TLS
    /// ([`RelayServer`]): over a stream, `engine` (which needs TCP I/O threads:
    /// [`only::EngineBuilder::client_threads`] or a TCP listener) dials the connection the
    /// allocation lives on, and the candidate ranks below a UDP-allocated one; no
    /// server-reflexive candidate comes from it (the server saw a TCP address). One allocation
    /// per server and transport.
    ///
    /// An allocation lost after it was made (the connection closed, a refresh failed) is made
    /// again, after 1 second and then doubling waits up to a minute, while the endpoint lives:
    /// its new relayed candidate replaces the old one for new peers and is added to the open
    /// ones, whose agents check it against the remote candidates they know (a peer that
    /// reached the other side only through the old relayed address needs an ICE restart,
    /// [`SdpChanges::ice_restart`], whose offer carries the new candidate). Blocks: do not
    /// call it from a `only` I/O thread or a callback.
    pub fn gather_relay_via(
        &self,
        engine: &Arc<Engine>,
        server: &RelayServer,
        timeout: Duration,
    ) -> Result<SocketAddr, Error> {
        self.gather(Arc::downgrade(engine), server, timeout)
    }

    fn gather(
        &self,
        engine: Weak<Engine>,
        server: &RelayServer,
        timeout: Duration,
    ) -> Result<SocketAddr, Error> {
        if server.needs_tls_config() {
            return Err(Error::Turn(
                "a turns: server needs RelayServer::tls_config".into(),
            ));
        }
        let b = self.binding().ok_or(Error::Closed)?.clone();
        let deadline = Instant::now() + timeout;
        // Component 2's allocation (RTCP socket) runs next to component 1's.
        let mut started = vec![self.start_relay(&engine, server, false)?];
        if self.0.rtcp.get().is_some() {
            match self.start_relay(&engine, server, true) {
                Ok(r) => started.push(r),
                Err(e) => {
                    self.drop_relay(&started[0].0);
                    return Err(e);
                }
            }
        }
        let mut done = Vec::new();
        let mut failed = None;
        for (r, rx) in &started {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(Ok(a)) => done.push((r.clone(), a)),
                Ok(Err(e)) => failed = Some(Error::Turn(e)),
                Err(_) => failed = Some(Error::Timeout),
            }
            if failed.is_some() {
                break;
            }
        }
        if let Some(e) = failed {
            for (r, _) in &started {
                self.drop_relay(r);
            }
            return Err(e);
        }
        let mut cs = lock(&self.0.candidates);
        let mut first = None;
        for (r, (relayed, mapped)) in done {
            let comp = if r.rtcp { 2 } else { 1 };
            let base = r.base().unwrap_or_else(|| b.local_addr());
            if !server.wire.is_stream() {
                if let Some(m) =
                    mapped.filter(|m| !cs.iter().any(|x| x.addr() == *m && x.component() == comp))
                {
                    cs.push(only_ice::Candidate::server_reflexive(m, base).with_component(comp));
                }
            }
            if !cs.iter().any(|x| x.addr() == relayed) {
                cs.push(r.candidate(relayed, base));
            }
            first.get_or_insert(relayed);
        }
        first.ok_or(Error::Timeout)
    }

    /// Registers and starts an allocation on `server` for component 1, or for component 2
    /// from the RTCP socket (`rtcp`); its result arrives on the receiver.
    fn start_relay(
        &self,
        engine: &Weak<Engine>,
        server: &RelayServer,
        rtcp: bool,
    ) -> Result<(Arc<relay::Relay>, mpsc::Receiver<relay::Allocated>), Error> {
        let dtls_cfg = match &server.wire {
            relay::Wire::Dtls(c, name) => Some(relay::dtls_config(c, name).map_err(Error::Turn)?),
            _ => None,
        };
        let (tx, rx) = mpsc::channel();
        let cfg =
            only_turn::client::ClientConfig::new(server.addr, &server.username, &server.password);
        let r = self.0.with_relays(|relays| {
            relays.retain(|r| !r.is_dead());
            if relays.iter().filter(|r| r.rtcp == rtcp).count() >= MAX_RELAYS {
                return Err(Error::Turn("too many TURN allocations".into()));
            }
            // Datagrams from the server's address to one socket go to one relay: UDP and DTLS
            // ones share that.
            let datagram = !server.wire.is_stream();
            if relays.iter().any(|r| {
                r.server == server.addr
                    && r.rtcp == rtcp
                    && (r.wire.code() == server.wire.code() || datagram && !r.wire.is_stream())
            }) {
                return Err(Error::Turn(format!(
                    "an allocation on {} over {} exists already",
                    server.addr,
                    server.transport()
                )));
            }
            let r = relay::Relay::new(
                &self.0,
                engine.clone(),
                server.wire.clone(),
                dtls_cfg,
                cfg,
                rtcp,
                tx,
            );
            relays.push(r.clone());
            Ok(r)
        })?;
        // The first Allocate goes out (or the connection is dialed) here.
        r.start();
        Ok((r, rx))
    }

    fn drop_relay(&self, r: &Arc<relay::Relay>) {
        r.close();
        self.0
            .with_relays(|relays| relays.retain(|x| !Arc::ptr_eq(x, r)));
    }

    /// Listens for ICE-TCP connections (RFC 6544) on `addr` and adds a passive TCP host
    /// candidate for new peers: remote agents with active TCP candidates (browsers, pion)
    /// connect to it and run checks, DTLS and media over the connection (RFC 4571 framing).
    /// The candidate is `addr`, or with the unspecified address the endpoint's primary
    /// address, with the bound port, which must differ from the UDP port (port 0 picks one).
    /// Returns the candidate's address. A dedicated thread accepts (at most 256 connections at
    /// once); a connection whose first frame is not a check for one of this endpoint's peers
    /// within 10 seconds is closed, and so are a peer's connections when it closes. Once per
    /// endpoint; needs an engine with TCP I/O threads ([`only::EngineBuilder::client_threads`]
    /// or a TCP listener).
    pub fn listen_tcp(&self, engine: &Arc<Engine>, addr: SocketAddr) -> Result<SocketAddr, Error> {
        if self.0.tcp.get().is_some_and(|t| t.is_listening()) {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "the endpoint listens on TCP already",
            )));
        }
        let udp = self.local_addr().ok_or(Error::Closed)?;
        let mut l = std::net::TcpListener::bind(addr).map_err(Error::Io)?;
        if l.local_addr().map_err(Error::Io)?.port() == udp.port() {
            if addr.port() != 0 {
                return Err(Error::InvalidCandidate(format!(
                    "{addr}: the TCP port must differ from the UDP port"
                )));
            }
            l = std::net::TcpListener::bind(addr).map_err(Error::Io)?;
        }
        let bound = l.local_addr().map_err(Error::Io)?;
        let local = if bound.ip().is_unspecified() {
            SocketAddr::new(primary_ip(bound.is_ipv6()), bound.port())
        } else {
            bound
        };
        self.0
            .tcp_side()
            .listen(engine, l, local)
            .map_err(Error::Io)?;
        lock(&self.0.candidates).push(only_ice::Candidate::host_tcp(
            local,
            only_ice::TcpType::Passive,
        ));
        Ok(local)
    }

    /// Adds an active ICE-TCP host candidate (RFC 6544) for new peers: their agents pair it
    /// with the remote passive TCP candidates (an [`RtcServer`] or an endpoint listening on
    /// TCP, pion, a TCP-only media server) and `engine` (which needs TCP I/O threads:
    /// [`only::EngineBuilder::client_threads`] or a TCP listener) dials one connection per
    /// pair when its first check goes out; checks, DTLS and media then run over it (RFC 4571
    /// framing). The candidate's address is the endpoint's primary host address with port 9,
    /// as the SDP writes an active candidate; it is returned. A connection that fails or
    /// closes is dialed again by the agent's next check; a peer's connections close with it.
    /// Connections of the endpoint (active and passive) are bounded together (256). Once per
    /// endpoint.
    pub fn dial_tcp(&self, engine: &Arc<Engine>) -> Result<SocketAddr, Error> {
        let host = lock(&self.0.candidates)
            .iter()
            .find(|c| c.kind() == only_ice::CandidateKind::Host && c.tcp_type().is_none())
            .map(only_ice::Candidate::addr)
            .or_else(|| self.local_addr())
            .ok_or(Error::Closed)?;
        let addr = SocketAddr::new(host.ip(), 9);
        if !self.0.tcp_side().set_active(engine, addr) {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "the endpoint has an active TCP candidate already",
            )));
        }
        lock(&self.0.candidates).push(only_ice::Candidate::host_tcp(
            addr,
            only_ice::TcpType::Active,
        ));
        Ok(addr)
    }

    /// Resolves remote candidates whose address is an mDNS name (`<uuid>.local`: browsers
    /// conceal their host addresses so, draft-ietf-mmusic-mdns-ice-candidates), in
    /// descriptions and trickled ([`Peer::add_remote_candidate`]), with one-shot mDNS queries
    /// (RFC 6762 §5.1) sent at once, after 1 and 2 seconds and then every 2 seconds, giving
    /// up after `timeout`; the peers get the resolved candidates (one per address the name
    /// has) as they arrive, answers are cached for their TTL. Without it such candidates are
    /// skipped (the remote's checks still reach a reachable endpoint, as peer-reflexive
    /// candidates).
    ///
    /// The queries and answers go through a socket served by `engine` (which needs UDP I/O
    /// threads: [`only::EngineBuilder::udp_client_threads`] or a UDP listener, and must be
    /// started): the mDNS port 5353 shared with the system's responder and the
    /// `224.0.0.251` group, or, when that port cannot be bound, an ephemeral port asking for
    /// unicast answers (then [`conceal_host_candidates`](Self::conceal_host_candidates) is
    /// not available). With IPv6, a second socket does the same over `ff02::fb`, joined on
    /// every interface with a link-local address: queries go out on each, answers go back on
    /// the link of their query, and a resolved link-local address is reached through the
    /// interface its answer came from (ADR-054). Once per endpoint.
    pub fn resolve_mdns(&self, engine: &Engine, timeout: Duration) -> Result<(), Error> {
        if self.0.mdns.get().is_some() {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "the endpoint resolves mDNS names already",
            )));
        }
        let m = mdns::Mdns::new(&self.0, engine, timeout).map_err(Error::Io)?;
        if let Err(m) = self.0.mdns.set(m) {
            m.close();
        }
        Ok(())
    }

    /// Conceals this endpoint's host addresses as browsers do: new peers signal each host
    /// candidate with a random mDNS name (`<uuid>.local`, one per address) instead of its
    /// IP, and the related address of server-reflexive and relayed candidates as
    /// `0.0.0.0:0`; the endpoint answers mDNS queries for those names on the local network.
    /// Needs [`resolve_mdns`](Self::resolve_mdns) first, on the shared mDNS port
    /// ([`Error::Io`] otherwise). The remote must resolve the names (browsers do) or reach
    /// this endpoint through other candidates. Applies to the peers created after the call.
    pub fn conceal_host_candidates(&self) -> Result<(), Error> {
        match self.0.mdns.get() {
            Some(m) if m.can_respond() => {
                self.0.conceal.store(true, Ordering::Relaxed);
                Ok(())
            }
            Some(_) => Err(Error::Io(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "the mDNS port could not be bound: no mDNS answers possible",
            ))),
            None => Err(Error::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "call resolve_mdns first",
            ))),
        }
    }

    /// Adds a simultaneous-open ICE-TCP host candidate (RFC 6544 `tcptype so`) for new
    /// peers: it pairs with the remote's `so` candidates (libnice, another endpoint), and
    /// both sides connect at once between the two advertised ports. The candidate's port
    /// listens (connections the remote opens first are accepted and identified by their first
    /// check, as for [`listen_tcp`](Self::listen_tcp)) and the checks to a remote `so`
    /// candidate are dialed from that same port (`SO_REUSEPORT`) when no connection with it
    /// was accepted; connects that cross make one connection (TCP simultaneous open). Checks,
    /// DTLS and media then run over it (RFC 4571 framing). The candidate is `addr`, or with
    /// the unspecified address the endpoint's primary address, with the bound port, which
    /// must differ from the UDP port (port 0 picks one); it is returned. A dedicated thread
    /// accepts; the connections count with the endpoint's others (256). Once per endpoint;
    /// needs an engine with TCP I/O threads ([`only::EngineBuilder::client_threads`] or a
    /// TCP listener). Browsers and pion have no `so` candidates.
    pub fn listen_tcp_so(
        &self,
        engine: &Arc<Engine>,
        addr: SocketAddr,
    ) -> Result<SocketAddr, Error> {
        let udp = self.local_addr().ok_or(Error::Closed)?;
        if addr.port() != 0 && addr.port() == udp.port() {
            return Err(Error::InvalidCandidate(format!(
                "{addr}: the TCP port must differ from the UDP port"
            )));
        }
        let mut l = only_sys::listen(addr, true, 128).map_err(Error::Io)?;
        if l.local_addr().map_err(Error::Io)?.port() == udp.port() {
            l = only_sys::listen(addr, true, 128).map_err(Error::Io)?;
        }
        l.set_nonblocking(false).map_err(Error::Io)?;
        let bound = l.local_addr().map_err(Error::Io)?;
        let local = if bound.ip().is_unspecified() {
            SocketAddr::new(primary_ip(bound.is_ipv6()), bound.port())
        } else {
            bound
        };
        self.0
            .tcp_side()
            .listen_so(engine, l, local)
            .map_err(Error::Io)?;
        lock(&self.0.candidates).push(only_ice::Candidate::host_tcp(local, only_ice::TcpType::So));
        Ok(local)
    }

    /// Builds every peer's configuration with `f` (start from [`rtc_config`]); applies to the
    /// peers created after the call.
    #[must_use]
    pub fn config(self, f: impl Fn() -> RtcConfig + Send + Sync + 'static) -> Self {
        *lock(&self.0.config) = Arc::new(f);
        self
    }

    /// Which local candidates new peers use, as a browser's `iceTransportPolicy`: only those
    /// `f` accepts go into their agents and their offers and answers (`|c| c.kind() ==
    /// "relay"` for a relay-only policy, `|c| c.transport() == "tcp"` for ICE-TCP only).
    /// [`candidates`](Self::candidates) still lists them all. Applies to the peers created
    /// after the call.
    #[must_use]
    pub fn candidate_filter(self, f: impl Fn(&Candidate) -> bool + Send + Sync + 'static) -> Self {
        *lock(&self.0.filter) = Some(Arc::new(f));
        self
    }

    /// Whether a peer whose ICE goes `Disconnected` is closed (default `true`).
    #[must_use]
    pub fn close_on_disconnect(self, yes: bool) -> Self {
        self.0.close_on_disconnect.store(yes, Ordering::Relaxed);
        self
    }

    /// Closes a peer that is not connected (ICE and DTLS up) this long after it was created
    /// (default 30 seconds; `None` waits forever); applies to the peers created after the
    /// call.
    #[must_use]
    pub fn connect_timeout(self, t: Option<Duration>) -> Self {
        *lock(&self.0.connect_timeout) = t;
        self
    }

    /// Most peers at once (default [`DEFAULT_MAX_PEERS`]); offers past it fail with
    /// [`Error::TooManyPeers`]. 0 removes the limit.
    #[must_use]
    pub fn max_peers(self, n: usize) -> Self {
        self.0.max_peers.store(n, Ordering::Relaxed);
        self
    }

    /// Starts a new peer with an offer made by `f`; returns the peer and the SDP offer (with
    /// this endpoint's candidates). Hand the answer to [`Peer::accept_answer`].
    pub fn create_offer<H: PeerHandler>(
        &self,
        handler: H,
        f: impl FnOnce(&mut SdpChanges<'_, '_>),
    ) -> Result<(Peer, String), Error> {
        self.0.create_offer(Box::new(handler), f)
    }

    /// Accepts a remote SDP offer for a new peer; returns the peer and the SDP answer.
    pub fn accept_offer<H: PeerHandler>(
        &self,
        offer: &str,
        handler: H,
    ) -> Result<(Peer, String), Error> {
        self.0.accept_offer(offer, Box::new(handler))
    }

    /// Open peers.
    pub fn peers(&self) -> usize {
        lock(&self.0.peers).len()
    }

    /// Closes every peer, deletes the TURN allocations and closes the socket.
    pub fn close(&self) {
        self.0.close_all();
        let relays = self.0.with_relays(std::mem::take);
        for r in relays {
            r.close();
        }
        if let Some(t) = self.0.tcp.get() {
            t.close();
        }
        if let Some(m) = self.0.mdns.get() {
            m.close();
        }
        if let Some(b) = self.binding() {
            b.close();
        }
        if let Some(b) = self.0.rtcp.get() {
            b.close();
        }
    }
}
