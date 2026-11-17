#![forbid(unsafe_code)]
//! WebRTC for `only`: an in-house, sans-io WebRTC stack driven by `only` UDP sockets, with no
//! third-party dependencies.
//!
//! The protocol layers are crates of their own: ICE (full agent and ICE-lite, consent
//! freshness, trickle, restarts: `only-ice`), DTLS 1.2 with DTLS-SRTP and certificate
//! fingerprint verification (`only-dtls`), SRTP/SRTCP with AES-CM-HMAC-SHA1-80/32 and
//! AEAD-AES-128/256-GCM (`only-srtp`), RTP/RTCP with packetization of Opus, G.711, G.722, VP8,
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

use crate::rtc::{Output, Rtc, RtcErr, RtcEvent};
use crate::types::ConfigInner;
pub use crate::types::{
    Candidate, ChannelConfig, ChannelId, Codec, Direction, Event, Frequency, IceConnectionState,
    KeyframeRequest, KeyframeRequestKind, MediaAdded, MediaData, MediaKind, MediaTime, Mid,
    OtherEvent, Pt, Reliability, RtcConfig, RtpPacket, SdpChanges,
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
                connect_by: hub.connect_timeout.map(|d| Instant::now() + d),
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

    /// Adds a trickled remote ICE candidate (`candidate:...` or `a=candidate:...`).
    pub fn add_remote_candidate(&self, candidate: &str) -> Result<(), Error> {
        let c = Candidate::parse(candidate)?;
        self.with_rtc_inner(|rtc| rtc.add_remote_candidate(c.0))
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

    /// One datagram for this peer.
    fn input(&self, source: SocketAddr, destination: SocketAddr, data: &[u8]) {
        {
            let mut st = lock(&self.0.state);
            if st.closed {
                return;
            }
            st.rtc
                .handle_receive(Instant::now(), source, destination, data);
        }
        self.drive();
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
        let close_on_disconnect = hub.as_ref().is_some_and(|h| h.close_on_disconnect);
        {
            let mut st = lock(&self.0.state);
            if st.closed {
                return;
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
                    Output::Transmit(src, dest, contents) => {
                        if let Some(hub) = &hub {
                            hub.transmit(self.0.id, src, dest, &contents);
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
    close_on_disconnect: bool,
    connect_timeout: Option<Duration>,
    config: Box<ConfigFn>,
    candidates: Mutex<Vec<only_ice::Candidate>>,
    peers: Mutex<HashMap<u64, Peer>>,
    by_ufrag: Mutex<HashMap<String, u64>>,
    by_addr: Mutex<HashMap<SocketAddr, u64>>,
    stun_waiters: Mutex<HashMap<[u8; 12], mpsc::Sender<SocketAddr>>>,
    /// TURN allocations ([`Endpoint::gather_relay`]), at most [`MAX_RELAYS`].
    relays: Mutex<Vec<Arc<relay::Relay>>>,
    /// The passive ICE-TCP candidate's listener ([`Endpoint::listen_tcp`]).
    tcp: OnceLock<Arc<tcp::TcpSide>>,
}

/// Most TURN allocations of one [`Endpoint`].
const MAX_RELAYS: usize = 4;

impl Hub {
    fn new(tx: Tx, ice_lite: bool, candidates: Vec<only_ice::Candidate>) -> Hub {
        Hub {
            tx,
            ice_lite,
            max_peers: AtomicUsize::new(DEFAULT_MAX_PEERS),
            close_on_disconnect: true,
            connect_timeout: Some(Duration::from_secs(30)),
            config: Box::new(rtc_config),
            candidates: Mutex::new(candidates),
            peers: Mutex::new(HashMap::new()),
            by_ufrag: Mutex::new(HashMap::new()),
            by_addr: Mutex::new(HashMap::new()),
            stun_waiters: Mutex::new(HashMap::new()),
            relays: Mutex::new(Vec::new()),
            tcp: OnceLock::new(),
        }
    }

    fn peer_by_ufrag(&self, ufrag: &str) -> Option<u64> {
        lock(&self.by_ufrag).get(ufrag).copied()
    }

    /// Hands a datagram to peer `id`; `false` if it is gone.
    fn input_peer(
        &self,
        id: u64,
        source: SocketAddr,
        destination: SocketAddr,
        data: &[u8],
    ) -> bool {
        let p = lock(&self.peers).get(&id).cloned();
        match p {
            Some(p) => {
                p.input(source, destination, data);
                true
            }
            None => false,
        }
    }

    fn binding(&self) -> Option<&UdpBinding> {
        match &self.tx {
            Tx::Bound(b) => b.get(),
            Tx::Listener(_) => None,
        }
    }

    /// The relay whose allocation has the relayed address `addr`.
    fn relay_at(&self, addr: SocketAddr) -> Option<Arc<relay::Relay>> {
        let relays = lock(&self.relays);
        if relays.is_empty() {
            return None;
        }
        relays
            .iter()
            .find(|r| r.relayed.get() == Some(&addr))
            .cloned()
    }

    /// The relay whose TURN server is at `addr`.
    fn relay_of_server(&self, addr: SocketAddr) -> Option<Arc<relay::Relay>> {
        let relays = lock(&self.relays);
        if relays.is_empty() {
            return None;
        }
        relays.iter().find(|r| r.server == addr).cloned()
    }

    fn new_rtc(&self) -> Result<Rtc, Error> {
        let mut rtc =
            Rtc::new((self.config)().0, self.ice_lite, Instant::now()).map_err(rtc_err)?;
        for c in lock(&self.candidates).iter() {
            rtc.add_local_candidate(c.clone());
        }
        Ok(rtc)
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

    fn remove(&self, id: u64) {
        let p = lock(&self.peers).remove(&id);
        if let Some(p) = p {
            lock(&self.by_ufrag).remove(&p.0.ufrag);
        }
        lock(&self.by_addr).retain(|_, v| *v != id);
        if let Some(t) = self.tcp.get() {
            t.close_peer(id);
        }
    }

    fn transmit(&self, id: u64, src: SocketAddr, dest: SocketAddr, data: &[u8]) {
        // Replies from where we send belong to this peer (full ICE agents send first).
        if let Some(t) = self.tcp.get().filter(|t| t.local == src) {
            t.send(dest, data);
            return;
        }
        lock(&self.by_addr).entry(dest).or_insert(id);
        if let Some(r) = self.relay_at(src) {
            r.send(dest, data);
            return;
        }
        match &self.tx {
            Tx::Listener(conns) => {
                let c = lock(conns).get(&dest).cloned();
                if let Some(c) = c {
                    let _ = c.send(data);
                }
            }
            Tx::Bound(b) => {
                if let Some(b) = b.get() {
                    let _ = b.send_to(data, dest);
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
        lock(&self.candidates)
            .iter()
            .map(only_ice::Candidate::addr)
            .find(|a| a.port() == local.port() && a.is_ipv4() == local.is_ipv4())
            .unwrap_or(local)
    }

    fn on_datagram(&self, source: SocketAddr, local: SocketAddr, data: &[u8]) {
        let is_stun = stun::is_stun(data);
        if is_stun && !lock(&self.stun_waiters).is_empty() {
            if let Ok(m) = stun::Message::parse(data) {
                let tx = lock(&self.stun_waiters).remove(&m.transaction_id());
                if let Some(tx) = tx {
                    if let Some(a) = stun::parse_binding_response(data, &m.transaction_id()) {
                        let _ = tx.send(a);
                    }
                    return;
                }
            }
        }
        if let Some(r) = self.relay_of_server(source) {
            if let Some((peer, relayed, data)) = r.input(data) {
                self.route(peer, relayed, &data);
            }
            return;
        }
        self.route(source, self.destination(local), data);
    }

    /// A datagram from `source` that arrived on the local address `destination`, for a peer.
    fn route(&self, source: SocketAddr, destination: SocketAddr, data: &[u8]) {
        let is_stun = stun::is_stun(data);
        let mut id = lock(&self.by_addr).get(&source).copied();
        if id.is_none() && is_stun {
            // A connectivity check: USERNAME is "<our ufrag>:<their ufrag>".
            if let Ok(m) = stun::Message::parse(data) {
                if let Some(u) = m.get_str(stun::attr::USERNAME) {
                    let ours = u.split(':').next().unwrap_or("");
                    id = lock(&self.by_ufrag).get(ours).copied();
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
        let Some(id) = id else { return };
        let p = lock(&self.peers).get(&id).cloned();
        if let Some(p) = p {
            p.input(source, destination, data);
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
}

impl fmt::Debug for RtcUdp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtcUdp").finish_non_exhaustive()
    }
}

impl Handler for RtcUdp {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if let Some(hub) = self.hub.upgrade() {
            hub.on_datagram(c.peer_addr(), c.local_addr(), data);
        }
    }

    fn on_close(&mut self, c: &Conn<Self>, _err: Option<only::Error>) {
        if let Some(hub) = self.hub.upgrade() {
            if let Tx::Listener(conns) = &hub.tx {
                let mut conns = lock(conns);
                if conns.get(&c.peer_addr()).is_some_and(|x| x.id() == c.id()) {
                    conns.remove(&c.peer_addr());
                }
            }
        }
    }
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
    pub fn config(mut self, f: impl Fn() -> RtcConfig + Send + Sync + 'static) -> Self {
        self.hub_mut().config = Box::new(f);
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
    pub fn close_on_disconnect(mut self, yes: bool) -> Self {
        self.hub_mut().close_on_disconnect = yes;
        self
    }

    /// Closes a peer that is not connected (ICE and DTLS up) this long after it was created
    /// (default 30 seconds; `None` waits forever). Call before cloning.
    #[must_use]
    pub fn connect_timeout(mut self, t: Option<Duration>) -> Self {
        self.hub_mut().connect_timeout = t;
        self
    }

    /// Most peers at once (default [`DEFAULT_MAX_PEERS`]); offers past it fail with
    /// [`Error::TooManyPeers`]. 0 removes the limit.
    #[must_use]
    pub fn max_peers(self, n: usize) -> Self {
        self.0.max_peers.store(n, Ordering::Relaxed);
        self
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
        }
    }

    fn on_shutdown(&self, _c: &Conn<RtcUdp>) {
        self.0.close_all();
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
    /// candidate for new peers. Blocks: do not call it from a `only` I/O thread or a callback.
    pub fn gather_srflx(
        &self,
        stun_server: SocketAddr,
        timeout: Duration,
    ) -> Result<SocketAddr, Error> {
        let b = self.binding().ok_or(Error::Closed)?.clone();
        let tid = stun::transaction_id();
        let (tx, rx) = mpsc::channel();
        lock(&self.0.stun_waiters).insert(tid, tx);
        let req = stun::binding_request(tid);
        let deadline = Instant::now() + timeout;
        let r = loop {
            let _ = b.send_to(&req, stun_server);
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break Err(Error::Timeout);
            }
            match rx.recv_timeout(left.min(Duration::from_millis(250))) {
                Ok(a) => break Ok(a),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break Err(Error::Closed),
            }
        };
        lock(&self.0.stun_waiters).remove(&tid);
        let mapped = r?;
        let base = lock(&self.0.candidates)
            .first()
            .map_or_else(|| b.local_addr(), only_ice::Candidate::addr);
        {
            let c = only_ice::Candidate::server_reflexive(mapped, base);
            let mut cs = lock(&self.0.candidates);
            if !cs.iter().any(|x| x.addr() == mapped) {
                cs.push(c);
            }
        }
        Ok(mapped)
    }

    /// Allocates a relayed address on the TURN server at `turn_server` (over UDP from this
    /// endpoint's socket, long-term credentials `username` / `password`), waiting up to
    /// `timeout`, and adds it as a relayed candidate for new peers; the server-reflexive
    /// address the server saw is added too when it differs from the host candidates. The
    /// allocation, its permissions and channels are refreshed while the endpoint lives, and
    /// shared by every peer. At most 4 allocations per endpoint. Blocks: do not call it from a
    /// `only` I/O thread or a callback.
    pub fn gather_relay(
        &self,
        turn_server: SocketAddr,
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> Result<SocketAddr, Error> {
        let b = self.binding().ok_or(Error::Closed)?.clone();
        let (tx, rx) = mpsc::channel();
        let cfg = only_turn::client::ClientConfig::new(turn_server, username, password);
        let r = {
            let mut relays = lock(&self.0.relays);
            relays.retain(|r| !r.is_dead());
            if relays.len() >= MAX_RELAYS {
                return Err(Error::Turn("too many TURN allocations".into()));
            }
            if relays.iter().any(|r| r.server == turn_server) {
                return Err(Error::Turn(format!(
                    "an allocation on {turn_server} exists already"
                )));
            }
            let r = relay::Relay::new(&self.0, cfg, tx);
            relays.push(r.clone());
            r
        };
        // The first Allocate goes out on this kick.
        r.send_nothing();
        let res = match rx.recv_timeout(timeout) {
            Ok(Ok(a)) => Ok(a),
            Ok(Err(e)) => Err(Error::Turn(e)),
            Err(_) => Err(Error::Timeout),
        };
        let (relayed, mapped) = match res {
            Ok(a) => a,
            Err(e) => {
                r.close();
                lock(&self.0.relays).retain(|x| !Arc::ptr_eq(x, &r));
                return Err(e);
            }
        };
        let base = lock(&self.0.candidates)
            .first()
            .map_or_else(|| b.local_addr(), only_ice::Candidate::addr);
        let mut cs = lock(&self.0.candidates);
        if let Some(m) = mapped.filter(|m| !cs.iter().any(|x| x.addr() == *m)) {
            cs.push(only_ice::Candidate::server_reflexive(m, base));
        }
        if !cs.iter().any(|x| x.addr() == relayed) {
            cs.push(only_ice::Candidate::relayed(relayed, base));
        }
        Ok(relayed)
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
        if self.0.tcp.get().is_some() {
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
        let side = tcp::TcpSide::start(&self.0, engine, l, local).map_err(Error::Io)?;
        if self.0.tcp.set(side.clone()).is_err() {
            side.close();
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "the endpoint listens on TCP already",
            )));
        }
        lock(&self.0.candidates).push(only_ice::Candidate::host_tcp(
            local,
            only_ice::TcpType::Passive,
        ));
        Ok(local)
    }

    fn hub_mut(&mut self) -> &mut Hub {
        Arc::get_mut(&mut self.0).expect("configure the endpoint before cloning it")
    }

    /// Builds every peer's configuration with `f` (start from [`rtc_config`]). Call before
    /// cloning the endpoint.
    #[must_use]
    pub fn config(mut self, f: impl Fn() -> RtcConfig + Send + Sync + 'static) -> Self {
        self.hub_mut().config = Box::new(f);
        self
    }

    /// Whether a peer whose ICE goes `Disconnected` is closed (default `true`). Call before
    /// cloning the endpoint.
    #[must_use]
    pub fn close_on_disconnect(mut self, yes: bool) -> Self {
        self.hub_mut().close_on_disconnect = yes;
        self
    }

    /// Closes a peer that is not connected (ICE and DTLS up) this long after it was created
    /// (default 30 seconds; `None` waits forever). Call before cloning.
    #[must_use]
    pub fn connect_timeout(mut self, t: Option<Duration>) -> Self {
        self.hub_mut().connect_timeout = t;
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
        let relays = std::mem::take(&mut *lock(&self.0.relays));
        for r in relays {
            r.close();
        }
        if let Some(t) = self.0.tcp.get() {
            t.close();
        }
        if let Some(b) = self.binding() {
            b.close();
        }
    }
}
