//! WebRTC media for [WHIP and WHEP](crate::whip): [`RtcMedia`] is the [`WebRtcEngine`] that
//! carries a WHIP publisher's media into the [`Hub`] and a hub stream out to a WHEP viewer,
//! with the in-house WebRTC stack of `only-webrtc` (cargo feature `webrtc`).
//!
//! The engine runs on an [`only_webrtc::RtcServer`] the application serves on a
//! [`only::Listener::udp`] (ICE-lite: every peer shares the one port, whose public address is
//! the host candidate of every answer). Build it with [`RtcMedia::rtc_server`] (or configure
//! one with [`rtc_config`]), which offers and accepts exactly the codecs the hub carries:
//! H.264, H.265, Opus, G.711 µ-law and A-law. VP8, VP9 and AV1 have no [`Codec`] in the hub:
//! a media line offering only those is answered inactive, and an offer with no line the hub
//! can carry is refused (406). AAC and MP3 (from RTMP, RTSP, SRT publishers) cannot go to a
//! WebRTC viewer without transcoding, which this crate does not do: such tracks are not sent.
//!
//! **WHIP** (publish): the answer receives every audio and video line of the offer. Frames
//! arrive depacketized (H.264 and H.265 as Annex B); they become hub packets in the canonical
//! form of [`crate::av`]: AVCC, with the `AVCDecoderConfigurationRecord` /
//! `HEVCDecoderConfigurationRecord` built from the parameter sets found in band, a packet is
//! a keyframe when it holds an IDR / IRAP picture. The stream goes live (its tracks are set)
//! once every line has its codec and, for video, a keyframe with its parameter sets: right
//! after the peer connects a PLI asks the sender for one. A line that has shown nothing by
//! [`RtcMediaConfig::track_timeout`] is left out (audio-only or video-only), and joins later
//! with a track change if it starts. Packets that arrive before the stream is live are held,
//! within [`RtcMediaConfig::max_pending_packets`] and [`RtcMediaConfig::max_pending_bytes`].
//! Times are the RTP times of each line, on a common clock lined up by the arrival of each
//! line's first frame, and never decrease per track. A subscriber's keyframe request
//! ([`Publisher::on_keyframe_request`]) becomes a PLI to the publisher. The stream is
//! unpublished when the peer closes (ICE consent lost, DTLS close, connect timeout) and the
//! peer is closed when the client `DELETE`s its session.
//!
//! **WHEP** (play): the answer sends on the offer's (receive-only) lines. Once the peer is
//! connected (media written earlier would be dropped) it subscribes to the stream, starting
//! from the GOP cache; video goes out as Annex B with the parameter sets of the track's
//! configuration before each keyframe, on the RTP clock of 90 kHz, audio (Opus, G.711) as it
//! came. A PLI or FIR from the viewer becomes a keyframe request to the stream's publisher
//! ([`Subscription::request_keyframe`]). The peer is closed when the stream ends, and the
//! subscription when the peer closes. If the offer can take none of the stream's codecs the
//! answer is 406. WebRTC players do not expect B-frames: a stream that has them (an x264
//! default profile over RTMP) is sent in decode order with presentation times, which some
//! players show with stutter; publish with `-bf 0` for WebRTC viewers.
//!
//! **Threads**: peer callbacks run on the `only` I/O thread that read a datagram or on a timer
//! thread; hub sinks run on the publisher's thread under the stream's mutex. A peer method may
//! run that peer's callbacks on the calling thread, so nothing here calls a peer from the
//! keyframe hook (which may run under another stream's mutex), and nothing calls into the hub
//! from a peer callback that might run inside a sink: the PLI of a keyframe request, the
//! subscribe of a connected viewer and the close of a viewer whose stream ended are handed to
//! the media timer thread. Writing media to a viewer sends at once (SRTP, then the UDP
//! socket's queue); the stack exposes no send backlog, so viewers are not dropped by
//! [`crate::hub::Dropper`].
//!
//! Bounds: peers by [`only_webrtc::RtcServer::max_peers`] and sessions by
//! [`crate::whip::WhipConfig::max_sessions`]; a peer that does not connect in
//! [`only_webrtc::RtcServer::connect_timeout`] (30 s by default) is closed; frames by
//! `only-rtp` (4 MiB); packets held before a WHIP stream is live as above.
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use only::{Engine, Listener};
//! use only_http::{Router, serve};
//! use only_media::{
//!     Hub,
//!     webrtc::{RtcMedia, RtcMediaConfig},
//!     whip::{WhipConfig, WhipServer},
//! };
//!
//! let hub = Hub::default();
//! // The address browsers reach the UDP listener at is the host candidate of every answer.
//! let rtc = RtcMedia::rtc_server(vec!["203.0.113.7:8189".parse().unwrap()]);
//! let media = RtcMedia::new(rtc.clone(), RtcMediaConfig::default());
//! let whip = WhipServer::new(hub, Arc::new(media), WhipConfig::default());
//! let engine = Engine::builder()
//!     .listen(Listener::udp("0.0.0.0:8189".parse().unwrap()).serve(rtc))
//!     .listen(Listener::tcp("0.0.0.0:8080".parse().unwrap()).serve(serve(whip.routes(Router::new()))))
//!     .build()
//!     .unwrap();
//! engine.start().unwrap();
//! // POST an SDP offer to http://host:8080/whip/live/cam to publish, /whep/live/cam to play.
//! ```

use std::{
    collections::VecDeque,
    fmt,
    net::SocketAddr,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use only_webrtc::{
    Direction, Frequency, KeyframeRequest, KeyframeRequestKind, MediaAdded, MediaData, MediaKind,
    MediaTime, Mid, Peer, PeerHandler, Pt, RtcConfig, RtcServer,
};

use crate::{
    av::{Codec, Packet, SECOND, Time, Track, Tracks, from_ticks, to_ticks},
    codec::{h264, h265, opus},
    hub::{Hub, HubError, PeerInfo, Publisher, Sink, SubscribeOptions, Subscription, Timeline},
    whip::{Answer, OfferInfo, WebRtcEngine, WebRtcSession, WhipError},
};

/// How often a WHIP ingest asks again for a keyframe while its video waits for one (no
/// parameter sets or keyframe yet, or frames lost).
const KEYFRAME_RETRY: Duration = Duration::from_secs(1);

/// The peer configuration [`RtcMedia`] needs: [`only_webrtc::rtc_config`] with exactly the
/// codecs the hub carries enabled (H.264, H.265, Opus, PCMU, PCMA). Pass it to
/// [`only_webrtc::RtcServer::config`], or start from it to change other settings.
pub fn rtc_config() -> RtcConfig {
    only_webrtc::rtc_config()
        .clear_codecs()
        .enable_opus(true)
        .enable_pcmu(true)
        .enable_pcma(true)
        .enable_h264(true)
        .enable_h265(true)
}

/// Configures [`RtcMedia`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RtcMediaConfig {
    /// How long a WHIP ingest waits, from the moment the peer connects, for every media line
    /// to show its codec (and video its first keyframe with parameter sets) before the stream
    /// goes live with the lines it has. Default 5 seconds.
    pub track_timeout: Duration,
    /// Most packets a WHIP ingest holds while its stream is not live yet; the oldest go first.
    /// Default 512.
    pub max_pending_packets: usize,
    /// Most payload bytes a WHIP ingest holds while its stream is not live yet. Default 8 MiB.
    pub max_pending_bytes: usize,
}

impl Default for RtcMediaConfig {
    fn default() -> Self {
        RtcMediaConfig {
            track_timeout: Duration::from_secs(5),
            max_pending_packets: 512,
            max_pending_bytes: 8 << 20,
        }
    }
}

/// The [`WebRtcEngine`] that carries WHIP and WHEP media through an
/// [`only_webrtc::RtcServer`] (see the [module docs](self)). Cheap to clone.
#[derive(Clone)]
pub struct RtcMedia {
    server: RtcServer,
    cfg: RtcMediaConfig,
}

impl fmt::Debug for RtcMedia {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtcMedia")
            .field("server", &self.server)
            .field("cfg", &self.cfg)
            .finish()
    }
}

impl RtcMedia {
    /// An engine whose peers live on `server` (configured with [`rtc_config`] or a superset
    /// of its codecs, and served on a UDP listener by the application).
    pub fn new(server: RtcServer, cfg: RtcMediaConfig) -> RtcMedia {
        RtcMedia { server, cfg }
    }

    /// A [`RtcServer`] for [`new`](Self::new): host candidates `addrs` (the addresses, with
    /// the UDP listener's port, viewers and publishers reach it at) and the codecs of
    /// [`rtc_config`]. Set its other options (`max_peers`, `connect_timeout` ...) before
    /// cloning it.
    pub fn rtc_server(addrs: Vec<SocketAddr>) -> RtcServer {
        RtcServer::new(addrs).config(rtc_config)
    }

    /// The server the peers live on.
    pub fn server(&self) -> &RtcServer {
        &self.server
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn rtc_error(e: only_webrtc::Error) -> WhipError {
    match e {
        only_webrtc::Error::Sdp(r) => WhipError::BadOffer(r),
        only_webrtc::Error::TooManyPeers => WhipError::Hub(HubError::Limit),
        e => WhipError::Internal(e.to_string()),
    }
}

/// The hub codec of a WebRTC codec, for those the hub carries.
fn to_hub(c: only_webrtc::Codec) -> Option<Codec> {
    Some(match c {
        only_webrtc::Codec::H264 => Codec::H264,
        only_webrtc::Codec::H265 => Codec::H265,
        only_webrtc::Codec::Opus => Codec::Opus,
        only_webrtc::Codec::Pcmu => Codec::Pcmu,
        only_webrtc::Codec::Pcma => Codec::Pcma,
        _ => return None,
    })
}

/// The WebRTC codec of a hub codec, for those WebRTC carries.
fn to_rtc(c: Codec) -> Option<only_webrtc::Codec> {
    Some(match c {
        Codec::H264 => only_webrtc::Codec::H264,
        Codec::H265 => only_webrtc::Codec::H265,
        Codec::Opus => only_webrtc::Codec::Opus,
        Codec::Pcmu => only_webrtc::Codec::Pcmu,
        Codec::Pcma => only_webrtc::Codec::Pcma,
        _ => return None,
    })
}

const VIDEO_CODECS: [only_webrtc::Codec; 2] = [only_webrtc::Codec::H264, only_webrtc::Codec::H265];
const AUDIO_CODECS: [only_webrtc::Codec; 3] = [
    only_webrtc::Codec::Opus,
    only_webrtc::Codec::Pcmu,
    only_webrtc::Codec::Pcma,
];

/// Whether `mid` negotiated a codec the hub carries.
fn carries(p: &Peer, mid: Mid, kind: MediaKind) -> bool {
    let codecs: &[only_webrtc::Codec] = match kind {
        MediaKind::Video => &VIDEO_CODECS,
        MediaKind::Audio => &AUDIO_CODECS,
    };
    codecs.iter().any(|c| p.payload_type(mid, *c).is_some())
}

fn nanos(d: Duration) -> Time {
    Time::try_from(d.as_nanos()).unwrap_or(Time::MAX)
}

/// A WHIP or WHEP session: the peer, closed on `DELETE`.
struct RtcSession {
    peer: Peer,
}

impl WebRtcSession for RtcSession {
    fn trickle(&mut self, fragment: &str) -> Result<(), WhipError> {
        if self.peer.is_closed() {
            return Err(WhipError::Hub(HubError::NotFound));
        }
        for line in fragment.lines().map(str::trim) {
            if line.starts_with("a=candidate:") {
                self.peer
                    .add_remote_candidate(line)
                    .map_err(|e| WhipError::BadOffer(e.to_string()))?;
            }
        }
        Ok(())
    }

    fn close(&mut self) {
        self.peer.close();
    }

    fn is_closed(&self) -> bool {
        self.peer.is_closed()
    }
}

impl WebRtcEngine for RtcMedia {
    fn publish(&self, info: &OfferInfo, publisher: Publisher) -> Result<Answer, WhipError> {
        let lines = Arc::new(AtomicUsize::new(0));
        let ingest = Ingest::new(publisher, self.cfg.clone(), lines.clone());
        let (peer, sdp) = self
            .server
            .accept_offer(&info.offer_text, ingest)
            .map_err(rtc_error)?;
        // The offer's lines were announced (on_media_added) while it was accepted.
        if lines.load(Ordering::Acquire) == 0 {
            peer.close();
            return Err(WhipError::Unsupported);
        }
        Ok(Answer::new(sdp, Box::new(RtcSession { peer })))
    }

    fn play(&self, info: &OfferInfo, hub: &Hub) -> Result<Answer, WhipError> {
        let tracks = hub
            .stream_info(&info.path)
            .map(|s| s.tracks)
            .ok_or(WhipError::Hub(HubError::NotFound))?;
        let shared = Arc::new(PlayShared::default());
        let player = Player {
            shared: shared.clone(),
            hub: hub.clone(),
            path: info.path.clone(),
            info: info.peer.clone(),
        };
        let (peer, sdp) = self
            .server
            .accept_offer(&info.offer_text, player)
            .map_err(rtc_error)?;
        let lines = lock(&shared.lines).clone();
        if pick(&peer, &lines, &tracks, true).is_none()
            && pick(&peer, &lines, &tracks, false).is_none()
        {
            peer.close();
            return Err(WhipError::Unsupported);
        }
        Ok(Answer::new(sdp, Box::new(RtcSession { peer })))
    }
}

// ---- WHIP: a peer's media into a publisher ----

/// One receiving media line of a WHIP peer.
struct InLine {
    mid: Mid,
    learn: Learn,
    /// RTP ticks of the first frame and its time on the session clock.
    first: Option<(u64, Time)>,
    last: Time,
    /// Index in the announced tracks.
    track: Option<usize>,
}

impl InLine {
    fn new(mid: Mid, video: bool) -> InLine {
        InLine {
            mid,
            learn: Learn::new(video),
            first: None,
            last: Time::MIN,
            track: None,
        }
    }

    fn ready(&self) -> bool {
        self.learn.ready()
    }
}

/// What a line's frames tell about its track: the codec and, for video, the parameter sets.
struct Learn {
    video: bool,
    codec: Option<Codec>,
    sps: Option<Vec<u8>>,
    pps: Option<Vec<u8>>,
    vps: Option<Vec<u8>>,
    params_changed: bool,
    config: Option<Vec<u8>>,
    /// A keyframe was seen with the current configuration.
    keyed: bool,
}

impl Learn {
    fn new(video: bool) -> Learn {
        Learn {
            video,
            codec: None,
            sps: None,
            pps: None,
            vps: None,
            params_changed: false,
            config: None,
            keyed: false,
        }
    }

    fn ready(&self) -> bool {
        self.codec.is_some() && (!self.video || (self.config.is_some() && self.keyed))
    }

    fn describe(&self) -> Option<Track> {
        let codec = self.codec?;
        Some(match codec {
            Codec::H264 | Codec::H265 => Track::video(codec, self.config.clone()?),
            Codec::Opus => Track::audio(Codec::Opus, opus::Head::new(2).encode(), 48_000, 2),
            c => Track::audio(c, Vec::new(), 8_000, 1),
        })
    }

    /// Switches the line to `codec` (the sender changed payload type): what was learnt goes.
    fn set_codec(&mut self, codec: Codec) {
        if self.codec != Some(codec) {
            self.codec = Some(codec);
            self.sps = None;
            self.pps = None;
            self.vps = None;
            self.config = None;
            self.keyed = false;
            self.params_changed = false;
        }
    }

    /// Converts an Annex B access unit to AVCC, learning the parameter sets; `None` when the
    /// stream cannot use it yet (no configuration or no keyframe so far).
    fn video_au(&mut self, annexb: &[u8]) -> Option<(Vec<u8>, bool)> {
        let h265 = self.codec == Some(Codec::H265);
        let mut au = Vec::with_capacity(annexb.len() + 16);
        let mut key = false;
        for nal in h264::split_annexb(annexb) {
            let Some(&b0) = nal.first() else { continue };
            let slot = if h265 {
                let t = h265::nal_type(b0);
                key |= h265::is_irap(t);
                match t {
                    h265::NAL_AUD => continue,
                    h265::NAL_VPS => Some(&mut self.vps),
                    h265::NAL_SPS => Some(&mut self.sps),
                    h265::NAL_PPS => Some(&mut self.pps),
                    _ => None,
                }
            } else {
                let t = h264::nal_type(b0);
                key |= t == h264::NAL_IDR;
                match t {
                    h264::NAL_AUD => continue,
                    h264::NAL_SPS => Some(&mut self.sps),
                    h264::NAL_PPS => Some(&mut self.pps),
                    _ => None,
                }
            };
            if let Some(slot) = slot {
                if slot.as_deref() != Some(nal) {
                    *slot = Some(nal.to_vec());
                    self.params_changed = true;
                }
            }
            h264::push_avcc(&mut au, nal);
        }
        if self.params_changed {
            let cfg = match (h265, &self.vps, &self.sps, &self.pps) {
                (false, _, Some(s), Some(p)) => Some(h264::Config::from_sets(s, p).encode()),
                (true, Some(v), Some(s), Some(p)) => {
                    h265::Config::from_sets(v, s, p).map(|c| c.encode())
                }
                _ => None,
            };
            if let Some(cfg) = cfg {
                self.params_changed = false;
                if self.config.as_ref() != Some(&cfg) {
                    self.config = Some(cfg);
                    // New parameter sets come with the keyframe that uses them.
                    self.keyed = false;
                }
            }
        }
        if self.config.is_none() || au.is_empty() {
            return None;
        }
        if !self.keyed {
            if !key {
                return None;
            }
            self.keyed = true;
        }
        Some((au, key))
    }
}

/// The handler of a WHIP peer: writes its frames into the publisher.
struct Ingest {
    publisher: Publisher,
    cfg: RtcMediaConfig,
    lines: Vec<InLine>,
    /// Lines that can be carried, for [`RtcMedia::publish`] (filled while the offer is
    /// accepted).
    accepted: Arc<AtomicUsize>,
    tracks: Vec<Track>,
    live: bool,
    pending: VecDeque<(usize, Packet)>,
    pending_bytes: usize,
    epoch: Option<Instant>,
    deadline: Option<Instant>,
    last_pli: Option<Instant>,
}

impl Ingest {
    fn new(publisher: Publisher, cfg: RtcMediaConfig, accepted: Arc<AtomicUsize>) -> Ingest {
        Ingest {
            publisher,
            cfg,
            lines: Vec::new(),
            accepted,
            tracks: Vec::new(),
            live: false,
            pending: VecDeque::new(),
            pending_bytes: 0,
            epoch: None,
            deadline: None,
            last_pli: None,
        }
    }

    /// Asks for a keyframe on `mid`, at most once per [`KEYFRAME_RETRY`].
    fn pli(&mut self, p: &Peer, mid: Mid) {
        let now = Instant::now();
        if self
            .last_pli
            .is_some_and(|t| now.duration_since(t) < KEYFRAME_RETRY)
        {
            return;
        }
        self.last_pli = Some(now);
        let _ = p.request_keyframe(mid, KeyframeRequestKind::Pli);
    }

    /// The session-clock time of a frame of line `i`, never behind the line's last one.
    fn time(&mut self, i: usize, d: &MediaData) -> Time {
        let epoch = *self.epoch.get_or_insert(d.network_time);
        let line = &mut self.lines[i];
        let ticks = d.time.ticks();
        let (t0, off) = *line.first.get_or_insert_with(|| {
            (
                ticks,
                nanos(d.network_time.saturating_duration_since(epoch)),
            )
        });
        let rel = i64::try_from(i128::from(ticks) - i128::from(t0)).unwrap_or(0);
        let t = (off + from_ticks(rel, d.time.rate().get())).max(line.last);
        line.last = t;
        t
    }

    fn hold(&mut self, i: usize, pkt: Packet) {
        self.pending_bytes += pkt.data.len();
        self.pending.push_back((i, pkt));
        while self.pending.len() > self.cfg.max_pending_packets
            || self.pending_bytes > self.cfg.max_pending_bytes
        {
            match self.pending.pop_front() {
                Some((_, p)) => self.pending_bytes -= p.data.len(),
                None => break,
            }
        }
    }

    fn try_go_live(&mut self) {
        let all = self.lines.iter().all(InLine::ready);
        let any = self.lines.iter().any(InLine::ready);
        let late = self.deadline.is_some_and(|d| Instant::now() >= d);
        if !(all || (any && late)) {
            return;
        }
        for line in &mut self.lines {
            if let Some(t) = line.ready().then(|| line.learn.describe()).flatten() {
                line.track = Some(self.tracks.len());
                self.tracks.push(t);
            }
        }
        self.live = true;
        self.publisher.set_tracks(Tracks::from(self.tracks.clone()));
        self.pending_bytes = 0;
        for (i, mut pkt) in std::mem::take(&mut self.pending) {
            if let Some(t) = self.lines[i].track {
                pkt.track = t;
                self.publisher.write(pkt);
            }
        }
    }

    /// Writes a packet of line `i`, announcing a new or changed track first.
    fn emit(&mut self, i: usize, mut pkt: Packet) {
        if !self.live {
            self.hold(i, pkt);
            self.try_go_live();
            return;
        }
        let line = &mut self.lines[i];
        if !line.ready() {
            return;
        }
        let Some(desc) = line.learn.describe() else {
            return;
        };
        let idx = match line.track {
            Some(idx) => {
                if self.tracks[idx] != desc {
                    self.tracks[idx] = desc;
                    self.publisher.set_tracks(Tracks::from(self.tracks.clone()));
                }
                idx
            }
            None => {
                // A line that showed up after the stream went live.
                let idx = self.tracks.len();
                line.track = Some(idx);
                self.tracks.push(desc);
                self.publisher.set_tracks(Tracks::from(self.tracks.clone()));
                idx
            }
        };
        pkt.track = idx;
        self.publisher.write(pkt);
    }
}

impl PeerHandler for Ingest {
    fn on_media_added(&mut self, p: &Peer, m: &MediaAdded) {
        let receives = matches!(m.direction, Direction::RecvOnly | Direction::SendRecv);
        if receives && carries(p, m.mid, m.kind) && !self.lines.iter().any(|l| l.mid == m.mid) {
            self.lines
                .push(InLine::new(m.mid, m.kind == MediaKind::Video));
            self.accepted.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn on_connected(&mut self, p: &Peer) {
        self.deadline = Some(Instant::now() + self.cfg.track_timeout);
        let Some(mid) = self.lines.iter().find(|l| l.learn.video).map(|l| l.mid) else {
            return;
        };
        // The hook may run under another stream's lock and a peer call may run this peer's
        // callbacks (which write to the hub): the PLI goes out from the timer thread.
        let peer = p.clone();
        let queued = Arc::new(AtomicBool::new(false));
        self.publisher.on_keyframe_request(move || {
            if queued.swap(true, Ordering::AcqRel) {
                return;
            }
            let (peer, queued) = (peer.clone(), queued.clone());
            crate::timer::after(Duration::ZERO, move || {
                queued.store(false, Ordering::Release);
                let _ = peer.request_keyframe(mid, KeyframeRequestKind::Pli);
            });
        });
        // Video starts at a keyframe with its parameter sets: ask for one now.
        self.pli(p, mid);
    }

    fn on_media_data(&mut self, p: &Peer, d: &MediaData) {
        let Some(i) = self.lines.iter().position(|l| l.mid == d.mid) else {
            return;
        };
        let Some(codec) = d.codec.and_then(to_hub) else {
            return; // VP8, VP9, AV1, G.722: not carried by the hub
        };
        if codec.is_video() != self.lines[i].learn.video {
            return;
        }
        self.lines[i].learn.set_codec(codec);
        let t = self.time(i, d);
        let pkt = if codec.is_video() {
            let mid = self.lines[i].mid;
            if !d.contiguous {
                self.pli(p, mid); // frames were lost: the next ones may not decode
            }
            match self.lines[i].learn.video_au(&d.data) {
                Some((au, key)) => Packet::new(0, t, t, key, au),
                None => {
                    self.pli(p, mid);
                    return;
                }
            }
        } else {
            Packet::new(0, t, t, true, d.data.to_vec())
        };
        self.emit(i, pkt);
    }

    fn on_close(&mut self, _p: &Peer) {
        self.pending.clear();
        self.publisher.close();
    }
}

// ---- WHEP: a hub stream out to a peer ----

#[derive(Default)]
struct PlayShared {
    /// The sending lines of the answer (filled while the offer is accepted).
    lines: Mutex<Vec<(Mid, MediaKind)>>,
    sub: Mutex<Option<Subscription>>,
    closed: AtomicBool,
}

/// The handler of a WHEP peer.
struct Player {
    shared: Arc<PlayShared>,
    hub: Hub,
    path: String,
    info: PeerInfo,
}

/// Where one kind of track goes: the stream's track and the line, payload type and clock.
#[derive(Clone)]
struct Out {
    track: usize,
    mid: Mid,
    pt: Pt,
    rate: Frequency,
    /// Video: the parameter sets of the configuration as Annex B, sent before keyframes
    /// that do not carry them.
    params: Vec<u8>,
    /// The NAL unit type of an SPS of the codec.
    sps_type: Option<(bool, u8)>,
}

/// The first track of a kind (`video`) a line of the peer can send, and where it goes.
fn pick(p: &Peer, lines: &[(Mid, MediaKind)], tracks: &Tracks, video: bool) -> Option<Out> {
    let kind = if video {
        MediaKind::Video
    } else {
        MediaKind::Audio
    };
    for (i, t) in tracks.iter().enumerate() {
        if t.codec.is_video() != video {
            continue;
        }
        let Some(c) = to_rtc(t.codec) else { continue };
        for (mid, k) in lines {
            if *k != kind {
                continue;
            }
            let Some(pt) = p.payload_type(*mid, c) else {
                continue;
            };
            let rate = Frequency::new(t.clock_rate()).unwrap_or(Frequency::NINETY_KHZ);
            let mut params = Vec::new();
            let mut sps_type = None;
            let mut push = |sets: &[Vec<u8>]| {
                for s in sets {
                    params.extend_from_slice(&[0, 0, 0, 1]);
                    params.extend_from_slice(s);
                }
            };
            match t.codec {
                Codec::H264 => {
                    sps_type = Some((false, h264::NAL_SPS));
                    if let Ok(c) = h264::Config::parse(&t.config) {
                        push(&c.sps);
                        push(&c.pps);
                    }
                }
                Codec::H265 => {
                    sps_type = Some((true, h265::NAL_SPS));
                    if let Ok(c) = h265::Config::parse(&t.config) {
                        push(&c.vps);
                        push(&c.sps);
                        push(&c.pps);
                    }
                }
                _ => {}
            }
            return Some(Out {
                track: i,
                mid: *mid,
                pt,
                rate,
                params,
                sps_type,
            });
        }
    }
    None
}

impl PeerHandler for Player {
    fn on_media_added(&mut self, _p: &Peer, m: &MediaAdded) {
        if matches!(m.direction, Direction::SendOnly | Direction::SendRecv) {
            lock(&self.shared.lines).push((m.mid, m.kind));
        }
    }

    fn on_connected(&mut self, p: &Peer) {
        // Media written before now would be dropped, so the subscription starts here; it is
        // made on the timer thread, since subscribing writes the GOP to this peer, which may
        // run this peer's callbacks.
        let (shared, hub, path, info, peer) = (
            self.shared.clone(),
            self.hub.clone(),
            self.path.clone(),
            self.info.clone(),
            p.clone(),
        );
        crate::timer::after(Duration::ZERO, move || {
            if shared.closed.load(Ordering::Acquire) {
                return;
            }
            let sink = PlaySink {
                peer: peer.clone(),
                lines: lock(&shared.lines).clone(),
                video: None,
                audio: None,
                timeline: Timeline::from_zero(),
                announced: false,
                buf: Vec::new(),
            };
            match hub.subscribe(&path, sink, SubscribeOptions::new(info)) {
                Ok(sub) => {
                    let mut g = lock(&shared.sub);
                    if shared.closed.load(Ordering::Acquire) {
                        drop(g);
                        sub.close();
                    } else {
                        *g = Some(sub);
                    }
                }
                Err(_) => peer.close(),
            }
        });
    }

    fn on_keyframe_request(&mut self, _p: &Peer, _req: &KeyframeRequest) {
        if let Some(sub) = lock(&self.shared.sub).as_ref() {
            sub.request_keyframe();
        }
    }

    fn on_close(&mut self, _p: &Peer) {
        self.shared.closed.store(true, Ordering::Release);
        let sub = lock(&self.shared.sub).take();
        if let Some(sub) = sub {
            sub.close();
        }
    }
}

/// The hub side of a WHEP peer.
struct PlaySink {
    peer: Peer,
    lines: Vec<(Mid, MediaKind)>,
    video: Option<Out>,
    audio: Option<Out>,
    timeline: Timeline,
    announced: bool,
    buf: Vec<u8>,
}

fn has_sps(avcc: &[u8], (h265, sps): (bool, u8)) -> bool {
    h264::avcc_nalus(avcc).iter().any(|n| {
        n.first().is_some_and(|&b| {
            if h265 {
                h265::nal_type(b) == sps
            } else {
                h264::nal_type(b) == sps
            }
        })
    })
}

impl Sink for PlaySink {
    fn on_tracks(&mut self, tracks: &Tracks) {
        if self.announced {
            self.timeline.restart();
        }
        self.announced = true;
        self.video = pick(&self.peer, &self.lines, tracks, true);
        self.audio = pick(&self.peer, &self.lines, tracks, false);
    }

    fn on_packet(&mut self, pkt: &Arc<Packet>) {
        let (out, video) = match (&self.video, &self.audio) {
            (Some(v), _) if v.track == pkt.track => (v, true),
            (_, Some(a)) if a.track == pkt.track => (a, false),
            _ => return,
        };
        let dts = self.timeline.stamp(video, pkt.dts);
        let pts = dts + pkt.cts().clamp(0, 10 * SECOND);
        let ticks = u64::try_from(to_ticks(pts, out.rate.get())).unwrap_or(0);
        let time = MediaTime::new(ticks, out.rate);
        let data: &[u8] = if video {
            self.buf.clear();
            if pkt.keyframe && out.sps_type.is_some_and(|s| !has_sps(&pkt.data, s)) {
                self.buf.extend_from_slice(&out.params);
            }
            h264::avcc_to_annexb(&pkt.data, &mut self.buf);
            &self.buf
        } else {
            &pkt.data
        };
        // Errors: the peer closed (its on_close ends the subscription) or the line stopped.
        let _ = self
            .peer
            .write_media(out.mid, out.pt, Instant::now(), time, data);
    }

    fn on_close(&mut self, _err: HubError) {
        // Closing runs the peer's callbacks, which must not run under the stream's lock.
        let peer = self.peer.clone();
        crate::timer::after(Duration::ZERO, move || peer.close());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn annexb(nals: &[&[u8]]) -> Vec<u8> {
        let mut v = Vec::new();
        for n in nals {
            v.extend_from_slice(&[0, 0, 0, 1]);
            v.extend_from_slice(n);
        }
        v
    }

    const SPS: &[u8] = &[0x67, 0x42, 0xc0, 0x1f, 0x8c, 0x8d, 0x40, 0x50, 0x1e, 0xd0];
    const PPS: &[u8] = &[0x68, 0xce, 0x3c, 0x80];

    #[test]
    fn h264_annexb_to_avcc_waits_for_parameter_sets_and_a_keyframe() {
        let mut l = Learn::new(true);
        l.set_codec(Codec::H264);
        // A P-frame first: nothing to decode it with.
        assert!(l.video_au(&annexb(&[&[0x41, 1, 2]])).is_none());
        // An IDR without SPS/PPS: still no configuration.
        assert!(l.video_au(&annexb(&[&[0x65, 1, 2]])).is_none());
        let (au, key) = l
            .video_au(&annexb(&[&[0x09, 0xf0], SPS, PPS, &[0x65, 1, 2]]))
            .unwrap();
        assert!(key && l.ready());
        // The AUD is dropped, the rest is AVCC.
        assert_eq!(h264::avcc_nalus(&au), vec![SPS, PPS, &[0x65, 1, 2][..]]);
        let cfg = h264::Config::parse(l.config.as_ref().unwrap()).unwrap();
        assert_eq!((cfg.sps[0].as_slice(), cfg.pps[0].as_slice()), (SPS, PPS));
        let (au, key) = l.video_au(&annexb(&[&[0x41, 9]])).unwrap();
        assert!(!key);
        assert_eq!(au, vec![0, 0, 0, 2, 0x41, 9]);
        // New parameter sets wait for their keyframe.
        let pps2: &[u8] = &[0x68, 0xce, 0x3c, 0x81];
        assert!(l.video_au(&annexb(&[pps2, &[0x41, 1]])).is_none());
        assert!(l.video_au(&annexb(&[&[0x65, 3]])).is_some());
        assert_eq!(
            h264::Config::parse(l.config.as_ref().unwrap()).unwrap().pps[0],
            pps2
        );
    }

    #[test]
    fn codec_maps_and_config() {
        for c in [
            Codec::H264,
            Codec::H265,
            Codec::Opus,
            Codec::Pcmu,
            Codec::Pcma,
        ] {
            assert_eq!(to_rtc(c).and_then(to_hub), Some(c));
        }
        assert!(to_rtc(Codec::Aac).is_none() && to_rtc(Codec::Mp3).is_none());
        assert!(to_hub(only_webrtc::Codec::Vp8).is_none());
        let d = RtcMediaConfig::default();
        assert_eq!(d.track_timeout, Duration::from_secs(5));
        assert_eq!((d.max_pending_packets, d.max_pending_bytes), (512, 8 << 20));
        let s = format!("{:?}", rtc_config());
        assert!(s.contains("H265") && !s.contains("Vp8"), "{s}");
        let mut opus = Learn::new(false);
        opus.set_codec(Codec::Opus);
        let t = opus.describe().unwrap();
        assert_eq!(
            (t.codec, t.sample_rate, t.channels),
            (Codec::Opus, 48_000, 2)
        );
        assert!(has_sps(&h264::to_avcc([SPS, PPS]), (false, h264::NAL_SPS)));
        assert!(!has_sps(&h264::to_avcc([PPS]), (false, h264::NAL_SPS)));
    }
}
