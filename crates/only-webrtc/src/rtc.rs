//! The sans-io peer connection: SDP offer/answer (JSEP), ICE ([`only_ice`]), DTLS
//! ([`only_dtls`]), SRTP ([`only_srtp`]), RTP/RTCP ([`only_rtp`]) and SCTP data channels
//! ([`only_sctp`]) glued together. No I/O: datagrams come in through
//! [`Rtc::handle_receive`], time through [`Rtc::handle_timeout`]; datagrams to send, events
//! and the next deadline come out of [`Rtc::poll_output`].

use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use only_dtls::{Config as DtlsConfig, Connection, Event as DtlsEvent, Fingerprint, Identity};
use only_dtls::{PeerVerifier, Role};
use only_ice::{Candidate as IceCandidate, Credentials, IceAgent, IceConfig, IceEvent};
use only_rtp::codec::{FrameAssembler, Packetizer};
use only_rtp::{
    BandwidthEstimator, Extension, ExtensionMap, ExtensionValues, RecvStream, Rtcp, RtpHeader,
    SendStream, TwccReceiver, TwccSender,
};
use only_sctp::{Association, Config as SctpConfig, Event as SctpEvent};
use only_srtp::{Context as Srtp, Profile};

use crate::sdp::{Attr, Media, Sdp};
use crate::types::{
    Change, Changes, ChannelConfig, ChannelId, Codec, ConfigInner, Direction, IceConnectionState,
    KeyframeRequest, KeyframeRequestKind, MediaAdded, MediaData, MediaKind, MediaTime, Mid, Other,
    Pt, RtpPacket,
};
use crate::{Frequency, fill_random};

/// RTP payload bytes per packet: an MTU of 1200 minus RTP header, extensions and SRTP tag.
const RTP_PAYLOAD_MTU: usize = 1100;
/// SCTP packet size inside a DTLS record.
const SCTP_MTU: usize = 1200;
/// Our `a=max-message-size`.
const MAX_MESSAGE_SIZE: usize = 262_144;
/// Received RTP streams tracked per peer (more SSRCs are ignored).
const MAX_RECV_STREAMS: usize = 64;
/// How often RTCP reports go out.
const RTCP_INTERVAL: Duration = Duration::from_millis(1000);

/// What [`Rtc::poll_output`] returns.
#[derive(Debug)]
pub(crate) enum Output {
    /// Call [`Rtc::handle_timeout`] then.
    Timeout(Instant),
    /// Send `2` from the local address `0` to `1`.
    Transmit(SocketAddr, SocketAddr, Vec<u8>),
    /// Something happened.
    Event(RtcEvent),
}

/// The events of a peer.
#[derive(Debug)]
pub(crate) enum RtcEvent {
    IceState(IceConnectionState),
    Connected,
    ChannelOpen(ChannelId, String),
    ChannelData(ChannelId, Vec<u8>, bool),
    ChannelClose(ChannelId),
    BufferedLow(ChannelId),
    MediaAdded(MediaAdded),
    MediaData(MediaData),
    Rtp(RtpPacket),
    Keyframe(KeyframeRequest),
    Other(Other),
    /// The peer is gone (DTLS closed or failed); last event.
    Closed,
}

/// A refused operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RtcErr(pub(crate) String);

fn err(s: impl Into<String>) -> RtcErr {
    RtcErr(s.into())
}

fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    fill_random(&mut b);
    u32::from_be_bytes(b)
}

fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    fill_random(&mut b);
    u64::from_be_bytes(b) >> 2
}

fn random_token(n: usize) -> String {
    const CH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut b = vec![0u8; n];
    fill_random(&mut b);
    b.iter()
        .map(|x| char::from(CH[usize::from(*x) % CH.len()]))
        .collect()
}

/// `sha-256 AB:CD:...`
fn fingerprint_sdp(f: &Fingerprint) -> String {
    let mut s = String::from(f.algorithm().name());
    s.push(' ');
    for (i, b) in f.value().iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        let _ = write!(s, "{b:02X}");
    }
    s
}

// ---- codecs ----

/// A negotiated (or offered) payload type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodecParams {
    pub(crate) codec: Codec,
    pub(crate) pt: u8,
    pub(crate) clock: u32,
    pub(crate) channels: Option<u8>,
    pub(crate) fmtp: String,
    pub(crate) rtx: Option<u8>,
    pub(crate) fb: Vec<String>,
}

const VIDEO_FB: [&str; 5] = ["goog-remb", "transport-cc", "ccm fir", "nack", "nack pli"];
const AUDIO_FB: [&str; 1] = ["transport-cc"];

/// Our default payload types.
fn local_codecs(cfg: &ConfigInner, kind: MediaKind) -> Vec<CodecParams> {
    let mut out = Vec::new();
    for c in &cfg.codecs {
        if c.kind() != kind {
            continue;
        }
        let (pt, rtx, clock, channels, fmtp) = match c {
            Codec::Opus => (111, None, 48_000, Some(2), "minptime=10;useinbandfec=1"),
            Codec::Pcmu => (0, None, 8000, None, ""),
            Codec::Pcma => (8, None, 8000, None, ""),
            Codec::G722 => (9, None, 8000, None, ""),
            Codec::Vp8 => (96, Some(97), 90_000, None, ""),
            Codec::Vp9 => (98, Some(99), 90_000, None, "profile-id=0"),
            Codec::H264 => (
                102,
                Some(103),
                90_000,
                None,
                "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
            ),
            Codec::H265 => (104, Some(105), 90_000, None, ""),
            Codec::Av1 => (45, Some(46), 90_000, None, ""),
        };
        let fb = if kind == MediaKind::Video {
            VIDEO_FB.iter().map(|s| (*s).to_owned()).collect()
        } else {
            AUDIO_FB.iter().map(|s| (*s).to_owned()).collect()
        };
        out.push(CodecParams {
            codec: *c,
            pt,
            clock,
            channels,
            fmtp: fmtp.to_owned(),
            rtx,
            fb,
        });
    }
    out
}

fn fmtp_param<'a>(fmtp: &'a str, key: &str) -> Option<&'a str> {
    fmtp.split(';').find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        k.trim().eq_ignore_ascii_case(key).then(|| v.trim())
    })
}

/// The payload types of a remote media section that this configuration supports.
fn remote_codecs(cfg: &ConfigInner, m: &Media, kind: MediaKind) -> Vec<CodecParams> {
    let mut maps: Vec<(u8, String, u32, Option<u8>)> = Vec::new();
    for v in m.all("rtpmap") {
        let Some((pt, enc)) = v.split_once(' ') else {
            continue;
        };
        let Ok(pt) = pt.trim().parse::<u8>() else {
            continue;
        };
        let mut f = enc.trim().split('/');
        let name = f.next().unwrap_or("").to_owned();
        let clock = f.next().and_then(|c| c.parse().ok()).unwrap_or(0);
        let ch = f.next().and_then(|c| c.parse().ok());
        maps.push((pt, name, clock, ch));
    }
    // Static payload types without rtpmap.
    for f in &m.fmts {
        if let Ok(pt) = f.parse::<u8>() {
            if maps.iter().any(|x| x.0 == pt) {
                continue;
            }
            let name = match pt {
                0 => "PCMU",
                8 => "PCMA",
                9 => "G722",
                _ => continue,
            };
            maps.push((pt, name.to_owned(), 8000, None));
        }
    }
    let fmtp_of = |pt: u8| -> String {
        m.all("fmtp")
            .find_map(|v| {
                let (p, rest) = v.split_once(' ')?;
                (p.trim().parse::<u8>().ok()? == pt).then(|| rest.trim().to_owned())
            })
            .unwrap_or_default()
    };
    let fb_of = |pt: u8, ours: &[&str]| -> Vec<String> {
        let mut fb = Vec::new();
        for v in m.all("rtcp-fb") {
            let Some((p, rest)) = v.split_once(' ') else {
                continue;
            };
            let p = p.trim();
            if p != "*" && p.parse::<u8>().ok() != Some(pt) {
                continue;
            }
            let rest = rest.trim();
            if ours.contains(&rest) && !fb.iter().any(|x: &String| x == rest) {
                fb.push(rest.to_owned());
            }
        }
        fb
    };
    let ours: &[&str] = if kind == MediaKind::Video {
        &VIDEO_FB
    } else {
        &AUDIO_FB
    };
    let mut out = Vec::new();
    for (pt, name, clock, ch) in &maps {
        let Some(codec) = Codec::from_name(name) else {
            continue;
        };
        if codec.kind() != kind || !cfg.codecs.contains(&codec) {
            continue;
        }
        let fmtp = fmtp_of(*pt);
        match codec {
            Codec::H264 if fmtp_param(&fmtp, "packetization-mode") != Some("1") => continue,
            Codec::Vp9 if fmtp_param(&fmtp, "profile-id").is_some_and(|p| p != "0") => continue,
            Codec::Opus if *clock != 48_000 => continue,
            _ => {}
        }
        let rtx = maps.iter().find_map(|(rp, rn, _, _)| {
            (rn.eq_ignore_ascii_case("rtx")
                && fmtp_param(&fmtp_of(*rp), "apt").and_then(|a| a.parse::<u8>().ok()) == Some(*pt))
            .then_some(*rp)
        });
        out.push(CodecParams {
            codec,
            pt: *pt,
            clock: if *clock == 0 { 90_000 } else { *clock },
            channels: *ch,
            fmtp,
            rtx,
            fb: fb_of(*pt, ours),
        });
    }
    out
}

fn remote_extmap(m: &Media) -> ExtensionMap {
    let mut map = ExtensionMap::new();
    for v in m.all("extmap") {
        let mut f = v.split_whitespace();
        let (Some(id), Some(uri)) = (f.next(), f.next()) else {
            continue;
        };
        let Ok(id) = id.split('/').next().unwrap_or("").parse::<u8>() else {
            continue;
        };
        if let Some(e) = Extension::from_uri(uri) {
            if id > 0 {
                map.insert(id, e);
            }
        }
    }
    map
}

fn local_extmap(kind: MediaKind) -> ExtensionMap {
    match kind {
        MediaKind::Audio => ExtensionMap::default_audio(),
        MediaKind::Video => ExtensionMap::default_video(),
    }
}

// ---- state ----

/// A received RTP stream.
#[derive(Debug)]
struct Recv {
    line: usize,
    stream: RecvStream,
    assembler: Option<(u8, FrameAssembler)>,
    rid: Option<String>,
}

/// How an incoming SSRC maps to a media line.
#[derive(Debug, Clone, Copy)]
struct Route {
    line: usize,
    /// For an RTX stream: the SSRC it repairs.
    repairs: Option<u32>,
}

#[derive(Debug)]
struct MediaLine {
    mid: Mid,
    kind: MediaKind,
    /// What the application asked for.
    want: Direction,
    /// The negotiated direction (from this side).
    dir: Direction,
    stopped: bool,
    negotiated: bool,
    codecs: Vec<CodecParams>,
    ext: ExtensionMap,
    stream_id: String,
    track_id: String,
    send: SendStream,
    packetizers: HashMap<u8, Box<dyn Packetizer>>,
    last_pt: Option<u8>,
    remote_ssrcs: Vec<u32>,
    remote_rtx: HashMap<u32, u32>,
    fir_seq: u8,
}

impl MediaLine {
    fn new(
        mid: Mid,
        kind: MediaKind,
        want: Direction,
        stream_id: Option<String>,
        track_id: Option<String>,
    ) -> MediaLine {
        let ssrc = random_u32();
        let rtx = random_u32();
        MediaLine {
            mid,
            kind,
            want,
            dir: want,
            stopped: false,
            negotiated: false,
            codecs: Vec::new(),
            ext: local_extmap(kind),
            stream_id: stream_id.unwrap_or_else(|| random_token(12)),
            track_id: track_id.unwrap_or_else(|| random_token(12)),
            send: SendStream::new(ssrc, 90_000, Some(rtx), random_u32() as u16),
            packetizers: HashMap::new(),
            last_pt: None,
            remote_ssrcs: Vec::new(),
            remote_rtx: HashMap::new(),
            fir_seq: 0,
        }
    }

    fn codec(&self, pt: u8) -> Option<&CodecParams> {
        self.codecs.iter().find(|c| c.pt == pt)
    }

    /// The codec an RTX payload type repairs.
    fn rtx_of(&self, pt: u8) -> Option<&CodecParams> {
        self.codecs.iter().find(|c| c.rtx == Some(pt))
    }
}

#[derive(Debug)]
struct Channel {
    cfg: ChannelConfig,
    stream: Option<u16>,
}

/// An offer this side sent and awaits the answer of.
#[derive(Debug)]
struct Pending {
    /// Lines added by the offer.
    new_lines: Vec<Mid>,
}

/// One peer connection, sans-io.
pub(crate) struct Rtc {
    cfg: ConfigInner,
    lite: bool,
    ice: IceAgent,
    ice_state: IceConnectionState,
    identity: Identity,
    remote_fp: Option<Fingerprint>,
    dtls_role: Option<Role>,
    dtls: Option<Connection>,
    dtls_connected: bool,
    srtp_tx: Option<Srtp>,
    srtp_rx: Option<Srtp>,
    sctp: Option<Association>,
    app_mid: Option<Mid>,
    app_negotiated: bool,
    remote_max_message: usize,
    channels: HashMap<ChannelId, Channel>,
    by_stream: HashMap<u16, ChannelId>,
    next_channel: usize,
    media: Vec<MediaLine>,
    next_mid: usize,
    session_id: u64,
    sdp_version: u64,
    pending: Option<Pending>,
    /// Whether any offer/answer completed.
    negotiated: bool,
    recv: HashMap<u32, Recv>,
    routes: HashMap<u32, Route>,
    ext: ExtensionMap,
    twcc_tx: TwccSender,
    twcc_rx: TwccReceiver,
    twcc_media_ssrc: u32,
    bwe: Option<BandwidthEstimator>,
    last_estimate: u64,
    next_rtcp: Option<Instant>,
    next_stats: Option<Instant>,
    cname: String,
    /// (local address to send from, destination, datagram).
    transmits: VecDeque<(SocketAddr, SocketAddr, Vec<u8>)>,
    events: VecDeque<RtcEvent>,
    alive: bool,
    closed_emitted: bool,
    stats: Stats,
    remote_addr: Option<SocketAddr>,
    /// The local address the first DTLS datagram arrived on (where DTLS answers go before ICE
    /// has a pair).
    remote_local: Option<SocketAddr>,
}

#[derive(Debug, Default, Clone, Copy)]
struct Stats {
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
}

impl std::fmt::Debug for Rtc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rtc")
            .field("ufrag", &self.local_ufrag())
            .field("ice", &self.ice_state)
            .field("dtls_connected", &self.dtls_connected)
            .finish_non_exhaustive()
    }
}

impl Rtc {
    /// A peer; `lite` runs an ICE-lite agent. Generates the DTLS certificate.
    pub(crate) fn new(cfg: ConfigInner, lite: bool, now: Instant) -> Result<Rtc, RtcErr> {
        let identity =
            Identity::generate_self_signed().map_err(|e| err(format!("certificate: {e}")))?;
        let ice = IceAgent::new(IceConfig::new(lite, false), now);
        let bwe = cfg.bwe.map(BandwidthEstimator::new);
        Ok(Rtc {
            lite,
            ice,
            ice_state: IceConnectionState::New,
            identity,
            remote_fp: None,
            dtls_role: None,
            dtls: None,
            dtls_connected: false,
            srtp_tx: None,
            srtp_rx: None,
            sctp: None,
            app_mid: None,
            app_negotiated: false,
            remote_max_message: 65_536,
            channels: HashMap::new(),
            by_stream: HashMap::new(),
            next_channel: 0,
            media: Vec::new(),
            next_mid: 0,
            session_id: random_u64(),
            sdp_version: 1,
            pending: None,
            negotiated: false,
            recv: HashMap::new(),
            routes: HashMap::new(),
            ext: ExtensionMap::new(),
            twcc_tx: TwccSender::new(),
            twcc_rx: TwccReceiver::new(),
            twcc_media_ssrc: 0,
            last_estimate: 0,
            bwe,
            next_rtcp: None,
            next_stats: cfg.stats_interval.map(|d| now + d),
            cname: random_token(16),
            transmits: VecDeque::new(),
            events: VecDeque::new(),
            alive: true,
            closed_emitted: false,
            stats: Stats::default(),
            remote_addr: None,
            remote_local: None,
            cfg,
        })
    }

    pub(crate) fn local_ufrag(&self) -> String {
        self.ice.local_credentials().ufrag.clone()
    }

    pub(crate) fn add_local_candidate(&mut self, c: IceCandidate) {
        self.ice.add_local_candidate(c);
    }

    pub(crate) fn add_remote_candidate(&mut self, c: IceCandidate) {
        self.ice.add_remote_candidate(c);
    }

    pub(crate) fn is_connected(&self) -> bool {
        self.dtls_connected && self.ice.send_pair().is_some()
    }

    pub(crate) fn is_alive(&self) -> bool {
        self.alive
    }

    // ---- SDP ----

    /// A change set for `SdpChanges`, numbered after what exists.
    pub(crate) fn changes(&self) -> Changes<'static> {
        Changes {
            next_channel: self.next_channel,
            next_mid: self.next_mid,
            ops: Vec::new(),
            _rtc: PhantomData,
        }
    }

    fn mid_free(&self, mid: &Mid) -> bool {
        !self.media.iter().any(|m| m.mid == *mid) && self.app_mid != Some(*mid)
    }

    fn alloc_mid(&mut self) -> Mid {
        loop {
            let m = Mid::new(&self.next_mid.to_string());
            self.next_mid += 1;
            if self.mid_free(&m) {
                return m;
            }
        }
    }

    /// Applies a change set; returns the offer when it needs negotiation.
    pub(crate) fn apply(
        &mut self,
        now: Instant,
        ch: Changes<'_>,
    ) -> Result<Option<String>, RtcErr> {
        self.next_channel = self.next_channel.max(ch.next_channel);
        self.next_mid = self.next_mid.max(ch.next_mid);
        let needs_offer = ch.ops.iter().any(|o| !matches!(o, Change::AddChannel(..)))
            || (ch.ops.iter().any(|o| matches!(o, Change::AddChannel(..)))
                && !self.app_negotiated
                && self.app_mid.is_none());
        let mut new_lines = Vec::new();
        for op in ch.ops {
            match op {
                Change::AddChannel(id, cfg) => {
                    self.channels.insert(id, Channel { cfg, stream: None });
                }
                Change::AddMedia {
                    mid,
                    kind,
                    dir,
                    stream_id,
                    track_id,
                } => {
                    let mid = if self.mid_free(&mid) {
                        mid
                    } else {
                        self.alloc_mid()
                    };
                    let mut line = MediaLine::new(mid, kind, dir, stream_id, track_id);
                    line.codecs = local_codecs(&self.cfg, kind);
                    self.media.push(line);
                    new_lines.push(mid);
                }
                Change::SetDirection(mid, dir) => {
                    if let Some(l) = self.media.iter_mut().find(|l| l.mid == mid) {
                        l.want = dir;
                    }
                }
                Change::StopMedia(mid) => {
                    if let Some(l) = self.media.iter_mut().find(|l| l.mid == mid) {
                        l.stopped = true;
                        l.want = Direction::Inactive;
                    }
                }
                Change::IceRestart(keep) => {
                    self.ice.restart(Credentials::random(), keep);
                }
            }
        }
        if !self.channels.is_empty() && self.app_mid.is_none() {
            self.app_mid = Some(self.alloc_mid());
        }
        self.open_pending_channels(now);
        if !needs_offer {
            return Ok(None);
        }
        if !self.lite {
            self.ice.set_controlling(true);
        }
        self.pending = Some(Pending { new_lines });
        Ok(Some(self.write_sdp(true)))
    }

    /// Applies the remote answer to our pending offer.
    pub(crate) fn accept_answer(&mut self, now: Instant, answer: &str) -> Result<(), RtcErr> {
        let sdp = Sdp::parse(answer).map_err(err)?;
        let pending = self.pending.take().ok_or_else(|| err("no offer pending"))?;
        self.apply_remote_transport(&sdp, false)?;
        if self.dtls_role.is_none() {
            let setup = sdp
                .media
                .iter()
                .find_map(|m| m.get("setup"))
                .or_else(|| sdp.get("setup"))
                .unwrap_or("active");
            self.dtls_role = Some(if setup == "passive" {
                Role::Client
            } else {
                Role::Server
            });
        }
        for m in &sdp.media {
            let Some(mid) = m.get("mid").map(Mid::new) else {
                continue;
            };
            if Some(mid) == self.app_mid {
                self.app_negotiated = m.port != 0;
                if let Some(v) = m.get("max-message-size").and_then(|v| v.parse().ok()) {
                    self.remote_max_message = v;
                }
                continue;
            }
            let cfg = self.cfg.clone();
            let Some(idx) = self.media.iter().position(|l| l.mid == mid) else {
                continue;
            };
            let line = &mut self.media[idx];
            if m.port == 0 {
                line.stopped = true;
                line.dir = Direction::Inactive;
                continue;
            }
            let remote_dir = m
                .attrs
                .iter()
                .find_map(|a| Direction::parse(&a.key))
                .unwrap_or(Direction::SendRecv);
            line.dir = line.want.intersect(remote_dir.reverse());
            line.codecs = remote_codecs(&cfg, m, line.kind);
            line.ext = remote_extmap(m);
            line.negotiated = true;
            read_ssrcs(line, m);
            if pending.new_lines.contains(&mid) {
                self.events.push_back(RtcEvent::MediaAdded(MediaAdded {
                    mid,
                    kind: line.kind,
                    direction: line.dir,
                }));
            }
        }
        self.after_negotiation(now);
        Ok(())
    }

    /// Accepts a remote offer and returns our answer.
    pub(crate) fn accept_offer(&mut self, now: Instant, offer: &str) -> Result<String, RtcErr> {
        let sdp = Sdp::parse(offer).map_err(err)?;
        if sdp.media.is_empty() {
            return Err(err("offer without media sections"));
        }
        // A remote offer replaces any of ours (glare: theirs wins here).
        self.pending = None;
        self.apply_remote_transport(&sdp, true)?;
        if self.dtls_role.is_none() {
            let setup = sdp
                .media
                .iter()
                .find_map(|m| m.get("setup"))
                .or_else(|| sdp.get("setup"))
                .unwrap_or("actpass");
            self.dtls_role = Some(if setup == "active" {
                Role::Server
            } else {
                Role::Client
            });
        }
        let cfg = self.cfg.clone();
        let mut order = Vec::new();
        for m in &sdp.media {
            let mid = m
                .get("mid")
                .map_or_else(|| Mid::new(&order.len().to_string()), Mid::new);
            let kind = match m.kind.as_str() {
                "audio" => Some(MediaKind::Audio),
                "video" => Some(MediaKind::Video),
                _ => None,
            };
            if m.kind == "application" && m.proto.contains("SCTP") {
                if self.app_mid.is_none() || self.app_mid == Some(mid) {
                    self.app_mid = Some(mid);
                    self.app_negotiated = m.port != 0;
                    if let Some(v) = m.get("max-message-size").and_then(|v| v.parse().ok()) {
                        self.remote_max_message = v;
                    }
                    order.push(Section::App(mid, m.port != 0));
                } else {
                    order.push(Section::Rejected(m.clone(), mid));
                }
                continue;
            }
            let Some(kind) = kind else {
                order.push(Section::Rejected(m.clone(), mid));
                continue;
            };
            let remote_dir = m
                .attrs
                .iter()
                .find_map(|a| Direction::parse(&a.key))
                .unwrap_or(Direction::SendRecv);
            let idx = match self.media.iter().position(|l| l.mid == mid) {
                Some(i) => i,
                None => {
                    let line = MediaLine::new(mid, kind, Direction::SendRecv, None, None);
                    self.media.push(line);
                    if let Ok(n) = mid.as_str().parse::<usize>() {
                        self.next_mid = self.next_mid.max(n + 1);
                    }
                    self.media.len() - 1
                }
            };
            let line = &mut self.media[idx];
            let was_new = !line.negotiated;
            if m.port == 0 {
                line.stopped = true;
            }
            line.codecs = remote_codecs(&cfg, m, kind);
            line.ext = remote_extmap(m);
            line.dir = if line.stopped || line.codecs.is_empty() {
                Direction::Inactive
            } else {
                line.want.intersect(remote_dir.reverse())
            };
            line.negotiated = true;
            read_ssrcs(line, m);
            if was_new && !line.codecs.is_empty() && !line.stopped {
                self.events.push_back(RtcEvent::MediaAdded(MediaAdded {
                    mid,
                    kind,
                    direction: line.dir,
                }));
            }
            order.push(Section::Line(mid));
        }
        // Our lines must follow the offer's order.
        let answer = self.write_answer(&order);
        self.after_negotiation(now);
        Ok(answer)
    }

    /// ICE credentials, candidates, ICE-lite and the DTLS fingerprint of a remote description.
    fn apply_remote_transport(&mut self, sdp: &Sdp, is_offer: bool) -> Result<(), RtcErr> {
        let first = sdp.media.first();
        let get = |k: &str| {
            first
                .and_then(|m| sdp.media_or_session(m, k))
                .or_else(|| sdp.get(k))
        };
        let ufrag = get("ice-ufrag").ok_or_else(|| err("no a=ice-ufrag"))?;
        let pwd = get("ice-pwd").ok_or_else(|| err("no a=ice-pwd"))?;
        let fp = get("fingerprint").ok_or_else(|| err("no a=fingerprint"))?;
        let fp = Fingerprint::parse(fp).map_err(|e| err(format!("fingerprint: {e}")))?;
        if self.remote_fp.as_ref().is_some_and(|f| *f != fp) && self.dtls.is_some() {
            return Err(err("the remote DTLS fingerprint changed"));
        }
        self.remote_fp = Some(fp);
        let creds = Credentials::new(ufrag, pwd);
        let restart = self.ice.remote_credentials().is_some_and(|c| *c != creds);
        if restart && is_offer {
            // The remote restarts ICE: so do we (RFC 8839 §4.4.1.1.1).
            self.ice.restart(Credentials::random(), true);
        }
        self.ice.set_remote_credentials(creds);
        if sdp.has("ice-lite") {
            self.ice.set_remote_lite(true);
        } else if is_offer && !self.lite {
            self.ice.set_controlling(false);
        }
        let mut end = false;
        for m in &sdp.media {
            for c in m.all("candidate") {
                if let Ok(c) = IceCandidate::parse(&format!("candidate:{c}")) {
                    self.ice.add_remote_candidate(c);
                }
            }
            end |= m.has("end-of-candidates");
        }
        if end || sdp.has("end-of-candidates") {
            self.ice.end_of_remote_candidates();
        }
        Ok(())
    }

    fn after_negotiation(&mut self, now: Instant) {
        self.negotiated = true;
        self.sdp_version += 1;
        let mut ext = ExtensionMap::new();
        for l in &self.media {
            for (id, e) in l.ext.iter() {
                if ext.get(id).is_none() && ext.id_of(e).is_none() {
                    ext.insert(id, e);
                }
            }
        }
        self.ext = ext;
        self.routes.clear();
        self.start_sctp(now);
        self.open_pending_channels(now);
    }

    fn write_sdp(&self, offer: bool) -> String {
        let mut sdp = Sdp {
            session_id: self.session_id,
            version: self.sdp_version,
            ..Sdp::default()
        };
        let mut order: Vec<Mid> = self.media.iter().map(|l| l.mid).collect();
        if let Some(a) = self.app_mid {
            // The application section goes where its mid sorts among ours (it was allocated
            // in sequence).
            let pos = order
                .iter()
                .position(|m| mid_order(m) > mid_order(&a))
                .unwrap_or(order.len());
            order.insert(pos, a);
        }
        let bundle: Vec<&str> = order
            .iter()
            .filter(|m| {
                self.media
                    .iter()
                    .find(|l| l.mid == **m)
                    .is_none_or(|l| !l.stopped)
            })
            .map(Mid::as_str)
            .collect();
        sdp.attrs
            .push(Attr::kv("group", format!("BUNDLE {}", bundle.join(" "))));
        sdp.attrs.push(Attr::kv("msid-semantic", " WMS *"));
        if self.lite {
            sdp.attrs.push(Attr::flag("ice-lite"));
        }
        for (i, mid) in order.iter().enumerate() {
            let setup = if offer {
                "actpass"
            } else {
                self.setup_answer()
            };
            let sec = if Some(*mid) == self.app_mid {
                self.app_section(*mid, setup, i == 0)
            } else if let Some(l) = self.media.iter().find(|l| l.mid == *mid) {
                self.line_section(l, setup, i == 0, offer)
            } else {
                continue;
            };
            sdp.media.push(sec);
        }
        sdp.write()
    }

    fn write_answer(&self, order: &[Section]) -> String {
        let mut sdp = Sdp {
            session_id: self.session_id,
            version: self.sdp_version,
            ..Sdp::default()
        };
        let mut bundle = Vec::new();
        for s in order {
            match s {
                Section::App(m, true) => bundle.push(m.as_str().to_owned()),
                Section::Line(m)
                    if self
                        .media
                        .iter()
                        .find(|l| l.mid == *m)
                        .is_some_and(|l| !l.stopped && !l.codecs.is_empty()) =>
                {
                    bundle.push(m.as_str().to_owned());
                }
                _ => {}
            }
        }
        sdp.attrs
            .push(Attr::kv("group", format!("BUNDLE {}", bundle.join(" "))));
        sdp.attrs.push(Attr::kv("msid-semantic", " WMS *"));
        if self.lite {
            sdp.attrs.push(Attr::flag("ice-lite"));
        }
        let setup = self.setup_answer();
        let mut first = true;
        for s in order {
            let sec = match s {
                Section::App(mid, true) => self.app_section(*mid, setup, first),
                Section::App(mid, false) => rejected(
                    &Media {
                        kind: "application".into(),
                        port: 0,
                        proto: "UDP/DTLS/SCTP".into(),
                        fmts: vec!["webrtc-datachannel".into()],
                        attrs: Vec::new(),
                    },
                    *mid,
                ),
                Section::Rejected(m, mid) => rejected(m, *mid),
                Section::Line(mid) => match self.media.iter().find(|l| l.mid == *mid) {
                    Some(l) if !l.stopped && !l.codecs.is_empty() => {
                        self.line_section(l, setup, first, false)
                    }
                    Some(l) => rejected(
                        &Media {
                            kind: l.kind.as_str().into(),
                            port: 0,
                            proto: "UDP/TLS/RTP/SAVPF".into(),
                            fmts: vec!["0".into()],
                            attrs: Vec::new(),
                        },
                        *mid,
                    ),
                    None => continue,
                },
            };
            if sec.port != 0 {
                first = false;
            }
            sdp.media.push(sec);
        }
        sdp.write()
    }

    fn setup_answer(&self) -> &'static str {
        match self.dtls_role {
            Some(Role::Server) => "passive",
            _ => "active",
        }
    }

    fn transport_attrs(&self, attrs: &mut Vec<Attr>, setup: &str, candidates: bool) {
        let c = self.ice.local_credentials();
        attrs.push(Attr::kv("ice-ufrag", c.ufrag.clone()));
        attrs.push(Attr::kv("ice-pwd", c.pwd.clone()));
        attrs.push(Attr::kv("ice-options", "trickle"));
        attrs.push(Attr::kv(
            "fingerprint",
            fingerprint_sdp(&self.identity.fingerprint()),
        ));
        attrs.push(Attr::kv("setup", setup));
        if candidates {
            for c in self.ice.local_candidates() {
                if c.kind() == only_ice::CandidateKind::PeerReflexive {
                    continue;
                }
                let s = c.to_sdp();
                attrs.push(Attr::kv(
                    "candidate",
                    s.strip_prefix("candidate:").unwrap_or(&s).to_owned(),
                ));
            }
            attrs.push(Attr::flag("end-of-candidates"));
        }
    }

    fn app_section(&self, mid: Mid, setup: &str, candidates: bool) -> Media {
        let mut attrs = Vec::new();
        self.transport_attrs(&mut attrs, setup, candidates);
        attrs.push(Attr::kv("mid", mid.as_str()));
        attrs.push(Attr::kv("sctp-port", "5000"));
        attrs.push(Attr::kv("max-message-size", MAX_MESSAGE_SIZE.to_string()));
        Media {
            kind: "application".into(),
            port: 9,
            proto: "UDP/DTLS/SCTP".into(),
            fmts: vec!["webrtc-datachannel".into()],
            attrs,
        }
    }

    fn line_section(&self, l: &MediaLine, setup: &str, candidates: bool, offer: bool) -> Media {
        let mut attrs = Vec::new();
        self.transport_attrs(&mut attrs, setup, candidates);
        attrs.push(Attr::kv("mid", l.mid.as_str()));
        for (id, e) in l.ext.iter() {
            attrs.push(Attr::kv("extmap", format!("{id} {}", e.uri())));
        }
        let dir = if offer { l.want } else { l.dir };
        attrs.push(Attr::flag(dir.as_str()));
        attrs.push(Attr::kv("msid", format!("{} {}", l.stream_id, l.track_id)));
        attrs.push(Attr::flag("rtcp-mux"));
        attrs.push(Attr::flag("rtcp-rsize"));
        let mut fmts = Vec::new();
        for c in &l.codecs {
            fmts.push(c.pt.to_string());
            let ch = c.channels.map(|n| format!("/{n}")).unwrap_or_default();
            attrs.push(Attr::kv(
                "rtpmap",
                format!("{} {}/{}{ch}", c.pt, c.codec.name(), c.clock),
            ));
            for fb in &c.fb {
                attrs.push(Attr::kv("rtcp-fb", format!("{} {fb}", c.pt)));
            }
            if !c.fmtp.is_empty() {
                attrs.push(Attr::kv("fmtp", format!("{} {}", c.pt, c.fmtp)));
            }
            if let Some(r) = c.rtx {
                fmts.push(r.to_string());
                attrs.push(Attr::kv("rtpmap", format!("{r} rtx/{}", c.clock)));
                attrs.push(Attr::kv("fmtp", format!("{r} apt={}", c.pt)));
            }
        }
        if dir.sends() {
            let ssrc = l.send.ssrc();
            let rtx = l
                .send
                .rtx_ssrc()
                .filter(|_| l.codecs.iter().any(|c| c.rtx.is_some()));
            if let Some(rtx) = rtx {
                attrs.push(Attr::kv("ssrc-group", format!("FID {ssrc} {rtx}")));
            }
            let mut ssrcs = vec![ssrc];
            ssrcs.extend(rtx);
            for s in ssrcs {
                attrs.push(Attr::kv("ssrc", format!("{s} cname:{}", self.cname)));
                attrs.push(Attr::kv(
                    "ssrc",
                    format!("{s} msid:{} {}", l.stream_id, l.track_id),
                ));
            }
        }
        if fmts.is_empty() {
            fmts.push("0".into());
        }
        Media {
            kind: l.kind.as_str().into(),
            port: if l.stopped { 0 } else { 9 },
            proto: "UDP/TLS/RTP/SAVPF".into(),
            fmts,
            attrs,
        }
    }

    // ---- data channels ----

    fn start_sctp(&mut self, now: Instant) {
        if self.sctp.is_some() || !self.app_negotiated || !self.dtls_connected {
            return;
        }
        let client = self.dtls_role == Some(Role::Client);
        let cfg = SctpConfig::new(client)
            .with_mtu(SCTP_MTU)
            .with_max_message_size(self.remote_max_message)
            .with_max_receive_message_size(MAX_MESSAGE_SIZE)
            .with_max_buffered_amount(self.cfg.sctp_max_buffered);
        let mut a = Association::new(cfg, now);
        if client {
            a.connect(now);
        }
        self.sctp = Some(a);
    }

    fn open_pending_channels(&mut self, now: Instant) {
        let Some(sctp) = self.sctp.as_mut() else {
            return;
        };
        let mut ids: Vec<ChannelId> = self
            .channels
            .iter()
            .filter(|(_, c)| c.stream.is_none())
            .map(|(id, _)| *id)
            .collect();
        ids.sort_by_key(|i| i.0);
        for id in ids {
            let Some(ch) = self.channels.get_mut(&id) else {
                continue;
            };
            match sctp.open_channel(now, ch.cfg.to_sctp()) {
                Ok(s) => {
                    ch.stream = Some(s);
                    self.by_stream.insert(s, id);
                }
                Err(e) => {
                    only_log::debug!(target: "only_webrtc", "open channel: {e}");
                    self.channels.remove(&id);
                }
            }
        }
    }

    /// Sends a data channel message; `Ok(false)` when its buffer is full.
    pub(crate) fn send_channel(
        &mut self,
        now: Instant,
        id: ChannelId,
        data: &[u8],
        binary: bool,
    ) -> Result<Option<bool>, RtcErr> {
        let Some(stream) = self.channels.get(&id).and_then(|c| c.stream) else {
            return Ok(None);
        };
        let Some(sctp) = self.sctp.as_mut() else {
            return Ok(None);
        };
        match sctp.send(now, stream, data, binary) {
            Ok(b) => Ok(Some(b)),
            Err(only_sctp::Error::UnknownChannel(_) | only_sctp::Error::ChannelClosed(_)) => {
                Ok(None)
            }
            Err(e) => Err(err(e.to_string())),
        }
    }

    // ---- media ----

    /// The negotiated payload type of `codec` on `mid` (a line that can send).
    pub(crate) fn payload_type(&self, mid: Mid, codec: Codec) -> Option<Pt> {
        let l = self.media.iter().find(|l| l.mid == mid)?;
        l.codecs
            .iter()
            .find(|c| c.codec == codec)
            .map(|c| Pt::from(c.pt))
    }

    /// Packetizes and sends one sample. `Ok(false)`: no such sending line.
    pub(crate) fn write_media(
        &mut self,
        now: Instant,
        mid: Mid,
        pt: Pt,
        time: MediaTime,
        data: &[u8],
    ) -> Result<bool, RtcErr> {
        let Some(idx) = self.media.iter().position(|l| l.mid == mid) else {
            return Ok(false);
        };
        let line = &mut self.media[idx];
        if line.stopped || !(line.dir.sends() || !line.negotiated && line.want.sends()) {
            return Ok(false);
        }
        let Some(codec) = line.codec(pt.get()).cloned() else {
            return Err(err(format!(
                "payload type {} not negotiated on {mid}",
                pt.get()
            )));
        };
        let (Some(tx), Some((src, dest))) = (self.srtp_tx.as_mut(), self.ice.send_pair()) else {
            return Ok(true); // not connected yet: dropped
        };
        line.last_pt = Some(codec.pt);
        let ts = time.ticks_at(codec.clock) as u32;
        let pk = line
            .packetizers
            .entry(codec.pt)
            .or_insert_with(|| only_rtp::codec::packetizer(codec.codec.rtp()));
        let payloads = pk.packetize(RTP_PAYLOAD_MTU, data);
        let has_mid = line.ext.id_of(Extension::Mid).is_some();
        let has_twcc = line.ext.id_of(Extension::TransportCc).is_some();
        let has_ast = line.ext.id_of(Extension::AbsSendTime).is_some();
        for (p, marker) in payloads {
            let mut ext = ExtensionValues::default();
            if has_mid {
                ext.mid = Some(mid.as_str().to_owned());
            }
            if has_ast {
                ext.abs_send_time = Some(abs_send_time_now());
            }
            let tw = has_twcc.then(|| self.twcc_tx.next_seq());
            ext.transport_cc = tw;
            let raw = line
                .send
                .write(now, codec.pt, marker, ts, &p, &ext, &line.ext);
            if let Some(s) = tw {
                self.twcc_tx.on_sent(s, now, raw.len());
            }
            if let Ok(out) = tx.protect_rtp(&raw) {
                self.stats.bytes_sent += out.len() as u64;
                self.stats.packets_sent += 1;
                self.transmits.push_back((src, dest, out));
            }
        }
        if self.next_rtcp.is_none() {
            self.next_rtcp = Some(now + Duration::from_millis(100));
        }
        Ok(true)
    }

    /// Asks the remote sender of `mid` for a keyframe. `false`: no such line.
    pub(crate) fn request_keyframe(&mut self, mid: Mid, kind: KeyframeRequestKind) -> bool {
        let Some(idx) = self.media.iter().position(|l| l.mid == mid) else {
            return false;
        };
        let mut targets: Vec<u32> = self
            .recv
            .iter()
            .filter(|(s, r)| {
                r.line == idx && self.routes.get(s).is_none_or(|x| x.repairs.is_none())
            })
            .map(|(s, _)| *s)
            .collect();
        if targets.is_empty() {
            targets = self.media[idx].remote_ssrcs.clone();
            let rtx: Vec<u32> = self.media[idx].remote_rtx.keys().copied().collect();
            targets.retain(|s| !rtx.contains(s));
        }
        let line = &mut self.media[idx];
        let sender = line.send.ssrc();
        let mut pkts = Vec::new();
        for t in targets {
            pkts.push(match kind {
                KeyframeRequestKind::Pli => Rtcp::Pli {
                    sender_ssrc: sender,
                    media_ssrc: t,
                },
                KeyframeRequestKind::Fir => {
                    line.fir_seq = line.fir_seq.wrapping_add(1);
                    Rtcp::Fir {
                        sender_ssrc: sender,
                        entries: vec![(t, line.fir_seq)],
                    }
                }
            });
        }
        if !pkts.is_empty() {
            self.send_rtcp(&pkts);
        }
        true
    }

    fn send_rtcp(&mut self, pkts: &[Rtcp]) {
        let (Some(tx), Some((src, dest))) = (self.srtp_tx.as_mut(), self.ice.send_pair()) else {
            return;
        };
        let raw = only_rtp::write_compound(pkts);
        if let Ok(out) = tx.protect_rtcp(&raw) {
            self.stats.bytes_sent += out.len() as u64;
            self.transmits.push_back((src, dest, out));
        }
    }

    // ---- input ----

    /// One received datagram from `source`, which arrived on the local address `destination`.
    pub(crate) fn handle_receive(
        &mut self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
        data: &[u8],
    ) {
        if !self.alive {
            return;
        }
        let Some(&b) = data.first() else { return };
        match b {
            0..=3 => {
                self.ice.handle_receive(now, source, destination, data);
            }
            20..=63 => {
                if self.remote_addr.is_none() {
                    self.remote_addr = Some(source);
                    self.remote_local = Some(destination);
                }
                self.handle_dtls(now, Some(data));
            }
            128..=191 => {
                self.stats.bytes_received += data.len() as u64;
                self.stats.packets_received += 1;
                if only_rtp::is_rtcp(data) {
                    self.handle_rtcp(now, data);
                } else {
                    self.handle_rtp(now, data);
                }
            }
            _ => {}
        }
        self.pump(now);
    }

    pub(crate) fn handle_timeout(&mut self, now: Instant) {
        if !self.alive {
            return;
        }
        self.ice.handle_timeout(now);
        if let Some(d) = self.dtls.as_mut() {
            if d.poll_timeout().is_some_and(|t| t <= now) {
                if let Err(e) = d.handle_timeout(now) {
                    only_log::debug!(target: "only_webrtc", "dtls: {e}");
                    self.die();
                }
            }
        }
        if let Some(s) = self.sctp.as_mut() {
            if s.poll_timeout().is_some_and(|t| t <= now) {
                s.handle_timeout(now);
            }
        }
        self.media_timers(now);
        self.pump(now);
    }

    fn die(&mut self) {
        self.alive = false;
    }

    /// Sends DTLS close_notify; the peer is dead afterwards.
    pub(crate) fn close(&mut self, now: Instant) {
        if let Some(s) = self.sctp.as_mut() {
            s.abort();
        }
        self.flush_sctp(now);
        if let Some(d) = self.dtls.as_mut() {
            d.close();
        }
        self.flush_dtls(now);
        self.ice.close();
        self.alive = false;
    }

    fn handle_dtls(&mut self, now: Instant, data: Option<&[u8]>) {
        if self.dtls.is_none() {
            self.start_dtls(now);
        }
        let Some(d) = self.dtls.as_mut() else { return };
        if let Some(data) = data {
            if let Err(e) = d.handle_datagram(now, data) {
                only_log::debug!(target: "only_webrtc", "dtls: {e}");
                self.die();
            }
        }
    }

    fn start_dtls(&mut self, now: Instant) {
        let (Some(role), Some(fp)) = (self.dtls_role, self.remote_fp.clone()) else {
            return;
        };
        if self.dtls.is_some() {
            return;
        }
        let cfg = Arc::new(DtlsConfig::webrtc(
            self.identity.clone(),
            PeerVerifier::Fingerprints(vec![fp]),
        ));
        let r = match role {
            Role::Client => Connection::client(cfg, now),
            Role::Server => {
                let peer = self.remote_addr.map(|a| a.to_string()).unwrap_or_default();
                Connection::server(cfg, now, peer.as_bytes())
            }
        };
        match r {
            Ok(c) => self.dtls = Some(c),
            Err(e) => {
                only_log::debug!(target: "only_webrtc", "dtls: {e}");
                self.die();
            }
        }
    }

    fn handle_rtp(&mut self, now: Instant, data: &[u8]) {
        let Some(rx) = self.srtp_rx.as_mut() else {
            return;
        };
        let Ok(pkt) = rx.unprotect_rtp(data) else {
            return;
        };
        let Some(h) = RtpHeader::parse(&pkt, &self.ext) else {
            return;
        };
        if let Some(seq) = h.ext.transport_cc {
            self.twcc_rx.on_received(seq, now);
            self.twcc_media_ssrc = h.ssrc;
        }
        let Some(route) = self.route(&h) else {
            return;
        };
        let mut payload = h.payload(&pkt);
        let (ssrc, seq, pt) = match route.repairs {
            Some(main) => {
                let line = &self.media[route.line];
                let Some(orig) = line.rtx_of(h.payload_type).map(|c| c.pt) else {
                    return;
                };
                if payload.len() < 2 {
                    return; // padding-only probe
                }
                let osn = u16::from_be_bytes([payload[0], payload[1]]);
                payload = &payload[2..];
                (main, osn, orig)
            }
            None => (h.ssrc, h.sequence_number, h.payload_type),
        };
        if payload.is_empty() {
            return;
        }
        let line_idx = route.line;
        let Some(codec) = self.media[line_idx].codec(pt).cloned() else {
            return;
        };
        let reorder = if codec.codec.kind() == MediaKind::Audio {
            self.cfg.reorder_audio
        } else {
            self.cfg.reorder_video
        };
        let nack = codec.fb.iter().any(|f| f == "nack");
        if self.recv.len() >= MAX_RECV_STREAMS && !self.recv.contains_key(&ssrc) {
            return;
        }
        let recv = self.recv.entry(ssrc).or_insert_with(|| Recv {
            line: line_idx,
            stream: RecvStream::new(ssrc, codec.clock, nack),
            assembler: None,
            rid: None,
        });
        if recv.rid.is_none() {
            recv.rid = h.ext.rid.clone();
        }
        let Some(ext_seq) = recv.stream.receive(now, seq, h.timestamp) else {
            return;
        };
        let mid = self.media[line_idx].mid;
        if self.cfg.rtp_mode {
            self.events.push_back(RtcEvent::Rtp(RtpPacket {
                seq_no: ext_seq,
                ssrc,
                pt: Pt::from(pt),
                marker: h.marker,
                rtp_time: h.timestamp,
                time: MediaTime::new(
                    u64::from(h.timestamp),
                    Frequency::new(codec.clock).unwrap_or(Frequency::NINETY_KHZ),
                ),
                received: now,
                payload: Arc::from(payload),
            }));
            return;
        }
        if recv.assembler.as_ref().is_none_or(|(p, _)| *p != pt) {
            recv.assembler = Some((pt, FrameAssembler::new(codec.codec.rtp(), reorder)));
        }
        let rid = recv.rid.clone();
        let Some((_, asm)) = recv.assembler.as_mut() else {
            return;
        };
        asm.push(ext_seq, h.timestamp, h.marker, payload, now);
        while let Some(f) = asm.pop() {
            self.events.push_back(RtcEvent::MediaData(MediaData {
                mid,
                pt: Pt::from(pt),
                rid: rid.clone(),
                codec: Some(codec.codec),
                time: MediaTime::new(
                    f.timestamp,
                    Frequency::new(codec.clock).unwrap_or(Frequency::NINETY_KHZ),
                ),
                network_time: f.first_arrival,
                contiguous: f.contiguous,
                data: Arc::from(f.data),
            }));
        }
    }

    /// Which line (and repaired stream) an incoming packet belongs to.
    fn route(&mut self, h: &RtpHeader) -> Option<Route> {
        if let Some(r) = self.routes.get(&h.ssrc) {
            return Some(*r);
        }
        let mut found = None;
        for (i, l) in self.media.iter().enumerate() {
            if l.remote_ssrcs.contains(&h.ssrc) {
                found = Some(Route {
                    line: i,
                    repairs: l.remote_rtx.get(&h.ssrc).copied(),
                });
                break;
            }
        }
        if found.is_none() {
            let line = h
                .ext
                .mid
                .as_deref()
                .and_then(|m| self.media.iter().position(|l| l.mid.as_str() == m))
                .or_else(|| {
                    let c: Vec<usize> = self
                        .media
                        .iter()
                        .enumerate()
                        .filter(|(_, l)| {
                            !l.stopped
                                && (l.codec(h.payload_type).is_some()
                                    || l.rtx_of(h.payload_type).is_some())
                        })
                        .map(|(i, _)| i)
                        .collect();
                    (c.len() == 1).then(|| c[0])
                })?;
            let l = &self.media[line];
            let repairs = if l.rtx_of(h.payload_type).is_some() {
                // Unsignalled RTX: repairs the line's (first) media stream.
                let main = self
                    .routes
                    .iter()
                    .find(|(_, r)| r.line == line && r.repairs.is_none())
                    .map(|(s, _)| *s)?;
                Some(main)
            } else {
                None
            };
            found = Some(Route { line, repairs });
        }
        let r = found?;
        if self.routes.len() < 256 {
            self.routes.insert(h.ssrc, r);
        }
        Some(r)
    }

    fn handle_rtcp(&mut self, now: Instant, data: &[u8]) {
        let Some(rx) = self.srtp_rx.as_mut() else {
            return;
        };
        let Ok(pkt) = rx.unprotect_rtcp(data) else {
            return;
        };
        let Ok(pkts) = only_rtp::parse_compound(&pkt) else {
            return;
        };
        let ntp = only_rtp::ntp_time(SystemTime::now());
        for p in pkts {
            match p {
                Rtcp::SenderReport {
                    ssrc,
                    info,
                    reports,
                } => {
                    if let Some(r) = self.recv.get_mut(&ssrc) {
                        r.stream.handle_sender_report(now, &info);
                        let mid = self.media[r.line].mid;
                        self.events.push_back(RtcEvent::Other(Other::SenderReport {
                            mid,
                            ssrc,
                            ntp_time: info.ntp_time,
                            rtp_time: info.rtp_time,
                        }));
                    }
                    self.report_blocks(now, ntp, &reports);
                }
                Rtcp::ReceiverReport { reports, .. } => self.report_blocks(now, ntp, &reports),
                Rtcp::Nack {
                    media_ssrc, lost, ..
                } => self.resend(now, media_ssrc, &lost),
                Rtcp::Pli { media_ssrc, .. } => {
                    self.keyframe_request(media_ssrc, KeyframeRequestKind::Pli);
                }
                Rtcp::Fir { entries, .. } => {
                    for (s, _) in entries {
                        self.keyframe_request(s, KeyframeRequestKind::Fir);
                    }
                }
                Rtcp::TransportCc(fb) => {
                    let res = self.twcc_tx.on_feedback(now, &fb);
                    if let Some(b) = self.bwe.as_mut() {
                        b.on_packet_results(now, &res);
                    }
                    self.bwe_event();
                }
                Rtcp::Remb { bitrate, .. } => {
                    if let Some(b) = self.bwe.as_mut() {
                        b.set_remote_estimate(bitrate);
                    }
                    self.bwe_event();
                }
                _ => {}
            }
        }
    }

    fn bwe_event(&mut self) {
        if let Some(b) = &self.bwe {
            let e = b.estimate();
            // Report changes of more than 5 %.
            if self.last_estimate == 0 || e.abs_diff(self.last_estimate) * 20 > self.last_estimate {
                self.last_estimate = e;
                self.events
                    .push_back(RtcEvent::Other(Other::EgressBitrateEstimate(e)));
            }
        }
    }

    fn report_blocks(&mut self, now: Instant, ntp: u64, blocks: &[only_rtp::ReportBlock]) {
        for b in blocks {
            if let Some(l) = self.media.iter_mut().find(|l| l.send.ssrc() == b.ssrc) {
                l.send.handle_report_block(now, ntp, b);
                if let Some(rtt) = l.send.rtt() {
                    for r in self.recv.values_mut() {
                        r.stream.set_rtt(rtt);
                    }
                }
            }
        }
    }

    fn keyframe_request(&mut self, media_ssrc: u32, kind: KeyframeRequestKind) {
        if let Some(l) = self.media.iter().find(|l| l.send.ssrc() == media_ssrc) {
            self.events.push_back(RtcEvent::Keyframe(KeyframeRequest {
                mid: l.mid,
                rid: None,
                kind,
            }));
        }
    }

    fn resend(&mut self, now: Instant, media_ssrc: u32, lost: &[u16]) {
        let Some(line) = self.media.iter_mut().find(|l| l.send.ssrc() == media_ssrc) else {
            return;
        };
        let (Some(tx), Some((src, dest))) = (self.srtp_tx.as_mut(), self.ice.send_pair()) else {
            return;
        };
        let rtx_pt = line.last_pt.and_then(|p| line.codec(p)).and_then(|c| c.rtx);
        let twcc = &mut self.twcc_tx;
        let has_twcc = line.ext.id_of(Extension::TransportCc).is_some();
        let mut seqs = Vec::new();
        let pkts = line.send.resend_with(now, lost, rtx_pt, &line.ext, |e| {
            if has_twcc {
                let s = twcc.next_seq();
                e.transport_cc = Some(s);
                seqs.push(s);
            }
        });
        for (i, raw) in pkts.into_iter().enumerate() {
            if let Some(s) = seqs.get(i) {
                twcc.on_sent(*s, now, raw.len());
            }
            if let Ok(out) = tx.protect_rtp(&raw) {
                self.stats.bytes_sent += out.len() as u64;
                self.transmits.push_back((src, dest, out));
            }
        }
    }

    /// NACKs, RTCP reports, TWCC feedback, statistics.
    fn media_timers(&mut self, now: Instant) {
        if self.srtp_tx.is_none() {
            return;
        }
        // NACKs.
        let mut out = Vec::new();
        for r in self.recv.values_mut() {
            if let Some(lost) = r.stream.poll_nack(now) {
                let sender = self.media.get(r.line).map_or(0, |l| l.send.ssrc());
                out.push(Rtcp::Nack {
                    sender_ssrc: sender,
                    media_ssrc: r.stream.ssrc(),
                    lost,
                });
            }
        }
        // TWCC feedback.
        let sender = self.media.first().map_or(1, |l| l.send.ssrc());
        while let Some(fb) = self
            .twcc_rx
            .poll_feedback(now, sender, self.twcc_media_ssrc)
        {
            out.push(fb);
            if out.len() > 32 {
                break;
            }
        }
        for p in out {
            self.send_rtcp(std::slice::from_ref(&p));
        }
        // Reports.
        if self.next_rtcp.is_none_or(|t| t <= now) {
            self.next_rtcp = Some(now + RTCP_INTERVAL);
            self.send_reports(now);
        }
        if let (Some(t), Some(d)) = (self.next_stats, self.cfg.stats_interval) {
            if t <= now {
                self.next_stats = Some(now + d);
                let rtt = self.media.iter().find_map(|l| l.send.rtt());
                self.events.push_back(RtcEvent::Other(Other::PeerStats {
                    bytes_sent: self.stats.bytes_sent,
                    bytes_received: self.stats.bytes_received,
                    packets_sent: self.stats.packets_sent,
                    packets_received: self.stats.packets_received,
                    rtt_ms: rtt.map(|r| r.as_millis() as u64),
                }));
            }
        }
    }

    fn send_reports(&mut self, now: Instant) {
        let ntp = only_rtp::ntp_time(SystemTime::now());
        let mut compounds = Vec::new();
        for (i, l) in self.media.iter().enumerate() {
            if l.stopped || !l.negotiated {
                continue;
            }
            let mut blocks = Vec::new();
            for r in self.recv.values_mut().filter(|r| r.line == i) {
                if let Some(b) = r.stream.report_block(now) {
                    blocks.push(b);
                }
            }
            blocks.truncate(31);
            let ssrc = l.send.ssrc();
            let mut pkts = Vec::new();
            match l.send.sender_report(now, ntp) {
                Some(info) => pkts.push(Rtcp::SenderReport {
                    ssrc,
                    info,
                    reports: blocks,
                }),
                None if !blocks.is_empty() => pkts.push(Rtcp::ReceiverReport {
                    ssrc,
                    reports: blocks,
                }),
                None => continue,
            }
            pkts.push(Rtcp::SourceDescription(vec![(
                ssrc,
                vec![(1, self.cname.clone())],
            )]));
            compounds.push(pkts);
        }
        for c in compounds {
            self.send_rtcp(&c);
        }
    }

    // ---- output ----

    /// Moves what the sub-protocols produced into the output queues.
    fn pump(&mut self, now: Instant) {
        for _ in 0..8 {
            let mut progress = false;
            while let Some(t) = self.ice.poll_transmit() {
                self.transmits
                    .push_back((t.source, t.destination, t.contents));
            }
            while let Some(e) = self.ice.poll_event() {
                progress = true;
                match e {
                    IceEvent::StateChanged(s) => {
                        let s = IceConnectionState::from_ice(s);
                        if s != self.ice_state {
                            self.ice_state = s;
                            self.events.push_back(RtcEvent::IceState(s));
                        }
                    }
                    IceEvent::SelectedPair { local, remote } => {
                        self.events
                            .push_back(RtcEvent::Other(Other::IcePair { local, remote }));
                    }
                    _ => {}
                }
            }
            if self.dtls.is_none()
                && self.dtls_role == Some(Role::Client)
                && self.ice.send_pair().is_some()
            {
                self.start_dtls(now);
                progress = true;
            }
            if self.flush_dtls(now) {
                progress = true;
            }
            if self.flush_sctp(now) {
                progress = true;
            }
            if !progress {
                break;
            }
        }
        if !self.alive && !self.closed_emitted {
            self.closed_emitted = true;
            self.events.push_back(RtcEvent::Closed);
        }
    }

    /// DTLS datagrams out, DTLS events in. Whether anything happened.
    fn flush_dtls(&mut self, now: Instant) -> bool {
        let Some(d) = self.dtls.as_mut() else {
            return false;
        };
        let mut progress = false;
        let path = self
            .ice
            .send_pair()
            .or_else(|| self.remote_local.zip(self.remote_addr));
        while let Some(t) = d.poll_transmit() {
            if let Some((src, dest)) = path {
                self.transmits.push_back((src, dest, t));
            }
        }
        let mut evs = Vec::new();
        while let Some(e) = d.poll_event() {
            evs.push(e);
        }
        for e in evs {
            progress = true;
            match e {
                DtlsEvent::Connected(info) => {
                    let role = self.dtls_role.unwrap_or(Role::Client);
                    if let Some(keys) = info.srtp_keys {
                        if let Some(p) = Profile::from_id(keys.profile.id()) {
                            let (lk, ls) = keys.local(role);
                            let (rk, rs) = keys.remote(role);
                            self.srtp_tx = Srtp::new(p, lk, ls).ok();
                            self.srtp_rx =
                                Srtp::new(p, rk, rs).ok().map(|c| c.with_replay_window(512));
                        }
                    }
                    self.dtls_connected = true;
                    self.events.push_back(RtcEvent::Connected);
                    self.next_rtcp = Some(now + Duration::from_millis(200));
                    self.start_sctp(now);
                    self.open_pending_channels(now);
                }
                DtlsEvent::ApplicationData(data) => {
                    if let Some(s) = self.sctp.as_mut() {
                        s.handle_packet(now, &data);
                    } else if self.app_negotiated {
                        // The peer's SCTP INIT can beat our Connected processing.
                        self.start_sctp(now);
                        if let Some(s) = self.sctp.as_mut() {
                            s.handle_packet(now, &data);
                        }
                    }
                }
                DtlsEvent::Closed => self.die(),
                _ => {}
            }
        }
        progress
    }

    /// SCTP packets into DTLS records, SCTP events out.
    fn flush_sctp(&mut self, now: Instant) -> bool {
        let Some(s) = self.sctp.as_mut() else {
            return false;
        };
        let mut progress = false;
        while let Some(p) = s.poll_transmit(now) {
            progress = true;
            if let Some(d) = self.dtls.as_mut() {
                let _ = d.send_application_data(&p);
            }
        }
        while let Some(e) = s.poll_event() {
            progress = true;
            match e {
                SctpEvent::ChannelOpen { stream, label, .. } => {
                    let id = match self.by_stream.get(&stream) {
                        Some(id) => *id,
                        None => {
                            let id = ChannelId(self.next_channel);
                            self.next_channel += 1;
                            self.by_stream.insert(stream, id);
                            let info = s.channel(stream);
                            let mut cfg = ChannelConfig::new(label.clone());
                            if let Some(i) = info {
                                cfg.ordered = i.ordered;
                                cfg.protocol = i.protocol;
                            }
                            self.channels.insert(
                                id,
                                Channel {
                                    cfg,
                                    stream: Some(stream),
                                },
                            );
                            id
                        }
                    };
                    self.events.push_back(RtcEvent::ChannelOpen(id, label));
                }
                SctpEvent::ChannelData {
                    stream,
                    data,
                    binary,
                } => {
                    if let Some(id) = self.by_stream.get(&stream) {
                        self.events
                            .push_back(RtcEvent::ChannelData(*id, data, binary));
                    }
                }
                SctpEvent::ChannelClose { stream } => {
                    if let Some(id) = self.by_stream.remove(&stream) {
                        self.channels.remove(&id);
                        self.events.push_back(RtcEvent::ChannelClose(id));
                    }
                }
                SctpEvent::BufferedAmountLow { stream } => {
                    if let Some(id) = self.by_stream.get(&stream) {
                        self.events.push_back(RtcEvent::BufferedLow(*id));
                    }
                }
                _ => {}
            }
        }
        progress
    }

    /// The next output: datagrams first, then events, then the next deadline.
    pub(crate) fn poll_output(&mut self, now: Instant) -> Output {
        if self.transmits.is_empty() && self.events.is_empty() {
            self.pump(now);
        }
        if let Some((s, d, t)) = self.transmits.pop_front() {
            return Output::Transmit(s, d, t);
        }
        if let Some(e) = self.events.pop_front() {
            return Output::Event(e);
        }
        let mut t = now + Duration::from_secs(1);
        let mut min = |x: Option<Instant>| {
            if let Some(x) = x {
                t = t.min(x);
            }
        };
        min(self.ice.poll_timeout());
        min(self.dtls.as_ref().and_then(Connection::poll_timeout));
        min(self.sctp.as_ref().and_then(Association::poll_timeout));
        if self.srtp_tx.is_some() {
            min(self.next_rtcp);
            min(self.next_stats);
            for r in self.recv.values() {
                min(r.stream.poll_timeout());
            }
            if self.ext.id_of(Extension::TransportCc).is_some() && !self.recv.is_empty() {
                min(Some(now + only_rtp::TWCC_FEEDBACK_INTERVAL));
            }
        }
        Output::Timeout(t.max(now))
    }
}

/// Sections of an answer, in the offer's order.
#[derive(Debug)]
enum Section {
    App(Mid, bool),
    Line(Mid),
    Rejected(Media, Mid),
}

fn rejected(m: &Media, mid: Mid) -> Media {
    Media {
        kind: m.kind.clone(),
        port: 0,
        proto: m.proto.clone(),
        fmts: if m.fmts.is_empty() {
            vec!["0".into()]
        } else {
            m.fmts.clone()
        },
        attrs: vec![Attr::kv("mid", mid.as_str()), Attr::flag("inactive")],
    }
}

/// Numeric mids sort numerically, others after them.
fn mid_order(m: &Mid) -> (usize, String) {
    match m.as_str().parse::<usize>() {
        Ok(n) => (n, String::new()),
        Err(_) => (usize::MAX, m.as_str().to_owned()),
    }
}

fn read_ssrcs(line: &mut MediaLine, m: &Media) {
    let mut ssrcs = Vec::new();
    for v in m.all("ssrc") {
        if let Some(Ok(s)) = v.split_whitespace().next().map(str::parse::<u32>) {
            if !ssrcs.contains(&s) && ssrcs.len() < 32 {
                ssrcs.push(s);
            }
        }
    }
    line.remote_rtx.clear();
    for v in m.all("ssrc-group") {
        let mut f = v.split_whitespace();
        if f.next() == Some("FID") {
            let a = f.next().and_then(|x| x.parse::<u32>().ok());
            let b = f.next().and_then(|x| x.parse::<u32>().ok());
            if let (Some(a), Some(b)) = (a, b) {
                line.remote_rtx.insert(b, a);
            }
        }
    }
    line.remote_ssrcs = ssrcs;
}

fn abs_send_time_now() -> u32 {
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    only_rtp::abs_send_time(d)
}

#[cfg(test)]
mod tests;
