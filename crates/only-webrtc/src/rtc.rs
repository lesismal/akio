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
use only_rtp::fec::{FecDecoder, FecEncoder, FecScheme};
use only_rtp::{
    BandwidthEstimator, CcfbReceiver, CcfbSender, Extension, ExtensionMap, ExtensionValues,
    RecvStream, RrtrResponder, Rtcp, RtpHeader, SendStream, TmmbrHandler, TwccReceiver, TwccSender,
};
use only_sctp::{Association, Config as SctpConfig, Event as SctpEvent};
use only_srtp::{Context as Srtp, Profile};

use crate::sdp::{Attr, Media, Sdp};
use crate::types::{
    Change, Changes, ChannelConfig, ChannelId, Codec, ConfigInner, Direction, FecMechanism,
    IceConnectionState, KeyframeRequest, KeyframeRequestKind, MediaAdded, MediaData, MediaKind,
    MediaTime, Mid, Other, Pt, RtpPacket,
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
/// Received streams repaired by FEC per peer: each decoder keeps up to 1024 recent packets
/// (about 1.5 MB), so a peer holds at most about 6 MB for it.
const MAX_FEC_DECODERS: usize = 4;
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
/// RFC 8888 congestion control feedback.
pub(crate) const FB_CCFB: &str = "ack ccfb";
/// RFC 5104 TMMBR / TMMBN.
pub(crate) const FB_TMMBR: &str = "ccm tmmbr";
/// libwebrtc's flag for RTCP XR receiver reference times.
pub(crate) const FB_RRTR: &str = "rrtr";

/// The RTCP feedback this configuration offers and accepts for `kind`.
fn our_fb(cfg: &ConfigInner, kind: MediaKind) -> Vec<&'static str> {
    let mut fb: Vec<&'static str> = if kind == MediaKind::Video {
        VIDEO_FB.to_vec()
    } else {
        AUDIO_FB.to_vec()
    };
    if cfg.ccfb {
        fb.push(FB_CCFB);
    }
    if kind == MediaKind::Video {
        if cfg.tmmbr {
            fb.push(FB_TMMBR);
        }
        if cfg.xr {
            fb.push(FB_RRTR);
        }
    }
    fb
}

/// The FEC payload types of a video line (all `None`: no FEC).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FecPts {
    pub(crate) red: Option<u8>,
    pub(crate) red_rtx: Option<u8>,
    pub(crate) ulpfec: Option<u8>,
    pub(crate) flexfec: Option<u8>,
}

impl FecPts {
    /// Our payload types for `mechanism`.
    fn local(cfg: &ConfigInner, kind: MediaKind) -> FecPts {
        match (kind, cfg.fec) {
            (MediaKind::Video, Some(FecMechanism::Ulpfec)) => FecPts {
                red: Some(116),
                red_rtx: Some(117),
                ulpfec: Some(118),
                flexfec: None,
            },
            (MediaKind::Video, Some(FecMechanism::FlexFec)) => FecPts {
                flexfec: Some(115),
                ..FecPts::default()
            },
            _ => FecPts::default(),
        }
    }

    /// The payload types of a remote video section this configuration accepts.
    fn remote(cfg: &ConfigInner, m: &Media, kind: MediaKind) -> FecPts {
        if kind != MediaKind::Video {
            return FecPts::default();
        }
        let mut maps: Vec<(u8, String)> = Vec::new();
        for v in m.all("rtpmap") {
            let Some((pt, enc)) = v.split_once(' ') else {
                continue;
            };
            let (Ok(pt), Some((name, clock))) =
                (pt.trim().parse::<u8>(), enc.trim().split_once('/'))
            else {
                continue;
            };
            if clock.split('/').next() == Some("90000")
                && m.fmts.iter().any(|f| f.parse() == Ok(pt))
            {
                maps.push((pt, name.to_ascii_lowercase()));
            }
        }
        let find = |n: &str| maps.iter().find(|(_, x)| x == n).map(|(p, _)| *p);
        match cfg.fec {
            Some(FecMechanism::Ulpfec) => {
                let (Some(red), Some(ulpfec)) = (find("red"), find("ulpfec")) else {
                    return FecPts::default();
                };
                let red_rtx = maps.iter().find_map(|(rp, rn)| {
                    (rn == "rtx"
                        && m.all("fmtp").any(|v| {
                            v.split_once(' ').is_some_and(|(p, rest)| {
                                p.trim().parse::<u8>() == Ok(*rp)
                                    && fmtp_param(rest, "apt").and_then(|a| a.parse().ok())
                                        == Some(red)
                            })
                        }))
                    .then_some(*rp)
                });
                FecPts {
                    red: Some(red),
                    red_rtx,
                    ulpfec: Some(ulpfec),
                    flexfec: None,
                }
            }
            Some(FecMechanism::FlexFec) => FecPts {
                flexfec: find("flexfec-03"),
                ..FecPts::default()
            },
            None => FecPts::default(),
        }
    }

    /// The scheme of received FEC, if any.
    fn receive_scheme(&self) -> Option<FecScheme> {
        if self.flexfec.is_some() {
            Some(FecScheme::Flexfec03)
        } else if self.red.is_some() && self.ulpfec.is_some() {
            Some(FecScheme::Ulpfec)
        } else {
            None
        }
    }
}

/// The FEC protection factor (FEC packets per 256 media packets) for a smoothed loss
/// fraction: three times the loss, 0 below 1 %, within the configured bounds.
pub(crate) fn fec_rate(cfg: &ConfigInner, loss: f64) -> u8 {
    let r = if loss < 0.01 { 0.0 } else { loss * 3.0 * 256.0 };
    (r.round().clamp(0.0, 255.0) as u8).clamp(cfg.fec_min, cfg.fec_max)
}

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
        let fb = our_fb(cfg, kind).into_iter().map(str::to_owned).collect();
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
    let ours = our_fb(cfg, kind);
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
            fb: fb_of(*pt, &ours),
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

/// One simulcast encoding this side sends (RFC 8853): its RID, RTP stream (with its own RTX
/// SSRC) and packetizers.
#[derive(Debug)]
struct SimEnc {
    rid: String,
    send: SendStream,
    packetizers: HashMap<u8, Box<dyn Packetizer>>,
    /// The answer accepted it (`a=simulcast:recv`); before an answer, every encoding is.
    active: bool,
}

/// Most simulcast encodings of one line (and RIDs accepted from a remote offer).
pub(crate) const MAX_SIMULCAST: usize = 8;

/// The RIDs of `a=simulcast:<dir> ...` in `m` (RFC 8853 §5.1): the first alternative of each
/// stream, paused ones (`~`) left out.
fn simulcast_rids(m: &Media, dir: &str) -> Option<Vec<String>> {
    let v = m.get("simulcast")?;
    let mut it = v.split_whitespace();
    while let Some(d) = it.next() {
        let list = it.next()?;
        if d != dir {
            continue;
        }
        let rids = list
            .split(';')
            .filter_map(|alt| alt.split(',').next())
            .filter(|r| !r.starts_with('~') && valid_rid(r))
            .take(MAX_SIMULCAST)
            .map(str::to_owned)
            .collect();
        return Some(rids);
    }
    None
}

/// RFC 8851 `rid-id`: letters, digits, `-` and `_` (at most 16 here, as browsers).
pub(crate) fn valid_rid(r: &str) -> bool {
    !r.is_empty()
        && r.len() <= 16
        && r.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
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
    /// Simulcast encodings this side sends; empty without simulcast.
    sim: Vec<SimEnc>,
    /// RIDs the remote's offer sends (`a=simulcast:send`): the answer receives them.
    recv_rids: Vec<String>,
    /// FEC payload types (offered, then negotiated).
    fec_pts: FecPts,
    /// Our FlexFEC stream (used when `flexfec-03` is negotiated and this line sends).
    fec_send: SendStream,
    /// The encoder protecting the sent stream, made on the first protected write.
    fec_enc: Option<FecEncoder>,
    /// Smoothed loss fraction of the sent stream from the remote's receiver reports.
    fec_loss: Option<f64>,
    /// Packets sent and retransmitted at the previous receiver report.
    fec_prev: (u64, u64),
    /// Remote FlexFEC SSRCs (`a=ssrc-group:FEC-FR`) and the SSRC each protects.
    remote_fec: HashMap<u32, u32>,
    /// RTCP XR receiver reference times were negotiated.
    xr: bool,
    /// A TMMBR this side keeps requesting from the remote sender (bits per second).
    tmmbr_req: Option<u64>,
}

impl MediaLine {
    fn new(
        mid: Mid,
        kind: MediaKind,
        want: Direction,
        stream_id: Option<String>,
        track_id: Option<String>,
        rids: &[String],
    ) -> MediaLine {
        let ssrc = random_u32();
        let rtx = random_u32();
        let sim = rids
            .iter()
            .take(MAX_SIMULCAST)
            .map(|r| SimEnc {
                rid: r.clone(),
                send: SendStream::new(
                    random_u32(),
                    90_000,
                    Some(random_u32()),
                    random_u32() as u16,
                ),
                packetizers: HashMap::new(),
                active: true,
            })
            .collect();
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
            sim,
            recv_rids: Vec::new(),
            fec_pts: FecPts::default(),
            fec_send: SendStream::new(random_u32(), 90_000, None, random_u32() as u16),
            fec_enc: None,
            fec_loss: None,
            fec_prev: (0, 0),
            remote_fec: HashMap::new(),
            xr: false,
            tmmbr_req: None,
        }
    }

    /// The scheme of the FEC this line sends with its media, if negotiated.
    fn fec_send_scheme(&self) -> Option<FecScheme> {
        if self.kind != MediaKind::Video || !self.sim.is_empty() || !self.negotiated {
            return None;
        }
        self.fec_pts.receive_scheme()
    }

    /// The send stream with SSRC `ssrc`: `None` for the main one, else the encoding's index.
    fn send_of(&self, ssrc: u32) -> Option<Option<usize>> {
        if self.sim.is_empty() && self.send.ssrc() == ssrc {
            return Some(None);
        }
        self.sim
            .iter()
            .position(|e| e.send.ssrc() == ssrc)
            .map(Some)
    }

    fn send_mut(&mut self, enc: Option<usize>) -> &mut SendStream {
        match enc {
            Some(i) => &mut self.sim[i].send,
            None => &mut self.send,
        }
    }

    /// The round-trip time of the first stream that has one.
    fn rtt(&self) -> Option<Duration> {
        self.send
            .rtt()
            .or_else(|| self.sim.iter().find_map(|e| e.send.rtt()))
    }

    fn codec(&self, pt: u8) -> Option<&CodecParams> {
        self.codecs.iter().find(|c| c.pt == pt)
    }

    /// The codec an RTX payload type repairs.
    fn rtx_of(&self, pt: u8) -> Option<&CodecParams> {
        self.codecs.iter().find(|c| c.rtx == Some(pt))
    }

    /// Whether `pt` is a negotiated payload type of this line (media, RTX or FEC).
    fn knows_pt(&self, pt: u8) -> bool {
        let f = &self.fec_pts;
        self.codec(pt).is_some()
            || self.rtx_of(pt).is_some()
            || [f.red, f.red_rtx, f.ulpfec, f.flexfec].contains(&Some(pt))
    }

    /// Whether `pt` is an RTX payload type of this line.
    fn is_rtx(&self, pt: u8) -> bool {
        self.rtx_of(pt).is_some() || self.fec_pts.red_rtx == Some(pt)
    }

    /// Whether `ssrc` is one this line sends media from.
    fn sends_ssrc(&self, ssrc: u32) -> bool {
        self.send_of(ssrc).is_some()
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
    /// Remote candidates whose address is an mDNS name: (name, candidate line), for the
    /// endpoint's resolver ([`Rtc::take_mdns`]).
    mdns_wanted: Vec<(String, String)>,
    /// FEC decoders by protected (received) media SSRC.
    fec_rx: HashMap<u32, FecDecoder>,
    /// RFC 8888 feedback was negotiated: it replaces transport-wide feedback.
    ccfb: bool,
    ccfb_rx: CcfbReceiver,
    ccfb_tx: CcfbSender,
    /// Answers the remote receivers' XR reference times.
    rrtr: RrtrResponder,
    /// The round-trip time from the last DLRR.
    xr_rtt: Option<Duration>,
    /// TMMBR state per sent SSRC.
    tmmbr: HashMap<u32, TmmbrState>,
    /// The NTP time of an instant: RTCP times follow the monotonic clock of the `now`
    /// arguments from there.
    ntp_anchor: (Instant, u64),
    /// The last REMB.
    remb: Option<u64>,
    /// The ICE pair the estimate was made on (a new one restarts it, ADR-050).
    probe_pair: Option<(SocketAddr, SocketAddr)>,
}

/// The TMMBR requests about one sent stream and its packet rate (for the overhead term).
#[derive(Debug)]
struct TmmbrState {
    handler: TmmbrHandler,
    bound: Option<u64>,
    packets: u64,
    at: Instant,
    pps: f64,
}

/// Sent SSRCs with TMMBR state.
const MAX_TMMBR_STREAMS: usize = 16;

#[derive(Debug, Default, Clone, Copy)]
struct Stats {
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
    fec_sent: u64,
    fec_received: u64,
    fec_recovered: u64,
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

/// mDNS candidates waiting for the resolver at once.
const MAX_MDNS_WANTED: usize = 32;

impl Rtc {
    /// A peer; `lite` runs an ICE-lite agent. Generates the DTLS certificate.
    pub(crate) fn new(cfg: ConfigInner, lite: bool, now: Instant) -> Result<Rtc, RtcErr> {
        let identity =
            Identity::generate_self_signed().map_err(|e| err(format!("certificate: {e}")))?;
        let mut ice_cfg = IceConfig::new(lite, false);
        ice_cfg.aggressive_nomination = cfg.ice_aggressive;
        ice_cfg.renomination = cfg.ice_renomination;
        let ice = IceAgent::new(ice_cfg, now);
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
            mdns_wanted: Vec::new(),
            fec_rx: HashMap::new(),
            ccfb: false,
            ccfb_rx: CcfbReceiver::new(),
            ccfb_tx: CcfbSender::new(),
            rrtr: RrtrResponder::new(),
            xr_rtt: None,
            tmmbr: HashMap::new(),
            remb: None,
            probe_pair: None,
            ntp_anchor: (now, only_rtp::ntp_time(SystemTime::now())),
            cfg,
        })
    }

    /// The 64-bit NTP time of `now`.
    fn ntp(&self, now: Instant) -> u64 {
        let (at, base) = self.ntp_anchor;
        let d = now.saturating_duration_since(at);
        let frac = (u128::from(d.subsec_nanos()) << 32) / 1_000_000_000;
        base.wrapping_add((d.as_secs() << 32) | frac as u64)
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

    /// Adds a remote candidate line (`candidate:...`): one whose address is an mDNS name is
    /// kept for the resolver ([`Rtc::take_mdns`]); `Err` for anything else that does not
    /// parse (FQDNs included).
    pub(crate) fn add_remote_candidate_line(
        &mut self,
        line: &str,
    ) -> Result<(), only_ice::ParseError> {
        let mut name = None;
        let r = IceCandidate::parse_resolved(line, |n| {
            name = Some(n.to_owned());
            None
        });
        match (r, name) {
            (Ok(c), _) => {
                self.ice.add_remote_candidate(c);
                Ok(())
            }
            (Err(only_ice::ParseError::Mdns), Some(n)) => {
                if self.mdns_wanted.len() < MAX_MDNS_WANTED {
                    self.mdns_wanted.push((n, line.to_owned()));
                }
                Ok(())
            }
            (Err(e), _) => Err(e),
        }
    }

    /// The mDNS candidates received since the last call, with the remote ufrag they belong
    /// to; `None` (and no allocation: this runs on every drive) when there are none.
    pub(crate) fn take_mdns(&mut self) -> Option<(Vec<(String, String)>, String)> {
        if self.mdns_wanted.is_empty() {
            return None;
        }
        let ufrag = self
            .ice
            .remote_credentials()
            .map(|c| c.ufrag.clone())
            .unwrap_or_default();
        Some((std::mem::take(&mut self.mdns_wanted), ufrag))
    }

    /// A resolved mDNS candidate, unless the remote restarted ICE since (`ufrag` is the
    /// remote ufrag when it arrived).
    pub(crate) fn add_resolved_candidate(&mut self, c: IceCandidate, ufrag: &str) {
        if self
            .ice
            .remote_credentials()
            .is_some_and(|r| r.ufrag == ufrag)
        {
            self.ice.add_remote_candidate(c);
        }
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
                    rids,
                } => {
                    let mid = if self.mid_free(&mid) {
                        mid
                    } else {
                        self.alloc_mid()
                    };
                    let mut line = MediaLine::new(mid, kind, dir, stream_id, track_id, &rids);
                    line.codecs = local_codecs(&self.cfg, kind);
                    if rids.is_empty() {
                        line.fec_pts = FecPts::local(&self.cfg, kind);
                    }
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
            line.fec_pts = if line.sim.is_empty() {
                FecPts::remote(&cfg, m, line.kind)
            } else {
                FecPts::default()
            };
            line.xr = remote_xr(&cfg, m, &line.codecs);
            line.ext = remote_extmap(m);
            line.negotiated = true;
            read_ssrcs(line, m);
            if !line.sim.is_empty() {
                // The encodings the answer receives; without `a=simulcast`, only the first.
                let accepted = simulcast_rids(m, "recv");
                for (i, e) in line.sim.iter_mut().enumerate() {
                    e.active = match &accepted {
                        Some(list) => list.contains(&e.rid),
                        None => i == 0,
                    };
                }
            }
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
                    let line = MediaLine::new(mid, kind, Direction::SendRecv, None, None, &[]);
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
            line.fec_pts = if line.sim.is_empty() {
                FecPts::remote(&cfg, m, kind)
            } else {
                FecPts::default()
            };
            line.xr = remote_xr(&cfg, m, &line.codecs);
            line.ext = remote_extmap(m);
            if cfg.ccfb
                && line
                    .codecs
                    .iter()
                    .any(|c| c.fb.iter().any(|f| f == FB_CCFB))
            {
                // The answer picks RFC 8888 over transport-wide feedback (as libwebrtc expects:
                // with both it keeps sending transport-wide feedback).
                for c in &mut line.codecs {
                    c.fb.retain(|f| f != "transport-cc");
                }
                line.ext.remove(Extension::TransportCc);
            }
            line.dir = if line.stopped || line.codecs.is_empty() {
                Direction::Inactive
            } else {
                line.want.intersect(remote_dir.reverse())
            };
            line.negotiated = true;
            read_ssrcs(line, m);
            // A simulcast sender: receive the RIDs it declares (`a=rid:<id> send`).
            line.recv_rids = simulcast_rids(m, "send")
                .unwrap_or_default()
                .into_iter()
                .filter(|r| {
                    m.all("rid")
                        .any(|v| v.split_whitespace().take(2).eq([r.as_str(), "send"]))
                })
                .collect();
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
        let renomination = get("ice-options")
            .is_some_and(|o| o.split_ascii_whitespace().any(|t| t == "renomination"));
        self.ice.set_remote_renomination(renomination);
        if sdp.has("ice-lite") {
            self.ice.set_remote_lite(true);
        } else if is_offer && !self.lite {
            self.ice.set_controlling(false);
        }
        let mut end = false;
        for m in &sdp.media {
            for c in m.all("candidate") {
                // Unusable lines (FQDNs, syntax) are skipped as browsers do.
                let _ = self.add_remote_candidate_line(&format!("candidate:{c}"));
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
        self.ccfb = self.cfg.ccfb
            && self
                .media
                .iter()
                .any(|l| !l.stopped && l.codecs.iter().any(|c| c.fb.iter().any(|f| f == FB_CCFB)));
        for l in &mut self.media {
            if l.fec_send_scheme().is_none() {
                l.fec_enc = None;
            }
        }
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
        attrs.push(Attr::kv(
            "ice-options",
            if self.cfg.ice_renomination {
                "trickle renomination"
            } else {
                "trickle"
            },
        ));
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
        // RFC 8888 is per section: libwebrtc wants it on every payload type (RTX, FEC too).
        let ccfb = l.codecs.iter().any(|c| c.fb.iter().any(|f| f == FB_CCFB));
        let ccfb_fb = |attrs: &mut Vec<Attr>, pt: u8| {
            if ccfb {
                attrs.push(Attr::kv("rtcp-fb", format!("{pt} {FB_CCFB}")));
            }
        };
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
                ccfb_fb(&mut attrs, r);
                attrs.push(Attr::kv("fmtp", format!("{r} apt={}", c.pt)));
            }
        }
        let f = l.fec_pts;
        if !l.codecs.is_empty() {
            if let Some(r) = f.red {
                fmts.push(r.to_string());
                attrs.push(Attr::kv("rtpmap", format!("{r} red/90000")));
                ccfb_fb(&mut attrs, r);
                if let Some(x) = f.red_rtx {
                    fmts.push(x.to_string());
                    attrs.push(Attr::kv("rtpmap", format!("{x} rtx/90000")));
                    ccfb_fb(&mut attrs, x);
                    attrs.push(Attr::kv("fmtp", format!("{x} apt={r}")));
                }
            }
            if let Some(u) = f.ulpfec {
                fmts.push(u.to_string());
                attrs.push(Attr::kv("rtpmap", format!("{u} ulpfec/90000")));
                ccfb_fb(&mut attrs, u);
            }
            if let Some(x) = f.flexfec {
                fmts.push(x.to_string());
                attrs.push(Attr::kv("rtpmap", format!("{x} flexfec-03/90000")));
                if l.codecs
                    .iter()
                    .any(|c| c.fb.iter().any(|f| f == "transport-cc"))
                {
                    attrs.push(Attr::kv("rtcp-fb", format!("{x} transport-cc")));
                }
                ccfb_fb(&mut attrs, x);
                attrs.push(Attr::kv("fmtp", format!("{x} repair-window=10000000")));
            }
            if self.cfg.xr && (offer || l.xr) {
                attrs.push(Attr::kv("rtcp-xr", "rcvr-rtt=all"));
            }
        }
        if dir.sends() && !l.sim.is_empty() {
            // RFC 8853: the encodings by RID (no SSRCs are signaled, as browsers do).
            let rids: Vec<&str> = l
                .sim
                .iter()
                .filter(|e| offer || e.active)
                .map(|e| e.rid.as_str())
                .collect();
            for r in &rids {
                attrs.push(Attr::kv("rid", format!("{r} send")));
            }
            attrs.push(Attr::kv("simulcast", format!("send {}", rids.join(";"))));
        } else if dir.sends() {
            let ssrc = l.send.ssrc();
            let rtx = l
                .send
                .rtx_ssrc()
                .filter(|_| l.codecs.iter().any(|c| c.rtx.is_some()));
            if let Some(rtx) = rtx {
                attrs.push(Attr::kv("ssrc-group", format!("FID {ssrc} {rtx}")));
            }
            let fec = f.flexfec.map(|_| l.fec_send.ssrc());
            if let Some(fec) = fec {
                attrs.push(Attr::kv("ssrc-group", format!("FEC-FR {ssrc} {fec}")));
            }
            let mut ssrcs = vec![ssrc];
            ssrcs.extend(rtx);
            ssrcs.extend(fec);
            for s in ssrcs {
                attrs.push(Attr::kv("ssrc", format!("{s} cname:{}", self.cname)));
                attrs.push(Attr::kv(
                    "ssrc",
                    format!("{s} msid:{} {}", l.stream_id, l.track_id),
                ));
            }
        }
        if !offer && dir.receives() && !l.recv_rids.is_empty() {
            for r in &l.recv_rids {
                attrs.push(Attr::kv("rid", format!("{r} recv")));
            }
            attrs.push(Attr::kv(
                "simulcast",
                format!("recv {}", l.recv_rids.join(";")),
            ));
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

    /// Packetizes and sends one sample, on simulcast encoding `rid` of a simulcast line.
    /// `Ok(false)`: no such sending line or encoding. On a simulcast line `rid` `None` is the
    /// first encoding; an encoding the answer did not accept drops the sample.
    pub(crate) fn write_media(
        &mut self,
        now: Instant,
        mid: Mid,
        rid: Option<&str>,
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
        let enc = match (line.sim.is_empty(), rid) {
            (true, None) => None,
            (true, Some(_)) => return Ok(false),
            (false, None) => Some(0),
            (false, Some(r)) => match line.sim.iter().position(|e| e.rid == r) {
                Some(i) => Some(i),
                None => return Ok(false),
            },
        };
        let Some(codec) = line.codec(pt.get()).cloned() else {
            return Err(err(format!(
                "payload type {} not negotiated on {mid}",
                pt.get()
            )));
        };
        if enc.is_some_and(|i| !line.sim[i].active) {
            return Ok(true); // not accepted by the answer: dropped
        }
        let (true, Some((src, dest))) = (self.srtp_tx.is_some(), self.ice.send_pair()) else {
            return Ok(true); // not connected yet: dropped
        };
        let ts = time.ticks_at(codec.clock) as u32;
        let has_mid = line.ext.id_of(Extension::Mid).is_some();
        let has_rid = line.ext.id_of(Extension::RtpStreamId).is_some();
        let has_twcc = line.ext.id_of(Extension::TransportCc).is_some();
        let has_ast = line.ext.id_of(Extension::AbsSendTime).is_some();
        // FEC: ULPFEC wraps every packet in RED; FlexFEC goes on its own stream.
        let scheme = if enc.is_none() {
            line.fec_send_scheme()
        } else {
            None
        };
        let fp = line.fec_pts;
        let red = (scheme == Some(FecScheme::Ulpfec))
            .then_some(fp.red.zip(fp.ulpfec))
            .flatten();
        if scheme.is_some() && line.fec_enc.is_none() {
            let rate = fec_rate(&self.cfg, line.fec_loss.unwrap_or(0.0));
            line.fec_enc = scheme.map(|sc| FecEncoder::new(sc, line.send.ssrc(), rate));
        }
        line.last_pt = Some(red.map_or(codec.pt, |(r, _)| r));
        let MediaLine {
            ext: map,
            send,
            packetizers,
            sim,
            fec_send,
            fec_enc,
            ..
        } = line;
        let (send, packetizers, rid) = match enc {
            Some(i) => {
                let e = &mut sim[i];
                (&mut e.send, &mut e.packetizers, Some(e.rid.as_str()))
            }
            None => (send, packetizers, None),
        };
        let pk = packetizers
            .entry(codec.pt)
            .or_insert_with(|| only_rtp::codec::packetizer(codec.codec.rtp()));
        let payloads = pk.packetize(RTP_PAYLOAD_MTU, data);
        let twcc = &mut self.twcc_tx;
        let mut ext_of = |rid: Option<&str>| {
            let mut ext = ExtensionValues::default();
            if has_mid {
                ext.mid = Some(mid.as_str().to_owned());
            }
            if has_rid {
                ext.rid = rid.map(str::to_owned);
            }
            if has_ast {
                ext.abs_send_time = Some(abs_send_time_now());
            }
            ext.transport_cc = has_twcc.then(|| twcc.next_seq());
            ext
        };
        // (packet, transport-wide sequence number, is FEC)
        let mut out: Vec<(Vec<u8>, Option<u16>, bool)> = Vec::with_capacity(payloads.len() + 1);
        for (p, marker) in payloads {
            let ext = ext_of(rid);
            let tw = ext.transport_cc;
            let raw = match red {
                Some((red_pt, _)) => {
                    let mut q = Vec::with_capacity(1 + p.len());
                    q.push(codec.pt);
                    q.extend_from_slice(&p);
                    send.write(now, red_pt, marker, ts, &q, &ext, map)
                }
                None => send.write(now, codec.pt, marker, ts, &p, &ext, map),
            };
            let fec = match fec_enc.as_mut() {
                Some(fe) => {
                    let plain = match red {
                        Some(_) => only_rtp::fec::red::unwrap_primary(&raw),
                        None => Some(raw.clone()),
                    };
                    plain.map_or_else(Vec::new, |pl| fe.push(&pl, marker))
                }
                None => Vec::new(),
            };
            out.push((raw, tw, false));
            for f in fec {
                let ext = ext_of(None);
                let tw = ext.transport_cc;
                let raw = match (red, fp.flexfec) {
                    (Some((red_pt, ulp_pt)), _) => {
                        let mut q = Vec::with_capacity(1 + f.len());
                        q.push(ulp_pt);
                        q.extend_from_slice(&f);
                        send.write(now, red_pt, false, ts, &q, &ext, map)
                    }
                    (None, Some(flex_pt)) => fec_send.write(now, flex_pt, false, ts, &f, &ext, map),
                    (None, None) => continue,
                };
                out.push((raw, tw, true));
            }
        }
        for (raw, tw, fec) in out {
            if let Some(s) = tw {
                self.twcc_tx.on_sent(s, now, raw.len());
            }
            self.note_sent(now, &raw);
            if fec {
                self.stats.fec_sent += 1;
            }
            let Some(tx) = self.srtp_tx.as_mut() else {
                break;
            };
            if let Ok(o) = tx.protect_rtp(&raw) {
                self.stats.bytes_sent += o.len() as u64;
                self.stats.packets_sent += 1;
                self.transmits.push_back((src, dest, o));
            }
        }
        if self.next_rtcp.is_none() {
            self.next_rtcp = Some(now + Duration::from_millis(100));
        }
        self.send_probes(now);
        Ok(true)
    }

    /// Asks the remote sender of `mid` for a keyframe. `false`: no such line.
    pub(crate) fn request_keyframe(&mut self, mid: Mid, kind: KeyframeRequestKind) -> bool {
        self.request_keyframe_of(mid, None, kind)
    }

    /// A keyframe request for the streams of `mid`, or with `rid` only for the simulcast
    /// encoding `rid` (`false` if no stream of that RID has arrived yet).
    pub(crate) fn request_keyframe_of(
        &mut self,
        mid: Mid,
        rid: Option<&str>,
        kind: KeyframeRequestKind,
    ) -> bool {
        let Some(idx) = self.media.iter().position(|l| l.mid == mid) else {
            return false;
        };
        let mut targets: Vec<u32> = self
            .recv
            .iter()
            .filter(|(s, r)| {
                r.line == idx
                    && self.routes.get(s).is_none_or(|x| x.repairs.is_none())
                    && rid.is_none_or(|w| r.rid.as_deref() == Some(w))
            })
            .map(|(s, _)| *s)
            .collect();
        if rid.is_some() && targets.is_empty() {
            return false;
        }
        if targets.is_empty() {
            targets = self.media[idx].remote_ssrcs.clone();
            let l = &self.media[idx];
            targets.retain(|s| !l.remote_rtx.contains_key(s) && !l.remote_fec.contains_key(s));
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
        self.send_probes(now);
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
        if self.ccfb {
            self.ccfb_rx.on_received(h.ssrc, h.sequence_number, now, 0);
        } else if let Some(seq) = h.ext.transport_cc {
            self.twcc_rx.on_received(seq, now);
            self.twcc_media_ssrc = h.ssrc;
        }
        let Some(route) = self.route(&h) else {
            return;
        };
        let fp = self.media[route.line].fec_pts;
        if fp.flexfec == Some(h.payload_type) {
            // A FlexFEC packet: the protected SSRC is in its header (flexfec-03).
            self.stats.fec_received += 1;
            let payload = h.payload(&pkt);
            let Some(protected) =
                only_rtp::fec::FecHeader::parse(FecScheme::Flexfec03, payload).and_then(|f| f.ssrc)
            else {
                return;
            };
            let rec = match self.fec_decoder(route.line, protected) {
                Some(d) => d.on_fec(payload),
                None => return,
            };
            self.deliver_recovered(now, route.line, rec);
            return;
        }
        if route.repairs.is_none() && fp.red.is_some() && fp.red == Some(h.payload_type) {
            let Some(inner) = only_rtp::fec::red::unwrap_primary(&pkt) else {
                return;
            };
            let Some(ih) = RtpHeader::parse(&inner, &self.ext) else {
                return;
            };
            if fp.ulpfec == Some(ih.payload_type) {
                // ULPFEC in RED: it takes a sequence number of the media stream.
                self.stats.fec_received += 1;
                self.fec_seq(now, route.line, h.ssrc, h.sequence_number, h.timestamp);
                let rec = match self.fec_decoder(route.line, h.ssrc) {
                    Some(d) => d.on_fec(ih.payload(&inner)),
                    None => return,
                };
                self.deliver_recovered(now, route.line, rec);
                return;
            }
            self.media_packet(now, route, &inner, &ih);
            return;
        }
        self.media_packet(now, route, &pkt, &h);
    }

    /// The FEC decoder of the received media stream `ssrc` on line `line`, made when FEC
    /// receiving is negotiated there.
    fn fec_decoder(&mut self, line: usize, ssrc: u32) -> Option<&mut FecDecoder> {
        let scheme = self.media.get(line)?.fec_pts.receive_scheme()?;
        if !self.fec_rx.contains_key(&ssrc) && self.fec_rx.len() >= MAX_FEC_DECODERS {
            return None;
        }
        Some(
            self.fec_rx
                .entry(ssrc)
                .or_insert_with(|| FecDecoder::new(scheme, ssrc)),
        )
    }

    /// A media packet (`pkt`, RED removed) or an RTX packet of a media stream.
    fn media_packet(&mut self, now: Instant, route: Route, pkt: &[u8], h: &RtpHeader) {
        let mut payload = h.payload(pkt);
        let (ssrc, seq, pt) = match route.repairs {
            Some(main) => {
                let line = &self.media[route.line];
                let fp = line.fec_pts;
                let Some(orig) = line
                    .rtx_of(h.payload_type)
                    .map(|c| c.pt)
                    .or_else(|| fp.red.filter(|_| fp.red_rtx == Some(h.payload_type)))
                else {
                    return;
                };
                if payload.len() < 2 {
                    return; // padding-only probe
                }
                let osn = u16::from_be_bytes([payload[0], payload[1]]);
                payload = &payload[2..];
                if fp.red == Some(orig) {
                    // A retransmitted RED packet: its primary block.
                    let Some(b) =
                        only_rtp::fec::red::parse(payload).and_then(|b| b.last().copied())
                    else {
                        return;
                    };
                    if fp.ulpfec == Some(b.pt) {
                        self.fec_seq(now, route.line, main, osn, h.timestamp);
                        return;
                    }
                    payload = b.data;
                    (main, osn, b.pt)
                } else {
                    (main, osn, orig)
                }
            }
            None => {
                let rec = if self.media[route.line].fec_pts.receive_scheme().is_some() {
                    match self.fec_decoder(route.line, h.ssrc) {
                        Some(d) => d.on_media(pkt),
                        None => Vec::new(),
                    }
                } else {
                    Vec::new()
                };
                let p = Pkt {
                    ssrc: h.ssrc,
                    seq: h.sequence_number,
                    pt: h.payload_type,
                    ts: h.timestamp,
                    marker: h.marker,
                    rid: h.ext.rid.as_deref(),
                };
                self.deliver(now, route.line, &p, payload, false);
                self.deliver_recovered(now, route.line, rec);
                return;
            }
        };
        let p = Pkt {
            ssrc,
            seq,
            pt,
            ts: h.timestamp,
            marker: h.marker,
            rid: h.ext.rid.as_deref(),
        };
        self.deliver(now, route.line, &p, payload, false);
    }

    /// Media packets rebuilt by FEC.
    fn deliver_recovered(&mut self, now: Instant, line: usize, rec: Vec<Vec<u8>>) {
        for r in rec {
            let Some(h) = RtpHeader::parse(&r, &self.ext) else {
                continue;
            };
            self.stats.fec_recovered += 1;
            let p = Pkt {
                ssrc: h.ssrc,
                seq: h.sequence_number,
                pt: h.payload_type,
                ts: h.timestamp,
                marker: h.marker,
                rid: h.ext.rid.as_deref(),
            };
            self.deliver(now, line, &p, h.payload(&r), true);
        }
    }

    /// A ULPFEC packet took sequence number `seq` of the media stream `ssrc`: it is not
    /// missing.
    fn fec_seq(&mut self, now: Instant, line: usize, ssrc: u32, seq: u16, ts: u32) {
        if let Some(r) = recv_entry(&mut self.recv, &self.media, line, ssrc, 90_000) {
            if let (Some(e), Some((_, a))) = (r.stream.receive(now, seq, ts), r.assembler.as_mut())
            {
                a.skip(e);
                // The number may have been the last thing the frames after it waited for
                // (a repaired FEC packet arriving after them): emit them now, not with the
                // next media packet, which may never come.
                self.pop_frames(line, ssrc);
            }
        }
    }

    /// Emits the frames the assembler of the received stream `ssrc` (on `line`) has complete.
    fn pop_frames(&mut self, line: usize, ssrc: u32) {
        let Some(l) = self.media.get(line) else {
            return;
        };
        let mid = l.mid;
        let Some(recv) = self.recv.get_mut(&ssrc) else {
            return;
        };
        let rid = recv.rid.clone();
        let Some((pt, asm)) = recv.assembler.as_mut() else {
            return;
        };
        let Some(codec) = l.codec(*pt) else {
            return;
        };
        while let Some(f) = asm.pop() {
            self.events.push_back(RtcEvent::MediaData(MediaData {
                mid,
                pt: Pt::from(*pt),
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

    /// One media packet into its receive stream and on to the application.
    fn deliver(
        &mut self,
        now: Instant,
        line_idx: usize,
        p: &Pkt<'_>,
        payload: &[u8],
        recovered: bool,
    ) {
        if payload.is_empty() {
            // Padding only: not a gap in the media stream.
            if !recovered && self.recv.contains_key(&p.ssrc) {
                self.fec_seq(now, line_idx, p.ssrc, p.seq, p.ts);
            }
            return;
        }
        let Some(codec) = self.media[line_idx].codec(p.pt).cloned() else {
            return;
        };
        let reorder = if codec.codec.kind() == MediaKind::Audio {
            self.cfg.reorder_audio
        } else {
            self.cfg.reorder_video
        };
        let rtp_mode = self.cfg.rtp_mode;
        let Some(recv) = recv_entry(&mut self.recv, &self.media, line_idx, p.ssrc, codec.clock)
        else {
            return;
        };
        if recv.rid.is_none() {
            recv.rid = p.rid.map(str::to_owned);
        }
        let got = if recovered {
            recv.stream.receive_recovered(now, p.seq)
        } else {
            recv.stream.receive(now, p.seq, p.ts)
        };
        let Some(ext_seq) = got else {
            return;
        };
        let (ssrc, pt) = (p.ssrc, p.pt);
        if rtp_mode {
            self.events.push_back(RtcEvent::Rtp(RtpPacket {
                seq_no: ext_seq,
                ssrc,
                pt: Pt::from(pt),
                marker: p.marker,
                rtp_time: p.ts,
                time: MediaTime::new(
                    u64::from(p.ts),
                    Frequency::new(codec.clock).unwrap_or(Frequency::NINETY_KHZ),
                ),
                received: now,
                payload: Arc::from(payload),
            }));
            return;
        }
        if recv.assembler.as_ref().is_none_or(|(x, _)| *x != pt) {
            recv.assembler = Some((pt, FrameAssembler::new(codec.codec.rtp(), reorder)));
        }
        let Some((_, asm)) = recv.assembler.as_mut() else {
            return;
        };
        asm.push(ext_seq, p.ts, p.marker, payload, now);
        self.pop_frames(line_idx, ssrc);
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
                        .filter(|(_, l)| !l.stopped && l.knows_pt(h.payload_type))
                        .map(|(i, _)| i)
                        .collect();
                    (c.len() == 1).then(|| c[0])
                })?;
            let l = &self.media[line];
            let repairs = if l.is_rtx(h.payload_type) {
                // Unsignalled RTX: repairs the stream of its repaired RID (simulcast), else the
                // line's (first) media stream.
                let by_rid = h.ext.rrid.as_deref().and_then(|rr| {
                    self.recv
                        .iter()
                        .find(|(s, r)| {
                            r.line == line
                                && r.rid.as_deref() == Some(rr)
                                && self.routes.get(s).is_some_and(|x| x.repairs.is_none())
                        })
                        .map(|(s, _)| *s)
                });
                let main = match by_rid {
                    Some(m) => m,
                    None => self
                        .routes
                        .iter()
                        .find(|(_, r)| r.line == line && r.repairs.is_none())
                        .map(|(s, _)| *s)?,
                };
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
        let ntp = self.ntp(now);
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
                    // With RFC 8888 negotiated its feedback drives the estimator.
                    if !self.ccfb {
                        if let Some(b) = self.bwe.as_mut() {
                            b.on_packet_results(now, &res);
                        }
                        self.bwe_event();
                    }
                }
                Rtcp::CongestionControl(fb) => {
                    let res = self.ccfb_tx.on_feedback(now, &fb);
                    if self.ccfb {
                        if let Some(b) = self.bwe.as_mut() {
                            b.on_packet_results(now, &res);
                        }
                        self.bwe_event();
                    }
                }
                Rtcp::Remb { bitrate, .. } => {
                    self.remb = (bitrate > 0).then_some(bitrate);
                    self.apply_remote_caps();
                }
                Rtcp::Tmmbr {
                    sender_ssrc,
                    entries,
                } => self.handle_tmmbr(now, sender_ssrc, &entries),
                Rtcp::Tmmbn {
                    sender_ssrc,
                    entries,
                } => {
                    self.events
                        .push_back(RtcEvent::Other(Other::MaxBitrateNotification {
                            ssrc: sender_ssrc,
                            entries: entries.iter().map(|e| (e.ssrc, e.bitrate)).collect(),
                        }));
                }
                Rtcp::ExtendedReport { ssrc, blocks } => self.handle_xr(now, ntp, ssrc, &blocks),
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
            let found = self
                .media
                .iter()
                .enumerate()
                .find_map(|(i, l)| l.send_of(b.ssrc).map(|e| (i, e)));
            if let Some((li, enc)) = found {
                let l = &mut self.media[li];
                l.send_mut(enc).handle_report_block(now, ntp, b);
                if enc.is_none() && l.send.packets_sent() > l.fec_prev.0 {
                    // The FEC rate follows the loss before repair: what the receiver reports,
                    // or (NACK repairs losses before the report) the share of packets it
                    // asked to have retransmitted since the previous report; smoothed. Reports
                    // without anything sent since leave it alone.
                    let (sent, resent) = (l.send.packets_sent(), l.send.packets_resent());
                    let (ps, pr) = l.fec_prev;
                    l.fec_prev = (sent, resent);
                    let nacked = (resent.saturating_sub(pr) as f64 / (sent - ps) as f64).min(1.0);
                    let loss = (f64::from(b.fraction_lost) / 256.0).max(nacked);
                    let s = l.fec_loss.map_or(loss, |x| 0.5 * x + 0.5 * loss);
                    l.fec_loss = Some(s);
                    if let Some(e) = l.fec_enc.as_mut() {
                        e.set_rate(fec_rate(&self.cfg, s));
                    }
                }
                if let Some(rtt) = l.rtt() {
                    for r in self.recv.values_mut() {
                        r.stream.set_rtt(rtt);
                    }
                }
            }
        }
    }

    fn keyframe_request(&mut self, media_ssrc: u32, kind: KeyframeRequestKind) {
        let found = self
            .media
            .iter()
            .find_map(|l| l.send_of(media_ssrc).map(|e| (l, e)));
        if let Some((l, enc)) = found {
            self.events.push_back(RtcEvent::Keyframe(KeyframeRequest {
                mid: l.mid,
                rid: enc.map(|i| l.sim[i].rid.clone()),
                kind,
            }));
        }
    }

    fn resend(&mut self, now: Instant, media_ssrc: u32, lost: &[u16]) {
        let Some((line, enc)) = self
            .media
            .iter_mut()
            .find_map(|l| l.send_of(media_ssrc).map(|e| (l, e)))
        else {
            return;
        };
        let (Some(tx), Some((src, dest))) = (self.srtp_tx.as_mut(), self.ice.send_pair()) else {
            return;
        };
        let rtx_pt = match line.last_pt {
            Some(p) if line.fec_pts.red == Some(p) => line.fec_pts.red_rtx,
            p => p.and_then(|p| line.codec(p)).and_then(|c| c.rtx),
        };
        let twcc = &mut self.twcc_tx;
        let has_twcc = line.ext.id_of(Extension::TransportCc).is_some();
        let has_rrid = line.ext.id_of(Extension::RepairedRtpStreamId).is_some();
        let mut seqs = Vec::new();
        let map = line.ext.clone();
        let pkts = line
            .send_mut(enc)
            .resend_with(now, lost, rtx_pt, &map, |e| {
                if has_twcc {
                    let s = twcc.next_seq();
                    e.transport_cc = Some(s);
                    seqs.push(s);
                }
                // An RTX stream names the encoding it repairs (RFC 8852).
                if rtx_pt.is_some() {
                    let rid = e.rid.take();
                    if has_rrid {
                        e.rrid = rid;
                    }
                }
            });
        for (i, raw) in pkts.iter().enumerate() {
            if let Some(s) = seqs.get(i) {
                twcc.on_sent(*s, now, raw.len());
            }
            if let Ok(out) = tx.protect_rtp(raw) {
                self.stats.bytes_sent += out.len() as u64;
                self.transmits.push_back((src, dest, out));
            }
        }
        for raw in &pkts {
            self.note_sent(now, raw);
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
        // Congestion control feedback: RFC 8888 when negotiated, else transport-wide.
        let sender = self.media.first().map_or(1, |l| l.send.ssrc());
        if self.ccfb {
            let ntp = self.ntp(now);
            while let Some(fb) = self.ccfb_rx.poll_feedback(now, ntp, sender) {
                out.push(fb);
                if out.len() > 32 {
                    break;
                }
            }
        } else {
            while let Some(fb) = self
                .twcc_rx
                .poll_feedback(now, sender, self.twcc_media_ssrc)
            {
                out.push(fb);
                if out.len() > 32 {
                    break;
                }
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
                let rtt = self.media.iter().find_map(MediaLine::rtt);
                self.events.push_back(RtcEvent::Other(Other::PeerStats {
                    bytes_sent: self.stats.bytes_sent,
                    bytes_received: self.stats.bytes_received,
                    packets_sent: self.stats.packets_sent,
                    packets_received: self.stats.packets_received,
                    rtt_ms: rtt.map(|r| r.as_millis() as u64),
                    xr_rtt_ms: self.xr_rtt.map(|r| r.as_millis() as u64),
                    fec_sent: self.stats.fec_sent,
                    fec_received: self.stats.fec_received,
                    fec_recovered: self.stats.fec_recovered,
                    ccfb: self.ccfb,
                }));
            }
        }
    }

    fn send_reports(&mut self, now: Instant) {
        let ntp = self.ntp(now);
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
            let receiving = !blocks.is_empty();
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
                None if l.sim.is_empty() => continue,
                None => {}
            }
            let mut sdes = vec![(ssrc, vec![(1, self.cname.clone())])];
            // One SR per simulcast encoding that sent something.
            for e in &l.sim {
                if let Some(info) = e.send.sender_report(now, ntp) {
                    let s = e.send.ssrc();
                    pkts.push(Rtcp::SenderReport {
                        ssrc: s,
                        info,
                        reports: Vec::new(),
                    });
                    sdes.push((s, vec![(1, self.cname.clone())]));
                }
            }
            if pkts.is_empty() {
                continue;
            }
            pkts.push(Rtcp::SourceDescription(sdes));
            if l.xr && receiving {
                // RFC 3611 §4.4: lets the sender's DLRR give this receiver the RTT.
                pkts.push(Rtcp::ExtendedReport {
                    ssrc,
                    blocks: vec![only_rtp::XrBlock::ReceiverReferenceTime { ntp }],
                });
            }
            if let Some(b) = l.tmmbr_req {
                if let Some(t) = feedback::tmmbr_request(l, i, &self.recv, &self.routes, b) {
                    pkts.push(t);
                }
            }
            compounds.push(pkts);
        }
        if let Some(dlrr) = self.rrtr.dlrr(now) {
            let ssrc = self.media.first().map_or(1, |l| l.send.ssrc());
            let xr = Rtcp::ExtendedReport {
                ssrc,
                blocks: vec![dlrr],
            };
            match compounds.first_mut() {
                Some(c) => c.push(xr),
                None => compounds.push(vec![
                    Rtcp::ReceiverReport {
                        ssrc,
                        reports: Vec::new(),
                    },
                    xr,
                ]),
            }
        }
        for c in compounds {
            self.send_rtcp(&c);
        }
        self.refresh_tmmbr(now);
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
                        self.on_selected_pair(now, local, remote);
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
            min(self
                .bwe
                .as_ref()
                .and_then(BandwidthEstimator::probe_timeout));
            for r in self.recv.values() {
                min(r.stream.poll_timeout());
            }
            if self.ccfb && !self.recv.is_empty() {
                min(Some(now + only_rtp::CCFB_FEEDBACK_INTERVAL));
            } else if self.ext.id_of(Extension::TransportCc).is_some() && !self.recv.is_empty() {
                min(Some(now + only_rtp::TWCC_FEEDBACK_INTERVAL));
            }
        }
        Output::Timeout(t.max(now))
    }
}

/// The fields of a received media packet that [`Rtc::deliver`] needs.
struct Pkt<'a> {
    ssrc: u32,
    seq: u16,
    pt: u8,
    ts: u32,
    marker: bool,
    rid: Option<&'a str>,
}

/// The receive stream of `ssrc` on `line`, made on first use (`None`: too many streams).
fn recv_entry<'a>(
    recv: &'a mut HashMap<u32, Recv>,
    media: &[MediaLine],
    line: usize,
    ssrc: u32,
    clock: u32,
) -> Option<&'a mut Recv> {
    if recv.len() >= MAX_RECV_STREAMS && !recv.contains_key(&ssrc) {
        return None;
    }
    let nack = media
        .get(line)?
        .codecs
        .iter()
        .any(|c| c.fb.iter().any(|f| f == "nack"));
    Some(recv.entry(ssrc).or_insert_with(|| Recv {
        line,
        stream: RecvStream::new(ssrc, clock, nack),
        assembler: None,
        rid: None,
    }))
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
    line.remote_fec.clear();
    for v in m.all("ssrc-group") {
        let mut f = v.split_whitespace();
        let kind = f.next();
        let a = f.next().and_then(|x| x.parse::<u32>().ok());
        let b = f.next().and_then(|x| x.parse::<u32>().ok());
        if let (Some(a), Some(b)) = (a, b) {
            match kind {
                Some("FID") => {
                    line.remote_rtx.insert(b, a);
                }
                Some("FEC-FR") if line.remote_fec.len() < 32 => {
                    line.remote_fec.insert(b, a);
                }
                _ => {}
            }
        }
    }
    line.remote_ssrcs = ssrcs;
}

/// Whether a remote media section asks for XR receiver reference times (`a=rtcp-xr` with
/// `rcvr-rtt`, RFC 3611 §5.1, or libwebrtc's `rrtr` feedback) and we offer them.
fn remote_xr(cfg: &ConfigInner, m: &Media, codecs: &[CodecParams]) -> bool {
    cfg.xr
        && (m.all("rtcp-xr").any(|v| v.contains("rcvr-rtt"))
            || codecs.iter().any(|c| c.fb.iter().any(|f| f == FB_RRTR)))
}

fn abs_send_time_now() -> u32 {
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    only_rtp::abs_send_time(d)
}

mod feedback;
mod pacing;
#[cfg(test)]
mod tests;
