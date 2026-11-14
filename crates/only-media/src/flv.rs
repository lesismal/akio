//! FLV (Adobe "Video File Format Specification" 10.1) with the Enhanced RTMP extensions to its
//! tags (FourCC `hvc1` / `avc1` video, `Opus` / `mp4a` audio), which RTMP carries as messages
//! and HTTP-FLV / WS-FLV as a file that never ends.
//!
//! * Tag bodies: [`parse_video`] and [`parse_audio`] read the legacy and the enhanced headers
//!   (H.264 codec id 7, H.265 as codec id 12 the way Chinese ffmpeg forks write it, or `hvc1`;
//!   AAC, MP3, G.711, `Opus`).
//! * Streams: [`Encoder`] turns tracks and packets into tag bodies (onMetaData, a sequence
//!   header per track, a body per packet); [`Decoder`] does the reverse, holding packets back
//!   until it knows the stream's tracks.
//! * Files: [`write_header`] / [`write_tag`] frame tags into an FLV file and [`Demuxer`] splits
//!   bytes fed in pieces of any size back into tags.

use std::fmt;

use crate::{
    amf::{self, Value},
    av::{Codec, MILLISECOND, Packet, Time, Track, Tracks},
    codec::{h264, h265, opus},
};

/// Tag type of audio.
pub const TAG_AUDIO: u8 = 8;
/// Tag type of video.
pub const TAG_VIDEO: u8 = 9;
/// Tag type of script data (onMetaData).
pub const TAG_SCRIPT: u8 = 18;

/// Malformed FLV data.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FlvError {
    /// A tag body or the file header ended early.
    Short,
    /// Not an FLV file.
    Signature,
    /// A tag larger than the demuxer's limit.
    TooLarge,
    /// Script data that does not parse.
    Script(amf::AmfError),
}

impl fmt::Display for FlvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlvError::Short => f.write_str("FLV data too short"),
            FlvError::Signature => f.write_str("not an FLV file"),
            FlvError::TooLarge => f.write_str("FLV tag too large"),
            FlvError::Script(e) => write!(f, "FLV script data: {e}"),
        }
    }
}

impl std::error::Error for FlvError {}

/// What a video or audio tag body carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PacketType {
    /// The codec configuration (AVC/HEVC record, AudioSpecificConfig, OpusHead).
    SequenceHeader,
    /// Coded frames.
    Coded,
    /// End of sequence.
    End,
    /// Anything else (metadata, multitrack, unknown codecs): skipped.
    Other,
}

/// A parsed video tag body.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VideoTag<'a> {
    /// The codec (`Unknown` for codecs the stack does not handle).
    pub codec: Codec,
    /// A keyframe.
    pub keyframe: bool,
    /// What the body carries.
    pub packet_type: PacketType,
    /// Composition time offset in milliseconds.
    pub cts: i32,
    /// The payload: configuration record or AVCC frame.
    pub data: &'a [u8],
}

/// A parsed audio tag body.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AudioTag<'a> {
    /// The codec.
    pub codec: Codec,
    /// What the body carries.
    pub packet_type: PacketType,
    /// Sample rate from the legacy header (AAC's real rate is in its config).
    pub sample_rate: u32,
    /// Channels from the legacy header.
    pub channels: u8,
    /// The payload.
    pub data: &'a [u8],
}

fn fourcc_video(f: &[u8]) -> Codec {
    match f {
        b"avc1" => Codec::H264,
        b"hvc1" => Codec::H265,
        _ => Codec::Unknown,
    }
}

fn cts24(b: &[u8]) -> i32 {
    let v = (i32::from(b[0]) << 16) | (i32::from(b[1]) << 8) | i32::from(b[2]);
    (v << 8) >> 8
}

/// Parses a video tag body.
pub fn parse_video(b: &[u8]) -> Result<VideoTag<'_>, FlvError> {
    let h = *b.first().ok_or(FlvError::Short)?;
    let frame_type = (h >> 4) & 7;
    if h & 0x80 != 0 {
        // Enhanced RTMP: IsExHeader | FrameType(3) | PacketType(4), FourCC.
        let pt = h & 0x0f;
        let four = b.get(1..5).ok_or(FlvError::Short)?;
        let codec = fourcc_video(four);
        let (packet_type, cts, data) = match pt {
            0 => (PacketType::SequenceHeader, 0, &b[5..]),
            1 => {
                let c = b.get(5..8).ok_or(FlvError::Short)?;
                let cts = if codec == Codec::H264 || codec == Codec::H265 {
                    cts24(c)
                } else {
                    0
                };
                (PacketType::Coded, cts, &b[8..])
            }
            2 => (PacketType::End, 0, &b[5..]),
            3 => (PacketType::Coded, 0, &b[5..]),
            _ => (PacketType::Other, 0, &b[5..]),
        };
        return Ok(VideoTag {
            codec,
            keyframe: frame_type == 1,
            packet_type,
            cts,
            data,
        });
    }
    let codec = match h & 0x0f {
        7 => Codec::H264,
        12 => Codec::H265,
        _ => Codec::Unknown,
    };
    if codec == Codec::Unknown {
        return Ok(VideoTag {
            codec,
            keyframe: frame_type == 1,
            packet_type: PacketType::Other,
            cts: 0,
            data: &b[1..],
        });
    }
    let hdr = b.get(1..5).ok_or(FlvError::Short)?;
    let packet_type = match hdr[0] {
        0 => PacketType::SequenceHeader,
        1 => PacketType::Coded,
        2 => PacketType::End,
        _ => PacketType::Other,
    };
    Ok(VideoTag {
        codec,
        keyframe: frame_type == 1,
        packet_type,
        cts: cts24(&hdr[1..4]),
        data: &b[5..],
    })
}

/// Parses an audio tag body.
pub fn parse_audio(b: &[u8]) -> Result<AudioTag<'_>, FlvError> {
    let h = *b.first().ok_or(FlvError::Short)?;
    let format = h >> 4;
    if format == 9 {
        // Enhanced RTMP: SoundFormat 9 | AudioPacketType(4), FourCC.
        let four = b.get(1..5).ok_or(FlvError::Short)?;
        let codec = match four {
            b"Opus" => Codec::Opus,
            b"mp4a" => Codec::Aac,
            b".mp3" => Codec::Mp3,
            _ => Codec::Unknown,
        };
        let packet_type = match h & 0x0f {
            0 => PacketType::SequenceHeader,
            1 => PacketType::Coded,
            2 => PacketType::End,
            _ => PacketType::Other,
        };
        return Ok(AudioTag {
            codec,
            packet_type,
            sample_rate: 48_000,
            channels: 2,
            data: &b[5..],
        });
    }
    let rate = [5512, 11025, 22050, 44100][usize::from((h >> 2) & 3)];
    let channels = if h & 1 == 1 { 2 } else { 1 };
    let (codec, sample_rate) = match format {
        10 => (Codec::Aac, rate),
        2 => (Codec::Mp3, rate),
        7 => (Codec::Pcma, 8000),
        8 => (Codec::Pcmu, 8000),
        _ => (Codec::Unknown, rate),
    };
    if codec == Codec::Aac {
        let t = *b.get(1).ok_or(FlvError::Short)?;
        return Ok(AudioTag {
            codec,
            packet_type: if t == 0 {
                PacketType::SequenceHeader
            } else {
                PacketType::Coded
            },
            sample_rate,
            channels,
            data: &b[2..],
        });
    }
    Ok(AudioTag {
        codec,
        packet_type: if codec == Codec::Unknown {
            PacketType::Other
        } else {
            PacketType::Coded
        },
        sample_rate,
        channels: if matches!(codec, Codec::Pcma | Codec::Pcmu) {
            1
        } else {
            channels
        },
        data: &b[1..],
    })
}

/// Configures an [`Encoder`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct EncoderConfig {
    /// Write H.265 with the legacy codec id 12 (players predating Enhanced RTMP: older
    /// flv.js forks, ffmpeg before 6.1 with Chinese patches) instead of the `hvc1` FourCC.
    pub legacy_hevc: bool,
}

/// Turns a stream's tracks and packets into FLV tag bodies. At most one video and one audio
/// track are carried (the first of each); the others are skipped.
#[derive(Debug, Default)]
pub struct Encoder {
    cfg: EncoderConfig,
    tracks: Option<Tracks>,
    video: Option<usize>,
    audio: Option<usize>,
}

impl Encoder {
    /// An encoder configured by `cfg`.
    pub fn new(cfg: EncoderConfig) -> Encoder {
        Encoder {
            cfg,
            ..Encoder::default()
        }
    }

    /// Sets the tracks; [`headers`](Self::headers) gives their tags.
    pub fn set_tracks(&mut self, tracks: &Tracks) {
        self.video = tracks
            .iter()
            .position(|t| matches!(t.codec, Codec::H264 | Codec::H265));
        self.audio = tracks.iter().position(|t| {
            matches!(
                t.codec,
                Codec::Aac | Codec::Opus | Codec::Mp3 | Codec::Pcma | Codec::Pcmu
            )
        });
        self.tracks = Some(tracks.clone());
    }

    /// The video and audio track indexes carried.
    pub fn carried(&self) -> (Option<usize>, Option<usize>) {
        (self.video, self.audio)
    }

    fn track(&self, i: Option<usize>) -> Option<&Track> {
        self.tracks.as_ref()?.get(i?)
    }

    /// The header tags: `(tag type, body)` for onMetaData, then the video and audio sequence
    /// headers.
    pub fn headers(&self) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        let v = self.track(self.video);
        let a = self.track(self.audio);
        if v.is_none() && a.is_none() {
            return out;
        }
        out.push((TAG_SCRIPT, self.metadata()));
        if let Some(t) = v {
            out.push((TAG_VIDEO, self.video_body(t.codec, true, 0, 0, &t.config)));
        }
        if let Some(t) = a {
            if matches!(t.codec, Codec::Aac | Codec::Opus) {
                let cfg = if t.codec == Codec::Opus && t.config.is_empty() {
                    opus::Head::new(t.channels.max(1)).encode()
                } else {
                    t.config.clone()
                };
                out.push((TAG_AUDIO, audio_body(t, true, &cfg)));
            }
        }
        out
    }

    fn metadata(&self) -> Vec<u8> {
        let mut props: Vec<(String, Value)> = Vec::new();
        if let Some(t) = self.track(self.video) {
            if t.width > 0 {
                props.push(("width".into(), Value::Number(f64::from(t.width))));
                props.push(("height".into(), Value::Number(f64::from(t.height))));
            }
            let id = match t.codec {
                Codec::H265 if self.cfg.legacy_hevc => 12.0,
                Codec::H265 => f64::from(u32::from_be_bytes(*b"hvc1")),
                _ => 7.0,
            };
            props.push(("videocodecid".into(), Value::Number(id)));
        }
        if let Some(t) = self.track(self.audio) {
            let id = match t.codec {
                Codec::Aac => 10.0,
                Codec::Mp3 => 2.0,
                Codec::Pcma => 7.0,
                Codec::Pcmu => 8.0,
                _ => f64::from(u32::from_be_bytes(*b"Opus")),
            };
            props.push(("audiocodecid".into(), Value::Number(id)));
            if t.sample_rate > 0 {
                props.push((
                    "audiosamplerate".into(),
                    Value::Number(f64::from(t.sample_rate)),
                ));
            }
            props.push(("stereo".into(), Value::Bool(t.channels >= 2)));
        }
        props.push(("encoder".into(), Value::from("only-media")));
        let mut b = Vec::new();
        amf::write_string(&mut b, "onMetaData");
        amf::write(&mut b, &Value::EcmaArray(props));
        b
    }

    fn video_body(&self, codec: Codec, header: bool, key: u8, cts: i32, data: &[u8]) -> Vec<u8> {
        let frame = if header || key == 1 { 1u8 } else { 2 };
        let mut b = Vec::with_capacity(data.len() + 8);
        let c = (cts as u32) & 0x00ff_ffff;
        if codec == Codec::H265 && !self.cfg.legacy_hevc {
            let pt = if header {
                0
            } else if cts == 0 {
                3
            } else {
                1
            };
            b.push(0x80 | (frame << 4) | pt);
            b.extend_from_slice(b"hvc1");
            if pt == 1 {
                b.extend_from_slice(&c.to_be_bytes()[1..]);
            }
        } else {
            let id = if codec == Codec::H265 { 12 } else { 7 };
            b.push((frame << 4) | id);
            b.push(u8::from(!header));
            b.extend_from_slice(&c.to_be_bytes()[1..]);
        }
        b.extend_from_slice(data);
        b
    }

    /// The tag type and body of `pkt`, `None` for a track not carried.
    pub fn packet(&self, pkt: &Packet) -> Option<(u8, Vec<u8>)> {
        if Some(pkt.track) == self.video {
            let t = self.track(self.video)?;
            let cts = ms(pkt.cts()) as i32;
            return Some((
                TAG_VIDEO,
                self.video_body(t.codec, false, u8::from(pkt.keyframe), cts, &pkt.data),
            ));
        }
        if Some(pkt.track) == self.audio {
            let t = self.track(self.audio)?;
            return Some((TAG_AUDIO, audio_body(t, false, &pkt.data)));
        }
        None
    }
}

fn audio_body(t: &Track, header: bool, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(data.len() + 5);
    match t.codec {
        Codec::Aac => {
            b.extend_from_slice(&[0xaf, u8::from(!header)]);
        }
        Codec::Opus => {
            b.push(0x90 | u8::from(!header));
            b.extend_from_slice(b"Opus");
        }
        Codec::Mp3 => {
            let r = match t.sample_rate {
                0..=8000 => 0,
                8001..=11025 => 1,
                11026..=22050 => 2,
                _ => 3,
            };
            b.push(0x20 | (r << 2) | 2 | u8::from(t.channels >= 2));
        }
        Codec::Pcma => b.push(0x72),
        _ => b.push(0x82),
    }
    b.extend_from_slice(data);
    b
}

/// Rounds a [`Time`] to milliseconds.
pub fn ms(t: Time) -> i64 {
    if t >= 0 {
        (t + MILLISECOND / 2) / MILLISECOND
    } else {
        -((-t + MILLISECOND / 2) / MILLISECOND)
    }
}

/// What a [`Decoder`] produced from a tag.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Event {
    /// The stream's tracks: first once all are known, again when a configuration changes.
    Tracks(Tracks),
    /// A packet indexing the last tracks.
    Packet(Packet),
}

/// Most packets a [`Decoder`] holds while it waits for the stream's tracks.
const MAX_PENDING: usize = 512;

/// Turns FLV tag bodies (from RTMP messages or an FLV file) back into tracks and packets.
///
/// Tracks are announced once every kind the stream has (from onMetaData's `videocodecid` /
/// `audiocodecid`, or from the tags seen) has its configuration, or after the first video
/// keyframe has waited a while for an audio configuration that never comes; packets before that
/// are held back (up to a bound). A new sequence header re-announces the tracks.
#[derive(Debug, Default)]
pub struct Decoder {
    meta_video: Option<bool>,
    meta_audio: Option<bool>,
    video: Option<Track>,
    audio: Option<Track>,
    seen_video: bool,
    seen_audio: bool,
    tracks: Option<Tracks>,
    pending: Vec<(bool, Packet)>,
    last_ts: Option<u32>,
    wraps: i64,
}

impl Decoder {
    /// A decoder.
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// The tracks announced last.
    pub fn tracks(&self) -> Option<&Tracks> {
        self.tracks.as_ref()
    }

    fn unwrap_ts(&mut self, ts: u32) -> Time {
        if let Some(last) = self.last_ts {
            if ts < last && last - ts > 1 << 31 {
                self.wraps += 1;
            } else if ts > last && ts - last > 1 << 31 && self.wraps > 0 {
                self.wraps -= 1;
            }
        }
        self.last_ts = Some(ts);
        (i64::from(ts) + (self.wraps << 32)) * MILLISECOND
    }

    /// Feeds one tag (`tag_type` [`TAG_VIDEO`], [`TAG_AUDIO`] or [`TAG_SCRIPT`]) with its
    /// timestamp in milliseconds. Bodies that do not parse are skipped.
    pub fn write(&mut self, tag_type: u8, ts: u32, body: &[u8]) -> Vec<Event> {
        let mut out = Vec::new();
        match tag_type {
            TAG_SCRIPT => self.script(body),
            TAG_VIDEO => {
                let Ok(v) = parse_video(body) else {
                    return out;
                };
                if v.codec == Codec::Unknown {
                    return out;
                }
                self.seen_video = true;
                match v.packet_type {
                    PacketType::SequenceHeader => {
                        let t = Track::video(v.codec, v.data.to_vec());
                        if self.video.as_ref() != Some(&t) {
                            self.video = Some(t);
                            self.reannounce(&mut out);
                        }
                    }
                    PacketType::Coded => {
                        let dts = self.unwrap_ts(ts);
                        let key = v.keyframe
                            || match v.codec {
                                Codec::H265 => h265::is_keyframe(v.data),
                                _ => h264::is_keyframe(v.data),
                            };
                        let p = Packet::new(
                            0,
                            dts,
                            dts + i64::from(v.cts) * MILLISECOND,
                            key,
                            strip_aud(v.data),
                        );
                        self.packet(true, p, &mut out);
                    }
                    _ => {}
                }
            }
            TAG_AUDIO => {
                let Ok(a) = parse_audio(body) else {
                    return out;
                };
                if a.codec == Codec::Unknown {
                    return out;
                }
                self.seen_audio = true;
                match a.packet_type {
                    PacketType::SequenceHeader => {
                        let t = match a.codec {
                            Codec::Aac => Track::aac(a.data.to_vec()),
                            Codec::Opus => {
                                let ch = opus::Head::parse(a.data).map_or(2, |h| h.channels);
                                Track::audio(Codec::Opus, a.data.to_vec(), 48_000, ch)
                            }
                            c => Track::audio(c, Vec::new(), a.sample_rate, a.channels),
                        };
                        if self.audio.as_ref() != Some(&t) {
                            self.audio = Some(t);
                            self.reannounce(&mut out);
                        }
                    }
                    PacketType::Coded => {
                        if self.audio.is_none() && !matches!(a.codec, Codec::Aac) {
                            // Codecs without configuration: the first frame defines the track.
                            let cfg = Vec::new();
                            let t = if a.codec == Codec::Opus {
                                Track::audio(Codec::Opus, cfg, 48_000, 2)
                            } else {
                                Track::audio(a.codec, cfg, a.sample_rate, a.channels)
                            };
                            self.audio = Some(t);
                            self.reannounce(&mut out);
                        }
                        let dts = self.unwrap_ts(ts);
                        let p = Packet::new(0, dts, dts, true, a.data.to_vec());
                        self.packet(false, p, &mut out);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        out
    }

    fn script(&mut self, body: &[u8]) {
        let Ok(vals) = amf::decode_all(body) else {
            return;
        };
        // "@setDataFrame", "onMetaData", {...} or "onMetaData", {...}
        let Some(i) = vals.iter().position(|v| v.as_str() == Some("onMetaData")) else {
            return;
        };
        let Some(meta) = vals.get(i + 1) else { return };
        if meta.props().is_none() {
            return;
        }
        let has = |k: &str| {
            meta.get(k).is_some_and(|v| {
                !matches!(v, Value::Null | Value::Undefined)
                    && v.as_f64() != Some(0.0)
                    && v.as_str() != Some("")
            })
        };
        self.meta_video = Some(has("videocodecid"));
        self.meta_audio = Some(has("audiocodecid"));
    }

    /// Whether every kind of track the stream has is configured.
    fn complete(&self) -> bool {
        let want_video = self.meta_video.unwrap_or(self.seen_video);
        let want_audio = self.meta_audio.unwrap_or(self.seen_audio);
        (!want_video || self.video.is_some())
            && (!want_audio || self.audio.is_some())
            && (self.video.is_some() || self.audio.is_some())
    }

    fn build(&self) -> Tracks {
        let mut v = Vec::new();
        if let Some(t) = &self.video {
            v.push(t.clone());
        }
        if let Some(t) = &self.audio {
            v.push(t.clone());
        }
        Tracks::from(v)
    }

    fn reannounce(&mut self, out: &mut Vec<Event>) {
        if self.tracks.is_some() || self.complete() {
            self.announce(out);
        }
    }

    fn announce(&mut self, out: &mut Vec<Event>) {
        let t = self.build();
        self.tracks = Some(t.clone());
        out.push(Event::Tracks(t));
        for (video, p) in std::mem::take(&mut self.pending) {
            self.emit(video, p, out);
        }
    }

    fn emit(&self, video: bool, mut p: Packet, out: &mut Vec<Event>) {
        if video && self.video.is_none() || !video && self.audio.is_none() {
            return;
        }
        p.track = usize::from(!(video || self.video.is_none()));
        out.push(Event::Packet(p));
    }

    fn packet(&mut self, video: bool, p: Packet, out: &mut Vec<Event>) {
        if self.tracks.is_some() {
            self.emit(video, p, out);
            return;
        }
        if self.complete() {
            self.announce(out);
            self.emit(video, p, out);
            return;
        }
        self.pending.push((video, p));
        // A kind announced by metadata may never come: give up waiting after a while.
        let span = self
            .pending
            .first()
            .zip(self.pending.last())
            .map_or(0, |(a, b)| b.1.dts - a.1.dts);
        if (self.pending.len() >= MAX_PENDING || span > 3 * crate::av::SECOND)
            && (self.video.is_some() || self.audio.is_some())
        {
            self.meta_video = Some(self.video.is_some());
            self.meta_audio = Some(self.audio.is_some());
            self.announce(out);
        } else if self.pending.len() > MAX_PENDING {
            self.pending.remove(0);
        }
    }
}

fn strip_aud(data: &[u8]) -> Vec<u8> {
    let nalus = h264::avcc_nalus(data);
    let total: usize = nalus.iter().map(|n| n.len() + 4).sum();
    if total == data.len() {
        let h264_aud = |n: &[u8]| h264::nal_type(n[0]) == h264::NAL_AUD;
        if !nalus.iter().any(|n| !n.is_empty() && h264_aud(n)) {
            return data.to_vec();
        }
        return h264::to_avcc(nalus.into_iter().filter(|n| !n.is_empty() && !h264_aud(n)));
    }
    data.to_vec()
}

/// Appends an FLV file header (with the first PreviousTagSize 0).
pub fn write_header(out: &mut Vec<u8>, video: bool, audio: bool) {
    out.extend_from_slice(b"FLV\x01");
    out.push((u8::from(audio) << 2) | u8::from(video));
    out.extend_from_slice(&[0, 0, 0, 9, 0, 0, 0, 0]);
}

/// Appends a tag and its PreviousTagSize.
pub fn write_tag(out: &mut Vec<u8>, tag_type: u8, ts: u32, body: &[u8]) {
    let n = body.len() as u32;
    out.push(tag_type);
    out.extend_from_slice(&n.to_be_bytes()[1..]);
    out.extend_from_slice(&ts.to_be_bytes()[1..]);
    out.push((ts >> 24) as u8);
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(body);
    out.extend_from_slice(&(n + 11).to_be_bytes());
}

/// One tag split out of an FLV byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    /// [`TAG_AUDIO`], [`TAG_VIDEO`] or [`TAG_SCRIPT`].
    pub tag_type: u8,
    /// Timestamp in milliseconds.
    pub ts: u32,
    /// The body.
    pub body: Vec<u8>,
}

/// Splits an FLV byte stream, fed in pieces of any size, into tags.
#[derive(Debug)]
pub struct Demuxer {
    buf: Vec<u8>,
    header_done: bool,
    max_tag: usize,
}

impl Default for Demuxer {
    fn default() -> Self {
        Demuxer {
            buf: Vec::new(),
            header_done: false,
            max_tag: 16 << 20,
        }
    }
}

impl Demuxer {
    /// A demuxer refusing tags over 16 MiB.
    pub fn new() -> Demuxer {
        Demuxer::default()
    }

    /// Feeds bytes; returns the tags completed.
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<Tag>, FlvError> {
        self.buf.extend_from_slice(data);
        let mut tags = Vec::new();
        let mut p = 0;
        if !self.header_done {
            if self.buf.len() < 9 {
                return Ok(tags);
            }
            if &self.buf[..3] != b"FLV" {
                return Err(FlvError::Signature);
            }
            let off =
                u32::from_be_bytes([self.buf[5], self.buf[6], self.buf[7], self.buf[8]]) as usize;
            if !(9..=1024).contains(&off) {
                return Err(FlvError::Signature);
            }
            if self.buf.len() < off + 4 {
                return Ok(tags);
            }
            p = off + 4;
            self.header_done = true;
        }
        while self.buf.len() - p >= 11 {
            let h = &self.buf[p..p + 11];
            let n = (usize::from(h[1]) << 16) | (usize::from(h[2]) << 8) | usize::from(h[3]);
            if n > self.max_tag {
                return Err(FlvError::TooLarge);
            }
            if self.buf.len() - p < 11 + n + 4 {
                break;
            }
            let ts = (u32::from(h[7]) << 24)
                | (u32::from(h[4]) << 16)
                | (u32::from(h[5]) << 8)
                | u32::from(h[6]);
            tags.push(Tag {
                tag_type: h[0] & 0x1f,
                ts,
                body: self.buf[p + 11..p + 11 + n].to_vec(),
            });
            p += 11 + n + 4;
        }
        self.buf.drain(..p);
        Ok(tags)
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const SAMPLE: &[u8] = include_bytes!("../testdata/h264_aac.flv");
    const SAMPLE_HEVC: &[u8] = include_bytes!("../testdata/h265_aac.flv");

    fn decode_file(b: &[u8]) -> (Tracks, Vec<Packet>) {
        let mut d = Demuxer::new();
        let mut dec = Decoder::new();
        let mut tracks = None;
        let mut pkts = Vec::new();
        for chunk in b.chunks(777) {
            for t in d.feed(chunk).unwrap() {
                for e in dec.write(t.tag_type, t.ts, &t.body) {
                    match e {
                        Event::Tracks(t) => tracks = Some(t),
                        Event::Packet(p) => pkts.push(p),
                    }
                }
            }
        }
        (tracks.unwrap(), pkts)
    }

    #[test]
    fn decode_real_files() {
        let (t, p) = decode_file(SAMPLE);
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].codec, Codec::H264);
        assert_eq!((t[0].width, t[0].height), (320, 240));
        assert_eq!(t[1].codec, Codec::Aac);
        assert_eq!(t[1].sample_rate, 44100);
        assert_eq!(p.iter().filter(|p| p.track == 0).count(), 50);
        assert!(p[0].keyframe || p.iter().find(|p| p.track == 0).unwrap().keyframe);
        assert_eq!(p.iter().filter(|p| p.track == 0 && p.keyframe).count(), 2);
        // B-frames: some packets have pts > dts.
        assert!(p.iter().any(|p| p.cts() > 0));

        let (t, p) = decode_file(SAMPLE_HEVC);
        assert_eq!(t[0].codec, Codec::H265);
        assert_eq!((t[0].width, t[0].height), (320, 240));
        assert_eq!(t[1].sample_rate, 48000);
        assert!(
            p.iter()
                .filter(|p| p.track == 0)
                .all(|p| !p.data.is_empty())
        );
    }

    #[test]
    fn encode_decode_round_trip() {
        for (sample, legacy) in [(SAMPLE, false), (SAMPLE_HEVC, false), (SAMPLE_HEVC, true)] {
            let (tracks, pkts) = decode_file(sample);
            let mut cfg = EncoderConfig::default();
            cfg.legacy_hevc = legacy;
            let mut enc = Encoder::new(cfg);
            enc.set_tracks(&tracks);
            let mut file = Vec::new();
            write_header(&mut file, true, true);
            for (typ, body) in enc.headers() {
                write_tag(&mut file, typ, 0, &body);
            }
            for p in &pkts {
                let (typ, body) = enc.packet(p).unwrap();
                write_tag(&mut file, typ, ms(p.dts) as u32, &body);
            }
            let (t2, p2) = decode_file(&file);
            assert_eq!(t2, tracks);
            assert_eq!(p2, pkts);
        }
    }

    #[test]
    fn opus_and_g711_tracks() {
        let tracks: Tracks = Arc::from(vec![Track::audio(Codec::Opus, vec![], 48_000, 2)]);
        let mut enc = Encoder::new(EncoderConfig::default());
        enc.set_tracks(&tracks);
        let mut dec = Decoder::new();
        let mut events = Vec::new();
        for (typ, b) in enc.headers() {
            events.extend(dec.write(typ, 0, &b));
        }
        let (typ, b) = enc
            .packet(&Packet::new(0, 0, 0, true, vec![0xfc, 1, 2]))
            .unwrap();
        events.extend(dec.write(typ, 20, &b));
        assert!(
            matches!(&events[0], Event::Tracks(t) if t[0].codec == Codec::Opus && t[0].channels == 2)
        );
        assert!(
            matches!(&events[1], Event::Packet(p) if p.data == [0xfc, 1, 2] && p.dts == 20 * MILLISECOND)
        );

        let mut dec = Decoder::new();
        let ev = dec.write(TAG_AUDIO, 0, &[0x72, 1, 2, 3]);
        assert!(matches!(&ev[0], Event::Tracks(t) if t[0].codec == Codec::Pcma));
        assert!(matches!(&ev[1], Event::Packet(p) if p.data == [1, 2, 3]));
    }

    #[test]
    fn timestamps_unwrap_and_garbage_is_skipped() {
        let mut dec = Decoder::new();
        assert!(dec.write(TAG_VIDEO, 0, &[]).is_empty());
        assert!(dec.write(TAG_VIDEO, 0, &[0x17]).is_empty());
        assert!(dec.write(TAG_SCRIPT, 0, &[0x02, 0x00]).is_empty());
        assert_eq!(
            dec.unwrap_ts(u32::MAX - 10),
            (i64::from(u32::MAX) - 10) * MILLISECOND
        );
        assert_eq!(dec.unwrap_ts(5), ((1i64 << 32) + 5) * MILLISECOND);
        let mut d = Demuxer::new();
        assert_eq!(d.feed(b"NOT A FLV FILE").unwrap_err(), FlvError::Signature);
    }
}
