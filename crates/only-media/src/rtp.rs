//! RTP (RFC 3550) packetization and depacketization of the canonical packets of
//! [`crate::av`]: H.264 (RFC 6184: single NAL unit, STAP-A, FU-A), H.265 (RFC 7798: single
//! NAL unit, aggregation packets, fragmentation units), VP8 (RFC 7741), VP9 (RFC 9628), AV1
//! (the AOM RTP payload format), AAC (RFC 3640 `mpeg4-generic`, `AAC-hbr`), Opus (RFC 7587)
//! and G.711, plus the RTCP sender report the RTSP server sends its players. VP8, VP9 and AV1
//! use the payload formats of `only-rtp`; a frame missing a packet is dropped, and their
//! configuration and picture size come from the keyframes ([`Depacketizer::take_config`],
//! [`Depacketizer::picture_size`]).
//!
//! A [`Packetizer`] turns one [`Packet`] into RTP packets; a [`Depacketizer`] turns RTP
//! packets back into packets, with times taken from the RTP timestamps (unwrapped, relative to
//! the first one, on the track's clock). RTP carries no decode times: depacketized video has
//! `dts == pts`.

use std::{cmp::Reverse, collections::BinaryHeap, fmt};

use crate::{
    av::{Codec, Packet, Time, Track, from_ticks, to_ticks},
    codec::{av1, h264, h265, vp8, vp9},
};
use only_rtp::codec as rtpc;

/// The `only-rtp` packetizer of a VP8, VP9 or AV1 track (concrete types, so that
/// [`Packetizer`] stays `Sync` and unwind-safe).
#[derive(Debug)]
enum FramePacketizer {
    Vp8(rtpc::Vp8Packetizer),
    Vp9(rtpc::Vp9Packetizer),
    Av1(rtpc::Av1Packetizer),
}

impl FramePacketizer {
    fn new(codec: Codec) -> Option<FramePacketizer> {
        // VP8 and VP9 start their 15-bit PictureID at a random value.
        let picture_id = (random_u32() & 0x7fff) as u16;
        Some(match codec {
            Codec::Vp8 => FramePacketizer::Vp8(rtpc::Vp8Packetizer::new(picture_id)),
            Codec::Vp9 => FramePacketizer::Vp9(rtpc::Vp9Packetizer::new(picture_id)),
            Codec::Av1 => FramePacketizer::Av1(rtpc::Av1Packetizer::new()),
            _ => return None,
        })
    }

    fn get(&mut self) -> &mut dyn rtpc::Packetizer {
        match self {
            FramePacketizer::Vp8(p) => p,
            FramePacketizer::Vp9(p) => p,
            FramePacketizer::Av1(p) => p,
        }
    }
}

/// The `only-rtp` depacketizer of a VP8, VP9 or AV1 track.
#[derive(Debug)]
enum FrameDepacketizer {
    Vp8(rtpc::Vp8Depacketizer),
    Vp9(rtpc::Vp9Depacketizer),
    Av1(rtpc::Av1Depacketizer),
}

impl FrameDepacketizer {
    fn new(codec: Codec) -> Option<FrameDepacketizer> {
        Some(match codec {
            Codec::Vp8 => FrameDepacketizer::Vp8(rtpc::Vp8Depacketizer::new()),
            Codec::Vp9 => FrameDepacketizer::Vp9(rtpc::Vp9Depacketizer::new()),
            Codec::Av1 => FrameDepacketizer::Av1(rtpc::Av1Depacketizer::new()),
            _ => return None,
        })
    }

    fn get(&mut self) -> &mut dyn rtpc::Depacketizer {
        match self {
            FrameDepacketizer::Vp8(d) => d,
            FrameDepacketizer::Vp9(d) => d,
            FrameDepacketizer::Av1(d) => d,
        }
    }
}

/// Whether a VP8, VP9 or AV1 frame starts with a keyframe.
fn vpx_keyframe(codec: Codec, frame: &[u8]) -> bool {
    match codec {
        Codec::Vp8 => vp8::is_keyframe(frame),
        Codec::Vp9 => vp9::is_keyframe(frame),
        Codec::Av1 => av1::is_keyframe(frame),
        _ => false,
    }
}

/// The largest RTP payload a [`Packetizer`] makes by default (fits a 1500-byte MTU with IP,
/// UDP and the RTSP interleaving header to spare).
pub const DEFAULT_MTU: usize = 1200;

/// A malformed RTP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RtpError {
    /// Shorter than its headers say.
    Short,
    /// Not RTP version 2.
    Version,
}

impl fmt::Display for RtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RtpError::Short => f.write_str("RTP packet too short"),
            RtpError::Version => f.write_str("not RTP version 2"),
        }
    }
}

impl std::error::Error for RtpError {}

/// The fixed RTP header fields.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Header {
    /// The marker bit (end of an access unit for video).
    pub marker: bool,
    /// The payload type.
    pub payload_type: u8,
    /// The sequence number.
    pub sequence: u16,
    /// The timestamp on the track's clock.
    pub timestamp: u32,
    /// The synchronization source.
    pub ssrc: u32,
}

impl Header {
    /// Parses an RTP packet: the header and the payload (CSRCs, extension and padding removed).
    pub fn parse(b: &[u8]) -> Result<(Header, &[u8]), RtpError> {
        if b.len() < 12 {
            return Err(RtpError::Short);
        }
        if b[0] >> 6 != 2 {
            return Err(RtpError::Version);
        }
        let cc = usize::from(b[0] & 0x0f);
        let mut p = 12 + 4 * cc;
        if b.len() < p {
            return Err(RtpError::Short);
        }
        if b[0] & 0x10 != 0 {
            let ext = b.get(p..p + 4).ok_or(RtpError::Short)?;
            p += 4 + 4 * usize::from(u16::from_be_bytes([ext[2], ext[3]]));
            if b.len() < p {
                return Err(RtpError::Short);
            }
        }
        let mut end = b.len();
        if b[0] & 0x20 != 0 {
            let pad = usize::from(b[end - 1]);
            if pad == 0 || pad > end - p {
                return Err(RtpError::Short);
            }
            end -= pad;
        }
        let h = Header {
            marker: b[1] & 0x80 != 0,
            payload_type: b[1] & 0x7f,
            sequence: u16::from_be_bytes([b[2], b[3]]),
            timestamp: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            ssrc: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
        };
        Ok((h, &b[p..end]))
    }

    /// Appends the 12-byte header.
    pub fn write(&self, out: &mut Vec<u8>) {
        out.push(0x80);
        out.push(u8::from(self.marker) << 7 | (self.payload_type & 0x7f));
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.ssrc.to_be_bytes());
    }
}

/// Whether an interleaved or UDP packet is RTCP rather than RTP (payload types 200-204 in the
/// second byte, RFC 5761).
pub fn is_rtcp(b: &[u8]) -> bool {
    b.len() >= 2 && (200..=204).contains(&b[1])
}

/// An RTCP sender report (RFC 3550 6.4.1) with no report blocks.
pub fn sender_report(ssrc: u32, ntp: u64, rtp_time: u32, packets: u32, octets: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(28);
    b.extend_from_slice(&[0x80, 200, 0, 6]);
    b.extend_from_slice(&ssrc.to_be_bytes());
    b.extend_from_slice(&ntp.to_be_bytes());
    b.extend_from_slice(&rtp_time.to_be_bytes());
    b.extend_from_slice(&packets.to_be_bytes());
    b.extend_from_slice(&octets.to_be_bytes());
    b
}

/// The NTP timestamp (RFC 5905 64-bit format) of the system clock now.
pub fn ntp_now() -> u64 {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs() + 2_208_988_800;
    let frac = (u64::from(d.subsec_nanos()) << 32) / 1_000_000_000;
    (secs << 32) | frac
}

/// Whether a codec has an RTP mapping here.
pub fn supported(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::H264
            | Codec::H265
            | Codec::Vp8
            | Codec::Vp9
            | Codec::Av1
            | Codec::Aac
            | Codec::Opus
            | Codec::Pcmu
            | Codec::Pcma
    )
}

/// Turns the packets of one track into RTP packets.
#[derive(Debug)]
pub struct Packetizer {
    codec: Codec,
    clock: u32,
    payload_type: u8,
    ssrc: u32,
    sequence: u16,
    base: u32,
    mtu: usize,
    /// Parameter sets (H.264 SPS/PPS, H.265 VPS/SPS/PPS) sent before keyframes that lack them.
    params: Vec<Vec<u8>>,
    /// The `only-rtp` packetizer of VP8, VP9 and AV1.
    frames: Option<FramePacketizer>,
    packets: u32,
    octets: u32,
    last_ts: u32,
}

fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    let _ = only_crypto::rand::fill_random(&mut b);
    u32::from_be_bytes(b)
}

impl Packetizer {
    /// A packetizer for `track` with payload type `payload_type`, a random SSRC, initial
    /// sequence number and timestamp base.
    pub fn new(track: &Track, payload_type: u8) -> Packetizer {
        let params = match track.codec {
            Codec::H264 => h264::Config::parse(&track.config)
                .map(|c| c.sps.into_iter().chain(c.pps).collect())
                .unwrap_or_default(),
            Codec::H265 => h265::Config::parse(&track.config)
                .map(|c| c.vps.into_iter().chain(c.sps).chain(c.pps).collect())
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        let base = random_u32();
        Packetizer {
            codec: track.codec,
            clock: track.clock_rate(),
            payload_type,
            ssrc: random_u32(),
            sequence: random_u32() as u16,
            base,
            mtu: DEFAULT_MTU,
            params,
            frames: FramePacketizer::new(track.codec),
            packets: 0,
            octets: 0,
            last_ts: base,
        }
    }

    /// Sets the largest payload.
    #[must_use]
    pub fn mtu(mut self, mtu: usize) -> Packetizer {
        self.mtu = mtu.max(64);
        self
    }

    /// The SSRC.
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// The sequence number of the next packet.
    pub fn next_sequence(&self) -> u16 {
        self.sequence
    }

    /// The RTP timestamp of time 0.
    pub fn base(&self) -> u32 {
        self.base
    }

    /// The track's clock rate.
    pub fn clock_rate(&self) -> u32 {
        self.clock
    }

    /// The RTP timestamp of `t`.
    pub fn timestamp(&self, t: Time) -> u32 {
        self.base.wrapping_add(to_ticks(t, self.clock) as u32)
    }

    /// A sender report for this stream, `rtp_time` being the RTP time of `ntp`.
    pub fn sender_report(&self, ntp: u64, rtp_time: u32) -> Vec<u8> {
        sender_report(self.ssrc, ntp, rtp_time, self.packets, self.octets)
    }

    /// The timestamp of the last packet made.
    pub fn last_timestamp(&self) -> u32 {
        self.last_ts
    }

    fn emit(&mut self, out: &mut Vec<Vec<u8>>, ts: u32, marker: bool, parts: &[&[u8]]) {
        let len: usize = parts.iter().map(|p| p.len()).sum();
        let mut b = Vec::with_capacity(12 + len);
        Header {
            marker,
            payload_type: self.payload_type,
            sequence: self.sequence,
            timestamp: ts,
            ssrc: self.ssrc,
        }
        .write(&mut b);
        for p in parts {
            b.extend_from_slice(p);
        }
        self.sequence = self.sequence.wrapping_add(1);
        self.packets = self.packets.wrapping_add(1);
        self.octets = self.octets.wrapping_add(len as u32);
        out.push(b);
    }

    /// Appends the RTP packets of `pkt` (its presentation time as RTP timestamp) to `out`.
    pub fn packetize(&mut self, pkt: &Packet, out: &mut Vec<Vec<u8>>) {
        let ts = self.timestamp(pkt.pts);
        self.last_ts = ts;
        if let Some(f) = self.frames.as_mut() {
            for (payload, marker) in f.get().packetize(self.mtu, &pkt.data) {
                self.emit(out, ts, marker, &[&payload]);
            }
            return;
        }
        match self.codec {
            Codec::H264 | Codec::H265 => self.video(pkt, ts, out),
            Codec::Aac => {
                let n = pkt.data.len();
                let hdr = [0, 16, (n >> 5) as u8, ((n & 0x1f) << 3) as u8];
                let room = self.mtu - 4;
                if n <= room {
                    self.emit(out, ts, true, &[&hdr, &pkt.data]);
                } else {
                    let chunks: Vec<&[u8]> = pkt.data.chunks(room).collect();
                    let last = chunks.len() - 1;
                    for (i, c) in chunks.into_iter().enumerate() {
                        self.emit(out, ts, i == last, &[&hdr, c]);
                    }
                }
            }
            _ => self.emit(out, ts, true, &[&pkt.data]),
        }
    }

    fn video(&mut self, pkt: &Packet, ts: u32, out: &mut Vec<Vec<u8>>) {
        let h265 = self.codec == Codec::H265;
        let kind = |n: &[u8]| {
            if h265 {
                h265::nal_type(n[0])
            } else {
                h264::nal_type(n[0])
            }
        };
        let (aud, sps) = if h265 {
            (h265::NAL_AUD, h265::NAL_SPS)
        } else {
            (h264::NAL_AUD, h264::NAL_SPS)
        };
        let nalus: Vec<&[u8]> = h264::avcc_nalus(&pkt.data)
            .into_iter()
            .filter(|n| n.len() > usize::from(h265) && kind(n) != aud)
            .collect();
        let mut all: Vec<Vec<u8>> = Vec::new();
        if pkt.keyframe && !nalus.iter().any(|n| kind(n) == sps) {
            all.extend(self.params.iter().cloned());
        }
        all.extend(nalus.iter().map(|n| n.to_vec()));
        let count = all.len();
        for (i, nal) in all.iter().enumerate() {
            let last = i + 1 == count;
            if nal.len() <= self.mtu {
                self.emit(out, ts, last, &[nal]);
                continue;
            }
            if h265 {
                let t = h265::nal_type(nal[0]);
                let ph = [(nal[0] & 0x81) | (49 << 1), nal[1]];
                let body = &nal[2..];
                let chunks: Vec<&[u8]> = body.chunks(self.mtu - 3).collect();
                let n = chunks.len();
                for (k, c) in chunks.into_iter().enumerate() {
                    let fu = t | if k == 0 { 0x80 } else { 0 } | if k + 1 == n { 0x40 } else { 0 };
                    self.emit(out, ts, last && k + 1 == n, &[&ph, &[fu], c]);
                }
            } else {
                let ind = (nal[0] & 0xe0) | 28;
                let t = nal[0] & 0x1f;
                let body = &nal[1..];
                let chunks: Vec<&[u8]> = body.chunks(self.mtu - 2).collect();
                let n = chunks.len();
                for (k, c) in chunks.into_iter().enumerate() {
                    let fu = t | if k == 0 { 0x80 } else { 0 } | if k + 1 == n { 0x40 } else { 0 };
                    self.emit(out, ts, last && k + 1 == n, &[&[ind, fu], c]);
                }
            }
        }
    }
}

/// Turns the RTP packets of one track back into canonical packets.
#[derive(Debug)]
pub struct Depacketizer {
    codec: Codec,
    clock: u32,
    /// Added to every time (lines tracks of one session up by arrival).
    offset: Time,
    base: Option<i64>,
    last_ext: i64,
    last_seq: Option<u16>,
    // video access unit being assembled
    au: Vec<u8>,
    au_ts: Option<i64>,
    au_key: bool,
    fu: Option<Vec<u8>>,
    // AAC fragments
    frag: Vec<u8>,
    // in-band parameter sets
    sps: Option<Vec<u8>>,
    pps: Option<Vec<u8>>,
    vps: Option<Vec<u8>>,
    params_changed: bool,
    max_au: usize,
    dts: DtsGen,
    /// VP8 / VP9 / AV1: the `only-rtp` depacketizer, whether the frame being assembled lost a
    /// packet, and the track its last keyframe describes.
    frames: Option<FrameDepacketizer>,
    broken: bool,
    keyframe_track: Option<Track>,
}

impl Depacketizer {
    /// A depacketizer for `track`.
    pub fn new(track: &Track) -> Depacketizer {
        Depacketizer {
            codec: track.codec,
            clock: track.clock_rate(),
            offset: 0,
            base: None,
            last_ext: 0,
            last_seq: None,
            au: Vec::new(),
            au_ts: None,
            au_key: false,
            fu: None,
            frag: Vec::new(),
            sps: None,
            pps: None,
            vps: None,
            params_changed: false,
            max_au: 8 << 20,
            dts: DtsGen::default(),
            frames: FrameDepacketizer::new(track.codec),
            broken: false,
            keyframe_track: None,
        }
    }

    /// Adds `offset` to every time produced.
    #[must_use]
    pub fn offset(mut self, offset: Time) -> Depacketizer {
        self.offset = offset;
        self
    }

    /// The codec configuration built from the parameter sets seen in band (H.264, H.265) or
    /// from the last keyframe (VP8, VP9: a `VPCodecConfigurationRecord`; AV1: an
    /// `AV1CodecConfigurationRecord` from its sequence header), if it changed since the last
    /// call.
    pub fn take_config(&mut self) -> Option<Vec<u8>> {
        if !self.params_changed {
            return None;
        }
        let c = match self.codec {
            Codec::Vp8 | Codec::Vp9 | Codec::Av1 => self.keyframe_track.as_ref()?.config.clone(),
            Codec::H264 => {
                let (s, p) = (self.sps.as_ref()?, self.pps.as_ref()?);
                h264::Config::from_sets(s, p).encode()
            }
            Codec::H265 => {
                let (v, s, p) = (self.vps.as_ref()?, self.sps.as_ref()?, self.pps.as_ref()?);
                h265::Config::from_sets(v, s, p)?.encode()
            }
            _ => return None,
        };
        self.params_changed = false;
        Some(c)
    }

    /// The picture size of the last keyframe (VP8, VP9, AV1), which their configuration does
    /// not carry (VP8, VP9).
    pub fn picture_size(&self) -> Option<(u32, u32)> {
        self.keyframe_track.as_ref().map(|t| (t.width, t.height))
    }

    fn time(&mut self, ts: u32) -> (Time, i64) {
        // Unwrap the 32-bit timestamp around the last one.
        let ext = match self.base {
            None => {
                self.base = Some(i64::from(ts));
                i64::from(ts)
            }
            Some(_) => {
                let d = ts.wrapping_sub(self.last_ext as u32) as i32;
                self.last_ext + i64::from(d)
            }
        };
        self.last_ext = ext;
        let rel = ext - self.base.unwrap_or(ext);
        (from_ticks(rel, self.clock) + self.offset, ext)
    }

    /// Feeds one RTP packet; appends the packets it completes to `out`.
    pub fn push(&mut self, rtp: &[u8], out: &mut Vec<Packet>) -> Result<(), RtpError> {
        let (h, payload) = Header::parse(rtp)?;
        let lost = self
            .last_seq
            .is_some_and(|s| h.sequence != s.wrapping_add(1));
        self.last_seq = Some(h.sequence);
        let (t, ext) = self.time(h.timestamp);
        if self.frames.is_some() {
            self.frame_packet(payload, ext, t, h.marker, lost, out);
            return Ok(());
        }
        match self.codec {
            Codec::H264 | Codec::H265 => {
                if self.au_ts.is_some_and(|a| a != ext) {
                    self.flush(out);
                }
                if lost {
                    self.fu = None;
                }
                self.au_ts = Some(ext);
                if self.codec == Codec::H264 {
                    self.h264(payload);
                } else {
                    self.h265(payload);
                }
                if h.marker {
                    self.flush_at(t, out);
                }
            }
            Codec::Aac => self.aac(payload, t, h.marker, lost, out),
            _ => {
                if !payload.is_empty() {
                    out.push(Packet::new(0, t, t, true, payload.to_vec()));
                }
            }
        }
        Ok(())
    }

    fn flush(&mut self, out: &mut Vec<Packet>) {
        if let Some(ext) = self.au_ts {
            let rel = ext - self.base.unwrap_or(ext);
            let t = from_ticks(rel, self.clock) + self.offset;
            if self.frames.is_some() {
                self.flush_frame(t, out);
            } else {
                self.flush_at(t, out);
            }
        }
    }

    /// One packet of a VP8 / VP9 / AV1 frame. A frame ends at the marker bit or when the
    /// timestamp changes; a frame that lost a packet (or does not depacketize) is dropped.
    fn frame_packet(
        &mut self,
        payload: &[u8],
        ext: i64,
        t: Time,
        marker: bool,
        lost: bool,
        out: &mut Vec<Packet>,
    ) {
        if self.au_ts.is_some_and(|a| a != ext) {
            // The frame ended without its marker: complete only if nothing went missing.
            self.broken |= lost;
            self.flush(out);
        }
        let Some(d) = self.frames.as_mut().map(FrameDepacketizer::get) else {
            return;
        };
        if self.au_ts.is_none() {
            // A new frame: it is whole if it starts here, whatever came before.
            d.reset();
            self.broken = !d.is_frame_start(payload);
        } else if lost {
            self.broken = true;
        }
        self.au_ts = Some(ext);
        if !self.broken
            && (d.depacketize(payload, &mut self.au).is_err() || self.au.len() > self.max_au)
        {
            self.broken = true;
        }
        if marker {
            self.flush_frame(t, out);
        }
    }

    fn flush_frame(&mut self, t: Time, out: &mut Vec<Packet>) {
        self.au_ts = None;
        let data = std::mem::take(&mut self.au);
        if std::mem::take(&mut self.broken) || data.is_empty() {
            return;
        }
        let key = vpx_keyframe(self.codec, &data);
        if key {
            if let Some(track) = Track::video_from_keyframe(self.codec, &data) {
                if self.keyframe_track.as_ref() != Some(&track) {
                    self.keyframe_track = Some(track);
                    self.params_changed = true;
                }
            }
        }
        out.push(Packet::new(0, t, t, key, data));
    }

    fn flush_at(&mut self, t: Time, out: &mut Vec<Packet>) {
        self.fu = None;
        self.au_ts = None;
        if !self.au.is_empty() {
            let data = std::mem::take(&mut self.au);
            let dts = self.dts.next(t);
            out.push(Packet::new(0, dts, t.max(dts), self.au_key, data));
        }
        self.au_key = false;
    }

    fn nal(&mut self, nal: &[u8]) {
        if nal.is_empty() || self.au.len() + nal.len() > self.max_au {
            return;
        }
        if self.codec == Codec::H264 {
            match h264::nal_type(nal[0]) {
                h264::NAL_IDR => self.au_key = true,
                h264::NAL_SPS => set_param(&mut self.sps, nal, &mut self.params_changed),
                h264::NAL_PPS => set_param(&mut self.pps, nal, &mut self.params_changed),
                h264::NAL_AUD => return,
                _ => {}
            }
        } else {
            let t = h265::nal_type(nal[0]);
            if h265::is_irap(t) {
                self.au_key = true;
            }
            match t {
                h265::NAL_VPS => set_param(&mut self.vps, nal, &mut self.params_changed),
                h265::NAL_SPS => set_param(&mut self.sps, nal, &mut self.params_changed),
                h265::NAL_PPS => set_param(&mut self.pps, nal, &mut self.params_changed),
                h265::NAL_AUD => return,
                _ => {}
            }
        }
        h264::push_avcc(&mut self.au, nal);
    }

    fn h264(&mut self, p: &[u8]) {
        let Some(&b0) = p.first() else { return };
        match b0 & 0x1f {
            1..=23 => self.nal(p),
            24 => {
                // STAP-A
                let mut r = &p[1..];
                while r.len() >= 2 {
                    let n = usize::from(u16::from_be_bytes([r[0], r[1]]));
                    if n > r.len() - 2 {
                        break;
                    }
                    let nal = r[2..2 + n].to_vec();
                    self.nal(&nal);
                    r = &r[2 + n..];
                }
            }
            28 => {
                // FU-A
                if p.len() < 2 {
                    return;
                }
                let fu = p[1];
                if fu & 0x80 != 0 {
                    let mut v = vec![(b0 & 0xe0) | (fu & 0x1f)];
                    v.extend_from_slice(&p[2..]);
                    self.fu = Some(v);
                } else if let Some(v) = self.fu.as_mut() {
                    if v.len() + p.len() > self.max_au {
                        self.fu = None;
                        return;
                    }
                    v.extend_from_slice(&p[2..]);
                }
                if fu & 0x40 != 0 {
                    if let Some(v) = self.fu.take() {
                        self.nal(&v);
                    }
                }
            }
            _ => {}
        }
    }

    fn h265(&mut self, p: &[u8]) {
        if p.len() < 2 {
            return;
        }
        match h265::nal_type(p[0]) {
            48 => {
                let mut r = &p[2..];
                while r.len() >= 2 {
                    let n = usize::from(u16::from_be_bytes([r[0], r[1]]));
                    if n > r.len() - 2 {
                        break;
                    }
                    let nal = r[2..2 + n].to_vec();
                    self.nal(&nal);
                    r = &r[2 + n..];
                }
            }
            49 => {
                if p.len() < 3 {
                    return;
                }
                let fu = p[2];
                if fu & 0x80 != 0 {
                    let mut v = vec![(p[0] & 0x81) | ((fu & 0x3f) << 1), p[1]];
                    v.extend_from_slice(&p[3..]);
                    self.fu = Some(v);
                } else if let Some(v) = self.fu.as_mut() {
                    if v.len() + p.len() > self.max_au {
                        self.fu = None;
                        return;
                    }
                    v.extend_from_slice(&p[3..]);
                }
                if fu & 0x40 != 0 {
                    if let Some(v) = self.fu.take() {
                        self.nal(&v);
                    }
                }
            }
            50 => {} // PACI
            _ => self.nal(p),
        }
    }

    fn aac(&mut self, p: &[u8], t: Time, marker: bool, lost: bool, out: &mut Vec<Packet>) {
        if lost {
            self.frag.clear();
        }
        if p.len() < 2 {
            return;
        }
        let hdr_bits = usize::from(u16::from_be_bytes([p[0], p[1]]));
        let n = hdr_bits.div_ceil(16);
        let hdr_bytes = hdr_bits.div_ceil(8);
        let Some(headers) = p.get(2..2 + hdr_bytes) else {
            return;
        };
        let mut data = &p[2 + hdr_bytes..];
        if n == 1 {
            // A 16-bit AU-header in fewer bits (1 to 8) is malformed.
            let Some(&[h0, h1]) = headers.get(..2) else {
                return;
            };
            let size = usize::from(u16::from_be_bytes([h0, h1]) >> 3);
            if size > data.len() || !self.frag.is_empty() {
                // A fragment of an AU larger than the packet.
                if self.frag.len() + data.len() > self.max_au {
                    self.frag.clear();
                    return;
                }
                self.frag.extend_from_slice(data);
                if marker || self.frag.len() >= size {
                    let au = std::mem::take(&mut self.frag);
                    if au.len() == size {
                        out.push(Packet::new(0, t, t, true, au));
                    }
                }
                return;
            }
        }
        let step = from_ticks(i64::from(crate::codec::aac::FRAME_SAMPLES), self.clock);
        for i in 0..n {
            let Some(h) = headers.get(2 * i..2 * i + 2) else {
                break;
            };
            let size = usize::from(u16::from_be_bytes([h[0], h[1]]) >> 3);
            if size > data.len() {
                break;
            }
            let at = t + step * i as Time;
            out.push(Packet::new(0, at, at, true, data[..size].to_vec()));
            data = &data[size..];
        }
    }
}

/// Derives decode times for video whose RTP timestamps are presentation times, which go
/// back and forth with B-frames: the decode time of a frame is the smallest presentation time
/// seen and not yet used, once `depth` (the reorder depth, learned when times go back) more
/// are known. No frame is held back.
#[derive(Debug, Default)]
struct DtsGen {
    heap: BinaryHeap<Reverse<Time>>,
    depth: usize,
    last: Option<Time>,
}

impl DtsGen {
    fn next(&mut self, pts: Time) -> Time {
        if self.last.is_some_and(|l| pts <= l) && self.depth < 8 {
            // Times went back: one more frame of reorder depth.
            self.depth += 1;
        }
        self.heap.push(Reverse(pts));
        let mut dts = None;
        while self.heap.len() > self.depth {
            let Some(Reverse(c)) = self.heap.pop() else {
                break;
            };
            if self.last.is_some_and(|l| c <= l) {
                continue; // too late to be anyone's decode time
            }
            dts = Some(c);
            break;
        }
        let dts = match (dts, self.last) {
            (Some(d), _) => d,
            (None, Some(l)) => l + 1,
            (None, None) => pts,
        };
        self.last = Some(dts);
        dts
    }
}

fn set_param(slot: &mut Option<Vec<u8>>, nal: &[u8], changed: &mut bool) {
    if slot.as_deref() != Some(nal) {
        *slot = Some(nal.to_vec());
        *changed = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::av::{MILLISECOND, SECOND};

    const SPS: &[u8] = &[
        0x67, 0x64, 0x00, 0x0d, 0xac, 0xd9, 0x41, 0x41, 0xfb, 0x01, 0x10, 0x00, 0x00, 0x03, 0x00,
        0x10, 0x00, 0x00, 0x03, 0x03, 0x20, 0xf1, 0x42, 0x99, 0x60,
    ];
    const PPS: &[u8] = &[0x68, 0xeb, 0xe3, 0xcb, 0x22, 0xc0];

    #[test]
    fn header_round_trip_and_errors() {
        let h = Header {
            marker: true,
            payload_type: 96,
            sequence: 65535,
            timestamp: 7,
            ssrc: 9,
        };
        let mut b = Vec::new();
        h.write(&mut b);
        b.extend_from_slice(b"xy");
        let (back, p) = Header::parse(&b).unwrap();
        assert_eq!(back, h);
        assert_eq!(p, b"xy");
        assert_eq!(Header::parse(&b[..5]), Err(RtpError::Short));
        b[0] = 0x40;
        assert_eq!(Header::parse(&b), Err(RtpError::Version));
        // padding + extension + csrc
        let mut c = vec![0xb1, 96, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1];
        c.extend_from_slice(&[0, 0, 0, 5]); // csrc
        c.extend_from_slice(&[0xbe, 0xde, 0, 1, 1, 2, 3, 4]); // ext
        c.extend_from_slice(&[9, 9, 0, 2]); // payload + 2 bytes padding
        assert_eq!(Header::parse(&c).unwrap().1, &[9, 9]);
        assert!(is_rtcp(&sender_report(1, ntp_now(), 2, 3, 4)));
    }

    fn round_trip(track: &Track, pkts: &[Packet], mtu: usize) -> Vec<Packet> {
        let mut p = Packetizer::new(track, 96).mtu(mtu);
        let mut d = Depacketizer::new(track);
        let mut out = Vec::new();
        for pkt in pkts {
            let mut rtp = Vec::new();
            p.packetize(pkt, &mut rtp);
            for r in rtp {
                d.push(&r, &mut out).unwrap();
            }
        }
        out
    }

    #[test]
    fn h264_single_and_fu_a() {
        let cfg = h264::Config::from_sets(SPS, PPS).encode();
        let track = Track::video(Codec::H264, cfg);
        let idr: Vec<u8> = std::iter::once(0x65)
            .chain((0..5000).map(|i| i as u8))
            .collect();
        let key = Packet::new(0, 0, 0, true, h264::to_avcc([&idr[..]]));
        let inter = Packet::new(
            0,
            40 * MILLISECOND,
            40 * MILLISECOND,
            false,
            h264::to_avcc([&[0x41u8, 1, 2][..]]),
        );
        let out = round_trip(&track, &[key, inter], 1000);
        assert_eq!(out.len(), 2);
        assert!(out[0].keyframe && !out[1].keyframe);
        // The keyframe got SPS and PPS in front.
        assert_eq!(h264::avcc_nalus(&out[0].data), vec![SPS, PPS, &idr[..]]);
        assert_eq!(out[1].pts, 40 * MILLISECOND);
        let mut d = Depacketizer::new(&track);
        let mut o = Vec::new();
        // STAP-A carrying SPS and PPS, then a single IDR NAL with marker.
        let mut stap = Vec::new();
        Header {
            payload_type: 96,
            timestamp: 1000,
            ..Header::default()
        }
        .write(&mut stap);
        stap.push(24);
        for n in [SPS, PPS] {
            stap.extend_from_slice(&(n.len() as u16).to_be_bytes());
            stap.extend_from_slice(n);
        }
        d.push(&stap, &mut o).unwrap();
        let mut idr1 = Vec::new();
        Header {
            marker: true,
            payload_type: 96,
            sequence: 1,
            timestamp: 1000,
            ..Header::default()
        }
        .write(&mut idr1);
        idr1.extend_from_slice(&[0x65, 1]);
        d.push(&idr1, &mut o).unwrap();
        assert_eq!(o.len(), 1);
        assert!(o[0].keyframe);
        let cfg2 = d.take_config().unwrap();
        assert_eq!(h264::Config::parse(&cfg2).unwrap().sps[0], SPS);
        assert!(d.take_config().is_none());
    }

    #[test]
    fn h265_fu_and_aggregation() {
        let track = Track::new(Codec::H265, vec![]);
        let idr: Vec<u8> = [0x26u8, 0x01]
            .into_iter()
            .chain((0..3000).map(|i| i as u8))
            .collect();
        let key = Packet::new(0, SECOND, SECOND, true, h264::to_avcc([&idr[..]]));
        let out = round_trip(&track, &[key], 1200);
        assert_eq!(out.len(), 1);
        assert!(out[0].keyframe);
        assert_eq!(h264::avcc_nalus(&out[0].data), vec![&idr[..]]);
        // aggregation packet
        let mut d = Depacketizer::new(&track);
        let mut ap = Vec::new();
        Header {
            marker: true,
            payload_type: 96,
            ..Header::default()
        }
        .write(&mut ap);
        ap.extend_from_slice(&[48 << 1, 1]);
        for n in [&[0x40u8, 1, 5][..], &[0x26, 1, 6]] {
            ap.extend_from_slice(&(n.len() as u16).to_be_bytes());
            ap.extend_from_slice(n);
        }
        let mut o = Vec::new();
        d.push(&ap, &mut o).unwrap();
        assert_eq!(o.len(), 1);
        assert_eq!(h264::avcc_nalus(&o[0].data).len(), 2);
    }

    #[test]
    fn aac_and_opus() {
        let track = Track::aac(vec![0x12, 0x10]);
        let a = Packet::new(0, 0, 0, true, vec![5; 300]);
        let b = Packet::new(0, 0, 0, true, vec![6; 3000]);
        let out = round_trip(&track, &[a.clone(), b.clone()], 1200);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].data, a.data);
        assert_eq!(out[1].data, b.data);
        // Two AUs in one packet.
        let mut d = Depacketizer::new(&track);
        let mut r = Vec::new();
        Header {
            marker: true,
            payload_type: 97,
            timestamp: 44100,
            ..Header::default()
        }
        .write(&mut r);
        r.extend_from_slice(&[0, 32, 0, 3 << 3, 0, 2 << 3, 1, 2, 3, 4, 5]);
        let mut o = Vec::new();
        d.push(&r, &mut o).unwrap();
        assert_eq!(o.len(), 2);
        assert_eq!(o[1].data, vec![4, 5]);
        assert_eq!(o[1].dts, from_ticks(1024, 44100));
        let opus = Track::audio(Codec::Opus, vec![], 48000, 2);
        let p = Packet::new(
            0,
            20 * MILLISECOND,
            20 * MILLISECOND,
            true,
            vec![0xfc, 1, 2],
        );
        let back = round_trip(
            &opus,
            &[Packet::new(0, 0, 0, true, vec![0xfc]), p.clone()],
            1200,
        );
        assert_eq!(back[1].data, p.data);
        assert_eq!(back[1].dts, 20 * MILLISECOND);
    }

    #[test]
    fn dts_from_reordered_pts() {
        let mut g = DtsGen::default();
        let ms = MILLISECOND;
        // I0 P120 B40 B80 P240 B160 B200 P360 B280 B320
        let pts = [0, 120, 40, 80, 240, 160, 200, 360, 280, 320];
        let dts: Vec<Time> = pts.iter().map(|&p| g.next(p * ms)).collect();
        for w in dts.windows(2) {
            assert!(w[1] > w[0], "{dts:?}");
        }
        // After the first B-frames taught it the depth, dts never passes pts.
        for i in 4..pts.len() {
            assert!(dts[i] <= pts[i] * ms, "{i} {dts:?}");
        }
        let mut g = DtsGen::default();
        assert_eq!(g.next(0), 0);
        assert_eq!(g.next(40 * ms), 40 * ms);
    }

    #[test]
    fn timestamps_unwrap() {
        let track = Track::audio(Codec::Pcmu, vec![], 8000, 1);
        let mut d = Depacketizer::new(&track);
        let mut o = Vec::new();
        for (i, ts) in [u32::MAX - 79, 80u32].into_iter().enumerate() {
            let mut r = Vec::new();
            Header {
                sequence: i as u16,
                timestamp: ts,
                ..Header::default()
            }
            .write(&mut r);
            r.push(1);
            d.push(&r, &mut o).unwrap();
        }
        assert_eq!(o[1].dts, 20 * MILLISECOND);
    }

    fn flv_video(data: &[u8]) -> (Track, Vec<Packet>) {
        use crate::flv::{Decoder, Demuxer, Event};
        let mut dec = Decoder::new();
        let (mut tracks, mut pkts) = (None, Vec::new());
        for t in Demuxer::new().feed(data).unwrap() {
            for e in dec.write(t.tag_type, t.ts, &t.body) {
                match e {
                    Event::Tracks(t) => tracks = Some(t),
                    Event::Packet(p) if p.track == 0 => pkts.push(p),
                    Event::Packet(_) => {}
                }
            }
        }
        (tracks.unwrap()[0].clone(), pkts)
    }

    /// VP9 and AV1 over RTP (`only-rtp` payload formats): frames come back byte for byte with
    /// their keyframes; the configuration and size come from the first keyframe; a lost packet
    /// drops its frame only.
    #[test]
    fn vp9_and_av1_round_trip() {
        for data in [
            &include_bytes!("../testdata/vp9_opus.flv")[..],
            &include_bytes!("../testdata/av1_opus.flv")[..],
        ] {
            let (track, pkts) = flv_video(data);
            assert!(supported(track.codec));
            let bare = Track::new(track.codec, Vec::new());
            let mut d = Depacketizer::new(&bare);
            let mut p = Packetizer::new(&track, 96).mtu(300);
            let mut out = Vec::new();
            let mut dropped = 0;
            for (i, pkt) in pkts.iter().enumerate() {
                let mut rtp = Vec::new();
                p.packetize(pkt, &mut rtp);
                if i == 10 && rtp.len() > 1 {
                    rtp.remove(rtp.len() / 2); // frame 10 loses a packet
                    dropped = 1;
                }
                for r in rtp {
                    d.push(&r, &mut out).unwrap();
                }
            }
            assert_eq!(out.len(), pkts.len() - dropped);
            let kept: Vec<&Packet> = pkts
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != 10 || dropped == 0)
                .map(|(_, p)| p)
                .collect();
            for (a, b) in kept.iter().zip(&out) {
                assert_eq!(a.data, b.data);
                assert_eq!(a.keyframe, b.keyframe);
                assert_eq!(a.pts - kept[0].pts, b.pts - out[0].pts);
            }
            let cfg = d.take_config().expect("config from the keyframe");
            assert!(d.take_config().is_none());
            let mut t = Track::video(track.codec, cfg);
            if t.width == 0 {
                (t.width, t.height) = d.picture_size().unwrap();
            }
            assert_eq!((t.width, t.height), (320, 240));
            assert_eq!(t.codec_string(), track.codec_string());
        }
    }
}
