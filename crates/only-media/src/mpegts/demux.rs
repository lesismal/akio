//! MPEG-TS demuxer: transport stream bytes back to canonical tracks and packets.
//!
//! [`Demuxer::feed`] takes the stream in pieces of any size (SRT payloads, file reads),
//! resynchronizes on the sync byte, follows the PAT and the first program's PMT (CRCs
//! checked, version changes honoured), reassembles PES packets and converts them:
//!
//! * H.264 / H.265: Annex B to AVCC access units; access unit delimiters dropped, parameter
//!   sets taken out of band into the track's configuration record (a change of parameter sets
//!   is a new list of tracks);
//! * AAC: ADTS frames to raw access units, the `AudioSpecificConfig` built from the header;
//! * Opus: the TS framing (control header, trim fields) removed, `OpusHead` from the
//!   descriptor's channel count;
//! * AV1 (stream type 0x06 with the `AV01` registration descriptor): the start-code format of
//!   AOM "Carriage of AV1 in MPEG-2 TS" back to canonical temporal units (sized OBUs, no
//!   temporal delimiter); the configuration record from the first sequence header. GStreamer's
//!   provisional `AV1G` mapping (plain OBUs, no start codes) is read too;
//! * MP3: frames as they are.
//!
//! Tracks come out ([`Event::Tracks`]) once every supported stream of the PMT has its
//! configuration (or after two seconds of stream time for a stream that never gets one,
//! which is then left out); packets seen before are held back (bounded) and follow. Times
//! are the 90 kHz PTS/DTS unwrapped across the 33-bit wrap, converted to nanoseconds.

use std::{collections::HashMap, fmt, sync::Arc};

use crate::{
    av::{Codec, Packet, SECOND, Time, Track, Tracks, from_ticks},
    codec::{aac, av1, h264, h265, opus},
};

use super::{
    PACKET_SIZE, PID_PAT, STREAM_AAC, STREAM_H264, STREAM_H265, STREAM_MP2_AUDIO, STREAM_MP3,
    STREAM_PRIVATE, crc32,
};

/// What the demuxer found.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Event {
    /// The stream's tracks: packets after it index these. Comes again when they change.
    Tracks(Tracks),
    /// One access unit or frame.
    Packet(Packet),
}

/// A malformed transport stream.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DemuxError {
    /// Bytes that are not transport stream packets (no sync byte found in a whole packet).
    NoSync,
}

impl fmt::Display for DemuxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DemuxError::NoSync => f.write_str("mpegts: lost sync"),
        }
    }
}

impl std::error::Error for DemuxError {}

/// Most packets held back while waiting for the tracks.
const MAX_PENDING: usize = 1024;
/// Largest PES reassembled.
const MAX_PES: usize = 8 << 20;
/// How long (stream time) a stream may go without configuration before the tracks are
/// announced without it.
const CONFIG_WAIT: Time = 2 * SECOND;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    H264,
    H265,
    Aac,
    Opus,
    Mp3,
    /// AV1; `true` in the start-code format, `false` as plain OBUs (GStreamer's `AV1G`).
    Av1(bool),
}

#[derive(Debug)]
struct Stream {
    pid: u16,
    kind: Kind,
    channels: u8,
    track: Option<Track>,
    /// Parameter sets seen in band.
    vps: Vec<u8>,
    sps: Vec<u8>,
    pps: Vec<u8>,
    pes: Vec<u8>,
    started: bool,
    /// The expected PES length (0 = unbounded).
    pes_len: usize,
    cc: Option<u8>,
}

/// An incremental MPEG-TS demuxer; see the [module docs](self).
#[derive(Debug, Default)]
pub struct Demuxer {
    buf: Vec<u8>,
    pmt_pid: Option<u16>,
    pmt_version: Option<u8>,
    streams: Vec<Stream>,
    by_pid: HashMap<u16, usize>,
    /// Stream index -> track index in the announced tracks.
    track_of: Vec<Option<usize>>,
    announced: Option<Tracks>,
    pending: Vec<(usize, Packet)>,
    first_time: Option<Time>,
    last_raw: Option<i64>,
    unwrapped: i64,
}

impl Demuxer {
    /// A demuxer waiting for the PAT.
    pub fn new() -> Demuxer {
        Demuxer::default()
    }

    /// The tracks announced last, if any.
    pub fn tracks(&self) -> Option<&Tracks> {
        self.announced.as_ref()
    }

    /// Feeds bytes; `emit` hears what they complete. Bytes that never hold a sync byte are an
    /// error, after which feeding may go on (the demuxer resynchronizes).
    pub fn feed(&mut self, data: &[u8], emit: &mut dyn FnMut(Event)) -> Result<(), DemuxError> {
        self.buf.extend_from_slice(data);
        let mut p = 0;
        let mut lost = false;
        while self.buf.len() - p >= PACKET_SIZE {
            if self.buf[p] != 0x47 {
                match self.buf[p..].iter().position(|&b| b == 0x47) {
                    Some(k) => {
                        if k >= PACKET_SIZE {
                            lost = true;
                        }
                        p += k;
                        continue;
                    }
                    None => {
                        lost = true;
                        p = self.buf.len();
                        break;
                    }
                }
            }
            let pkt: [u8; PACKET_SIZE] = self.buf[p..p + PACKET_SIZE]
                .try_into()
                .unwrap_or([0; PACKET_SIZE]);
            p += PACKET_SIZE;
            self.packet(&pkt, emit);
        }
        self.buf.drain(..p);
        if lost {
            Err(DemuxError::NoSync)
        } else {
            Ok(())
        }
    }

    /// Completes the PES packets in progress (end of stream).
    pub fn flush(&mut self, emit: &mut dyn FnMut(Event)) {
        for i in 0..self.streams.len() {
            self.finish_pes(i, emit);
        }
        if self.announced.is_none() && !self.streams.is_empty() {
            self.announce(true, emit);
        }
    }

    fn packet(&mut self, p: &[u8; PACKET_SIZE], emit: &mut dyn FnMut(Event)) {
        if p[1] & 0x80 != 0 {
            return; // transport error indicator
        }
        let pusi = p[1] & 0x40 != 0;
        let pid = (u16::from(p[1] & 0x1f) << 8) | u16::from(p[2]);
        let afc = (p[3] >> 4) & 3;
        let cc = p[3] & 0xf;
        let mut off = 4;
        if afc & 2 != 0 {
            off += 1 + usize::from(p[4]);
        }
        if afc & 1 == 0 || off >= PACKET_SIZE {
            return;
        }
        let payload = &p[off..];
        if pid == PID_PAT {
            self.pat(pusi, payload);
        } else if Some(pid) == self.pmt_pid {
            self.pmt(pusi, payload, emit);
        } else if let Some(&i) = self.by_pid.get(&pid) {
            self.es(i, pusi, cc, payload, emit);
        }
    }

    fn section(pusi: bool, payload: &[u8], table_id: u8) -> Option<&[u8]> {
        if !pusi {
            return None; // sections spanning packets are not used by PAT/PMT in practice
        }
        let ptr = usize::from(*payload.first()?);
        let s = payload.get(1 + ptr..)?;
        if *s.first()? != table_id || s.len() < 3 {
            return None;
        }
        let len = (usize::from(s[1] & 0x0f) << 8) | usize::from(s[2]);
        let sec = s.get(..3 + len)?;
        if len < 9 || crc32(sec) != 0 {
            return None;
        }
        Some(sec)
    }

    fn pat(&mut self, pusi: bool, payload: &[u8]) {
        let Some(sec) = Self::section(pusi, payload, 0x00) else {
            return;
        };
        let body = &sec[8..sec.len() - 4];
        for e in body.chunks_exact(4) {
            let program = u16::from_be_bytes([e[0], e[1]]);
            if program != 0 {
                let pid = (u16::from(e[2] & 0x1f) << 8) | u16::from(e[3]);
                if self.pmt_pid != Some(pid) {
                    self.pmt_pid = Some(pid);
                    self.pmt_version = None;
                }
                return;
            }
        }
    }

    fn pmt(&mut self, pusi: bool, payload: &[u8], emit: &mut dyn FnMut(Event)) {
        let Some(sec) = Self::section(pusi, payload, 0x02) else {
            return;
        };
        let version = (sec[5] >> 1) & 0x1f;
        if self.pmt_version == Some(version) {
            return;
        }
        if sec.len() < 16 {
            return;
        }
        let info_len = (usize::from(sec[10] & 0x0f) << 8) | usize::from(sec[11]);
        let Some(mut rest) = sec.get(12 + info_len..sec.len() - 4) else {
            return;
        };
        // Finish what the old program had before replacing it.
        for i in 0..self.streams.len() {
            self.finish_pes(i, emit);
        }
        self.pmt_version = Some(version);
        let mut streams = Vec::new();
        while rest.len() >= 5 {
            let st = rest[0];
            let pid = (u16::from(rest[1] & 0x1f) << 8) | u16::from(rest[2]);
            let es_len = (usize::from(rest[3] & 0x0f) << 8) | usize::from(rest[4]);
            let Some(desc) = rest.get(5..5 + es_len) else {
                break;
            };
            rest = &rest[5 + es_len..];
            let mut opus = false;
            let mut av1 = None;
            let mut channels = 2;
            let mut d = desc;
            while d.len() >= 2 {
                let (tag, n) = (d[0], usize::from(d[1]));
                let Some(body) = d.get(2..2 + n) else { break };
                if tag == 0x05 && body == b"Opus" {
                    opus = true;
                }
                if tag == 0x05 && body == b"AV01" {
                    av1 = Some(true);
                }
                if tag == 0x05 && body == b"AV1G" {
                    av1 = Some(false);
                }
                if tag == 0x7f && body.len() >= 2 && body[0] == 0x80 {
                    channels = body[1].max(1);
                }
                d = &d[2 + n..];
            }
            let kind = match st {
                STREAM_H264 => Kind::H264,
                STREAM_H265 => Kind::H265,
                STREAM_AAC => Kind::Aac,
                STREAM_MP3 | STREAM_MP2_AUDIO => Kind::Mp3,
                STREAM_PRIVATE if opus => Kind::Opus,
                STREAM_PRIVATE if av1.is_some() => Kind::Av1(av1 == Some(true)),
                _ => continue,
            };
            let track = (kind == Kind::Opus).then(|| {
                Track::audio(
                    Codec::Opus,
                    opus::Head::new(channels).encode(),
                    48_000,
                    channels,
                )
            });
            streams.push(Stream {
                pid,
                kind,
                channels,
                track,
                vps: Vec::new(),
                sps: Vec::new(),
                pps: Vec::new(),
                pes: Vec::new(),
                started: false,
                pes_len: 0,
                cc: None,
            });
        }
        self.by_pid = streams
            .iter()
            .enumerate()
            .map(|(i, s)| (s.pid, i))
            .collect();
        self.streams = streams;
        self.track_of = vec![None; self.streams.len()];
        self.announced = None;
        self.pending.clear();
        self.first_time = None;
    }

    fn es(&mut self, i: usize, pusi: bool, cc: u8, payload: &[u8], emit: &mut dyn FnMut(Event)) {
        let s = &mut self.streams[i];
        if let Some(prev) = s.cc {
            if cc == prev {
                return; // duplicate packet
            }
            if cc != (prev + 1) & 0xf && !pusi {
                // Discontinuity: the PES in progress is damaged.
                s.cc = Some(cc);
                s.started = false;
                s.pes.clear();
                return;
            }
        }
        s.cc = Some(cc);
        if pusi {
            self.finish_pes(i, emit);
            let s = &mut self.streams[i];
            s.started = true;
            s.pes.clear();
            s.pes_len = 0;
            if payload.len() >= 6 && payload[..3] == [0, 0, 1] {
                let n = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
                s.pes_len = if n == 0 { 0 } else { n + 6 };
            }
        }
        let s = &mut self.streams[i];
        if !s.started {
            return;
        }
        if s.pes.len() + payload.len() > MAX_PES {
            s.started = false;
            s.pes.clear();
            return;
        }
        s.pes.extend_from_slice(payload);
        if s.pes_len > 0 && s.pes.len() >= s.pes_len {
            self.finish_pes(i, emit);
        }
    }

    /// Unwraps a 33-bit timestamp against the latest one seen (B-frame reordering, which
    /// goes back a little, does not move the reference).
    fn unwrap_ts(&mut self, raw: i64) -> i64 {
        let Some(last) = self.last_raw else {
            self.last_raw = Some(raw);
            self.unwrapped = raw;
            return raw;
        };
        let d = signed33(raw - last);
        let v = self.unwrapped + d;
        if d > 0 {
            self.last_raw = Some(raw);
            self.unwrapped = v;
        }
        v
    }

    fn finish_pes(&mut self, i: usize, emit: &mut dyn FnMut(Event)) {
        let s = &mut self.streams[i];
        if !s.started || s.pes.is_empty() {
            return;
        }
        s.started = false;
        let pes = std::mem::take(&mut s.pes);
        let Some((pts, dts, body)) = parse_pes(&pes) else {
            return;
        };
        let Some(pts) = pts else { return };
        let dts = dts.unwrap_or(pts);
        let dts_u = self.unwrap_ts(dts);
        let pts_u = dts_u + signed33(pts - dts);
        let dts_ns = from_ticks(dts_u, 90_000);
        let pts_ns = from_ticks(pts_u, 90_000);
        let kind = self.streams[i].kind;
        match kind {
            Kind::H264 | Kind::H265 => {
                self.video(i, kind == Kind::H265, dts_ns, pts_ns, body, emit);
            }
            Kind::Aac => self.aac(i, pts_ns, body, emit),
            Kind::Opus => self.opus(i, pts_ns, body, emit),
            Kind::Mp3 => self.mp3(i, pts_ns, body, emit),
            Kind::Av1(start_codes) => self.av1(i, start_codes, dts_ns, pts_ns, body, emit),
        }
        self.streams[i].pes = pes;
        self.streams[i].pes.clear();
    }

    fn video(
        &mut self,
        i: usize,
        hevc: bool,
        dts: Time,
        pts: Time,
        body: &[u8],
        emit: &mut dyn FnMut(Event),
    ) {
        let s = &mut self.streams[i];
        let mut au = Vec::with_capacity(body.len() + 16);
        let mut key = false;
        let mut params_changed = false;
        for n in h264::split_annexb(body) {
            if n.is_empty() {
                continue;
            }
            if hevc {
                let t = h265::nal_type(n[0]);
                match t {
                    h265::NAL_AUD => continue,
                    h265::NAL_VPS => {
                        params_changed |= set(&mut s.vps, n);
                        continue;
                    }
                    h265::NAL_SPS => {
                        params_changed |= set(&mut s.sps, n);
                        continue;
                    }
                    h265::NAL_PPS => {
                        params_changed |= set(&mut s.pps, n);
                        continue;
                    }
                    _ => key |= h265::is_irap(t),
                }
            } else {
                let t = h264::nal_type(n[0]);
                match t {
                    h264::NAL_AUD => continue,
                    h264::NAL_SPS => {
                        params_changed |= set(&mut s.sps, n);
                        continue;
                    }
                    h264::NAL_PPS => {
                        params_changed |= set(&mut s.pps, n);
                        continue;
                    }
                    h264::NAL_IDR => key = true,
                    _ => {}
                }
            }
            h264::push_avcc(&mut au, n);
        }
        if params_changed && !s.sps.is_empty() && !s.pps.is_empty() {
            let track = if hevc {
                (!s.vps.is_empty())
                    .then(|| h265::Config::from_sets(&s.vps, &s.sps, &s.pps))
                    .flatten()
                    .map(|c| Track::video(Codec::H265, c.encode()))
            } else {
                Some(Track::video(
                    Codec::H264,
                    h264::Config::from_sets(&s.sps, &s.pps).encode(),
                ))
            };
            if let Some(t) = track {
                if s.track.as_ref() != Some(&t) {
                    let had = s.track.is_some();
                    s.track = Some(t);
                    if had && self.announced.is_some() {
                        self.announce(false, emit);
                    }
                }
            }
        }
        if au.is_empty() {
            return;
        }
        self.out(i, Packet::new(0, dts, pts, key, au), emit);
    }

    fn av1(
        &mut self,
        i: usize,
        start_codes: bool,
        dts: Time,
        pts: Time,
        body: &[u8],
        emit: &mut dyn FnMut(Event),
    ) {
        let tu = if start_codes {
            av1::read_start_codes(body)
        } else {
            av1::to_sample(body).into_owned()
        };
        if tu.is_empty() {
            return;
        }
        let key = av1::is_keyframe(&tu);
        if key {
            let s = &mut self.streams[i];
            if let Some(t) = Track::video_from_keyframe(Codec::Av1, &tu) {
                if s.track.as_ref() != Some(&t) {
                    let had = s.track.is_some();
                    s.track = Some(t);
                    if had && self.announced.is_some() {
                        self.announce(false, emit);
                    }
                }
            }
        }
        self.out(i, Packet::new(0, dts, pts, key, tu), emit);
    }

    fn aac(&mut self, i: usize, pts: Time, body: &[u8], emit: &mut dyn FnMut(Event)) {
        let Ok((frames, _)) = aac::split_adts(body) else {
            return;
        };
        let mut t = pts;
        for f in frames {
            let s = &mut self.streams[i];
            let asc = f.config.encode();
            if s.track.as_ref().is_none_or(|tr| tr.config != asc) {
                let had = s.track.is_some();
                s.track = Some(Track::aac(asc));
                if had && self.announced.is_some() {
                    self.announce(false, emit);
                }
            }
            let rate = f.config.sample_rate.max(1);
            self.out(i, Packet::new(0, t, t, true, f.payload.to_vec()), emit);
            t += from_ticks(i64::from(aac::FRAME_SAMPLES), rate);
        }
    }

    fn opus(&mut self, i: usize, pts: Time, body: &[u8], emit: &mut dyn FnMut(Event)) {
        let mut b = body;
        let mut t = pts;
        while b.len() >= 2 {
            if b[0] != 0x7f || b[1] & 0xe0 != 0xe0 {
                return;
            }
            let (start_trim, end_trim, ext) =
                (b[1] & 0x10 != 0, b[1] & 0x08 != 0, b[1] & 0x04 != 0);
            let mut p = 2;
            let mut size = 0usize;
            loop {
                let Some(&v) = b.get(p) else { return };
                p += 1;
                size += usize::from(v);
                if v != 0xff {
                    break;
                }
            }
            if start_trim {
                p += 2;
            }
            if end_trim {
                p += 2;
            }
            if ext {
                let Some(&n) = b.get(p) else { return };
                p += 1 + usize::from(n);
            }
            let Some(frame) = b.get(p..p + size) else {
                return;
            };
            let frame = frame.to_vec();
            let samples = opus::packet_samples(&frame);
            self.out(i, Packet::new(0, t, t, true, frame), emit);
            t += from_ticks(i64::from(samples), 48_000);
            b = &b[p + size..];
        }
    }

    fn mp3(&mut self, i: usize, pts: Time, body: &[u8], emit: &mut dyn FnMut(Event)) {
        let s = &mut self.streams[i];
        if s.track.is_none() {
            let (rate, ch) = mp3_header(body).unwrap_or((44_100, 2));
            s.track = Some(Track::audio(Codec::Mp3, Vec::new(), rate, ch));
            s.channels = ch;
        }
        self.out(i, Packet::new(0, pts, pts, true, body.to_vec()), emit);
    }

    fn out(&mut self, i: usize, mut pkt: Packet, emit: &mut dyn FnMut(Event)) {
        if self.announced.is_none() {
            let first = *self.first_time.get_or_insert(pkt.dts);
            let all = self.streams.iter().all(|s| s.track.is_some());
            if all || pkt.dts - first > CONFIG_WAIT {
                self.announce(true, emit);
            }
        }
        if self.announced.is_none() {
            if self.pending.len() < MAX_PENDING {
                self.pending.push((i, pkt));
            }
            return;
        }
        if let Some(Some(t)) = self.track_of.get(i) {
            pkt.track = *t;
            emit(Event::Packet(pkt));
        }
    }

    /// Announces the tracks the streams have; `first` also flushes the held packets.
    fn announce(&mut self, first: bool, emit: &mut dyn FnMut(Event)) {
        let mut tracks = Vec::new();
        for (i, s) in self.streams.iter().enumerate() {
            self.track_of[i] = s.track.as_ref().map(|t| {
                tracks.push(t.clone());
                tracks.len() - 1
            });
        }
        if tracks.is_empty() {
            return;
        }
        let tracks: Tracks = Arc::from(tracks);
        self.announced = Some(tracks.clone());
        emit(Event::Tracks(tracks));
        if first {
            for (i, mut p) in std::mem::take(&mut self.pending) {
                if let Some(Some(t)) = self.track_of.get(i) {
                    p.track = *t;
                    emit(Event::Packet(p));
                }
            }
        }
    }
}

fn signed33(d: i64) -> i64 {
    let d = d & ((1 << 33) - 1);
    if d >= 1 << 32 { d - (1 << 33) } else { d }
}

fn set(slot: &mut Vec<u8>, v: &[u8]) -> bool {
    if slot.as_slice() == v {
        return false;
    }
    *slot = v.to_vec();
    true
}

/// PTS, DTS (raw 33-bit ticks) and the payload of a PES packet.
fn parse_pes(b: &[u8]) -> Option<(Option<i64>, Option<i64>, &[u8])> {
    if b.len() < 9 || b[..3] != [0, 0, 1] {
        return None;
    }
    let flags = b[7];
    let hlen = usize::from(b[8]);
    let body_start = 9 + hlen;
    let declared = usize::from(u16::from_be_bytes([b[4], b[5]]));
    let end = if declared == 0 {
        b.len()
    } else {
        (6 + declared).min(b.len())
    };
    let body = b.get(body_start..end)?;
    let ts = |p: usize| -> Option<i64> {
        let t = b.get(p..p + 5)?;
        Some(
            (i64::from((t[0] >> 1) & 7) << 30)
                | (i64::from(t[1]) << 22)
                | (i64::from(t[2] >> 1) << 15)
                | (i64::from(t[3]) << 7)
                | i64::from(t[4] >> 1),
        )
    };
    let (pts, dts) = match flags >> 6 {
        2 => (ts(9), None),
        3 => (ts(9), ts(14)),
        _ => (None, None),
    };
    Some((pts, dts, body))
}

/// Sample rate and channels of the first MPEG audio frame header in `b`.
fn mp3_header(b: &[u8]) -> Option<(u32, u8)> {
    let h = b.windows(4).find(|w| w[0] == 0xff && w[1] & 0xe0 == 0xe0)?;
    let version = (h[1] >> 3) & 3;
    let idx = usize::from((h[2] >> 2) & 3);
    let base = [44_100u32, 48_000, 32_000].get(idx)?;
    let rate = match version {
        3 => *base,
        2 => base / 2,
        0 => base / 4,
        _ => return None,
    };
    let ch = if h[3] >> 6 == 3 { 1 } else { 2 };
    Some((rate, ch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        av::{MILLISECOND, to_ticks},
        mpegts::{Muxer, STREAM_PRIVATE},
    };

    fn demux_all(data: &[u8], chunk: usize) -> (Vec<Tracks>, Vec<Packet>) {
        let mut d = Demuxer::new();
        let mut tracks = Vec::new();
        let mut pkts = Vec::new();
        let mut emit = |e: Event| match e {
            Event::Tracks(t) => tracks.push(t),
            Event::Packet(p) => pkts.push(p),
        };
        for c in data.chunks(chunk) {
            d.feed(c, &mut emit).unwrap();
        }
        d.flush(&mut emit);
        (tracks, pkts)
    }

    #[test]
    fn h264_aac_file() {
        let data =
            std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/h264_aac.ts")).unwrap();
        let (tracks, pkts) = demux_all(&data, 1316);
        assert_eq!(tracks.len(), 1);
        let t = &tracks[0];
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].codec, Codec::H264);
        assert_eq!((t[0].width, t[0].height), (320, 240));
        assert_eq!(t[1].codec, Codec::Aac);
        assert_eq!((t[1].sample_rate, t[1].channels), (44_100, 2));
        let video: Vec<_> = pkts.iter().filter(|p| p.track == 0).collect();
        let audio = pkts.iter().filter(|p| p.track == 1).count();
        assert_eq!(video.len(), 50);
        assert!(video[0].keyframe);
        assert_eq!(video.iter().filter(|p| p.keyframe).count(), 2);
        assert!(audio > 80, "{audio}");
        // B-frames: some packets present after they decode.
        assert!(video.iter().any(|p| p.pts > p.dts));
        // AVCC with no parameter sets or AUDs left in band.
        for p in &video {
            for n in h264::avcc_nalus(&p.data) {
                let t = h264::nal_type(n[0]);
                assert!(t != h264::NAL_AUD && t != h264::NAL_SPS && t != h264::NAL_PPS);
            }
        }
        // Same result fed byte by byte in odd pieces.
        let (t2, p2) = demux_all(&data, 777);
        assert_eq!(t2[0], tracks[0]);
        assert_eq!(p2, pkts);
    }

    #[test]
    fn h265_opus_file() {
        let data = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/h265_opus.ts"
        ))
        .unwrap();
        let (tracks, pkts) = demux_all(&data, 188 * 3);
        let t = &tracks[0];
        assert_eq!(t[0].codec, Codec::H265);
        assert_eq!((t[0].width, t[0].height), (320, 240));
        assert_eq!(t[1].codec, Codec::Opus);
        assert_eq!(t[1].sample_rate, 48_000);
        let audio: Vec<_> = pkts.iter().filter(|p| p.track == 1).collect();
        assert!(audio.len() > 90, "{}", audio.len());
        assert_eq!(opus::packet_samples(&audio[0].data), 960);
        assert_eq!(audio[1].pts - audio[0].pts, 20 * MILLISECOND);
        assert!(pkts.iter().find(|p| p.track == 0).unwrap().keyframe);
    }

    #[test]
    fn round_trip_through_the_muxer() {
        let data =
            std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/h264_aac.ts")).unwrap();
        let (tracks, pkts) = demux_all(&data, 4096);
        let mut m = Muxer::new(&tracks[0]);
        let mut ts = Vec::new();
        m.write_tables(&mut ts);
        for p in &pkts {
            m.write_packet(p, &mut ts);
        }
        let (t2, p2) = demux_all(&ts, 1000);
        assert_eq!(t2[0], tracks[0]);
        assert_eq!(p2.len(), pkts.len());
        // Per track the packets are the same (the interleaving may differ: a video PES of
        // unbounded length ends only at the next one).
        for track in 0..2 {
            let a: Vec<_> = pkts.iter().filter(|p| p.track == track).collect();
            let b: Vec<_> = p2.iter().filter(|p| p.track == track).collect();
            assert_eq!(a.len(), b.len());
            for (x, y) in a.iter().zip(&b) {
                // Times survive to the 90 kHz tick (frames after the first of a multi-frame
                // PES carry nanoseconds the TS clock rounds).
                assert_eq!(to_ticks(x.dts, 90_000), to_ticks(y.dts, 90_000));
                assert_eq!(to_ticks(x.pts, 90_000), to_ticks(y.pts, 90_000));
                assert_eq!((x.keyframe, &x.data), (y.keyframe, &y.data));
            }
        }
    }

    #[test]
    fn av1_opus_round_trip() {
        use crate::flv::{Decoder, Demuxer as FlvDemuxer, Event as FlvEvent};
        let data = include_bytes!("../../testdata/av1_opus.flv");
        let mut dec = Decoder::new();
        let (mut tracks, mut pkts) = (None, Vec::new());
        for t in FlvDemuxer::new().feed(data).unwrap() {
            for e in dec.write(t.tag_type, t.ts, &t.body) {
                match e {
                    FlvEvent::Tracks(t) => tracks = Some(t),
                    FlvEvent::Packet(p) => pkts.push(p),
                }
            }
        }
        let mut tracks = tracks.unwrap().to_vec();
        assert_eq!(tracks[0].codec, Codec::Av1);
        // The in-band sequence header (ffmpeg's av1C carries a slightly different one).
        let key = pkts.iter().find(|p| p.track == 0 && p.keyframe).unwrap();
        tracks[0] = Track::video_from_keyframe(Codec::Av1, &key.data).unwrap();
        let mut m = Muxer::new(&tracks);
        assert!(m.carries(0) && m.carries(1));
        let mut ts = Vec::new();
        m.write_tables(&mut ts);
        // The PMT entry: private data, the AV01 registration descriptor, then the AV1 video
        // descriptor.
        let pmt = &ts[188..2 * 188];
        let at = pmt.windows(6).position(|w| w == b"\x05\x04AV01").unwrap();
        assert_eq!(pmt[at - 5], STREAM_PRIVATE);
        assert_eq!(&pmt[at + 6..at + 9], &[0x80, 4, 0x81]);
        // Keyframes without a sequence header get the configuration's.
        let mut stripped = 0;
        for p in &pkts {
            let mut p = p.clone();
            if p.track == 0 && p.keyframe && stripped == 0 {
                let seq = av1::sequence_header_obu(&p.data).unwrap().to_vec();
                let at = p.data.windows(seq.len()).position(|w| w == seq).unwrap();
                p.data.drain(at..at + seq.len());
                stripped += 1;
            }
            m.write_packet(&p, &mut ts);
        }
        assert_eq!(stripped, 1);
        let (t2, p2) = demux_all(&ts, 1316);
        assert_eq!(t2.len(), 1);
        assert_eq!(t2[0][0], tracks[0]);
        assert_eq!(t2[0][1].codec, Codec::Opus);
        let a: Vec<_> = pkts.iter().filter(|p| p.track == 0).collect();
        let b: Vec<_> = p2.iter().filter(|p| p.track == 0).collect();
        assert_eq!(a.len(), b.len());
        assert!(b[0].keyframe);
        for (x, y) in a.iter().zip(&b) {
            assert_eq!((x.keyframe, &x.data), (y.keyframe, &y.data));
            assert_eq!(to_ticks(x.pts, 90_000), to_ticks(y.pts, 90_000));
        }
        // GStreamer's provisional mapping: plain OBUs under `AV1G`.
        let mut g = Vec::new();
        Muxer::new(&tracks[..1]).write_tables(&mut g);
        let pmt = &mut g[188..2 * 188];
        let at = pmt.windows(4).position(|w| w == b"AV01").unwrap();
        pmt[at + 3] = b'G';
        pmt[at + 2] = b'1';
        // Recompute the PMT's CRC.
        let len = (usize::from(pmt[6] & 0x0f) << 8) | usize::from(pmt[7]);
        let crc = crc32(&pmt[5..5 + 3 + len - 4]).to_be_bytes();
        pmt[5 + 3 + len - 4..5 + 3 + len].copy_from_slice(&crc);
        let mut pes = vec![0, 0, 1, 0xbd, 0, 0, 0x84, 0x80, 5];
        pes.extend_from_slice(&[0x21, 0, 1, 0, 1]);
        pes.extend_from_slice(&[0x12, 0x00]);
        pes.extend_from_slice(&a[0].data);
        super::super::mux::write_pes_for_test(&mut g, 0x100, &pes);
        let (t3, p3) = demux_all(&g, 188);
        assert_eq!(t3[0][0], tracks[0]);
        assert_eq!(p3[0].data, a[0].data);
    }

    #[test]
    fn opus_round_trip_and_wrap() {
        let tracks = vec![Track::audio(
            Codec::Opus,
            opus::Head::new(2).encode(),
            48_000,
            2,
        )];
        let mut m = Muxer::new(&tracks);
        let mut ts = Vec::new();
        m.write_tables(&mut ts);
        // Start just before the 33-bit wrap: times keep increasing across it.
        let start = from_ticks((1i64 << 33) - 90_000, 90_000);
        for k in 0..100i64 {
            let t = start + k * 20 * MILLISECOND;
            let mut data = vec![0xfc];
            data.extend(std::iter::repeat_n(k as u8, 300));
            m.write_packet(&Packet::new(0, t, t, true, data), &mut ts);
        }
        let (tr, pkts) = demux_all(&ts, 188);
        assert_eq!(tr[0][0].codec, Codec::Opus);
        assert_eq!(tr[0][0].channels, 2);
        assert_eq!(pkts.len(), 100);
        for w in pkts.windows(2) {
            assert_eq!(w[1].pts - w[0].pts, 20 * MILLISECOND);
        }
        assert_eq!(pkts[7].data.len(), 301);
    }

    #[test]
    fn garbage_and_resync() {
        let data =
            std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/h264_aac.ts")).unwrap();
        let mut d = Demuxer::new();
        let mut n = 0;
        let mut emit = |e: Event| {
            if let Event::Packet(_) = e {
                n += 1;
            }
        };
        assert!(d.feed(&[1u8; 400], &mut emit).is_err());
        let mut bad = data;
        bad[188 * 40 + 100] ^= 0xff; // damage a payload byte
        bad.insert(188 * 60, 0x11); // and lose sync once
        let _ = d.feed(&bad, &mut emit);
        d.flush(&mut emit);
        assert!(n > 100, "{n}");
        assert_eq!(mp3_header(&[0xff, 0xfb, 0x90, 0xc0]), Some((44_100, 1)));
    }
}
