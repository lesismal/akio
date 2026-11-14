//! RTP fixed header (RFC 3550 §5.1) and header extensions (RFC 8285 one-byte and two-byte
//! forms) with the extensions WebRTC negotiates.

/// A header extension known to this crate, identified in SDP (`a=extmap`) by its URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Extension {
    /// `urn:ietf:params:rtp-hdrext:sdes:mid` (RFC 8843): the media identification tag.
    Mid,
    /// `urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id` (RFC 8852): the simulcast RID.
    RtpStreamId,
    /// `urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id` (RFC 8852): RID of the stream
    /// an RTX/FEC stream repairs.
    RepairedRtpStreamId,
    /// `http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time`: 24-bit 6.18 fixed-point
    /// seconds.
    AbsSendTime,
    /// `http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01`: the 16-bit
    /// transport-wide sequence number.
    TransportCc,
    /// `urn:ietf:params:rtp-hdrext:ssrc-audio-level` (RFC 6464): voice activity and level.
    AudioLevel,
    /// `urn:3gpp:video-orientation` (3GPP TS 26.114): the CVO byte.
    VideoOrientation,
    /// `urn:ietf:params:rtp-hdrext:toffset` (RFC 5450): 24-bit signed transmission offset.
    TransmissionOffset,
    /// `http://www.webrtc.org/experiments/rtp-hdrext/playout-delay`: minimum and maximum
    /// playout delay in 10 ms units (12 bits each).
    PlayoutDelay,
}

impl Extension {
    /// Every extension.
    pub const ALL: [Extension; 9] = [
        Extension::Mid,
        Extension::RtpStreamId,
        Extension::RepairedRtpStreamId,
        Extension::AbsSendTime,
        Extension::TransportCc,
        Extension::AudioLevel,
        Extension::VideoOrientation,
        Extension::TransmissionOffset,
        Extension::PlayoutDelay,
    ];

    /// The extension whose `a=extmap` URI is `uri`.
    #[must_use]
    pub fn from_uri(uri: &str) -> Option<Extension> {
        Extension::ALL.into_iter().find(|e| e.uri() == uri)
    }

    /// The `a=extmap` URI.
    #[must_use]
    pub fn uri(self) -> &'static str {
        match self {
            Extension::Mid => "urn:ietf:params:rtp-hdrext:sdes:mid",
            Extension::RtpStreamId => "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
            Extension::RepairedRtpStreamId => {
                "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id"
            }
            Extension::AbsSendTime => "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
            Extension::TransportCc => {
                "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"
            }
            Extension::AudioLevel => "urn:ietf:params:rtp-hdrext:ssrc-audio-level",
            Extension::VideoOrientation => "urn:3gpp:video-orientation",
            Extension::TransmissionOffset => "urn:ietf:params:rtp-hdrext:toffset",
            Extension::PlayoutDelay => "http://www.webrtc.org/experiments/rtp-hdrext/playout-delay",
        }
    }
}

/// The negotiated mapping between extension ids (1..=255) and [`Extension`]s; one id per
/// extension and one extension per id.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtensionMap {
    entries: Vec<(u8, Extension)>,
}

impl ExtensionMap {
    /// An empty map.
    #[must_use]
    pub fn new() -> ExtensionMap {
        ExtensionMap::default()
    }

    /// The ids Chrome offers for audio: 1 audio level, 2 abs-send-time, 3 transport-cc, 4 mid.
    #[must_use]
    pub fn default_audio() -> ExtensionMap {
        let mut m = ExtensionMap::new();
        m.insert(1, Extension::AudioLevel);
        m.insert(2, Extension::AbsSendTime);
        m.insert(3, Extension::TransportCc);
        m.insert(4, Extension::Mid);
        m
    }

    /// The ids Chrome offers for video: 2 abs-send-time, 3 transport-cc, 4 mid, 5 playout
    /// delay, 10 rtp-stream-id, 11 repaired-rtp-stream-id, 13 video orientation, 14 toffset.
    #[must_use]
    pub fn default_video() -> ExtensionMap {
        let mut m = ExtensionMap::new();
        m.insert(2, Extension::AbsSendTime);
        m.insert(3, Extension::TransportCc);
        m.insert(4, Extension::Mid);
        m.insert(5, Extension::PlayoutDelay);
        m.insert(10, Extension::RtpStreamId);
        m.insert(11, Extension::RepairedRtpStreamId);
        m.insert(13, Extension::VideoOrientation);
        m.insert(14, Extension::TransmissionOffset);
        m
    }

    /// Maps `id` to `ext`, replacing any previous mapping of either. Id 0 is reserved and
    /// ignored.
    pub fn insert(&mut self, id: u8, ext: Extension) {
        if id == 0 {
            return;
        }
        self.entries.retain(|&(i, e)| i != id && e != ext);
        self.entries.push((id, ext));
        self.entries.sort_unstable_by_key(|&(i, _)| i);
    }

    /// Removes the mapping of `ext`.
    pub fn remove(&mut self, ext: Extension) {
        self.entries.retain(|&(_, e)| e != ext);
    }

    /// The id of `ext`.
    #[must_use]
    pub fn id_of(&self, ext: Extension) -> Option<u8> {
        self.entries
            .iter()
            .find(|&&(_, e)| e == ext)
            .map(|&(i, _)| i)
    }

    /// The extension mapped to `id`.
    #[must_use]
    pub fn get(&self, id: u8) -> Option<Extension> {
        self.entries
            .iter()
            .find(|&&(i, _)| i == id)
            .map(|&(_, e)| e)
    }

    /// `(id, extension)` pairs in id order.
    pub fn iter(&self) -> impl Iterator<Item = (u8, Extension)> + '_ {
        self.entries.iter().copied()
    }

    /// Whether no extension is mapped.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Values of the known header extensions of one packet. Only extensions mapped in the
/// [`ExtensionMap`] are read and written.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtensionValues {
    /// MID (SDES).
    pub mid: Option<String>,
    /// RID (SDES rtp-stream-id).
    pub rid: Option<String>,
    /// Repaired RID (SDES repaired-rtp-stream-id).
    pub rrid: Option<String>,
    /// abs-send-time: 24 bits, 6.18 fixed-point seconds (see [`abs_send_time`]).
    pub abs_send_time: Option<u32>,
    /// Transport-wide sequence number.
    pub transport_cc: Option<u16>,
    /// `(voice_activity, level)`: level in -dBov, 0..=127.
    pub audio_level: Option<(bool, u8)>,
    /// The raw CVO byte (camera, flip, rotation bits).
    pub video_orientation: Option<u8>,
    /// Transmission offset in RTP timestamp units (24-bit signed).
    pub transmission_offset: Option<i32>,
    /// `(min, max)` playout delay in 10 ms units (12 bits each).
    pub playout_delay: Option<(u16, u16)>,
}

impl ExtensionValues {
    fn set(&mut self, ext: Extension, v: &[u8]) {
        let string = || {
            std::str::from_utf8(v)
                .ok()
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        match (ext, v) {
            (Extension::Mid, _) => self.mid = string().or_else(|| self.mid.take()),
            (Extension::RtpStreamId, _) => self.rid = string().or_else(|| self.rid.take()),
            (Extension::RepairedRtpStreamId, _) => {
                self.rrid = string().or_else(|| self.rrid.take());
            }
            (Extension::AbsSendTime, &[a, b, c]) => {
                self.abs_send_time = Some(u32::from_be_bytes([0, a, b, c]));
            }
            (Extension::TransportCc, &[a, b]) => {
                self.transport_cc = Some(u16::from_be_bytes([a, b]));
            }
            (Extension::AudioLevel, &[a]) => self.audio_level = Some((a & 0x80 != 0, a & 0x7f)),
            (Extension::VideoOrientation, &[a]) => self.video_orientation = Some(a),
            (Extension::TransmissionOffset, &[a, b, c]) => {
                // Sign-extend the 24-bit value.
                self.transmission_offset = Some(i32::from_be_bytes([a, b, c, 0]) >> 8);
            }
            (Extension::PlayoutDelay, &[a, b, c]) => {
                let v = u32::from_be_bytes([0, a, b, c]);
                self.playout_delay = Some(((v >> 12) as u16, (v & 0xfff) as u16));
            }
            _ => {}
        }
    }

    /// `(extension, encoded value)` for every value that is set.
    fn encode(&self) -> Vec<(Extension, Vec<u8>)> {
        let mut out = Vec::new();
        let mut s = |e, v: &Option<String>| {
            if let Some(v) = v {
                if !v.is_empty() && v.len() <= 255 {
                    out.push((e, v.as_bytes().to_vec()));
                }
            }
        };
        s(Extension::Mid, &self.mid);
        s(Extension::RtpStreamId, &self.rid);
        s(Extension::RepairedRtpStreamId, &self.rrid);
        if let Some(v) = self.abs_send_time {
            out.push((Extension::AbsSendTime, v.to_be_bytes()[1..].to_vec()));
        }
        if let Some(v) = self.transport_cc {
            out.push((Extension::TransportCc, v.to_be_bytes().to_vec()));
        }
        if let Some((vad, level)) = self.audio_level {
            out.push((
                Extension::AudioLevel,
                vec![(u8::from(vad) << 7) | (level & 0x7f)],
            ));
        }
        if let Some(v) = self.video_orientation {
            out.push((Extension::VideoOrientation, vec![v]));
        }
        if let Some(v) = self.transmission_offset {
            out.push((Extension::TransmissionOffset, v.to_be_bytes()[1..].to_vec()));
        }
        if let Some((min, max)) = self.playout_delay {
            let v = (u32::from(min & 0xfff) << 12) | u32::from(max & 0xfff);
            out.push((Extension::PlayoutDelay, v.to_be_bytes()[1..].to_vec()));
        }
        out
    }
}

/// abs-send-time for the time `elapsed` since any epoch (only differences matter): 6.18 fixed
/// point, wrapping every 64 s.
#[must_use]
pub fn abs_send_time(elapsed: std::time::Duration) -> u32 {
    let units = (elapsed.as_nanos() << 18) / 1_000_000_000;
    (units & 0x00ff_ffff) as u32
}

/// A parsed RTP header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RtpHeader {
    /// Marker bit.
    pub marker: bool,
    /// Payload type (7 bits).
    pub payload_type: u8,
    /// Sequence number.
    pub sequence_number: u16,
    /// Timestamp.
    pub timestamp: u32,
    /// Synchronization source.
    pub ssrc: u32,
    /// Contributing sources (at most 15 are written).
    pub csrc: Vec<u32>,
    /// Known header extension values.
    pub ext: ExtensionValues,
    /// Length of the header including CSRCs and the extension block (set by
    /// [`parse`](Self::parse); ignored by [`write`](Self::write)).
    pub header_len: usize,
    /// Number of padding bytes at the end of the packet, including the count byte (0 when
    /// the P bit is clear). [`write`](Self::write) appends this much padding (at most 255).
    pub padding_len: usize,
}

const ONE_BYTE_PROFILE: u16 = 0xbede;

impl RtpHeader {
    /// Parses an RTP packet's header; the payload is `&packet[header_len..packet.len() -
    /// padding_len]`. Unknown and unmapped extensions are skipped, as are values of the wrong
    /// size. `None` when it is not RTP version 2 or a length field runs past the end.
    #[must_use]
    pub fn parse(packet: &[u8], map: &ExtensionMap) -> Option<RtpHeader> {
        let b = packet.get(..12)?;
        if b[0] >> 6 != 2 {
            return None;
        }
        let cc = usize::from(b[0] & 0x0f);
        let mut h = RtpHeader {
            marker: b[1] & 0x80 != 0,
            payload_type: b[1] & 0x7f,
            sequence_number: u16::from_be_bytes([b[2], b[3]]),
            timestamp: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            ssrc: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
            ..RtpHeader::default()
        };
        let csrc = packet.get(12..12 + 4 * cc)?;
        h.csrc = csrc
            .chunks_exact(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        let mut n = 12 + 4 * cc;
        if b[0] & 0x10 != 0 {
            let x = packet.get(n..n + 4)?;
            let profile = u16::from_be_bytes([x[0], x[1]]);
            let len = 4 * usize::from(u16::from_be_bytes([x[2], x[3]]));
            let data = packet.get(n + 4..n + 4 + len)?;
            if profile == ONE_BYTE_PROFILE {
                parse_one_byte(data, map, &mut h.ext);
            } else if profile & 0xfff0 == 0x1000 {
                parse_two_byte(data, map, &mut h.ext);
            }
            n += 4 + len;
        }
        h.header_len = n;
        if b[0] & 0x20 != 0 {
            let pad = usize::from(*packet.last()?);
            if pad == 0 || n + pad > packet.len() {
                return None;
            }
            h.padding_len = pad;
        }
        Some(h)
    }

    /// The payload of `packet` according to this header (from [`parse`](Self::parse)).
    #[must_use]
    pub fn payload<'a>(&self, packet: &'a [u8]) -> &'a [u8] {
        let end = packet.len().saturating_sub(self.padding_len);
        packet.get(self.header_len..end).unwrap_or(&[])
    }

    /// Serializes the header followed by `payload` and `padding_len` bytes of padding.
    /// Extensions are written in id order, in the one-byte form when every id is at most 14 and
    /// every value 1..=16 bytes, the two-byte form otherwise; values of unmapped extensions are
    /// left out.
    #[must_use]
    pub fn write(&self, map: &ExtensionMap, payload: &[u8]) -> Vec<u8> {
        let cc = self.csrc.len().min(15);
        let pad = self.padding_len.min(255);
        let mut exts: Vec<(u8, Vec<u8>)> = self
            .ext
            .encode()
            .into_iter()
            .filter_map(|(e, v)| map.id_of(e).map(|id| (id, v)))
            .collect();
        exts.sort_unstable_by_key(|&(id, _)| id);
        let mut out = Vec::with_capacity(12 + 4 * cc + 64 + payload.len() + pad);
        let mut b0 = 0x80 | cc as u8;
        if pad > 0 {
            b0 |= 0x20;
        }
        if !exts.is_empty() {
            b0 |= 0x10;
        }
        out.push(b0);
        out.push((u8::from(self.marker) << 7) | (self.payload_type & 0x7f));
        out.extend_from_slice(&self.sequence_number.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.ssrc.to_be_bytes());
        for c in &self.csrc[..cc] {
            out.extend_from_slice(&c.to_be_bytes());
        }
        if !exts.is_empty() {
            let one = exts
                .iter()
                .all(|(id, v)| *id <= 14 && (1..=16).contains(&v.len()));
            let start = out.len();
            out.extend_from_slice(&if one { ONE_BYTE_PROFILE } else { 0x1000 }.to_be_bytes());
            out.extend_from_slice(&[0, 0]);
            for (id, v) in &exts {
                if one {
                    out.push((id << 4) | (v.len() as u8 - 1));
                } else {
                    out.push(*id);
                    out.push(v.len() as u8);
                }
                out.extend_from_slice(v);
            }
            while (out.len() - start) % 4 != 0 {
                out.push(0);
            }
            let words = ((out.len() - start - 4) / 4) as u16;
            out[start + 2..start + 4].copy_from_slice(&words.to_be_bytes());
        }
        out.extend_from_slice(payload);
        if pad > 0 {
            out.resize(out.len() + pad - 1, 0);
            out.push(pad as u8);
        }
        out
    }
}

fn parse_one_byte(mut d: &[u8], map: &ExtensionMap, ext: &mut ExtensionValues) {
    while let Some((&b, rest)) = d.split_first() {
        if b == 0 {
            d = rest;
            continue;
        }
        let id = b >> 4;
        if id == 15 {
            return; // RFC 8285 §4.2: stop processing.
        }
        let len = usize::from(b & 0x0f) + 1;
        let Some(v) = rest.get(..len) else {
            return;
        };
        if let Some(e) = map.get(id) {
            ext.set(e, v);
        }
        d = &rest[len..];
    }
}

fn parse_two_byte(mut d: &[u8], map: &ExtensionMap, ext: &mut ExtensionValues) {
    while let Some((&id, rest)) = d.split_first() {
        if id == 0 {
            d = rest;
            continue;
        }
        let Some((&len, rest)) = rest.split_first() else {
            return;
        };
        let len = usize::from(len);
        let Some(v) = rest.get(..len) else {
            return;
        };
        if let Some(e) = map.get(id) {
            ext.set(e, v);
        }
        d = &rest[len..];
    }
}

/// RFC 5761 §4 demultiplexing: whether a packet on a muxed RTP/RTCP flow is RTCP (version 2
/// and a second byte, the RTCP packet type or RTP marker + payload type, in 192..=223).
#[must_use]
pub fn is_rtcp(packet: &[u8]) -> bool {
    match packet {
        [b0, b1, _, _, ..] => b0 >> 6 == 2 && (192..=223).contains(b1),
        _ => false,
    }
}
