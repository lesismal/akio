//! H.264 payload format (RFC 6184, packetization-mode 1).

use super::{CodecError, Depacketizer, Packetizer};

const STAP_A: u8 = 24;
const FU_A: u8 = 28;
const FU_B: u8 = 29;
const IDR: u8 = 5;
const SPS: u8 = 7;
const AUD: u8 = 9;
const FILLER: u8 = 12;

pub(crate) const START_CODE: [u8; 4] = [0, 0, 0, 1];

/// Position of the next `00 00 01` at or after `from`.
fn find_start(data: &[u8], from: usize) -> Option<usize> {
    let tail = data.get(from..)?;
    tail.windows(3)
        .position(|w| w == [0, 0, 1])
        .map(|p| p + from)
}

fn trim_zeros(mut nal: &[u8]) -> &[u8] {
    while let [rest @ .., 0] = nal {
        nal = rest;
    }
    nal
}

/// NAL units of an Annex-B byte stream (3- or 4-byte start codes). Bytes before the first
/// start code are ignored; trailing zero bytes of each unit (`trailing_zero_8bits`, the extra
/// zero of a 4-byte start code) are removed; empty units are skipped. Input without any start
/// code is one NAL unit.
pub(crate) fn annexb_nals(data: &[u8]) -> Vec<&[u8]> {
    fn push<'a>(out: &mut Vec<&'a [u8]>, n: &'a [u8]) {
        let n = trim_zeros(n);
        if !n.is_empty() {
            out.push(n);
        }
    }
    let mut out = Vec::new();
    let Some(first) = find_start(data, 0) else {
        push(&mut out, data);
        return out;
    };
    let mut pos = first + 3;
    while let Some(s) = find_start(data, pos) {
        push(&mut out, data.get(pos..s).unwrap_or_default());
        pos = s + 3;
    }
    push(&mut out, data.get(pos..).unwrap_or_default());
    out
}

/// Whether the packetizer sends this NAL unit: AUD and filler data are dropped like browsers
/// do, and types 0 and 24..=31 (unspecified; RFC 6184 uses them for packet types) cannot be
/// carried as single NAL unit packets.
pub(crate) fn sendable(nal: &[u8]) -> bool {
    let t = nal.first().map_or(0, |b| b & 0x1f);
    !matches!(t, 0 | AUD | FILLER | 24..=31)
}

/// H.264 packetizer (packetization-mode 1). Input is Annex-B. NAL units that fit are
/// aggregated greedily into STAP-A packets (a run of one is sent as a single NAL unit packet,
/// so SPS and PPS ahead of a large IDR become one STAP-A, as pion and libwebrtc send), units
/// larger than `mtu` are split into FU-A packets. AUD (9) and filler (12) units are dropped.
/// The minimum `mtu` is 3.
#[derive(Debug, Default, Clone)]
pub struct H264Packetizer {
    _priv: (),
}

impl H264Packetizer {
    /// A new packetizer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

fn flush_stap(pending: &mut Vec<&[u8]>, out: &mut Vec<Vec<u8>>) {
    match pending.as_slice() {
        [] => {}
        [one] => out.push(one.to_vec()),
        many => {
            let mut hdr = STAP_A;
            for n in many {
                let b = n.first().copied().unwrap_or(0);
                hdr |= b & 0x80;
                hdr = (hdr & !0x60) | (hdr & 0x60).max(b & 0x60);
            }
            let mut p = vec![hdr];
            for n in many {
                p.extend_from_slice(&(n.len() as u16).to_be_bytes());
                p.extend_from_slice(n);
            }
            out.push(p);
        }
    }
    pending.clear();
}

impl Packetizer for H264Packetizer {
    fn packetize(&mut self, mtu: usize, frame: &[u8]) -> Vec<(Vec<u8>, bool)> {
        let mtu = mtu.min(usize::from(u16::MAX));
        if mtu < 3 {
            return Vec::new();
        }
        let mut out: Vec<Vec<u8>> = Vec::new();
        let mut pending: Vec<&[u8]> = Vec::new();
        let mut pending_len = 1; // STAP-A header
        for nal in annexb_nals(frame).into_iter().filter(|n| sendable(n)) {
            if nal.len() <= mtu {
                if !pending.is_empty() && pending_len + 2 + nal.len() > mtu {
                    flush_stap(&mut pending, &mut out);
                    pending_len = 1;
                }
                pending.push(nal);
                pending_len += 2 + nal.len();
                continue;
            }
            flush_stap(&mut pending, &mut out);
            pending_len = 1;
            let (h, body) = (nal[0], &nal[1..]);
            let chunks = body.chunks(mtu - 2);
            let n = chunks.len();
            for (i, c) in chunks.enumerate() {
                let mut fu = h & 0x1f;
                if i == 0 {
                    fu |= 0x80;
                } else if i + 1 == n {
                    fu |= 0x40;
                }
                let mut p = Vec::with_capacity(2 + c.len());
                p.push((h & 0xe0) | FU_A);
                p.push(fu);
                p.extend_from_slice(c);
                out.push(p);
            }
        }
        flush_stap(&mut pending, &mut out);
        let n = out.len();
        out.into_iter()
            .enumerate()
            .map(|(i, p)| (p, i + 1 == n))
            .collect()
    }
}

/// H.264 depacketizer: single NAL unit, STAP-A and FU-A packets to Annex-B with 4-byte start
/// codes. FU-B packets are ignored; STAP-B, MTAP and reserved types are errors.
#[derive(Debug, Default, Clone)]
pub struct H264Depacketizer {
    in_fu: bool,
}

impl H264Depacketizer {
    /// A new depacketizer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Visits the NAL unit headers (first byte) of a single NAL or STAP-A packet, or the
/// reconstructed header of an FU-A start fragment.
fn nal_types(payload: &[u8], mut f: impl FnMut(u8)) {
    let Some(&b0) = payload.first() else { return };
    match b0 & 0x1f {
        1..=23 => f(b0 & 0x1f),
        STAP_A => {
            let mut pos = 1;
            while let (Some(&a), Some(&b)) = (payload.get(pos), payload.get(pos + 1)) {
                let len = usize::from(u16::from_be_bytes([a, b]));
                if let Some(&h) = payload.get(pos + 2).filter(|_| len > 0) {
                    f(h & 0x1f);
                }
                pos += 2 + len;
            }
        }
        FU_A => {
            if let Some(&fu) = payload.get(1).filter(|fu| *fu & 0x80 != 0) {
                f(fu & 0x1f);
            }
        }
        _ => {}
    }
}

impl Depacketizer for H264Depacketizer {
    fn depacketize(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), CodecError> {
        let b0 = *payload.first().ok_or(CodecError::Truncated)?;
        match b0 & 0x1f {
            1..=23 => {
                self.in_fu = false;
                out.extend_from_slice(&START_CODE);
                out.extend_from_slice(payload);
            }
            STAP_A => {
                self.in_fu = false;
                let mut rest = &payload[1..];
                while !rest.is_empty() {
                    let [a, b, tail @ ..] = rest else {
                        return Err(CodecError::Truncated);
                    };
                    let len = usize::from(u16::from_be_bytes([*a, *b]));
                    if tail.len() < len {
                        return Err(CodecError::Truncated);
                    }
                    let (nal, tail) = tail.split_at(len);
                    if !nal.is_empty() {
                        out.extend_from_slice(&START_CODE);
                        out.extend_from_slice(nal);
                    }
                    rest = tail;
                }
            }
            FU_A => {
                let fu = *payload.get(1).ok_or(CodecError::Truncated)?;
                let data = &payload[2..];
                if fu & 0x80 != 0 {
                    out.extend_from_slice(&START_CODE);
                    out.push((b0 & 0xe0) | (fu & 0x1f));
                    self.in_fu = true;
                } else if !self.in_fu {
                    return Err(CodecError::FragmentWithoutStart);
                }
                out.extend_from_slice(data);
                if fu & 0x40 != 0 {
                    self.in_fu = false;
                }
            }
            FU_B => {}
            t => return Err(CodecError::UnsupportedType(t)),
        }
        Ok(())
    }

    fn is_frame_start(&self, payload: &[u8]) -> bool {
        match payload.first().map(|b| b & 0x1f) {
            Some(FU_A | FU_B) => payload.get(1).is_some_and(|fu| fu & 0x80 != 0),
            Some(1..=24) => true,
            _ => false,
        }
    }

    fn is_frame_end(&self, _payload: &[u8], marker: bool) -> bool {
        marker
    }

    fn is_keyframe(&self, payload: &[u8]) -> bool {
        let mut key = false;
        nal_types(payload, |t| key |= t == IDR || t == SPS);
        key
    }

    fn reset(&mut self) {
        self.in_fu = false;
    }
}
