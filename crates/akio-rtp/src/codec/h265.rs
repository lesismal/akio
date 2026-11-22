//! H.265 payload format (RFC 7798), without DONL (`sprop-max-don-diff` 0).

use super::h264::{START_CODE, annexb_nals};
use super::{CodecError, Depacketizer, Packetizer};

const AP: u8 = 48;
const FU: u8 = 49;
const PACI: u8 = 50;
const VPS: u8 = 32;
const SPS: u8 = 33;

fn nal_type(b0: u8) -> u8 {
    (b0 >> 1) & 0x3f
}

/// Whether the packetizer sends this NAL unit (a 2-byte header and not a packet type).
pub(crate) fn sendable(nal: &[u8]) -> bool {
    nal.first().is_some_and(|b| nal_type(*b) < AP) && nal.len() >= 2
}

/// H.265 packetizer. Input is Annex-B. NAL units that fit are aggregated greedily into
/// aggregation packets (type 48; a run of one is sent as a single NAL unit packet), units
/// larger than `mtu` are split into fragmentation units (type 49). Units shorter than the
/// 2-byte NAL header and types 48..=63 (packet types in RFC 7798) are dropped. The minimum
/// `mtu` is 4.
#[derive(Debug, Default, Clone)]
pub struct H265Packetizer {
    _priv: (),
}

impl H265Packetizer {
    /// A new packetizer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

fn flush_ap(pending: &mut Vec<&[u8]>, out: &mut Vec<Vec<u8>>) {
    match pending.as_slice() {
        [] => {}
        [one] => out.push(one.to_vec()),
        many => {
            // F: OR of the units; LayerId and TID: the lowest of the units.
            let (mut f, mut layer, mut tid) = (0u8, u8::MAX, u8::MAX);
            for n in many {
                let (a, b) = (
                    n.first().copied().unwrap_or(0),
                    n.get(1).copied().unwrap_or(0),
                );
                f |= a & 0x80;
                layer = layer.min(((a & 1) << 5) | (b >> 3));
                tid = tid.min(b & 0x07);
            }
            let mut p = vec![f | (AP << 1) | (layer >> 5), ((layer & 0x1f) << 3) | tid];
            for n in many {
                p.extend_from_slice(&(n.len() as u16).to_be_bytes());
                p.extend_from_slice(n);
            }
            out.push(p);
        }
    }
    pending.clear();
}

impl Packetizer for H265Packetizer {
    fn packetize(&mut self, mtu: usize, frame: &[u8]) -> Vec<(Vec<u8>, bool)> {
        let mtu = mtu.min(usize::from(u16::MAX));
        if mtu < 4 {
            return Vec::new();
        }
        let mut out: Vec<Vec<u8>> = Vec::new();
        let mut pending: Vec<&[u8]> = Vec::new();
        let mut pending_len = 2; // payload header
        for nal in annexb_nals(frame).into_iter().filter(|n| sendable(n)) {
            if nal.len() <= mtu {
                if !pending.is_empty() && pending_len + 2 + nal.len() > mtu {
                    flush_ap(&mut pending, &mut out);
                    pending_len = 2;
                }
                pending.push(nal);
                pending_len += 2 + nal.len();
                continue;
            }
            flush_ap(&mut pending, &mut out);
            pending_len = 2;
            let (a, b, body) = (nal[0], nal[1], &nal[2..]);
            let chunks = body.chunks(mtu - 3);
            let n = chunks.len();
            for (i, c) in chunks.enumerate() {
                let mut fu = nal_type(a);
                if i == 0 {
                    fu |= 0x80;
                } else if i + 1 == n {
                    fu |= 0x40;
                }
                let mut p = Vec::with_capacity(3 + c.len());
                p.extend_from_slice(&[(a & 0x81) | (FU << 1), b, fu]);
                p.extend_from_slice(c);
                out.push(p);
            }
        }
        flush_ap(&mut pending, &mut out);
        let n = out.len();
        out.into_iter()
            .enumerate()
            .map(|(i, p)| (p, i + 1 == n))
            .collect()
    }
}

/// H.265 depacketizer: single NAL unit, aggregation and fragmentation unit packets to
/// Annex-B with 4-byte start codes. PACI (50) and reserved types are errors.
#[derive(Debug, Default, Clone)]
pub struct H265Depacketizer {
    in_fu: bool,
}

impl H265Depacketizer {
    /// A new depacketizer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

fn nal_types(payload: &[u8], mut f: impl FnMut(u8)) {
    let (Some(&b0), Some(_)) = (payload.first(), payload.get(1)) else {
        return;
    };
    match nal_type(b0) {
        AP => {
            let mut pos = 2;
            while let (Some(&a), Some(&b)) = (payload.get(pos), payload.get(pos + 1)) {
                let len = usize::from(u16::from_be_bytes([a, b]));
                if let Some(&h) = payload.get(pos + 2).filter(|_| len > 0) {
                    f(nal_type(h));
                }
                pos += 2 + len;
            }
        }
        FU => {
            if let Some(&fu) = payload.get(2).filter(|fu| *fu & 0x80 != 0) {
                f(fu & 0x3f);
            }
        }
        PACI..=63 => {}
        t => f(t),
    }
}

impl Depacketizer for H265Depacketizer {
    fn depacketize(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), CodecError> {
        let [b0, b1, rest @ ..] = payload else {
            return Err(CodecError::Truncated);
        };
        match nal_type(*b0) {
            AP => {
                self.in_fu = false;
                let mut rest = rest;
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
            FU => {
                let [fu, data @ ..] = rest else {
                    return Err(CodecError::Truncated);
                };
                if fu & 0x80 != 0 {
                    out.extend_from_slice(&START_CODE);
                    out.push((b0 & 0x81) | ((fu & 0x3f) << 1));
                    out.push(*b1);
                    self.in_fu = true;
                } else if !self.in_fu {
                    return Err(CodecError::FragmentWithoutStart);
                }
                out.extend_from_slice(data);
                if fu & 0x40 != 0 {
                    self.in_fu = false;
                }
            }
            t @ PACI..=63 => return Err(CodecError::UnsupportedType(t)),
            _ => {
                self.in_fu = false;
                out.extend_from_slice(&START_CODE);
                out.extend_from_slice(payload);
            }
        }
        Ok(())
    }

    fn is_frame_start(&self, payload: &[u8]) -> bool {
        match payload.first().map(|b| nal_type(*b)) {
            _ if payload.len() < 2 => false,
            Some(FU) => payload.get(2).is_some_and(|fu| fu & 0x80 != 0),
            Some(t) => t < PACI,
            None => false,
        }
    }

    fn is_frame_end(&self, _payload: &[u8], marker: bool) -> bool {
        marker
    }

    fn is_keyframe(&self, payload: &[u8]) -> bool {
        let mut key = false;
        nal_types(payload, |t| {
            key |= (16..=21).contains(&t) || t == VPS || t == SPS;
        });
        key
    }

    fn reset(&mut self) {
        self.in_fu = false;
    }
}
