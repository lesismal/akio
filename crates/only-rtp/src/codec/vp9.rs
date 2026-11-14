//! VP9 payload format (RFC 9628).

use super::{CodecError, Depacketizer, Packetizer};

/// Required octet plus the 2-octet PictureID.
const DESC_LEN: usize = 3;
/// Scalability structure written on the first packet of a keyframe: N_S=0 Y=1 G=1, width,
/// height, N_G=1, one picture (TID=0 U=1 R=1, P_DIFF=1).
const SS_LEN: usize = 8;

/// VP9 packetizer in non-flexible mode: `I=1, M=1` 15-bit PictureID incrementing per frame,
/// `B` on the first and `E` on the last payload, `P` from the VP9 frame header, `Z=1`, and a
/// scalability structure with the frame size on the first payload of a keyframe (as pion and
/// libwebrtc do). Frames whose header does not parse are sent as inter frames without SS.
#[derive(Debug, Clone)]
pub struct Vp9Packetizer {
    picture_id: u16,
}

impl Vp9Packetizer {
    /// A packetizer whose first frame uses `picture_id` (masked to 15 bits).
    #[must_use]
    pub fn new(picture_id: u16) -> Self {
        Self {
            picture_id: picture_id & 0x7fff,
        }
    }

    /// The PictureID the next frame will carry.
    #[must_use]
    pub fn picture_id(&self) -> u16 {
        self.picture_id
    }
}

impl Packetizer for Vp9Packetizer {
    fn packetize(&mut self, mtu: usize, frame: &[u8]) -> Vec<(Vec<u8>, bool)> {
        if frame.is_empty() {
            return Vec::new();
        }
        let key = keyframe_size(frame);
        let first_hdr = DESC_LEN + if key.is_some() { SS_LEN } else { 0 };
        if mtu <= first_hdr {
            return Vec::new();
        }
        let pid = self.picture_id;
        self.picture_id = (pid + 1) & 0x7fff;
        let mut out = Vec::new();
        let mut rest = frame;
        while !rest.is_empty() {
            let first = out.is_empty();
            let hdr = if first { first_hdr } else { DESC_LEN };
            let n = rest.len().min(mtu - hdr);
            let (part, tail) = rest.split_at(n);
            rest = tail;
            let mut b0 = 0x81; // I, Z
            if key.is_none() {
                b0 |= 0x40; // P
            }
            if first {
                b0 |= 0x08; // B
            }
            if rest.is_empty() {
                b0 |= 0x04; // E
            }
            let mut p = Vec::with_capacity(hdr + n);
            p.extend_from_slice(&[b0, 0x80 | (pid >> 8) as u8, pid as u8]);
            if let (true, Some((w, h))) = (first, key) {
                p[0] |= 0x02; // V
                p.push(0x18);
                p.extend_from_slice(&w.to_be_bytes());
                p.extend_from_slice(&h.to_be_bytes());
                p.extend_from_slice(&[0x01, 0x14, 0x01]);
            }
            p.extend_from_slice(part);
            out.push((p, rest.is_empty()));
        }
        out
    }
}

/// MSB-first bit reader over a byte slice.
struct Bits<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Bits<'_> {
    fn read(&mut self, n: usize) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..n {
            let byte = *self.buf.get(self.pos / 8)?;
            v = (v << 1) | u32::from((byte >> (7 - self.pos % 8)) & 1);
            self.pos += 1;
        }
        Some(v)
    }
}

/// `Some((width, height))` when `frame` starts with a VP9 keyframe uncompressed header.
fn keyframe_size(frame: &[u8]) -> Option<(u16, u16)> {
    let mut b = Bits { buf: frame, pos: 0 };
    if b.read(2)? != 2 {
        return None; // frame_marker
    }
    let lo = b.read(1)?;
    let hi = b.read(1)?;
    let profile = (hi << 1) | lo;
    if profile == 3 {
        b.read(1)?; // reserved_zero
    }
    if b.read(1)? == 1 {
        return None; // show_existing_frame
    }
    if b.read(1)? == 1 {
        return None; // frame_type: non-key
    }
    b.read(2)?; // show_frame, error_resilient_mode
    if b.read(24)? != 0x49_83_42 {
        return None; // frame_sync_code
    }
    if profile >= 2 {
        b.read(1)?; // ten_or_twelve_bit
    }
    let color_space = b.read(3)?;
    if color_space != 7 {
        b.read(1)?; // color_range
        if profile == 1 || profile == 3 {
            b.read(3)?; // subsampling_x, subsampling_y, reserved_zero
        }
    } else if profile == 1 || profile == 3 {
        b.read(1)?; // reserved_zero
    }
    let w = b.read(16)? as u16;
    let h = b.read(16)? as u16;
    Some((w.wrapping_add(1), h.wrapping_add(1)))
}

/// A parsed VP9 payload descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Descriptor {
    pub(crate) inter: bool,
    pub(crate) begin: bool,
    pub(crate) end: bool,
    /// Spatial layer id when the L octet is present.
    pub(crate) sid: Option<u8>,
    pub(crate) len: usize,
}

fn byte(p: &[u8], pos: usize) -> Result<u8, CodecError> {
    p.get(pos).copied().ok_or(CodecError::Truncated)
}

pub(crate) fn parse_descriptor(p: &[u8]) -> Result<Descriptor, CodecError> {
    let b0 = byte(p, 0)?;
    let (i, inter, l, f, v) = (
        b0 & 0x80 != 0,
        b0 & 0x40 != 0,
        b0 & 0x20 != 0,
        b0 & 0x10 != 0,
        b0 & 0x02 != 0,
    );
    let mut pos = 1;
    if i {
        pos += if byte(p, pos)? & 0x80 != 0 { 2 } else { 1 };
    }
    let mut sid = None;
    if l {
        sid = Some((byte(p, pos)? >> 1) & 0x07);
        pos += if f { 1 } else { 2 }; // non-flexible: TL0PICIDX
    }
    if f && inter {
        // Up to 3 P_DIFF octets, N=1 means another follows.
        let mut n = 0;
        loop {
            let d = byte(p, pos)?;
            pos += 1;
            n += 1;
            if d & 1 == 0 {
                break;
            }
            if n == 3 {
                return Err(CodecError::Malformed("VP9 more than 3 P_DIFF"));
            }
        }
    }
    if v {
        let ss = byte(p, pos)?;
        pos += 1;
        let ns = usize::from(ss >> 5) + 1;
        if ss & 0x10 != 0 {
            pos += 4 * ns; // WIDTH, HEIGHT
        }
        if ss & 0x08 != 0 {
            let ng = byte(p, pos)?;
            pos += 1;
            for _ in 0..ng {
                let r = usize::from((byte(p, pos)? >> 2) & 0x03);
                pos += 1 + r;
            }
        }
    }
    if pos > p.len() {
        return Err(CodecError::Truncated);
    }
    Ok(Descriptor {
        inter,
        begin: b0 & 0x08 != 0,
        end: b0 & 0x04 != 0,
        sid,
        len: pos,
    })
}

/// VP9 depacketizer: strips the payload descriptor (flexible and non-flexible mode, layer
/// indices, reference indices and the scalability structure). Spatial layer frames of one
/// picture are concatenated.
#[derive(Debug, Default, Clone)]
pub struct Vp9Depacketizer {
    _priv: (),
}

impl Vp9Depacketizer {
    /// A new depacketizer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

fn picture_start(d: &Descriptor) -> bool {
    d.begin && d.sid.is_none_or(|s| s == 0)
}

impl Depacketizer for Vp9Depacketizer {
    fn depacketize(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), CodecError> {
        let d = parse_descriptor(payload)?;
        out.extend_from_slice(payload.get(d.len..).unwrap_or_default());
        Ok(())
    }

    fn is_frame_start(&self, payload: &[u8]) -> bool {
        parse_descriptor(payload).is_ok_and(|d| picture_start(&d))
    }

    fn is_frame_end(&self, payload: &[u8], marker: bool) -> bool {
        marker || parse_descriptor(payload).is_ok_and(|d| d.end && d.sid.is_none())
    }

    fn is_keyframe(&self, payload: &[u8]) -> bool {
        parse_descriptor(payload).is_ok_and(|d| picture_start(&d) && !d.inter)
    }
}
