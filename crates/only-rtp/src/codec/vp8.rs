//! VP8 payload format (RFC 7741).

use super::{CodecError, Depacketizer, Packetizer};

/// Descriptor size the packetizer writes: required octet, X octet, 2-octet PictureID.
const DESC_LEN: usize = 4;

/// VP8 packetizer: every payload carries the descriptor `X=1, I=1, M=1` with a 15-bit
/// PictureID that increments per frame; `S=1, PID=0` on the first payload of a frame.
#[derive(Debug, Clone)]
pub struct Vp8Packetizer {
    picture_id: u16,
}

impl Vp8Packetizer {
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

impl Packetizer for Vp8Packetizer {
    fn packetize(&mut self, mtu: usize, frame: &[u8]) -> Vec<(Vec<u8>, bool)> {
        if frame.is_empty() || mtu <= DESC_LEN {
            return Vec::new();
        }
        let chunk = mtu - DESC_LEN;
        let pid = self.picture_id;
        let n = frame.len().div_ceil(chunk);
        let mut out = Vec::with_capacity(n);
        for (i, part) in frame.chunks(chunk).enumerate() {
            let mut p = Vec::with_capacity(DESC_LEN + part.len());
            p.push(if i == 0 { 0x90 } else { 0x80 });
            p.push(0x80);
            p.push(0x80 | (pid >> 8) as u8);
            p.push(pid as u8);
            p.extend_from_slice(part);
            out.push((p, i + 1 == n));
        }
        self.picture_id = (pid + 1) & 0x7fff;
        out
    }
}

/// A parsed VP8 payload descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Descriptor {
    /// Start of a VP8 partition.
    pub(crate) start: bool,
    /// Partition index.
    pub(crate) pid: u8,
    /// Descriptor length in bytes.
    pub(crate) len: usize,
}

pub(crate) fn parse_descriptor(p: &[u8]) -> Result<Descriptor, CodecError> {
    let b0 = *p.first().ok_or(CodecError::Truncated)?;
    let mut pos = 1;
    if b0 & 0x80 != 0 {
        let x = *p.get(pos).ok_or(CodecError::Truncated)?;
        pos += 1;
        if x & 0x80 != 0 {
            let m = *p.get(pos).ok_or(CodecError::Truncated)?;
            pos += if m & 0x80 != 0 { 2 } else { 1 };
        }
        if x & 0x40 != 0 {
            pos += 1; // TL0PICIDX
        }
        if x & 0x30 != 0 {
            pos += 1; // TID/Y/KEYIDX
        }
        if pos > p.len() {
            return Err(CodecError::Truncated);
        }
    }
    Ok(Descriptor {
        start: b0 & 0x10 != 0,
        pid: b0 & 0x07,
        len: pos,
    })
}

/// VP8 depacketizer: strips the payload descriptor (parsing the X/I/L/T/K extensions).
#[derive(Debug, Default, Clone)]
pub struct Vp8Depacketizer {
    _priv: (),
}

impl Vp8Depacketizer {
    /// A new depacketizer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Depacketizer for Vp8Depacketizer {
    fn depacketize(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), CodecError> {
        let d = parse_descriptor(payload)?;
        out.extend_from_slice(payload.get(d.len..).unwrap_or_default());
        Ok(())
    }

    fn is_frame_start(&self, payload: &[u8]) -> bool {
        parse_descriptor(payload).is_ok_and(|d| d.start && d.pid == 0)
    }

    fn is_frame_end(&self, _payload: &[u8], marker: bool) -> bool {
        marker
    }

    fn is_keyframe(&self, payload: &[u8]) -> bool {
        match parse_descriptor(payload) {
            Ok(d) if d.start && d.pid == 0 => payload.get(d.len).is_some_and(|b| b & 1 == 0),
            _ => false,
        }
    }
}
