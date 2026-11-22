//! AV1 payload format (RTP Payload Format for AV1, aomediacodec).

use super::{CodecError, Depacketizer, MAX_FRAME_SIZE, Packetizer};

const Z: u8 = 0x80;
const Y: u8 = 0x40;
const N: u8 = 0x08;

const OBU_SEQUENCE_HEADER: u8 = 1;
const OBU_TEMPORAL_DELIMITER: u8 = 2;
const OBU_TILE_LIST: u8 = 8;

/// Reads a leb128 value (at most 8 bytes); returns `(value, bytes read)`.
pub(crate) fn read_leb128(b: &[u8]) -> Option<(u64, usize)> {
    let mut v = 0u64;
    for (i, byte) in b.iter().take(8).enumerate() {
        v |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

pub(crate) fn write_leb128(out: &mut Vec<u8>, mut v: usize) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn leb128_len(v: usize) -> usize {
    let mut n = 1;
    let mut v = v >> 7;
    while v != 0 {
        n += 1;
        v >>= 7;
    }
    n
}

/// One OBU of a low-overhead bitstream: header bytes (1 or 2) and payload.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Obu<'a> {
    pub(crate) header: &'a [u8],
    pub(crate) payload: &'a [u8],
}

impl Obu<'_> {
    pub(crate) fn obu_type(&self) -> u8 {
        (self.header[0] >> 3) & 0x0f
    }

    /// The `(temporal_id, spatial_id)` of the extension header, if present.
    fn layer(&self) -> Option<u8> {
        self.header.get(1).map(|e| e >> 3)
    }
}

/// Parses OBUs (`obu_has_size_field` may be 0 only on the last one) until the end of `data` or
/// the first malformed OBU (forbidden bit set, truncated header or size).
pub(crate) fn parse_obus(data: &[u8]) -> Vec<Obu<'_>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(&h) = data.get(pos) {
        if h & 0x80 != 0 {
            break;
        }
        let hlen = if h & 0x04 != 0 { 2 } else { 1 };
        let Some(header) = data.get(pos..pos + hlen) else {
            break;
        };
        pos += hlen;
        let size = if h & 0x02 != 0 {
            let Some((v, n)) = data.get(pos..).and_then(read_leb128) else {
                break;
            };
            pos += n;
            match usize::try_from(v) {
                Ok(v) if v <= data.len() - pos => v,
                _ => break,
            }
        } else {
            data.len() - pos
        };
        out.push(Obu {
            header,
            payload: &data[pos..pos + size],
        });
        pos += size;
    }
    out
}

/// AV1 packetizer. Input is a temporal unit in low-overhead bitstream format (OBUs with
/// `obu_has_size_field = 1`). Temporal delimiter and tile list OBUs are dropped; OBU elements
/// are carried without size fields, the last element of a packet counted by W where possible
/// and the others with leb128 lengths; OBUs are fragmented across packets with Z/Y; a sequence
/// header starts a new packet with N=1, and a change of temporal/spatial layer starts a new
/// packet. The packet layout is byte-identical to pion's `AV1Payloader`. The minimum `mtu` is 2.
#[derive(Debug, Default, Clone)]
pub struct Av1Packetizer {
    _priv: (),
}

impl Av1Packetizer {
    /// A new packetizer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Packet builder state.
struct Builder {
    mtu: usize,
    packets: Vec<Vec<u8>>,
    /// Elements written to the last packet since its W was last set.
    count: usize,
}

/// How many bytes of `want` fit with their leb128 length in `room` bytes.
fn fit_with_length(want: usize, room: usize) -> usize {
    let l = leb128_len(want);
    if want + l <= room {
        return want;
    }
    let at_edge = l > 1 && want == 1 << (7 * (l - 1));
    if at_edge && want + l - 1 <= room {
        return want - 1;
    }
    want - l
}

impl Builder {
    fn new_packet(&mut self, header: u8) {
        let mut p = Vec::with_capacity(self.mtu);
        p.push(header);
        self.packets.push(p);
    }

    fn free(&self) -> usize {
        self.packets
            .last()
            .map_or(0, |p| self.mtu.saturating_sub(p.len()))
    }

    fn last(&mut self) -> &mut Vec<u8> {
        if self.packets.is_empty() {
            self.packets.push(vec![0]);
        }
        let i = self.packets.len() - 1;
        &mut self.packets[i]
    }

    /// Appends one OBU element. `last` means the packet must end after it (a new packet or the
    /// end of the temporal unit follows), `fresh` forces a new packet first.
    fn append(&mut self, mut elem: &[u8], new_sequence: bool, last: bool, fresh: bool) {
        let mtu = self.mtu;
        let mut free = self.free();
        if self.packets.is_empty() || free == 0 || fresh {
            self.new_packet(if new_sequence { N } else { 0 });
            free = mtu - 1;
            self.count = 0;
        }
        let mut written = elem.len().min(free);
        if (last || written >= free) && self.count < 3 {
            let w = (self.count as u8 + 1) << 4;
            let p = self.last();
            p[0] |= w & 0x30;
            p.extend_from_slice(&elem[..written]);
            self.count = 0;
        } else if free >= 2 {
            written = fit_with_length(written, free);
            let p = self.last();
            write_leb128(p, written);
            p.extend_from_slice(&elem[..written]);
            self.count += 1;
        } else {
            written = 0;
        }
        elem = &elem[written..];
        while !elem.is_empty() {
            let continues = written != 0;
            if continues {
                self.last()[0] |= Y;
            }
            self.new_packet(if continues { Z } else { 0 });
            written = elem.len().min(mtu - 1);
            let p = self.last();
            if last || elem.len() >= mtu - 1 {
                p[0] |= 0x10; // W=1
            } else {
                written = fit_with_length(written, mtu - 1);
                write_leb128(p, written);
            }
            p.extend_from_slice(&elem[..written]);
            elem = &elem[written..];
            self.count = 1;
        }
    }
}

impl Packetizer for Av1Packetizer {
    fn packetize(&mut self, mtu: usize, frame: &[u8]) -> Vec<(Vec<u8>, bool)> {
        if mtu < 2 || frame.is_empty() {
            return Vec::new();
        }
        let mut b = Builder {
            mtu,
            packets: Vec::new(),
            count: 0,
        };
        // The element waiting to be appended: (OBU without size field, is a sequence header).
        let mut pending: Option<(Vec<u8>, bool)> = None;
        let mut layer: Option<u8> = None;
        let mut fresh = false;
        for obu in parse_obus(frame) {
            let t = obu.obu_type();
            let mut boundary = t == OBU_TEMPORAL_DELIMITER || t == OBU_SEQUENCE_HEADER;
            if let (Some(new), Some(cur)) = (obu.layer(), layer) {
                boundary |= (new & 0x1f) != (cur & 0x1f);
            }
            if obu.layer().is_some() {
                layer = obu.layer();
            }
            if let Some((elem, seq)) = pending.take() {
                b.append(&elem, seq, boundary, fresh);
                fresh = boundary;
                if boundary {
                    layer = None;
                }
            }
            if t == OBU_TILE_LIST || t == OBU_TEMPORAL_DELIMITER {
                continue;
            }
            let mut elem = Vec::with_capacity(obu.header.len() + obu.payload.len());
            elem.extend_from_slice(obu.header);
            elem[0] &= !0x02; // obu_has_size_field = 0
            elem.extend_from_slice(obu.payload);
            pending = Some((elem, t == OBU_SEQUENCE_HEADER));
        }
        if let Some((elem, seq)) = pending {
            b.append(&elem, seq, true, fresh);
        }
        let n = b.packets.len();
        b.packets
            .into_iter()
            .enumerate()
            .map(|(i, p)| (p, i + 1 == n))
            .collect()
    }
}

/// AV1 depacketizer: OBU elements to OBUs with `obu_has_size_field = 1` (sizes re-added),
/// reassembling fragmented OBUs across packets (Z/Y). Temporal delimiter and tile list OBUs
/// are dropped.
#[derive(Debug, Default, Clone)]
pub struct Av1Depacketizer {
    /// The fragment of an OBU continued in the next packet (Y=1).
    partial: Vec<u8>,
    has_partial: bool,
}

impl Av1Depacketizer {
    /// A new depacketizer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Splits the elements of an AV1 packet (after the aggregation header).
fn elements(w: u8, body: &[u8]) -> Result<Vec<&[u8]>, CodecError> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < body.len() {
        let len = if w != 0 && out.len() + 1 == usize::from(w) {
            body.len() - pos
        } else {
            let (v, n) = read_leb128(&body[pos..]).ok_or(CodecError::Truncated)?;
            pos += n;
            usize::try_from(v)
                .ok()
                .filter(|v| *v <= body.len() - pos)
                .ok_or(CodecError::Truncated)?
        };
        out.push(&body[pos..pos + len]);
        pos += len;
    }
    if w != 0 && out.len() != usize::from(w) {
        return Err(CodecError::Malformed(
            "AV1 W does not match the element count",
        ));
    }
    Ok(out)
}

fn emit_obu(obu: &[u8], out: &mut Vec<u8>) -> Result<(), CodecError> {
    let Some(&h) = obu.first() else {
        return Ok(());
    };
    if h & 0x80 != 0 {
        return Err(CodecError::Malformed("AV1 OBU forbidden bit"));
    }
    let hlen = if h & 0x04 != 0 { 2 } else { 1 };
    if obu.len() < hlen {
        return Err(CodecError::Truncated);
    }
    let t = (h >> 3) & 0x0f;
    if t == OBU_TEMPORAL_DELIMITER || t == OBU_TILE_LIST {
        return Ok(());
    }
    if h & 0x02 != 0 {
        // Already sized: the size must cover the rest of the element exactly.
        let (v, n) = read_leb128(&obu[hlen..]).ok_or(CodecError::Truncated)?;
        if usize::try_from(v).ok() != Some(obu.len() - hlen - n) {
            return Err(CodecError::Malformed(
                "AV1 OBU size does not match its element",
            ));
        }
        out.extend_from_slice(obu);
        return Ok(());
    }
    out.push(h | 0x02);
    out.extend_from_slice(&obu[1..hlen]);
    write_leb128(out, obu.len() - hlen);
    out.extend_from_slice(&obu[hlen..]);
    Ok(())
}

impl Depacketizer for Av1Depacketizer {
    fn depacketize(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), CodecError> {
        let [agg, body @ ..] = payload else {
            return Err(CodecError::Truncated);
        };
        let (z, y, w, n) = (agg & Z != 0, agg & Y != 0, (agg >> 4) & 0x03, agg & N != 0);
        if z && n {
            return Err(CodecError::Malformed("AV1 Z and N both set"));
        }
        if n || !z {
            self.partial.clear();
            self.has_partial = false;
        }
        let elems = elements(w, body)?;
        let count = elems.len();
        for (i, e) in elems.into_iter().enumerate() {
            let continued = i == 0 && z;
            if continued && !self.has_partial {
                return Err(CodecError::FragmentWithoutStart);
            }
            if continued || (i + 1 == count && y) {
                if self.partial.len() + e.len() > MAX_FRAME_SIZE {
                    return Err(CodecError::FrameTooLarge);
                }
                self.partial.extend_from_slice(e);
                if i + 1 == count && y {
                    self.has_partial = true;
                    break;
                }
                let whole = std::mem::take(&mut self.partial);
                self.has_partial = false;
                emit_obu(&whole, out)?;
                continue;
            }
            emit_obu(e, out)?;
        }
        Ok(())
    }

    fn is_frame_start(&self, payload: &[u8]) -> bool {
        payload.first().is_some_and(|b| b & Z == 0)
    }

    fn is_frame_end(&self, _payload: &[u8], marker: bool) -> bool {
        marker
    }

    fn is_keyframe(&self, payload: &[u8]) -> bool {
        let [agg, body @ ..] = payload else {
            return false;
        };
        if agg & N != 0 {
            return true;
        }
        let Ok(elems) = elements((agg >> 4) & 0x03, body) else {
            return false;
        };
        elems.iter().enumerate().any(|(i, e)| {
            !(i == 0 && agg & Z != 0)
                && e.first()
                    .is_some_and(|h| (h >> 3) & 0x0f == OBU_SEQUENCE_HEADER)
        })
    }

    fn reset(&mut self) {
        self.partial.clear();
        self.has_partial = false;
    }
}
