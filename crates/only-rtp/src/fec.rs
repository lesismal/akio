//! Forward error correction: XOR parity FEC in the ULPFEC (RFC 5109) and FlexFEC (RFC 8627,
//! and the draft-ietf-payload-flexible-fec-scheme-03 header libwebrtc sends as
//! `flexfec-03`) formats, and RED (RFC 2198), which carries ULPFEC in WebRTC.
//!
//! Every scheme protects a group of media packets of one SSRC with parity packets: each FEC
//! packet XORs the bytes after the 12-byte fixed RTP header of the packets its mask selects
//! (CSRCs, header extensions, payload and padding), plus the header fields needed to rebuild
//! them (P, X, CC, M, PT, the length and the timestamp). One missing packet per FEC packet
//! can be rebuilt, and recovered packets can help other FEC packets in turn.
//!
//! [`FecEncoder`] collects the outgoing media packets of a frame and returns FEC payloads
//! (the FEC header and repair payload): for ULPFEC the caller sends them on the media SSRC
//! wrapped in RED ([`red::write`]), for FlexFEC as packets of the separate FEC stream (for
//! RFC 8627 with the protected SSRC as the only CSRC). [`FecDecoder`] takes received media
//! packets and FEC payloads and returns the media packets it rebuilt.

use std::collections::BTreeMap;

/// The FEC payload format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FecScheme {
    /// ULPFEC (RFC 5109) with one protection level: 16- or 48-bit masks, protection length
    /// = the longest protected packet.
    Ulpfec,
    /// FlexFEC as libwebrtc implements it for the SDP name `flexfec-03`
    /// (draft-ietf-payload-flexible-fec-scheme-03): the protected SSRC in the FEC header
    /// (SSRCCount = 1), K bit = 1 on the last mask segment, masks of 15, 46 or 109 bits.
    Flexfec03,
    /// FlexFEC as RFC 8627 §4.2.2.1 specifies it (R = F = 0, flexible mask): the protected
    /// SSRC in the CSRC list of the FEC packet's RTP header (one protected stream is
    /// supported), k bit = 1 when another mask segment follows, masks of 15, 46 or 110 bits.
    Flexfec,
}

impl FecScheme {
    /// Largest sequence number offset a mask can express.
    fn max_offset(self) -> u16 {
        match self {
            FecScheme::Ulpfec => 47,
            FecScheme::Flexfec03 => 108,
            FecScheme::Flexfec => 109,
        }
    }
}

/// Media packets per protection group of [`FecEncoder`] (libwebrtc's limit, which every
/// scheme's mask can express).
pub const MAX_FEC_GROUP: usize = 48;

/// A parsed FEC header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FecHeader {
    /// XOR of the protected packets' P, X and CC bits (the low six bits of the first byte).
    pub pxcc_recovery: u8,
    /// XOR of the protected packets' second byte (M and PT).
    pub mpt_recovery: u8,
    /// XOR of the protected packets' lengths minus 12.
    pub length_recovery: u16,
    /// XOR of the protected packets' timestamps.
    pub ts_recovery: u32,
    /// The protected SSRC when the header carries it ([`FecScheme::Flexfec03`]).
    pub ssrc: Option<u32>,
    /// The lowest protected sequence number.
    pub base_seq: u16,
    /// Offsets from `base_seq` of the protected packets, ascending.
    pub offsets: Vec<u16>,
    /// The header length; the repair payload follows.
    pub header_len: usize,
    /// How many repair bytes follow (ULPFEC: the protection length, which the parser does
    /// not check against the payload).
    pub protection_len: usize,
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

/// Appends the offsets of the set bits of the `width` most significant bits of `v`
/// (MSB = offset `first`).
fn mask_bits(v: u64, width: u32, first: u16, out: &mut Vec<u16>) {
    for i in 0..width {
        if v & (1 << (width - 1 - i)) != 0 {
            out.push(first + i as u16);
        }
    }
}

impl FecHeader {
    /// Parses the header at the start of a FEC payload (for ULPFEC, after RED was
    /// removed). `None` if it is truncated, uses an unsupported variant (FlexFEC with the R
    /// or F bit, flexfec-03 with more than one SSRC, ULPFEC with the E bit) or protects
    /// nothing.
    #[must_use]
    pub fn parse(scheme: FecScheme, p: &[u8]) -> Option<FecHeader> {
        let mut offsets = Vec::new();
        let (header_len, base_seq, ssrc, length_recovery, ts_recovery);
        match scheme {
            FecScheme::Ulpfec => {
                let h = p.get(..14)?;
                if h[0] & 0x80 != 0 {
                    return None;
                }
                let long = h[0] & 0x40 != 0;
                base_seq = be16(h, 2);
                ts_recovery = be32(h, 4);
                length_recovery = be16(h, 8);
                ssrc = None;
                let prot = usize::from(be16(h, 10));
                if long {
                    let m = p.get(12..18)?;
                    let v = (u64::from(be16(m, 0)) << 32) | u64::from(be32(m, 2));
                    mask_bits(v, 48, 0, &mut offsets);
                    header_len = 18;
                } else {
                    mask_bits(u64::from(be16(h, 12)), 16, 0, &mut offsets);
                    header_len = 14;
                }
                if offsets.is_empty() {
                    return None;
                }
                return Some(FecHeader {
                    pxcc_recovery: h[0] & 0x3f,
                    mpt_recovery: h[1],
                    length_recovery,
                    ts_recovery,
                    ssrc,
                    base_seq,
                    offsets,
                    header_len,
                    protection_len: prot,
                });
            }
            FecScheme::Flexfec03 => {
                let h = p.get(..20)?;
                if h[0] & 0xc0 != 0 || h[8] != 1 {
                    return None;
                }
                length_recovery = be16(h, 2);
                ts_recovery = be32(h, 4);
                ssrc = Some(be32(h, 12));
                base_seq = be16(h, 16);
                let m0 = be16(h, 18);
                mask_bits(u64::from(m0 & 0x7fff), 15, 0, &mut offsets);
                if m0 & 0x8000 != 0 {
                    header_len = 20;
                } else {
                    let m1 = be32(p.get(20..24)?, 0);
                    mask_bits(u64::from(m1 & 0x7fff_ffff), 31, 15, &mut offsets);
                    if m1 & 0x8000_0000 != 0 {
                        header_len = 24;
                    } else {
                        let b = p.get(24..32)?;
                        let m2 = (u64::from(be32(b, 0)) << 32) | u64::from(be32(b, 4));
                        if m2 & (1 << 63) == 0 {
                            return None;
                        }
                        mask_bits(m2 & !(1 << 63), 63, 46, &mut offsets);
                        header_len = 32;
                    }
                }
            }
            FecScheme::Flexfec => {
                let h = p.get(..12)?;
                if h[0] & 0xc0 != 0 {
                    return None;
                }
                length_recovery = be16(h, 2);
                ts_recovery = be32(h, 4);
                ssrc = None;
                base_seq = be16(h, 8);
                let m0 = be16(h, 10);
                mask_bits(u64::from(m0 & 0x7fff), 15, 0, &mut offsets);
                if m0 & 0x8000 == 0 {
                    header_len = 12;
                } else {
                    let m1 = be32(p.get(12..16)?, 0);
                    mask_bits(u64::from(m1 & 0x7fff_ffff), 31, 15, &mut offsets);
                    if m1 & 0x8000_0000 == 0 {
                        header_len = 16;
                    } else {
                        let b = p.get(16..24)?;
                        let m2 = (u64::from(be32(b, 0)) << 32) | u64::from(be32(b, 4));
                        mask_bits(m2, 64, 46, &mut offsets);
                        header_len = 24;
                    }
                }
            }
        }
        if offsets.is_empty() {
            return None;
        }
        Some(FecHeader {
            pxcc_recovery: p[0] & 0x3f,
            mpt_recovery: p[1],
            length_recovery,
            ts_recovery,
            ssrc,
            base_seq,
            offsets,
            header_len,
            protection_len: p.len() - header_len,
        })
    }

    /// Serializes the header for `scheme` (the repair payload goes after it). `ssrc` is
    /// written for [`FecScheme::Flexfec03`] (0 if `None`); `protection_len` for ULPFEC.
    /// Offsets beyond the scheme's mask are dropped.
    #[must_use]
    pub fn write(&self, scheme: FecScheme) -> Vec<u8> {
        let max = scheme.max_offset();
        let mut mask: u128 = 0;
        let mut top = 0u16;
        for &o in self.offsets.iter().filter(|&&o| o <= max) {
            mask |= 1u128 << (127 - o);
            top = top.max(o);
        }
        // Bits `from..from + width` of the mask (MSB first) as an integer.
        let bits = |from: u32, width: u32| ((mask << from) >> (128 - width)) as u64;
        let mut b = Vec::with_capacity(32);
        match scheme {
            FecScheme::Ulpfec => {
                let long = top > 15;
                b.push(if long { 0x40 } else { 0 } | (self.pxcc_recovery & 0x3f));
                b.push(self.mpt_recovery);
                b.extend_from_slice(&self.base_seq.to_be_bytes());
                b.extend_from_slice(&self.ts_recovery.to_be_bytes());
                b.extend_from_slice(&self.length_recovery.to_be_bytes());
                b.extend_from_slice(&(self.protection_len.min(0xffff) as u16).to_be_bytes());
                if long {
                    b.extend_from_slice(&bits(0, 48).to_be_bytes()[2..]);
                } else {
                    b.extend_from_slice(&(bits(0, 16) as u16).to_be_bytes());
                }
            }
            FecScheme::Flexfec03 | FecScheme::Flexfec => {
                let k03 = scheme == FecScheme::Flexfec03;
                b.push(self.pxcc_recovery & 0x3f);
                b.push(self.mpt_recovery);
                b.extend_from_slice(&self.length_recovery.to_be_bytes());
                b.extend_from_slice(&self.ts_recovery.to_be_bytes());
                if k03 {
                    b.extend_from_slice(&[1, 0, 0, 0]);
                    b.extend_from_slice(&self.ssrc.unwrap_or(0).to_be_bytes());
                }
                b.extend_from_slice(&self.base_seq.to_be_bytes());
                // flexfec-03: K = 1 marks the last segment; RFC 8627: k = 1 means more.
                let segs = if top <= 14 {
                    1
                } else if top <= 45 {
                    2
                } else {
                    3
                };
                let k = |last: bool| if last == k03 { 0x8000u16 } else { 0 };
                b.extend_from_slice(&(k(segs == 1) | bits(0, 15) as u16).to_be_bytes());
                if segs >= 2 {
                    let v = (u32::from(k(segs == 2)) << 16) | bits(15, 31) as u32;
                    b.extend_from_slice(&v.to_be_bytes());
                }
                if segs == 3 {
                    let v = if k03 {
                        (1 << 63) | bits(46, 63)
                    } else {
                        bits(46, 64)
                    };
                    b.extend_from_slice(&v.to_be_bytes());
                }
            }
        }
        b
    }
}

/// `k` media packets protected by `m` FEC packets, interleaved: FEC packet `i` protects the
/// media packets `j` with `j % m == i`, so a burst of up to `m` consecutive losses is
/// recoverable. `m` is clamped to 1..=k.
#[must_use]
pub fn interleaved_masks(k: usize, m: usize) -> Vec<Vec<usize>> {
    let m = m.clamp(1, k.max(1));
    (0..m).map(|i| (i..k).step_by(m).collect()).collect()
}

/// The XOR accumulator of one FEC packet.
#[derive(Default)]
struct Parity {
    pxcc: u8,
    mpt: u8,
    len: u16,
    ts: u32,
    payload: Vec<u8>,
}

impl Parity {
    /// XORs in an RTP packet (at least 12 bytes).
    fn add(&mut self, pkt: &[u8]) {
        self.pxcc ^= pkt[0] & 0x3f;
        self.mpt ^= pkt[1];
        self.len ^= (pkt.len() - 12) as u16;
        self.ts ^= be32(pkt, 4);
        let body = &pkt[12..];
        if self.payload.len() < body.len() {
            self.payload.resize(body.len(), 0);
        }
        self.payload
            .iter_mut()
            .zip(body)
            .for_each(|(a, b)| *a ^= *b);
    }
}

/// Media packets usable for FEC: RTP version 2, at least the fixed header, at most 64 KiB
/// after it.
fn rtp_ok(p: &[u8]) -> bool {
    p.len() >= 12 && p[0] >> 6 == 2 && p.len() - 12 <= 0xffff
}

/// Builds the FEC payloads protecting `media` (RTP packets of `ssrc` in any order) with
/// `masks` (each a list of indices into `media`). `None` if a packet is not RTP, belongs to
/// another SSRC, or the sequence numbers span more than the scheme's mask.
fn encode(
    scheme: FecScheme,
    ssrc: u32,
    media: &[&[u8]],
    masks: &[Vec<usize>],
) -> Option<Vec<Vec<u8>>> {
    if media.is_empty() || media.iter().any(|p| !rtp_ok(p) || be32(p, 8) != ssrc) {
        return None;
    }
    let seqs: Vec<u16> = media.iter().map(|p| be16(p, 2)).collect();
    // The base is the sequence number from which every other is closest ahead.
    let base = *seqs
        .iter()
        .min_by_key(|&&b| seqs.iter().map(|&s| s.wrapping_sub(b)).max())?;
    if seqs
        .iter()
        .any(|&s| s.wrapping_sub(base) > scheme.max_offset())
    {
        return None;
    }
    let mut out = Vec::with_capacity(masks.len());
    for mask in masks {
        let mut par = Parity::default();
        let mut offsets = Vec::new();
        for &i in mask {
            let p = media.get(i)?;
            par.add(p);
            offsets.push(be16(p, 2).wrapping_sub(base));
        }
        offsets.sort_unstable();
        offsets.dedup();
        if offsets.is_empty() {
            continue;
        }
        let h = FecHeader {
            pxcc_recovery: par.pxcc,
            mpt_recovery: par.mpt,
            length_recovery: par.len,
            ts_recovery: par.ts,
            ssrc: Some(ssrc),
            base_seq: base,
            offsets,
            header_len: 0,
            protection_len: par.payload.len(),
        };
        let mut b = h.write(scheme);
        b.extend_from_slice(&par.payload);
        out.push(b);
    }
    Some(out)
}

/// The sending side: collects the media packets of one SSRC and emits FEC payloads at the
/// end of each frame (or when the group reaches [`MAX_FEC_GROUP`] packets).
///
/// The rate is libwebrtc's protection factor: FEC packets per 256 media packets (rounded,
/// at least one per group when non-zero, at most one per media packet). Masks are
/// [`interleaved_masks`].
#[derive(Debug)]
pub struct FecEncoder {
    scheme: FecScheme,
    ssrc: u32,
    rate: u8,
    group: Vec<Vec<u8>>,
}

impl FecEncoder {
    /// An encoder for media SSRC `ssrc` with protection factor `rate` (0 = off).
    #[must_use]
    pub fn new(scheme: FecScheme, ssrc: u32, rate: u8) -> FecEncoder {
        FecEncoder {
            scheme,
            ssrc,
            rate,
            group: Vec::new(),
        }
    }

    /// Changes the protection factor (takes effect with the next group).
    pub fn set_rate(&mut self, rate: u8) {
        self.rate = rate;
    }

    /// The protection factor.
    #[must_use]
    pub fn rate(&self) -> u8 {
        self.rate
    }

    /// Adds an outgoing media packet (the plain RTP packet, before RED or SRTP);
    /// `end_of_frame` (normally the marker bit) closes the group. Returns the FEC payloads
    /// to send now (empty while the group is open, the rate is 0, or the packet is not RTP
    /// of this SSRC). A packet whose sequence number does not fit the group's mask closes
    /// the group first.
    pub fn push(&mut self, packet: &[u8], end_of_frame: bool) -> Vec<Vec<u8>> {
        if self.rate == 0 || !rtp_ok(packet) || be32(packet, 8) != self.ssrc {
            self.group.clear();
            return Vec::new();
        }
        let mut out = Vec::new();
        if let Some(first) = self.group.first() {
            let span = be16(packet, 2).wrapping_sub(be16(first, 2));
            if span > self.scheme.max_offset() || span == 0 {
                out = self.flush();
            }
        }
        self.group.push(packet.to_vec());
        if end_of_frame || self.group.len() >= MAX_FEC_GROUP {
            out.extend(self.flush());
        }
        out
    }

    /// Emits FEC for the packets collected so far and starts a new group.
    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        let group = std::mem::take(&mut self.group);
        let k = group.len();
        if k == 0 || self.rate == 0 {
            return Vec::new();
        }
        let m = ((k * usize::from(self.rate) + 128) >> 8).clamp(1, k);
        let refs: Vec<&[u8]> = group.iter().map(Vec::as_slice).collect();
        encode(self.scheme, self.ssrc, &refs, &interleaved_masks(k, m)).unwrap_or_default()
    }

    /// FEC payloads for an explicit group: `media` (RTP packets of this SSRC) protected by
    /// `masks` (indices into `media`). `None` if a packet is not RTP of this SSRC or the
    /// sequence numbers span more than the scheme's mask.
    #[must_use]
    pub fn encode(&self, media: &[&[u8]], masks: &[Vec<usize>]) -> Option<Vec<Vec<u8>>> {
        encode(self.scheme, self.ssrc, media, masks)
    }
}

/// Extends a 16-bit sequence number to the 64-bit one closest to `last`.
fn unwrap16(last: u64, seq: u16) -> Option<u64> {
    let delta = i64::from(seq.wrapping_sub(last as u16) as i16);
    u64::try_from(last as i64 + delta).ok()
}

/// Media packets kept for recovery (by sequence number distance from the newest).
const MEDIA_WINDOW: u64 = 1024;
/// FEC packets waiting for recovery.
const MAX_PENDING_FEC: usize = 64;

#[derive(Debug)]
struct PendingFec {
    header: FecHeader,
    base: u64,
    repair: Vec<u8>,
}

/// The receiving side: keeps recent media packets and FEC payloads of one protected SSRC
/// and rebuilds missing media packets.
#[derive(Debug)]
pub struct FecDecoder {
    scheme: FecScheme,
    ssrc: u32,
    last: Option<u64>,
    media: BTreeMap<u64, Vec<u8>>,
    fec: Vec<PendingFec>,
    recovered: u64,
}

impl FecDecoder {
    /// A decoder for media SSRC `ssrc`.
    #[must_use]
    pub fn new(scheme: FecScheme, ssrc: u32) -> FecDecoder {
        FecDecoder {
            scheme,
            ssrc,
            last: None,
            media: BTreeMap::new(),
            fec: Vec::new(),
            recovered: 0,
        }
    }

    /// Packets recovered so far.
    #[must_use]
    pub fn recovered(&self) -> u64 {
        self.recovered
    }

    fn ext(&mut self, seq: u16) -> Option<u64> {
        let ext = match self.last {
            None => (1 << 32) + u64::from(seq),
            Some(l) => unwrap16(l, seq)?,
        };
        if self.last.is_none_or(|l| ext > l) {
            self.last = Some(ext);
        }
        Some(ext)
    }

    fn prune(&mut self) {
        let Some(last) = self.last else {
            return;
        };
        let floor = last.saturating_sub(MEDIA_WINDOW);
        while self
            .media
            .first_key_value()
            .is_some_and(|(&k, _)| k < floor)
        {
            self.media.pop_first();
        }
        self.fec.retain(|f| f.base + 128 >= floor);
        if self.fec.len() > MAX_PENDING_FEC {
            let n = self.fec.len() - MAX_PENDING_FEC;
            self.fec.drain(..n);
        }
    }

    /// Records a received (or otherwise obtained) media packet — the plain RTP packet,
    /// after SRTP and RED were removed — and returns the packets it lets the decoder
    /// rebuild. Packets of other SSRCs are ignored.
    pub fn on_media(&mut self, packet: &[u8]) -> Vec<Vec<u8>> {
        if !rtp_ok(packet) || be32(packet, 8) != self.ssrc {
            return Vec::new();
        }
        let Some(ext) = self.ext(be16(packet, 2)) else {
            return Vec::new();
        };
        self.media.entry(ext).or_insert_with(|| packet.to_vec());
        self.prune();
        self.recover()
    }

    /// Records a FEC payload (ULPFEC: the RED block; FlexFEC: the FEC packet's payload)
    /// and returns the packets it lets the decoder rebuild. Payloads that do not parse, or
    /// (flexfec-03) protect another SSRC, are ignored.
    pub fn on_fec(&mut self, payload: &[u8]) -> Vec<Vec<u8>> {
        let Some(header) = FecHeader::parse(self.scheme, payload) else {
            return Vec::new();
        };
        if header.ssrc.is_some_and(|s| s != self.ssrc) {
            return Vec::new();
        }
        let Some(repair) = payload
            .get(header.header_len..header.header_len + header.protection_len)
            .map(<[u8]>::to_vec)
        else {
            return Vec::new();
        };
        let Some(base) = self.ext(header.base_seq) else {
            return Vec::new();
        };
        self.fec.push(PendingFec {
            header,
            base,
            repair,
        });
        self.prune();
        self.recover()
    }

    fn recover(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let mut progress = false;
            let mut i = 0;
            while i < self.fec.len() {
                let (first, second) = {
                    let f = &self.fec[i];
                    let mut missing = f
                        .header
                        .offsets
                        .iter()
                        .map(|&o| f.base + u64::from(o))
                        .filter(|e| !self.media.contains_key(e));
                    (missing.next(), missing.next())
                };
                match (first, second) {
                    (None, _) => {
                        self.fec.swap_remove(i);
                    }
                    (Some(e), None) => {
                        let f = self.fec.swap_remove(i);
                        if let Some(p) = self.rebuild(&f, e) {
                            self.media.insert(e, p.clone());
                            self.recovered += 1;
                            out.push(p);
                            progress = true;
                        }
                    }
                    _ => i += 1,
                }
            }
            if !progress {
                return out;
            }
        }
    }

    fn rebuild(&self, f: &PendingFec, ext: u64) -> Option<Vec<u8>> {
        let h = &f.header;
        let mut par = Parity {
            pxcc: h.pxcc_recovery,
            mpt: h.mpt_recovery,
            len: h.length_recovery,
            ts: h.ts_recovery,
            payload: f.repair.clone(),
        };
        for &o in &h.offsets {
            let e = f.base + u64::from(o);
            if e != ext {
                par.add(self.media.get(&e)?);
            }
        }
        let len = usize::from(par.len);
        if par.payload.len() < len {
            // ULPFEC with a short protection length cannot rebuild the whole packet.
            return None;
        }
        let mut p = Vec::with_capacity(12 + len);
        p.push(0x80 | par.pxcc);
        p.push(par.mpt);
        p.extend_from_slice(&(ext as u16).to_be_bytes());
        p.extend_from_slice(&par.ts.to_be_bytes());
        p.extend_from_slice(&self.ssrc.to_be_bytes());
        p.extend_from_slice(&par.payload[..len]);
        // The rebuilt header must at least hold its CSRCs.
        (p.len() >= 12 + 4 * usize::from(p[0] & 0x0f)).then_some(p)
    }
}

/// RED, the RTP payload for redundant audio data (RFC 2198), used by WebRTC to carry
/// ULPFEC next to the media on one SSRC.
pub mod red {
    use crate::packet::{ExtensionMap, RtpHeader};

    /// One block of a RED payload.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RedBlock<'a> {
        /// Payload type of the block.
        pub pt: u8,
        /// Timestamp offset from the RTP timestamp (14 bits; 0 for the primary block).
        pub timestamp_offset: u16,
        /// The block's data.
        pub data: &'a [u8],
    }

    /// Splits a RED payload into its blocks (redundant ones first, the primary last).
    /// `None` if the headers run past the payload or a block length does.
    #[must_use]
    pub fn parse(payload: &[u8]) -> Option<Vec<RedBlock<'_>>> {
        let mut heads = Vec::new();
        let mut pos = 0;
        loop {
            let b = *payload.get(pos)?;
            if b & 0x80 == 0 {
                heads.push((b & 0x7f, 0u16, None));
                pos += 1;
                break;
            }
            let h = payload.get(pos..pos + 4)?;
            let ts = (u16::from(h[1]) << 6) | u16::from(h[2] >> 2);
            let len = (usize::from(h[2] & 3) << 8) | usize::from(h[3]);
            heads.push((b & 0x7f, ts, Some(len)));
            pos += 4;
        }
        let mut out = Vec::with_capacity(heads.len());
        for (pt, timestamp_offset, len) in heads {
            let len = len.unwrap_or_else(|| payload.len().saturating_sub(pos));
            let data = payload.get(pos..pos + len)?;
            pos += len;
            out.push(RedBlock {
                pt,
                timestamp_offset,
                data,
            });
        }
        Some(out)
    }

    /// Builds a RED payload from `blocks`, the last one primary. Redundant blocks longer
    /// than 1023 bytes, and timestamp offsets beyond 14 bits, are dropped.
    #[must_use]
    pub fn write(blocks: &[RedBlock<'_>]) -> Vec<u8> {
        let Some((primary, redundant)) = blocks.split_last() else {
            return Vec::new();
        };
        let redundant: Vec<_> = redundant
            .iter()
            .filter(|b| b.data.len() < 1024 && b.timestamp_offset < 1 << 14)
            .collect();
        let mut out = Vec::new();
        for b in &redundant {
            let ts = b.timestamp_offset;
            let len = b.data.len() as u16;
            out.push(0x80 | (b.pt & 0x7f));
            out.push((ts >> 6) as u8);
            out.push(((ts as u8 & 0x3f) << 2) | (len >> 8) as u8);
            out.push(len as u8);
        }
        out.push(primary.pt & 0x7f);
        for b in &redundant {
            out.extend_from_slice(b.data);
        }
        out.extend_from_slice(primary.data);
        out
    }

    /// Wraps an RTP packet's payload in RED as the only (primary) block: the header is kept
    /// (with its extensions; padding is dropped) and the payload type becomes `red_pt`.
    /// `None` if it is not an RTP packet.
    #[must_use]
    pub fn wrap(packet: &[u8], red_pt: u8) -> Option<Vec<u8>> {
        let h = RtpHeader::parse(packet, &ExtensionMap::new())?;
        let mut out = Vec::with_capacity(packet.len() + 1);
        out.extend_from_slice(&packet[..h.header_len]);
        out[0] &= !0x20;
        out[1] = (out[1] & 0x80) | (red_pt & 0x7f);
        out.push(h.payload_type & 0x7f);
        out.extend_from_slice(h.payload(packet));
        Some(out)
    }

    /// The inverse of [`wrap`] for a RED packet: the RTP packet carrying its primary block
    /// with the block's payload type (redundant blocks are dropped). `None` if it is not an
    /// RTP packet with a RED payload.
    #[must_use]
    pub fn unwrap_primary(packet: &[u8]) -> Option<Vec<u8>> {
        let h = RtpHeader::parse(packet, &ExtensionMap::new())?;
        let blocks = parse(h.payload(packet))?;
        let primary = blocks.last()?;
        let mut out = Vec::with_capacity(packet.len());
        out.extend_from_slice(&packet[..h.header_len]);
        out[0] &= !0x20;
        out[1] = (out[1] & 0x80) | (primary.pt & 0x7f);
        out.extend_from_slice(primary.data);
        Some(out)
    }
}
