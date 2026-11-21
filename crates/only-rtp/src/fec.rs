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
//!
//! ULPFEC can also protect packets unequally (RFC 5109 §5, §7.4): level 0 of a FEC packet
//! covers the first L0 bytes after the fixed header of its level-0 packets (and their header
//! fields), level 1 the next L1 bytes of its level-1 packets, and so on.
//! [`FecEncoder::set_ulp_level0`] protects the start of every packet with the group's
//! FEC packets and the rest once per group; [`FecEncoder::encode_ulp`] takes explicit levels.
//! The decoder rebuilds packets piecewise from any levels and returns them once complete.
//! Packets it could only rebuild in part can be taken out with [`FecDecoder::take_partials`].
//!
//! Groups are protected as libwebrtc protects them: its packet mask tables
//! ([`packet_masks`], [`FecMaskType`]), its rules for closing a group that spans several
//! frames ([`FecProtection`]), and its protection policy ([`ProtectionPolicy`]: the factors
//! from the loss, the bits per frame and the resolution, RTT-aware with NACK).

use std::collections::BTreeMap;

mod policy;
mod tables;

pub use policy::{ProtectionPolicy, protection_factors};

/// The FEC payload format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FecScheme {
    /// ULPFEC (RFC 5109): 16- or 48-bit masks; by default one protection level whose
    /// protection length is the longest protected packet, optionally more levels (see
    /// [`FecEncoder::set_ulp_level0`]).
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
    /// Offsets from `base_seq` of the protected packets (for ULPFEC: at level 0), ascending.
    pub offsets: Vec<u16>,
    /// The header length (for ULPFEC up to the end of the level-0 header); the repair
    /// payload follows.
    pub header_len: usize,
    /// How many repair bytes follow (ULPFEC: the level-0 protection length, which the
    /// parser does not check against the payload unless further levels follow it).
    pub protection_len: usize,
    /// ULPFEC levels 1, 2, ... (RFC 5109 §7.4), each header after the previous level's
    /// payload. Empty for one level and for FlexFEC.
    pub ulp_levels: Vec<UlpLevel>,
}

/// A ULPFEC protection level above level 0 (RFC 5109 §7.4): it protects bytes `S..S + L`
/// after the fixed RTP header of its packets, where `S` is the sum of the lower levels'
/// protection lengths and `L` its own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UlpLevel {
    /// Offsets from the FEC header's `base_seq` of the packets protected at this level,
    /// ascending.
    pub offsets: Vec<u16>,
    /// The protection length `L`.
    pub protection_len: usize,
    /// Where this level's repair payload starts in the FEC payload (set by the parser;
    /// ignored by the writer).
    pub payload_offset: usize,
}

/// One level of a ULPFEC packet built by [`FecEncoder::encode_ulp`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UlpLevelSpec {
    /// The protected packets (indices into the media list).
    pub mask: Vec<usize>,
    /// The protection length of this level.
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
    /// nothing. ULPFEC bytes after the level-0 payload are further levels; `None` if one of
    /// them is truncated, runs past the payload or protects nothing.
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
                let mut ulp_levels = Vec::new();
                let level_header = if long { 8 } else { 4 };
                let mut pos = header_len + prot;
                while pos < p.len() {
                    let lh = p.get(pos..pos + level_header)?;
                    let mut lo = Vec::new();
                    if long {
                        let v = (u64::from(be16(lh, 2)) << 32) | u64::from(be32(lh, 4));
                        mask_bits(v, 48, 0, &mut lo);
                    } else {
                        mask_bits(u64::from(be16(lh, 2)), 16, 0, &mut lo);
                    }
                    let len = usize::from(be16(lh, 0));
                    let start = pos + level_header;
                    if lo.is_empty() || start + len > p.len() {
                        return None;
                    }
                    ulp_levels.push(UlpLevel {
                        offsets: lo,
                        protection_len: len,
                        payload_offset: start,
                    });
                    pos = start + len;
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
                    ulp_levels,
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
            ulp_levels: Vec::new(),
        })
    }

    /// Whether the ULPFEC header needs the 48-bit masks (an offset of any level above 15).
    fn ulp_long(&self) -> bool {
        let max = FecScheme::Ulpfec.max_offset();
        self.offsets
            .iter()
            .chain(self.ulp_levels.iter().flat_map(|l| &l.offsets))
            .any(|&o| o > 15 && o <= max)
    }

    /// Serializes the header for `scheme` (the repair payload goes after it). `ssrc` is
    /// written for [`FecScheme::Flexfec03`] (0 if `None`); `protection_len` for ULPFEC, which
    /// ends with the level-0 header (see [`write_level`](Self::write_level) for the others).
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
                let long = self.ulp_long();
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

    /// Serializes the ULPFEC header of `ulp_levels[i]` (level `i + 1`): its protection
    /// length and mask, 16 or 48 bits like every level of the packet. `None` if there is no
    /// such level. A FEC packet is [`write`](Self::write), the level-0 repair bytes, then
    /// per further level this header and its repair bytes.
    #[must_use]
    pub fn write_level(&self, i: usize) -> Option<Vec<u8>> {
        let level = self.ulp_levels.get(i)?;
        let long = self.ulp_long();
        let mut mask: u64 = 0;
        for &o in level
            .offsets
            .iter()
            .filter(|&&o| o <= FecScheme::Ulpfec.max_offset())
        {
            mask |= 1 << (47 - o);
        }
        let mut b = Vec::with_capacity(8);
        b.extend_from_slice(&(level.protection_len.min(0xffff) as u16).to_be_bytes());
        if long {
            b.extend_from_slice(&mask.to_be_bytes()[2..]);
        } else {
            b.extend_from_slice(&((mask >> 32) as u16).to_be_bytes());
        }
        Some(b)
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

/// Which of libwebrtc's packet mask tables protects groups of up to 12 media packets
/// ([`packet_masks`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum FecMaskType {
    /// For random (independent) losses; libwebrtc's default and what Chrome sends.
    #[default]
    Random,
    /// For bursts of consecutive losses with little reordering.
    Bursty,
}

/// libwebrtc's packet masks (`PacketMaskTable::LookUp`): `k` media packets protected by `m`
/// FEC packets, each mask listing the media packets (indices into the group) its FEC packet
/// protects. Up to 12 media packets the masks come from libwebrtc's tables of `mask` type
/// (optimised for the recovery of random or bursty losses), above that they are
/// [`interleaved_masks`]. `m` is clamped to 1..=k; `k` 0 gives no masks.
#[must_use]
pub fn packet_masks(k: usize, m: usize, mask: FecMaskType) -> Vec<Vec<usize>> {
    if k == 0 {
        return Vec::new();
    }
    let m = m.clamp(1, k);
    if k > 12 {
        return interleaved_masks(k, m);
    }
    let table: &[u16] = match mask {
        FecMaskType::Random => &tables::RANDOM,
        FecMaskType::Bursty => &tables::BURSTY,
    };
    // Rows of every smaller group size, then of every smaller FEC count of this one.
    let start = (1..k).map(|j| j * (j + 1) / 2).sum::<usize>() + m * (m - 1) / 2;
    table[start..start + m]
        .iter()
        .map(|&row| (0..k).filter(|&j| row & (0x8000 >> j) != 0).collect())
        .collect()
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
    let base = group_base(scheme, ssrc, media)?;
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
            ulp_levels: Vec::new(),
        };
        let mut b = h.write(scheme);
        b.extend_from_slice(&par.payload);
        out.push(b);
    }
    Some(out)
}

/// The sequence number base of a group: the one from which every other is closest ahead.
/// `None` if the group is empty, a packet is not RTP of `ssrc`, or the span exceeds the
/// scheme's mask.
fn group_base(scheme: FecScheme, ssrc: u32, media: &[&[u8]]) -> Option<u16> {
    if media.is_empty() || media.iter().any(|p| !rtp_ok(p) || be32(p, 8) != ssrc) {
        return None;
    }
    let seqs: Vec<u16> = media.iter().map(|p| be16(p, 2)).collect();
    let base = *seqs
        .iter()
        .min_by_key(|&&b| seqs.iter().map(|&s| s.wrapping_sub(b)).max())?;
    seqs.iter()
        .all(|&s| s.wrapping_sub(base) <= scheme.max_offset())
        .then_some(base)
}

/// XOR of bytes `start..start + len` after the fixed header of `packets` (zero past
/// their ends).
fn xor_range(packets: &[&[u8]], start: usize, len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    for p in packets {
        let body = p.get(12 + start..).unwrap_or(&[]);
        out.iter_mut().zip(body).for_each(|(a, b)| *a ^= *b);
    }
    out
}

/// Builds ULPFEC payloads with explicit protection levels: `fec[j]` lists the levels of FEC
/// packet `j`, level 0 first. `None` if a packet is not RTP of `ssrc`, the sequence numbers
/// span more than 48, a mask is empty or out of range, the protection lengths add up to
/// more than 65535, or RFC 5109 §7.4's rules are broken: (a) a packet is protected more
/// than once at a level above 0, or more than once at level 0 with different protection
/// lengths; (b) a packet is protected at level `p > 0` but nowhere at level `p - 1`.
fn encode_ulp(ssrc: u32, media: &[&[u8]], fec: &[Vec<UlpLevelSpec>]) -> Option<Vec<Vec<u8>>> {
    let base = group_base(FecScheme::Ulpfec, ssrc, media)?;
    // Rules (a) and (b): per level, which packets it protects (and level 0's lengths).
    let depth = fec.iter().map(Vec::len).max().unwrap_or(0);
    let mut at: Vec<Vec<Option<usize>>> = vec![vec![None; media.len()]; depth];
    for levels in fec {
        if levels.is_empty() || levels.iter().map(|l| l.protection_len).sum::<usize>() > 0xffff {
            return None;
        }
        for (n, level) in levels.iter().enumerate() {
            if level.mask.is_empty() {
                return None;
            }
            for &i in &level.mask {
                let slot = at[n].get_mut(i)?;
                match *slot {
                    Some(l) if n > 0 || l != levels[0].protection_len => return None,
                    _ => *slot = Some(levels[0].protection_len),
                }
            }
        }
    }
    if (1..depth).any(|n| (0..media.len()).any(|i| at[n][i].is_some() && at[n - 1][i].is_none())) {
        return None;
    }
    let mut out = Vec::with_capacity(fec.len());
    for levels in fec {
        let select = |mask: &[usize]| -> Vec<&[u8]> {
            let mut m = mask.to_vec();
            m.sort_unstable();
            m.dedup();
            m.into_iter().map(|i| media[i]).collect()
        };
        let offsets = |pkts: &[&[u8]]| -> Vec<u16> {
            let mut o: Vec<u16> = pkts.iter().map(|p| be16(p, 2).wrapping_sub(base)).collect();
            o.sort_unstable();
            o
        };
        let l0 = select(&levels[0].mask);
        let mut par = Parity::default();
        for p in &l0 {
            par.add(p);
        }
        let mut payloads = Vec::with_capacity(levels.len());
        let mut start = 0;
        let mut ulp_levels = Vec::new();
        for (n, level) in levels.iter().enumerate() {
            let pkts = select(&level.mask);
            payloads.push(xor_range(&pkts, start, level.protection_len));
            if n > 0 {
                ulp_levels.push(UlpLevel {
                    offsets: offsets(&pkts),
                    protection_len: level.protection_len,
                    payload_offset: 0,
                });
            }
            start += level.protection_len;
        }
        let h = FecHeader {
            pxcc_recovery: par.pxcc,
            mpt_recovery: par.mpt,
            length_recovery: par.len,
            ts_recovery: par.ts,
            ssrc: Some(ssrc),
            base_seq: base,
            offsets: offsets(&l0),
            header_len: 0,
            protection_len: levels[0].protection_len,
            ulp_levels,
        };
        let mut b = h.write(FecScheme::Ulpfec);
        for (n, payload) in payloads.iter().enumerate() {
            if n > 0 {
                b.extend(h.write_level(n - 1)?);
            }
            b.extend_from_slice(payload);
        }
        out.push(b);
    }
    Some(out)
}

/// How [`FecEncoder`] protects a stream (libwebrtc's `FecProtectionParams`, for delta and key
/// frames), as [`ProtectionPolicy`] chooses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FecProtection {
    /// Protection factor of groups without a keyframe packet: FEC packets per 256 media
    /// packets (0 = no FEC).
    pub delta_rate: u8,
    /// Protection factor of groups with a keyframe packet.
    pub key_rate: u8,
    /// A group spans at most this many frames (0 is taken as 1); it closes earlier at a
    /// frame end once the FEC packets it needs come close to the factor (at most 50 / 256
    /// more) and it has enough packets (1, or 4 when the factor is above 80; one more when
    /// frames have two packets or more on average), as libwebrtc's `UlpfecGenerator`.
    pub max_frames: u8,
    /// The packet masks of groups of up to 12 packets.
    pub mask: FecMaskType,
}

impl FecProtection {
    /// One factor for every frame, one frame per group, random masks.
    #[must_use]
    pub fn rate(rate: u8) -> FecProtection {
        FecProtection {
            delta_rate: rate,
            key_rate: rate,
            max_frames: 1,
            mask: FecMaskType::Random,
        }
    }
}

/// libwebrtc's `ForwardErrorCorrection::NumFecPackets`: `rate` / 256 of `k`, rounded, at least
/// one while `rate` is not 0, at most `k`.
fn num_fec(k: usize, rate: u8) -> usize {
    if rate == 0 || k == 0 {
        return 0;
    }
    ((k * usize::from(rate) + 128) >> 8).clamp(1, k)
}

/// The sending side: collects the media packets of one SSRC and emits FEC payloads when a
/// group closes: at a frame end (one frame per group by default, see
/// [`FecProtection::max_frames`]) or when the group reaches [`MAX_FEC_GROUP`] packets.
///
/// The rate is libwebrtc's protection factor: FEC packets per 256 media packets (rounded,
/// at least one per group when non-zero, at most one per media packet). Masks are
/// [`packet_masks`] (libwebrtc's tables up to 12 packets, interleaved above), so a group
/// protects as Chrome's does.
#[derive(Debug)]
pub struct FecEncoder {
    scheme: FecScheme,
    ssrc: u32,
    prot: FecProtection,
    ulp_level0: Option<usize>,
    group: Vec<Vec<u8>>,
    /// Frames ended in the group, and whether one of its packets belongs to a keyframe.
    frames: usize,
    key: bool,
}

impl FecEncoder {
    /// An encoder for media SSRC `ssrc` with protection factor `rate` (0 = off).
    #[must_use]
    pub fn new(scheme: FecScheme, ssrc: u32, rate: u8) -> FecEncoder {
        FecEncoder {
            scheme,
            ssrc,
            prot: FecProtection::rate(rate),
            ulp_level0: None,
            group: Vec::new(),
            frames: 0,
            key: false,
        }
    }

    /// ULPFEC unequal protection (RFC 5109 §5): with `Some(l0)`, the FEC packets of a group
    /// protect only the first `l0` bytes after each packet's fixed header (the
    /// part most media formats need to decode anything: CSRCs, extensions, payload
    /// descriptors), and the last of them also carries a level 1 protecting the rest of
    /// every packet of the group once. With `m` FEC packets per group this costs about
    /// `m * l0 + longest - l0` repair bytes instead of `m * longest`: any loss the level-0
    /// packets can repair gets its start back, and the whole packet when it is the only
    /// loss of the group. `None` (the default) and the other schemes protect whole packets.
    /// Only for receivers that implement levels (this decoder): libwebrtc reads level 0
    /// alone and would rebuild packets longer than `l0` wrongly. Groups then span one frame.
    pub fn set_ulp_level0(&mut self, l0: Option<usize>) {
        self.ulp_level0 = l0.map(|l| l.min(0xffff));
    }

    /// Changes the protection factor of every frame (takes effect with the next group).
    pub fn set_rate(&mut self, rate: u8) {
        self.prot.delta_rate = rate;
        self.prot.key_rate = rate;
    }

    /// The protection factor of delta frames.
    #[must_use]
    pub fn rate(&self) -> u8 {
        self.prot.delta_rate
    }

    /// Sets the whole protection (factors, frames per group, masks).
    pub fn set_protection(&mut self, p: FecProtection) {
        self.prot = p;
    }

    /// The protection in use.
    #[must_use]
    pub fn protection(&self) -> FecProtection {
        self.prot
    }

    /// The factor of the open group (its key factor once it holds a keyframe packet).
    fn group_rate(&self) -> u8 {
        if self.key {
            self.prot.key_rate
        } else {
            self.prot.delta_rate
        }
    }

    /// Adds an outgoing media packet (the plain RTP packet, before RED or SRTP);
    /// `end_of_frame` (normally the marker bit) may close the group. Returns the FEC payloads
    /// to send now (empty while the group is open, the rate is 0, or the packet is not RTP
    /// of this SSRC). A packet whose sequence number does not fit the group's mask closes
    /// the group first.
    pub fn push(&mut self, packet: &[u8], end_of_frame: bool) -> Vec<Vec<u8>> {
        self.push_frame(packet, end_of_frame, false)
    }

    /// [`push`](Self::push) of a packet that belongs to a keyframe when `keyframe`: its group
    /// is protected with [`FecProtection::key_rate`].
    pub fn push_frame(
        &mut self,
        packet: &[u8],
        end_of_frame: bool,
        keyframe: bool,
    ) -> Vec<Vec<u8>> {
        let off = self.prot.delta_rate == 0 && self.prot.key_rate == 0;
        if off || !rtp_ok(packet) || be32(packet, 8) != self.ssrc {
            self.reset();
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
        self.key |= keyframe;
        if end_of_frame {
            self.frames += 1;
        }
        let max_frames = if self.ulp_level0.is_some() {
            1
        } else {
            usize::from(self.prot.max_frames.max(1))
        };
        let close = end_of_frame
            && (self.frames >= max_frames || (self.overhead_ok() && self.enough_packets()));
        if close || self.group.len() >= MAX_FEC_GROUP {
            out.extend(self.flush());
        }
        out
    }

    /// libwebrtc's `ExcessOverheadBelowMax`: the FEC packets the group needs exceed the
    /// factor by less than 50 / 256 of its media packets.
    fn overhead_ok(&self) -> bool {
        let k = self.group.len();
        let rate = self.group_rate();
        let overhead = (num_fec(k, rate) << 8) / k.max(1);
        (overhead as i64 - i64::from(rate)) < 50
    }

    /// libwebrtc's `MinimumMediaPacketsReached`.
    fn enough_packets(&self) -> bool {
        let k = self.group.len();
        let min = if self.group_rate() > 80 { 4 } else { 1 };
        let per_frame = k as f64 / self.frames.max(1) as f64;
        if per_frame < 2.0 { k >= min } else { k > min }
    }

    fn reset(&mut self) {
        self.group.clear();
        self.frames = 0;
        self.key = false;
    }

    /// Emits FEC for the packets collected so far and starts a new group.
    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        let rate = self.group_rate();
        let group = std::mem::take(&mut self.group);
        self.reset();
        let k = group.len();
        let m = num_fec(k, rate);
        if m == 0 {
            return Vec::new();
        }
        let refs: Vec<&[u8]> = group.iter().map(Vec::as_slice).collect();
        let masks = packet_masks(k, m, self.prot.mask);
        let longest = refs.iter().map(|p| p.len() - 12).max().unwrap_or(0);
        match self.ulp_level0 {
            Some(l0) if self.scheme == FecScheme::Ulpfec && longest > l0 => {
                let mut fec: Vec<Vec<UlpLevelSpec>> = masks
                    .into_iter()
                    .map(|mask| {
                        vec![UlpLevelSpec {
                            mask,
                            protection_len: l0,
                        }]
                    })
                    .collect();
                if let Some(last) = fec.last_mut() {
                    last.push(UlpLevelSpec {
                        mask: (0..k).collect(),
                        protection_len: (longest - l0).min(0xffff - l0),
                    });
                }
                encode_ulp(self.ssrc, &refs, &fec).unwrap_or_default()
            }
            _ => encode(self.scheme, self.ssrc, &refs, &masks).unwrap_or_default(),
        }
    }

    /// FEC payloads for an explicit group: `media` (RTP packets of this SSRC) protected by
    /// `masks` (indices into `media`). `None` if a packet is not RTP of this SSRC or the
    /// sequence numbers span more than the scheme's mask.
    #[must_use]
    pub fn encode(&self, media: &[&[u8]], masks: &[Vec<usize>]) -> Option<Vec<Vec<u8>>> {
        encode(self.scheme, self.ssrc, media, masks)
    }

    /// ULPFEC payloads with explicit protection levels for `media` (RTP packets of this
    /// SSRC): `fec[j]` lists the levels of FEC packet `j`, level 0 first, each protecting
    /// its packets' bytes after the lower levels' (RFC 5109 §7.4, §8.2). The header fields
    /// are recovered from the level-0 packets. `None` for the FlexFEC schemes, if a packet
    /// is not RTP of this SSRC, the sequence numbers span more than 48, a mask is empty or
    /// out of range, a packet's levels add up to more than 65535 bytes, or the rules of
    /// §7.4 are broken: a packet protected more than once at a level above 0 (or at level 0
    /// with different protection lengths), or at level `p` but nowhere at level `p - 1`.
    #[must_use]
    pub fn encode_ulp(&self, media: &[&[u8]], fec: &[Vec<UlpLevelSpec>]) -> Option<Vec<Vec<u8>>> {
        if self.scheme != FecScheme::Ulpfec {
            return None;
        }
        encode_ulp(self.ssrc, media, fec)
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

/// One protection level of a pending FEC packet: its packets' bytes `start..start +
/// repair.len()` after the fixed header XOR to `repair`.
#[derive(Debug)]
struct Level {
    exts: Vec<u64>,
    start: usize,
    repair: Vec<u8>,
}

#[derive(Debug)]
struct PendingFec {
    base: u64,
    pxcc: u8,
    mpt: u8,
    len: u16,
    ts: u32,
    /// Level 0 first (it also recovers the header); `None` once used or useless.
    levels: Vec<Option<Level>>,
}

/// A media packet, received or (partly) rebuilt.
#[derive(Debug, Default)]
struct Media {
    /// The fixed header (zeros until known) and the body bytes (zeros where unknown).
    pkt: Vec<u8>,
    /// The fixed header and the length are known.
    header: bool,
    /// Known body byte ranges, sorted and disjoint.
    known: Vec<(usize, usize)>,
    /// Complete: received, or rebuilt and returned.
    done: bool,
}

impl Media {
    fn received(packet: &[u8]) -> Media {
        Media {
            pkt: packet.to_vec(),
            header: true,
            known: vec![(0, packet.len() - 12)],
            done: true,
        }
    }

    /// Whether body bytes `s..e` are known (bytes past a known length are zeros).
    fn covers(&self, s: usize, e: usize) -> bool {
        let e = if self.header {
            e.min(self.pkt.len() - 12)
        } else {
            e
        };
        s >= e || self.known.iter().any(|&(a, b)| a <= s && e <= b)
    }

    /// XORs body bytes `s..s + out.len()` into `out`.
    fn xor_into(&self, s: usize, out: &mut [u8]) {
        let body = self.pkt.get(12 + s..).unwrap_or(&[]);
        out.iter_mut().zip(body).for_each(|(a, b)| *a ^= *b);
    }

    /// Stores body bytes from `s` (cut at the length once it is known).
    fn store(&mut self, s: usize, data: &[u8]) {
        let e = if self.header {
            (s + data.len()).min(self.pkt.len() - 12)
        } else {
            s + data.len()
        };
        if s >= e {
            return;
        }
        if self.pkt.len() < 12 + e {
            self.pkt.resize(12 + e, 0);
        }
        self.pkt[12 + s..12 + e].copy_from_slice(&data[..e - s]);
        self.known.push((s, e));
        self.known.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(self.known.len());
        for &(a, b) in &self.known {
            match merged.last_mut() {
                Some(last) if a <= last.1 => last.1 = last.1.max(b),
                _ => merged.push((a, b)),
            }
        }
        self.known = merged;
    }

    /// Sets the rebuilt fixed header and body length.
    fn set_header(&mut self, head: &[u8; 12], len: usize) {
        self.pkt.resize(12 + len, 0);
        self.pkt[..12].copy_from_slice(head);
        self.header = true;
        for r in &mut self.known {
            r.1 = r.1.min(len);
        }
        self.known.retain(|&(a, b)| a < b);
    }

    fn complete(&self) -> bool {
        self.header && self.covers(0, self.pkt.len() - 12)
    }
}

/// A media packet [`FecDecoder::take_partials`] could only rebuild in part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialPacket {
    /// The fixed header and the known start of the rest (CSRCs, extensions, payload), the P
    /// bit cleared.
    pub packet: Vec<u8>,
    /// The length of the whole packet after the fixed header.
    pub length: usize,
}

/// The receiving side: keeps recent media packets and FEC payloads of one protected SSRC
/// and rebuilds missing media packets.
///
/// Every protection level of a FEC packet whose packets all but one are known over its
/// byte range rebuilds that range of the missing one (level 0 also its header and length);
/// a packet is returned once all of it is known. Rebuilt pieces help other levels and FEC
/// packets in turn.
#[derive(Debug)]
pub struct FecDecoder {
    scheme: FecScheme,
    ssrc: u32,
    last: Option<u64>,
    media: BTreeMap<u64, Media>,
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

    /// Missing packets of which some bytes were rebuilt but not all (ULPFEC with levels
    /// or a short protection length), within the recovery window.
    #[must_use]
    pub fn partially_recovered(&self) -> usize {
        self.media
            .values()
            .filter(|m| !m.done && (m.header || !m.known.is_empty()))
            .count()
    }

    /// Takes the packets rebuilt only in part whose RTP timestamp is not `ts` (call it with
    /// the timestamp of a newly received media packet: once a later frame arrives, the FEC
    /// that could complete an earlier one has normally been sent, as encoders close a group
    /// at the end of a frame), oldest first. A packet qualifies when its header (with length)
    /// is known and some bytes after it from the start; it comes back truncated to that
    /// prefix (the P bit cleared, its padding being unknown) and is not rebuilt again. A
    /// depacketizer can often still use the start of a payload (payload descriptors, the
    /// first partition, the beginning of a NAL unit).
    pub fn take_partials(&mut self, ts: u32) -> Vec<PartialPacket> {
        let mut out = Vec::new();
        for m in self.media.values_mut() {
            if m.done || !m.header || be32(&m.pkt, 4) == ts {
                continue;
            }
            let Some(&(0, end)) = m.known.first() else {
                continue;
            };
            if end == 0 {
                continue;
            }
            m.done = true;
            let mut packet = m.pkt[..12 + end].to_vec();
            packet[0] &= !0x20;
            out.push(PartialPacket {
                packet,
                length: m.pkt.len() - 12,
            });
        }
        out
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
        let m = self.media.entry(ext).or_default();
        if !m.done {
            *m = Media::received(packet);
        }
        self.prune();
        self.recover()
    }

    /// Records a FEC payload (ULPFEC: the RED block; FlexFEC: the FEC packet's payload)
    /// and returns the packets it lets the decoder rebuild. Payloads that do not parse, or
    /// (flexfec-03) protect another SSRC, are ignored.
    pub fn on_fec(&mut self, payload: &[u8]) -> Vec<Vec<u8>> {
        let Some(h) = FecHeader::parse(self.scheme, payload) else {
            return Vec::new();
        };
        if h.ssrc.is_some_and(|s| s != self.ssrc) {
            return Vec::new();
        }
        let Some(repair) = payload.get(h.header_len..h.header_len + h.protection_len) else {
            return Vec::new();
        };
        let Some(base) = self.ext(h.base_seq) else {
            return Vec::new();
        };
        let exts = |o: &[u16]| o.iter().map(|&o| base + u64::from(o)).collect();
        let mut levels = vec![Some(Level {
            exts: exts(&h.offsets),
            start: 0,
            repair: repair.to_vec(),
        })];
        let mut start = h.protection_len;
        for l in &h.ulp_levels {
            levels.push(Some(Level {
                exts: exts(&l.offsets),
                start,
                repair: payload[l.payload_offset..l.payload_offset + l.protection_len].to_vec(),
            }));
            start += l.protection_len;
        }
        self.fec.push(PendingFec {
            base,
            pxcc: h.pxcc_recovery,
            mpt: h.mpt_recovery,
            len: h.length_recovery,
            ts: h.ts_recovery,
            levels,
        });
        self.prune();
        self.recover()
    }

    /// The one packet of a level not known over its range (level 0: or without header),
    /// `Some(None)` if all are known, `None` if several are missing.
    fn missing(&self, level: &Level, level0: bool) -> Option<Option<u64>> {
        let end = level.start + level.repair.len();
        let mut missing = None;
        for &e in &level.exts {
            let known = self
                .media
                .get(&e)
                .is_some_and(|m| (m.header || !level0) && m.covers(level.start, end));
            if !known {
                if missing.is_some() {
                    return None;
                }
                missing = Some(e);
            }
        }
        Some(missing)
    }

    fn recover(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let mut progress = false;
            for fi in 0..self.fec.len() {
                for li in 0..self.fec[fi].levels.len() {
                    let Some(level) = &self.fec[fi].levels[li] else {
                        continue;
                    };
                    match self.missing(level, li == 0) {
                        None => {}
                        Some(None) => self.fec[fi].levels[li] = None,
                        Some(Some(e)) => {
                            if let Some(level) = self.fec[fi].levels[li].take() {
                                if let Some(p) = self.rebuild(fi, &level, li == 0, e) {
                                    out.push(p);
                                }
                                progress = true;
                            }
                        }
                    }
                }
            }
            self.fec.retain(|f| f.levels.iter().any(Option::is_some));
            if !progress {
                return out;
            }
        }
    }

    /// Rebuilds the range of `level` (and for level 0 the header) of packet `ext`, all other
    /// packets of the level being known; returns the packet if that completed it.
    fn rebuild(&mut self, fi: usize, level: &Level, level0: bool, ext: u64) -> Option<Vec<u8>> {
        let f = &self.fec[fi];
        let need_header = level0 && !self.media.get(&ext).is_some_and(|m| m.header);
        let (mut pxcc, mut mpt, mut len, mut ts) = (f.pxcc, f.mpt, f.len, f.ts);
        let mut data = level.repair.clone();
        for &e in level.exts.iter().filter(|&&e| e != ext) {
            let m = self.media.get(&e)?;
            if need_header {
                pxcc ^= m.pkt[0] & 0x3f;
                mpt ^= m.pkt[1];
                len ^= (m.pkt.len() - 12) as u16;
                ts ^= be32(&m.pkt, 4);
            }
            m.xor_into(level.start, &mut data);
        }
        let ssrc = self.ssrc;
        let m = self.media.entry(ext).or_default();
        if need_header {
            let len = usize::from(len);
            // The rebuilt header must at least hold its CSRCs.
            if len < 4 * usize::from(pxcc & 0x0f) {
                return None;
            }
            let mut head = [0u8; 12];
            head[0] = 0x80 | pxcc;
            head[1] = mpt;
            head[2..4].copy_from_slice(&(ext as u16).to_be_bytes());
            head[4..8].copy_from_slice(&ts.to_be_bytes());
            head[8..12].copy_from_slice(&ssrc.to_be_bytes());
            m.set_header(&head, len);
        }
        m.store(level.start, &data);
        if m.done || !m.complete() {
            return None;
        }
        m.done = true;
        self.recovered += 1;
        Some(m.pkt.clone())
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
