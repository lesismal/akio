//! RTCP (RFC 3550 §6, RFC 4585 §6, RFC 5104 §4.3.1, REMB draft-alvestrand-rmcat-remb-03,
//! transport-wide congestion control draft-holmer-rmcat-transport-wide-cc-extensions-01).

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Why an RTCP compound packet did not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The buffer ends inside a header or before the length a header announces.
    TooShort,
    /// A packet is not version 2.
    BadVersion,
    /// The padding count is zero or larger than the packet.
    BadPadding,
    /// A known packet type's body does not match its count / length fields.
    Malformed(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TooShort => f.write_str("RTCP: truncated packet"),
            Error::BadVersion => f.write_str("RTCP: not version 2"),
            Error::BadPadding => f.write_str("RTCP: bad padding"),
            Error::Malformed(what) => write!(f, "RTCP: malformed {what}"),
        }
    }
}

impl std::error::Error for Error {}

/// RTCP packet types.
const SR: u8 = 200;
const RR: u8 = 201;
const SDES: u8 = 202;
const BYE: u8 = 203;
const RTPFB: u8 = 205;
const PSFB: u8 = 206;

/// A reception report block (RFC 3550 §6.4.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReportBlock {
    /// The source this block reports on.
    pub ssrc: u32,
    /// Fraction of packets lost since the previous report, in 1/256.
    pub fraction_lost: u8,
    /// Cumulative packets lost (24-bit signed on the wire; clamped when written).
    pub cumulative_lost: i32,
    /// Extended highest sequence number received (cycles << 16 | highest).
    pub extended_highest_seq: u32,
    /// Interarrival jitter in timestamp units.
    pub jitter: u32,
    /// Middle 32 bits of the NTP timestamp of the last sender report received (0 if none).
    pub last_sr: u32,
    /// Delay since that sender report in 1/65536 s.
    pub delay_since_last_sr: u32,
}

/// The sender information of a sender report (RFC 3550 §6.4.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SenderInfo {
    /// 64-bit NTP wallclock time (see [`ntp_time`]).
    pub ntp_time: u64,
    /// The RTP timestamp corresponding to `ntp_time`.
    pub rtp_time: u32,
    /// Packets sent.
    pub packet_count: u32,
    /// Payload octets sent.
    pub octet_count: u32,
}

/// Transport-wide congestion control feedback (RTPFB FMT 15).
///
/// `packets` lists every sequence number from `base_seq` in order (`packets[i].0 ==
/// base_seq + i`; [`write_compound`] relies on the order, not on these values) with its
/// receive delta in 250 µs units: for the first received packet relative to
/// `reference_time * 64 ms`, for every later one relative to the previous received packet;
/// `None` for packets not received. Deltas in 0..=255 use the one-byte form, others the
/// two-byte signed form (clamped to `i16`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TwccFeedback {
    /// SSRC of the feedback sender.
    pub sender_ssrc: u32,
    /// SSRC of the media source (informational for transport-wide feedback).
    pub media_ssrc: u32,
    /// Transport-wide sequence number of the first packet.
    pub base_seq: u16,
    /// 24-bit reference time in 64 ms units.
    pub reference_time: u32,
    /// Feedback packet counter (wraps).
    pub fb_count: u8,
    /// `(sequence number, receive delta)` per packet.
    pub packets: Vec<(u16, Option<i64>)>,
}

/// One RTCP packet of a compound packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rtcp {
    /// Sender report (200). At most 31 report blocks are written.
    SenderReport {
        /// Sender SSRC.
        ssrc: u32,
        /// Sender information.
        info: SenderInfo,
        /// Reception report blocks.
        reports: Vec<ReportBlock>,
    },
    /// Receiver report (201). At most 31 report blocks are written.
    ReceiverReport {
        /// Sender SSRC.
        ssrc: u32,
        /// Reception report blocks.
        reports: Vec<ReportBlock>,
    },
    /// Source description (202): chunks of `(ssrc, [(item type, text)])` (1 = CNAME).
    /// At most 31 chunks and 255-byte texts are written; item type 0 is never written.
    SourceDescription(Vec<(u32, Vec<(u8, String)>)>),
    /// Goodbye (203). At most 31 SSRCs and a 255-byte reason are written.
    Goodbye {
        /// Sources leaving.
        ssrcs: Vec<u32>,
        /// Optional reason.
        reason: Option<String>,
    },
    /// Generic NACK (205/1, RFC 4585 §6.2.1).
    Nack {
        /// SSRC of the NACK sender.
        sender_ssrc: u32,
        /// SSRC of the media source.
        media_ssrc: u32,
        /// Lost sequence numbers (encoded as PID + BLP pairs, preserving order).
        lost: Vec<u16>,
    },
    /// Transport-wide congestion control feedback (205/15).
    TransportCc(TwccFeedback),
    /// Picture loss indication (206/1).
    Pli {
        /// SSRC of the PLI sender.
        sender_ssrc: u32,
        /// SSRC of the media source.
        media_ssrc: u32,
    },
    /// Full intra request (206/4, RFC 5104): `(ssrc, command sequence number)` entries.
    Fir {
        /// SSRC of the FIR sender.
        sender_ssrc: u32,
        /// Requested sources.
        entries: Vec<(u32, u8)>,
    },
    /// Receiver estimated maximum bitrate (206/15 "REMB").
    Remb {
        /// SSRC of the REMB sender.
        sender_ssrc: u32,
        /// Bitrate in bits per second (written as 6-bit exponent and 18-bit mantissa, so
        /// large values lose precision).
        bitrate: u64,
        /// The SSRCs the estimate applies to (at most 255 are written).
        ssrcs: Vec<u32>,
    },
    /// Any other packet: type, the 5-bit count/FMT field and the body after the 4-byte
    /// header (padding removed).
    Unknown {
        /// Packet type.
        packet_type: u8,
        /// The count / FMT field.
        fmt: u8,
        /// The body.
        data: Vec<u8>,
    },
}

/// The 64-bit NTP timestamp (seconds since 1900 in the high 32 bits) of `now`; 0 before the
/// Unix epoch.
#[must_use]
pub fn ntp_time(now: SystemTime) -> u64 {
    const NTP_UNIX_OFFSET: u64 = 2_208_988_800;
    let Ok(d) = now.duration_since(UNIX_EPOCH) else {
        return 0;
    };
    let secs = d.as_secs().wrapping_add(NTP_UNIX_OFFSET);
    let frac = (u64::from(d.subsec_nanos()) << 32) / 1_000_000_000;
    (secs << 32) | frac
}

/// The middle 32 bits of an NTP timestamp (the LSR / DLSR format).
#[must_use]
pub fn compact_ntp(ntp: u64) -> u32 {
    (ntp >> 16) as u32
}

/// Largest TWCC status count accepted by the parser (larger feedback becomes
/// [`Rtcp::Unknown`]), so a small packet cannot allocate megabytes.
pub const MAX_TWCC_STATUSES: usize = 16_384;

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Option<u32> {
        self.take(3)
            .map(|b| u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Option<u64> {
        Some((u64::from(self.u32()?) << 32) | u64::from(self.u32()?))
    }
    fn remaining(&self) -> usize {
        self.0.len()
    }
}

/// Parses a compound RTCP packet (or a single packet). Unknown packet types and feedback
/// formats become [`Rtcp::Unknown`]; trailing bytes inside a known packet (profile
/// extensions, alignment) are ignored. Never panics.
///
/// # Errors
///
/// When a header is truncated, is not version 2, announces more bytes than remain, has bad
/// padding, or a known packet's counts do not fit its length.
pub fn parse_compound(buf: &[u8]) -> Result<Vec<Rtcp>, Error> {
    let mut out = Vec::new();
    let mut rest = buf;
    while !rest.is_empty() {
        let h = rest.get(..4).ok_or(Error::TooShort)?;
        if h[0] >> 6 != 2 {
            return Err(Error::BadVersion);
        }
        let len = 4 * (usize::from(u16::from_be_bytes([h[2], h[3]])) + 1);
        let pkt = rest.get(..len).ok_or(Error::TooShort)?;
        rest = &rest[len..];
        let mut body = &pkt[4..];
        if h[0] & 0x20 != 0 {
            let pad = usize::from(*body.last().ok_or(Error::BadPadding)?);
            if pad == 0 || pad > body.len() {
                return Err(Error::BadPadding);
            }
            body = &body[..body.len() - pad];
        }
        out.push(parse_one(h[1], h[0] & 0x1f, body)?);
    }
    Ok(out)
}

fn report_block(r: &mut Reader<'_>) -> Option<ReportBlock> {
    let ssrc = r.u32()?;
    let fraction_lost = r.u8()?;
    let lost = r.u24()?;
    Some(ReportBlock {
        ssrc,
        fraction_lost,
        cumulative_lost: ((lost << 8) as i32) >> 8,
        extended_highest_seq: r.u32()?,
        jitter: r.u32()?,
        last_sr: r.u32()?,
        delay_since_last_sr: r.u32()?,
    })
}

fn reports(r: &mut Reader<'_>, count: u8) -> Option<Vec<ReportBlock>> {
    (0..count).map(|_| report_block(r)).collect()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn parse_one(pt: u8, count: u8, body: &[u8]) -> Result<Rtcp, Error> {
    let mut r = Reader(body);
    let unknown = || Rtcp::Unknown {
        packet_type: pt,
        fmt: count,
        data: body.to_vec(),
    };
    Ok(match pt {
        SR => {
            let m = Error::Malformed("sender report");
            let ssrc = r.u32().ok_or(m)?;
            let info = SenderInfo {
                ntp_time: r.u64().ok_or(m)?,
                rtp_time: r.u32().ok_or(m)?,
                packet_count: r.u32().ok_or(m)?,
                octet_count: r.u32().ok_or(m)?,
            };
            let reports = reports(&mut r, count).ok_or(m)?;
            Rtcp::SenderReport {
                ssrc,
                info,
                reports,
            }
        }
        RR => {
            let m = Error::Malformed("receiver report");
            let ssrc = r.u32().ok_or(m)?;
            let reports = reports(&mut r, count).ok_or(m)?;
            Rtcp::ReceiverReport { ssrc, reports }
        }
        SDES => Rtcp::SourceDescription(parse_sdes(body, count).ok_or(Error::Malformed("SDES"))?),
        BYE => {
            let m = Error::Malformed("BYE");
            let ssrcs = (0..count)
                .map(|_| r.u32())
                .collect::<Option<Vec<_>>>()
                .ok_or(m)?;
            let reason = if r.remaining() > 0 {
                let n = usize::from(r.u8().ok_or(m)?);
                Some(text(r.take(n).ok_or(m)?))
            } else {
                None
            };
            Rtcp::Goodbye { ssrcs, reason }
        }
        RTPFB | PSFB => {
            let m = Error::Malformed("feedback");
            let sender_ssrc = r.u32().ok_or(m)?;
            let media_ssrc = r.u32().ok_or(m)?;
            match (pt, count) {
                (RTPFB, 1) => {
                    if r.remaining() % 4 != 0 {
                        return Err(Error::Malformed("NACK"));
                    }
                    let mut lost = Vec::new();
                    while let (Some(pid), Some(blp)) = (r.u16(), r.u16()) {
                        lost.push(pid);
                        for i in 0..16u16 {
                            if blp & (1 << i) != 0 {
                                lost.push(pid.wrapping_add(i + 1));
                            }
                        }
                    }
                    Rtcp::Nack {
                        sender_ssrc,
                        media_ssrc,
                        lost,
                    }
                }
                (RTPFB, 15) => match parse_twcc(sender_ssrc, media_ssrc, &mut r)? {
                    Some(fb) => Rtcp::TransportCc(fb),
                    None => unknown(),
                },
                (PSFB, 1) => Rtcp::Pli {
                    sender_ssrc,
                    media_ssrc,
                },
                (PSFB, 4) => {
                    if r.remaining() % 8 != 0 {
                        return Err(Error::Malformed("FIR"));
                    }
                    let mut entries = Vec::new();
                    while let (Some(ssrc), Some(seq), Some(_)) = (r.u32(), r.u8(), r.u24()) {
                        entries.push((ssrc, seq));
                    }
                    Rtcp::Fir {
                        sender_ssrc,
                        entries,
                    }
                }
                (PSFB, 15) if r.0.starts_with(b"REMB") => {
                    let m = Error::Malformed("REMB");
                    r.take(4).ok_or(m)?;
                    let n = r.u8().ok_or(m)?;
                    let v = r.u24().ok_or(m)?;
                    let (exp, mantissa) = (v >> 18, u64::from(v & 0x3_ffff));
                    let bitrate = u64::try_from(u128::from(mantissa) << exp).unwrap_or(u64::MAX);
                    let ssrcs = (0..n)
                        .map(|_| r.u32())
                        .collect::<Option<Vec<_>>>()
                        .ok_or(m)?;
                    Rtcp::Remb {
                        sender_ssrc,
                        bitrate,
                        ssrcs,
                    }
                }
                _ => unknown(),
            }
        }
        _ => unknown(),
    })
}

/// SDES chunks: `(ssrc, [(item type, text)])`.
type SdesChunks = Vec<(u32, Vec<(u8, String)>)>;

fn parse_sdes(body: &[u8], count: u8) -> Option<SdesChunks> {
    let mut chunks = Vec::new();
    let mut pos = 0usize;
    for _ in 0..count {
        let s = body.get(pos..pos + 4)?;
        let ssrc = u32::from_be_bytes([s[0], s[1], s[2], s[3]]);
        pos += 4;
        let mut items = Vec::new();
        loop {
            let t = *body.get(pos)?;
            if t == 0 {
                // Null item, then pad to the next 32-bit boundary.
                pos = (pos + 4) & !3;
                break;
            }
            let n = usize::from(*body.get(pos + 1)?);
            let v = body.get(pos + 2..pos + 2 + n)?;
            items.push((t, text(v)));
            pos += 2 + n;
        }
        chunks.push((ssrc, items));
    }
    Some(chunks)
}

/// TWCC packet status symbols.
const NOT_RECEIVED: u8 = 0;
const SMALL: u8 = 1;
const LARGE: u8 = 2;

fn parse_twcc(
    sender_ssrc: u32,
    media_ssrc: u32,
    r: &mut Reader<'_>,
) -> Result<Option<TwccFeedback>, Error> {
    let m = Error::Malformed("transport-cc feedback");
    let base_seq = r.u16().ok_or(m)?;
    let count = usize::from(r.u16().ok_or(m)?);
    let reference_time = r.u24().ok_or(m)?;
    let fb_count = r.u8().ok_or(m)?;
    if count > MAX_TWCC_STATUSES {
        return Ok(None);
    }
    let mut statuses: Vec<u8> = Vec::with_capacity(count);
    while statuses.len() < count {
        let c = r.u16().ok_or(m)?;
        let left = count - statuses.len();
        if c & 0x8000 == 0 {
            let sym = ((c >> 13) & 3) as u8;
            let run = usize::from(c & 0x1fff).min(left);
            statuses.extend(std::iter::repeat_n(sym, run));
        } else if c & 0x4000 == 0 {
            statuses.extend((0..14).rev().map(|i| ((c >> i) & 1) as u8).take(left));
        } else {
            statuses.extend((0..7).rev().map(|i| ((c >> (2 * i)) & 3) as u8).take(left));
        }
    }
    let mut packets = Vec::with_capacity(count);
    for (i, s) in statuses.into_iter().enumerate() {
        let seq = base_seq.wrapping_add(i as u16);
        let delta = match s {
            NOT_RECEIVED => None,
            SMALL => Some(i64::from(r.u8().ok_or(m)?)),
            LARGE => Some(i64::from(r.u16().ok_or(m)? as i16)),
            _ => return Err(m),
        };
        packets.push((seq, delta));
    }
    Ok(Some(TwccFeedback {
        sender_ssrc,
        media_ssrc,
        base_seq,
        reference_time,
        fb_count,
        packets,
    }))
}

/// Serializes `packets` as one compound packet (no validation of the RFC 3550 compound
/// rules; put a report first yourself). Counts beyond the field sizes are truncated as
/// documented on each [`Rtcp`] variant.
#[must_use]
pub fn write_compound(packets: &[Rtcp]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in packets {
        write_one(p, &mut out);
    }
    out
}

/// Appends a header + `body` (padded with RTCP padding when not 32-bit aligned).
fn packet(out: &mut Vec<u8>, pt: u8, count: u8, body: &[u8]) {
    let pad = (4 - body.len() % 4) % 4;
    let words = (body.len() + pad) / 4;
    let mut b0 = 0x80 | (count & 0x1f);
    if pad > 0 {
        b0 |= 0x20;
    }
    out.push(b0);
    out.push(pt);
    out.extend_from_slice(&(words as u16).to_be_bytes());
    out.extend_from_slice(body);
    if pad > 0 {
        out.resize(out.len() + pad - 1, 0);
        out.push(pad as u8);
    }
}

fn put_report(b: &mut Vec<u8>, r: &ReportBlock) {
    b.extend_from_slice(&r.ssrc.to_be_bytes());
    b.push(r.fraction_lost);
    let lost = r.cumulative_lost.clamp(-0x80_0000, 0x7f_ffff);
    b.extend_from_slice(&lost.to_be_bytes()[1..]);
    b.extend_from_slice(&r.extended_highest_seq.to_be_bytes());
    b.extend_from_slice(&r.jitter.to_be_bytes());
    b.extend_from_slice(&r.last_sr.to_be_bytes());
    b.extend_from_slice(&r.delay_since_last_sr.to_be_bytes());
}

fn pad4(b: &mut Vec<u8>) {
    while b.len() % 4 != 0 {
        b.push(0);
    }
}

fn write_one(p: &Rtcp, out: &mut Vec<u8>) {
    let mut b = Vec::new();
    match p {
        Rtcp::SenderReport {
            ssrc,
            info,
            reports,
        } => {
            let n = reports.len().min(31);
            b.extend_from_slice(&ssrc.to_be_bytes());
            b.extend_from_slice(&info.ntp_time.to_be_bytes());
            b.extend_from_slice(&info.rtp_time.to_be_bytes());
            b.extend_from_slice(&info.packet_count.to_be_bytes());
            b.extend_from_slice(&info.octet_count.to_be_bytes());
            reports[..n].iter().for_each(|r| put_report(&mut b, r));
            packet(out, SR, n as u8, &b);
        }
        Rtcp::ReceiverReport { ssrc, reports } => {
            let n = reports.len().min(31);
            b.extend_from_slice(&ssrc.to_be_bytes());
            reports[..n].iter().for_each(|r| put_report(&mut b, r));
            packet(out, RR, n as u8, &b);
        }
        Rtcp::SourceDescription(chunks) => {
            let n = chunks.len().min(31);
            for (ssrc, items) in &chunks[..n] {
                b.extend_from_slice(&ssrc.to_be_bytes());
                for (t, v) in items.iter().filter(|(t, _)| *t != 0) {
                    let v = &v.as_bytes()[..v.len().min(255)];
                    b.push(*t);
                    b.push(v.len() as u8);
                    b.extend_from_slice(v);
                }
                b.push(0);
                pad4(&mut b);
            }
            packet(out, SDES, n as u8, &b);
        }
        Rtcp::Goodbye { ssrcs, reason } => {
            let n = ssrcs.len().min(31);
            ssrcs[..n]
                .iter()
                .for_each(|s| b.extend_from_slice(&s.to_be_bytes()));
            if let Some(r) = reason {
                let r = &r.as_bytes()[..r.len().min(255)];
                b.push(r.len() as u8);
                b.extend_from_slice(r);
                pad4(&mut b);
            }
            packet(out, BYE, n as u8, &b);
        }
        Rtcp::Nack {
            sender_ssrc,
            media_ssrc,
            lost,
        } => {
            b.extend_from_slice(&sender_ssrc.to_be_bytes());
            b.extend_from_slice(&media_ssrc.to_be_bytes());
            for (pid, blp) in nack_pairs(lost) {
                b.extend_from_slice(&pid.to_be_bytes());
                b.extend_from_slice(&blp.to_be_bytes());
            }
            packet(out, RTPFB, 1, &b);
        }
        Rtcp::TransportCc(fb) => {
            write_twcc(fb, &mut b);
            packet(out, RTPFB, 15, &b);
        }
        Rtcp::Pli {
            sender_ssrc,
            media_ssrc,
        } => {
            b.extend_from_slice(&sender_ssrc.to_be_bytes());
            b.extend_from_slice(&media_ssrc.to_be_bytes());
            packet(out, PSFB, 1, &b);
        }
        Rtcp::Fir {
            sender_ssrc,
            entries,
        } => {
            b.extend_from_slice(&sender_ssrc.to_be_bytes());
            b.extend_from_slice(&[0; 4]);
            for (ssrc, seq) in entries {
                b.extend_from_slice(&ssrc.to_be_bytes());
                b.extend_from_slice(&[*seq, 0, 0, 0]);
            }
            packet(out, PSFB, 4, &b);
        }
        Rtcp::Remb {
            sender_ssrc,
            bitrate,
            ssrcs,
        } => {
            let n = ssrcs.len().min(255);
            b.extend_from_slice(&sender_ssrc.to_be_bytes());
            b.extend_from_slice(&[0; 4]);
            b.extend_from_slice(b"REMB");
            let (mut mantissa, mut exp) = (*bitrate, 0u32);
            while mantissa >= 1 << 18 {
                mantissa >>= 1;
                exp += 1;
            }
            b.push(n as u8);
            let v = (exp << 18) | mantissa as u32;
            b.extend_from_slice(&v.to_be_bytes()[1..]);
            ssrcs[..n]
                .iter()
                .for_each(|s| b.extend_from_slice(&s.to_be_bytes()));
            packet(out, PSFB, 15, &b);
        }
        Rtcp::Unknown {
            packet_type,
            fmt,
            data,
        } => packet(out, *packet_type, *fmt, data),
    }
}

/// Groups `lost` into `(PID, BLP)` pairs, keeping the list order: a sequence number joins
/// the current pair when it is 1..=16 after the PID and after the pair's last member.
pub(crate) fn nack_pairs(lost: &[u16]) -> Vec<(u16, u16)> {
    let mut out: Vec<(u16, u16)> = Vec::new();
    let mut last_off = 0u16;
    for &s in lost {
        if let Some((pid, blp)) = out.last_mut() {
            let off = s.wrapping_sub(*pid);
            if (1..=16).contains(&off) && off > last_off {
                *blp |= 1 << (off - 1);
                last_off = off;
                continue;
            }
        }
        out.push((s, 0));
        last_off = 0;
    }
    out
}

/// Status chunk builder (the same packing as libwebrtc / pion: run-length while a run
/// lasts, otherwise one-bit vectors of 14 or two-bit vectors of 7 symbols).
#[derive(Default)]
struct ChunkBuilder {
    syms: Vec<u8>,
    large: bool,
    mixed: bool,
}

impl ChunkBuilder {
    fn can_add(&self, s: u8) -> bool {
        let n = self.syms.len();
        n < 7
            || (n < 14 && !self.large && s != LARGE)
            || (n < 0x1fff && !self.mixed && self.syms.first() == Some(&s))
    }

    fn add(&mut self, s: u8) {
        self.large |= s == LARGE;
        self.mixed |= self.syms.first().is_some_and(|&f| f != s);
        self.syms.push(s);
    }

    /// Emits one chunk from the front of the buffer.
    fn emit(&mut self) -> u16 {
        if !self.mixed {
            let c =
                (u16::from(self.syms.first().copied().unwrap_or(0)) << 13) | self.syms.len() as u16;
            self.syms.clear();
            self.large = false;
            return c;
        }
        if self.syms.len() == 14 {
            // 1 | 0 (one-bit symbols) | 14 symbols, first in the most significant bit.
            let bits = self
                .syms
                .iter()
                .fold(0u16, |c, &s| (c << 1) | u16::from(s & 1));
            self.syms.clear();
            self.large = false;
            self.mixed = false;
            return 0x8000 | bits;
        }
        let n = self.syms.len().min(7);
        let mut c = 0xc000u16;
        for (i, &s) in self.syms[..n].iter().enumerate() {
            c |= u16::from(s & 3) << (2 * (6 - i));
        }
        self.syms.drain(..n);
        self.large = self.syms.contains(&LARGE);
        self.mixed = self
            .syms
            .first()
            .is_some_and(|&f| self.syms.iter().any(|&s| s != f));
        c
    }
}

fn write_twcc(fb: &TwccFeedback, b: &mut Vec<u8>) {
    let count = fb.packets.len().min(0xffff);
    b.extend_from_slice(&fb.sender_ssrc.to_be_bytes());
    b.extend_from_slice(&fb.media_ssrc.to_be_bytes());
    b.extend_from_slice(&fb.base_seq.to_be_bytes());
    b.extend_from_slice(&(count as u16).to_be_bytes());
    b.extend_from_slice(&(fb.reference_time & 0x00ff_ffff).to_be_bytes()[1..]);
    b.push(fb.fb_count);
    let mut chunks = ChunkBuilder::default();
    let mut deltas = Vec::new();
    for &(_, d) in &fb.packets[..count] {
        let sym = match d {
            None => NOT_RECEIVED,
            Some(d @ 0..=255) => {
                deltas.push(d as u8);
                SMALL
            }
            Some(d) => {
                let d = d.clamp(i64::from(i16::MIN), i64::from(i16::MAX)) as i16;
                deltas.extend_from_slice(&d.to_be_bytes());
                LARGE
            }
        };
        if !chunks.can_add(sym) {
            b.extend_from_slice(&chunks.emit().to_be_bytes());
        }
        chunks.add(sym);
    }
    while !chunks.syms.is_empty() {
        b.extend_from_slice(&chunks.emit().to_be_bytes());
    }
    b.extend_from_slice(&deltas);
}
