//! Frames (RFC 9000 section 19, RFC 9221 DATAGRAM): parsing, encoding, and which packet types
//! may carry them (section 12.4).

use std::fmt;
use std::ops::Range;

use super::cid::{ConnectionId, ResetToken};
use super::coding::{Reader, VARINT_MAX, put_varint, varint_len};
use super::ranges::RangeSet;

/// Transport error codes (RFC 9000 section 20.1).
#[allow(dead_code)]
pub mod code {
    pub const NO_ERROR: u64 = 0x0;
    pub const INTERNAL_ERROR: u64 = 0x1;
    pub const CONNECTION_REFUSED: u64 = 0x2;
    pub const FLOW_CONTROL_ERROR: u64 = 0x3;
    pub const STREAM_LIMIT_ERROR: u64 = 0x4;
    pub const STREAM_STATE_ERROR: u64 = 0x5;
    pub const FINAL_SIZE_ERROR: u64 = 0x6;
    pub const FRAME_ENCODING_ERROR: u64 = 0x7;
    pub const TRANSPORT_PARAMETER_ERROR: u64 = 0x8;
    pub const CONNECTION_ID_LIMIT_ERROR: u64 = 0x9;
    pub const PROTOCOL_VIOLATION: u64 = 0xa;
    pub const INVALID_TOKEN: u64 = 0xb;
    pub const APPLICATION_ERROR: u64 = 0xc;
    pub const CRYPTO_BUFFER_EXCEEDED: u64 = 0xd;
    pub const KEY_UPDATE_ERROR: u64 = 0xe;
    pub const AEAD_LIMIT_REACHED: u64 = 0xf;
    pub const CRYPTO_ERROR: u64 = 0x100;
}

/// A transport error detected locally: the connection closes with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportError {
    pub code: u64,
    /// The frame type that triggered it, if any.
    pub frame: Option<u64>,
    pub reason: String,
}

impl TransportError {
    pub fn new(code: u64, reason: impl Into<String>) -> TransportError {
        TransportError {
            code,
            frame: None,
            reason: reason.into(),
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "transport error {:#x}: {}", self.code, self.reason)
    }
}

fn enc_err(ty: u64) -> TransportError {
    TransportError {
        code: code::FRAME_ENCODING_ERROR,
        frame: Some(ty),
        reason: "malformed frame".into(),
    }
}

/// Frame type values.
pub mod ty {
    pub const PADDING: u64 = 0x00;
    pub const PING: u64 = 0x01;
    pub const ACK: u64 = 0x02;
    pub const ACK_ECN: u64 = 0x03;
    pub const RESET_STREAM: u64 = 0x04;
    pub const STOP_SENDING: u64 = 0x05;
    pub const CRYPTO: u64 = 0x06;
    pub const NEW_TOKEN: u64 = 0x07;
    pub const STREAM: u64 = 0x08;
    pub const MAX_DATA: u64 = 0x10;
    pub const MAX_STREAM_DATA: u64 = 0x11;
    pub const MAX_STREAMS_BIDI: u64 = 0x12;
    pub const MAX_STREAMS_UNI: u64 = 0x13;
    pub const DATA_BLOCKED: u64 = 0x14;
    pub const STREAM_DATA_BLOCKED: u64 = 0x15;
    pub const STREAMS_BLOCKED_BIDI: u64 = 0x16;
    pub const STREAMS_BLOCKED_UNI: u64 = 0x17;
    pub const NEW_CONNECTION_ID: u64 = 0x18;
    pub const RETIRE_CONNECTION_ID: u64 = 0x19;
    pub const PATH_CHALLENGE: u64 = 0x1a;
    pub const PATH_RESPONSE: u64 = 0x1b;
    pub const CONNECTION_CLOSE: u64 = 0x1c;
    pub const CONNECTION_CLOSE_APP: u64 = 0x1d;
    pub const HANDSHAKE_DONE: u64 = 0x1e;
    pub const DATAGRAM: u64 = 0x30;
    pub const DATAGRAM_LEN: u64 = 0x31;
}

/// A parsed frame. Payload-carrying frames hold the byte range of their data in the packet
/// payload, so the caller can share it without copying.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    Padding,
    Ping,
    Ack {
        /// Acknowledged packet numbers, highest range first.
        ranges: Vec<Range<u64>>,
        /// Raw ACK Delay field (scaled by the peer's ack_delay_exponent).
        delay: u64,
        /// ECT(0), ECT(1), ECN-CE counts (ACK_ECN).
        ecn: Option<[u64; 3]>,
    },
    ResetStream {
        id: u64,
        code: u64,
        final_size: u64,
    },
    StopSending {
        id: u64,
        code: u64,
    },
    Crypto {
        offset: u64,
        data: Range<usize>,
    },
    NewToken(&'a [u8]),
    Stream {
        id: u64,
        offset: u64,
        data: Range<usize>,
        fin: bool,
    },
    MaxData(u64),
    MaxStreamData {
        id: u64,
        max: u64,
    },
    MaxStreams {
        bidi: bool,
        max: u64,
    },
    DataBlocked(u64),
    StreamDataBlocked {
        id: u64,
        max: u64,
    },
    StreamsBlocked {
        bidi: bool,
        max: u64,
    },
    NewConnectionId {
        seq: u64,
        retire_prior_to: u64,
        cid: ConnectionId,
        token: ResetToken,
    },
    RetireConnectionId(u64),
    PathChallenge([u8; 8]),
    PathResponse([u8; 8]),
    ConnectionClose {
        app: bool,
        code: u64,
        frame: u64,
        reason: &'a [u8],
    },
    HandshakeDone,
    Datagram(Range<usize>),
}

impl Frame<'_> {
    /// Whether receiving it makes the packet ack-eliciting.
    pub fn ack_eliciting(&self) -> bool {
        !matches!(
            self,
            Frame::Padding | Frame::Ack { .. } | Frame::ConnectionClose { .. }
        )
    }

    /// Whether it is a probing frame (RFC 9000 section 9.1).
    pub fn probing(&self) -> bool {
        matches!(
            self,
            Frame::Padding
                | Frame::PathChallenge(_)
                | Frame::PathResponse(_)
                | Frame::NewConnectionId { .. }
        )
    }

    /// Whether an Initial or Handshake packet may carry it.
    pub fn allowed_in_handshake(&self) -> bool {
        matches!(
            self,
            Frame::Padding
                | Frame::Ping
                | Frame::Ack { .. }
                | Frame::Crypto { .. }
                | Frame::ConnectionClose { app: false, .. }
        )
    }
}

/// Parses the next frame. `ty` gets the frame type for error reports.
pub fn parse<'a>(r: &mut Reader<'a>) -> Result<Frame<'a>, TransportError> {
    let t = r.varint().ok_or_else(|| enc_err(0))?;
    let e = || enc_err(t);
    let f = match t {
        ty::PADDING => {
            // Swallow a run of padding at once.
            while r.peek() == Some(0) {
                r.u8();
            }
            Frame::Padding
        }
        ty::PING => Frame::Ping,
        ty::ACK | ty::ACK_ECN => {
            let largest = r.varint().ok_or_else(e)?;
            let delay = r.varint().ok_or_else(e)?;
            let count = r.varint().ok_or_else(e)?;
            let first = r.varint().ok_or_else(e)?;
            if first > largest {
                return Err(e());
            }
            let mut ranges = Vec::with_capacity(1 + count.min(32) as usize);
            ranges.push(largest - first..largest + 1);
            let mut smallest = largest - first;
            for _ in 0..count {
                let gap = r.varint().ok_or_else(e)?;
                let len = r.varint().ok_or_else(e)?;
                let hi = smallest.checked_sub(gap + 2).ok_or_else(e)?;
                let lo = hi.checked_sub(len).ok_or_else(e)?;
                ranges.push(lo..hi + 1);
                smallest = lo;
            }
            let ecn = if t == ty::ACK_ECN {
                Some([
                    r.varint().ok_or_else(e)?,
                    r.varint().ok_or_else(e)?,
                    r.varint().ok_or_else(e)?,
                ])
            } else {
                None
            };
            Frame::Ack { ranges, delay, ecn }
        }
        ty::RESET_STREAM => Frame::ResetStream {
            id: r.varint().ok_or_else(e)?,
            code: r.varint().ok_or_else(e)?,
            final_size: r.varint().ok_or_else(e)?,
        },
        ty::STOP_SENDING => Frame::StopSending {
            id: r.varint().ok_or_else(e)?,
            code: r.varint().ok_or_else(e)?,
        },
        ty::CRYPTO => {
            let offset = r.varint().ok_or_else(e)?;
            let len = r.varint().ok_or_else(e)?;
            let start = r.pos();
            let n = usize::try_from(len).map_err(|_| e())?;
            r.bytes(n).ok_or_else(e)?;
            if offset + len > VARINT_MAX {
                return Err(e());
            }
            Frame::Crypto {
                offset,
                data: start..start + n,
            }
        }
        ty::NEW_TOKEN => {
            let tok = r.vbytes().ok_or_else(e)?;
            if tok.is_empty() {
                return Err(e());
            }
            Frame::NewToken(tok)
        }
        0x08..=0x0f => {
            let id = r.varint().ok_or_else(e)?;
            let offset = if t & 0x04 != 0 {
                r.varint().ok_or_else(e)?
            } else {
                0
            };
            let n = if t & 0x02 != 0 {
                usize::try_from(r.varint().ok_or_else(e)?).map_err(|_| e())?
            } else {
                r.remaining()
            };
            let start = r.pos();
            r.bytes(n).ok_or_else(e)?;
            if offset + n as u64 > VARINT_MAX {
                return Err(TransportError {
                    code: code::FRAME_ENCODING_ERROR,
                    frame: Some(t),
                    reason: "stream offset too large".into(),
                });
            }
            Frame::Stream {
                id,
                offset,
                data: start..start + n,
                fin: t & 0x01 != 0,
            }
        }
        ty::MAX_DATA => Frame::MaxData(r.varint().ok_or_else(e)?),
        ty::MAX_STREAM_DATA => Frame::MaxStreamData {
            id: r.varint().ok_or_else(e)?,
            max: r.varint().ok_or_else(e)?,
        },
        ty::MAX_STREAMS_BIDI | ty::MAX_STREAMS_UNI => Frame::MaxStreams {
            bidi: t == ty::MAX_STREAMS_BIDI,
            max: r.varint().ok_or_else(e)?,
        },
        ty::DATA_BLOCKED => Frame::DataBlocked(r.varint().ok_or_else(e)?),
        ty::STREAM_DATA_BLOCKED => Frame::StreamDataBlocked {
            id: r.varint().ok_or_else(e)?,
            max: r.varint().ok_or_else(e)?,
        },
        ty::STREAMS_BLOCKED_BIDI | ty::STREAMS_BLOCKED_UNI => Frame::StreamsBlocked {
            bidi: t == ty::STREAMS_BLOCKED_BIDI,
            max: r.varint().ok_or_else(e)?,
        },
        ty::NEW_CONNECTION_ID => {
            let seq = r.varint().ok_or_else(e)?;
            let retire_prior_to = r.varint().ok_or_else(e)?;
            let len = usize::from(r.u8().ok_or_else(e)?);
            if !(1..=20).contains(&len) || retire_prior_to > seq {
                return Err(e());
            }
            let cid = ConnectionId::new(r.bytes(len).ok_or_else(e)?).ok_or_else(e)?;
            Frame::NewConnectionId {
                seq,
                retire_prior_to,
                cid,
                token: r.array().ok_or_else(e)?,
            }
        }
        ty::RETIRE_CONNECTION_ID => Frame::RetireConnectionId(r.varint().ok_or_else(e)?),
        ty::PATH_CHALLENGE => Frame::PathChallenge(r.array().ok_or_else(e)?),
        ty::PATH_RESPONSE => Frame::PathResponse(r.array().ok_or_else(e)?),
        ty::CONNECTION_CLOSE | ty::CONNECTION_CLOSE_APP => {
            let app = t == ty::CONNECTION_CLOSE_APP;
            let code = r.varint().ok_or_else(e)?;
            let frame = if app { 0 } else { r.varint().ok_or_else(e)? };
            let reason = r.vbytes().ok_or_else(e)?;
            Frame::ConnectionClose {
                app,
                code,
                frame,
                reason,
            }
        }
        ty::HANDSHAKE_DONE => Frame::HandshakeDone,
        ty::DATAGRAM | ty::DATAGRAM_LEN => {
            let n = if t == ty::DATAGRAM_LEN {
                usize::try_from(r.varint().ok_or_else(e)?).map_err(|_| e())?
            } else {
                r.remaining()
            };
            let start = r.pos();
            r.bytes(n).ok_or_else(e)?;
            Frame::Datagram(start..start + n)
        }
        _ => {
            return Err(TransportError {
                code: code::FRAME_ENCODING_ERROR,
                frame: Some(t),
                reason: "unknown frame type".into(),
            });
        }
    };
    Ok(f)
}

// ---- encoding ----

/// Writes an ACK frame for `ranges` (at most `max_ranges` highest), with the raw delay field.
#[cfg_attr(not(any(test, feature = "fuzzing")), allow(dead_code))]
pub fn put_ack(out: &mut Vec<u8>, ranges: &RangeSet, delay: u64, max_ranges: usize) {
    put_ack_ecn(out, ranges, delay, max_ranges, None);
}

/// [`put_ack`], as an ACK_ECN frame carrying the ECT(0), ECT(1) and CE counts when given.
pub fn put_ack_ecn(
    out: &mut Vec<u8>,
    ranges: &RangeSet,
    delay: u64,
    max_ranges: usize,
    ecn: Option<[u64; 3]>,
) {
    let mut it = ranges.iter().rev().take(max_ranges.max(1));
    let Some(first) = it.next() else { return };
    let rest: Vec<Range<u64>> = it.collect();
    put_varint(out, if ecn.is_some() { ty::ACK_ECN } else { ty::ACK });
    let largest = first.end - 1;
    put_varint(out, largest);
    put_varint(out, delay);
    put_varint(out, rest.len() as u64);
    put_varint(out, largest - first.start);
    let mut smallest = first.start;
    for r in rest {
        let hi = r.end - 1;
        put_varint(out, smallest - hi - 2);
        put_varint(out, hi - r.start);
        smallest = r.start;
    }
    if let Some(c) = ecn {
        for v in c {
            put_varint(out, v);
        }
    }
}

/// Upper bound of an ACK frame's size (an ACK_ECN frame's: three counts included).
pub fn ack_size(ranges: &RangeSet, delay: u64, max_ranges: usize) -> usize {
    let n = ranges.len().min(max_ranges.max(1));
    1 + 8 + varint_len(delay) + varint_len(n as u64) + n * 16 + 3 * 8
}

pub fn put_crypto_header(out: &mut Vec<u8>, offset: u64, len: usize) {
    put_varint(out, ty::CRYPTO);
    put_varint(out, offset);
    put_varint(out, len as u64);
}

pub fn crypto_header_size(offset: u64, len: usize) -> usize {
    1 + varint_len(offset) + varint_len(len as u64)
}

/// A STREAM frame header (with offset if non-zero, always with a length).
pub fn put_stream_header(out: &mut Vec<u8>, id: u64, offset: u64, len: usize, fin: bool) {
    let mut t = ty::STREAM | 0x02;
    if offset != 0 {
        t |= 0x04;
    }
    if fin {
        t |= 0x01;
    }
    put_varint(out, t);
    put_varint(out, id);
    if offset != 0 {
        put_varint(out, offset);
    }
    put_varint(out, len as u64);
}

pub fn put_simple(out: &mut Vec<u8>, t: u64, vals: &[u64]) {
    put_varint(out, t);
    for &v in vals {
        put_varint(out, v);
    }
}

pub fn put_new_cid(out: &mut Vec<u8>, seq: u64, rpt: u64, cid: &ConnectionId, token: &ResetToken) {
    put_varint(out, ty::NEW_CONNECTION_ID);
    put_varint(out, seq);
    put_varint(out, rpt);
    out.push(cid.len() as u8);
    out.extend_from_slice(cid);
    out.extend_from_slice(token);
}

pub fn put_close(out: &mut Vec<u8>, app: bool, code: u64, frame: u64, reason: &[u8]) {
    put_varint(
        out,
        if app {
            ty::CONNECTION_CLOSE_APP
        } else {
            ty::CONNECTION_CLOSE
        },
    );
    put_varint(out, code);
    if !app {
        put_varint(out, frame);
    }
    put_varint(out, reason.len() as u64);
    out.extend_from_slice(reason);
}

pub fn put_datagram(out: &mut Vec<u8>, data: &[u8]) {
    put_varint(out, ty::DATAGRAM_LEN);
    put_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(b: &[u8]) -> Result<Frame<'_>, TransportError> {
        let mut r = Reader::new(b);
        let f = parse(&mut r)?;
        assert!(r.is_empty(), "trailing bytes after {f:?}");
        Ok(f)
    }

    #[test]
    fn acks_round_trip() {
        let mut s = RangeSet::new();
        s.insert(0..3);
        s.insert(5..6);
        s.insert(10..20);
        let mut out = Vec::new();
        put_ack(&mut out, &s, 7, 32);
        assert!(out.len() <= ack_size(&s, 7, 32));
        let Frame::Ack { ranges, delay, ecn } = one(&out).unwrap() else {
            panic!()
        };
        assert_eq!(ranges, vec![10..20, 5..6, 0..3]);
        assert_eq!((delay, ecn), (7, None));
        // Limited to the two highest.
        out.clear();
        put_ack(&mut out, &s, 0, 2);
        let Frame::Ack { ranges, .. } = one(&out).unwrap() else {
            panic!()
        };
        assert_eq!(ranges, vec![10..20, 5..6]);
        // ACK_ECN with counts; a range below zero is an encoding error.
        assert_eq!(
            one(&[0x03, 5, 0, 0, 0, 1, 2, 3]).unwrap(),
            Frame::Ack {
                ranges: std::iter::once(5..6).collect(),
                delay: 0,
                ecn: Some([1, 2, 3])
            }
        );
        assert_eq!(
            one(&[0x02, 5, 0, 0, 6]).unwrap_err().code,
            code::FRAME_ENCODING_ERROR
        );
        assert!(one(&[0x02, 5, 0, 1, 0, 4, 0]).is_err());
        let empty = RangeSet::new();
        out.clear();
        put_ack(&mut out, &empty, 0, 4);
        assert!(out.is_empty());
        // And written.
        put_ack_ecn(&mut out, &s, 3, 32, Some([7, 0, 1 << 40]));
        assert!(out.len() <= ack_size(&s, 3, 32));
        let Frame::Ack { ranges, ecn, .. } = one(&out).unwrap() else {
            panic!()
        };
        assert_eq!(ranges.len(), 3);
        assert_eq!(ecn, Some([7, 0, 1 << 40]));
    }

    #[test]
    fn all_frames_round_trip() {
        let cid = ConnectionId::new(&[9; 8]).unwrap();
        let mut out = Vec::new();
        put_simple(&mut out, ty::PING, &[]);
        put_simple(&mut out, ty::RESET_STREAM, &[4, 7, 100]);
        put_simple(&mut out, ty::STOP_SENDING, &[4, 9]);
        put_crypto_header(&mut out, 10, 3);
        out.extend_from_slice(b"abc");
        put_simple(&mut out, ty::NEW_TOKEN, &[2]);
        out.extend_from_slice(b"tk");
        put_stream_header(&mut out, 8, 0, 2, false);
        out.extend_from_slice(b"hi");
        put_stream_header(&mut out, 8, 2, 0, true);
        put_simple(&mut out, ty::MAX_DATA, &[1000]);
        put_simple(&mut out, ty::MAX_STREAM_DATA, &[8, 50]);
        put_simple(&mut out, ty::MAX_STREAMS_BIDI, &[10]);
        put_simple(&mut out, ty::MAX_STREAMS_UNI, &[11]);
        put_simple(&mut out, ty::DATA_BLOCKED, &[12]);
        put_simple(&mut out, ty::STREAM_DATA_BLOCKED, &[8, 13]);
        put_simple(&mut out, ty::STREAMS_BLOCKED_BIDI, &[14]);
        put_simple(&mut out, ty::STREAMS_BLOCKED_UNI, &[15]);
        put_new_cid(&mut out, 3, 1, &cid, &[7; 16]);
        put_simple(&mut out, ty::RETIRE_CONNECTION_ID, &[2]);
        put_simple(&mut out, ty::PATH_CHALLENGE, &[]);
        out.extend_from_slice(&[1; 8]);
        put_simple(&mut out, ty::PATH_RESPONSE, &[]);
        out.extend_from_slice(&[2; 8]);
        put_close(&mut out, false, 0xa, 0x08, b"bad");
        put_close(&mut out, true, 5, 0, b"app");
        put_simple(&mut out, ty::HANDSHAKE_DONE, &[]);
        put_datagram(&mut out, b"dg");
        out.extend_from_slice(&[0, 0, 0]);
        let mut r = Reader::new(&out);
        let mut got = Vec::new();
        while !r.is_empty() {
            got.push(parse(&mut r).unwrap());
        }
        let crypto_at = 1 + 5 + 3 + 3;
        let want = vec![
            Frame::Ping,
            Frame::ResetStream {
                id: 4,
                code: 7,
                final_size: 100,
            },
            Frame::StopSending { id: 4, code: 9 },
            Frame::Crypto {
                offset: 10,
                data: crypto_at..crypto_at + 3,
            },
            Frame::NewToken(b"tk"),
            Frame::Stream {
                id: 8,
                offset: 0,
                data: crypto_at + 3 + 4 + 3..crypto_at + 3 + 4 + 3 + 2,
                fin: false,
            },
            Frame::Stream {
                id: 8,
                offset: 2,
                data: crypto_at + 3 + 4 + 3 + 2 + 4..crypto_at + 3 + 4 + 3 + 2 + 4,
                fin: true,
            },
            Frame::MaxData(1000),
            Frame::MaxStreamData { id: 8, max: 50 },
            Frame::MaxStreams {
                bidi: true,
                max: 10,
            },
            Frame::MaxStreams {
                bidi: false,
                max: 11,
            },
            Frame::DataBlocked(12),
            Frame::StreamDataBlocked { id: 8, max: 13 },
            Frame::StreamsBlocked {
                bidi: true,
                max: 14,
            },
            Frame::StreamsBlocked {
                bidi: false,
                max: 15,
            },
            Frame::NewConnectionId {
                seq: 3,
                retire_prior_to: 1,
                cid,
                token: [7; 16],
            },
            Frame::RetireConnectionId(2),
            Frame::PathChallenge([1; 8]),
            Frame::PathResponse([2; 8]),
            Frame::ConnectionClose {
                app: false,
                code: 0xa,
                frame: 8,
                reason: b"bad",
            },
            Frame::ConnectionClose {
                app: true,
                code: 5,
                frame: 0,
                reason: b"app",
            },
            Frame::HandshakeDone,
        ];
        assert_eq!(&got[..want.len()], &want[..]);
        assert!(matches!(got[want.len()], Frame::Datagram(ref r) if r.len() == 2));
        assert_eq!(got[want.len() + 1], Frame::Padding);
        assert_eq!(got.len(), want.len() + 2);
        assert!(Frame::Ping.ack_eliciting() && !Frame::Padding.ack_eliciting());
        assert!(Frame::PathChallenge([0; 8]).probing() && !Frame::Ping.probing());
        assert!(Frame::Ping.allowed_in_handshake() && !Frame::HandshakeDone.allowed_in_handshake());
        assert!(out.len() > crypto_header_size(10, 3));
    }

    #[test]
    fn malformed_frames() {
        for bad in [
            &[0x40][..],                // truncated type
            &[0x21][..],                // unknown type
            &[0x06, 0, 5, 1][..],       // short CRYPTO
            &[0x07, 0][..],             // empty NEW_TOKEN
            &[0x0a, 0, 9, 1][..],       // short STREAM
            &[0x18, 1, 2, 8][..],       // retire_prior_to > seq
            &[0x18, 1, 0, 21][..],      // CID too long
            &[0x1a, 1, 2][..],          // short PATH_CHALLENGE
            &[0x1c, 1, 0, 5, b'x'][..], // short reason
            &[0x31, 4, 1][..],          // short DATAGRAM
            &[0x0e, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
        ] {
            assert!(one(bad).is_err(), "{bad:?}");
        }
        // Unbounded STREAM and DATAGRAM frames take the rest.
        assert!(
            matches!(one(&[0x08, 0, 1, 2]).unwrap(), Frame::Stream { data, .. } if data == (2..4))
        );
        assert_eq!(one(&[0x30, 1]).unwrap(), Frame::Datagram(1..2));
        let e = TransportError::new(code::PROTOCOL_VIOLATION, "x");
        assert_eq!(e.to_string(), "transport error 0xa: x");
    }
}
