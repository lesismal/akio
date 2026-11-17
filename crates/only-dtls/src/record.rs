//! The DTLS record layer (RFC 6347 §4.1): headers, datagram splitting and the anti-replay
//! window.

use crate::codec::{Reader, put_u16, put_u48};

/// `change_cipher_spec` content type.
pub(crate) const CT_CHANGE_CIPHER_SPEC: u8 = 20;
/// `alert` content type.
pub(crate) const CT_ALERT: u8 = 21;
/// `handshake` content type.
pub(crate) const CT_HANDSHAKE: u8 = 22;
/// `application_data` content type.
pub(crate) const CT_APPLICATION_DATA: u8 = 23;
/// `tls12_cid` content type (RFC 9146).
pub(crate) const CT_TLS12_CID: u8 = 25;
/// `ack` content type (RFC 9147 §7).
pub(crate) const CT_ACK: u8 = 26;

/// DTLS 1.2 on the wire.
pub(crate) const DTLS12: u16 = 0xfefd;
/// DTLS 1.3 in `supported_versions` (RFC 9147 §5.3).
pub(crate) const DTLS13: u16 = 0xfefc;
/// DTLS 1.0 on the wire (accepted in epoch-0 record headers and HelloVerifyRequest).
pub(crate) const DTLS10: u16 = 0xfeff;

/// Record header length: type, version, epoch, 48-bit sequence number, length.
pub(crate) const HEADER_LEN: usize = 13;
/// Largest plaintext fragment (2^14).
pub(crate) const MAX_PLAINTEXT: usize = 16384;
/// Largest protected fragment accepted (2^14 + 2048, RFC 5246 §6.2.3).
pub(crate) const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 2048;
/// Largest sequence number (2^48 - 1).
pub(crate) const MAX_SEQ: u64 = (1 << 48) - 1;

/// A parsed record header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    pub(crate) content_type: u8,
    pub(crate) version: u16,
    pub(crate) epoch: u16,
    pub(crate) seq: u64,
}

impl Header {
    /// The 13-byte header with `len` as the fragment length.
    pub(crate) fn encode(&self, len: usize, out: &mut Vec<u8>) {
        out.push(self.content_type);
        put_u16(out, self.version);
        put_u16(out, self.epoch);
        put_u48(out, self.seq);
        put_u16(out, len as u16);
    }

    /// The 64-bit `epoch || sequence_number` value used in nonces and the MAC input.
    pub(crate) fn epoch_seq(&self) -> u64 {
        u64::from(self.epoch) << 48 | self.seq
    }
}

/// Splits a datagram into records. Stops at the first malformed record (RFC 6347 §4.1.2.7:
/// invalid records are discarded; a broken length makes the rest of the datagram unusable).
/// `tls12_cid` records are skipped (see [`split_cid`]).
pub(crate) fn split(datagram: &[u8]) -> Vec<(Header, &[u8])> {
    split_cid(datagram, 0)
        .into_iter()
        .filter_map(|r| match r {
            Wire::Plain {
                h,
                cid: None,
                fragment,
            } => Some((h, fragment)),
            _ => None,
        })
        .collect()
}

/// One record of a datagram as it is on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Wire<'a> {
    /// A record with the 13-byte DTLS 1.2 header (DTLS 1.2 records, DTLS 1.3 DTLSPlaintext),
    /// or an RFC 9146 `tls12_cid` record with the CID after the sequence number.
    Plain {
        h: Header,
        cid: Option<&'a [u8]>,
        fragment: &'a [u8],
    },
    /// A DTLS 1.3 DTLSCiphertext with the unified header (RFC 9147 §4).
    Unified(Unified<'a>),
}

/// A DTLS 1.3 unified header record: `0b001CSLEE`, CID, 8- or 16-bit (encrypted) sequence
/// number, optional length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unified<'a> {
    /// The header bytes as received (the sequence number still encrypted).
    pub(crate) header: &'a [u8],
    pub(crate) epoch_bits: u8,
    pub(crate) cid: Option<&'a [u8]>,
    /// Offset and length (1 or 2) of the sequence number in `header`.
    pub(crate) seq_at: usize,
    pub(crate) seq_len: usize,
    pub(crate) ciphertext: &'a [u8],
}

/// Splits a datagram into records of either header form; `cid_len` is the length of the
/// connection ID this endpoint asked the peer to use (0: none). Stops at the first malformed
/// record.
pub(crate) fn split_cid(datagram: &[u8], cid_len: usize) -> Vec<Wire<'_>> {
    let mut out = Vec::new();
    let mut rest = datagram;
    while let Some(&first) = rest.first() {
        if first & 0xe0 == 0x20 {
            let Some((u, n)) = parse_unified(rest, cid_len) else {
                break;
            };
            out.push(Wire::Unified(u));
            rest = &rest[n..];
            continue;
        }
        let mut r = Reader::new(rest);
        let Ok(h) = read_header(&mut r) else { break };
        let cid = if h.content_type == CT_TLS12_CID {
            if cid_len == 0 {
                break;
            }
            let Ok(c) = r.bytes(cid_len) else { break };
            Some(c)
        } else {
            None
        };
        let Ok(fragment) = r.vec16() else { break };
        if fragment.len() > MAX_CIPHERTEXT {
            break;
        }
        out.push(Wire::Plain { h, cid, fragment });
        let used = rest.len() - r.rest().len();
        rest = &rest[used..];
    }
    out
}

fn parse_unified(d: &[u8], cid_len: usize) -> Option<(Unified<'_>, usize)> {
    let first = d[0];
    let has_cid = first & 0x10 != 0;
    let seq_len = if first & 0x08 != 0 { 2 } else { 1 };
    let has_len = first & 0x04 != 0;
    if has_cid && cid_len == 0 {
        return None;
    }
    let mut at = 1;
    let cid = if has_cid {
        let c = d.get(at..at + cid_len)?;
        at += cid_len;
        Some(c)
    } else {
        None
    };
    let seq_at = at;
    at += seq_len;
    let (len, hdr_end) = if has_len {
        let l = d.get(at..at + 2)?;
        (usize::from(u16::from_be_bytes([l[0], l[1]])), at + 2)
    } else {
        (d.len().checked_sub(at)?, at)
    };
    let ciphertext = d.get(hdr_end..hdr_end + len)?;
    if len > MAX_CIPHERTEXT {
        return None;
    }
    Some((
        Unified {
            header: &d[..hdr_end],
            epoch_bits: first & 0x03,
            cid,
            seq_at,
            seq_len,
            ciphertext,
        },
        hdr_end + len,
    ))
}

/// The full sequence number closest to `expected` whose low `bits` bits are `low` (RFC 9147
/// §4.2.2).
pub(crate) fn reconstruct_seq(expected: u64, low: u64, bits: u32) -> u64 {
    let win = 1u64 << bits;
    let mask = win - 1;
    let candidate = (expected & !mask) | low;
    let half = win / 2;
    if candidate + half <= expected && candidate.checked_add(win).is_some() {
        candidate + win
    } else if candidate > expected + half && candidate >= win {
        candidate - win
    } else {
        candidate
    }
}

fn read_header(r: &mut Reader<'_>) -> Result<Header, crate::Error> {
    let content_type = r.u8()?;
    let version = r.u16()?;
    let epoch = r.u16()?;
    let seq = r.u48()?;
    if !matches!(
        content_type,
        CT_CHANGE_CIPHER_SPEC
            | CT_ALERT
            | CT_HANDSHAKE
            | CT_APPLICATION_DATA
            | CT_TLS12_CID
            | CT_ACK
    ) || (version != DTLS12 && version != DTLS10)
    {
        return Err(crate::Error::decode("bad record header"));
    }
    Ok(Header {
        content_type,
        version,
        epoch,
        seq,
    })
}

/// The connection ID of the first record of `datagram`, for a listener that routes datagrams
/// by CID (RFC 9146 / RFC 9147 §9) rather than by address: `cid_len` is the length of the CIDs
/// it hands out. `None` for records without a CID (handshake records, peers that use none).
#[must_use]
pub fn connection_id(datagram: &[u8], cid_len: usize) -> Option<&[u8]> {
    if cid_len == 0 {
        return None;
    }
    match split_cid(datagram, cid_len).into_iter().next()? {
        Wire::Plain { cid, .. } => cid,
        Wire::Unified(u) => u.cid,
    }
}

/// The 64-record sliding anti-replay window of RFC 6347 §4.1.2.6 (one per epoch).
#[derive(Debug, Clone, Default)]
pub(crate) struct ReplayWindow {
    /// Highest sequence number accepted so far, if any.
    top: Option<u64>,
    /// Bit `i` set: `top - i` was accepted.
    bits: u64,
}

impl ReplayWindow {
    const SIZE: u64 = 64;

    /// Highest sequence number accepted so far.
    pub(crate) fn top(&self) -> Option<u64> {
        self.top
    }

    /// Whether `seq` is new (not seen and not left of the window). Does not update the window:
    /// call [`ReplayWindow::accept`] once the record authenticated.
    pub(crate) fn check(&self, seq: u64) -> bool {
        match self.top {
            None => true,
            Some(top) if seq > top => true,
            Some(top) => {
                let d = top - seq;
                d < Self::SIZE && self.bits & (1 << d) == 0
            }
        }
    }

    /// Marks `seq` as received.
    pub(crate) fn accept(&mut self, seq: u64) {
        match self.top {
            None => {
                self.top = Some(seq);
                self.bits = 1;
            }
            Some(top) if seq > top => {
                let shift = seq - top;
                self.bits = if shift >= Self::SIZE {
                    0
                } else {
                    self.bits << shift
                };
                self.bits |= 1;
                self.top = Some(seq);
            }
            Some(top) => {
                let d = top - seq;
                if d < Self::SIZE {
                    self.bits |= 1 << d;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_records() {
        let mut d = Vec::new();
        let h = Header {
            content_type: CT_HANDSHAKE,
            version: DTLS12,
            epoch: 0,
            seq: 7,
        };
        h.encode(3, &mut d);
        d.extend_from_slice(b"abc");
        let h2 = Header {
            content_type: CT_APPLICATION_DATA,
            version: DTLS12,
            epoch: 1,
            seq: MAX_SEQ,
        };
        h2.encode(1, &mut d);
        d.push(9);
        let recs = split(&d);
        assert_eq!(recs, vec![(h, &b"abc"[..]), (h2, &[9u8][..])]);
        // A tls12_cid record with a 4-byte CID after them.
        let mut c = d.clone();
        c.extend_from_slice(&[25, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 3]);
        c.extend_from_slice(b"cid!");
        c.extend_from_slice(&[0, 2, 7, 7]);
        assert_eq!(split(&c).len(), 2, "CID records need the CID length");
        let w = split_cid(&c, 4);
        assert_eq!(w.len(), 3);
        assert!(matches!(
            &w[2],
            Wire::Plain {
                cid: Some(b"cid!"),
                fragment: [7, 7],
                ..
            }
        ));
        assert_eq!(connection_id(&c[d.len()..], 4), Some(&b"cid!"[..]));
        assert_eq!(connection_id(&d, 4), None);
        assert_eq!(h2.epoch_seq(), 1 << 48 | MAX_SEQ);
        // A truncated trailing record is dropped; the first survives.
        assert_eq!(split(&d[..d.len() - 1]).len(), 1);
        // Garbage type or version.
        let mut bad = d.clone();
        bad[0] = 99;
        assert!(split(&bad).is_empty());
        let mut bad = d;
        bad[1] = 3;
        assert!(split(&bad).is_empty());
    }

    #[test]
    fn unified_header() {
        // 0b001_1_1_1_10: CID, 16-bit sequence number, length, epoch bits 2.
        let mut d = vec![0x3e];
        d.extend_from_slice(b"ab");
        d.extend_from_slice(&[0x12, 0x34, 0, 17]);
        d.extend_from_slice(&[9; 17]);
        // Then one without CID, 8-bit sequence number and no length: the rest.
        d.extend_from_slice(&[0x23, 0x56]);
        d.extend_from_slice(&[8; 20]);
        let w = split_cid(&d, 2);
        assert_eq!(w.len(), 2);
        let Wire::Unified(u) = &w[0] else { panic!() };
        assert_eq!(
            (u.epoch_bits, u.cid, u.seq_at, u.seq_len),
            (2, Some(&b"ab"[..]), 3, 2)
        );
        assert_eq!(u.header.len(), 7);
        assert_eq!(u.ciphertext.len(), 17);
        let Wire::Unified(u) = &w[1] else { panic!() };
        assert_eq!(
            (u.epoch_bits, u.cid, u.seq_len, u.ciphertext.len()),
            (3, None, 1, 20)
        );
        assert_eq!(connection_id(&d, 2), Some(&b"ab"[..]));
        // A CID bit without a CID length, or a truncated length: nothing.
        assert!(split_cid(&d, 0).is_empty());
        assert!(split_cid(&d[..10], 2).is_empty());
    }

    #[test]
    fn sequence_reconstruction() {
        assert_eq!(reconstruct_seq(0, 5, 8), 5);
        assert_eq!(reconstruct_seq(0x1ff, 0x01, 8), 0x201);
        assert_eq!(reconstruct_seq(0x201, 0xff, 8), 0x1ff);
        assert_eq!(reconstruct_seq(0x10000, 0xffff, 16), 0xffff);
        assert_eq!(reconstruct_seq(0xfff0, 0x0002, 16), 0x10002);
        assert_eq!(reconstruct_seq(3, 0xfe, 8), 0xfe);
    }

    #[test]
    fn replay_window() {
        let mut w = ReplayWindow::default();
        assert!(w.check(5));
        w.accept(5);
        assert!(!w.check(5));
        assert!(w.check(4));
        assert!(w.check(6));
        w.accept(3);
        assert!(!w.check(3));
        w.accept(100);
        assert!(!w.check(5), "left of the window");
        assert!(!w.check(36));
        assert!(w.check(37));
        assert!(w.check(99));
        w.accept(99);
        assert!(!w.check(99));
        w.accept(1000);
        assert!(!w.check(100));
        assert!(w.check(999));
    }
}
