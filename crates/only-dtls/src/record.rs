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

/// DTLS 1.2 on the wire.
pub(crate) const DTLS12: u16 = 0xfefd;
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
pub(crate) fn split(datagram: &[u8]) -> Vec<(Header, &[u8])> {
    let mut out = Vec::new();
    let mut r = Reader::new(datagram);
    while !r.is_empty() {
        let Ok(h) = read_header(&mut r) else { break };
        let Ok(fragment) = r.vec16() else { break };
        if fragment.len() > MAX_CIPHERTEXT {
            break;
        }
        out.push((h, fragment));
    }
    out
}

fn read_header(r: &mut Reader<'_>) -> Result<Header, crate::Error> {
    let content_type = r.u8()?;
    let version = r.u16()?;
    let epoch = r.u16()?;
    let seq = r.u48()?;
    if !matches!(
        content_type,
        CT_CHANGE_CIPHER_SPEC | CT_ALERT | CT_HANDSHAKE | CT_APPLICATION_DATA
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
