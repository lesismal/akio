//! IPv4 (RFC 791 / RFC 815) and IPv6 (RFC 8200 4.5) fragment reassembly with limits:
//! concurrent datagrams, buffered bytes and a timeout, so hostile fragments cannot exhaust
//! memory. IPv6 fragments that overlap are discarded with their whole datagram (RFC 5722; an
//! exact duplicate is ignored).

use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

use super::buf::Assembler;

/// A partially received datagram is dropped this long after its first fragment.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(30);
/// Datagrams being reassembled at once.
pub(crate) const MAX_DATAGRAMS: usize = 64;
/// Bytes buffered for all of them.
pub(crate) const MAX_BYTES: usize = 1 << 20;
/// Largest IPv4 payload.
const MAX_PAYLOAD: usize = 65535 - 20;
/// Largest IPv6 fragmentable part (the payload length less the fragment header).
const MAX_PAYLOAD_V6: usize = 65535 - 8;

/// (source, destination, protocol (IPv4 only, 0 for IPv6), identification).
type Key = (IpAddr, IpAddr, u8, u32);

#[derive(Debug)]
struct Partial {
    data: Vec<u8>,
    /// Ranges received, offsets from 0 (`Assembler` with the in-order point fixed at 0).
    have: Assembler,
    /// Payload length, known once the last fragment (MF clear) arrived.
    total: Option<usize>,
    /// Upper-layer protocol (IPv6: from the first fragment's fragment header).
    proto: u8,
    deadline: Instant,
}

/// A reassembled datagram.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Datagram {
    pub(crate) src: IpAddr,
    pub(crate) dst: IpAddr,
    pub(crate) proto: u8,
    pub(crate) payload: Vec<u8>,
}

#[derive(Debug, Default)]
pub(crate) struct Reassembler {
    parts: HashMap<Key, Partial>,
    bytes: usize,
    next_deadline: Option<Instant>,
}

impl Reassembler {
    /// Adds one fragment (`offset` bytes into the payload, `more` = MF / M flag). `proto` is
    /// the upper-layer protocol: IPv4's protocol field, or the Next Header of an IPv6 fragment
    /// header (taken from the first fragment). Returns the whole datagram once complete.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        proto: u8,
        id: u32,
        offset: usize,
        more: bool,
        data: &[u8],
        now: Instant,
    ) -> Option<Datagram> {
        let v6 = src.is_ipv6();
        let end = offset + data.len();
        let max = if v6 { MAX_PAYLOAD_V6 } else { MAX_PAYLOAD };
        if end > max || (more && (data.is_empty() || data.len() % 8 != 0)) {
            return None;
        }
        self.expire(now);
        let key = (src, dst, if v6 { 0 } else { proto }, id);
        if !self.parts.contains_key(&key) {
            if self.parts.len() >= MAX_DATAGRAMS {
                return None;
            }
            let deadline = now + TIMEOUT;
            self.next_deadline = Some(self.next_deadline.map_or(deadline, |d| d.min(deadline)));
            self.parts.insert(
                key,
                Partial {
                    data: Vec::new(),
                    have: Assembler::default(),
                    total: None,
                    proto,
                    deadline,
                },
            );
        }
        let p = self.parts.get_mut(&key)?;
        if v6 {
            let r = (offset as u32, end as u32);
            if p.have.ranges().contains(&r) {
                return None; // an exact duplicate
            }
            if p.have.ranges().iter().any(|&(s, e)| s < r.1 && r.0 < e) {
                // RFC 5722: overlapping fragments discard the whole datagram.
                let gone = self.parts.remove(&key).map_or(0, |p| p.data.len());
                self.bytes -= gone;
                return None;
            }
            if offset == 0 {
                p.proto = proto;
            }
        }
        if !more {
            if p.total.is_some_and(|t| t != end) || p.data.len() > end {
                // Conflicting lengths: drop the datagram.
                let gone = self.parts.remove(&key).map_or(0, |p| p.data.len());
                self.bytes -= gone;
                return None;
            }
            p.total = Some(end);
        } else if p.total.is_some_and(|t| end > t) {
            return None;
        }
        if end > p.data.len() {
            let grow = end - p.data.len();
            if self.bytes + grow > MAX_BYTES {
                return None;
            }
            self.bytes += grow;
            p.data.resize(end, 0);
        }
        if !p.have.add(offset as u32, end as u32) {
            return None;
        }
        p.data[offset..end].copy_from_slice(data);
        let complete =
            p.total.is_some_and(|t| p.have.ranges() == [(0, t as u32)]) || p.total == Some(0);
        if !complete {
            return None;
        }
        let p = self.parts.remove(&key)?;
        self.bytes -= p.data.len();
        Some(Datagram {
            src,
            dst,
            proto: p.proto,
            payload: p.data,
        })
    }

    /// Drops datagrams past their timeout.
    pub(crate) fn expire(&mut self, now: Instant) {
        match self.next_deadline {
            Some(d) if now >= d => {}
            _ => return,
        }
        let mut freed = 0;
        let mut next: Option<Instant> = None;
        self.parts.retain(|_, p| {
            if now >= p.deadline {
                freed += p.data.len();
                false
            } else {
                next = Some(next.map_or(p.deadline, |d| d.min(p.deadline)));
                true
            }
        });
        self.bytes -= freed;
        self.next_deadline = next;
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.next_deadline
    }

    #[cfg(test)]
    fn pending(&self) -> (usize, usize) {
        (self.parts.len(), self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{Ipv4Addr, Ipv6Addr};

    const S: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    const D: IpAddr = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
    const S6: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
    const D6: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2));

    #[test]
    fn ipv6_fragments_and_overlap() {
        let t = Instant::now();
        let mut r = Reassembler::default();
        let payload: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
        // Later fragments carry another next header: the first fragment's wins.
        assert!(
            r.add(S6, D6, 99, 1 << 20, 1232, true, &payload[1232..2464], t)
                .is_none()
        );
        // An exact duplicate is ignored.
        assert!(
            r.add(S6, D6, 99, 1 << 20, 1232, true, &payload[1232..2464], t)
                .is_none()
        );
        assert!(
            r.add(S6, D6, 17, 1 << 20, 0, true, &payload[..1232], t)
                .is_none()
        );
        let d = r
            .add(S6, D6, 99, 1 << 20, 2464, false, &payload[2464..], t)
            .unwrap();
        assert_eq!((d.proto, d.payload.len()), (17, 3000));
        assert_eq!(d.payload, payload);
        // Overlap: the datagram is gone.
        assert!(r.add(S6, D6, 17, 9, 0, true, &payload[..16], t).is_none());
        assert!(r.add(S6, D6, 17, 9, 8, true, &payload[8..24], t).is_none());
        assert_eq!(r.pending(), (0, 0));
        // ... and later fragments start a new one, which never completes alone.
        assert!(
            r.add(S6, D6, 17, 9, 16, false, &payload[16..24], t)
                .is_none()
        );
        assert_eq!(r.pending().0, 1);
        // The IPv6 limit is the 16-bit payload length less the fragment header.
        assert!(r.add(S6, D6, 17, 10, 65528, false, &[0; 8], t).is_none());
        assert_eq!(r.pending().0, 1);
    }

    #[test]
    fn out_of_order_fragments() {
        let t = Instant::now();
        let mut r = Reassembler::default();
        let payload: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        assert!(
            r.add(S, D, 17, 7, 2400, false, &payload[2400..], t)
                .is_none()
        );
        assert!(r.add(S, D, 17, 7, 0, true, &payload[..1200], t).is_none());
        // Another datagram interleaved.
        assert!(r.add(S, D, 17, 8, 0, true, &payload[..8], t).is_none());
        let d = r
            .add(S, D, 17, 7, 1200, true, &payload[1200..2400], t)
            .unwrap();
        assert_eq!(d.payload, payload);
        assert_eq!(r.pending(), (1, 8));
        r.expire(t + TIMEOUT);
        assert_eq!(r.pending(), (0, 0));
    }

    #[test]
    fn limits() {
        let t = Instant::now();
        let mut r = Reassembler::default();
        for id in 0..MAX_DATAGRAMS as u32 {
            assert!(r.add(S, D, 17, id, 0, true, &[0; 8], t).is_none());
        }
        // Table full: a new datagram is refused.
        assert!(r.add(S, D, 17, 999, 0, true, &[0; 8], t).is_none());
        assert_eq!(r.pending().0, MAX_DATAGRAMS);
        // Not a multiple of 8 with MF set, or past the maximum: refused.
        assert!(r.add(S, D, 17, 0, 8, true, &[0; 7], t).is_none());
        assert!(r.add(S, D, 17, 0, 65528, false, &[0; 100], t).is_none());
        // Conflicting last fragments drop the datagram.
        assert!(r.add(S, D, 17, 1, 16, false, &[0; 8], t).is_none());
        assert!(r.add(S, D, 17, 1, 32, false, &[0; 8], t).is_none());
        assert_eq!(r.pending().0, MAX_DATAGRAMS - 1);
    }

    #[test]
    fn byte_budget() {
        let t = Instant::now();
        let mut r = Reassembler::default();
        let big = vec![0u8; 60_000];
        let mut accepted = 0;
        for id in 0..40u32 {
            r.add(S, D, 17, id, 0, true, &big, t);
            accepted = r.pending().1;
        }
        assert!(accepted <= MAX_BYTES);
    }
}
