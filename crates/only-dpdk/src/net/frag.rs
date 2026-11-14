//! IPv4 fragment reassembly (RFC 791 / RFC 815) with limits: concurrent datagrams, buffered
//! bytes and a timeout, so hostile fragments cannot exhaust memory.

use std::{
    collections::HashMap,
    net::Ipv4Addr,
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

type Key = (Ipv4Addr, Ipv4Addr, u8, u16);

#[derive(Debug)]
struct Partial {
    data: Vec<u8>,
    /// Ranges received, offsets from 0 (`Assembler` with the in-order point fixed at 0).
    have: Assembler,
    /// Payload length, known once the last fragment (MF clear) arrived.
    total: Option<usize>,
    deadline: Instant,
}

/// A reassembled datagram.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Datagram {
    pub(crate) src: Ipv4Addr,
    pub(crate) dst: Ipv4Addr,
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
    /// Adds one fragment (`offset` bytes into the payload, `more` = MF flag). Returns the whole
    /// datagram once complete.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add(
        &mut self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        proto: u8,
        id: u16,
        offset: usize,
        more: bool,
        data: &[u8],
        now: Instant,
    ) -> Option<Datagram> {
        let end = offset + data.len();
        if end > MAX_PAYLOAD || (more && (data.is_empty() || data.len() % 8 != 0)) {
            return None;
        }
        self.expire(now);
        let key = (src, dst, proto, id);
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
                    deadline,
                },
            );
        }
        let p = self.parts.get_mut(&key)?;
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
            proto,
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

    const S: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
    const D: Ipv4Addr = Ipv4Addr::new(2, 2, 2, 2);

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
        for id in 0..MAX_DATAGRAMS as u16 {
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
        for id in 0..40u16 {
            r.add(S, D, 17, id, 0, true, &big, t);
            accepted = r.pending().1;
        }
        assert!(accepted <= MAX_BYTES);
    }
}
