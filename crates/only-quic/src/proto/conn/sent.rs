//! The packets of one number space that were sent and are neither acknowledged nor lost.
//!
//! Packet numbers only grow, and packets leave this table mostly in the order they entered it,
//! so it is a ring indexed by `pn - base` instead of an ordered map: inserting is a push at the
//! back, an acknowledgment takes a run of slots, and slots emptied at the front are dropped.

use std::collections::VecDeque;
use std::ops::Range;

use super::Sent;

#[derive(Debug, Default)]
pub(crate) struct SentPackets {
    /// The packet number of `slots[0]`.
    base: u64,
    /// `None`: a number not sent in this space, or a packet already acknowledged or lost
    /// (never at the front).
    slots: VecDeque<Option<Sent>>,
    live: usize,
}

impl SentPackets {
    /// Records packet `pn`, which is above every packet recorded before.
    pub(crate) fn insert(&mut self, pn: u64, p: Sent) {
        if self.slots.is_empty() {
            self.base = pn;
        }
        let end = self.base + self.slots.len() as u64;
        debug_assert!(pn >= end, "packet numbers must grow");
        for _ in end..pn {
            self.slots.push_back(None);
        }
        self.slots.push_back(Some(p));
        self.live += 1;
    }

    /// Slot indices of the packet numbers in `r` that the table covers.
    fn span(&self, r: Range<u64>) -> Range<usize> {
        let end = self.base + self.slots.len() as u64;
        let lo = r.start.clamp(self.base, end);
        let hi = r.end.clamp(lo, end);
        (lo - self.base) as usize..(hi - self.base) as usize
    }

    /// Takes packet `pn` out.
    pub(crate) fn remove(&mut self, pn: u64) -> Option<Sent> {
        let i = self.span(pn..pn.saturating_add(1));
        if i.is_empty() {
            return None;
        }
        let p = self.slots[i.start].take()?;
        self.live -= 1;
        self.trim();
        Some(p)
    }

    /// Takes the packets numbered in `r` out, lowest first, appending them to `out`.
    pub(crate) fn remove_range(&mut self, r: Range<u64>, out: &mut Vec<(u64, Sent)>) {
        let span = self.span(r);
        let base = self.base;
        for i in span {
            if let Some(p) = self.slots[i].take() {
                out.push((base + i as u64, p));
                self.live -= 1;
            }
        }
        self.trim();
    }

    /// Drops emptied slots at the front.
    fn trim(&mut self) {
        while matches!(self.slots.front(), Some(None)) {
            self.slots.pop_front();
            self.base += 1;
        }
        if self.live == 0 {
            self.slots.clear();
        }
    }

    /// The packets numbered up to `largest`, lowest first.
    pub(crate) fn up_to(&self, largest: u64) -> impl Iterator<Item = (u64, &Sent)> {
        let span = self.span(0..largest.saturating_add(1));
        let base = self.base;
        self.slots
            .range(span.clone())
            .zip(span)
            .filter_map(move |(p, i)| p.as_ref().map(|p| (base + i as u64, p)))
    }

    /// Every packet, lowest number first.
    pub(crate) fn values(&self) -> impl Iterator<Item = &Sent> {
        self.slots.iter().flatten()
    }

    /// Takes every packet out, lowest number first.
    pub(crate) fn drain(&mut self) -> impl Iterator<Item = Sent> + use<> {
        self.live = 0;
        std::mem::take(&mut self.slots).into_iter().flatten()
    }

    pub(crate) fn clear(&mut self) {
        self.slots.clear();
        self.live = 0;
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.live
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn pkt(size: u16) -> Sent {
        Sent {
            time: Instant::now(),
            size,
            ack_eliciting: true,
            in_flight: true,
            mtu_probe: false,
            ecn: false,
            frames: Vec::new(),
        }
    }

    #[test]
    fn ring_tracks_packets_by_number() {
        let mut s = SentPackets::default();
        assert!(s.remove(0).is_none());
        for pn in [3u64, 4, 5, 7, 8, 10] {
            s.insert(pn, pkt(pn as u16));
        }
        assert_eq!(s.len(), 6);
        assert!(s.remove(6).is_none() && s.remove(2).is_none() && s.remove(99).is_none());
        assert_eq!(
            s.up_to(7).map(|(pn, _)| pn).collect::<Vec<_>>(),
            [3, 4, 5, 7]
        );
        let mut out = Vec::new();
        s.remove_range(4..9, &mut out);
        assert_eq!(
            out.iter().map(|(pn, _)| *pn).collect::<Vec<_>>(),
            [4, 5, 7, 8]
        );
        assert_eq!(s.len(), 2);
        assert_eq!(s.remove(3).map(|p| p.size), Some(3));
        // The front advanced to the next packet left.
        assert_eq!(s.base, 10);
        assert_eq!(s.slots.len(), 1);
        assert_eq!(s.values().map(|p| p.size).collect::<Vec<_>>(), [10]);
        assert_eq!(s.up_to(9).count(), 0);
        s.remove_range(0..u64::MAX, &mut out);
        assert_eq!(s.len(), 0);
        assert!(s.slots.is_empty());
        // Empty: the next packet starts a new base.
        s.insert(20, pkt(20));
        s.insert(21, pkt(21));
        assert_eq!(s.drain().map(|p| p.size).collect::<Vec<_>>(), [20, 21]);
        assert_eq!(s.len(), 0);
        s.insert(30, pkt(30));
        s.clear();
        assert_eq!((s.len(), s.values().count()), (0, 0));
    }
}
