//! Sliding replay window over 64-bit packet indices (RFC 3711 §3.3.2).

use crate::Error;

#[derive(Debug, Clone)]
pub(crate) struct ReplayWindow {
    /// Highest index accepted so far.
    max: u64,
    /// Bit `i % size` is set when index `i` (within `max - size < i <= max`) was accepted.
    bits: Vec<u64>,
}

impl ReplayWindow {
    /// A window of `words * 64` indices whose first accepted index is `first`.
    pub(crate) fn new(words: usize, first: u64) -> ReplayWindow {
        let mut w = ReplayWindow {
            max: first,
            bits: vec![0; words.max(1)],
        };
        w.set(first);
        w
    }

    fn size(&self) -> u64 {
        self.bits.len() as u64 * 64
    }

    pub(crate) fn max(&self) -> u64 {
        self.max
    }

    fn slot(&self, i: u64) -> (usize, u64) {
        let pos = i % self.size();
        ((pos / 64) as usize, 1u64 << (pos % 64))
    }

    fn set(&mut self, i: u64) {
        let (w, b) = self.slot(i);
        if let Some(x) = self.bits.get_mut(w) {
            *x |= b;
        }
    }

    fn clear(&mut self, i: u64) {
        let (w, b) = self.slot(i);
        if let Some(x) = self.bits.get_mut(w) {
            *x &= !b;
        }
    }

    /// `Err(Replay)` when `i` was already accepted or is too old.
    pub(crate) fn check(&self, i: u64) -> Result<(), Error> {
        if i > self.max {
            return Ok(());
        }
        if self.max - i >= self.size() {
            return Err(Error::Replay);
        }
        let (w, b) = self.slot(i);
        match self.bits.get(w) {
            Some(x) if x & b == 0 => Ok(()),
            _ => Err(Error::Replay),
        }
    }

    /// Records `i` as received (call only after [`check`](Self::check) and authentication).
    pub(crate) fn accept(&mut self, i: u64) {
        if i > self.max {
            let shift = i - self.max;
            if shift >= self.size() {
                self.bits.iter_mut().for_each(|x| *x = 0);
            } else {
                for j in self.max + 1..=i {
                    self.clear(j);
                }
            }
            self.max = i;
        }
        self.set(i);
    }
}

#[cfg(test)]
mod tests {
    use super::ReplayWindow;

    #[test]
    fn window() {
        let mut w = ReplayWindow::new(1, 100);
        assert!(w.check(100).is_err());
        assert!(w.check(101).is_ok());
        assert!(w.check(99).is_ok());
        w.accept(99);
        assert!(w.check(99).is_err());
        w.accept(150);
        assert!(w.check(100).is_err());
        assert!(w.check(98).is_ok()); // 150 - 98 < 64, never seen
        assert!(w.check(120).is_ok());
        assert!(w.check(87).is_ok());
        assert!(w.check(86).is_err());
        w.accept(1000);
        assert!(w.check(150).is_err());
        assert!(w.check(999).is_ok());
        assert_eq!(w.max(), 1000);
        let mut big = ReplayWindow::new(16, 5000);
        assert!(big.check(5000 - 1000).is_ok());
        big.accept(4000);
        assert!(big.check(4000).is_err());
    }
}
