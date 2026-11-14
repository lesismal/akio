//! A set of disjoint half-open `u64` ranges: received packet numbers, acknowledged or lost
//! stream bytes.

use std::collections::BTreeMap;
use std::ops::Range;

/// Disjoint, non-adjacent ranges `start..end`, keyed by start.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RangeSet(BTreeMap<u64, u64>);

impl RangeSet {
    pub fn new() -> RangeSet {
        RangeSet(BTreeMap::new())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of ranges.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn contains(&self, v: u64) -> bool {
        self.0
            .range(..=v)
            .next_back()
            .is_some_and(|(_, &e)| v < e)
    }

    /// Adds `r`; returns whether anything new was added.
    pub fn insert(&mut self, r: Range<u64>) -> bool {
        if r.start >= r.end {
            return false;
        }
        let (mut start, mut end) = (r.start, r.end);
        // Merge with a range starting at or before `start` that reaches it.
        if let Some((&s, &e)) = self.0.range(..=start).next_back() {
            if e >= end {
                return false;
            }
            if e >= start {
                start = s;
                self.0.remove(&s);
            }
        }
        // Absorb ranges starting inside `start..=end`.
        loop {
            let next = self.0.range(start..=end).next().map(|(&s, &e)| (s, e));
            match next {
                Some((s, e)) => {
                    self.0.remove(&s);
                    end = end.max(e);
                }
                None => break,
            }
        }
        self.0.insert(start, end);
        true
    }

    pub fn insert_one(&mut self, v: u64) -> bool {
        self.insert(v..v + 1)
    }

    /// Removes `r` from the set.
    pub fn remove(&mut self, r: Range<u64>) {
        if r.start >= r.end {
            return;
        }
        if let Some((&s, &e)) = self.0.range(..r.start).next_back() {
            if e > r.start {
                self.0.insert(s, r.start);
                if e > r.end {
                    self.0.insert(r.end, e);
                    return;
                }
            }
        }
        loop {
            let next = self.0.range(r.start..r.end).next().map(|(&s, &e)| (s, e));
            match next {
                Some((s, e)) => {
                    self.0.remove(&s);
                    if e > r.end {
                        self.0.insert(r.end, e);
                        break;
                    }
                }
                None => break,
            }
        }
    }

    /// Drops everything below `v`.
    pub fn remove_below(&mut self, v: u64) {
        self.remove(0..v);
    }

    pub fn min(&self) -> Option<u64> {
        self.0.iter().next().map(|(&s, _)| s)
    }

    pub fn max(&self) -> Option<u64> {
        self.0.iter().next_back().map(|(_, &e)| e - 1)
    }

    /// The first range.
    pub fn first(&self) -> Option<Range<u64>> {
        self.0.iter().next().map(|(&s, &e)| s..e)
    }

    /// Removes and returns the first range, at most `max` long.
    pub fn pop_first(&mut self, max: u64) -> Option<Range<u64>> {
        let (s, e) = self.0.pop_first()?;
        if e - s > max {
            self.0.insert(s + max, e);
            return Some(s..s + max);
        }
        Some(s..e)
    }

    /// Ranges in ascending order.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = Range<u64>> + '_ {
        self.0.iter().map(|(&s, &e)| s..e)
    }

    /// Keeps only the `n` highest ranges.
    pub fn keep_highest(&mut self, n: usize) {
        while self.0.len() > n {
            self.0.pop_first();
        }
    }

    /// The ranges overlapping `r`, clipped to it.
    pub fn overlapping(&self, r: Range<u64>) -> Vec<Range<u64>> {
        let mut out = Vec::new();
        if let Some((_, &e)) = self.0.range(..r.start).next_back() {
            if e > r.start {
                out.push(r.start..e.min(r.end));
            }
        }
        for (&s, &e) in self.0.range(r.start..r.end) {
            out.push(s..e.min(r.end));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &RangeSet) -> Vec<Range<u64>> {
        s.iter().collect()
    }

    #[test]
    fn insert_merges() {
        let mut s = RangeSet::new();
        assert!(s.insert(5..10));
        assert!(!s.insert(6..8));
        assert!(s.insert(12..14));
        assert!(s.insert(10..12));
        assert_eq!(v(&s), vec![5..14]);
        assert!(s.insert(0..2));
        assert!(s.insert(1..6));
        assert_eq!(v(&s), vec![0..14]);
        assert!(s.insert(20..30));
        assert!(s.insert(16..18));
        assert!(s.insert(15..40));
        assert_eq!(v(&s), vec![0..14, 15..40]);
        assert!(!s.insert(3..3));
        assert!(s.contains(0) && s.contains(13) && !s.contains(14) && s.contains(39));
        assert_eq!((s.min(), s.max(), s.len()), (Some(0), Some(39), 2));
        assert!(s.insert_one(14));
        assert_eq!(v(&s), vec![0..40]);
    }

    #[test]
    fn remove_splits() {
        let mut s = RangeSet::new();
        s.insert(0..10);
        s.insert(20..30);
        s.remove(5..25);
        assert_eq!(v(&s), vec![0..5, 25..30]);
        s.remove(2..3);
        assert_eq!(v(&s), vec![0..2, 3..5, 25..30]);
        s.remove_below(4);
        assert_eq!(v(&s), vec![4..5, 25..30]);
        assert_eq!(s.overlapping(0..26), vec![4..5, 25..26]);
        assert_eq!(s.overlapping(26..100), vec![26..30]);
        assert_eq!(s.pop_first(10), Some(4..5));
        assert_eq!(s.pop_first(2), Some(25..27));
        assert_eq!(s.first(), Some(27..30));
        s.insert(40..41);
        s.keep_highest(1);
        assert_eq!(v(&s), vec![40..41]);
        s.remove(0..0);
        s.clear();
        assert!(s.is_empty() && s.max().is_none());
    }
}
