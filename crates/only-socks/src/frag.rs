//! SOCKS5 UDP fragment reassembly (RFC 1928 section 7), used by the server's relay for the
//! client's datagrams and by the client's association for the relay's.
//!
//! `FRAG` is 0 for a whole datagram, else the fragment's position 1..=127, with the high bit
//! set on the last one. RFC 1928 keeps one reassembly queue and timer per association, reset
//! when the timer expires or a fragment arrives with a position lower than the highest one
//! seen. Fragments carry no sequence number, so a lost one cannot be told apart from a
//! reordered one; this implementation therefore takes a sequence only in order (1, 2, 3, ...)
//! and drops it on any gap, repeat or change of destination, or when a datagram with `FRAG` 0
//! arrives in the middle (that one passes through). Bounded: one sequence per association, at
//! most [`MAX_DATAGRAM`] bytes, dropped once [`TIMEOUT`] has passed since its first fragment
//! (checked when the next one arrives; the memory goes with the association).

use std::time::{Duration, Instant};

use crate::Dest;

/// The reassembly timer: RFC 1928 asks for at least 5 seconds.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(5);

/// Largest reassembled payload: the most one UDP datagram can carry.
pub(crate) const MAX_DATAGRAM: usize = 65_507;

/// What a datagram's `FRAG` field made of it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Frag<'a> {
    /// A whole datagram (`FRAG` 0): relay `payload` as it is.
    Whole(&'a [u8]),
    /// The last fragment of a complete sequence: relay this payload to the sequence's
    /// destination.
    Complete(Dest, Vec<u8>),
    /// Kept (a fragment of a sequence in progress) or dropped: nothing to relay yet.
    Held,
}

/// One association's reassembly queue.
#[derive(Debug, Default)]
pub(crate) struct Reassembly {
    seq: Option<Seq>,
}

#[derive(Debug)]
struct Seq {
    dest: Dest,
    /// Position of the last fragment taken.
    last: u8,
    data: Vec<u8>,
    started: Instant,
}

impl Reassembly {
    /// Takes one datagram (its `FRAG` value, destination and payload) at `now`.
    pub(crate) fn push<'a>(
        &mut self,
        now: Instant,
        frag: u8,
        dest: &Dest,
        payload: &'a [u8],
    ) -> Frag<'a> {
        if self
            .seq
            .as_ref()
            .is_some_and(|s| now.saturating_duration_since(s.started) >= TIMEOUT)
        {
            self.seq = None;
        }
        if frag == 0 {
            self.seq = None;
            return Frag::Whole(payload);
        }
        let (pos, end) = (frag & 0x7f, frag & 0x80 != 0);
        if pos == 0 {
            self.seq = None; // 0x80: no such position
            return Frag::Held;
        }
        if pos == 1 {
            // A new sequence (one in progress is abandoned: its position went back).
            if payload.len() > MAX_DATAGRAM {
                self.seq = None;
                return Frag::Held;
            }
            if end {
                self.seq = None;
                return Frag::Complete(dest.clone(), payload.to_vec());
            }
            self.seq = Some(Seq {
                dest: dest.clone(),
                last: 1,
                data: payload.to_vec(),
                started: now,
            });
            return Frag::Held;
        }
        let Some(s) = self.seq.as_mut() else {
            return Frag::Held; // the start was lost (or timed out): drop the rest
        };
        if pos != s.last + 1 || s.dest != *dest || s.data.len() + payload.len() > MAX_DATAGRAM {
            self.seq = None;
            return Frag::Held;
        }
        s.data.extend_from_slice(payload);
        s.last = pos;
        if end {
            let s = self.seq.take().expect("checked above");
            return Frag::Complete(s.dest, s.data);
        }
        Frag::Held
    }

    /// Abandons the sequence in progress, if any (a whole datagram arrived).
    #[inline]
    pub(crate) fn reset(&mut self) {
        if self.seq.is_some() {
            self.seq = None;
        }
    }

    /// Bytes held.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.seq.as_ref().map_or(0, |s| s.data.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(p: u16) -> Dest {
        Dest::Addr(([10, 0, 0, 1], p).into())
    }

    #[test]
    fn in_order_sequences_reassemble() {
        let mut r = Reassembly::default();
        let t = Instant::now();
        assert_eq!(r.push(t, 0, &d(1), b"whole"), Frag::Whole(b"whole"));
        assert_eq!(r.push(t, 1, &d(1), b"ab"), Frag::Held);
        assert_eq!(r.push(t, 2, &d(1), b"cd"), Frag::Held);
        assert_eq!(
            r.push(t, 0x83, &d(1), b"e"),
            Frag::Complete(d(1), b"abcde".to_vec())
        );
        assert_eq!(r.held(), 0);
        // A single-fragment sequence.
        assert_eq!(
            r.push(t, 0x81, &d(2), b"x"),
            Frag::Complete(d(2), b"x".to_vec())
        );
        // All 127 positions.
        for i in 1..127u8 {
            assert_eq!(r.push(t, i, &d(3), &[i]), Frag::Held);
        }
        match r.push(t, 0xff, &d(3), &[127]) {
            Frag::Complete(_, v) => assert_eq!(v, (1..=127).collect::<Vec<u8>>()),
            f => panic!("{f:?}"),
        }
    }

    #[test]
    fn gaps_repeats_and_other_destinations_drop_the_sequence() {
        let mut r = Reassembly::default();
        let t = Instant::now();
        r.push(t, 1, &d(1), b"a");
        assert_eq!(r.push(t, 3, &d(1), b"c"), Frag::Held); // gap
        assert_eq!(r.held(), 0);
        assert_eq!(r.push(t, 0x84, &d(1), b"d"), Frag::Held);
        r.push(t, 1, &d(1), b"a");
        r.push(t, 2, &d(1), b"b");
        assert_eq!(r.push(t, 2, &d(1), b"b"), Frag::Held); // repeat: lower or equal
        assert_eq!(r.held(), 0);
        r.push(t, 1, &d(1), b"a");
        assert_eq!(r.push(t, 0x82, &d(2), b"b"), Frag::Held); // another destination
        assert_eq!(r.held(), 0);
        // A whole datagram in the middle passes and ends the sequence.
        r.push(t, 1, &d(1), b"a");
        assert_eq!(r.push(t, 0, &d(1), b"w"), Frag::Whole(b"w"));
        assert_eq!(r.push(t, 0x82, &d(1), b"b"), Frag::Held);
        // A restart at 1 replaces the sequence.
        r.push(t, 1, &d(1), b"old");
        r.push(t, 1, &d(1), b"new");
        assert_eq!(
            r.push(t, 0x82, &d(1), b"!"),
            Frag::Complete(d(1), b"new!".to_vec())
        );
        assert_eq!(r.push(t, 0x80, &d(1), b"?"), Frag::Held);
    }

    #[test]
    fn bounded_in_size_and_time() {
        let mut r = Reassembly::default();
        let t = Instant::now();
        let big = vec![0u8; 40_000];
        r.push(t, 1, &d(1), &big);
        assert_eq!(r.push(t, 2, &d(1), &big), Frag::Held); // over 65,507 bytes
        assert_eq!(r.held(), 0);
        assert_eq!(r.push(t, 1, &d(1), &vec![0; MAX_DATAGRAM + 1]), Frag::Held);
        assert_eq!(r.held(), 0);
        r.push(t, 1, &d(1), b"a");
        assert_eq!(r.push(t + TIMEOUT, 0x82, &d(1), b"b"), Frag::Held);
        assert_eq!(r.held(), 0);
        r.push(t, 1, &d(1), b"a");
        let almost = t + Duration::from_millis(4_999);
        assert_eq!(
            r.push(almost, 0x82, &d(1), b"b"),
            Frag::Complete(d(1), b"ab".to_vec())
        );
    }
}
