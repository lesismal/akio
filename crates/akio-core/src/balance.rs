//! Accept-time balancing of a listener's connections over its I/O threads (ADR-100).
//!
//! `SO_REUSEPORT` hashes new connections over a listener's sockets (one per I/O thread). The
//! hash is uniform only on average: 1024 connections over 8 threads land 119..141 per thread
//! (measured), and when every connection carries the same load the busiest thread saturates
//! while the others idle, so its queue (and the tail latency of its connections) grows without
//! bound at a fixed offered rate well below the group's capacity. A thread that accepts a
//! connection while it holds more than its share hands it, before reading a byte, to the
//! thread with the fewest connections; the connection then lives there for good (ADR-001: no
//! connection ever moves once it is open).
//!
//! Backend-facing: the backends call [`pick`] on every accept of a balanced listener.

use crate::LoopStats;

/// How many more connections than the least loaded thread a thread keeps before it hands new
/// ones on: `2 + min / 32`. It bounds the spread to about 3% of the share once threads hold
/// dozens of connections, while short-lived connections (a few open per thread) are kept where
/// they are accepted unless the difference is real, so a hand-off (one cross-thread wake-up)
/// is not paid on every accept.
#[inline]
pub fn slack(min: u64) -> u64 {
    2 + min / 32
}

/// The index in `loads` of the thread to hand a connection accepted by thread `me` to, or
/// `None` to keep it: the least loaded thread, when `me` holds more than [`slack`] connections
/// above it. Ties go to the lowest index.
pub fn pick_index(me: usize, loads: &[u64]) -> Option<usize> {
    let mine = *loads.get(me)?;
    let (best, &min) = loads.iter().enumerate().min_by_key(|&(i, &l)| (l, i))?;
    (best != me && mine > min.saturating_add(slack(min))).then_some(best)
}

/// [`pick_index`] over the threads `loops` (in any order), with `me` the accepting thread's
/// stats and `stats` mapping a thread to its stats: the thread to hand the new connection to.
/// The caller announces the hand-off with [`LoopStats::handoff_begin`] on the target so that
/// threads accepting at the same moment see it.
pub fn pick<'a, T>(
    me: &LoopStats,
    loops: &'a [T],
    stats: impl Fn(&T) -> &LoopStats,
) -> Option<&'a T> {
    if loops.len() < 2 {
        return None;
    }
    let mine = me.load();
    let mut best: Option<(&T, u64)> = None;
    for l in loops {
        let s = stats(l);
        if std::ptr::eq(s, me) {
            continue;
        }
        let load = s.load();
        if best.is_none_or(|(_, b)| load < b) {
            best = Some((l, load));
        }
    }
    let (target, min) = best?;
    (mine > min.saturating_add(slack(min))).then_some(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LoopMeta;

    #[test]
    fn keeps_within_slack() {
        assert_eq!(pick_index(0, &[0, 0, 0]), None);
        assert_eq!(pick_index(0, &[2, 0, 0]), None); // 2 <= 0 + 2
        assert_eq!(pick_index(0, &[3, 0, 1]), Some(1)); // 3 > 0 + 2
        assert_eq!(pick_index(1, &[3, 0, 1]), None); // the least loaded keeps its own
        assert_eq!(pick_index(2, &[5, 9, 1]), None);
        // At 128 per thread the slack is 6.
        assert_eq!(pick_index(0, &[134, 128, 130]), None);
        assert_eq!(pick_index(0, &[135, 128, 130]), Some(1));
        assert_eq!(pick_index(3, &[1]), None);
    }

    #[test]
    fn ties_go_to_the_lowest_index() {
        assert_eq!(pick_index(3, &[4, 1, 1, 9]), Some(1));
    }

    /// Accepting 1024 connections whose first socket choice is as skewed as the kernel's hash
    /// was in the measurement (or worse) ends with every thread within the slack.
    #[test]
    fn spreads_a_skewed_arrival() {
        let loops: Vec<LoopStats> = (0..8)
            .map(|i| LoopStats::new(LoopMeta::new("test", None, i)))
            .collect();
        // A deterministic, strongly skewed arrival: thread 3 gets every other connection.
        let mut x = 7u64;
        for n in 0..1024u64 {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let first = if n % 2 == 0 {
                3
            } else {
                (x >> 33) as usize % 8
            };
            let me = &loops[first];
            match pick(me, &loops, |l| l) {
                Some(t) => {
                    t.handoff_begin();
                    t.handoff_done();
                    t.accepted.add_local(1);
                }
                None => me.accepted.add_local(1),
            }
        }
        let loads: Vec<u64> = loops.iter().map(LoopStats::load).collect();
        let (min, max) = (*loads.iter().min().unwrap(), *loads.iter().max().unwrap());
        assert_eq!(loads.iter().sum::<u64>(), 1024);
        assert!(max - min <= slack(min) + 1, "{loads:?}");
    }

    #[test]
    fn pending_handoffs_count_as_load() {
        let loops: Vec<LoopStats> = (0..2)
            .map(|i| LoopStats::new(LoopMeta::new("test", None, i)))
            .collect();
        loops[0].accepted.add_local(10);
        loops[1].accepted.add_local(4);
        assert!(pick(&loops[0], &loops, |l| l).is_some());
        for _ in 0..4 {
            loops[1].handoff_begin();
        }
        assert_eq!(loops[1].load(), 8);
        assert!(pick(&loops[0], &loops, |l| l).is_none());
        loops[1].handoff_done();
        loops[1].handoff_done();
        assert_eq!(loops[1].load(), 6);
        // Closed connections leave the count.
        loops[0].closed.add_local(5);
        assert_eq!(loops[0].load(), 5);
        // Never below zero.
        for _ in 0..10 {
            loops[1].handoff_done();
        }
        assert_eq!(loops[1].load(), 4);
    }
}
