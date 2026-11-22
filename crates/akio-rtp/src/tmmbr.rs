//! TMMBR / TMMBN handling for the media sender (RFC 5104 §3.5.4): the bounding set of the
//! requests of every receiver, the bitrate it allows, and the notification.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::rtcp::{Rtcp, TmmbItem};

/// Requests not refreshed for this long are dropped (libwebrtc: five regular RTCP
/// intervals of 5 s).
pub const TMMBR_TIMEOUT: Duration = Duration::from_secs(25);
/// Requesters tracked.
const MAX_REQUESTERS: usize = 64;

/// The bounding set of TMMBR tuples (RFC 5104 §3.5.4.2): the tuples whose limit line
/// `net bitrate = bitrate - 8 * overhead * packet rate` is the lowest for some
/// non-negative packet rate (before it reaches zero), ordered by increasing overhead.
/// Zero-bitrate tuples are ignored; among equal tuples the first wins.
#[must_use]
pub fn bounding_set(candidates: &[TmmbItem]) -> Vec<TmmbItem> {
    let mut c: Vec<TmmbItem> = candidates
        .iter()
        .copied()
        .filter(|t| t.bitrate > 0)
        .collect();
    if c.len() <= 1 {
        return c;
    }
    // By increasing overhead; for equal overheads only the lowest bitrate matters.
    c.sort_by_key(|t| (t.overhead, t.bitrate));
    c.dedup_by_key(|t| t.overhead);
    // The lowest bitrate bounds at packet rate 0 (ties: the steepest of them).
    let first = c
        .iter()
        .enumerate()
        .min_by_key(|(_, t)| (t.bitrate, std::cmp::Reverse(t.overhead)))
        .map_or(0, |(i, _)| i);
    let slope = |t: &TmmbItem| 8.0 * f64::from(t.overhead);
    // Where a tuple's net bitrate reaches zero.
    let zero = |t: &TmmbItem| {
        if t.overhead == 0 {
            f64::INFINITY
        } else {
            t.bitrate as f64 / slope(t)
        }
    };
    // (tuple, packet rate from which it is the lowest).
    let mut hull: Vec<(TmmbItem, f64)> = vec![(c[first], 0.0)];
    // Flatter tuples than the first are above it everywhere at rates >= 0.
    for &t in &c[first + 1..] {
        while let Some(&(top, from)) = hull.last() {
            // Crossing point of `t` (steeper) with `top`.
            let x = (t.bitrate as f64 - top.bitrate as f64) / (slope(&t) - slope(&top));
            if x <= from && hull.len() > 1 {
                hull.pop();
                continue;
            }
            if x > from && x < zero(&top) {
                hull.push((t, x));
            }
            break;
        }
    }
    hull.into_iter().map(|(t, _)| t).collect()
}

/// The net media bitrate the bounding set `set` allows at `packet_rate` packets per second
/// (the minimum over its lines, at least 0), or `None` for an empty set.
#[must_use]
pub fn bounded_bitrate(set: &[TmmbItem], packet_rate: f64) -> Option<u64> {
    set.iter()
        .map(|t| {
            let v = t.bitrate as f64 - 8.0 * f64::from(t.overhead) * packet_rate.max(0.0);
            v.max(0.0) as u64
        })
        .min()
}

/// The media sender's TMMBR state: the latest request of each receiver (for this sender's
/// media SSRC), their bounding set, and the TMMBN announcing it.
#[derive(Debug)]
pub struct TmmbrHandler {
    media_ssrc: u32,
    requests: BTreeMap<u32, (TmmbItem, Instant)>,
}

impl TmmbrHandler {
    /// A handler for requests about `media_ssrc`.
    #[must_use]
    pub fn new(media_ssrc: u32) -> TmmbrHandler {
        TmmbrHandler {
            media_ssrc,
            requests: BTreeMap::new(),
        }
    }

    /// Takes the entries of a TMMBR from `sender_ssrc` that concern this media SSRC (a
    /// request of 0 bits/s withdraws the sender's request). Returns whether the bounding
    /// set changed, in which case a TMMBN should be sent.
    pub fn on_tmmbr(&mut self, now: Instant, sender_ssrc: u32, entries: &[TmmbItem]) -> bool {
        let before = self.bounding_set(now);
        for e in entries.iter().filter(|e| e.ssrc == self.media_ssrc) {
            if e.bitrate == 0 {
                self.requests.remove(&sender_ssrc);
                continue;
            }
            let owned = TmmbItem {
                ssrc: sender_ssrc,
                ..*e
            };
            self.requests.insert(sender_ssrc, (owned, now));
        }
        while self.requests.len() > MAX_REQUESTERS {
            if let Some((&old, _)) = self.requests.iter().min_by_key(|(_, (_, at))| *at) {
                self.requests.remove(&old);
            }
        }
        self.bounding_set(now) != before
    }

    /// The current bounding set, owners in `ssrc` (requests older than [`TMMBR_TIMEOUT`]
    /// expire).
    pub fn bounding_set(&mut self, now: Instant) -> Vec<TmmbItem> {
        self.requests
            .retain(|_, (_, at)| now.saturating_duration_since(*at) <= TMMBR_TIMEOUT);
        let reqs: Vec<TmmbItem> = self.requests.values().map(|(t, _)| *t).collect();
        bounding_set(&reqs)
    }

    /// The bitrate the requests allow at `packet_rate` packets per second, or `None`
    /// without requests.
    pub fn max_bitrate(&mut self, now: Instant, packet_rate: f64) -> Option<u64> {
        bounded_bitrate(&self.bounding_set(now), packet_rate)
    }

    /// The TMMBN announcing the current bounding set.
    pub fn tmmbn(&mut self, now: Instant) -> Rtcp {
        Rtcp::Tmmbn {
            sender_ssrc: self.media_ssrc,
            entries: self.bounding_set(now),
        }
    }
}
