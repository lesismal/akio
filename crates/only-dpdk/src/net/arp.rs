//! ARP (RFC 826) neighbour cache: resolved entries with a reachability timeout, and pending
//! entries holding the IP packets waiting for the answer, so the first packet to a new
//! neighbour (a TCP SYN, a UDP datagram) is sent as soon as the reply arrives instead of being
//! dropped.

use std::{
    collections::{HashMap, VecDeque},
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use super::wire::Mac;

/// A resolved entry is trusted this long after it was learned or confirmed.
pub(crate) const REACHABLE: Duration = Duration::from_secs(60);
/// After `REACHABLE`, the entry is still used while a unicast refresh is in flight, this long.
const STALE_GRACE: Duration = Duration::from_secs(5);
/// Interval between requests for an unresolved address.
pub(crate) const RETRY: Duration = Duration::from_secs(1);
/// Requests sent before giving up on an address (its queued packets are dropped).
pub(crate) const MAX_TRIES: u8 = 3;
/// IP packets queued per unresolved neighbour.
pub(crate) const MAX_QUEUE: usize = 1024;
/// Neighbours kept; beyond it the entry expiring first is evicted.
const MAX_ENTRIES: usize = 4096;

#[derive(Debug)]
enum Entry {
    Resolved {
        mac: Mac,
        expires: Instant,
        refreshing: bool,
    },
    Pending {
        queue: VecDeque<Vec<u8>>,
        last: Instant,
        tries: u8,
    },
}

/// What a lookup tells the sender to do.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Lookup {
    /// Send to this MAC. `refresh`: also send a unicast request to confirm the entry.
    Mac { mac: Mac, refresh: bool },
    /// Unresolved: queue the packet (`queue_packet`) and, if `request`, broadcast a request.
    Pending { request: bool },
}

#[derive(Debug, Default)]
pub(crate) struct ArpCache {
    entries: HashMap<Ipv4Addr, Entry>,
    /// Earliest retry among pending entries (None: no pending entry).
    next_retry: Option<Instant>,
}

impl ArpCache {
    pub(crate) fn lookup(&mut self, ip: Ipv4Addr, now: Instant) -> Lookup {
        match self.entries.get_mut(&ip) {
            Some(Entry::Resolved {
                mac,
                expires,
                refreshing,
            }) => {
                if now < *expires {
                    return Lookup::Mac {
                        mac: *mac,
                        refresh: false,
                    };
                }
                if !*refreshing {
                    *refreshing = true;
                    *expires = now + STALE_GRACE;
                    return Lookup::Mac {
                        mac: *mac,
                        refresh: true,
                    };
                }
                // Refresh unanswered: resolve again from scratch.
                self.entries.remove(&ip);
                self.start_pending(ip, now);
                Lookup::Pending { request: true }
            }
            Some(Entry::Pending { .. }) => Lookup::Pending { request: false },
            None => {
                self.start_pending(ip, now);
                Lookup::Pending { request: true }
            }
        }
    }

    fn start_pending(&mut self, ip: Ipv4Addr, now: Instant) {
        self.make_room(now);
        self.entries.insert(
            ip,
            Entry::Pending {
                queue: VecDeque::new(),
                last: now,
                tries: 1,
            },
        );
        let at = now + RETRY;
        self.next_retry = Some(self.next_retry.map_or(at, |t| t.min(at)));
    }

    fn make_room(&mut self, now: Instant) {
        if self.entries.len() < MAX_ENTRIES {
            return;
        }
        self.entries.retain(|_, e| match e {
            Entry::Resolved { expires, .. } => *expires > now,
            Entry::Pending { .. } => true,
        });
        if self.entries.len() >= MAX_ENTRIES {
            let victim = self
                .entries
                .iter()
                .filter_map(|(ip, e)| match e {
                    Entry::Resolved { expires, .. } => Some((*expires, *ip)),
                    Entry::Pending { .. } => None,
                })
                .min()
                .map(|(_, ip)| ip)
                .or_else(|| self.entries.keys().next().copied());
            if let Some(ip) = victim {
                self.entries.remove(&ip);
            }
        }
    }

    /// Queues an IP packet for `ip` (which must be pending). Returns `false` if dropped.
    pub(crate) fn queue_packet(&mut self, ip: Ipv4Addr, packet: Vec<u8>) -> bool {
        match self.entries.get_mut(&ip) {
            Some(Entry::Pending { queue, .. }) if queue.len() < MAX_QUEUE => {
                queue.push_back(packet);
                true
            }
            _ => false,
        }
    }

    /// Records `ip` at `mac` (from an ARP packet). `create`: add the entry if unknown (only
    /// for requests aimed at us and replies, RFC 826's merge rule otherwise). Returns the
    /// packets that were waiting for it.
    pub(crate) fn learn(
        &mut self,
        ip: Ipv4Addr,
        mac: Mac,
        now: Instant,
        create: bool,
    ) -> Option<VecDeque<Vec<u8>>> {
        if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || mac == [0; 6] {
            return None;
        }
        let exists = self.entries.contains_key(&ip);
        if !exists && !create {
            return None;
        }
        if !exists {
            self.make_room(now);
        }
        let old = self.entries.insert(
            ip,
            Entry::Resolved {
                mac,
                expires: now + REACHABLE,
                refreshing: false,
            },
        );
        match old {
            Some(Entry::Pending { queue, .. }) if !queue.is_empty() => Some(queue),
            _ => None,
        }
    }

    /// Retries due requests. Returns the addresses to request again; drops entries that ran
    /// out of tries (their packets are lost: TCP retransmits, UDP is best effort), returning
    /// them in `failed`.
    pub(crate) fn poll(
        &mut self,
        now: Instant,
        retry: &mut Vec<Ipv4Addr>,
        failed: &mut Vec<Ipv4Addr>,
    ) {
        match self.next_retry {
            Some(t) if now >= t => {}
            _ => return,
        }
        let mut next: Option<Instant> = None;
        self.entries.retain(|ip, e| {
            let Entry::Pending { last, tries, .. } = e else {
                return true;
            };
            if now >= *last + RETRY {
                if *tries >= MAX_TRIES {
                    failed.push(*ip);
                    return false;
                }
                *tries += 1;
                *last = now;
                retry.push(*ip);
            }
            let at = *last + RETRY;
            next = Some(next.map_or(at, |t| t.min(at)));
            true
        });
        self.next_retry = next;
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.next_retry
    }

    #[cfg(test)]
    pub(crate) fn resolved(&self, ip: Ipv4Addr) -> Option<Mac> {
        match self.entries.get(&ip) {
            Some(Entry::Resolved { mac, .. }) => Some(*mac),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
    const MAC: Mac = [2, 0, 0, 0, 0, 9];

    #[test]
    fn pending_queue_released_on_reply() {
        let t = Instant::now();
        let mut c = ArpCache::default();
        assert_eq!(c.lookup(IP, t), Lookup::Pending { request: true });
        assert!(c.queue_packet(IP, vec![1]));
        assert_eq!(c.lookup(IP, t), Lookup::Pending { request: false });
        assert!(c.queue_packet(IP, vec![2]));
        let q = c.learn(IP, MAC, t, true).unwrap();
        assert_eq!(q, [vec![1], vec![2]]);
        assert_eq!(
            c.lookup(IP, t),
            Lookup::Mac {
                mac: MAC,
                refresh: false
            }
        );
    }

    #[test]
    fn retries_then_gives_up() {
        let t = Instant::now();
        let mut c = ArpCache::default();
        c.lookup(IP, t);
        let (mut r, mut f) = (Vec::new(), Vec::new());
        c.poll(t + Duration::from_millis(10), &mut r, &mut f);
        assert!(r.is_empty() && f.is_empty());
        c.poll(t + RETRY, &mut r, &mut f);
        assert_eq!(r, [IP]);
        c.poll(t + RETRY * 2, &mut r, &mut f);
        assert_eq!(r, [IP, IP]);
        c.poll(t + RETRY * 3, &mut r, &mut f);
        assert_eq!(f, [IP]);
        assert_eq!(c.next_deadline(), None);
    }

    #[test]
    fn stale_entry_refreshes() {
        let t = Instant::now();
        let mut c = ArpCache::default();
        c.learn(IP, MAC, t, true);
        let later = t + REACHABLE;
        assert_eq!(
            c.lookup(IP, later),
            Lookup::Mac {
                mac: MAC,
                refresh: true
            }
        );
        assert_eq!(
            c.lookup(IP, later),
            Lookup::Mac {
                mac: MAC,
                refresh: false
            }
        );
        // Confirmed by a reply.
        c.learn(IP, MAC, later, false);
        assert_eq!(
            c.lookup(IP, later + STALE_GRACE),
            Lookup::Mac {
                mac: MAC,
                refresh: false
            }
        );
        // Not confirmed: resolved again.
        let much_later = later + REACHABLE * 2;
        assert_eq!(
            c.lookup(IP, much_later),
            Lookup::Mac {
                mac: MAC,
                refresh: true
            }
        );
        assert_eq!(
            c.lookup(IP, much_later + STALE_GRACE),
            Lookup::Pending { request: true }
        );
    }

    #[test]
    fn merge_rule() {
        let t = Instant::now();
        let mut c = ArpCache::default();
        assert!(c.learn(IP, MAC, t, false).is_none());
        assert_eq!(c.resolved(IP), None);
        c.learn(IP, MAC, t, true);
        c.learn(IP, [2, 0, 0, 0, 0, 10], t, false);
        assert_eq!(c.resolved(IP), Some([2, 0, 0, 0, 0, 10]));
    }
}
