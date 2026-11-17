//! Neighbour cache for ARP (RFC 826, IPv4) and Neighbor Discovery (RFC 4861, IPv6): resolved
//! entries with a reachability timeout, and pending entries holding the IP packets waiting for
//! the answer, so the first packet to a new neighbour (a TCP SYN, a UDP datagram) is sent as
//! soon as the reply arrives instead of being dropped. The same state machine serves both
//! families: a resolved entry past its reachable time is still used while a unicast probe
//! confirms it (ARP request / NDP neighbor solicitation, RFC 4861's STALE -> PROBE), and is
//! resolved from scratch when the probe goes unanswered.

use std::{
    collections::{HashMap, VecDeque},
    hash::Hash,
    net::{Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use super::{hash::KeyedHash, wire::Mac};

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
/// Bytes of IP packets queued for all unresolved neighbours together (an on-link scan cannot
/// make the pending queues grow past this).
pub(crate) const MAX_QUEUED_BYTES: usize = 4 << 20;

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

/// An address a neighbour can be learned for.
pub(crate) trait NeighborAddr: Copy + Eq + Hash + Ord + std::fmt::Debug {
    /// A unicast address of a host (not unspecified, broadcast or multicast).
    fn usable(&self) -> bool;
}

impl NeighborAddr for Ipv4Addr {
    fn usable(&self) -> bool {
        !(self.is_unspecified() || self.is_broadcast() || self.is_multicast())
    }
}

impl NeighborAddr for Ipv6Addr {
    fn usable(&self) -> bool {
        !(self.is_unspecified() || self.is_multicast())
    }
}

#[derive(Debug)]
pub(crate) struct NeighborCache<A> {
    entries: HashMap<A, Entry, KeyedHash>,
    /// Earliest retry among pending entries (None: no pending entry).
    next_retry: Option<Instant>,
    /// Bytes in all pending queues.
    queued: usize,
}

impl<A> Default for NeighborCache<A> {
    fn default() -> Self {
        NeighborCache {
            entries: HashMap::with_hasher(KeyedHash::random()),
            next_retry: None,
            queued: 0,
        }
    }
}

fn queue_bytes(e: &Entry) -> usize {
    match e {
        Entry::Pending { queue, .. } => queue.iter().map(Vec::len).sum(),
        Entry::Resolved { .. } => 0,
    }
}

/// The ARP cache.
pub(crate) type ArpCache = NeighborCache<Ipv4Addr>;
/// The NDP neighbor cache.
pub(crate) type NdpCache = NeighborCache<Ipv6Addr>;

impl<A: NeighborAddr> NeighborCache<A> {
    pub(crate) fn lookup(&mut self, ip: A, now: Instant) -> Lookup {
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

    fn start_pending(&mut self, ip: A, now: Instant) {
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
            if let Some(e) = victim.and_then(|ip| self.entries.remove(&ip)) {
                self.queued -= queue_bytes(&e);
            }
        }
    }

    /// Queues an IP packet for `ip` (which must be pending). Returns `false` if dropped.
    pub(crate) fn queue_packet(&mut self, ip: A, packet: Vec<u8>) -> bool {
        if self.queued + packet.len() > MAX_QUEUED_BYTES {
            return false;
        }
        match self.entries.get_mut(&ip) {
            Some(Entry::Pending { queue, .. }) if queue.len() < MAX_QUEUE => {
                self.queued += packet.len();
                queue.push_back(packet);
                true
            }
            _ => false,
        }
    }

    /// Records `ip` at `mac` (from an ARP packet or a neighbor solicitation / advertisement).
    /// `create`: add the entry if unknown (only for requests aimed at us and replies, RFC 826's
    /// merge rule otherwise). Returns the packets that were waiting for it.
    pub(crate) fn learn(
        &mut self,
        ip: A,
        mac: Mac,
        now: Instant,
        create: bool,
    ) -> Option<VecDeque<Vec<u8>>> {
        if !ip.usable() || mac == [0; 6] || mac[0] & 1 != 0 {
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
            Some(Entry::Pending { queue, .. }) if !queue.is_empty() => {
                self.queued -= queue.iter().map(Vec::len).sum::<usize>();
                Some(queue)
            }
            _ => None,
        }
    }

    /// Retries due requests. Returns the addresses to request again; drops entries that ran
    /// out of tries (their packets are lost: TCP retransmits, UDP is best effort), returning
    /// them in `failed`.
    pub(crate) fn poll(&mut self, now: Instant, retry: &mut Vec<A>, failed: &mut Vec<A>) {
        match self.next_retry {
            Some(t) if now >= t => {}
            _ => return,
        }
        let mut next: Option<Instant> = None;
        let mut freed = 0;
        self.entries.retain(|ip, e| {
            let Entry::Pending { last, tries, queue } = e else {
                return true;
            };
            if now >= *last + RETRY {
                if *tries >= MAX_TRIES {
                    freed += queue.iter().map(Vec::len).sum::<usize>();
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
        self.queued -= freed;
        self.next_retry = next;
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.next_retry
    }

    /// The MAC of a resolved entry.
    #[cfg(test)]
    pub(crate) fn resolved(&self, ip: A) -> Option<Mac> {
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
    fn queued_bytes_bounded() {
        let t = Instant::now();
        let mut c = ArpCache::default();
        let a = Ipv4Addr::new(10, 0, 0, 1);
        let b = Ipv4Addr::new(10, 0, 0, 2);
        c.lookup(a, t);
        c.lookup(b, t);
        let half = MAX_QUEUED_BYTES / 2;
        assert!(c.queue_packet(a, vec![0; half - 1])); // just under
        assert!(c.queue_packet(b, vec![0; half + 1])); // at the limit
        assert!(!c.queue_packet(b, vec![0; 1])); // over
        // Released bytes are available again.
        c.learn(a, MAC, t, true).unwrap();
        assert!(c.queue_packet(b, vec![0; half - 1]));
        // Failed resolutions give their bytes back too.
        let (mut r, mut f) = (Vec::new(), Vec::new());
        for i in 1..=u32::from(MAX_TRIES) {
            c.poll(t + RETRY * i, &mut r, &mut f);
        }
        assert_eq!(f, [b]);
        assert_eq!(c.queued, 0);
    }

    #[test]
    fn ndp_cache_same_machine() {
        let ip: Ipv6Addr = "fd00::9".parse().unwrap();
        let t = Instant::now();
        let mut c = NdpCache::default();
        assert_eq!(c.lookup(ip, t), Lookup::Pending { request: true });
        assert!(c.queue_packet(ip, vec![7]));
        assert_eq!(c.learn(ip, MAC, t, true).unwrap(), [vec![7]]);
        assert_eq!(c.resolved(ip), Some(MAC));
        // Multicast addresses and multicast MACs are never learned.
        assert!(c.learn("ff02::1".parse().unwrap(), MAC, t, true).is_none());
        assert!(c.learn(ip, [0x33, 0x33, 0, 0, 0, 1], t, false).is_none());
        assert_eq!(c.resolved(ip), Some(MAC));
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
