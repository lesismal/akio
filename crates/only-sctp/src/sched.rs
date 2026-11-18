//! Stream schedulers (RFC 8260 §3): which stream's queued message the next DATA / I-DATA
//! chunk comes from. The sender keeps one queue per stream; the scheduler keeps the streams
//! with queued data in a ring, with their priority and virtual time, and picks one per chunk
//! without looking anything up. Without I-DATA a message, once started, is finished before any
//! other is picked (its fragments need consecutive TSNs), so the unit of scheduling is the
//! message; with I-DATA it is the chunk.

use std::collections::VecDeque;
use std::hash::{BuildHasherDefault, Hasher};

use crate::Scheduler;

/// A stream's scheduling state while it has nothing queued.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SchedState {
    /// RFC 8832 priority: higher is served first (priority scheduler) and gets a larger share
    /// (weighted fair queueing).
    pub(crate) priority: u16,
    /// Weighted fair queueing: virtual time at which the stream's last chunk finished.
    vfinish: u64,
}

impl Default for SchedState {
    fn default() -> SchedState {
        SchedState {
            priority: DEFAULT_PRIORITY,
            vfinish: 0,
        }
    }
}

/// RFC 8832 "normal" priority (WebRTC's `low`, the default of data channels).
pub(crate) const DEFAULT_PRIORITY: u16 = 256;

/// Virtual time units per byte at weight 1.
const SCALE: u64 = 1 << 16;

#[derive(Clone, Copy, Debug)]
struct Active {
    stream: u16,
    priority: u16,
    vfinish: u64,
}

#[derive(Debug)]
pub(crate) struct Sched {
    kind: Scheduler,
    /// Streams with queued messages, in round-robin order.
    ring: VecDeque<Active>,
    /// First come, first served: (stream, message id) in the order queued. Entries of
    /// messages already sent or dropped are skipped when they reach the front.
    fcfs: VecDeque<(u16, u64)>,
    /// Weighted fair queueing: the virtual time (finish tag of the last chunk picked).
    vtime: u64,
    /// Round robin per packet: the front stream was served in the current packet.
    rrp_served: bool,
    /// Ring index of the last stream `select` returned.
    picked: usize,
}

impl Sched {
    pub(crate) fn new(kind: Scheduler) -> Sched {
        Sched {
            kind,
            ring: VecDeque::new(),
            fcfs: VecDeque::new(),
            vtime: 0,
            rrp_served: false,
            picked: 0,
        }
    }

    /// A message was queued on `stream`; `was_idle` when its queue was empty before.
    pub(crate) fn on_enqueue(&mut self, stream: u16, msg_id: u64, was_idle: bool, st: SchedState) {
        if self.kind == Scheduler::FirstComeFirstServed {
            self.fcfs.push_back((stream, msg_id));
        }
        if was_idle {
            // A stream that was idle does not bank credit (start-time fair queueing).
            self.ring.push_back(Active {
                stream,
                priority: st.priority,
                vfinish: st.vfinish.max(self.vtime),
            });
        }
    }

    fn position(&self, stream: u16) -> Option<usize> {
        if self
            .ring
            .get(self.picked)
            .is_some_and(|a| a.stream == stream)
        {
            return Some(self.picked);
        }
        self.ring.iter().position(|a| a.stream == stream)
    }

    /// `stream` has no queued message any more; returns its state to keep.
    pub(crate) fn remove(&mut self, stream: u16) -> Option<SchedState> {
        let i = self.position(stream)?;
        let a = self.ring.remove(i)?;
        if i == 0 {
            self.rrp_served = false;
        }
        Some(SchedState {
            priority: a.priority,
            vfinish: a.vfinish,
        })
    }

    /// The priority of `stream` changed.
    pub(crate) fn set_priority(&mut self, stream: u16, priority: u16) {
        if let Some(i) = self.position(stream) {
            self.ring[i].priority = priority;
        }
    }

    /// A new packet is being filled.
    pub(crate) fn new_packet(&mut self) {
        if std::mem::take(&mut self.rrp_served) {
            self.ring.rotate_left(1.min(self.ring.len()));
        }
    }

    /// The stream to serve next. `head` gives the id of a stream's first queued message
    /// (first come, first served only).
    pub(crate) fn select(&mut self, head: impl Fn(u16) -> Option<u64>) -> Option<u16> {
        let i = match self.kind {
            Scheduler::FirstComeFirstServed => {
                while let Some(&(s, id)) = self.fcfs.front() {
                    if head(s) == Some(id) {
                        return Some(s);
                    }
                    self.fcfs.pop_front();
                }
                return None;
            }
            _ if self.ring.len() <= 1 => 0,
            Scheduler::RoundRobin | Scheduler::RoundRobinPerPacket => 0,
            Scheduler::Priority => {
                let mut best = 0;
                for (i, a) in self.ring.iter().enumerate() {
                    if a.priority > self.ring[best].priority {
                        best = i;
                    }
                }
                best
            }
            Scheduler::FairCapacity | Scheduler::WeightedFairQueueing => {
                let mut best = 0;
                for (i, a) in self.ring.iter().enumerate() {
                    if a.vfinish < self.ring[best].vfinish {
                        best = i;
                    }
                }
                best
            }
        };
        let a = self.ring.get(i)?;
        self.picked = i;
        Some(a.stream)
    }

    /// `bytes` of `stream` went out. `unit_done`: a message ended, or a chunk was sent with
    /// I-DATA; `emptied`: the stream has nothing queued any more (its state is returned to
    /// keep).
    pub(crate) fn served(
        &mut self,
        stream: u16,
        bytes: usize,
        unit_done: bool,
        emptied: bool,
    ) -> Option<SchedState> {
        let i = self.position(stream)?;
        match self.kind {
            Scheduler::FairCapacity | Scheduler::WeightedFairQueueing => {
                let a = &mut self.ring[i];
                let weight = if self.kind == Scheduler::FairCapacity {
                    1
                } else {
                    u64::from(a.priority.max(1))
                };
                self.vtime = self.vtime.max(a.vfinish);
                let cost = (bytes.max(1) as u64).saturating_mul(SCALE) / weight;
                a.vfinish = a.vfinish.saturating_add(cost.max(1));
            }
            // Only a turn of the front stream counts (not a DATA message it locked onto).
            Scheduler::RoundRobinPerPacket => self.rrp_served |= i == 0,
            _ => {}
        }
        if emptied {
            return self.remove(stream);
        }
        if unit_done
            && matches!(self.kind, Scheduler::RoundRobin | Scheduler::Priority)
            && self.ring.len() > 1
        {
            if let Some(a) = self.ring.remove(i) {
                self.ring.push_back(a);
            }
        }
        None
    }
}

/// Hasher for the stream-id keyed tables (at most 65536 keys, so no flooding beyond that):
/// one multiply, high bits folded down.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct StreamHasher(u64);

impl Hasher for StreamHasher {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u16(u16::from(b));
        }
    }

    fn write_u16(&mut self, n: u16) {
        let h = (self.0 ^ u64::from(n)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        self.0 = h ^ (h >> 29);
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

pub(crate) type StreamMap<V> = std::collections::HashMap<u16, V, BuildHasherDefault<StreamHasher>>;
