#![forbid(unsafe_code)]
//! Hierarchical timer wheel: 4 levels of 64 slots (64⁴ ticks) plus an overflow list.
//!
//! The wheel is single-threaded and clock-agnostic: the owner maps wall time to integer ticks
//! (`akio` uses milliseconds), calls [`Wheel::advance`], and sleeps until [`Wheel::next_deadline`].
//! Scheduling and cancelling are O(1); advancing is amortised O(1) per tick plus O(fired).
//!
//! Guide: [Architecture](https://lesismal.github.io/akio/en/architecture.html)
//! (中文: [架构](https://lesismal.github.io/akio/zh-CN/architecture.html)).
#![warn(clippy::unwrap_used)]

const LEVELS: usize = 4;
const SLOTS: usize = 64;
const SPAN: u64 = (SLOTS as u64).pow(LEVELS as u32);

/// Identifies a scheduled timer; stale ids (already fired or cancelled) are harmless.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerId {
    idx: u32,
    gen_: u32,
}

struct Entry<T> {
    deadline: u64,
    gen_: u32,
    val: Option<T>,
}

/// A hierarchical timer wheel holding values of type `T`.
pub struct Wheel<T> {
    now: u64,
    levels: [[Vec<u32>; SLOTS]; LEVELS],
    overflow: Vec<u32>,
    entries: Vec<Entry<T>>,
    free: Vec<u32>,
    len: usize,
}

impl<T> std::fmt::Debug for Wheel<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wheel").finish_non_exhaustive()
    }
}

impl<T> Wheel<T> {
    /// A wheel whose clock starts at tick `now`.
    pub fn new(now: u64) -> Self {
        Wheel {
            now,
            levels: std::array::from_fn(|_| std::array::from_fn(|_| Vec::new())),
            overflow: Vec::new(),
            entries: Vec::new(),
            free: Vec::new(),
            len: 0,
        }
    }

    /// The wheel's current tick.
    pub fn now(&self) -> u64 {
        self.now
    }

    /// Number of pending timers.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no timer is pending.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Schedules `val` for tick `deadline`. A deadline not after `now` fires on the next tick.
    pub fn schedule(&mut self, deadline: u64, val: T) -> TimerId {
        let deadline = deadline.max(self.now + 1);
        let idx = match self.free.pop() {
            Some(i) => {
                let e = &mut self.entries[i as usize];
                e.deadline = deadline;
                e.val = Some(val);
                i
            }
            None => {
                self.entries.push(Entry {
                    deadline,
                    gen_: 0,
                    val: Some(val),
                });
                (self.entries.len() - 1) as u32
            }
        };
        self.len += 1;
        self.place(idx);
        TimerId {
            idx,
            gen_: self.entries[idx as usize].gen_,
        }
    }

    /// Cancels a timer, returning its value if it was still pending.
    pub fn cancel(&mut self, id: TimerId) -> Option<T> {
        let e = self.entries.get_mut(id.idx as usize)?;
        if e.gen_ != id.gen_ || e.val.is_none() {
            return None;
        }
        // The slot list still references `idx`; it is skipped lazily (see `fire`/`cascade`).
        let v = e.val.take();
        e.gen_ = e.gen_.wrapping_add(1);
        self.len -= 1;
        // The index is recycled only when its stale slot reference is consumed.
        v
    }

    /// The earliest tick at which something may fire (a lower bound), or `None` when empty.
    pub fn next_deadline(&self) -> Option<u64> {
        if self.len == 0 {
            return None;
        }
        // Scan level 0 for the next occupied slot; anything further is bounded by the next
        // cascade boundary. Cheap enough: at most 64 + 3 checks.
        for d in 1..=SLOTS as u64 {
            let t = self.now + d;
            if self.levels[0][(t % SLOTS as u64) as usize]
                .iter()
                .any(|&i| self.live(i))
            {
                return Some(t);
            }
        }
        // Not within this level-0 revolution: wake at the next cascade boundary.
        Some((self.now / SLOTS as u64 + 1) * SLOTS as u64)
    }

    /// Advances the clock to `to`, calling `fire` for every timer due on the way, in deadline
    /// order (ties in arbitrary order).
    pub fn advance(&mut self, to: u64, mut fire: impl FnMut(T)) {
        while self.now < to {
            if self.len == 0 {
                self.now = to; // nothing pending: skip ahead
                return;
            }
            self.now += 1;
            let now = self.now;
            // Cascade higher levels first: entries whose deadline == now land in level 0 below.
            if now % SPAN == 0 {
                for i in std::mem::take(&mut self.overflow) {
                    self.place_if_live(i);
                }
            }
            for lvl in (1..LEVELS).rev() {
                if now % (SLOTS as u64).pow(lvl as u32) == 0 {
                    let slot = ((now >> (6 * lvl)) % SLOTS as u64) as usize;
                    for i in std::mem::take(&mut self.levels[lvl][slot]) {
                        self.place_if_live(i);
                    }
                }
            }
            let slot = (now % SLOTS as u64) as usize;
            for i in std::mem::take(&mut self.levels[0][slot]) {
                let e = &mut self.entries[i as usize];
                if let Some(v) = e.val.take() {
                    debug_assert_eq!(e.deadline, now);
                    e.gen_ = e.gen_.wrapping_add(1);
                    self.len -= 1;
                    self.free.push(i);
                    fire(v);
                } else {
                    self.free.push(i); // cancelled earlier; recycle now
                }
            }
        }
    }

    fn live(&self, i: u32) -> bool {
        self.entries[i as usize].val.is_some()
    }

    fn place_if_live(&mut self, i: u32) {
        if self.live(i) {
            self.place(i);
        } else {
            self.free.push(i); // cancelled; its only slot reference is gone
        }
    }

    fn place(&mut self, i: u32) {
        let deadline = self.entries[i as usize].deadline;
        let d = deadline.saturating_sub(self.now);
        let lvl = (0..LEVELS).find(|&l| d < (SLOTS as u64).pow(l as u32 + 1));
        match lvl {
            Some(l) => {
                let slot = ((deadline >> (6 * l)) % SLOTS as u64) as usize;
                self.levels[l][slot].push(i);
            }
            None => self.overflow.push(i),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(w: &mut Wheel<u64>, to: u64) -> Vec<(u64, u64)> {
        let mut out = vec![];
        for t in w.now() + 1..=to {
            w.advance(t, |v| out.push((t, v)));
        }
        out
    }

    #[test]
    fn fires_at_deadline_across_levels() {
        let mut w = Wheel::new(0);
        // Miri is ~1000x slower: keep the far deadlines for native runs only.
        let ds: &[u64] = if cfg!(miri) {
            &[1, 5, 63, 64, 65, 130]
        } else {
            &[1, 5, 63, 64, 65, 200, 4095, 4096, 5000, 300_000, 20_000_000]
        };
        for &d in ds {
            w.schedule(d, d);
        }
        let got = run(&mut w, ds[ds.len() - 1] + 1);
        assert_eq!(got.len(), ds.len());
        for (t, v) in got {
            assert_eq!(t, v, "timer {v} fired at {t}");
        }
        assert!(w.is_empty());
    }

    #[test]
    fn past_deadline_fires_next_tick() {
        let mut w = Wheel::new(100);
        w.schedule(10, 7);
        assert_eq!(run(&mut w, 101), vec![(101, 7)]);
    }

    #[test]
    fn cancel_prevents_fire_and_stale_id_is_harmless() {
        let mut w = Wheel::new(0);
        let a = w.schedule(10, 1);
        let _b = w.schedule(10, 2);
        assert_eq!(w.cancel(a), Some(1));
        assert_eq!(w.cancel(a), None);
        assert_eq!(run(&mut w, 20), vec![(10, 2)]);
        assert_eq!(w.len(), 0);
        // slot reuse must not resurrect the stale id
        let c = w.schedule(30, 3);
        assert_eq!(w.cancel(a), None);
        assert_eq!(w.cancel(c), Some(3));
    }

    #[test]
    fn next_deadline_is_a_lower_bound() {
        let mut w = Wheel::new(0);
        assert_eq!(w.next_deadline(), None);
        w.schedule(10, 1);
        assert_eq!(w.next_deadline(), Some(10));
        w.schedule(100_000, 2);
        let mut w2 = Wheel::new(0);
        w2.schedule(100_000, 2);
        assert!(w2.next_deadline().unwrap() <= 100_000);
    }

    #[test]
    fn matches_naive_model_on_random_workload() {
        // xorshift: deterministic, no dependency
        let mut s = 0x9E3779B97F4A7C15u64;
        let mut rnd = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let mut w = Wheel::new(0);
        let mut model: Vec<(u64, u64, Option<TimerId>)> = vec![];
        let mut id = 0;
        let mut fired = vec![];
        let ticks: u64 = if cfg!(miri) { 150 } else { 20_000 };
        for t in 1..=ticks {
            for _ in 0..(rnd() % 3) {
                let dl = t + rnd() % if cfg!(miri) { 300 } else { 70_000 };
                id += 1;
                model.push((dl, id, Some(w.schedule(dl, id))));
            }
            if rnd() % 5 == 0 && !model.is_empty() {
                let k = (rnd() as usize) % model.len();
                if let Some(tid) = model[k].2.take() {
                    if w.cancel(tid).is_some() {
                        model[k].0 = u64::MAX; // cancelled
                    }
                }
            }
            w.advance(t, |v| fired.push((t, v)));
        }
        for (t, v) in &fired {
            let m = model.iter().find(|m| m.1 == *v).unwrap();
            assert_eq!(m.0, *t, "timer {v} fired at wrong tick");
        }
        let due = model.iter().filter(|m| m.0 <= ticks).count();
        assert_eq!(fired.len(), due);
    }
}
