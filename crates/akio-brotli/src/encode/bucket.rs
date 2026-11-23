//! The greedy and lazy parse of levels 0..=6 over per-hash buckets, with the bucket size and
//! the hash length as constants.
//!
//! A searched position is hashed once: the search enters it into its bucket after looking at
//! the bucket, as Google's `H5` and `H54` do, instead of hashing it again when the next search
//! enters the positions before it. Positions whose hash could still change (a stream's last
//! bytes, which the next write extends) are entered later, as before. The tables, counters and
//! limits live in locals for the whole parse.

use super::{Command, Encoder, Found, LAZY_MARGIN, MIN_SCORE, load4, load8, log2_floor, match_len};

/// The tables and limits of one parse: `SIZE` positions per hash, five-byte hashes when `H5`.
struct Buckets<'t, const SIZE: usize, const H5: bool> {
    d: &'t [u8],
    num: &'t mut [u8],
    buckets: &'t mut [u32],
    /// `num.len() - 1`.
    mask: usize,
    /// 64 or 32 minus the hash bits.
    shift: u32,
    /// The next position to enter.
    ins: usize,
    max_dist: usize,
    nice: usize,
    zero: usize,
    fwd: usize,
    back: usize,
}

impl<const SIZE: usize, const H5: bool> Buckets<'_, SIZE, H5> {
    /// The hash of position `i`: of four bytes, or five (`H5`).
    #[inline(always)]
    fn key(&self, i: usize) -> usize {
        let h = if H5 {
            let v = load8(self.d, i) << 24;
            (v.wrapping_mul(0x1E35_A7BD_1E35_A7BD) >> self.shift) as usize
        } else {
            (load4(self.d, i).wrapping_mul(0x1E35_A7BD) >> self.shift) as usize
        };
        h & self.mask
    }

    /// Enters position `i` of hash `h`.
    #[inline(always)]
    fn store(&mut self, i: usize, h: usize) {
        let slot = if SIZE == 1 {
            0
        } else {
            let k = self.num[h];
            self.num[h] = k.wrapping_add(1);
            usize::from(k) & (SIZE - 1)
        };
        if let Some(b) = self.buckets.get_mut(h * SIZE + slot) {
            *b = i as u32;
        }
    }

    /// [`Encoder::insert_until`].
    #[inline(always)]
    fn insert_until(&mut self, upto: usize) {
        if self.ins >= upto {
            return;
        }
        self.insert_range(upto);
    }

    #[inline(never)]
    fn insert_range(&mut self, upto: usize) {
        let lim = upto.min(self.d.len().saturating_sub(3));
        while self.ins < lim {
            let i = self.ins;
            let key = self.key(i);
            self.store(i, key);
            self.ins += 1;
        }
        self.ins = self.ins.max(upto);
    }

    /// [`Encoder::reach`].
    #[inline(always)]
    fn reach(&self, i: usize) -> usize {
        (i + self.fwd - self.back).min(self.max_dist)
    }

    /// [`Encoder::dict_room`].
    #[inline(always)]
    fn dict_room(&self, i: usize, c: usize) -> usize {
        if c < self.zero && i + self.fwd - self.back <= self.max_dist {
            self.zero - c
        } else {
            0
        }
    }

    /// [`Encoder::find`] at `i` (all positions before it entered), then enters `i` when its
    /// hash is final (its bytes are all in the data).
    #[inline(always)]
    fn find(&mut self, i: usize, end: usize, ring: &[u32; 4]) -> Option<Found> {
        let hlen = if H5 { 5 } else { 4 };
        // (Searched when four bytes are left before `end`, at most the data's end.)
        let key = if i + 4 <= self.d.len() {
            self.key(i)
        } else {
            0
        };
        let best = self.search(i, end, ring, key);
        if self.ins == i && i + hlen <= self.d.len() {
            self.store(i, key);
            self.ins = i + 1;
        }
        best
    }

    #[inline(always)]
    fn search(&self, i: usize, end: usize, ring: &[u32; 4], h: usize) -> Option<Found> {
        let d = self.d;
        let max_len = end - i;
        if max_len < 2 {
            return None;
        }
        let max_dist = self.reach(i);
        let mut best: Option<Found> = None;
        let mut best_score = MIN_SCORE;
        let mut best_len = 0;
        for (k, &rd) in ring.iter().enumerate() {
            let dist = rd as usize;
            if dist == 0 || dist > max_dist {
                continue;
            }
            if d.get(i) != d.get(i - dist)
                || d.get(i + 1) != d.get(i + 1 - dist)
                || (best_len > 0
                    && (best_len >= max_len || d.get(i + best_len) != d.get(i + best_len - dist)))
            {
                continue;
            }
            let len = match_len(d, i - dist, i, max_len);
            if len < if k < 2 { 2 } else { 3 } {
                continue;
            }
            let score = 135 * len as i64 + 1920 + if k == 0 { 15 } else { -60 };
            if score > best_score {
                best_score = score;
                best_len = len;
                best = Some(Found { len, dist, score });
            }
        }
        if max_len < 4 {
            return best;
        }
        let k = if SIZE == 1 {
            0
        } else {
            usize::from(self.num[h])
        };
        let Some(bucket) = self.buckets.get(h * SIZE..h * SIZE + SIZE) else {
            return best;
        };
        // Newest first; a slot never filled holds `EMPTY`, past `i`, which ends the search
        // below (the slots before it in this order are the only ones filled).
        for j in 1..=SIZE {
            let c = bucket[k.wrapping_sub(j) & (SIZE - 1)] as usize;
            let mut max_len = max_len;
            if i.wrapping_sub(c).wrapping_sub(1) >= max_dist {
                let room = if c < i { self.dict_room(i, c) } else { 0 };
                if room < 4 {
                    if room == 0 {
                        break;
                    }
                    continue;
                }
                max_len = max_len.min(room);
            }
            if best_len >= max_len {
                if max_len < end - i {
                    continue;
                }
                break;
            }
            if d.get(c + best_len) != d.get(i + best_len) {
                continue;
            }
            let len = match_len(d, c, i, max_len);
            if len >= 4 {
                let dist = i - c;
                let score = 135 * len as i64 + 1920 - 30 * log2_floor(dist);
                if score > best_score {
                    best_score = score;
                    best_len = len;
                    best = Some(Found { len, dist, score });
                    if len >= self.nice {
                        break;
                    }
                }
            }
        }
        best
    }
}

impl Encoder<'_> {
    /// [`Encoder::parse_lazy`] at a level with buckets.
    pub(super) fn parse_buckets(&mut self, start: usize, end: usize, cmds: &mut Vec<Command>) {
        // (Five-byte hashes from 16 entries per bucket, `Encoder::new`.)
        match self.block_bits {
            0 => self.parse_with::<1, false>(start, end, cmds),
            1 => self.parse_with::<2, false>(start, end, cmds),
            2 => self.parse_with::<4, false>(start, end, cmds),
            3 => self.parse_with::<8, false>(start, end, cmds),
            4 => self.parse_with::<16, true>(start, end, cmds),
            _ => self.parse_with::<32, true>(start, end, cmds),
        }
    }

    /// [`Encoder::insert_until`] at a level with buckets.
    pub(super) fn insert_buckets(&mut self, upto: usize) {
        match self.block_bits {
            0 => self.buckets::<1, false>().t.insert_until(upto),
            1 => self.buckets::<2, false>().t.insert_until(upto),
            2 => self.buckets::<4, false>().t.insert_until(upto),
            3 => self.buckets::<8, false>().t.insert_until(upto),
            4 => self.buckets::<16, true>().t.insert_until(upto),
            _ => self.buckets::<32, true>().t.insert_until(upto),
        }
    }

    /// The tables as [`Buckets`], in a guard that writes their `ins` back.
    fn buckets<const SIZE: usize, const H5: bool>(&mut self) -> Guard<'_, SIZE, H5> {
        debug_assert_eq!(SIZE, 1 << self.block_bits);
        debug_assert_eq!(H5, self.hash5);
        let ins = self.ins;
        let t = Buckets::<SIZE, H5> {
            d: self.data,
            mask: self.num.len().wrapping_sub(1),
            num: &mut self.num,
            buckets: &mut self.buckets,
            shift: if H5 { 64 } else { 32 } - self.p.hash_bits,
            ins,
            max_dist: self.max_dist,
            nice: self.p.nice,
            zero: self.zero,
            fwd: self.fwd,
            back: self.back,
        };
        Guard {
            t,
            ins: &mut self.ins,
        }
    }

    fn parse_with<const SIZE: usize, const H5: bool>(
        &mut self,
        start: usize,
        end: usize,
        cmds: &mut Vec<Command>,
    ) {
        let lazy = self.p.lazy;
        let insert_all = self.p.insert_all;
        let mut ring = self.last;
        let mut g = self.buckets::<SIZE, H5>();
        let t = &mut g.t;
        let mut i = start;
        let mut lit_start = start;
        const RANDOM_WINDOW: usize = 64;
        while i < end {
            t.insert_until(i);
            let Some(mut cur) = t.find(i, end, &ring) else {
                let gap = i - lit_start;
                if gap > RANDOM_WINDOW && i + 20 < end {
                    let (span, step) = if gap > 5 * RANDOM_WINDOW {
                        (16, 4)
                    } else {
                        (8, 2)
                    };
                    let stop = i + span;
                    while i < stop {
                        t.insert_until(i + 1);
                        i += step;
                        t.ins = i;
                    }
                } else {
                    i += 1;
                }
                continue;
            };
            if lazy {
                let mut steps = 0;
                while steps < 4 && i + 1 < end {
                    t.insert_until(i + 1);
                    match t.find(i + 1, end, &ring) {
                        Some(nx) if nx.len >= 4 && nx.score > cur.score + LAZY_MARGIN => {
                            cur = nx;
                            i += 1;
                            steps += 1;
                        }
                        _ => break,
                    }
                }
            }
            cmds.push(Command {
                insert: (i - lit_start) as u32,
                copy: cur.len as u32,
                dist: cur.dist as u32,
                out: 0,
            });
            if cur.dist as u32 != ring[0] {
                ring = [cur.dist as u32, ring[0], ring[1], ring[2]];
            }
            let next = i + cur.len;
            if !insert_all && cur.len > 16 {
                t.insert_until(i + 8);
                t.ins = t.ins.max(next);
            }
            i = next;
            lit_start = i;
        }
        if lit_start < end {
            cmds.push(Command {
                insert: (end - lit_start) as u32,
                copy: 0,
                dist: 0,
                out: 0,
            });
        }
    }
}

/// [`Buckets`] over an encoder's tables, writing the next position to enter back when dropped.
struct Guard<'t, const SIZE: usize, const H5: bool> {
    t: Buckets<'t, SIZE, H5>,
    ins: &'t mut usize,
}

impl<const SIZE: usize, const H5: bool> Drop for Guard<'_, SIZE, H5> {
    fn drop(&mut self) {
        *self.ins = self.t.ins;
    }
}
