//! The capturing Pike VM: where the leftmost-first match is and what its groups hold, in time
//! linear in the text (times the program size).
//!
//! It runs [`Prog::caps`], whose splits put the preferred branch first. Threads are kept in
//! priority order; each carries its capture slots. When the thread of highest priority still
//! alive reaches `Match`, that match is kept and every thread of lower priority is dropped; the
//! threads of higher priority run on and may replace it with a later end. A new thread starts at
//! each position (lowest priority) until a match is found: the leftmost start wins. This is the
//! semantics of Go's `regexp` and of the `regex` crate.

use std::cell::Cell;

use crate::exec::{EDGE, Inst, Prog, look_ok};

/// No position recorded in a slot.
pub(crate) const NONE: usize = usize::MAX;

/// A set of threads: the instructions, in priority order, and the slots of each.
#[derive(Debug, Default)]
struct Threads {
    /// Instruction indexes in the order they were added (priority); `sparse` maps back.
    dense: Vec<u32>,
    sparse: Vec<u32>,
    /// `slots` per instruction, indexed by `pc * slots`.
    caps: Vec<usize>,
}

impl Threads {
    fn reset(&mut self, insts: usize, slots: usize) {
        self.dense.clear();
        if self.sparse.len() < insts {
            self.sparse.resize(insts, 0);
        }
        let n = insts.saturating_mul(slots);
        if self.caps.len() < n {
            self.caps.resize(n, NONE);
        }
    }

    /// Adds `pc`; false when it was already there.
    fn insert(&mut self, pc: u32) -> bool {
        let Some(&i) = self.sparse.get(pc as usize) else {
            return false;
        };
        if self.dense.get(i as usize) == Some(&pc) {
            return false;
        }
        if let Some(s) = self.sparse.get_mut(pc as usize) {
            *s = self.dense.len() as u32;
        }
        self.dense.push(pc);
        true
    }
}

/// A step of the closure: an instruction to follow, or a slot to put back once the branch
/// that set it has been followed.
#[derive(Clone, Copy, Debug)]
enum Frame {
    Explore(u32),
    Restore(u32, usize),
}

/// The capturing VM's working memory, kept per thread between searches.
#[derive(Debug, Default)]
struct Scratch {
    clist: Threads,
    nlist: Threads,
    stack: Vec<Frame>,
    /// The slots of the thread being followed.
    cur: Vec<usize>,
}

thread_local! {
    /// One [`Scratch`] per thread, taken by a search and put back after.
    static SCRATCH: Cell<Option<Box<Scratch>>> = const { Cell::new(None) };
}

/// The category of the character before `at` in `text` (`EDGE` at the start).
fn cat_before(prog: &Prog, text: &str, at: usize) -> u8 {
    text.get(..at)
        .and_then(|s| s.chars().next_back())
        .map_or(EDGE, |c| prog.category(c))
}

/// The category of the character starting at `at` in `text` (`EDGE` at the end).
fn cat_at(prog: &Prog, text: &str, at: usize) -> u8 {
    text.get(at..)
        .and_then(|s| s.chars().next())
        .map_or(EDGE, |c| prog.category(c))
}

/// Follows the jumps, splits, saves and assertions from `pc` at position `at` (between
/// characters of categories `prev` and `next`), adding the instructions reached to `list` in
/// priority order with the slots in `cur` as they are on the way there.
#[allow(clippy::too_many_arguments)]
fn add(
    insts: &[Inst],
    list: &mut Threads,
    stack: &mut Vec<Frame>,
    cur: &mut [usize],
    slots: usize,
    pc: u32,
    at: usize,
    prev: u8,
    next: u8,
) {
    stack.clear();
    stack.push(Frame::Explore(pc));
    while let Some(f) = stack.pop() {
        match f {
            Frame::Restore(slot, old) => {
                if let Some(s) = cur.get_mut(slot as usize) {
                    *s = old;
                }
            }
            Frame::Explore(pc) => {
                if !list.insert(pc) {
                    continue;
                }
                let Some(&inst) = insts.get(pc as usize) else {
                    continue;
                };
                match inst {
                    Inst::Jmp(x) => stack.push(Frame::Explore(x)),
                    Inst::Split(a, b) => {
                        stack.push(Frame::Explore(b));
                        stack.push(Frame::Explore(a));
                    }
                    Inst::Look(l) => {
                        if look_ok(l, prev, next) {
                            stack.push(Frame::Explore(pc + 1));
                        }
                    }
                    Inst::Save(slot) => match cur.get_mut(slot as usize) {
                        Some(s) => {
                            stack.push(Frame::Restore(slot, *s));
                            *s = at;
                            stack.push(Frame::Explore(pc + 1));
                        }
                        None => stack.push(Frame::Explore(pc + 1)),
                    },
                    // A thread that waits for a character, or has matched: keep its slots.
                    _ => {
                        let start = (pc as usize).saturating_mul(slots);
                        if let Some(row) = list.caps.get_mut(start..start.saturating_add(slots)) {
                            row.copy_from_slice(cur);
                        }
                    }
                }
            }
        }
    }
}

/// The leftmost-first match in `text` starting at `start` or later (assertions see the text
/// before `start`), its slots written to `out` (`2 * groups` of them, [`NONE`] where a group took
/// no part). Returns whether there is one. `start` must be a character boundary of `text`.
pub(crate) fn search(prog: &Prog, text: &str, start: usize, out: &mut [usize]) -> bool {
    let mut sc = SCRATCH
        .try_with(Cell::take)
        .ok()
        .flatten()
        .unwrap_or_default();
    let found = run(prog, text, start, out, &mut sc);
    let _ = SCRATCH.try_with(|c| c.set(Some(sc)));
    found
}

fn run(prog: &Prog, text: &str, start: usize, out: &mut [usize], sc: &mut Scratch) -> bool {
    let insts = &prog.caps[..];
    let slots = out.len();
    let Scratch {
        clist,
        nlist,
        stack,
        cur,
    } = sc;
    clist.reset(insts.len(), slots);
    nlist.reset(insts.len(), slots);
    cur.clear();
    cur.resize(slots, NONE);
    let mut matched = false;
    let mut at = start;
    let mut prev = cat_before(prog, text, at);
    loop {
        let c = text.get(at..).and_then(|s| s.chars().next());
        let next = c.map_or(EDGE, |c| prog.category(c));
        if !matched && (!prog.anchored() || at == 0) {
            cur.fill(NONE);
            add(insts, clist, stack, cur, slots, 0, at, prev, next);
        }
        if clist.dense.is_empty() && (matched || prog.anchored()) {
            break;
        }
        let after = c.map_or(at, |c| at + c.len_utf8());
        let next2 = cat_at(prog, text, after);
        let mut i = 0;
        while let Some(&pc) = clist.dense.get(i) {
            i += 1;
            let Some(&inst) = insts.get(pc as usize) else {
                continue;
            };
            let row = (pc as usize).saturating_mul(slots);
            match inst {
                Inst::Match => {
                    if let Some(r) = clist.caps.get(row..row.saturating_add(slots)) {
                        out.copy_from_slice(r);
                    }
                    matched = true;
                    // The threads after this one have lower priority.
                    break;
                }
                _ => {
                    if c.is_some_and(|c| prog.consumes(inst, c)) {
                        if let Some(r) = clist.caps.get(row..row.saturating_add(slots)) {
                            cur.copy_from_slice(r);
                        }
                        let n = next;
                        add(insts, nlist, stack, cur, slots, pc + 1, after, n, next2);
                    }
                }
            }
        }
        if c.is_none() {
            break;
        }
        std::mem::swap(clist, nlist);
        nlist.dense.clear();
        at = after;
        prev = next;
    }
    matched
}
