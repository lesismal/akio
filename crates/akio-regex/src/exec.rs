//! The tree compiled to a Thompson NFA program ([`Prog`]), run by a Pike VM (no captures) and
//! by a DFA built from it ahead of time. A second program, with the groups' `Save` instructions
//! and the repetitions' priorities, is run by the capturing Pike VM ([`crate::pike`]) to find
//! where a match is and what its groups hold.
//!
//! Both engines move a set of *pending* instructions (threads waiting to be expanded) from one
//! position to the next. At each position the pending set is expanded through jumps, splits and
//! assertions, which only need the categories of the characters before and after the position
//! (start/end of input, `\n`, word character, anything else); the consuming instructions that
//! accept the next character give the next pending set. Instruction 0 is added at every
//! position (an unanchored search) unless the pattern starts with `^` / `\A`. The pending set
//! and the previous category determine everything that follows, so they are the DFA state.
//!
//! The DFA's alphabet is a partition of all characters into classes that no instruction and no
//! assertion tells apart: a table for ASCII, sorted intervals for the rest. Its states are built
//! breadth-first from the start, within limits; a transition that was not built is taken by the
//! NFA from the state's pending set, and the search returns to the DFA when the NFA reaches a
//! set the DFA has.

use std::{cell::Cell, collections::HashMap};

use crate::{
    Error,
    parse::{Look, Node, Parsed, in_ranges},
    tables,
};

/// Largest compiled program, in instructions.
const MAX_INSTS: usize = 20_000;
/// The DFA is built for programs of at most this many instructions.
const DFA_MAX_INSTS: usize = 4096;
/// Most DFA states built ahead of time.
const DFA_MAX_STATES: usize = 2048;
/// Most transition table entries (states times classes): 2 MiB of `u32`.
const DFA_MAX_ENTRIES: usize = 512 * 1024;
/// Instructions visited while building the DFA before it stops adding states.
const DFA_BUDGET: usize = 1_000_000;

/// Transition targets with a meaning of their own (state indexes stay below
/// [`DFA_MAX_ENTRIES`]).
const MATCH: u32 = u32::MAX;
const DEAD: u32 = u32::MAX - 1;
/// Not built: the step is taken by the NFA.
const MISS: u32 = u32::MAX - 2;

/// Character categories, as the assertions see them.
pub(crate) const EDGE: u8 = 0;
const NL: u8 = 1;
const WORD: u8 = 2;
const OTHER: u8 = 3;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Inst {
    Char(char),
    /// Index into `Prog::classes`.
    Class(u32),
    /// Any character but `\n`.
    Any,
    /// Any character.
    AnyNl,
    Split(u32, u32),
    Jmp(u32),
    Look(Look),
    /// Records the position in a capture slot (the capturing program only).
    Save(u32),
    Match,
}

/// Whether `c` is a word character (`\w`): Unicode, or ASCII only with `ascii`.
pub(crate) fn is_word(c: char, ascii: bool) -> bool {
    if c.is_ascii() {
        c.is_ascii_alphanumeric() || c == '_'
    } else {
        !ascii && in_ranges(tables::WORD, c as u32)
    }
}

pub(crate) fn look_ok(l: Look, prev: u8, next: u8) -> bool {
    match l {
        Look::StartText => prev == EDGE,
        Look::EndText => next == EDGE,
        Look::StartLine => prev == EDGE || prev == NL,
        Look::EndLine => next == EDGE || next == NL,
        Look::Word => (prev == WORD) != (next == WORD),
        Look::NotWord => (prev == WORD) == (next == WORD),
    }
}

/// A compiled pattern.
#[derive(Debug)]
pub(crate) struct Prog {
    insts: Vec<Inst>,
    classes: Vec<Box<[(u32, u32)]>>,
    /// Starts with `^` / `\A`: threads start at position 0 only.
    anchored: bool,
    /// The empty string at position 0 matches whatever follows: every input matches.
    always: bool,
    /// Has `\b` / `\B`: word characters are a category of their own.
    word_looks: bool,
    /// `\b` / `\B` see ASCII word characters only.
    ascii_word: bool,
    /// Has `(?m)^` / `(?m)$`: `\n` is a category of its own.
    line_looks: bool,
    /// The whole pattern is this literal text.
    literal: Option<Box<str>>,
    /// Matches the whole text only: [`literal`](Prog::literal) is compared, not searched for.
    whole: bool,
    dfa: Option<Dfa>,
    /// The capturing program: the same pattern with `Save` instructions around each group and
    /// around the whole match (slots 0 and 1), and splits ordered by priority (the preferred
    /// branch first: the left alternative, more of a greedy repetition, less of a lazy one).
    pub(crate) caps: Vec<Inst>,
    /// The name of each group, by number; group 0 is the whole match.
    pub(crate) names: std::sync::Arc<[Option<Box<str>>]>,
}

struct Compiler {
    insts: Vec<Inst>,
    /// Compiling the capturing program: groups save their bounds, and lazy repetitions prefer
    /// to stop.
    caps: bool,
}

impl Compiler {
    fn push(&mut self, i: Inst) -> Result<u32, Error> {
        if self.insts.len() >= MAX_INSTS {
            return Err(Error {
                pos: 0,
                msg: "pattern too large",
            });
        }
        self.insts.push(i);
        Ok((self.insts.len() - 1) as u32)
    }

    fn here(&self) -> u32 {
        self.insts.len() as u32
    }

    fn emit(&mut self, n: &Node) -> Result<(), Error> {
        match n {
            Node::Empty => {}
            Node::Char(c) => {
                self.push(Inst::Char(*c))?;
            }
            Node::Class(k) => {
                self.push(Inst::Class(*k))?;
            }
            Node::Any { nl } => {
                self.push(if *nl { Inst::AnyNl } else { Inst::Any })?;
            }
            Node::Look(l) => {
                self.push(Inst::Look(*l))?;
            }
            Node::Concat(v) => {
                for n in v {
                    self.emit(n)?;
                }
            }
            Node::Alt(v) => {
                let mut jumps = Vec::new();
                for (k, n) in v.iter().enumerate() {
                    if k + 1 < v.len() {
                        let split = self.push(Inst::Split(0, 0))?;
                        self.emit(n)?;
                        jumps.push(self.push(Inst::Jmp(0))?);
                        let next = self.here();
                        self.insts[split as usize] = Inst::Split(split + 1, next);
                    } else {
                        self.emit(n)?;
                    }
                }
                let end = self.here();
                for j in jumps {
                    self.insts[j as usize] = Inst::Jmp(end);
                }
            }
            Node::Repeat {
                node,
                min,
                max,
                greedy,
            } => self.repeat(node, *min, *max, *greedy)?,
            Node::Group(k, n) => {
                if self.caps {
                    self.push(Inst::Save(k * 2))?;
                    self.emit(n)?;
                    self.push(Inst::Save(k * 2 + 1))?;
                } else {
                    self.emit(n)?;
                }
            }
        }
        Ok(())
    }

    /// A split preferring `more` (another repetition) over `out`, or the other way round for a
    /// lazy repetition in the capturing program (only it runs threads by priority).
    fn split(&self, greedy: bool, more: u32, out: u32) -> Inst {
        if self.caps && !greedy {
            Inst::Split(out, more)
        } else {
            Inst::Split(more, out)
        }
    }

    /// `n{min,max}`, in the shapes Go's `regexp/syntax` simplifies and compiles it to, so that
    /// the threads' priorities, hence the match and its groups, are Go's: `x{n,}` is `n - 1`
    /// copies of `x` then `x+`, `x{n,m}` is `n` copies then `(x(x)?)?` nested, `x+` loops back
    /// after `x`, and `x*` is `(x+)?` when `x` can match the empty text (golang/go#46123), a
    /// loop before `x` otherwise. A repetition of a repetition of the same kind and greediness
    /// is one (`x**` is `x*`).
    fn repeat(
        &mut self,
        mut n: &Node,
        mut min: u32,
        mut max: Option<u32>,
        greedy: bool,
    ) -> Result<(), Error> {
        let kind = |min: u32, max: Option<u32>| matches!((min, max), (0 | 1, None) | (0, Some(1)));
        while let Node::Repeat {
            node: inner,
            min: imin,
            max: imax,
            greedy: ig,
        } = n
        {
            if !(kind(min, max) && (min, max) == (*imin, *imax) && greedy == *ig) {
                break;
            }
            n = inner;
            (min, max) = (*imin, *imax);
        }
        let Some(max) = max else {
            if min == 0 {
                return self.star(n, greedy);
            }
            for _ in 1..min {
                self.emit(n)?;
            }
            return self.plus(n, greedy);
        };
        for _ in 0..min {
            self.emit(n)?;
        }
        let mut splits = Vec::new();
        for _ in min..max {
            splits.push(self.push(Inst::Split(0, 0))?);
            self.emit(n)?;
        }
        let out = self.here();
        for s in splits {
            self.insts[s as usize] = self.split(greedy, s + 1, out);
        }
        Ok(())
    }

    /// `x*`.
    fn star(&mut self, n: &Node, greedy: bool) -> Result<(), Error> {
        if nullable(n) {
            // (x+)?
            let q = self.push(Inst::Split(0, 0))?;
            self.plus(n, greedy)?;
            let out = self.here();
            self.insts[q as usize] = self.split(greedy, q + 1, out);
            return Ok(());
        }
        // L: split(L+1, out); x; jmp L
        let l = self.push(Inst::Split(0, 0))?;
        self.emit(n)?;
        self.push(Inst::Jmp(l))?;
        let out = self.here();
        self.insts[l as usize] = self.split(greedy, l + 1, out);
        Ok(())
    }

    /// `x+`: L: x; split(L, out).
    fn plus(&mut self, n: &Node, greedy: bool) -> Result<(), Error> {
        let l = self.here();
        self.emit(n)?;
        let s = self.push(Inst::Split(0, 0))?;
        self.insts[s as usize] = self.split(greedy, l, s + 1);
        Ok(())
    }

    /// The program for `parsed`: the matching one, or with `caps` the capturing one.
    fn program(parsed: &Parsed, caps: bool) -> Result<Vec<Inst>, Error> {
        let mut c = Compiler {
            insts: Vec::new(),
            caps,
        };
        if parsed.opts.whole {
            c.push(Inst::Look(Look::StartText))?;
        }
        if caps {
            c.push(Inst::Save(0))?;
        }
        c.emit(&parsed.root)?;
        if caps {
            c.push(Inst::Save(1))?;
        }
        if parsed.opts.whole {
            c.push(Inst::Look(Look::EndText))?;
        }
        c.push(Inst::Match)?;
        Ok(c.insts)
    }
}

/// Whether `n` can match the empty text.
fn nullable(n: &Node) -> bool {
    match n {
        Node::Empty | Node::Look(_) => true,
        Node::Char(_) | Node::Class(_) | Node::Any { .. } => false,
        Node::Concat(v) => v.iter().all(nullable),
        Node::Alt(v) => v.iter().any(nullable),
        Node::Repeat { node, min, .. } => *min == 0 || nullable(node),
        Node::Group(_, n) => nullable(n),
    }
}

/// The text of a pattern that is only literal characters.
fn literal(n: &Node) -> Option<Box<str>> {
    match n {
        Node::Char(c) => Some(c.to_string().into()),
        Node::Group(_, n) => literal(n),
        Node::Concat(v) => v
            .iter()
            .map(|n| match n {
                Node::Char(c) => Some(*c),
                _ => None,
            })
            .collect::<Option<String>>()
            .map(String::into_boxed_str),
        _ => None,
    }
}

impl Prog {
    pub(crate) fn new(parsed: Parsed) -> Result<Prog, Error> {
        let whole = parsed.opts.whole;
        let insts = Compiler::program(&parsed, false)?;
        let caps = Compiler::program(&parsed, true)?;
        let looks = |f: fn(Look) -> bool| insts.iter().any(|i| matches!(i, Inst::Look(l) if f(*l)));
        let word_looks = looks(|l| matches!(l, Look::Word | Look::NotWord));
        let line_looks = looks(|l| matches!(l, Look::StartLine | Look::EndLine));
        let mut prog = Prog {
            anchored: matches!(insts[0], Inst::Look(Look::StartText)),
            insts,
            classes: parsed.classes,
            always: false,
            word_looks,
            ascii_word: parsed.opts.ascii,
            line_looks,
            literal: literal(&parsed.root),
            whole,
            dfa: None,
            caps,
            names: parsed.names.into(),
        };
        let mut sc = Scratch::default();
        sc.reserve(prog.insts.len());
        prog.always = [EDGE, NL, WORD, OTHER].iter().all(|&next| {
            sc.pending.clear();
            sc.pending.insert(0);
            prog.expand(&mut sc, EDGE, next, None) == Step::Match
        });
        if !prog.always && prog.insts.len() <= DFA_MAX_INSTS {
            prog.dfa = Dfa::build(&prog, &mut sc);
        }
        Ok(prog)
    }

    /// Whether threads start at position 0 only (`^` / `\A` first).
    pub(crate) fn anchored(&self) -> bool {
        self.anchored
    }

    /// The literal text the pattern is, and whether it must be the whole text.
    pub(crate) fn literal(&self) -> Option<(&str, bool)> {
        self.literal.as_deref().map(|l| (l, self.whole))
    }

    /// The category of `c`, merged with `OTHER` where no assertion tells them apart (fewer DFA
    /// states).
    pub(crate) fn category(&self, c: char) -> u8 {
        if c == '\n' {
            if self.line_looks { NL } else { OTHER }
        } else if self.word_looks && is_word(c, self.ascii_word) {
            WORD
        } else {
            OTHER
        }
    }

    pub(crate) fn consumes(&self, inst: Inst, c: char) -> bool {
        match inst {
            Inst::Char(x) => x == c,
            Inst::Any => c != '\n',
            Inst::AnyNl => true,
            Inst::Class(k) => in_ranges(&self.classes[k as usize], c as u32),
            _ => false,
        }
    }

    /// Expands `sc.pending` at a position between characters of categories `prev` and `next`;
    /// with `c` (the next character), fills `sc.next` with the instructions after those that
    /// accept it. Returns the number of instructions visited in `Step::Cont`.
    fn expand(&self, sc: &mut Scratch, prev: u8, next: u8, c: Option<char>) -> Step {
        let Scratch {
            pending,
            next: out,
            visited,
            stack,
            ..
        } = sc;
        visited.clear();
        out.clear();
        for &pc in &pending.dense {
            stack.clear();
            stack.push(pc);
            while let Some(pc) = stack.pop() {
                if !visited.insert(pc) {
                    continue;
                }
                let inst = self.insts[pc as usize];
                match inst {
                    Inst::Jmp(x) => stack.push(x),
                    Inst::Split(a, b) => {
                        stack.push(b);
                        stack.push(a);
                    }
                    Inst::Look(l) => {
                        if look_ok(l, prev, next) {
                            stack.push(pc + 1);
                        }
                    }
                    Inst::Match => return Step::Match,
                    _ => {
                        if c.is_some_and(|c| self.consumes(inst, c)) {
                            out.insert(pc + 1);
                        }
                    }
                }
            }
        }
        Step::Cont(visited.dense.len())
    }

    /// One character on the NFA: `sc.pending` (at a position after a character of category
    /// `*prev`) moves past `c`.
    fn nfa_step(&self, sc: &mut Scratch, prev: &mut u8, c: char) -> Step {
        let cat = self.category(c);
        let r = self.expand(sc, *prev, cat, Some(c));
        if r == Step::Match {
            return r;
        }
        if !self.anchored {
            sc.next.insert(0);
        }
        std::mem::swap(&mut sc.pending, &mut sc.next);
        *prev = cat;
        if sc.pending.dense.is_empty() {
            return Step::Dead;
        }
        r
    }

    /// Whether the pending threads match at the end of the input.
    fn nfa_finish(&self, sc: &mut Scratch, prev: u8) -> bool {
        self.expand(sc, prev, EDGE, None) == Step::Match
    }

    /// Matches `s` on the DFA alone, in one tight loop; `None` when the DFA has no such
    /// transition (or no DFA was built): the caller runs a full [`Search`].
    #[inline]
    pub(crate) fn dfa_match(&self, s: &str) -> Option<bool> {
        let d = self.dfa.as_ref()?;
        let b = s.as_bytes();
        let mut st = d.start;
        let mut i = 0;
        while let Some(&byte) = b.get(i) {
            let (k, len) = if byte < 0x80 {
                (d.ascii[usize::from(byte)], 1)
            } else {
                let c = s[i..].chars().next()?;
                (d.class_of(c), c.len_utf8())
            };
            let nx = *d.trans.get(st as usize + usize::from(k))?;
            if nx >= MISS {
                return match nx {
                    MATCH => Some(true),
                    DEAD => Some(false),
                    _ => None,
                };
            }
            st = nx;
            i += len;
        }
        Some(d.trans.get(st as usize + d.classes)? == &MATCH)
    }

    pub(crate) fn start(&self) -> Search<'_> {
        let mode = if self.always {
            Mode::Done(true)
        } else if let Some(d) = &self.dfa {
            Mode::Dfa(d.start)
        } else {
            Mode::Nfa(EDGE)
        };
        let mut s = Search {
            prog: self,
            mode,
            scratch: None,
        };
        if let Mode::Nfa(_) = s.mode {
            let sc = s.scratch();
            sc.pending.clear();
            sc.pending.insert(0);
        }
        s
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Match,
    Dead,
    /// Instructions visited.
    Cont(usize),
}

/// A set of instruction indexes (Briggs-Torczon): O(1) insert, test and clear.
#[derive(Debug, Default)]
struct Sparse {
    dense: Vec<u32>,
    sparse: Vec<u32>,
}

impl Sparse {
    fn reserve(&mut self, n: usize) {
        if self.sparse.len() < n {
            self.sparse.resize(n, 0);
            self.dense.reserve(n.saturating_sub(self.dense.len()));
        }
    }

    fn clear(&mut self) {
        self.dense.clear();
    }

    /// Adds `pc`; false when it was already there.
    fn insert(&mut self, pc: u32) -> bool {
        let i = self.sparse[pc as usize] as usize;
        if i < self.dense.len() && self.dense[i] == pc {
            return false;
        }
        self.sparse[pc as usize] = self.dense.len() as u32;
        self.dense.push(pc);
        true
    }
}

/// The NFA's working memory, kept per thread between searches.
#[derive(Debug, Default)]
struct Scratch {
    pending: Sparse,
    next: Sparse,
    visited: Sparse,
    stack: Vec<u32>,
    /// The pending set sorted, to look it up among the DFA states.
    key: Vec<u32>,
}

impl Scratch {
    fn reserve(&mut self, n: usize) {
        self.pending.reserve(n);
        self.next.reserve(n);
        self.visited.reserve(n);
    }

    /// Sorts the pending set into `key`.
    fn sort_key(&mut self) {
        self.key.clear();
        self.key.extend_from_slice(&self.pending.dense);
        self.key.sort_unstable();
    }
}

thread_local! {
    /// One [`Scratch`] per thread, taken by a search that needs the NFA and put back after
    /// (a search nested in another one, from a `Display` impl, makes its own).
    static SCRATCH: Cell<Option<Box<Scratch>>> = const { Cell::new(None) };
}

#[derive(Debug)]
struct Dfa {
    /// Class of each ASCII character.
    ascii: [u8; 128],
    /// Classes of the other characters: `(first code point, class)`, sorted, from 0x80 on.
    other: Vec<(u32, u8)>,
    classes: usize,
    /// Indexed by state index (`state * (classes + 1)`) plus class: the next state index, or
    /// [`MATCH`], [`DEAD`], [`MISS`]. The entry after the classes is the end of the input:
    /// [`MATCH`] or [`DEAD`] (no division to find a state's number when a search ends).
    trans: Vec<u32>,
    /// Pending set and previous category of each state (by state number).
    states: Vec<(Box<[u32]>, u8)>,
    /// State index of each sorted pending set, per previous category.
    index: [HashMap<Box<[u32]>, u32>; 4],
    start: u32,
}

impl Dfa {
    /// The class of a non-ASCII character.
    fn class_of(&self, c: char) -> u8 {
        let i = self.other.partition_point(|&(lo, _)| lo <= c as u32);
        self.other.get(i.wrapping_sub(1)).map_or(0, |&(_, k)| k)
    }

    /// `None` when the characters fall in more than 256 classes.
    fn build(prog: &Prog, sc: &mut Scratch) -> Option<Dfa> {
        // The distinct consuming instructions (a repetition copies the same one many times).
        let mut seen = std::collections::HashSet::new();
        let consuming: Vec<Inst> = prog
            .insts
            .iter()
            .copied()
            .filter(|&i| match i {
                Inst::Char(c) => seen.insert((0, c as u32)),
                Inst::Class(k) => seen.insert((1, k)),
                Inst::Any => seen.insert((2, 0)),
                Inst::AnyNl => seen.insert((3, 0)),
                _ => false,
            })
            .collect();
        // A character's signature: its category and the instructions that accept it.
        let mut sigs: HashMap<Vec<bool>, u8> = HashMap::new();
        let mut rep: Vec<char> = Vec::new();
        let mut class = |c: char| -> Option<u8> {
            let cat = prog.category(c);
            let mut sig = vec![cat == NL, cat == WORD];
            sig.extend(consuming.iter().map(|&i| prog.consumes(i, c)));
            if let Some(&k) = sigs.get(&sig) {
                return Some(k);
            }
            let k = u8::try_from(rep.len()).ok()?;
            sigs.insert(sig, k);
            rep.push(c);
            Some(k)
        };
        let mut ascii = [0u8; 128];
        for (b, slot) in ascii.iter_mut().enumerate() {
            *slot = class(char::from(b as u8))?;
        }
        // Non-ASCII: intervals between every boundary an instruction or category has.
        let mut starts: Vec<u32> = vec![0x80, 0xd800, 0xe000];
        let mut bound = |lo: u32, hi: u32| {
            starts.push(lo);
            if hi < 0x10_ffff {
                starts.push(hi + 1);
            }
        };
        for &i in &consuming {
            match i {
                Inst::Char(c) => bound(c as u32, c as u32),
                Inst::Class(k) => {
                    for &(lo, hi) in &prog.classes[k as usize] {
                        bound(lo, hi);
                    }
                }
                _ => {}
            }
        }
        if prog.word_looks && !prog.ascii_word {
            for &(lo, hi) in tables::WORD {
                bound(lo, hi);
            }
        }
        starts.retain(|&s| s >= 0x80);
        starts.sort_unstable();
        starts.dedup();
        let mut other: Vec<(u32, u8)> = Vec::with_capacity(starts.len());
        for &s in &starts {
            // Surrogates are not characters: that interval keeps the class before it.
            let k = match char::from_u32(s) {
                Some(c) => class(c)?,
                None => continue,
            };
            if other.last().is_none_or(|&(_, last)| last != k) {
                other.push((s, k));
            }
        }
        let classes = rep.len();
        let mut dfa = Dfa {
            ascii,
            other,
            classes,
            trans: Vec::new(),
            states: Vec::new(),
            index: Default::default(),
            start: 0,
        };
        let mut budget = DFA_BUDGET;
        sc.pending.clear();
        sc.pending.insert(0);
        dfa.start = dfa.add(prog, sc, EDGE);
        let mut s = 0;
        while s < dfa.states.len() && budget > 0 {
            for (k, &c) in rep.iter().enumerate() {
                let (pcs, prev) = &dfa.states[s];
                let mut prev = *prev;
                sc.pending.clear();
                for &pc in pcs {
                    sc.pending.insert(pc);
                }
                let target = match prog.nfa_step(sc, &mut prev, c) {
                    Step::Match => MATCH,
                    Step::Dead => DEAD,
                    Step::Cont(n) => {
                        budget = budget.saturating_sub(n);
                        match dfa.lookup(sc, prev) {
                            Some(t) => t,
                            None if dfa.states.len() < DFA_MAX_STATES
                                && (dfa.states.len() + 1) * (classes + 1) <= DFA_MAX_ENTRIES =>
                            {
                                dfa.add(prog, sc, prev)
                            }
                            None => MISS,
                        }
                    }
                };
                dfa.trans[s * (classes + 1) + k] = target;
            }
            s += 1;
        }
        Some(dfa)
    }

    /// The state index of `sc.pending` after a character of category `prev`, if there is one
    /// (leaves the sorted set in `sc.key`).
    fn lookup(&self, sc: &mut Scratch, prev: u8) -> Option<u32> {
        sc.sort_key();
        self.index[prev as usize].get(&sc.key[..]).copied()
    }

    /// Adds the state for `sc.pending` after a character of category `prev`; returns its index.
    fn add(&mut self, prog: &Prog, sc: &mut Scratch, prev: u8) -> u32 {
        sc.sort_key();
        let at = (self.states.len() * (self.classes + 1)) as u32;
        let key: Box<[u32]> = sc.key.clone().into_boxed_slice();
        self.index[prev as usize].insert(key.clone(), at);
        self.states.push((key, prev));
        self.trans.resize(self.trans.len() + self.classes, MISS);
        self.trans.push(if prog.nfa_finish(sc, prev) {
            MATCH
        } else {
            DEAD
        });
        at
    }
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Done(bool),
    /// In the DFA, at this state index.
    Dfa(u32),
    /// On the NFA (pending set in the scratch), after a character of this category.
    Nfa(u8),
}

/// A search in progress: input is fed in pieces, then [`finish`](Search::finish) tells whether
/// it matched.
#[derive(Debug)]
pub(crate) struct Search<'p> {
    prog: &'p Prog,
    mode: Mode,
    scratch: Option<Box<Scratch>>,
}

impl Drop for Search<'_> {
    fn drop(&mut self) {
        if let Some(sc) = self.scratch.take() {
            let _ = SCRATCH.try_with(|c| c.set(Some(sc)));
        }
    }
}

impl Search<'_> {
    fn scratch(&mut self) -> &mut Scratch {
        let n = self.prog.insts.len();
        self.scratch.get_or_insert_with(|| {
            let mut sc = SCRATCH
                .try_with(Cell::take)
                .ok()
                .flatten()
                .unwrap_or_default();
            sc.reserve(n);
            sc
        })
    }

    /// Whether the outcome is known whatever follows.
    pub(crate) fn done(&self) -> Option<bool> {
        match self.mode {
            Mode::Done(m) => Some(m),
            _ => None,
        }
    }

    /// One character on the NFA from DFA state index `st` (a transition that was not built),
    /// then back to the DFA if it has the state reached.
    fn miss(&mut self, st: u32, c: char) {
        let prog = self.prog;
        let Some(d) = &prog.dfa else {
            return;
        };
        let (pcs, prev) = &d.states[st as usize / (d.classes + 1)];
        let sc = self.scratch();
        sc.pending.clear();
        for &pc in pcs {
            sc.pending.insert(pc);
        }
        self.nfa_char(*prev, c);
    }

    /// One character on the NFA, then back to the DFA if it has the state reached.
    fn nfa_char(&mut self, mut prev: u8, c: char) {
        let prog = self.prog;
        let sc = self.scratch();
        let mode = match prog.nfa_step(sc, &mut prev, c) {
            Step::Match => Mode::Done(true),
            Step::Dead => Mode::Done(false),
            Step::Cont(_) => match prog.dfa.as_ref().and_then(|d| d.lookup(sc, prev)) {
                Some(st) => Mode::Dfa(st),
                None => Mode::Nfa(prev),
            },
        };
        self.mode = mode;
    }

    pub(crate) fn feed(&mut self, s: &str) {
        let prog = self.prog;
        let b = s.as_bytes();
        let mut i = 0;
        while i < b.len() {
            match self.mode {
                Mode::Done(_) => return,
                Mode::Dfa(mut st) => {
                    let Some(d) = &prog.dfa else {
                        return;
                    };
                    let mut special = None;
                    while let Some(&byte) = b.get(i) {
                        let (k, len) = if byte < 0x80 {
                            (d.ascii[byte as usize], 1)
                        } else {
                            match s[i..].chars().next() {
                                Some(c) => (d.class_of(c), c.len_utf8()),
                                None => return,
                            }
                        };
                        let nx = d.trans[st as usize + k as usize];
                        if nx >= MISS {
                            special = Some(nx);
                            break;
                        }
                        st = nx;
                        i += len;
                    }
                    match special {
                        Some(MATCH) => self.mode = Mode::Done(true),
                        Some(DEAD) => self.mode = Mode::Done(false),
                        Some(_) => {
                            let Some(c) = s[i..].chars().next() else {
                                return;
                            };
                            self.miss(st, c);
                            i += c.len_utf8();
                        }
                        None => self.mode = Mode::Dfa(st),
                    }
                }
                Mode::Nfa(prev) => {
                    let Some(c) = s[i..].chars().next() else {
                        return;
                    };
                    self.nfa_char(prev, c);
                    i += c.len_utf8();
                }
            }
        }
    }

    pub(crate) fn finish(&mut self) -> bool {
        match self.mode {
            Mode::Done(m) => m,
            Mode::Dfa(st) => self
                .prog
                .dfa
                .as_ref()
                .is_some_and(|d| d.trans[st as usize + d.classes] == MATCH),
            Mode::Nfa(prev) => {
                let prog = self.prog;
                let sc = self.scratch();
                prog.nfa_finish(sc, prev)
            }
        }
    }

    /// Runs the NFA only (no DFA, no literal search), for the tests and the fuzz target.
    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn nfa_only(prog: &Prog, s: &str) -> bool {
        if prog.always {
            return true;
        }
        let mut sc = Scratch::default();
        sc.reserve(prog.insts.len());
        sc.pending.insert(0);
        let mut prev = EDGE;
        for c in s.chars() {
            match prog.nfa_step(&mut sc, &mut prev, c) {
                Step::Match => return true,
                Step::Dead => return false,
                Step::Cont(_) => {}
            }
        }
        prog.nfa_finish(&mut sc, prev)
    }

    /// Whether the DFA was built and how many states it has (tests).
    #[cfg(test)]
    pub(crate) fn dfa_states(prog: &Prog) -> Option<usize> {
        prog.dfa.as_ref().map(|d| d.states.len())
    }
}
