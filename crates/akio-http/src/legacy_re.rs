//! The route constraint engine the router used before ADR-051, kept unchanged (test and fuzzing
//! builds only) as the reference that `akio-regex` (`RegexBuilder` with `whole_text` and
//! `ascii_classes`, what the router uses now) is compared with: the differential test below and
//! the `regex_match` fuzz target. Do not fix or extend it: it records the old behaviour.
//!
//! A small regular expression engine for route parameter constraints (`{id:[0-9]+}`): a pattern
//! always matches the whole input (as if wrapped in `^(?:...)$`), in time linear in the input
//! (Thompson NFA simulation, no backtracking).
//!
//! Syntax (a subset of the `regex` crate's, with the same meaning):
//!
//! * literals (any Unicode scalar value), `.` (any character but `\n`), `^` and `$` (start and
//!   end of the input);
//! * classes `[a-z0-9_]`, `[^/]`, with ranges, negation, escapes and `\d \w \s` inside; a `]`
//!   first in the class and a `-` first or last are literal;
//! * `\d` `\w` `\s` and their negations `\D` `\W` `\S` (ASCII: `[0-9]`, `[0-9A-Za-z_]`,
//!   `[\t\n\x0B\x0C\r ]`); escapes `\n \t \r \f \v \a`, `\xHH`, `\x{H...}`, `\uHHHH`, `\u{H...}`,
//!   `\UHHHHHHHH`, `\U{H...}`, and any escaped ASCII punctuation;
//! * groups `(...)`, `(?:...)`, `(?P<name>...)`, `(?<name>...)` (nothing is captured), alternation
//!   `|`, quantifiers `*` `+` `?` `{m}` `{m,}` `{m,n}` (counts up to 1000), each optionally lazy
//!   (`*?`; laziness does not change whether the input matches).
//!
//! Unsupported syntax is a compile error naming it: flags (`(?i)`), word boundaries and other
//! assertions (`\b`, `\A`, `\<`), Unicode classes (`\p{L}`), backreferences, POSIX and nested
//! classes (`[[:alpha:]]`), class set operations (`&&`, `--`, `~~`).
//!

use std::fmt;

/// A pattern that does not compile: what is wrong and where (a byte offset in the pattern).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Error {
    /// Byte offset in the pattern.
    pub pos: usize,
    /// What is wrong.
    pub msg: &'static str,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.msg, self.pos)
    }
}

impl std::error::Error for Error {}

/// Largest repetition count in `{m,n}`.
const MAX_REPEAT: u32 = 1000;
/// Largest compiled program, in instructions.
const MAX_INSTS: usize = 10_000;
/// Deepest group nesting.
const MAX_DEPTH: u32 = 64;

enum Node {
    Empty,
    Char(char),
    /// Sorted, non-overlapping, non-adjacent inclusive ranges of code points.
    Class(Vec<(u32, u32)>),
    /// Any character but `\n`.
    Any,
    Start,
    End,
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    Repeat(Box<Node>, u32, Option<u32>),
}

/// Sorts and merges ranges; with `negate`, complements them over all code points.
fn normalize(mut r: Vec<(u32, u32)>, negate: bool) -> Vec<(u32, u32)> {
    r.sort_unstable();
    let mut out: Vec<(u32, u32)> = Vec::with_capacity(r.len());
    for (lo, hi) in r {
        match out.last_mut() {
            Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
            _ => out.push((lo, hi)),
        }
    }
    if !negate {
        return out;
    }
    let mut neg = Vec::with_capacity(out.len() + 1);
    let mut next = 0u32;
    for (lo, hi) in out {
        if lo > next {
            neg.push((next, lo - 1));
        }
        next = hi + 1;
    }
    if next <= 0x10_ffff {
        neg.push((next, 0x10_ffff));
    }
    neg
}

const DIGIT: &[(u32, u32)] = &[(0x30, 0x39)];
const WORD: &[(u32, u32)] = &[(0x30, 0x39), (0x41, 0x5a), (0x5f, 0x5f), (0x61, 0x7a)];
const SPACE: &[(u32, u32)] = &[(0x09, 0x0d), (0x20, 0x20)];

/// A Perl class (`\d \w \s` and negations).
fn perl_class(c: char) -> Option<(&'static [(u32, u32)], bool)> {
    Some(match c {
        'd' => (DIGIT, false),
        'D' => (DIGIT, true),
        'w' => (WORD, false),
        'W' => (WORD, true),
        's' => (SPACE, false),
        'S' => (SPACE, true),
        _ => return None,
    })
}

/// What an escape stands for.
enum Escape {
    Char(char),
    Class(&'static [(u32, u32)], bool),
}

struct Parser {
    chars: Vec<(usize, char)>,
    len: usize,
    i: usize,
    depth: u32,
}

impl Parser {
    fn pos(&self) -> usize {
        self.chars.get(self.i).map_or(self.len, |&(p, _)| p)
    }

    fn err<T>(&self, msg: &'static str) -> Result<T, Error> {
        Err(Error {
            pos: self.pos(),
            msg,
        })
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.i).map(|&(_, c)| c)
    }

    fn peek2(&self) -> Option<char> {
        self.chars.get(self.i + 1).map(|&(_, c)| c)
    }

    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn alt(&mut self) -> Result<Node, Error> {
        let mut alts = vec![self.concat()?];
        while self.eat('|') {
            alts.push(self.concat()?);
        }
        Ok(if alts.len() == 1 {
            alts.pop().unwrap_or(Node::Empty)
        } else {
            Node::Alt(alts)
        })
    }

    fn concat(&mut self) -> Result<Node, Error> {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            let atom = self.atom()?;
            items.push(self.quantifiers(atom)?);
        }
        Ok(match items.len() {
            0 => Node::Empty,
            1 => items.pop().unwrap_or(Node::Empty),
            _ => Node::Concat(items),
        })
    }

    fn atom(&mut self) -> Result<Node, Error> {
        let Some(c) = self.peek() else {
            return self.err("unexpected end of pattern");
        };
        if matches!(c, '*' | '+' | '?' | '{') {
            return self.err("repetition operator missing expression");
        }
        self.i += 1;
        Ok(match c {
            '.' => Node::Any,
            '^' => Node::Start,
            '$' => Node::End,
            '(' => self.group()?,
            '[' => self.class()?,
            '\\' => match self.escape(false)? {
                Escape::Char(c) => Node::Char(c),
                Escape::Class(r, neg) => Node::Class(normalize(r.to_vec(), neg)),
            },
            c => Node::Char(c),
        })
    }

    fn group(&mut self) -> Result<Node, Error> {
        if self.depth >= MAX_DEPTH {
            return self.err("groups nested too deeply");
        }
        if self.eat('?') {
            if self.eat(':') {
            } else if self.eat('<') || (self.eat('P') && self.eat('<')) {
                let start = self.i;
                while let Some(c) = self.peek() {
                    if c == '>' {
                        break;
                    }
                    let ok = c == '_'
                        || c.is_ascii_alphabetic()
                        || (c.is_ascii_digit() && self.i > start);
                    if !ok {
                        return self.err("invalid group name");
                    }
                    self.i += 1;
                }
                if self.i == start || !self.eat('>') {
                    return self.err("invalid group name");
                }
            } else {
                return self.err("group flags are not supported");
            }
        }
        self.depth += 1;
        let inner = self.alt()?;
        self.depth -= 1;
        if !self.eat(')') {
            return self.err("unclosed group");
        }
        Ok(inner)
    }

    fn hex(&mut self, digits: usize) -> Result<char, Error> {
        let mut v = 0u32;
        if self.eat('{') {
            let start = self.i;
            while let Some(d) = self.peek().and_then(|c| c.to_digit(16)) {
                if self.i - start >= 8 {
                    return self.err("invalid escape: too many hex digits");
                }
                v = v * 16 + d;
                self.i += 1;
            }
            if self.i == start || !self.eat('}') {
                return self.err("invalid hex escape");
            }
        } else {
            for _ in 0..digits {
                let Some(d) = self.peek().and_then(|c| c.to_digit(16)) else {
                    return self.err("invalid hex escape");
                };
                v = v * 16 + d;
                self.i += 1;
            }
        }
        match char::from_u32(v) {
            Some(c) => Ok(c),
            None => self.err("invalid escape: not a Unicode scalar value"),
        }
    }

    /// After a `\`.
    fn escape(&mut self, in_class: bool) -> Result<Escape, Error> {
        let Some(c) = self.peek() else {
            return self.err("incomplete escape");
        };
        self.i += 1;
        if let Some((r, neg)) = perl_class(c) {
            return Ok(Escape::Class(r, neg));
        }
        Ok(Escape::Char(match c {
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            'f' => '\x0c',
            'v' => '\x0b',
            'a' => '\x07',
            'x' => self.hex(2)?,
            'u' => self.hex(4)?,
            'U' => self.hex(8)?,
            c if c.is_ascii() && !c.is_ascii_alphanumeric() && c != '<' && c != '>' => c,
            _ => {
                self.i -= 1;
                return self.err(if in_class {
                    "unsupported escape in class"
                } else {
                    "unsupported escape (assertions, Unicode classes and backreferences are not supported)"
                });
            }
        }))
    }

    /// After a `[`.
    fn class(&mut self) -> Result<Node, Error> {
        let negate = self.eat('^');
        let mut ranges: Vec<(u32, u32)> = Vec::new();
        let mut first = true;
        loop {
            let Some(c) = self.peek() else {
                return self.err("unclosed character class");
            };
            if c == ']' && !first {
                self.i += 1;
                break;
            }
            first = false;
            if c == '[' {
                return self.err("nested and POSIX classes are not supported");
            }
            if matches!(
                (c, self.peek2()),
                ('&', Some('&')) | ('~', Some('~')) | ('-', Some('-'))
            ) {
                return self.err("class set operations are not supported");
            }
            self.i += 1;
            let lo = if c == '\\' {
                match self.escape(true)? {
                    Escape::Char(c) => c,
                    Escape::Class(r, neg) => {
                        ranges.extend(normalize(r.to_vec(), neg));
                        if self.peek() == Some('-') && !matches!(self.peek2(), Some(']') | None) {
                            return self.err("invalid range boundary: a class");
                        }
                        continue;
                    }
                }
            } else {
                c
            };
            if self.peek() == Some('-') && !matches!(self.peek2(), Some(']') | None) {
                self.i += 1;
                let hi = match self.peek() {
                    Some('\\') => {
                        self.i += 1;
                        match self.escape(true)? {
                            Escape::Char(c) => c,
                            Escape::Class(..) => {
                                return self.err("invalid range boundary: a class");
                            }
                        }
                    }
                    Some('[') => return self.err("nested and POSIX classes are not supported"),
                    Some(c) => {
                        self.i += 1;
                        c
                    }
                    None => return self.err("unclosed character class"),
                };
                if lo > hi {
                    return self.err("invalid class range: start > end");
                }
                ranges.push((lo as u32, hi as u32));
            } else {
                ranges.push((lo as u32, lo as u32));
            }
        }
        Ok(Node::Class(normalize(ranges, negate)))
    }

    fn skip_space(&mut self) {
        while self.peek().is_some_and(char::is_whitespace) {
            self.i += 1;
        }
    }

    /// A count in `{m,n}`, with whitespace around it; `None` (nothing consumed) without digits.
    fn number(&mut self) -> Result<Option<u32>, Error> {
        let before = self.i;
        self.skip_space();
        let start = self.i;
        let mut v = 0u32;
        while let Some(d) = self.peek().and_then(|c| c.to_digit(10)) {
            v = v.saturating_mul(10).saturating_add(d);
            self.i += 1;
        }
        if self.i == start {
            self.i = before;
            return Ok(None);
        }
        if v > MAX_REPEAT {
            return self.err("repetition count too large (at most 1000)");
        }
        self.skip_space();
        Ok(Some(v))
    }

    fn quantifiers(&mut self, mut node: Node) -> Result<Node, Error> {
        loop {
            let (min, max) = match self.peek() {
                Some('*') => (0, None),
                Some('+') => (1, None),
                Some('?') => (0, Some(1)),
                Some('{') => {
                    self.i += 1;
                    let Some(min) = self.number()? else {
                        return self.err("repetition quantifier expects a decimal");
                    };
                    let max = if self.eat(',') {
                        self.number()?
                    } else {
                        Some(min)
                    };
                    if self.peek() != Some('}') {
                        return self.err("unclosed counted repetition");
                    }
                    if max.is_some_and(|m| m < min) {
                        return self.err("invalid repetition range: min > max");
                    }
                    (min, max)
                }
                _ => return Ok(node),
            };
            self.i += 1;
            self.eat('?'); // lazy: the same matches
            node = Node::Repeat(Box::new(node), min, max);
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Inst {
    Char(char),
    /// Index into `Prog::classes`.
    Class(u32),
    Any,
    Split(u32, u32),
    Jmp(u32),
    Start,
    End,
    Match,
}

struct Compiler {
    insts: Vec<Inst>,
    classes: Vec<Vec<(u32, u32)>>,
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
            Node::Class(r) => {
                let idx = self.classes.len() as u32;
                self.classes.push(r.clone());
                self.push(Inst::Class(idx))?;
            }
            Node::Any => {
                self.push(Inst::Any)?;
            }
            Node::Start => {
                self.push(Inst::Start)?;
            }
            Node::End => {
                self.push(Inst::End)?;
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
            Node::Repeat(n, min, max) => {
                for _ in 0..*min {
                    self.emit(n)?;
                }
                match max {
                    None => {
                        // x*: L: split(L+1, out); x; jmp L
                        let l = self.push(Inst::Split(0, 0))?;
                        self.emit(n)?;
                        self.push(Inst::Jmp(l))?;
                        let out = self.here();
                        self.insts[l as usize] = Inst::Split(l + 1, out);
                    }
                    Some(max) => {
                        let mut splits = Vec::new();
                        for _ in *min..*max {
                            splits.push(self.push(Inst::Split(0, 0))?);
                            self.emit(n)?;
                        }
                        let out = self.here();
                        for s in splits {
                            self.insts[s as usize] = Inst::Split(s + 1, out);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// A set of states for patterns with at most 64 consuming instructions: each state's follow
/// set is a bit mask, so a step is a few AND/OR operations.
#[derive(Debug)]
struct Bits {
    /// The consuming instruction of each state.
    state_inst: Vec<u32>,
    /// States active before the first character.
    init: u64,
    /// Whether the empty input matches.
    empty_matches: bool,
    /// States reachable after a state consumed a character.
    follow: Vec<u64>,
    /// States after which the end of the input matches.
    accept: u64,
    /// States that accept each ASCII byte.
    ascii: Box<[u64; 128]>,
}

/// A compiled pattern; matches whole inputs only.
pub(crate) struct Regex {
    insts: Vec<Inst>,
    classes: Vec<Vec<(u32, u32)>>,
    bits: Option<Bits>,
}

impl fmt::Debug for Regex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Regex")
            .field("insts", &self.insts.len())
            .finish_non_exhaustive()
    }
}

impl Regex {
    /// Compiles `pattern` (see the module docs for the syntax).
    pub(crate) fn new(pattern: &str) -> Result<Regex, Error> {
        let mut p = Parser {
            chars: pattern.char_indices().collect(),
            len: pattern.len(),
            i: 0,
            depth: 0,
        };
        let ast = p.alt()?;
        if p.peek().is_some() {
            return p.err("unmatched `)`");
        }
        let mut c = Compiler {
            insts: Vec::new(),
            classes: Vec::new(),
        };
        c.emit(&ast)?;
        c.push(Inst::Match)?;
        let mut re = Regex {
            insts: c.insts,
            classes: c.classes,
            bits: None,
        };
        re.bits = re.build_bits();
        Ok(re)
    }

    /// Whether the whole of `s` matches.
    pub(crate) fn is_match(&self, s: &str) -> bool {
        match &self.bits {
            Some(b) => self.bits_match(b, s),
            None => self.pike_match(s),
        }
    }

    fn consumes(&self, inst: Inst, c: char) -> bool {
        match inst {
            Inst::Char(x) => x == c,
            Inst::Any => c != '\n',
            Inst::Class(k) => {
                let r = &self.classes[k as usize];
                let c = c as u32;
                // First range ending at or after `c`.
                let i = r.partition_point(|&(_, hi)| hi < c);
                r.get(i).is_some_and(|&(lo, _)| lo <= c)
            }
            _ => false,
        }
    }

    /// Instructions reached from `pc` without consuming: calls `f` on every consuming one and on
    /// `Match`. `seen` is scratch space (cleared here).
    fn closure(
        &self,
        pc: u32,
        at_start: bool,
        at_end: bool,
        seen: &mut [bool],
        stack: &mut Vec<u32>,
        mut f: impl FnMut(u32),
    ) {
        seen.fill(false);
        stack.clear();
        stack.push(pc);
        while let Some(pc) = stack.pop() {
            if std::mem::replace(&mut seen[pc as usize], true) {
                continue;
            }
            match self.insts[pc as usize] {
                Inst::Jmp(x) => stack.push(x),
                Inst::Split(a, b) => {
                    stack.push(b);
                    stack.push(a);
                }
                Inst::Start => {
                    if at_start {
                        stack.push(pc + 1);
                    }
                }
                Inst::End => {
                    if at_end {
                        stack.push(pc + 1);
                    }
                }
                _ => f(pc),
            }
        }
    }

    fn build_bits(&self) -> Option<Bits> {
        let consuming: Vec<u32> = (0..self.insts.len() as u32)
            .filter(|&pc| {
                matches!(
                    self.insts[pc as usize],
                    Inst::Char(_) | Inst::Any | Inst::Class(_)
                )
            })
            .collect();
        if consuming.len() > 64 {
            return None;
        }
        let mut state_of = vec![u32::MAX; self.insts.len()];
        for (s, &pc) in consuming.iter().enumerate() {
            state_of[pc as usize] = s as u32;
        }
        let match_pc = (self.insts.len() - 1) as u32;
        let (mut seen, mut stack) = (vec![false; self.insts.len()], Vec::new());
        let mut set = |pc: u32, at_start: bool, at_end: bool| {
            let (mut mask, mut matched) = (0u64, false);
            self.closure(pc, at_start, at_end, &mut seen, &mut stack, |p| {
                if p == match_pc {
                    matched = true;
                } else {
                    mask |= 1 << state_of[p as usize];
                }
            });
            (mask, matched)
        };
        let init = set(0, true, false).0;
        let empty_matches = set(0, true, true).1;
        let mut follow = Vec::with_capacity(consuming.len());
        let mut accept = 0u64;
        for (s, &pc) in consuming.iter().enumerate() {
            follow.push(set(pc + 1, false, false).0);
            if set(pc + 1, false, true).1 {
                accept |= 1 << s;
            }
        }
        let mut ascii = Box::new([0u64; 128]);
        for (b, m) in ascii.iter_mut().enumerate() {
            for (s, &pc) in consuming.iter().enumerate() {
                if self.consumes(self.insts[pc as usize], char::from(b as u8)) {
                    *m |= 1 << s;
                }
            }
        }
        Some(Bits {
            state_inst: consuming,
            init,
            empty_matches,
            follow,
            accept,
            ascii,
        })
    }

    fn bits_match(&self, b: &Bits, s: &str) -> bool {
        let (mut cur, mut last) = (b.init, 0u64);
        if s.is_empty() {
            return b.empty_matches;
        }
        for c in s.chars() {
            let mut m = if (c as u32) < 128 {
                cur & b.ascii[c as usize]
            } else {
                let mut m = 0u64;
                let mut bits = cur;
                while bits != 0 {
                    let st = bits.trailing_zeros();
                    if self.consumes(self.insts[b.state_inst[st as usize] as usize], c) {
                        m |= 1 << st;
                    }
                    bits &= bits - 1;
                }
                m
            };
            if m == 0 {
                return false;
            }
            last = m;
            let mut next = 0u64;
            while m != 0 {
                next |= b.follow[m.trailing_zeros() as usize];
                m &= m - 1;
            }
            cur = next;
        }
        last & b.accept != 0
    }

    /// The general simulation (Pike VM without captures), for patterns too large for [`Bits`].
    pub(crate) fn pike_match(&self, s: &str) -> bool {
        let n = self.insts.len();
        let mut cur = Sparse::new(n);
        let mut next = Sparse::new(n);
        let mut stack = Vec::new();
        cur.add(self, 0, true, s.is_empty(), &mut stack);
        for (i, c) in s.char_indices() {
            if cur.dense.is_empty() {
                return false;
            }
            let at_end = i + c.len_utf8() == s.len();
            next.clear();
            for &pc in &cur.dense {
                if self.consumes(self.insts[pc as usize], c) {
                    next.add(self, pc + 1, false, at_end, &mut stack);
                }
            }
            std::mem::swap(&mut cur, &mut next);
        }
        cur.contains((n - 1) as u32)
    }
}

/// A sparse set of instruction indexes (Briggs-Torczon).
struct Sparse {
    dense: Vec<u32>,
    sparse: Vec<u32>,
}

impl Sparse {
    fn new(n: usize) -> Sparse {
        Sparse {
            dense: Vec::with_capacity(n),
            sparse: vec![0; n],
        }
    }

    fn contains(&self, pc: u32) -> bool {
        let i = self.sparse[pc as usize] as usize;
        i < self.dense.len() && self.dense[i] == pc
    }

    fn clear(&mut self) {
        self.dense.clear();
    }

    /// Adds `pc` and everything reachable from it without consuming.
    fn add(&mut self, re: &Regex, pc: u32, at_start: bool, at_end: bool, stack: &mut Vec<u32>) {
        stack.clear();
        stack.push(pc);
        while let Some(pc) = stack.pop() {
            if self.contains(pc) {
                continue;
            }
            self.sparse[pc as usize] = self.dense.len() as u32;
            self.dense.push(pc);
            match re.insts[pc as usize] {
                Inst::Jmp(x) => stack.push(x),
                Inst::Split(a, b) => {
                    stack.push(b);
                    stack.push(a);
                }
                Inst::Start if at_start => stack.push(pc + 1),
                Inst::End if at_end => stack.push(pc + 1),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(p: &str, s: &str) -> bool {
        let re = Regex::new(p).unwrap_or_else(|e| panic!("{p}: {e}"));
        let fast = re.is_match(s);
        assert_eq!(fast, re.pike_match(s), "engines disagree on {p:?} / {s:?}");
        fast
    }

    #[test]
    fn matches_whole_inputs() {
        let yes = [
            ("[0-9]+", "42"),
            ("\\d{4}-\\d{2}", "2026-11"),
            ("0x[0-9a-f]+", "0x1f"),
            ("a|bc|", ""),
            ("a|bc|", "bc"),
            ("(?:ab)*c", "ababc"),
            ("(?P<x>a)(?<y>b)", "ab"),
            ("[^/]+", "héllo"),
            ("é+.", "éé\u{1F600}"),
            (".", "x"),
            ("[]a]+", "]a]"),
            ("[a-]+", "-a"),
            ("[-a]", "-"),
            ("[\\w-]+", "a_b-9"),
            ("\\W\\S\\D", "/x/"),
            ("\\s", "\t"),
            ("a{2,3}", "aaa"),
            ("a{2,}", "aaaaaa"),
            ("a{0}b", "b"),
            ("(a*)*b", "aab"),
            ("^ab$", "ab"),
            ("a^?b", "ab"),
            ("\\x41\\x{42}\\u0043\\u{44}\\U00000045", "ABCDE"),
            ("\\.\\-\\/\\ ", ".-/ "),
            ("a**", "aa"),
            ("a+?b??", "a"),
            ("a}", "a}"),
            ("]", "]"),
            ("[^\\n]", "x"),
            ("x{ 2 , 3 }", "xx"),
            ("x{\t2,\t3}", "xx"),
            ("[a-b-c]+", "a-cb"),
            ("(|a)+", "aa"),
            ("[\\x{1F600}-\\x{1F64F}]", "\u{1F610}"),
        ];
        for (p, s) in yes {
            assert!(m(p, s), "{p:?} should match {s:?}");
        }
        let no = [
            ("[0-9]+", "42x"),
            ("[0-9]+", ""),
            ("\\d{4}-\\d{2}", "2026-1"),
            (".", "\n"),
            (".", "ab"),
            ("a{2,3}", "aaaa"),
            ("a{2,3}", "a"),
            ("[^/]+", "a/b"),
            ("a$b", "ab"),
            ("a^b", "ab"),
            ("\\d", "\u{0663}"), // ASCII digits only
            ("(?:ab)*c", "abac"),
            ("[^a-z]", "q"),
            ("[]a]", ""),
        ];
        for (p, s) in no {
            assert!(!m(p, s), "{p:?} should not match {s:?}");
        }
    }

    #[test]
    fn unsupported_syntax_is_a_compile_error() {
        for p in [
            "a{",
            "a{,5}",
            "{",
            "?",
            "*a",
            "a{3,2}",
            "a{1001}",
            "(a",
            "a)",
            "[a",
            "[]",
            "[^]",
            "[z-a]",
            "[\\d-z]",
            "[a-\\d]",
            "(?i)a",
            "(?P<1>a)",
            "(?<>a)",
            "\\b",
            "\\B",
            "\\A",
            "\\z",
            "\\<",
            "\\>",
            "\\p{L}",
            "\\1",
            "\\0",
            "\\e",
            "\\x{D800}",
            "\\x{110000}",
            "\\xZ",
            "[[:alpha:]]",
            "[a&&b]",
            "[a--b]",
            "[a~~b]",
            "[[a]]",
            "\\",
            "(?)",
            "\\x{123456789}",
        ] {
            assert!(Regex::new(p).is_err(), "{p:?} should not compile");
        }
        let e = Regex::new("ab(?i)c").unwrap_err();
        assert_eq!((e.pos, e.msg), (4, "group flags are not supported"));
        assert_eq!(e.to_string(), "group flags are not supported at byte 4");
        assert!(
            Regex::new("(((((((((((((((((((((((((((((((((a)))))))))))))))))))))))))))))))))")
                .is_ok()
        );
        assert!(Regex::new(&"(".repeat(100)).is_err());
        assert_eq!(
            Regex::new("(a{1000}){1000}").unwrap_err().msg,
            "pattern too large"
        );
    }

    #[test]
    fn large_patterns_use_the_general_engine() {
        let re = Regex::new("[a-c]{70}x|y{3,100}").unwrap();
        assert!(re.bits.is_none());
        assert!(re.is_match(&format!("{}x", "abc".repeat(23) + "a")));
        assert!(!re.is_match(&"abc".repeat(24)));
        assert!(re.is_match("yyyy"));
        assert!(!re.is_match("yy"));
        // Linear time: a pathological pattern for backtracking engines.
        let re = Regex::new("(a|aa)*(a|aa)*(a|aa)*b{0,60}c").unwrap();
        assert!(!re.is_match(&"a".repeat(5000)));
    }

    #[test]
    fn engines_agree_on_small_patterns() {
        let pats = [
            "a*b?c+",
            "(a|b)*c",
            "[^a]*a",
            "^a*$",
            "(a$|b)c?",
            "(^|x)y",
            "a{2,4}b{0,2}",
            "(ab|a)(bc|c)",
            ".*\\d",
            "(?:\\w+-)*\\w+",
            "",
        ];
        let inputs = [
            "", "a", "b", "c", "ab", "abc", "aab", "xy", "y", "aaaab", "a-b-c", "é9", "ac",
        ];
        for p in pats {
            for s in inputs {
                m(p, s);
            }
        }
    }
}

/// Old engine error messages for syntax `akio-regex` supports (ADR-051: the router accepts a
/// superset): flags, `\b \B \A \z`, Unicode / dotted group names, programs of 10 000 to 20 000
/// instructions.
const SUPERSET: &[&str] = &[
    "group flags are not supported",
    "unsupported escape (assertions, Unicode classes and backreferences are not supported)",
    "invalid group name",
    "pattern too large",
];

/// Compiles `pattern` with the old engine and with the router's `akio-regex` matcher and checks
/// they agree: the router must accept every pattern the old engine accepted (except two groups
/// with the same name, which the `regex` crate refuses too), may accept more ([`SUPERSET`]),
/// and must match every subject the same way. Returns how many subjects matched, if both
/// compiled.
pub(crate) fn check_agreement<'a>(
    pattern: &str,
    subjects: impl Iterator<Item = &'a str>,
) -> Option<usize> {
    let old = Regex::new(pattern);
    let new = crate::router::Matcher::compile(pattern);
    let (old, new) = match (old, new) {
        (Ok(o), Ok(n)) => (o, n),
        (Err(_), Err(_)) => return None,
        (Ok(_), Err(e)) => {
            assert_eq!(
                e.message(),
                "duplicate group name",
                "the old engine compiled {pattern:?}, akio-regex refused it: {e}"
            );
            return None;
        }
        (Err(e), Ok(_)) => {
            assert!(
                SUPERSET.contains(&e.msg),
                "akio-regex compiled {pattern:?}, the old engine refused it: {e}"
            );
            return None;
        }
    };
    let mut matched = 0;
    for s in subjects {
        let want = old.is_match(s);
        assert_eq!(want, old.pike_match(s), "old engines: {pattern:?} / {s:?}");
        assert_eq!(new.is_match(s), want, "pattern {pattern:?}, subject {s:?}");
        matched += usize::from(want);
    }
    Some(matched)
}

#[cfg(test)]
mod differential {
    use super::check_agreement;

    /// xorshift64*: deterministic, no dependencies.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }

        fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
            &v[self.below(v.len())]
        }
    }

    /// Characters subjects are made of: ASCII digits, letters and punctuation, controls the
    /// classes tell apart, and non-ASCII digits, letters and spaces (where Unicode and ASCII
    /// `\d \w \s` differ).
    const ALPHABET: &[char] = &[
        'a',
        'b',
        'c',
        'x',
        'z',
        'A',
        'B',
        'Z',
        '0',
        '1',
        '5',
        '9',
        '-',
        '_',
        '.',
        '~',
        '%',
        '/',
        ' ',
        '\t',
        '\n',
        '\r',
        '\x0b',
        '\x0c',
        '\x00',
        '}',
        ']',
        '^',
        '$',
        'é',
        'É',
        'ß',
        '中',
        '\u{0663}',
        '\u{ff10}',
        '\u{00a0}',
        '\u{3000}',
        '\u{212a}',
        '\u{1F600}',
        '\u{10FFFF}',
    ];

    /// A generated pattern: its text and how to make texts it matches.
    enum G {
        /// Pattern text and the characters it may consume (one each).
        One(String, Vec<char>),
        Start,
        End,
        Cat(Vec<G>),
        Alt(Vec<G>),
        Rep(Box<G>, u32, Option<u32>, bool),
        Group(Box<G>, &'static str),
    }

    const ONES: &[(&str, &str)] = &[
        ("a", "a"),
        ("b", "b"),
        ("0", "0"),
        ("-", "-"),
        ("é", "é"),
        ("中", "中"),
        (".", "a0-é中 \t"),
        ("\\d", "0159"),
        ("\\D", "a-é\u{0663}"),
        ("\\w", "aZ0_"),
        ("\\W", "-.é中 "),
        ("\\s", " \t\n\r\x0b\x0c"),
        ("\\S", "a0é\u{3000}"),
        ("[a-c]", "abc"),
        ("[^/]", "a0-é."),
        ("[0-9]", "059"),
        ("[\\w-]", "a_-9"),
        ("[^\\d]", "a-é\u{0663}"),
        ("[\\s\\d]", " 9\t"),
        ("[]a]", "]a"),
        ("[a-]", "a-"),
        ("[^a-z0-9]", "A-é"),
        ("[0-9a-fA-F]", "0aF"),
        ("\\.", "."),
        ("\\-", "-"),
        ("\\x41", "A"),
        ("\\u{e9}", "é"),
        ("\\x{1F600}", "\u{1F600}"),
        ("[\\x{1F600}-\\x{1F64F}]", "\u{1F600}"),
        ("\\t", "\t"),
        ("\\n", "\n"),
        ("[\\n]", "\n"),
    ];

    fn generate(r: &mut Rng, depth: u32) -> G {
        let leaf = depth == 0 || r.below(3) == 0;
        if leaf {
            return match r.below(20) {
                0 => G::Start,
                1 => G::End,
                _ => {
                    let &(p, cs) = r.pick(ONES);
                    G::One(p.to_owned(), cs.chars().collect())
                }
            };
        }
        match r.below(5) {
            0 | 1 => G::Cat((0..=r.below(4)).map(|_| generate(r, depth - 1)).collect()),
            2 => G::Alt(
                (0..2 + r.below(2))
                    .map(|_| generate(r, depth - 1))
                    .collect(),
            ),
            3 => {
                let (min, max) = *r.pick(&[
                    (0, None),
                    (1, None),
                    (0, Some(1)),
                    (2, Some(2)),
                    (1, Some(3)),
                    (2, None),
                    (0, Some(0)),
                ]);
                G::Rep(Box::new(generate(r, depth - 1)), min, max, r.below(4) == 0)
            }
            _ => {
                let kind = *r.pick(&["(", "(?:", "(?P<n>", "(?<n>"]);
                G::Group(Box::new(generate(r, depth - 1)), kind)
            }
        }
    }

    fn render(g: &G, out: &mut String) {
        match g {
            G::One(p, _) => out.push_str(p),
            G::Start => out.push('^'),
            G::End => out.push('$'),
            G::Cat(v) => v.iter().for_each(|g| render(g, out)),
            G::Alt(v) => {
                // Alternation binds loosest: group it so it stays one item.
                out.push_str("(?:");
                for (i, g) in v.iter().enumerate() {
                    if i > 0 {
                        out.push('|');
                    }
                    render(g, out);
                }
                out.push(')');
            }
            G::Rep(g, min, max, lazy) => {
                out.push_str("(?:");
                render(g, out);
                out.push(')');
                match (min, max) {
                    (0, None) => out.push('*'),
                    (1, None) => out.push('+'),
                    (0, Some(1)) => out.push('?'),
                    (m, None) => out.push_str(&format!("{{{m},}}")),
                    (m, Some(n)) if m == n => out.push_str(&format!("{{{m}}}")),
                    (m, Some(n)) => out.push_str(&format!("{{{m},{n}}}")),
                }
                if *lazy {
                    out.push('?');
                }
            }
            G::Group(g, kind) => {
                // Unique names: the old engine accepted duplicates, akio-regex refuses them.
                let kind = kind.replace('n', &format!("n{}", out.len()));
                out.push_str(&kind);
                render(g, out);
                out.push(')');
            }
        }
    }

    /// A text the pattern probably matches (assertions are skipped, so not always).
    fn sample(g: &G, r: &mut Rng, out: &mut String) {
        match g {
            G::One(_, cs) => out.push(*r.pick(cs)),
            G::Start | G::End => {}
            G::Cat(v) => v.iter().for_each(|g| sample(g, r, out)),
            G::Alt(v) => sample(r.pick(v), r, out),
            G::Rep(g, min, max, _) => {
                let n = min + r.below((max.unwrap_or(min + 3) - min + 1) as usize) as u32;
                (0..n).for_each(|_| sample(g, r, out));
            }
            G::Group(g, _) => sample(g, r, out),
        }
    }

    /// Near misses: one character dropped, replaced or inserted.
    fn mutate(s: &str, r: &mut Rng) -> String {
        let mut v: Vec<char> = s.chars().collect();
        let at = r.below(v.len() + 1);
        match r.below(3) {
            0 if at < v.len() => {
                v.remove(at);
            }
            1 if at < v.len() => v[at] = *r.pick(ALPHABET),
            _ => v.insert(at, *r.pick(ALPHABET)),
        }
        v.into_iter().collect()
    }

    fn random_text(r: &mut Rng) -> String {
        (0..r.below(10)).map(|_| *r.pick(ALPHABET)).collect()
    }

    /// Every regexp route pattern in the repository's tests, examples and docs, the old
    /// engine's own unit test patterns and the codec benchmark's.
    const REPO: &[&str] = &[
        "[0-9]+",
        "[0-9",
        "[{]+",
        "\\d{2}",
        "[a-z]{2,3}",
        "\\d{4}-\\d{2}",
        "\\d{4}-\\d{2}-\\d{2}",
        ".+",
        "0x[0-9a-f]+",
        "v[0-9]+",
        "re",
        "regexp",
        "[a-z0-9_-]{3,16}",
        "[a-z0-9_-]{1,39}",
        "[A-Za-z0-9_.-]+",
        "[0-9a-f]{7,40}",
        "[a-z][a-z0-9_]{2,15}",
        "[a-z0-9_-]+\\.(?:png|jpe?g|gif)",
        "\\w+",
        "0x[0-9a-fA-F]+",
        "0x[0-9a-f]+",
        "a|bc|",
        "(?:ab)*c",
        "(?P<x>a)(?<y>b)",
        "[^/]+",
        "é+.",
        ".",
        "[]a]+",
        "[a-]+",
        "[-a]",
        "[\\w-]+",
        "\\W\\S\\D",
        "\\s",
        "a{2,3}",
        "a{2,}",
        "a{0}b",
        "(a*)*b",
        "^ab$",
        "a^?b",
        "\\x41\\x{42}\\u0043\\u{44}\\U00000045",
        "\\.\\-\\/\\ ",
        "a**",
        "a+?b??",
        "a}",
        "]",
        "[^\\n]",
        "x{ 2 , 3 }",
        "x{\t2,\t3}",
        "[a-b-c]+",
        "(|a)+",
        "[\\x{1F600}-\\x{1F64F}]",
        "\\d",
        "a$b",
        "a^b",
        "[^a-z]",
        "[]a]",
        "a*b?c+",
        "(a|b)*c",
        "[^a]*a",
        "^a*$",
        "(a$|b)c?",
        "(^|x)y",
        "a{2,4}b{0,2}",
        "(ab|a)(bc|c)",
        ".*\\d",
        "(?:\\w+-)*\\w+",
        "",
        "[a-c]{70}x|y{3,100}",
        "(a|aa)*(a|aa)*(a|aa)*b{0,60}c",
        // Rejected by both, or only by the old engine (the documented superset).
        "a{",
        "a{,5}",
        "{",
        "?",
        "*a",
        "a{3,2}",
        "a{1001}",
        "(a",
        "a)",
        "[a",
        "[]",
        "[^]",
        "[z-a]",
        "[\\d-z]",
        "[a-\\d]",
        "(?i)a",
        "(?P<1>a)",
        "(?<>a)",
        "\\b",
        "\\B",
        "\\A",
        "\\z",
        "\\<",
        "\\>",
        "\\p{L}",
        "\\1",
        "\\0",
        "\\e",
        "\\x{D800}",
        "\\x{110000}",
        "\\xZ",
        "[[:alpha:]]",
        "[a&&b]",
        "[a--b]",
        "[a~~b]",
        "[[a]]",
        "\\",
        "(?)",
        "\\x{123456789}",
        "(a{1000}){1000}",
        "(a{1000}){15}",
        "(?P<a.b>x)",
        "(?<é>x)",
    ];

    /// Subjects for a pattern: samples of it, near misses and random text.
    fn subjects(g: Option<&G>, r: &mut Rng) -> Vec<String> {
        let mut v = vec![String::new()];
        for _ in 0..12 {
            let s = match g {
                Some(g) => {
                    let mut s = String::new();
                    sample(g, r, &mut s);
                    s
                }
                None => random_text(r),
            };
            v.push(mutate(&s, r));
            v.push(s);
        }
        for _ in 0..6 {
            v.push(random_text(r));
        }
        v
    }

    #[test]
    fn repository_patterns_agree() {
        let mut r = Rng(0x0123_4567_89ab_cdef);
        let mut texts: Vec<String> = ALPHABET.iter().map(char::to_string).collect();
        texts.extend((0..300).map(|_| random_text(&mut r)));
        texts.extend(
            [
                "1234567",
                "2026-11",
                "2026-11-19",
                "0x1f",
                "v12",
                "ab",
                "ababc",
                "abc",
                "ok",
                "re",
                "regexp",
                "a.png",
                "a/b.png",
                "photo.jpeg",
                "abcdef0",
                "octocat_42",
            ]
            .map(String::from),
        );
        let (mut both, mut matched) = (0, 0);
        for p in REPO {
            if let Some(n) = check_agreement(p, texts.iter().map(String::as_str)) {
                both += 1;
                matched += n;
            }
        }
        assert!(
            both >= 60,
            "only {both} patterns compiled with both engines"
        );
        assert!(matched > 1000, "only {matched} matches");
    }

    #[test]
    #[cfg_attr(miri, ignore = "thousands of patterns: hours under Miri")]
    fn generated_patterns_agree() {
        let mut r = Rng(0x5eed_0f0b_1a5e_d00d);
        let (mut both, mut cases, mut matched) = (0, 0, 0);
        for _ in 0..3000 {
            let g = generate(&mut r, 4);
            let mut p = String::new();
            render(&g, &mut p);
            let subjects = subjects(Some(&g), &mut r);
            cases += subjects.len();
            if let Some(n) = check_agreement(&p, subjects.iter().map(String::as_str)) {
                both += 1;
                matched += n;
            }
        }
        assert!(both > 2900, "only {both} generated patterns compiled");
        // Both outcomes are well represented.
        assert!(cases > 90_000 && matched > cases / 5 && matched < cases * 4 / 5);
    }

    #[test]
    #[cfg_attr(miri, ignore = "thousands of patterns: hours under Miri")]
    fn random_syntax_agrees() {
        // Pattern soup: mostly invalid, exercises which patterns each engine accepts.
        const SOUP: &[&str] = &[
            "a", "é", "0", "-", ".", "^", "$", "|", "(", ")", "(?:", "(?P<n>", "(?<n>", "(?", "[",
            "]", "[^", "\\", "\\d", "\\w", "\\s", "\\b", "\\x", "\\u{", "{", "}", "{2}", "{1,3}",
            ",", "*", "+", "?", "a-z", "0-9", "&&", "--", ":", "<", ">", "P", "i", "1", " ",
        ];
        let mut r = Rng(0xfeed_beef_cafe_f00d);
        let mut both = 0;
        for _ in 0..20_000 {
            let p: String = (0..=r.below(8)).map(|_| *r.pick(SOUP)).collect();
            let subjects = subjects(None, &mut r);
            both += usize::from(check_agreement(&p, subjects.iter().map(String::as_str)).is_some());
        }
        assert!(both > 1000, "only {both} soup patterns compiled");
    }
}
