//! Pattern syntax to a tree ([`Node`]), with the flags applied: case folding is done here, so
//! the tree only has characters, classes, `.`, assertions, concatenation, alternation, counted
//! repetition (greedy or lazy, `(?U)` applied) and capturing groups.

use crate::{Error, tables};

/// Largest repetition count in `{m,n}`.
const MAX_REPEAT: u32 = 1000;
/// Deepest group nesting.
const MAX_DEPTH: u32 = 64;
/// Most capturing groups in a pattern.
const MAX_GROUPS: u32 = 1000;

/// A zero-width assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Look {
    /// `^`, `\A`: the start of the input.
    StartText,
    /// `$`, `\z`: the end of the input.
    EndText,
    /// `(?m)^`: the start of the input or after `\n`.
    StartLine,
    /// `(?m)$`: the end of the input or before `\n`.
    EndLine,
    /// `\b`: between a word character and something else (`\w`: Unicode, or ASCII with
    /// [`Options::ascii`]).
    Word,
    /// `\B`: not at a word boundary.
    NotWord,
}

pub(crate) enum Node {
    Empty,
    Char(char),
    /// Index of a class (sorted, merged ranges) in [`Parsed::classes`].
    Class(u32),
    /// `.`: any character but `\n`, or any at all with `nl`.
    Any {
        nl: bool,
    },
    Look(Look),
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    /// `x{min,max}`, greedy or lazy (`(?U)` already applied).
    Repeat {
        node: Box<Node>,
        min: u32,
        max: Option<u32>,
        greedy: bool,
    },
    /// A capturing group: its number (1 for the first `(` of the pattern) and what is inside.
    Group(u32, Box<Node>),
}

/// The parse result: the tree and the classes it refers to.
pub(crate) struct Parsed {
    pub(crate) root: Node,
    /// The options it was parsed with (the compiler applies [`Options::whole`]).
    pub(crate) opts: Options,
    pub(crate) classes: Vec<Box<[(u32, u32)]>>,
    /// The name of each group, by number (group 0, the whole match, has none).
    pub(crate) names: Vec<Option<Box<str>>>,
}

/// Compile options that change what the syntax means.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct Options {
    /// `\d \w \s` (and negations) are ASCII; `\b \B` see ASCII word characters.
    pub(crate) ascii: bool,
    /// The pattern matches the whole text only (`\A(?:...)\z`).
    pub(crate) whole: bool,
}

pub(crate) fn parse(pattern: &str, opts: Options) -> Result<Parsed, Error> {
    let mut p = Parser {
        ascii: opts.ascii,
        chars: pattern.char_indices().collect(),
        len: pattern.len(),
        i: 0,
        depth: 0,
        flags: Flags::default(),
        names: Vec::new(),
        groups: vec![None],
        classes: Vec::new(),
    };
    let root = p.alt()?;
    if p.peek().is_some() {
        return p.err("unmatched `)`");
    }
    Ok(Parsed {
        root,
        opts,
        classes: p.classes,
        names: p.groups,
    })
}

#[derive(Clone, Copy, Default)]
struct Flags {
    /// `i`: case-insensitive.
    i: bool,
    /// `m`: `^` and `$` match at line boundaries.
    m: bool,
    /// `s`: `.` matches `\n`.
    s: bool,
    /// `U`: greedy and lazy repetition swapped.
    u: bool,
}

/// Whether `c` is in the sorted ranges `r`.
pub(crate) fn in_ranges(r: &[(u32, u32)], c: u32) -> bool {
    let i = r.partition_point(|&(_, hi)| hi < c);
    r.get(i).is_some_and(|&(lo, _)| lo <= c)
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

/// The next case variant of `c` (`c` itself when it has none).
fn fold_next(c: u32) -> u32 {
    match tables::FOLD.binary_search_by_key(&c, |&(k, _)| k) {
        Ok(i) => tables::FOLD[i].1,
        Err(_) => c,
    }
}

/// Adds the case variants of every character in `r` (simple case folding).
fn fold(r: &mut Vec<(u32, u32)>) {
    for k in 0..r.len() {
        let (lo, hi) = r[k];
        let start = tables::FOLD.partition_point(|&(c, _)| c < lo);
        for &(c, mut x) in tables::FOLD[start..].iter().take_while(|&&(c, _)| c <= hi) {
            while x != c {
                r.push((x, x));
                x = fold_next(x);
            }
        }
    }
}

/// ASCII `\d`, `\w` and `\s` (`[0-9]`, `[0-9A-Za-z_]`, `[\t\n\x0B\x0C\r ]`).
const ASCII_DIGIT: &[(u32, u32)] = &[(0x30, 0x39)];
const ASCII_WORD: &[(u32, u32)] = &[(0x30, 0x39), (0x41, 0x5a), (0x5f, 0x5f), (0x61, 0x7a)];
const ASCII_SPACE: &[(u32, u32)] = &[(0x09, 0x0d), (0x20, 0x20)];

/// A Perl class (`\d \w \s` and negations): its ranges and whether it is negated.
fn perl_class(c: char, ascii: bool) -> Option<(&'static [(u32, u32)], bool)> {
    let (digit, word, space) = if ascii {
        (ASCII_DIGIT, ASCII_WORD, ASCII_SPACE)
    } else {
        (tables::DIGIT, tables::WORD, tables::SPACE)
    };
    Some(match c {
        'd' => (digit, false),
        'D' => (digit, true),
        'w' => (word, false),
        'W' => (word, true),
        's' => (space, false),
        'S' => (space, true),
        _ => return None,
    })
}

/// What an escape stands for.
enum Escape {
    Char(char),
    Class(&'static [(u32, u32)], bool),
    Look(Look),
}

/// What an atom turned out to be.
enum Atom {
    Node(Node),
    /// A `(?flags)` group: it changes the flags and matches nothing.
    Flags,
}

struct Parser {
    /// [`Options::ascii`].
    ascii: bool,
    chars: Vec<(usize, char)>,
    len: usize,
    i: usize,
    depth: u32,
    flags: Flags,
    /// Group names seen (duplicates are an error, as in the `regex` crate).
    names: Vec<String>,
    /// The name of each capturing group so far, by number (`None` for group 0 and unnamed ones).
    groups: Vec<Option<Box<str>>>,
    classes: Vec<Box<[(u32, u32)]>>,
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

    /// Interns a class (sorted, merged ranges) and returns its node.
    fn class_node(&mut self, r: Vec<(u32, u32)>) -> Node {
        if let Some(i) = self.classes.iter().position(|c| **c == *r) {
            return Node::Class(i as u32);
        }
        self.classes.push(r.into_boxed_slice());
        Node::Class((self.classes.len() - 1) as u32)
    }

    /// A literal, case-folded under `(?i)`.
    fn literal(&mut self, c: char) -> Node {
        if self.flags.i && fold_next(c as u32) != c as u32 {
            let mut r = vec![(c as u32, c as u32)];
            fold(&mut r);
            let r = normalize(r, false);
            return self.class_node(r);
        }
        Node::Char(c)
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
            match self.atom()? {
                Atom::Node(n) => items.push(self.quantifiers(n)?),
                // A quantifier right after it reaches `atom` and is refused there.
                Atom::Flags => {}
            }
        }
        Ok(match items.len() {
            0 => Node::Empty,
            1 => items.pop().unwrap_or(Node::Empty),
            _ => Node::Concat(items),
        })
    }

    fn atom(&mut self) -> Result<Atom, Error> {
        let Some(c) = self.peek() else {
            return self.err("unexpected end of pattern");
        };
        if matches!(c, '*' | '+' | '?' | '{') {
            return self.err("repetition operator missing expression");
        }
        self.i += 1;
        Ok(Atom::Node(match c {
            '.' => Node::Any { nl: self.flags.s },
            '^' => Node::Look(if self.flags.m {
                Look::StartLine
            } else {
                Look::StartText
            }),
            '$' => Node::Look(if self.flags.m {
                Look::EndLine
            } else {
                Look::EndText
            }),
            '(' => return self.group(),
            '[' => self.class()?,
            '\\' => match self.escape(false)? {
                Escape::Char(c) => self.literal(c),
                Escape::Class(r, neg) => {
                    let r = normalize(r.to_vec(), neg);
                    self.class_node(r)
                }
                Escape::Look(l) => Node::Look(l),
            },
            c => self.literal(c),
        }))
    }

    /// Flags after `(?` up to (not including) `:` or `)`.
    fn flags(&mut self) -> Result<Flags, Error> {
        let mut f = self.flags;
        let mut seen: Vec<char> = Vec::new();
        let mut negated = false;
        let mut dangling = false;
        loop {
            let Some(c) = self.peek() else {
                return self.err("unclosed group");
            };
            if c == ':' || c == ')' {
                break;
            }
            if c == '-' {
                if negated {
                    return self.err("repeated negation in flags");
                }
                negated = true;
                dangling = true;
                self.i += 1;
                continue;
            }
            if seen.contains(&c) {
                return self.err("duplicate flag");
            }
            seen.push(c);
            dangling = false;
            match c {
                'i' => f.i = !negated,
                'm' => f.m = !negated,
                's' => f.s = !negated,
                // Swapped greediness.
                'U' => f.u = !negated,
                'u' | 'x' | 'R' => {
                    return self.err("unsupported flag (only i, m, s and U are supported)");
                }
                _ => return self.err("unrecognized flag"),
            }
            self.i += 1;
        }
        if dangling {
            return self.err("expected a flag after `-`");
        }
        if seen.is_empty() && !negated && self.peek() == Some(')') {
            return self.err("repetition operator missing expression");
        }
        Ok(f)
    }

    fn group_name(&mut self) -> Result<String, Error> {
        let start = self.i;
        while let Some(c) = self.peek() {
            if c == '>' {
                break;
            }
            let ok = if self.i == start {
                c == '_' || c.is_alphabetic()
            } else {
                c == '_' || c == '.' || c == '[' || c == ']' || c.is_alphanumeric()
            };
            if !ok {
                return self.err("invalid group name");
            }
            self.i += 1;
        }
        if self.i == start || self.peek() != Some('>') {
            return self.err("invalid group name");
        }
        let name: String = self.chars[start..self.i].iter().map(|&(_, c)| c).collect();
        if self.names.contains(&name) {
            return self.err("duplicate group name");
        }
        self.names.push(name.clone());
        self.i += 1;
        Ok(name)
    }

    /// After a `(`.
    fn group(&mut self) -> Result<Atom, Error> {
        if self.depth >= MAX_DEPTH {
            return self.err("groups nested too deeply");
        }
        let saved = self.flags;
        // The group's number, for a capturing group: taken at its `(`, before the groups inside.
        let mut capture = None;
        if self.eat('?') {
            if self.peek() == Some('<') && matches!(self.peek2(), Some('=' | '!')) {
                return self.err("look-around is not supported");
            }
            if self.eat('<') || (self.peek() == Some('P') && self.peek2() == Some('<')) {
                if self.peek() == Some('P') {
                    self.i += 2;
                }
                let name = self.group_name()?;
                capture = Some(self.new_group(Some(name.into()))?);
            } else {
                let f = self.flags()?;
                if self.eat(')') {
                    // `(?i)`: the flags hold until the end of the enclosing group.
                    self.flags = f;
                    return Ok(Atom::Flags);
                }
                self.i += 1; // `:`
                self.flags = f;
            }
        } else {
            capture = Some(self.new_group(None)?);
        }
        self.depth += 1;
        let inner = self.alt();
        self.depth -= 1;
        self.flags = saved;
        let inner = inner?;
        if !self.eat(')') {
            return self.err("unclosed group");
        }
        Ok(Atom::Node(match capture {
            Some(k) => Node::Group(k, Box::new(inner)),
            None => inner,
        }))
    }

    /// Numbers a new capturing group.
    fn new_group(&mut self, name: Option<Box<str>>) -> Result<u32, Error> {
        let Ok(k) = u32::try_from(self.groups.len()) else {
            return self.err("too many groups");
        };
        if k > MAX_GROUPS {
            return self.err("too many groups");
        }
        self.groups.push(name);
        Ok(k)
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
        if let Some((r, neg)) = perl_class(c, self.ascii) {
            return Ok(Escape::Class(r, neg));
        }
        if !in_class {
            let look = match c {
                'b' | 'B' if self.peek() == Some('{') => {
                    return self.err("special word boundaries (`\\b{...}`) are not supported");
                }
                'b' => Some(Look::Word),
                'B' => Some(Look::NotWord),
                'A' => Some(Look::StartText),
                'z' => Some(Look::EndText),
                _ => None,
            };
            if let Some(l) = look {
                return Ok(Escape::Look(l));
            }
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
                    "unsupported escape (Unicode classes, backreferences and other assertions are not supported)"
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
                    Escape::Look(_) => return self.err("unsupported escape in class"),
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
                            Escape::Class(..) | Escape::Look(_) => {
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
        // Case folding comes before negation: `(?i)[^x]` excludes `X` too.
        if self.flags.i {
            fold(&mut ranges);
        }
        let r = normalize(ranges, negate);
        Ok(self.class_node(r))
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
            // Lazy (`*?`) or, under `(?U)`, greedy: it changes where a match ends and what the
            // groups hold, not whether a text matches.
            let greedy = self.eat('?') == self.flags.u;
            node = Node::Repeat {
                node: Box::new(node),
                min,
                max,
                greedy,
            };
        }
    }
}
