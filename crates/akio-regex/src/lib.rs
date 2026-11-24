#![forbid(unsafe_code)]
#![warn(clippy::unwrap_used)]
//! A small regular expression engine in safe Rust, without dependencies, whose matching time
//! is linear in the input whatever the pattern: a Thompson NFA run by a Pike VM, with a DFA
//! built ahead of time. It answers *does the pattern occur anywhere in this text*
//! ([`Regex::is_match`]), also for text that is being formatted ([`Regex::is_match_fmt`]: nothing
//! is allocated), and *where, and what do its groups hold* ([`Regex::find`],
//! [`Regex::captures`]), with Go's template rules to build text from a match ([`Regex::expand`],
//! [`Regex::replace_all`]). `akio-log` uses it for env_logger-style message filters
//! (`AKIO_LOG=info/connection (reset|refused)`).
//!
//! An internal crate of [`akio`](https://github.com/lesismal/akio) (docs/api-stability.md).
//!
//! ```
//! use akio_regex::Regex;
//!
//! let re = Regex::new(r"(?i)\bconn(ection)? (reset|refused)\b").unwrap();
//! assert!(re.is_match("peer 10.0.0.7: Connection reset by peer"));
//! assert!(!re.is_match("connections reset: 0"));
//! let peer = "10.0.0.7";
//! assert!(re.is_match_fmt(format_args!("{peer}: conn refused")));
//! ```
//!
//! # Syntax
//!
//! A subset of the `regex` crate's, with the same meaning (the differential fuzz target checks
//! it against that crate):
//!
//! * literals (any Unicode scalar value); `.` (any character but `\n`);
//! * classes `[a-z0-9_]`, `[^/]`, with ranges, negation, escapes and Perl classes inside; a `]`
//!   first in the class and a `-` first or last are literal;
//! * `\d` (Unicode decimal digits), `\w` (Unicode word characters), `\s` (Unicode white space)
//!   and their negations `\D \W \S`; escapes `\n \t \r \f \v \a`, `\xHH`, `\x{H...}`, `\uHHHH`,
//!   `\u{H...}`, `\UHHHHHHHH`, `\U{H...}` and any escaped ASCII punctuation;
//! * capturing groups `(...)`, `(?P<name>...)`, `(?<name>...)` (at most 1000), non-capturing
//!   `(?:...)`, alternation `|`, repetition `*` `+` `?` `{m}` `{m,}` `{m,n}` (counts up to 1000),
//!   greedy or lazy (`*?`; laziness changes where a match ends, not whether a text matches);
//! * assertions `^` and `\A` (start of the text), `$` and `\z` (end of the text), `\b` and `\B`
//!   (Unicode word boundary and its negation);
//! * flags `(?i)` (case-insensitive, Unicode simple case folding), `(?m)` (`^` and `$` also
//!   match after and before `\n`), `(?s)` (`.` matches `\n`), `(?U)` (greedy and lazy swapped), with
//!   negation (`(?-i)`) and scoped forms (`(?i:...)`); a `(?flags)` group applies to the rest of
//!   the enclosing group.
//!
//! Everything else is a compile error naming what is not supported: Unicode classes (`\p{L}`),
//! backreferences, look-around, POSIX and nested classes (`[[:alpha:]]`), class set operations
//! (`&&`, `--`, `~~`), the flags `u`, `x` and `R`, and special word boundaries (`\<`, `\b{start}`).
//!
//! [`RegexBuilder`] has two options: `ascii_classes` (`\d \w \s` and `\b` are ASCII) and
//! `whole_text` (the pattern must match the whole text, as if written `\A(?:...)\z`).
//! `akio-http`'s router compiles its route constraints (`{id:[0-9]+}`) with both.
//!
//! # Cost
//!
//! Compiling builds the NFA program (at most 20 000 instructions) and, for programs of at most
//! 4096 instructions, up to 2048 DFA states. The DFA's alphabet is the set of character classes
//! no instruction or assertion tells apart (a table for ASCII, sorted intervals for the rest), so
//! a search costs one class lookup and one table load per character, ASCII or not, and allocates
//! nothing. A pattern that is plain literal text is searched with `str::contains`. A transition
//! the DFA did not build is stepped on the NFA (time proportional to the program size), with
//! per-thread working memory kept between searches, and the search returns to the DFA as soon as
//! it reaches a state the DFA has. There is no backtracking: `(a*)*b` on a million `a`s takes
//! linear time.
//!
//! # Matches and groups
//!
//! [`find`](Regex::find), [`captures`](Regex::captures) and the functions built on them return
//! the leftmost-first match, as Go's `regexp` and the `regex` crate do: the match that starts
//! first, and among those the one the pattern prefers (the left alternative, more of a greedy
//! repetition, less of a lazy one). They run a Pike VM with capture slots over a second program
//! (the same pattern with an instruction saving each group's bounds), in time linear in the
//! text times the program's size, with per-thread working memory kept between searches. A search
//! from the start of a text that does not match costs a DFA pass ([`is_match`](Regex::is_match));
//! a literal pattern is found with `str::find`.
//!
//! ```
//! use akio_regex::Regex;
//!
//! let re = Regex::new(r"^/old/(?P<id>[0-9]+)(/.*)?$").unwrap();
//! let path = "/old/42/edit";
//! let caps = re.captures(path).unwrap();
//! assert_eq!(caps.get(1), Some(5..7));
//! assert_eq!(caps.name("id").map(|r| &path[r]), Some("42"));
//! let mut to = String::new();
//! re.expand(&caps, "/new/${id}$2", path, &mut to);
//! assert_eq!(to, "/new/42/edit");
//! assert_eq!(Regex::new("a+").unwrap().replace_all("baaac", "<$0>"), "b<aaa>c");
//! ```

use std::{borrow::Cow, error, fmt, ops::Range, str::FromStr, sync::Arc};

mod exec;
mod parse;
mod pike;
#[rustfmt::skip]
mod tables;

/// A pattern that does not compile: what is wrong and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pos: usize,
    msg: &'static str,
}

impl Error {
    /// The byte offset in the pattern where the problem was found.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// What is wrong.
    pub fn message(&self) -> &'static str {
        self.msg
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.msg, self.pos)
    }
}

impl error::Error for Error {}

/// A compiled pattern. Cloning is cheap (the program is shared); two `Regex`es are equal when
/// their patterns are the same text compiled with the same [`RegexBuilder`] options.
#[derive(Clone)]
pub struct Regex {
    pattern: Arc<str>,
    opts: parse::Options,
    prog: Arc<exec::Prog>,
}

/// Compile options: [`RegexBuilder::new`], then the options, then [`build`](RegexBuilder::build).
/// [`Regex::new`] is `RegexBuilder::new(pattern).build()`.
///
/// ```
/// use akio_regex::RegexBuilder;
///
/// // A route constraint: the whole segment, ASCII digits.
/// let re = RegexBuilder::new(r"\d{4}").whole_text(true).ascii_classes(true).build().unwrap();
/// assert!(re.is_match("2026"));
/// assert!(!re.is_match("x2026"));
/// assert!(!re.is_match("٢٠٢٦")); // Arabic-Indic digits are not ASCII
/// ```
#[derive(Clone, Debug)]
pub struct RegexBuilder {
    pattern: String,
    opts: parse::Options,
}

impl RegexBuilder {
    /// Options for `pattern`, all off.
    pub fn new(pattern: &str) -> RegexBuilder {
        RegexBuilder {
            pattern: pattern.to_owned(),
            opts: parse::Options::default(),
        }
    }

    /// `\d \w \s` and their negations mean `[0-9]`, `[0-9A-Za-z_]` and `[\t\n\x0B\x0C\r ]`,
    /// and `\b \B` see ASCII word characters only (off: Unicode, as in the `regex` crate). The
    /// rest of the syntax is unchanged: literals, classes and `.` still match any Unicode
    /// character, and `(?i)` still folds Unicode case.
    pub fn ascii_classes(&mut self, yes: bool) -> &mut RegexBuilder {
        self.opts.ascii = yes;
        self
    }

    /// The pattern matches the whole text or nothing, as if written `\A(?:pattern)\z` (off: it
    /// matches anywhere in the text).
    pub fn whole_text(&mut self, yes: bool) -> &mut RegexBuilder {
        self.opts.whole = yes;
        self
    }

    /// Compiles the pattern (see the crate documentation for the syntax).
    pub fn build(&self) -> Result<Regex, Error> {
        let parsed = parse::parse(&self.pattern, self.opts)?;
        Ok(Regex {
            pattern: self.pattern.as_str().into(),
            opts: self.opts,
            prog: Arc::new(exec::Prog::new(parsed)?),
        })
    }
}

impl Regex {
    /// Compiles `pattern` (see the crate documentation for the syntax), with the default options
    /// (an unanchored search, Unicode classes).
    pub fn new(pattern: &str) -> Result<Regex, Error> {
        RegexBuilder::new(pattern).build()
    }

    /// The pattern this was compiled from.
    pub fn as_str(&self) -> &str {
        &self.pattern
    }

    /// Whether the pattern matches anywhere in `text` (the whole of `text` with
    /// [`RegexBuilder::whole_text`]).
    #[inline]
    pub fn is_match(&self, text: &str) -> bool {
        match self.prog.literal() {
            Some((lit, true)) => return text == lit,
            Some((lit, false)) => return text.contains(lit),
            None => {}
        }
        if let Some(m) = self.prog.dfa_match(text) {
            return m;
        }
        let mut s = self.prog.start();
        s.feed(text);
        s.finish()
    }

    /// [`is_match`](Regex::is_match) on the text `args` formats to, without collecting it into a
    /// string: the pieces are matched as they are written. Formatting goes on to the
    /// end once the outcome is known (only matching stops), so `Display` impls never see an
    /// error they did not cause.
    pub fn is_match_fmt(&self, args: fmt::Arguments<'_>) -> bool {
        if let Some(s) = args.as_str() {
            return self.is_match(s);
        }
        let mut s = Feed(self.prog.start());
        if s.0.done().is_none() {
            let _ = fmt::write(&mut s, args);
        }
        s.0.finish()
    }

    /// The leftmost-first match in `text`: its byte range.
    pub fn find(&self, text: &str) -> Option<Range<usize>> {
        self.find_at(text, 0)
    }

    /// The leftmost-first match in `text` that starts at `start` or later. Assertions see the
    /// text before `start` (`^` and `\A` still mean the start of `text`, `\b` looks at the
    /// character before `start`). `None` when `start` is past the end or not a character
    /// boundary.
    pub fn find_at(&self, text: &str, start: usize) -> Option<Range<usize>> {
        if !text.is_char_boundary(start) {
            return None;
        }
        match self.prog.literal() {
            Some((lit, false)) => {
                let i = text.get(start..)?.find(lit)?;
                let s = start.checked_add(i)?;
                return Some(s..s.checked_add(lit.len())?);
            }
            Some((lit, true)) => return (start == 0 && text == lit).then_some(0..text.len()),
            None => {}
        }
        if start == 0 && !self.is_match(text) {
            return None;
        }
        let mut slots = [pike::NONE; 2];
        if !pike::search(&self.prog, text, start, &mut slots) {
            return None;
        }
        Some(slots[0]..slots[1])
    }

    /// Every successive match in `text`, as Go's `FindAllString` finds them: after each match
    /// the search goes on from its end, and an empty match right where the previous one ended
    /// is skipped.
    pub fn find_iter<'r, 't>(&'r self, text: &'t str) -> FindIter<'r, 't> {
        FindIter {
            re: self,
            text,
            pos: 0,
            prev_end: None,
        }
    }

    /// The leftmost-first match in `text` and what each group holds.
    pub fn captures(&self, text: &str) -> Option<Captures> {
        self.captures_at(text, 0)
    }

    /// [`captures`](Regex::captures) of the match [`find_at`](Regex::find_at) finds.
    pub fn captures_at(&self, text: &str, start: usize) -> Option<Captures> {
        if !text.is_char_boundary(start) || (start == 0 && !self.is_match(text)) {
            return None;
        }
        let mut slots = vec![pike::NONE; self.captures_len().saturating_mul(2)];
        if !pike::search(&self.prog, text, start, &mut slots) {
            return None;
        }
        Some(Captures {
            slots: slots.into(),
            names: Arc::clone(&self.prog.names),
        })
    }

    /// The number of groups, the whole match (group 0) included.
    pub fn captures_len(&self) -> usize {
        self.prog.names.len()
    }

    /// The name of each group, by number: `None` for group 0 and for unnamed groups.
    pub fn group_names(&self) -> impl ExactSizeIterator<Item = Option<&str>> + '_ {
        self.prog.names.iter().map(|n| n.as_deref())
    }

    /// Appends `template` to `out` with the groups of `caps` (a match in `text`) put in, by Go's
    /// `Regexp.Expand` rules: `$1` or `${1}` is group 1, `$name` or `${name}` the group of that
    /// name, the name being the longest run of letters, digits and `_` (so `$1x` is the group
    /// named `1x`, and `${1}x` is group 1 then `x`); `$$` is a `$`. A group that does not exist
    /// or took no part is empty, and a `$` not followed by a valid name is itself. A non-ASCII
    /// character counts as a letter when it is alphabetic (Go: when it is in a Unicode letter
    /// category) and as a digit when `\d` matches it.
    pub fn expand(&self, caps: &Captures, template: &str, text: &str, out: &mut String) {
        let mut t = template;
        while let Some(i) = t.find('$') {
            out.push_str(&t[..i]);
            t = &t[i + 1..];
            if let Some(rest) = t.strip_prefix('$') {
                out.push('$');
                t = rest;
                continue;
            }
            let Some((name, num, rest)) = extract(t) else {
                out.push('$');
                continue;
            };
            t = rest;
            let range = match num {
                Some(k) => caps.get(k),
                None => caps.name(name),
            };
            if let Some(s) = range.and_then(|r| text.get(r)) {
                out.push_str(s);
            }
        }
        out.push_str(t);
    }

    /// `text` with every match replaced by `template` expanded ([`expand`](Regex::expand)), as
    /// Go's `ReplaceAllString`: an empty match right after a match is not replaced, and the
    /// search always moves on by at least one character. Borrowed when nothing matched.
    pub fn replace_all<'t>(&self, text: &'t str, template: &str) -> Cow<'t, str> {
        let mut out = String::new();
        let mut last = 0;
        let mut pos = 0;
        let mut any = false;
        while pos <= text.len() {
            let Some(caps) = self.captures_at(text, pos) else {
                break;
            };
            let m = caps.range();
            any = true;
            out.push_str(text.get(last..m.start).unwrap_or(""));
            if m.end > last || m.start == 0 {
                self.expand(&caps, template, text, &mut out);
            }
            last = m.end;
            let width = text
                .get(pos..)
                .and_then(|s| s.chars().next())
                .map_or(0, char::len_utf8);
            pos = if pos + width > m.end {
                pos + width
            } else if pos + 1 > m.end {
                pos + 1
            } else {
                m.end
            };
        }
        if !any {
            return Cow::Borrowed(text);
        }
        out.push_str(text.get(last..).unwrap_or(""));
        Cow::Owned(out)
    }

    /// Runs the NFA alone (no DFA): the fuzz target compares the two.
    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn nfa_is_match(&self, text: &str) -> bool {
        exec::Search::nfa_only(&self.prog, text)
    }
}

/// A group's name or number after a `$` in a template (Go's `extract`): the name, its number
/// when it is a number without a leading zero, and the rest of the template.
fn extract(t: &str) -> Option<(&str, Option<usize>, &str)> {
    let (brace, s) = match t.strip_prefix('{') {
        Some(s) => (true, s),
        None => (false, t),
    };
    let end = s
        .char_indices()
        .find(|&(_, c)| !(c == '_' || is_letter(c) || is_digit(c)))
        .map_or(s.len(), |(i, _)| i);
    if end == 0 {
        return None;
    }
    let name = &s[..end];
    let rest = if brace {
        s[end..].strip_prefix('}')?
    } else {
        &s[end..]
    };
    let mut num = Some(0usize);
    for b in name.bytes() {
        num = match num {
            Some(n) if b.is_ascii_digit() && n < 100_000_000 => {
                Some(n * 10 + usize::from(b - b'0'))
            }
            _ => None,
        };
    }
    if name.len() > 1 && name.starts_with('0') {
        num = None;
    }
    Some((name, num, rest))
}

/// A letter, for a group name in a template.
fn is_letter(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_alphabetic()
    } else {
        c.is_alphabetic()
    }
}

/// A decimal digit (Unicode `Nd`, as `\d`), for a group name in a template.
fn is_digit(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_digit()
    } else {
        parse::in_ranges(tables::DIGIT, c as u32)
    }
}

/// The successive matches in a text: [`Regex::find_iter`].
#[derive(Debug)]
pub struct FindIter<'r, 't> {
    re: &'r Regex,
    text: &'t str,
    pos: usize,
    prev_end: Option<usize>,
}

impl Iterator for FindIter<'_, '_> {
    type Item = Range<usize>;

    fn next(&mut self) -> Option<Range<usize>> {
        while self.pos <= self.text.len() {
            let m = self.re.find_at(self.text, self.pos)?;
            let mut accept = true;
            if m.end == self.pos {
                // An empty match: not right where the previous match ended, and the search
                // moves on by a character.
                if Some(m.start) == self.prev_end {
                    accept = false;
                }
                self.pos += self
                    .text
                    .get(self.pos..)
                    .and_then(|s| s.chars().next())
                    .map_or(1, char::len_utf8);
            } else {
                self.pos = m.end;
            }
            self.prev_end = Some(m.end);
            if accept {
                return Some(m);
            }
        }
        None
    }
}

/// What the groups of a match hold: [`Regex::captures`]. Group 0 is the whole match.
#[derive(Clone, PartialEq, Eq)]
pub struct Captures {
    /// Start and end of each group, `pike::NONE` where it took no part.
    slots: Box<[usize]>,
    names: Arc<[Option<Box<str>>]>,
}

impl Captures {
    /// The byte range of the whole match.
    pub fn range(&self) -> Range<usize> {
        self.get(0).unwrap_or(0..0)
    }

    /// The byte range group `i` matched; `None` when there is no such group or it took no part
    /// in the match.
    pub fn get(&self, i: usize) -> Option<Range<usize>> {
        let k = i.checked_mul(2)?;
        let s = *self.slots.get(k)?;
        let e = *self.slots.get(k.checked_add(1)?)?;
        (s != pike::NONE && e != pike::NONE).then_some(s..e)
    }

    /// The byte range the group named `name` matched.
    pub fn name(&self, name: &str) -> Option<Range<usize>> {
        let i = self.names.iter().position(|n| n.as_deref() == Some(name))?;
        self.get(i)
    }

    /// The number of groups, the whole match (group 0) included.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.names.len()
    }
}

impl fmt::Debug for Captures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut l = f.debug_list();
        for i in 0..self.len() {
            l.entry(&self.get(i));
        }
        l.finish()
    }
}

/// Matches what is written to it.
struct Feed<'p>(exec::Search<'p>);

impl fmt::Write for Feed<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.0.done().is_none() {
            self.0.feed(s);
        }
        Ok(())
    }
}

impl fmt::Debug for Regex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Regex").field(&self.as_str()).finish()
    }
}

impl fmt::Display for Regex {
    /// The pattern.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialEq for Regex {
    fn eq(&self, other: &Regex) -> bool {
        self.as_str() == other.as_str() && self.opts == other.opts
    }
}

impl Eq for Regex {}

impl FromStr for Regex {
    type Err = Error;

    fn from_str(s: &str) -> Result<Regex, Error> {
        Regex::new(s)
    }
}

#[cfg(test)]
mod tests {
    use std::{fmt::Write as _, time::Instant};

    use super::*;

    /// Matches `s` every way there is and checks they agree.
    fn m(p: &str, s: &str) -> bool {
        let re = Regex::new(p).unwrap_or_else(|e| panic!("{p}: {e}"));
        let fast = re.is_match(s);
        assert_eq!(
            fast,
            exec::Search::nfa_only(&re.prog, s),
            "DFA and NFA disagree on {p:?} / {s:?}"
        );
        assert_eq!(
            fast,
            re.is_match_fmt(format_args!("{s}{}", "")),
            "fmt disagrees on {p:?} / {s:?}"
        );
        // Split into single characters.
        let mut search = re.prog.start();
        for c in s.chars() {
            search.feed(c.encode_utf8(&mut [0; 4]));
        }
        assert_eq!(fast, search.finish(), "pieces disagree on {p:?} / {s:?}");
        fast
    }

    #[test]
    fn searches() {
        let yes = [
            ("abc", "xxabcxx"),
            ("", ""),
            ("", "abc"),
            ("a*", "bbb"),
            ("^abc", "abcdef"),
            ("def$", "abcdef"),
            ("^$", ""),
            ("[0-9]+ms", "took 15ms"),
            ("\\d{4}-\\d{2}", "on 2026-11-19"),
            ("a|bc|d", "xxbcx"),
            ("(?:ab)*c", "c"),
            ("(?P<x>a)(?<y>b)", "zab"),
            ("[^/]+", "/héllo"),
            ("é+.", "xéé\u{1F600}"),
            ("[]a]+", "]"),
            ("[a-]+", "-"),
            ("[\\w-]+", "a_b-9"),
            ("\\s", "a\tb"),
            ("a{2,3}", "aaaa"),
            ("(a*)*b", "aab"),
            ("\\x41\\x{42}\\u0043\\u{44}\\U00000045", "ABCDE"),
            ("\\bfoo\\b", "a foo b"),
            ("\\bfoo\\b", "foo"),
            ("\\Boo", "foo"),
            ("\\b", "x"),
            ("\\B", ""),
            ("\\B", "  "),
            ("\\d", "\u{0663}"),          // Arabic-Indic digit three
            ("\\w+", "\u{4e2d}\u{6587}"), // CJK
            ("\\bé", "é"),
            ("\\s", "\u{3000}"),
            ("(?i)hello", "HeLLo world"),
            ("(?i)k", "\u{212a}"), // Kelvin sign
            ("(?i)\u{212a}", "k"),
            ("(?i)ſ", "S"),
            ("(?i)[a-c]+", "xBCx"),
            ("(?i)[^a]", "b"),
            ("(?i:a)B", "aB"),
            ("a(?i)b|c", "C"),
            ("(?i)a(?-i)b", "Ab"),
            ("(?m)^b$", "a\nb\nc"),
            ("(?m)$", "a"),
            ("(?m)^", "a\n"),
            ("(?s)a.b", "a\nb"),
            ("\\Aab\\z", "ab"),
            ("(?U)a+", "a"),
            ("a+?b??", "a"),
            ("x{ 2 , 3 }", "xx"),
            ("[\\x{1F600}-\\x{1F64F}]", "\u{1F610}"),
            ("(|a)+", "aa"),
            ("^*a", "a"),
        ];
        for (p, s) in yes {
            assert!(m(p, s), "{p:?} should match {s:?}");
        }
        let no = [
            ("abc", "abd"),
            ("^abc", "xabc"),
            ("abc$", "abcx"),
            ("^$", "a"),
            (".", "\n"),
            ("a.b", "a\nb"),
            ("[^/]+", "///"),
            ("\\bfoo\\b", "foobar"),
            ("\\bfoo\\b", "afoo"),
            ("\\Boo\\B", "foo"),
            ("\\b", ""),
            ("\\b", "  "),
            ("\\bé", "aé"),
            ("hello", "HELLO"),
            ("(?i)[^a]", "A"),
            ("(?i:a)B", "Ab"),
            ("(?i)a(?-i)b", "AB"),
            ("^b$", "a\nb\nc"),
            ("(?m)^b$", "a\nbc"),
            ("\\Aab\\z", "ab\n"),
            ("\\d", "x"),
            ("\\w", "-"),
            ("\\S", " \t"),
            ("[0-9]+", ""),
            ("a{3}", "aa"),
        ];
        for (p, s) in no {
            assert!(!m(p, s), "{p:?} should not match {s:?}");
        }
    }

    /// Like `m`, with the options: every way of matching must agree.
    fn mo(p: &str, ascii: bool, whole: bool, s: &str) -> bool {
        let re = RegexBuilder::new(p)
            .ascii_classes(ascii)
            .whole_text(whole)
            .build()
            .unwrap_or_else(|e| panic!("{p}: {e}"));
        let fast = re.is_match(s);
        assert_eq!(
            fast,
            exec::Search::nfa_only(&re.prog, s),
            "NFA: {p:?} / {s:?}"
        );
        assert_eq!(
            fast,
            re.is_match_fmt(format_args!("{s}{}", "")),
            "fmt: {p:?} / {s:?}"
        );
        fast
    }

    #[test]
    fn options() {
        // whole_text: as if `\A(?:...)\z`.
        for (p, s, want) in [
            ("abc", "abc", true),
            ("abc", "xabc", false),
            ("abc", "abcx", false),
            ("", "", true),
            ("", "a", false),
            ("a|bc|", "", true),
            ("a|bc|", "bc", true),
            ("a|bc", "abc", false),
            ("[0-9]+", "42", true),
            ("[0-9]+", "42x", false),
            ("a*", "bbb", false),
            ("^a$|b", "b", true),
            ("a$b", "ab", false),
            ("(?m)a$", "a\n", false),
            ("é+.", "éé\u{1F600}", true),
            ("[^/]+", "a/b", false),
        ] {
            assert_eq!(mo(p, false, true, s), want, "whole {p:?} / {s:?}");
            // An unanchored search finds at least what a whole match does.
            if want {
                assert!(mo(p, false, false, s), "search {p:?} / {s:?}");
            }
        }
        // ascii_classes: `\d \w \s` and `\b` are ASCII.
        for (p, s, ascii, unicode) in [
            ("\\d", "\u{0663}", false, true),
            ("\\d", "7", true, true),
            ("\\D", "\u{0663}", true, false),
            ("\\w", "é", false, true),
            ("\\W", "é", true, false),
            ("[\\w-]+", "a_b-9", true, true),
            ("[^\\w]", "中", true, false),
            ("\\s", "\u{3000}", false, true),
            ("\\s", "\x0b", true, true),
            ("\\S", "\u{3000}", true, false),
            ("\\bé", "é", false, true),
            ("a\\bé", "aé", true, false),
            ("a\\Bé", "aé", false, true),
            ("(?i)k", "\u{212a}", true, true), // case folding stays Unicode
        ] {
            assert_eq!(mo(p, true, true, s), ascii, "ascii {p:?} / {s:?}");
            assert_eq!(mo(p, false, true, s), unicode, "unicode {p:?} / {s:?}");
        }
        // Equality includes the options.
        let mut b = RegexBuilder::new("a+");
        let plain = b.build().unwrap();
        let whole = b.whole_text(true).build().unwrap();
        assert_eq!(plain, Regex::new("a+").unwrap());
        assert_ne!(plain, whole);
        assert_eq!(whole.as_str(), "a+");
        assert!(plain.is_match("baab") && !whole.is_match("baab") && whole.is_match("aa"));
        assert!(RegexBuilder::new("(").whole_text(true).build().is_err());
    }

    #[test]
    fn syntax_errors() {
        for p in [
            "a{",
            "a{,5}",
            "{",
            "?",
            "*a",
            "a|*",
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
            "[\\b]",
            "(?x)a",
            "(?u)a",
            "(?R)a",
            "(?q)a",
            "(?ii)a",
            "(?i-i)a",
            "(?-)a",
            "(?i--m)a",
            "(?)",
            "(?i)*",
            "a(?i)+",
            "(?=a)",
            "(?!a)",
            "(?<=a)",
            "(?<!a)",
            "(?P<1>a)",
            "(?<>a)",
            "(?P<a>x)(?<a>y)",
            "(?P=a)",
            "\\b{start}",
            "\\<",
            "\\>",
            "\\Z",
            "\\p{L}",
            "\\pL",
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
            "\\x{123456789}",
        ] {
            assert!(Regex::new(p).is_err(), "{p:?} should not compile");
        }
        let e = Regex::new("ab(?x)c").unwrap_err();
        assert_eq!(e.position(), 4);
        assert_eq!(
            e.to_string(),
            "unsupported flag (only i, m, s and U are supported) at byte 4"
        );
        assert!(Regex::new(&"(".repeat(100)).is_err());
        assert_eq!(
            Regex::new("(a{1000}){1000}").unwrap_err().message(),
            "pattern too large"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "long inputs: minutes under Miri")]
    fn pathological_patterns_are_linear() {
        let long = "a".repeat(100_000);
        let t = Instant::now();
        for p in [
            "(a*)*b",
            "(a|aa)*(a|aa)*(a|aa)*b{0,60}c",
            "(a+)+$b",
            "(x+x+)+y",
            "(?i)(\\w+\\s?)*$z",
            "a{0,100}a{0,100}b",
        ] {
            let re = Regex::new(p).unwrap();
            assert!(!re.is_match(&long), "{p}");
            assert!(!exec::Search::nfa_only(&re.prog, &long[..20_000]), "{p}");
        }
        // Non-ASCII text runs on the NFA all the way.
        let re = Regex::new("(é*)*b").unwrap();
        assert!(!re.is_match(&"é".repeat(50_000)));
        assert!(
            t.elapsed().as_secs() < 20,
            "took {:?}: not linear",
            t.elapsed()
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "long inputs: minutes under Miri")]
    fn large_patterns_fall_back_to_the_nfa() {
        // Exponentially many DFA states: the DFA stops at its limit and the NFA takes over.
        let re = Regex::new("[ab]*a[ab]{20}c").unwrap();
        assert!(exec::Search::dfa_states(&re.prog).is_some_and(|n| n <= 2048));
        let s = format!("{}a{}c", "ab".repeat(50), "b".repeat(20));
        assert!(m("[ab]*a[ab]{20}c", &s));
        assert!(!m(
            "[ab]*a[ab]{20}c",
            &format!("{}a{}c", "ab".repeat(50), "b".repeat(19))
        ));
        // Too many instructions for a DFA.
        let re = Regex::new("x(?:[a-c]{1000}){5}y").unwrap();
        assert!(exec::Search::dfa_states(&re.prog).is_none());
        assert!(re.is_match(&format!("zx{}y", "abc".repeat(1666) + "ab")));
        assert!(!re.is_match(&format!("zx{}y", "abc".repeat(1666))));
        // Always matching: no DFA, no search.
        let re = Regex::new("a*|b").unwrap();
        assert!(exec::Search::dfa_states(&re.prog).is_none());
        assert!(re.is_match("zzz"));
    }

    #[test]
    fn fmt_matching_does_not_stop_formatting() {
        struct Loud<'a>(&'a std::cell::Cell<usize>);
        impl fmt::Display for Loud<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for _ in 0..3 {
                    self.0.set(self.0.get() + 1);
                    f.write_str("piece ")?;
                }
                Ok(())
            }
        }
        let n = std::cell::Cell::new(0);
        let re = Regex::new("^piece").unwrap();
        assert!(re.is_match_fmt(format_args!("{}", Loud(&n))));
        assert_eq!(n.get(), 3);
        assert!(re.is_match_fmt(format_args!("piece")));
        assert!(!re.is_match_fmt(format_args!("x{}", Loud(&n))));
        // Nested searches (a `Display` that searches itself) each get working memory.
        struct Nested<'a>(&'a Regex);
        impl fmt::Display for Nested<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("é")?;
                let inner = self.0.is_match_fmt(format_args!("{}é", "x"));
                write!(f, "{inner}")
            }
        }
        let re = Regex::new("é+true").unwrap();
        let mut s = String::new();
        write!(s, "{}", Nested(&re)).unwrap();
        assert_eq!(s, "éfalse");
        assert!(re.is_match_fmt(format_args!("{}{}", "é", true)));
        assert!(!re.is_match_fmt(format_args!("{}", Nested(&re))));
    }

    #[test]
    fn api() {
        let re: Regex = "a+b".parse().unwrap();
        assert_eq!(re.as_str(), "a+b");
        assert_eq!(re.to_string(), "a+b");
        assert_eq!(format!("{re:?}"), "Regex(\"a+b\")");
        let copy = re.clone();
        assert_eq!(copy, Regex::new("a+b").unwrap());
        assert_eq!(copy, re);
        assert_ne!(re, Regex::new("a+ b").unwrap());
        fn send_sync<T: Send + Sync>() {}
        send_sync::<Regex>();
        send_sync::<Error>();
    }
}
