# ADR-115: Where an `akio-regex` pattern matches, its groups, and Go's templates

English | [简体中文](115-regex-matches-groups-expand.zh-CN.md)

Status: accepted (2026-11-24)

## Context

akit, the gateway built on akio, follows fit, which runs Go's `regexp`. fit's `rewrite`
middleware replaces each match of a regular expression in the request's path (`regexp`,
`replacement` with `$1` and `${name}`), and its `redirect` middleware builds the URL from the
groups of the one match (`"to": "/new/$1"`). akio-regex (ADR-047, ADR-051) answered only whether a
pattern occurs in a text: it parsed groups but captured nothing, and laziness and `(?U)` were
accepted and ignored. akit refused the fields as not supported yet (akit's request A32).

## Decision

1. **Matches and groups on `Regex`**: `find` and `find_at(text, start)` (a byte range),
   `find_iter`, `captures` and `captures_at` (a `Captures`: each group's range by number with
   `get`, by name with `name`, the whole match with `range`), `captures_len` and `group_names`.
   `find_at` and `captures_at` take a start that is not a character boundary, or past the end, as
   no match; assertions see the text before the start (`^` is still the start of the text).
2. **The leftmost-first semantics of Go's `regexp`** (the `regex` crate's too): the match that
   starts first, and among those the one the pattern prefers. The parser now keeps capturing
   groups (`Node::Group`, numbered at their `(`, at most 1000) and each repetition's greediness
   (`*?`, and `(?U)` swapping the two). The compiler emits repetitions in the shapes Go's
   `regexp/syntax` simplifies and compiles them to, because with a sub-expression that can match
   the empty text the shape decides which thread wins: `x{n,}` is `n - 1` copies of `x` then
   `x+`; `x+` loops back after `x`; `x*` is `(x+)?` when `x` can match the empty text
   (golang/go#46123) and a loop before `x` otherwise; `x{n,m}` is `n` copies then nested
   optionals; a repetition of a repetition of the same kind and greediness is one (`x**` is
   `x*`).
3. **A second program for captures.** `Prog` keeps the matching program as it was (the DFA and
   `is_match` are unchanged: laziness changes no answer of theirs) and compiles a capturing one:
   the same pattern with `Save` instructions around every group and around the whole match, and
   each split ordered by priority. Both are bounded by the same 20 000 instructions, so a pattern
   whose groups are repeated past that is refused when compiled ("pattern too large").
4. **A capturing Pike VM** (`pike.rs`): threads in priority order, each with its capture slots
   (a row per instruction, copied when a thread is added; a `Save` is undone after the branch
   that set it has been followed). When the thread of highest priority reaches `Match`, the
   match is kept and the threads after it dropped; a thread starts at each position until a
   match is found. Time is linear in the text times the program's size, whatever the pattern;
   working memory is kept per thread between searches, as the matching VM's is. Before it runs
   from the start of a text, `is_match` (the DFA) rejects a text that does not match; a literal
   pattern is found with `str::find`.
5. **Go's templates**: `expand(caps, template, text, out)` follows `Regexp.Expand`: `$1`,
   `${1}`, `$name`, `${name}` (the name the longest run of letters, digits and `_`, so `$1x` names
   the group `1x`), `$$`; an unknown or unmatched group is empty, a malformed `$` is itself.
   `replace_all(text, template)` is `ReplaceAllString`, empty matches included (one right after a
   match is not replaced), and borrows the text when nothing matched. `find_iter` is
   `FindAllString`'s iteration. One difference: for a template's group name, a non-ASCII
   character counts as a letter when Rust's `char::is_alphabetic` says so (Go asks for a Unicode
   letter category; the two differ on letter numbers and some combining marks) and as a digit when
   `\d` matches it.

## Consequences

- akit's `rewrite` (`regexp`, `replacement`) and `redirect` (groups in `to`) run as fit's, compiled
  when the config is.
- `Regex::new` on a pattern with groups repeated past 20 000 instructions in the capturing program
  now fails where it compiled before; a pattern with more than 1000 groups fails too. Both are
  far beyond what routes and log filters use.
- Compiling builds one more program (about the size of the first plus two instructions per
  group); the DFA is built from the first as before.
- A pattern that is a single group of literal text, `(abc)`, still takes the literal fast path
  for `is_match` and `find`.

## Verification

- `tests/captures.rs`: a table of patterns, texts and templates whose expectations Go 1.27's
  `regexp` printed (`FindStringSubmatchIndex`, `FindAllStringIndex`, `ReplaceAllString`), covering
  empty matches, nullable repetitions (`(a*)*`, `(a*)+`), laziness and `(?U)`, alternation
  priority, unmatched groups, Unicode, `\b`, `(?m)^`, and template edge cases; `expand`'s rules;
  groups and names; `find_at`'s start and assertions; the limits; linear time on pathological
  patterns from a later start (where the DFA does not reject first); searches on several threads.
- An offline differential run against Go's `regexp`: 132 000 (pattern, text, template) cases from
  a random grammar (groups, named groups, alternation, classes, `^ $ \b \B`, `(?i:...)`, greedy
  and lazy counted repetition, `(?U)`): submatch indexes, every match and `ReplaceAllString`
  agreed in every case both engines compiled (akio-regex refuses `\b{...}`, which Go reads as a
  repeated `\b`: the `regex` crate's syntax, unchanged).
- The `regex_search` fuzz target also compares `find`, `find_iter` and `captures`' whole match
  with the `regex` crate.
- `cargo test` of akio-regex, akio-log and akio-http (router), and the workspace suite on Linux
  with epoll and io_uring.
