# akio-regex

[中文](README.zh-CN.md)

A small regular expression engine for [`akio`](https://github.com/lesismal/akio), in safe Rust
(`#![forbid(unsafe_code)]`) without dependencies. Matching time is linear in the input whatever
the pattern. It is the engine behind `akio-log`'s env_logger-style message filters
(`AKIO_LOG=info/connection (reset|refused)`) and `akio-http`'s route constraints
(`/users/{id:[0-9]+}`, ADR-051). An internal crate (docs/api-stability.md): use it through
`akio-log` and `akio-http`.

- Does the pattern occur anywhere in this text? `Regex::is_match(&str)`, and
  `Regex::is_match_fmt(format_args!(..))`, which matches the pieces as they are formatted, with
  no string built and no allocation.
- Where, and what the groups hold (ADR-115): `find`, `find_at`, `find_iter`, `captures`
  (`Captures::get`, `name`, `range`), with the leftmost-first semantics of Go's `regexp` and the
  `regex` crate, on a capturing Pike VM in linear time; `expand` and `replace_all` with Go's
  template rules (`$1`, `${name}`, `$$`), as `Regexp.Expand` and `ReplaceAllString`.
- `RegexBuilder` options: `whole_text(true)` matches the whole text only (as `\A(?:...)\z`), and
  `ascii_classes(true)` makes `\d \w \s` and `\b` ASCII. The router uses both.
- The syntax is a subset of the `regex` crate's, with the same meaning: literals, `.`, classes with
  ranges and negation, Unicode-aware `\d \w \s` (and `\D \W \S`), repetition `* + ? {m,n}`,
  greedy or lazy, alternation, groups (capturing, named, non-capturing), `^ $ \A \z`,
  `\b \B` (Unicode word boundaries), flags `(?i)` (Unicode simple case folding), `(?m)`, `(?s)`
  and `(?U)`, negated (`(?-i)`) and scoped (`(?i:...)`). Unicode classes (`\p{..}`),
  backreferences, look-around and the `u` / `x` / `R` flags are compile errors that say so.
- Engine: a Thompson NFA. A pattern that is a plain literal is searched with `str::contains`.
  Otherwise a DFA is built when the regex is compiled (up to 2048 states, over character classes
  that no instruction tells apart: a table for ASCII, intervals for everything else), so a search
  costs one class lookup and one table load per character. A transition outside the DFA is taken
  by a Pike VM from the state's thread set, using per-thread working memory kept between searches,
  and the search goes back to the DFA as soon as it reaches a known state. There is no
  backtracking: `(a*)*b` on 100 000 `a`s takes linear time.
- The Unicode tables (`\w`, `\d`, `\s`, simple case folding) are generated from regex-syntax by
  `tools/regex-tables`, so the differential fuzz target `regex_search` compares the two engines
  on the same Unicode data.

```rust
use akio_regex::Regex;

let re = Regex::new(r"(?i)\bconn(ection)? (reset|refused)\b").unwrap();
assert!(re.is_match("peer 10.0.0.7: Connection reset by peer"));
assert!(!re.is_match("connections reset: 0"));
let peer = "10.0.0.7";
assert!(re.is_match_fmt(format_args!("{peer}: conn refused")));
```

## Cost

`cargo run --release --manifest-path tools/codec-bench/Cargo.toml logregex` compares it with the
`regex` crate on an 86-byte log message (see docs/BENCHMARKS.md for the figures from the
benchmark host). The DFA runs at about one nanosecond per character on ASCII and non-ASCII text
alike; a literal pattern is a `str::contains` (6.8 ns against `regex`'s 12.3 ns there). The
`regex` crate is several times faster on alternations of literals and on `\b` (it has SIMD
literal search and a lazy DFA over bytes), and slower on case-insensitive alternations (69 against
86 ns). Compiling takes 15-100 µs (building the DFA up front), the most for patterns with `\b`,
which add the Unicode word boundaries to the character classes.
