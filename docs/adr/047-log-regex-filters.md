# ADR-047: `/regex` message filters in akio-log, on a new internal crate `akio-regex`

English | [简体中文](047-log-regex-filters.zh-CN.md)

Status: accepted (2026-11-19)

## Context

`akio_log::Filter` (ADR-012) parses env_logger-style directives but rejected the `/regex` suffix
(`RUST_LOG=info/connection reset`), which env_logger uses to keep only the records whose message
matches. Users coming from env_logger expect it, and it is the quickest way to cut a noisy debug
log down to one connection or one error.

A regex in a logging path has two risks. A backtracking engine can take exponential time on a
pattern such as `(a*)*b`, which would turn a log call into a stall of an I/O thread (rules.md,
rule 1). And matching must not cost anything when no pattern is set, nor allocate per record
when one is (rule 12).

ADR-005 keeps third-party crates out of the libraries, so the `regex` crate is not an option for
akio-log. The workspace already has one engine, `akio_http::re` (DEV-PLAN wave A, ADR-007): a
Thompson NFA for route constraints. It matches whole segments only (as if anchored), its `\d \w
\s` are ASCII, and it refuses `(?i)` and `\b`. It is private to akio-http, and akio-log is below
akio-http in the dependency graph. A grep of the workspace finds no other pattern matcher: the
router's partial-segment patterns are literal splitting, and nothing else parses regexes.

## Decision

1. **A new internal crate, `akio-regex`** (no dependencies, `#![forbid(unsafe_code)]`, version
   in lockstep, internal tier in docs/api-stability.md): a linear-time engine with a deliberately
   small API: `Regex::new`, `as_str`, `is_match(&str)`, `is_match_fmt(fmt::Arguments)`,
   `FromStr` / `Display` / `Debug` / `Clone` / `Eq` (by pattern text), and `Error` with
   `position()` / `message()`.
   - Syntax: a subset of the `regex` crate's with the same meaning: literals, `.`, classes with
     ranges and negation, Unicode `\d \w \s` and negations, `* + ? {m,n}` greedy and lazy,
     alternation, groups (non-capturing; named groups accepted), `^ $ \A \z \b \B`, and the flags
     `i` (Unicode simple case folding), `m`, `s`, `U`, negated and scoped. Anything else (Unicode
     classes, backreferences, look-around, the `u` / `x` / `R` flags, `\<`, `\b{..}`) is a
     compile error that names it.
   - Engine: the pattern compiles to a Thompson NFA (at most 20 000 instructions). A DFA is
     built at compile time (for programs of at most 4096 instructions; up to 2048 states, a 2 MiB
     table and a work budget), over character classes that no instruction or assertion tells
     apart (a 128-entry table for ASCII, sorted intervals for the rest). A state is the set of
     pending NFA threads plus the category of the previous character (start, `\n`, word,
     other), which is all the assertions need. A transition the DFA did not build is taken by a
     Pike VM from that state's threads, and the search returns to the DFA when it reaches a known
     state. A pattern that is literal text is searched with `str::contains`. Time is linear in
     the input in every case; nothing is allocated per search (the NFA's working memory is kept
     per thread).
   - Unicode data: `\w`, `\d`, `\s` and the case folding orbits are generated from regex-syntax
     (pinned to the version in fuzz/Cargo.lock) by `tools/regex-tables`, its own workspace like
     `tools/codec-bench`, so the differential fuzz target compares engines, not Unicode versions.
2. **akio-log uses it for `/regex`.** `Filter` gains `message_regex(pattern)`,
   `message_pattern()` and `matches(&Record)` (level and message; the message is streamed into
   the matcher with `is_match_fmt`, no string built). The directive parser takes everything after
   the first `/` as the pattern (env_logger rejects a second `/`; here the pattern may contain
   one); an empty pattern means no filter; an invalid one is a `ParseFilterError` whose
   directive is `/pattern` and whose reason carries the regex error and its byte offset.
   `ParseFilterError`'s private `reason` becomes a `Cow<'static, str>`. `Display` writes the
   pattern back, so filters still round-trip. `enabled(metadata)` is unchanged (levels only: a
   logger's `enabled` runs before there is a message). `FmtLogger` matches the message slice of
   the line it already formatted, so a message filter formats nothing twice.
3. **akio-http keeps `akio_http::re` for now** (done since: ADR-051 moved the router onto
   `akio-regex`). Route constraints are anchored and documented as
   ASCII (`\d` = `[0-9]`); switching them to `akio-regex` would change which routes match. A
   later change may move the router onto `akio-regex` with an ASCII mode and the bit-parallel
   matcher; this ADR does not.

## Alternatives

- **The engine inside akio-log** (a private module). Rejected: a regex engine is not a logging
  concern, it would be hard to share with the router later, and a crate of its own gets its own
  fuzz target, README, API snapshot and Miri run without making akio-log's API larger.
- **Move `akio_http::re` down into a shared crate and extend it.** Rejected for this change: its
  whole-match semantics and ASCII classes are part of the router's documented behaviour, and the
  bit-parallel fast path is shaped around anchored matching. Generalising it would change routing
  in the same change as logging.
- **A backtracking engine** (smaller, supports more syntax). Rejected: one pathological pattern in
  `AKIO_LOG` would stall every thread that logs.
- **A lazy DFA** (states built during searches). Rejected for now: `is_match` takes `&self` and
  log calls come from every thread, so the cache would need a lock or per-thread copies. The
  ahead-of-time DFA plus the NFA fallback covers log filters (short patterns) without shared
  mutable state.
- **Format the message into a thread-local `String` and match that.** Rejected: `is_match_fmt`
  matches the pieces as they are written, which needs no buffer and no copy.

## Consequences

- Public API: akio-log adds `Filter::message_regex`, `Filter::message_pattern`,
  `Filter::matches` (additive). `"info/foo".parse::<Filter>()` now succeeds where it was an error.
  akio-regex is a new internal crate (published because akio-log depends on it).
- Cost (gpu51, CPU 2, docs/BENCHMARKS.md): a filter without a pattern is unchanged (an `Option`
  check in `FmtLogger::log`; disabled statements 0.397 ns before and after). With one, `FmtLogger`
  pays one search over the message; `Filter::matches` with `/connection (reset|refused)` on a
  72-byte message costs 107 ns, formatting included (7.1 ns without a pattern). Against the
  `regex` crate on an 86-byte message (`tools/codec-bench logregex`): a literal 6.8 vs 12.3 ns,
  `(?i)CONNECTION (reset|refused)` 69 vs 86 ns, `\b\d+ms\b` 93 vs 33 ns, an alternation of
  literals 93 vs 16 ns (`regex` has SIMD literal search); non-ASCII text runs at the ASCII speed.
  Compiling takes 15-100 µs (most with `\b`); it happens once, when the filter is parsed.
- Verification: unit tests (syntax errors, flags, Unicode classes and folding, assertions,
  pathological patterns on 100 000-character inputs, DFA and NFA agreement, piecewise feeding,
  nested searches from `Display` impls), an end-to-end `AKIO_LOG` test with a message regex, and
  the cargo-fuzz target `regex_search`: whatever akio-regex compiles, the `regex` crate must
  compile and match the same way, on the DFA, the NFA alone and fed in pieces.
- The workspace has two regex engines until the router moves (point 3).
