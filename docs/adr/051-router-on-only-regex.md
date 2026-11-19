# ADR-051: Route constraints on `only-regex`

English | [简体中文](051-router-on-only-regex.zh-CN.md)

Status: accepted (2026-11-19)

## Context

The workspace had two regex engines. `only_http::re` (DEV-PLAN wave A, ADR-007) matched route
constraints (`{id:[0-9]+}`): a Thompson NFA with a bit-parallel simulation for programs of at
most 64 consuming instructions and a Pike VM above that, whole-segment matching, ASCII `\d \w \s`,
no flags and no assertions but `^ $`. `only-regex` (ADR-047) is the engine behind only-log's
message filters: Unicode classes, `(?i)`, `\b`, an unanchored search, and a DFA built at compile
time. ADR-047 left moving the router onto `only-regex` for later, because the two differ in
anchoring and in what `\d` means, and either difference would change which routes match.

Two engines means two parsers to keep in line with the `regex` crate, two fuzz targets and two
sets of bugs. `only_http::re` was `#[doc(hidden)]` and absent from `api/only-http.txt`: it was
not a public API, so removing it needs no deprecation (docs/deprecation.md covers public items).

## Decision

1. **`only-regex` gains `RegexBuilder`** with two options (`Regex::new(p)` is
   `RegexBuilder::new(p).build()`, unchanged):
   - `whole_text(true)`: the pattern matches the whole text or nothing, as if written
     `\A(?:pattern)\z`. The compiler puts the two assertions around the program; a literal
     pattern compares with `==` instead of `str::contains`.
   - `ascii_classes(true)`: `\d \w \s` and their negations are `[0-9]`, `[0-9A-Za-z_]` and
     `[\t\n\x0B\x0C\r ]`, and `\b \B` see ASCII word characters (non-ASCII characters are not word
     characters). Literals, classes, `.` and `(?i)` keep their Unicode meaning.
   - `Regex` equality now compares the options too.
2. **The router compiles every constraint with both options** (`router::Matcher`), in regexp
   segments and in partial segments alike. Precedence, backtracking, brace handling and the
   registration panics are untouched: only the matcher behind them changed.
3. **Accepted patterns: the old set, plus a documented superset, minus duplicate names.** Every
   pattern the old engine accepted matches exactly the same segments. The router now also
   accepts what `only-regex` supports and the old engine refused: flags `(?i) (?m) (?s) (?U)`
   (negated and scoped), `\A \z \b \B`, group names that are Unicode or contain `.`, `[`, `]`, and
   programs of 10 000 to 20 000 instructions. The one narrowing: two groups with the same name
   (`(?P<a>x)|(?P<a>y)`) are refused at registration, as the `regex` crate refuses them (the old
   engine claimed to be a subset of `regex` and missed this case; nothing is captured, so a name
   never had any effect).
4. **The old engine stays as a test reference.** `only_http::re` is removed from the API and
   from normal builds; its source is kept unchanged as `src/legacy_re.rs`, compiled only for
   tests and the `fuzzing` feature, so that the differential checks below keep running.
5. **A DFA fast path in `only-regex`.** `Regex::is_match` first runs the ahead-of-time DFA in one
   tight loop (one class lookup and one table load per character, no search state) and falls
   back to the full search only on a transition the DFA did not build. Each DFA state row gains
   an end-of-text entry, so ending a search no longer divides to find the state number. This
   also speeds up only-log's message filters.

## Verification

- A differential test (`legacy_re::differential`, run by `cargo test`): every regexp route
  pattern in the repository's tests, examples, docs and benchmarks and the old engine's own unit
  test patterns (accepted and refused), 3 000 generated patterns (literals, Perl classes, classes,
  escapes, `.`, `^ $`, groups, alternation, greedy and lazy counted repetition) with about 30
  subjects each (texts the pattern generates, one-character mutations of them, random text over
  an alphabet of ASCII, controls and non-ASCII digits, letters and spaces), and 20 000 random
  syntax soups. For each pattern: same accept/refuse decision up to point 3, and the same answer
  on every subject. Switching either option off makes it fail.
- The `regex_match` fuzz target now runs the same check on fuzzer input (old engine against the
  router's matcher), then compares the matcher with the `regex` crate (`^(?:pattern)$`, ASCII
  subjects only when the pattern has Perl classes or word boundaries). gpu51: 997 s with 4 workers, 835 000 runs, corpus 11 → 2 607 inputs, no finding.
- Router tests for ASCII `\d` and `\b`, `(?i)` and the duplicate name panic; `only-regex` unit
  tests for both options (DFA, NFA and streamed matching agree).

## Consequences

- Cost (gpu51, CPU 2, same-run A/B under `quiet.sh`, base = main before this change):
  `examples/router-bench.rs`, ns per lookup, medians of the 6 quiet rounds of 10 (in the other 4
  the host slowed down 1.7× for both binaries alike, ratios unchanged): the GitHub table with
  `{id:[0-9]+}` / `{number:[0-9]+}` 28.1 → 28.1, a new table of 8 routes with varied constraints
  (counted repetition, alternation, classes, partial segments) 46.0 → 42.0, the plain and
  partial-segment tables 27.2 → 27.1 and 28.7 → 28.6; 0 allocations everywhere. The engine alone
  (`tools/codec-bench regex`): `[0-9]+` on 7 digits 8.5 → 5.7 ns, `\d{4}-\d{2}-\d{2}` 11.9 → 7.6,
  `[a-z0-9_-]{3,16}` on 14 characters 17.6 → 10.6, `(?:v[0-9]+|latest)` 7.5 → 5.4. Compiling a
  constraint builds the DFA at registration: 7–13 µs instead of 2.1 µs, once per route.
  only-log's message filters gain a few percent from the fast path (`codec-bench logregex`).
- Public API: `only-regex` (internal tier) adds `RegexBuilder` (`new`, `whole_text`,
  `ascii_classes`, `build`). only-http's public API is unchanged; it now depends on `only-regex`
  directly (it already did through only-log, so the dependency graph does not change).
- One engine: syntax fixes and features land once. The old engine's 1 000 lines remain, frozen,
  as long as the differential check is worth its upkeep.
- `tools/codec-bench regex` measures `only-regex` with the router's options against `regex`.
