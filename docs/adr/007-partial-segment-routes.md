# ADR-007: Partial-segment route patterns

English | [简体中文](007-partial-segment-routes.zh-CN.md)

Status: accepted (2026-11-16)

## Context

`only_http::Router` matched whole segments only: static, `{id:re}`, `:id`/`{id}`, `*rest`.
Routes such as `/{name}.txt`, `/v{version}/x` or `/{owner}/{repo}.git` needed a parameter and a
check in the handler. Adding them touches the pattern syntax and the matching order, both part of
the public behaviour of `Router`.

## Decision

1. **Syntax.** A segment that mixes literal text with `{…}` groups is a *partial segment*:
   `{name}.txt`, `v{major:[0-9]+}.{minor}`, `pre-{mid}-post`. Groups are `{name}` or
   `{name:regexp}`; braces nest inside a group (`\d{4}`), a backslash escapes, braces inside a
   `[…]` class are literal. A wildcard cannot share a segment, two parameters must be separated
   by literal text, and unbalanced braces panic at registration, like other route errors.
2. **Matching, linear and without backtracking inside the segment.** A literal at the start and a
   literal at the end of the segment are matched there. In between, each parameter is non-empty
   and ends at the first occurrence of the literal text that follows it. A regexp parameter must
   also match its whole value. So `{name}.txt` takes `a.b.txt` as `name = a.b`, and
   `{name}.{ext}` takes `a.b.c` as `name = a`, `ext = b.c` (chi's rule). Choosing other split
   points is never tried: lookups stay linear in the path length whatever the pattern.
3. **Precedence.** Partial segments go between static segments and whole-segment regexps:
   **static > partial > regexp > parameter > wildcard**, with backtracking between kinds as
   before. A partial segment has literal text, so it is more specific than a whole-segment
   parameter; it is tried before a regexp because most regexps in route tables are broad
   (`[0-9]+`, `.+`). Among partial segments, the one with more literal text is tried first
   (`{name}.tar.gz` before `{name}.gz`), then registration order. Patterns of the same shape
   (`{a}.txt` and `{b}.txt`) are one node; different names for it panic.
4. **No allocation.** Matching pushes parameter byte ranges as the other kinds do.

## Consequences

- Route tables that only use the old kinds match exactly as before (the router benchmark is
  unchanged, and every old test passes).
- A static segment that contains a `{…}` group is now a pattern, and one with unbalanced braces
  panics. A whole-segment `{…}` whose braces cannot be balanced (a regexp with an unescaped brace
  in an unusual place) keeps its old meaning.
- A route needing a different split (the last `.` instead of the first) uses a regexp parameter
  over the whole segment or checks in the handler.
