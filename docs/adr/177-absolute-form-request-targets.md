# ADR-177: Request targets in absolute form, taken as an origin server takes them

English | [简体中文](177-absolute-form-request-targets.zh-CN.md)

Status: accepted (2026-11-26). akit's A200.

## Context

An HTTP/1.1 request may name its target in absolute form, `GET http://a.example/admin/x?q
HTTP/1.1`. RFC 9112 §3.2.2 has an origin server accept it, take the target's authority as the
request's host and ignore `Host`; Go's server does (`r.URL.Path` is `/admin/x`, `r.Host`
`a.example`), and so does fit. akio's HTTP/1 server copied the target as it was: `Request::path()`
was `http://a.example/admin/x` and `Host` stayed what the field said. A router that goes by the
path, akio-http's or akit's, took the request for no path it knew, while a proxy that sends its
upstream the origin form asks for `/admin/x`. akit's fuzzing (I77) found a request spelled so
that missed a route protecting `/admin/*` and reached its upstream through a catch-all route;
akit rewrites such targets in its listener meanwhile.

The server also took any other target a request line could hold: `GET a.example:443` (authority
form, `CONNECT`'s), `GET admin/x`, `GET *`.

## Decision

1. **HTTP/1: a target in absolute form is taken by its path and query.** The head parser
   recognises `scheme "://" authority path-abempty ["?" query]` (RFC 3986 §3; any scheme) and
   gives `Request::target` its origin form: `/admin/x?q`, `/` for an empty path (`http://a?q` is
   `/?q`). The authority's host and port, without user information (`a.example:8080` of
   `http://u:p@a.example:8080/x`), replace the `Host` field, as RFC 9112 §3.2.2 asks.
   `Request::path()`, `query()`, the router, middleware and services see an ordinary request.
2. **`Request::raw_target()`** gives the target as sent: the absolute form for such a request,
   `target` for any other. The access log (`observe::access_log`) writes it. It is kept in a
   private `Option<Box<str>>` field of `Request`, allocated only for a target in absolute form.
3. **`Host` is still checked as RFC 9112 §3.2 asks, before it is replaced:** an HTTP/1.1 request
   without one, or any request with more than one, is answered 400 whatever its target. HTTP/1.0
   needs none; the target's authority becomes its `Host` all the same.
4. **Only the forms RFC 9112 §3.2 defines are taken.** Origin form for every method, absolute form
   for every method but `CONNECT`, `*` for `OPTIONS` alone, and any target for `CONNECT` (its
   authority form is the service's to check, as before). Anything else, authority form for another
   method included, and an absolute form whose host is empty (RFC 9110 §4.2.1) or holds a byte RFC
   3986 does not allow in a host and port, is answered 400 and the connection closed.
5. **HTTP/2 and HTTP/3: `:path` is in origin form, or `*` for `OPTIONS`.** `:authority` and
   `:path` already come apart, so there is nothing to split; RFC 9113 §8.3.1 and RFC 9114 §4.3.1
   give `:path` the origin form for `http` and `https` (or `*` for `OPTIONS`). A request whose
   `:path` is anything else, an absolute URI included, is malformed: the HTTP/2 server resets the
   stream with `PROTOCOL_ERROR`, the HTTP/3 server refuses it as it refuses other malformed
   requests. The check applies whatever the `:scheme`: akio's servers are origin servers for
   `http` and `https`, and a path that is not one would reach the router as the HTTP/1 target
   did. An extended CONNECT's `:path` is in origin form too.

## Consequences

- A request in absolute form takes the route of its path, with its target's host: what akit's
  listener rewrote, akio does, and akit's stopgap can go (its `RouterRequest::host` override
  included, since `Host` is replaced).
- An application that read the absolute form from `Request::target` reads it from
  `raw_target()`. One that relied on `Host` over the target's authority now sees the authority.
- Requests in a form an origin server cannot take (authority form but for `CONNECT`, a relative
  path, `*` but for `OPTIONS`) are refused where they were routed by a target that is not a path.
- Cost: a request in origin form pays one byte test on its target (`/`) and 16 bytes more in
  `Request`; only one in absolute form pays a split and an allocation. The parser is on the hot
  path (rule 16); the same-run A/B of pipelined HTTP/1 requests is left to a benchmark task
  (rule 20), with no change expected.
- Tests: parse unit tests (`absolute_form_parts`, `request_target_forms`), the router test
  `absolute_form_targets_are_routed_by_their_path` (tests/http.rs), HTTP/2 (`h2_frames.rs`
  `malformed_requests_are_reset`) and HTTP/3 (`request_heads`) cases, and the `http1_request`
  fuzz target's invariant that a parsed target is a path, `*` for `OPTIONS` or a `CONNECT`'s, with
  two seeds.
