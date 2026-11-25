# ADR-126: A request changed by a middleware

English | [简体中文](126-request-changed-by-a-middleware.zh-CN.md)

Status: accepted (2026-11-25)

## Context

A gateway's middleware changes the request before the handler sees it: fit's `headers` middleware
sets, adds and removes request fields, its `rewrite` middleware changes the path, ForwardAuth copies
the auth service's fields into the request, JWT adds its claims as fields, and a Proxy-Wasm
plugin's request phase (ADR-125) edits the request's fields and path. akio-http's `Context` gave
its request by shared reference only (`req()`), so akit kept the changed fields in a context local
and the rewritten path in another, and every handler that read the request had to know of both
(akit's request A33).

The request is owned by the context until it is shared: a `Detached` and a WebSocket upgrade take
an `Arc` of it, and `suspend` (ADR-109) moved a shared copy into the resumed context while the
server kept another.

## Decision

`Context::req_mut(&mut self) -> Option<&mut Request>`: the request, to change its fields, target,
method or body. What reads the request afterwards sees the change: `path()`, `header()`, the
handlers after the middleware, `Files`' conditional and range fields, the response filters'
`&Request`.

- `None` once the request is shared: after `detach` (the `Detached` has it) or a WebSocket upgrade.
- `suspend` now moves the request whole into the resumed context, which can change it (a
  ForwardAuth copying fields after its call); the context the server keeps holds an empty request
  and is not asked for it again (it is detached, and is not recycled).
- Route parameters keep reading the path they were matched in: the router's parameters are ranges
  of the path, so the first `req_mut` on a routed request with parameters copies the path into the
  parameters (one allocation, only then). A router matches before its routes' layers run: a target
  changed by one of them does not route the request again, while one changed by a middleware in
  front of the whole router does.
- The request's framing stays the server's: a changed `Content-Length` or `Transfer-Encoding`
  does not change how the rest of its body is read.

`set_target` or `headers_mut` alone were considered: narrower, but a request edit (a Proxy-Wasm
plugin's) may change the method too, and a `&mut Request` costs nothing more to give.

## Consequences

- akit drops its stopgaps: the `headers`, ForwardAuth and JWT middlewares change the request's
  fields in place, `rewrite` its target, and akit-listener's canonical path is the request's target.
- Nothing changes on the hot path: `req_mut` is a match on the owned request, and the parameters'
  copy is made only when a routed request with parameters is changed.

## Tests

`crates/akio-http/tests/req_mut.rs` (HTTP/1.1 and HTTP/2, epoll and io_uring): fields set, added
and removed and the target rewritten in front of a router (which routes the new path), seen by the
handler, `path()`, `header()` and a response filter; the next request on the connection unchanged;
a target changed by a route's layer, its parameters (decoded and raw) still the matched path's;
`None` after `detach`; a resumed suspended request changed. `crates/akio-h3/tests/end_hooks.rs`:
the same rewrite over HTTP/3.
