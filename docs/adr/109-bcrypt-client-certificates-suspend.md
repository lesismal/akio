# ADR-109: bcrypt, the client's certificate on each request, and requests suspended and resumed

English | [简体中文](109-bcrypt-client-certificates-suspend.zh-CN.md)

Status: accepted (2026-11-24)

## Context

akit, the gateway built on akio, ports fit's `basic_auth` and `client_cert` middleware (its
iteration I42, requests A63, A64 and A65):

- `basic_auth` checks HTTP Basic passwords against bcrypt hashes, as `htpasswd -B` and Go's
  `x/crypto/bcrypt` make them. `akio-crypto` had PBKDF2 and HKDF, not bcrypt (A63).
- `client_cert` lets a request through only when its client sent a certificate the listener's
  TLS verified, and passes its subject on. A server handler had no way to see that certificate:
  `TlsInfo` did not carry it, and a handler sees a `Context`, not the connection (A64).
- A bcrypt check takes milliseconds to tens of milliseconds of CPU, so it cannot run on an I/O
  thread. fit runs it on a small pool while the request waits, then goes on to the next
  middleware and the handler. With akio a middleware could detach the response and answer from
  the pool, but not go on with the chain: the next handler takes a `Context`, and a detached
  request has none. `run_on_pool` moves every request of a listener to the pool, which costs
  every request a hop to save one in many a bcrypt check (A65). ForwardAuth (an authorization
  server asked before the request goes on) needs the same.

## Decision

- **`akio_crypto::bcrypt`**: `Hash::parse` (`$2a$`, `$2b$`, `$2y$`, `$2$`, cost 4 to 31, with a
  `ParseError` saying why not), `Hash::verify` (EksBlowfish, the 23 bytes compared in constant
  time; a password is read to its first 72 bytes, as Go and OpenBSD read it; bits past the salt's
  and hash's bytes ignored, as Go ignores them), `Display` (the hash written back), `hash` (random
  salt, `$2b$`, passwords over 72 bytes refused) and `hash_with_salt`. Blowfish's tables are pi's
  digits, generated and checked against Go's. Blowfish indexes its S-boxes with key-dependent
  bytes, as every bcrypt does; a check's time depends on its cost only.
- **`Request::peer_certificates: Option<Arc<[Vec<u8>]>>`** (akio-http): the chain the client sent
  and the TLS handshake verified, DER, leaf first, set by the HTTP/1.1, HTTP/2 and HTTP/3 servers.
  The sessions ask the transport once the handshake is done (`akio_tls::peer_chain`, which shares
  the chain from then on; `PeerChain::Handshaking` before) and give each request an `Arc`: one
  copy per connection, a reference count per request, and nothing for a connection without a
  certificate. A request that came as TLS 1.3 early data has none: the client's certificate comes
  after it. A resumed session has the chain of the session it resumes (the session state already
  held it). `TlsInfo::peer_certificates` and `akio_quic::Connection::peer_certificates` give it
  too. `Request` and `TlsInfo` are `#[non_exhaustive]`: the fields are additive.
- **`Context::suspend` → `Suspended`**, and **`Suspended::resume(f)`** (akio-http): the context
  moves into the `Suspended` (its request, shared; parameters, locals, response filters and extra
  headers, the responder), the server's own reads as detached, and `resume` runs `f` with it on
  the calling thread, then answers `500` if `f` neither responded nor detached, as a server does
  after `call`. Dropping it unresumed answers `500`. HTTP/1.1 answers keep their order (the
  responder holds the request's place). A resumed context may be suspended again; like a context
  on the pool it cannot take the connection over. **`Context::suspend_to_pool(work)`** runs `work`
  on the logical pool with the suspended request, and answers `503` with `Retry-After: 1` when the
  pool is full, as `detach_to_pool` does.
- A request whose body is **streamed** (`BodyMode::Stream`) cannot be suspended (`None`): the
  server feeds its body to the context after `call`. A service that wants to suspend a request
  with a body asks for it whole (`Service::body_mode`); `run_on_pool` draws the same line.

## Consequences

A gateway can check passwords, certificates and outside authorizations without blocking an I/O
thread and without moving its other requests off it. Additive API. The streamed-body limit of
`suspend` is the one cost: akit's `basic_auth` asks for the body whole (within the listener's
body limit) only for a request whose password it has not checked yet; a later version may let a
suspended request hold its body's reads instead.

## Verification

- `akio-crypto` bcrypt: hashes made by Go (`$2a$`), Apache `htpasswd -B` (`$2y$`) and OpenBSD's
  vector, empty, non-ASCII and NUL-bearing passwords, the 72-byte cut, hashes reproduced from
  their salt, malformed hashes with their reasons.
- `akio-http/tests/peer_certificates.rs`: HTTP/1.1 and HTTP/2 over TLS with and without a client
  certificate, a second (resumed) connection, and in the clear; `akio-h3/tests/peer_certificates.rs`
  over HTTP/3.
- `akio-http/tests/suspend.rs`: suspended requests resumed from the pool and other threads, a
  request suspended twice, locals, filters and headers kept, pipelined HTTP/1.1 answers in order
  (with and without `run_on_pool`), `500` for one dropped or left unanswered, `503` from a full
  pool, a body read whole kept, a streamed body refused, and HTTP/2 streams. On epoll and
  io_uring.
