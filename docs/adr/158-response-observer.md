# ADR-158: A listener's response observer, without an allocation per request

English | [简体中文](158-response-observer.zh-CN.md)

Status: accepted (2026-11-26)

## Context

An access log and request metrics learn of each response on the thread that sends it, which for
a proxied request is the thread its upstream answered on. The only way akio-http offered was a
response filter (`Context::add_response_filter`), a boxed closure: a closure that carries anything
(the start time, a metrics slot, a log shard) costs an allocation per request, which rule 12 keeps
off the hot path. akit's dispatcher registers one for every request (akit's request A29); akio's
own `HttpMetrics` middleware does the same, and clones an `Arc` per request.

## Decision

A per-listener observer, set once, and two words a request carries inline:

```rust
pub trait ResponseObserver: Send + Sync + 'static {
    fn on_response(&self, resp: &Response, req: &Request, words: [u64; 2], started: Instant);
}
impl<S> HttpAcceptor<S> { pub fn observer(self, observer: Arc<dyn ResponseObserver>) -> Self; }
impl Context { pub fn set_observed(&mut self, words: [u64; 2]) -> bool; }
pub fn akio_h3::serve_with_observer(quic, cfg, service, observer) -> QuicServer;
```

- `set_observed` stores the words and `Instant::now()` (of its first call; a later call replaces
  the words) in the request's `Finish`, the part of the context that travels with its response
  (to a `Detached`, a suspended context, a held head's `Going`). `false`, nothing stored, when
  the listener has no observer or the response was already taken.
- The observer runs once per observed request, when its response goes to the connection, on the
  thread that sends it, last in `Finish::apply`: after the response filters, the extra headers,
  the time header and, with held heads (ADR-128), after the outer filters, once the head goes. A
  streamed response is observed when its head goes (its end is `on_end`'s, ADR-127).
- A response sent after its client went (a detached request answered to a closed connection) is
  observed as sent. A request whose response is never sent (its context, `Detached` or
  `Suspended` dropped unanswered; a held head cut) is not: `on_end` (`End::Gone`) hears those,
  at the cost of its hooks.
- HTTP/1.1 and HTTP/2 through `HttpAcceptor::observer`; HTTP/3 through
  `akio_h3::serve_with_observer`, by a new `ConnSink::observer` (default none) that
  `Context::new_ext` asks, so any transport on the `transport` seam can carry one.

**No count every thread shares.** Each connection makes its own handle on the observer when it
opens (`Arc<dyn ResponseObserver>` wrapping the listener's: one allocation per connection, only
with an observer), and each request clones that handle into its `Finish`: the count it bumps is
the connection's, touched by its own thread (and, for a request answered elsewhere, by that
thread), never one all I/O threads write. A request that does not call `set_observed` pays a
clone of the connection's handle and the cost of a `None` check; a listener without an observer
pays nothing.

The HTTP/2 session is now boxed inside the HTTP/1 session (one allocation per HTTP/2
connection): the handles of the connection and of its HTTP/2 driver took an idle HTTP/1
connection past its 256-byte budget (`size_tests`).

**Rejected.** A `Service` method called on the response: the sending thread has the context's
response, not the service. A `'static` observer leaked once per listener: listeners come and go
on a reload. A global registry indexed by the words: a lock or a shared count per response.

## Consequences

- akit's dispatcher sets the route's metrics slot and the log shard as the words, and its
  observer writes the access log line and counts; `Dispatcher::track` goes.
- `Finish` grows by the handle and the words (48 bytes), and a `Context` with it.

## Tests

`crates/akio-http/tests/observer.rs` (HTTP/1.1 and HTTP/2): a response sent inline, detached
(observed on the answering thread, with its duration), with filters and extra headers (seen), a
later `set_observed` replacing the words, streamed (at its head), held (once the head went),
suspended; a request that did not ask and one that asked too late not observed; nothing observed
twice; a response sent after its client went observed, one never sent not; no observer:
`set_observed` is `false`. `crates/akio-http/tests/observer_allocs.rs`: with a counting global
allocator, observed HTTP/1.1 keep-alive requests allocate nothing in the steady state, where a
boxed response filter costs one per request. `crates/akio-h3/tests/observer.rs`: HTTP/3.
