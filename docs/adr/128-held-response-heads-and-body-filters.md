# ADR-128: Response heads held, and response bodies filtered, by work done elsewhere

English | [简体中文](128-held-response-heads-and-body-filters.zh-CN.md)

Status: accepted (2026-11-25)

## Context

ADR-125 section 5 maps Proxy-Wasm's callbacks onto akio-http's hooks. Its request phase works
with what akio-http has (`Context::suspend`, ADR-109; `Context::req_mut`, ADR-126). Its response
phase does not: `proxy_on_response_headers`, `proxy_on_response_body` and
`proxy_on_response_trailers` must run on the plugin's pool (`akio_wasm::InstancePool`, never on
an I/O thread), and a response filter (`add_response_filter`), a body tap (ADR-116) and a stream
coding (ADR-074, ADR-112) all run where the response is written and decide there. fit had the
same gap with fib and filled it with fib's A41 (`OnHeaderAsync`) and A46 (`OnBodyFilterAsync`);
ADR-125 names their akio versions H1 and H2 (milestone W6), requested by akit as A166 and A167
for I72.

## Decision

Both are built above the transports, in `Context`'s response path: a response's head is settled
there for HTTP/1.1, HTTP/2 and HTTP/3 alike, and a `BodyStream` can be written from any thread,
so one implementation serves the three protocols, whole and streamed bodies, and file bodies.

### Held heads (H1, A166)

`Context::hold_response_head(timeout: Duration, f: impl FnOnce(HeldHead, &Request) + Send)`.

- `f` runs on the thread sending the response, once the ordinary response filters ran and the
  fields of `add_response_header` were added: the head a plugin sees is the one the client would
  get but for the outer filters (ADR-116), which run after it, so a cache in front sees the
  plugin's changes. Several held heads go one after another, in the order they were added.
- `HeldHead` has `status()`, `headers()`, `headers_mut()`, `body()` (a whole body, as the filters
  left it; `None` for a streamed, file or filtered one), `is_live()`, and three ways out, from any
  thread: `resume()` (on to the next held head, or to the client), `respond(Response)` (a local
  response, sent whole in its place after the outer filters: possible because nothing has gone
  yet, unlike fit, which fails it), and `fail()`. Dropped unanswered, it fails.
- Failing cuts the response: the HTTP/1 connection is closed, the HTTP/2 or HTTP/3 stream reset
  (`H2Responder::reset`, and `ConnSink::reset`, a new defaulted method of the doc-hidden transport
  seam that akio-h3 implements), and the request ends `End::Gone` (ADR-127).
- Past `timeout`, the response is cut, as by `fail`; a later answer does nothing (`is_live` says
  so). The timer is akio-http's one timer thread, holding a weak reference.
- Meanwhile a whole response waits whole, and what the handler writes to a streamed one is held,
  counted in its `queued_bytes` (a producer that paces itself on them waits, as for a slow client,
  and `on_drain` runs once the head went and the bytes drained) up to 4 MiB, past which writes
  fail with `Overloaded` and the response is cut.
- A response to `CONNECT` (a tunnel, ADR-113, ADR-122) and an upgrade's go at once, as in fit.

### Body filters (H2, A167)

`Context::add_body_filter(filter: impl BodyFilter)`, with

```rust
pub trait BodyFilter: Send + 'static {
    fn filter(&mut self, chunk: BodyChunk, done: FilterDone);
    fn abort(&mut self) {}
}
pub struct BodyChunk { pub data: Vec<u8>, pub end: bool, pub trailers: Headers }
impl FilterDone { pub fn done(self, data: Vec<u8>, trailers: Headers); pub fn fail(self); }
```

- One call at a time, given everything written since the last; `done`, from any thread, at once
  or later, gives what goes out in its place. What is written meanwhile is held (up to 4 MiB, as
  above) and goes to the next call whole. The last call has `end` set and the body's trailers
  (empty when none), which it may change or add; they follow the body (HTTP/1.1 chunked trailers,
  HTTP/2 and HTTP/3 trailer sections). A filter that holds the body to its end answers the other
  calls with nothing, as the Proxy-Wasm SDK's `http_body` example does.
- The filter is given the body once the head went (after the held heads). Its output goes to the
  next body filter (they run in the order they were added, as response filters do), then through
  the stream coding a response filter set and any body tap, to the client: the coding applies to
  the filter's output, so a plugin sees the identity body even behind `compress`.
- A response sent whole goes as a streamed one: it is marked streamed before the response filters
  run (so `compress` picks a stream coding rather than compressing the whole body, and `etag`
  leaves it), loses `Content-Length`, and its body is given in one last call. A file body is read
  on the disk pool in pieces into the filter, as ADR-124 reads a coded one; nothing is sent with
  `sendfile`. A plugin that only wants headers registers no body filter, and its file bodies keep
  `sendfile`.
- Pacing: the filter's output is written as it comes back; the next call waits while the output
  stream holds more than 256 KiB, until it drains. HTTP/3 refuses a write whole when its send
  buffer is full (`Overloaded`, not taken): the gate keeps it and writes it again once the stream
  drained. Any other failed write cuts.
- Failure: `fail`, a dropped `FilterDone`, the 4 MiB bound, or the handler dropping its stream
  unfinished cuts the response (the stream reset on HTTP/2 and HTTP/3, the connection closed on
  HTTP/1.1, after any head that went) and calls the filter's `abort` once any call under way came
  back, unless the last call was made (even one that failed).
- Not called for a response without a body (to `HEAD`, or `1xx`, `204`, `304`, as filters may
  make it), nor for `CONNECT` or an upgrade: the filter is dropped.

### The done, log and delete callbacks

ADR-127's `on_end` is what they need, and nothing more: the filtered stream's end guard is the
response's own, so `End::Sent` comes after the last call's output was handed to the connection,
and `End::Gone` when the response was cut. The Proxy-Wasm host queues `proxy_on_done`,
`proxy_on_log` and `proxy_on_delete` for the instance from it (`InstancePool::submit_to`), after
any body call still queued there.

### How it is built

A new private module `gate`: a `Gate` is where a body is held while its head is held or a call is
out, with the filter, the bytes pending, and its output (`BodyStream`, possibly another gate).
One thread at a time works on the output, taking it out of the gate's state, so no lock is held
while calling a filter, writing, finishing or registering a drain waiter (whose callback may run
at once). A writer's `on_drain` runs when the gate holds nothing and its output's own drain
callback ran: HTTP/3's means room for more, possibly with bytes still queued, so the gate does not
wait for `queued_bytes` to reach zero there (it would wait forever, re-registering at once).
`BodyStream` gains a fourth inner variant, the writer's side of a gate. `Finish` gains
one boxed field, allocated only by a request that registers a hook; nothing changes for one that
does not (`Session` is unchanged: `size_tests` still pass; `Out` stays 24 bytes).

## Consequences

- akit's I72 can call `proxy_on_response_headers`, `_body` and `_trailers` on its pool, over all
  three protocols, with the guarantees of fit's decision 023 and two it lacked: a local response
  after the head was held, and a filtered file body.
- A filtered response costs a copy of each write into the gate, and a call elsewhere per part of
  the body that arrives while none is under way; a response with a held head only, a whole one,
  costs nothing until it goes.
- A `BodyStream` dropped unfinished on HTTP/3 is still not reset when nothing filters it (the
  transport's `BodySink` has no `Drop`): the cut paths here reset it explicitly
  (`BodySink::reset`). Making a plain drop reset too is left to its own change.
- Not made: filters on request bodies (A75), resuming a body filter's paused output without a
  call (`continue_stream`), and changing a held head's status (`HeldHead::respond` replaces the
  whole response instead).
