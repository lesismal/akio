# ADR-180: Connection handles, close deadlines and a listener's accept and close hooks

English | [简体中文](180-connection-handles-and-accept-hooks.zh-CN.md)

Status: accepted (2026-11-26). akit's A232.

## Context

fit's console (and, since fit's I161, its Admin API) bounds the connections of clients that have
not logged in: one is closed 5 s after it was accepted, whatever it sends, until a request with a
valid session comes; from then on it is kept for 2 minutes between requests, and put back on the
5 s rule when its session ends. When `max_conns` are open, a new connection closes the oldest
unauthenticated one of the client holding the most, rather than being refused. akit is to do the
same on akio.

akio had the pieces underneath and no way to reach them from there: akio-core's `Conn<H>` can
close a connection and set its own idle timeout (ADR-155) from any thread, but an HTTP handler
gets a `Context`, not the connection, and `Conn<H>` is typed by the protocol's handler, which an
application never names. `Listener::filter` (ADR-099) sees the peer's address only and answers yes
or no, so nothing told an application of each connection accepted, nor of its closing, to keep a
table of them; and nothing closed a connection at a time set in advance whatever it does.

## Decision

1. **`ConnHandle` (akio-core, re-exported by `akio`)**: a cloneable, `Send + Sync` handle to a
   connection without its handler type, on the same `Arc<ConnInner>` as `Conn<H>`: `id`,
   `is_open`, `local_addr`, `peer_addr`, `close`, `set_idle_timeout` (ADR-155's, same backends and
   errors), and a close deadline. Equal and hashed by connection. `Conn::handle()` makes one. Like
   `Conn`, it never touches a recycled descriptor; once the connection is closed its calls do
   nothing or return `Error::Closed`.
2. **A close deadline: `close_at(Instant)`, `close_after(Duration)` and `cancel_close()`.** The
   connection is closed at the deadline whatever it sends, unless the deadline is cancelled or
   replaced first (the last one set is in force). A generation counter on `ConnInner` (8 bytes per
   connection) holds the deadline in force; setting or cancelling one moves it on. Each call
   posts, through `run_on_loop`'s path, a timer on the connection's own I/O thread's wheel (ADR-103;
   the process-wide timer thread if that thread has none) that holds a weak reference and the
   generation it was set with, and closes the connection only if the generation still matches. A
   cancelled timer stays in the wheel until its time and then does nothing: no lock, no
   cancellation across threads, nothing kept alive. A deadline already past closes the connection
   at the loop's next turn.
3. **`Listener::on_accept(Fn(&ConnHandle))` and `Listener::on_close(Fn(&ConnHandle))` (akio).** The
   acceptor of a listener with either is wrapped (`akio_core::hooked`, a `DynAcceptor`) so that
   `on_accept` runs on the connection's I/O thread after the filter and the `max_connections`
   check, before any transport work and the acceptor's `on_open`, and `on_close` after the
   handler's `on_close`. `on_close` comes exactly once for every connection `on_accept` saw: also
   when `on_accept`, `on_open` or the handler's `on_close` panics (the connection is then refused or
   closed as before), and when a backend drops a handler it could not register. Closing is posted
   to the loop, so `on_close` never runs inside a `close` call and `on_accept` may close another
   connection under the table's lock. A listener without hooks keeps its acceptor unwrapped and
   pays nothing; one with `on_close` pays one boxed wrapper per connection.
4. **`Context::connection() -> Option<ConnHandle>` (akio-http)**: the connection a request came on,
   HTTP/1.1 or HTTP/2 (the whole connection, every stream of it), `None` on HTTP/3 (the QUIC
   connection is the transport's) and once the response has been handed off. Taken from the
   context's responder, so a request that does not ask pays nothing; HTTP/2 takes its connection
   lock once.
5. **`HttpConfig`'s timeouts stay as they are.** The connection's own idle timeout runs alongside
   the HTTP head, body and keep-alive timeouts; the shorter closes an idle connection, so an
   application that keeps logged-in connections for 2 minutes sets a keep-alive timeout at least
   that long.

## Consequences

- akit's console and Admin API keep fit's rules: `on_accept` records each connection with its
  client and sets `close_after(5 s)`; a request with a valid session calls `cancel_close` and
  `set_idle_timeout(2 min)`, and the end of the session `close_after(5 s)` again; past `max_conns`,
  `on_accept` closes the oldest unauthenticated connection of the client holding the most;
  `on_close` takes connections out of the table. Its stopgap (the Admin API's bounds on the
  console) goes.
- Tests (akio `conn_handle`, akio-http `connection_handle`, on every backend the suites run): a
  table kept by the hooks, closing from another thread, a deadline that closes a connection that
  keeps sending, a cancelled one, a replaced one, one already past, an idle timeout set through a
  handle, eviction when the table is full, a panicking `on_accept`; over HTTP/1.1 and HTTP/2, a
  login that cancels the deadline and a logout that sets it again.
- Cost: 8 bytes in every `ConnInner`; per `close_at`, one task posted to the loop and one timer.
  Nothing on the read or write path. DEV-PLAN section 4 names what a benchmark task should measure
  (accept rate with hooks and a deadline per connection).
- Not done: a hook given the connection before the filter decides (the filter still answers from
  the address alone); deadlines on HTTP/3 connections.
