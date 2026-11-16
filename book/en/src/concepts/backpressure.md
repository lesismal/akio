# Backpressure

`send` never blocks. That makes the I/O thread safe, but it means a fast producer and a slow
consumer will queue data in memory unless something pushes back. `only` pushes back at three
levels.

## 1. Reads pause when a connection's own queue is high

When a connection has at least `Config::write_high_watermark` bytes queued (default 256 KiB),
`only` stops reading from it, and resumes when the queue falls to a quarter of that. A client
that pipelines requests without reading the responses therefore slows itself down instead of
growing the server's memory. Each pause is counted (`only_backpressure_events_total`) and
visible per connection in the connection table.

## 2. `send` fails beyond a hard limit

Beyond `Config::max_queued_bytes` per connection (default 64 MiB), `send*` returns
`Error::Overloaded` and queues nothing (counted in `only_overloaded_total`). Treat it as "this
peer is not keeping up": close it, or drop the message, or stop producing.

Producers that run outside callbacks (a thread streaming a file, a broadcaster) should pace
themselves with `queued_bytes()`, or with `ResponseStream::queued_bytes` /
`BodyStream::queued_bytes` in HTTP, rather than wait for `Overloaded`.

## 3. Relaying: `hold_reads` + `on_drain`

When data flows from connection A to connection B (proxies, tunnels, fan-in), B's queue is what
grows. Stop reading A while B is behind, and resume A when B has drained:

```rust,ignore
{{#include ../../../../crates/only/examples/guide-basics.rs:backpressure}}
```

- `hold_reads(true)` stops reading from the peer (the kernel's receive buffer then fills and TCP
  flow control slows the sender down). `hold_reads(false)` resumes.
- `on_drain(f)` calls `f` once everything queued on that connection has been written, right away
  if nothing is queued, or when it closes. It is one-shot: register it again next time.

- `set_relayed(true)` on **both** ends of the relay. Otherwise the engine also stops reading a
  connection while its *own* output queue is above `Config::write_high_watermark`. In a relay
  that queue holds the other side's data, and a peer that only reads once it can write (an echo
  server, a target that talks first) never drains it while you stop reading: both sides wait for
  each other forever. A relayed connection skips that pause; your `hold_reads` / `on_drain`
  pacing bounds memory instead (`Config::max_queued_bytes` still applies). HTTP `CONNECT` or
  upgrade relays use `RawConn::set_relayed`.

only-socks relays exactly this way in both directions.

## Pools and protocols

- The logical pool queue is bounded (`PoolConfig::queue_capacity`): `spawn_blocking` returns
  `Overloaded` instead of queueing without limit.
- HTTP/2 enforces flow control both ways and limits what a response may hold back for a slow
  peer (`H2Config::max_pending_bytes`).
- QUIC bounds each stream's and each connection's send buffer (`TransportConfig::
  stream_send_buffer`, `send_buffer`): `send` fails with `Overloaded` and
  `QuicHandler::on_stream_writable` says when to go on. KCP's `Session::send` fails with
  `KcpError::Full` past `KcpConfig::write_queue` and `KcpHandler::on_writable` follows at half.
  HTTP/3 responses and file bodies follow the QUIC buffers.
- UDP has no backpressure: datagrams the socket refuses are dropped, as UDP allows.

## Limits worth setting

| Knob | Default | Purpose |
|---|---|---|
| `write_high_watermark` | 256 KiB | pause reads of a connection with a big backlog |
| `max_queued_bytes` | 64 MiB | hard per-connection memory bound |
| `max_connections` | 0 (none) | refuse accepts beyond this many open connections |
| `idle_timeout` | none | close connections whose peer sent nothing for this long |
| `HttpConfig::max_body_bytes` | 1 MiB | buffered request body limit (413 beyond) |
| `PoolConfig::queue_capacity` | 65,536 | bounded blocking-work queue |

All of the first four can be changed at runtime with `Engine::reload`.
