# ADR-102: Remembered QUIC routes per UDP peer, and the QPACK dynamic table on by default for HTTP/3 servers

English | [简体中文](102-quic-peer-routes-qpack-server-default.zh-CN.md)

Status: accepted (2026-11-24)

## Context

In HttpArena on gpu51, akio trailed fib and fib-tuned on HTTP/3:

- baseline-h3 (64 connections): akio 1.95M req/s at 219% server CPU, against 2.10M for fib and 2.11M for fib-tuned.
- static-h3: akio 397k, against 403k for fib.

akio led every HTTP/2 test.

There were two candidate causes:

1. **The server's shared state.**
   - Every akio-quic server has one `Ep`, which all its UDP threads use.
   - Every datagram locks the endpoint's `Mutex<Endpoint>` to route its connection ID, then the connection table's mutex.
   - Every datagram sent locks the socket table's mutex.
   - fib keeps a table of peers per poller and takes no lock; its CID-to-connection map is used only for unknown addresses.
2. **The client's work per request.**

### The measurement

The test was baseline-h3 on gpu51: server on CPUs 0-3,8-11, h2load-h3 (`-c 64 -m 64 -t 8`) on CPUs 4-7,12-15, 15 s after a warm-up. `pidstat` and `/proc/net/snmp` were sampled during the run.

| | akio | fib-tuned |
| --- | --- | --- |
| req/s | 1.94M (1.95M in a second run) | 2.09M |
| h2load-h3 CPU | 799% (all 8 cores) | 798% |
| Server UDP threads | 14-47% each, all 8 busy | - |
| Response header bytes (h2load "headers") | 1.76 GB, 60.6 B/response, 31.6% QPACK savings | 209 MB, 7.0 B/response, 85.1% savings |
| UDP datagrams (in, 15 s) | 1.46M (20.0 requests each) | 1.27M (24.7 requests each) |

What this shows:

- **The load generator is the limit**, for akio and for fib alike. akio's server threads were far from busy, and the 64 connections were spread over all 8 threads.
- A perf profile of the server (999 Hz, 4 s, call graphs) has no futex, mutex or spin frames among its top symbols; the kernel's lock symbols are 0.1% or less. Time goes to:
  - parsing request heads (`request_head` 5.3%),
  - Huffman-decoding the requests' QPACK fields (4.7%),
  - the handler,
  - building responses.
- So the shared locks cost nothing visible at this load and do not decide this test. They go anyway (rule 12: no global lock per request), because at higher datagram rates they would.
- **The difference is the bytes the client has to take in per response.** Each akio response head carried:
  - `date` (31 bytes as a literal with a static name reference),
  - `content-type: text/plain; charset=utf-8` (27 bytes: the static table has only `text/plain;charset=utf-8`, without the space),
  - the status, the content length and the section prefix.
- akio-h3's QPACK encoder existed, but was off by default (ADR-061), so all of this went as literals.
- fib's response is `:status`, a `content-type` the static table holds and the length: about 7 bytes. fib sends no `date`.

RFC 9110 section 6.6.1 requires an origin server with a clock to send `Date`, so dropping it is not an option.

h2load v1.69 advertises a 4096-byte QPACK table (`qpack_max_dtable_capacity = --header-table-size`, default 4 KiB) and 100 blocked streams. With the encoder on, every one of those fields becomes a one-byte reference once inserted.

## Decision

### akio-quic: remembered routes

- Each UDP handler (one per peer address, owned by one I/O thread) remembers the connection its last routed short-header datagram went to, as `(connection ID, Connection, generation)`.
- A later short-header datagram carrying the same connection ID goes straight to that connection: no endpoint lock and no connection-table lock.
- `Endpoint::route_short` is the lookup that fills this memory; anything it does not find goes through `handle_ecn` as before (long headers, unknown IDs, stateless resets).
- `Ep::routes_gen` is bumped whenever the endpoint removes a route (`RetireCid`, `Drained`, a connection leaving the table). A remembered route is used only while the generation is unchanged.
  - The generation is read before the lookup, so a removal that races with it invalidates the route.
  - A datagram that slips through in that window reaches a connection that ignores it (drained) or still owns the ID (retired a moment ago). This is harmless.
- A server connection remembers the UDP socket it last sent on (`Shared::tx_sock`). It reuses that socket while it is open and has the destination's address; otherwise it looks the socket up in the shared table as before.
- Clients keep the table lookup, because they have one socket, or two during a migration.

### akio-h3: the encoder on by default for servers

- `H3Config::qpack_encoder_capacity` now defaults to 4096 (it was 0). `H3ClientOptions::qpack_encoder_capacity` stays 0.
- The encoder still uses at most what the peer allows, and nothing changes with peers that advertise no table (curl, quic-go, fib).
- `date` is now cacheable. It changes once a second, and every response of that second repeats it, so one insert a second per connection replaces a 31-byte literal per response.
- `date` goes through the encoder whenever there is one; a server without an encoder keeps the per-thread cached literal.

### Fix: inserts beyond the encoder stream's room

- The encoder queued its inserts with `let _ = c.send(encoder_stream, ..)`.
- While the connection's send buffer was full (large responses waiting for the peer's credit), that send failed with `Overloaded`, and the inserts were lost.
- The sections that referenced them then could never decode: the peer's streams waited forever.
- The existing test `many_responses_over_the_connection_buffer` caught this as soon as the encoder was on by default.
- The fix: `EncShared::section` sets `Encoder::room` to the encoder stream's `send_capacity` before each section. `insert` and `duplicate` refuse an instruction that would not fit, so the field goes as a literal.
- No insert is made that cannot be sent.

## Verification

- Unit test `encoder_inserts_within_the_stream_room`: no room gives literals only and no inserts; one insert's worth of room gives exactly one insert; with room, `date` and `content-type` become two one-byte references.
- Integration test `many_connections_over_several_threads_close_and_reconnect`: 12 connections on a 4-thread server, 16 requests each. The server closes them all, the table empties, and 12 new connections from the same client engine work.
- The akio-h3 suite passes with the new default, including the backpressure tests.
- Interop:
  - quic-go and fib, both ways.
  - ngtcp2 (libcurl-gnutls) and OpenSSL QUIC (libcurl), with nghttp3 as the HTTP/3 client in both cases. The default server now uses its encoder with them.
  - curl and `openssl s_client -quic`.
  - libnghttp3's QPACK decoder against our encoder, 5 configurations x 3 seeds (`tools/interop/quic/docker.sh`).
- `cargo test --workspace`: macOS, and gpu51 on epoll and io_uring.

## Measured

Pending. HttpArena runs on gpu51 were paused before the A/B could run.

The variants are registered for the shared A/B batch:

- `akio-h3` (route memory only, 1e1fb670).
- `akio-h3q` (route memory plus the QPACK default, 87aef2a8).

Each runs against `akio` (main 50a82315) and fib-tuned on baseline-h3, static-h3, baseline-h2, static-h2, baseline-h2c and json-h2c.

## Consequences

- An HTTP/3 server spends a lock per response on its encoder (`EncShared`, per connection, uncontended) and handles the peer's section acknowledgements.
  - ADR-061 measured encoders on both ends at 0.83x of the default in `quic-bench h3`, with akio's own client as the bottleneck.
  - Here the client decodes cheaper references and takes in about 50 bytes less per response.
  - Whether that wins for a CPU-bound client is what the A/B decides. If it does not, the default goes back to 0 and this section says so.
- Applications that set `qpack_encoder_capacity: 0` explicitly keep the old wire format.
- Remembered routes cost one `Connection` clone per UDP peer and an atomic load per datagram.
- A peer that alternates connection IDs over one address falls back to the endpoint for each change: correct, just not faster.
