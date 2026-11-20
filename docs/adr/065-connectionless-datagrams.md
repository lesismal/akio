# ADR-065: Connectionless UDP listeners (`DatagramsHandler`)

English | [简体中文](065-connectionless-datagrams.zh-CN.md)

Status: accepted (2026-11-21)

## Context

A UDP listener turns every source address into a connection: a `Conn`, a handler, an idle timer
and an entry in the loop's peer table (`Listener::udp`, M2), bounded by `Config::udp_max_peers`
and `udp_idle_timeout`. That is right for protocols with per-peer state (QUIC, DTLS, KCP, game
sessions), and the batching of ADR-024 and the M2 UDP work (`recvmmsg`, replies of a receive
batch leaving with `sendmmsg` and UDP GSO, `on_batch_end`) lives behind it.

DNS, syslog, StatsD, NTP-style or telemetry collectors answer each datagram on its own. For them
the peer table is pure cost: a handler and timer per client that is never seen again, a table
that spoofed sources fill up to `udp_max_peers` (after which real clients are refused), and an
`on_open` / `on_close` pair per address. DEV-PLAN listed a connectionless `DatagramsHandler` as
not done.

Constraints: thread-per-core with callbacks inline on the I/O thread (ADR-001); no new
dependencies; every queue bounded with a safe default (`docs/rules.md`); epoll, kqueue and
io_uring supported; the existing per-peer path must not get slower.

## Decision

1. **A second way to serve a UDP listener**, `Listener::udp(addr).serve_datagrams(factory)`
   instead of `.serve(acceptor)`. `factory: Fn(&DatagramSender) -> H` runs once per I/O thread
   (one `SO_REUSEPORT` socket per thread on Linux, as for per-peer listeners; one thread
   elsewhere), so the handler is per thread and needs no lock: "one handler per listener" in the
   thread-per-core sense. `build` refuses it on a TCP listener or together with `.serve`
   (`InvalidInput`).
2. **`DatagramsHandler` gets batches.** `on_datagrams(&mut self, batch: &Datagrams<'_>, out:
   &mut Replies)` runs once per receive batch (one `recvmmsg` of up to 32 datagrams on Linux, up
   to 32 `recv_from` calls into one buffer elsewhere); `Datagrams` iterates `(SocketAddr,
   &[u8])` borrowed from the receive slots (GRO receives split back into datagrams, as on the
   per-peer path). `on_shutdown(&mut self, out)` lets it send last datagrams. A batch rather than
   a per-datagram callback because the batch is what the syscalls deliver and what a handler
   needs to amortise its own work (one lock, one lookup, one log write per batch); a per-datagram
   loop is one `for` away. Two arguments rather than one object because the batch borrows the
   receive buffers immutably while replies are queued mutably.
3. **Replies leave together, through the same batching.** `Replies::send_to(data, addr)` copies
   the datagram into one contiguous per-thread buffer; when the callback returns it is sent with
   `sendmmsg` (64 messages per call), runs of equal-size datagrams to one address merged into
   one UDP GSO message (contiguous in the buffer, so one iovec), GSO probed and disabled as on
   the per-peer path; one `sendto` each where there is no `sendmmsg`. Datagrams the network
   refuses (too big, wrong family, unreachable) are dropped, as UDP does.
4. **Bounded, with backpressure.** The queue counts each datagram's bytes plus 64 against
   `Config::max_queued_bytes` (default 64 MiB; at least one maximal datagram). When it is full,
   `send_to` first sends what is queued, then refuses with `WouldBlock` (counted in the
   `overloaded` metric). Datagrams the socket has no room for (`EAGAIN`) wait; the thread then
   polls for writability only and stops reading until they are out, so a full socket pushes back
   on the receive side instead of growing anything. `send_to` of more than 65,535 bytes is
   `InvalidInput`. An emptied buffer that grew past 1 MiB is freed.
5. **Cross-thread sends**: `DatagramSender` (`Send + Sync + Clone`) wraps the socket and sends
   with one `sendto` on the calling thread; a full socket drops the datagram with `WouldBlock`
   (the semantics of `UdpBinding::send_to`). No queue to the I/O thread: nothing to bound, no
   wake-up, and UDP has no ordering between threads to preserve. Obtained from the factory,
   `Replies::sender()` or `Engine::datagram_sender(local)` (the first thread's socket on Linux).
6. **No per-peer state at all**: no table, no `Conn`, no idle timer, no `on_open` /
   `on_close`; `udp_max_peers`, `udp_idle_timeout`, `spawn_blocking` and the connection table do
   not apply (slow work goes to the application's own threads, which answer with a
   `DatagramSender`). Memory is the receive slots, the reply buffer and the handler, independent
   of the number of peers.
7. **One driver, three backends.** `only_core::DatagramPort` (backend-facing) owns the socket,
   receive batch, handler and reply queue and exposes `on_readable` / `on_writable` /
   `wants_read` / `wants_write` / `shutdown` / `on_reload`. The epoll/kqueue UDP loop
   (`UdpGroup::bind_datagrams`) polls it under its socket token; the io_uring loop
   (`UringGroup::bind_datagrams`) arms a one-shot `IORING_OP_POLL_ADD` per socket (`POLLIN`,
   or `POLLOUT` while replies wait) and runs the same driver on completion, cancelling it at
   shutdown. Readiness from the ring and I/O by `recvmmsg` / `sendmmsg` is the conclusion of the
   M2 evaluation (a multishot `recvmsg` with provided buffers would re-implement the batching
   for no measurable gain), now for a listener that does run on io_uring threads, so
   `ONLY_DEFAULT_BACKEND=uring` (ADR-029) applies to datagram listeners (per-peer UDP listeners
   still always run on the epoll UDP loop). A strict `UringConfig` fails `build` where io_uring
   is unavailable, as for TCP.
8. **Not supported**: DPDK (its userspace UDP is per-peer; `build` fails with `Unsupported`,
   adding it means a datagram port over the stack's sockets); `Engine::set_threads` (refused, as
   for per-peer UDP listeners: a socket added to or removed from the `SO_REUSEPORT` group moves
   peers between threads); runtime-bound datagram sockets (`Engine::bind_udp` stays per-peer);
   ECN codepoints in either direction (the per-peer path keeps them). A panic in a callback is
   caught and logged and the handler keeps serving: there is no connection to close, and
   stopping the listener would turn one bad datagram into an outage.

## Consequences

- DNS-style servers keep no state per client and cannot be pushed into refusing clients by
  spoofed sources; a 10,000-peer test shows no growth of the resident set.
- The per-peer path is unchanged (the UDP loop gained a branch on its socket token for loops
  that serve a datagram port); the A/B below shows no regression.
- Public API, additive only: `only::{DatagramsHandler, Datagrams, DatagramsIter, Replies,
  DatagramSender}`, `Listener::serve_datagrams`, `Engine::datagram_sender`, and the backend
  constructors `UdpGroup::bind_datagrams` / `UringGroup::bind_datagrams`.
- Tests: `crates/only/tests/datagrams.rs` (batches and boundaries across peers; every batch's
  replies in one `sendmmsg`, counted by the `writes` metric; a burst to one peer; senders from
  other threads, the factory's and the engine's; 11,000 distinct peers with no peers, no
  connections and bounded RSS; a per-peer listener next to a datagram one; shutdown datagrams;
  panics; size limits; misuse), on kqueue, epoll and io_uring (`ONLY_TEST_BACKEND=uring`), and
  unit tests of the reply queue (limit below / at / above, GSO run boundaries, order).
- Example: `crates/only/examples/udp-dns.rs` (a DNS-style responder); `bench-server udp-dgram`
  for benchmarks.

## Measurements

gpu51 (Ryzen 7 7800X3D, Linux 7.0), quiet host (`quiet.sh`), one alternating run: 64-byte UDP
echo, server 4 threads on CPUs 0–3, `echo-bench` 64 sockets × 64 B with 8 threads on CPUs 4–11,
10-second runs, 9 rounds in rotating order; medians, server CPU per request from `/proc`.

| Server | req/s, median (range) | vs per-peer before | server CPU per request | vs before |
|---|---:|---:|---:|---:|
| per-peer `Listener::udp(..).serve`, before (`b22519ae`) | 768,144 (684,519–860,916) | 1.00 | 4,745 ns | 1.00 |
| per-peer, after | 781,173 (712,511–841,607) | 1.02 | 4,747 ns | 1.00 |
| `serve_datagrams`, epoll | 829,051 (726,597–926,309) | 1.08 | 4,407 ns | 0.93 |
| `serve_datagrams`, io_uring | 838,496 (680,238–912,182) | 1.09 | 4,364 ns | 0.92 |

The per-peer path does not regress (throughput within the run-to-run spread, CPU per request
equal). Without the peer lookup, `Conn` and per-peer cork/flush bookkeeping the connectionless
echo costs 7–8% less server CPU per request; with 64 clients on loopback the client is close to
its limit, so throughput gains less than that. Rerun with `tools/bench/udp-dgram.sh`.
