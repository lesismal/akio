# ADR-106: io_uring ring sends: responses leave as SEND entries in the loop's one `io_uring_enter`

English | [简体中文](106-uring-ring-sends.zh-CN.md)

Status: accepted (2026-11-24)

## Context

The io_uring backend received through the ring (multishot recv on a provided-buffer ring,
`DEFER_TASKRUN`) but wrote every response itself: at the end of each callback the loop called
`write`/`writev` on the socket, through the write path shared with epoll (`ConnInner` writes
straight to the socket from any thread and queues the rest). On loads where one read carries one
request or message, that is one system call per request on top of the shared `io_uring_enter`.

The 2026-11-16 evaluation (docs/BENCHMARKS.md, "io_uring features evaluation") measured ring
sends on a bare ring at +1–4% throughput and 2–6% less CPU per request, but did not adopt them:
the write path is shared with epoll and with other threads, and ring sends need the bytes kept
until their completion, one send in flight per connection, and ordering against direct writes.

In HttpArena on the same host (server on 8 CPUs), aegon, a C++ io_uring framework that sends with
`IORING_OP_SEND` and makes no send or receive system calls on the hot path, was ahead of akio on
syscall-bound loads: echo-ws 9–17%, echo-ws-pipeline 9–16%, HTTP/1.1 baseline 11% and pipelined
19%. A profile showed akio on io_uring making one `writev` per read (about 20 messages per
`io_uring_enter` on echo-ws) where aegon makes none.

Two unfinished branches tried it. One described the queued bytes from the loop's flushes inside
the shared write path (`ConnInner`) and kept them queued until the completion; the other lent
the queue's front to a send started from `refresh` after `on_data` only, allocated a box per send
and fell back to `writev` with kernel TLS. This ADR takes the first design, which covers every
loop flush (callbacks, writability, completions from the pool, kernel TLS control records) with
one invariant, and adds from the second the deferral of the submission to the end of the batch.

## Decision

- **Ring mode in `ConnInner`** (akio-core, `#[doc(hidden)]` backend plumbing):
  `set_ring_sends(true)` at registration. The loop's own flushes, `uncork_flush_ring` and
  `flush_queue_ring`, do not write queued bytes: they describe up to 16 leading byte chunks of the
  queue in a `RingSend` (address, length) and mark that many bytes in flight
  (`WriteState::ring_inflight`). The bytes stay in the queue, counted by `queued_bytes`,
  backpressure, `max_queued_bytes` and `on_drain`, until the backend reports the completion with
  `ring_sent(res)`, which consumes what was sent and describes the next send. A short send leaves
  the rest at the head of the queue for the next entry; `EAGAIN` makes the loop wait for
  `POLLOUT`; any other error closes the connection as a failed `writev` does.
- **While a ring send is in flight nothing else touches the socket**: `write_queue` returns at
  once and the queue is not empty, so the direct writes of other threads (which still happen when
  nothing is queued) queue behind it, and so do kernel TLS socket operations and `sendfile`
  chunks, which the loop runs synchronously once they reach the head (a send stops in front of
  them). Per-connection order is the queue's order. Appending to the in-flight chunk happens only
  within its capacity (`push_copy` never reallocates a chunk), outside the range being sent.
- **Submission at the end of the batch**: the loop records the connection whose flush described
  a send (`Loop::unsent`) and, right before it enters the kernel, describes each again
  (`ring_redescribe`: nothing consumed the head meanwhile, so the send only grows) and pushes one
  `IORING_OP_SEND` (one buffer) or `IORING_OP_SENDMSG` (several; the boxed `msghdr` and iovecs
  belong to the connection and are reused) with `MSG_NOSIGNAL`. So everything a batch answered
  on a connection (several recv completions, a pool completion) leaves in one send, and every
  connection's send goes to the kernel in the one `io_uring_enter` the loop makes anyway: a batch
  costs one system call however many connections answered. At most one send per connection is in
  flight.
- **Close**: `mark_closed` stops counting the queue but keeps its chunks while a send reads them;
  the loop keeps the connection's `ConnInner` and `msghdr` in `orphans` until the completion
  arrives (the shutdown at close ends the send quickly), then frees them with `ring_release`. A
  send still waiting in `unsent` was never seen by the kernel and is released at once. At loop
  exit the existing cancel-all-and-drain covers sends; if it times out their memory is leaked,
  like the provided buffers.
- **TLS** needs nothing new: records are sealed into the queue when the application sends, so ring
  sends carry ciphertext. With kernel TLS the kernel encrypts what `SEND` hands it; its control
  records and key updates (socket operations) and `sendfile` run from the loop between sends, in
  queue order. Datagram and userspace-stack connections never take this path.
- **Write timeout**: progress is what completions report (`ring_sent` counts the bytes sent), so
  a stalled peer still trips `write_timeout`; the close then ends the pending send.
- **Switch**: on by default for every io_uring connection; `AKIO_URING_SENDS=write` restores the
  `write`/`writev` path (for A/B measurements). epoll and kqueue are unchanged (ring mode is never
  set there; the added check is one branch on `ring_inflight`). The capability probe requires
  `SEND` and `SENDMSG` (Linux 5.3 / 5.6, below the backend's 5.19 minimum).
- **Not adopted**: `SEND_ZC` and registered buffers (loopback always copies, and the 2026-11-16
  numbers stand), linked sends, `MSG_WAITALL` with `IOSQE_CQE_SKIP_SUCCESS` (the loop must learn
  when the kernel is done with the bytes).

## Consequences

- No send system call per request on io_uring; the loop's `io_uring_enter` carries every send of
  the batch. Measurements below.
- A response is on the wire after the loop's next `io_uring_enter` instead of during the callback:
  within the same loop iteration, so no added latency beyond the batch.
- Output queued on io_uring connections now stays in the queue until its completion: `queued_bytes`
  reports in-flight bytes, and the write-timeout check is armed once per timeout period while a
  connection keeps sending.
- One more completion per send to reap; with `DEFER_TASKRUN` the send runs inline at submit, so its
  completion is ready at the next wait.
- `WriteState` grows by a flag and a counter per connection (every backend).

## Measurements

gpu51 (Ryzen 7 7800X3D, Linux 7.0), `http-bench` with 8 I/O threads on CPUs 0-3,8-11, gcannon
(HttpArena's load generator) with 8 threads on CPUs 4-7,12-15, 5 s runs, fresh server per run,
variant order rotated, medians of 3 rounds (spread within 2%). `main` is the code before this
change; `write` is this build with `AKIO_URING_SENDS=write`.

| Case | main io_uring | ring sends | ring / main io_uring | ring / epoll |
|---|---:|---:|---:|---:|
| echo-ws, 512 connections | 1,290,871 | 1,433,949 | 1.111 | 1.182 |
| echo-ws, 4096 connections | 1,260,852 | 1,388,751 | 1.101 | 1.171 |
| echo-ws-pipeline (16), 512 | 17,862,374 | 16,813,974 | 0.941 (1.085 vs `write`) | 1.140 |
| echo-ws-pipeline (16), 4096 | 17,308,358 | 16,169,145 | 0.934 (1.078 vs `write`) | 1.128 |
| HTTP/1.1 baseline, 4096 | 1,149,072 | 1,285,558 | 1.119 | 1.168 |
| HTTP/1.1 pipelined (16), 4096 | 6,806,851 | 6,638,940 | 0.975 (0.977 vs `write`) | 1.001 |

On the pipelined WebSocket rows the new binary was 13% slower than main with ring sends off too
(`write` 0.867x main io_uring, epoll 0.872x main epoll), so that gap is not the send path (the
profile shows more instructions in `akio_ws::protocol::Decoder::decode`, whose code akio-ws did
not change: a code-layout effect under investigation). Against the same build, ring sends gain
8% there.

System calls per response (perf stat on the server, whole run):

| Case | main io_uring: total / writev / io_uring_enter | ring sends: total / writev / io_uring_enter | epoll: total |
|---|---|---|---|
| echo-ws 512 | 1.057 / 1.005 / 0.051 | 0.026 / 0 / 0.026 | 2.025 |
| echo-ws-pipeline 512 | 0.066 / 0.063 / 0.0032 | 0.002 / 0 / 0.0016 | 0.127 |
| HTTP/1.1 baseline 4096 | 1.057 / 1.001 / 0.052 | 0.045 / 0 / 0.041 | 2.012 |
| HTTP/1.1 pipelined 4096 | 0.067 / 0.063 / 0.0033 | 0.003 / 0 / 0.0018 | 0.127 |
