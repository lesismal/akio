# ADR-190: akio-buf's thread caches are bounded in bytes, so that work stealing does not multiply them

English | [简体中文](190-buffer-pool-bytes-per-thread.zh-CN.md)

Status: accepted (2026-11-28). akit's A303.

## Context

With work stealing the default scheduling on epoll/kqueue (ADR-104), akit-proxy's streamed
download lost its memory bound: `stream_download` (64 MiB to a paced HTTP/1.1 client, the process's
resident memory sampled, bound 16 MiB) rose 51-59 MiB in its case framed by a length on gpu51
(16 cores), and passed on event loops and on io_uring. akit suspected its linked backpressure: the
upstream connection's `hold_reads`, set from the client's side, and the client's
`queued_bytes` / `on_drain`, not taking effect across workers.

They do. `tests/relay_memory.rs` relays 64 MiB between two connections whose rounds run on any of
16 workers, holding the upstream's reads while more than 64 KiB waits for the client and resuming
them on the client's `on_drain`, as akit does. The bytes waiting for the client never passed
128 KiB (the bound plus one read) on any scheduling; the resident memory rose 54-56 MiB under work
stealing, and a few MiB on event loops and io_uring. A hold is an atomic the reading round checks
after every read, and `on_drain` runs on whichever thread empties the queue: neither depends on
which worker runs a round.

The memory was in akio-buf's pool. Each thread keeps freed buffers of a size class (512 B to
256 KiB) for its next `get`, up to 64 of each class: about 21 MiB per thread. akit's response framed
by its length sends each piece as `data.to_vec()` of a full 64 KiB read: exactly a size class, so
whoever frees it pools it (`send_owned` after writing it directly, the queue after writing it
later), and nothing on that path takes a 64 KiB buffer back out. On event loops the two
connections' threads fill their caches, 4 MiB each. Under work stealing every one of the 16 workers
runs rounds of both connections in turn, frees some of the pieces and keeps them: 16 x 4 MiB is the
64 MiB moved, which is what the resident memory showed. The chunked case passed because a chunk
with its framing is not a class size.

## Decision

1. **A thread keeps at most 256 KiB of a size class** (`MAX_CACHED_CLASS_BYTES`), and still at most
   64 buffers: 64 of 512 bytes and of 4 KiB (unchanged), 16 of 16 KiB, 4 of 64 KiB, one of
   256 KiB. About 1 MiB per thread in all, against about 21 MiB before. What the caches hold
   together is still per thread, but now small enough that a pool of workers which all free
   every connection's buffers stays far below what a relay moves.
2. **No change to the schedulers, `hold_reads`, `queued_bytes` or `on_drain`**: they already took
   effect across workers. The test keeps both bounds: the bytes waiting for the client, and the
   resident memory (Linux).

## Consequences

- akit's `stream_download` passes under work stealing (10 of 10 runs alone on gpu51), so akit can
  drop `akit_runtime::scheduled` and its decision 91 once its akio pin moves past this change.
- The small classes keep their 64 buffers: an HTTP/1 server's pipelined answers (ADR-106) and
  response heads (ADR-081) are pooled as before. A thread that frees more than four 64 KiB (or one
  256 KiB) buffers before taking them again allocates the rest from the allocator. Not
  benchmarked; the large classes are used by large queued sends, where the copy costs more than
  the allocation.
- Alternatives not taken: a process-wide budget counted on every `get` and `put` (an atomic shared
  by every thread on the hot path), and caches per worker pool (the pool would have to know the
  scheduling). The bound per thread needs neither.

## Verification

`crates/akio/tests/relay_memory.rs` (`relayed_stream_to_a_slow_client_stays_bounded`): fails
before this change under work stealing on gpu51 (resident memory rose 54-56 MiB, bound 16 MiB, 3 of
3 runs), passes on event loops and io_uring before and after, and under work stealing after:
30 of 30 runs alone on each, the resident memory rising at most 6.4 MiB (work stealing), 1.1 MiB
(event loops) and 2.4 MiB (io_uring). akit's `stream_download` under work stealing, case framed by
its length: 8.1 MiB, against 52-57 MiB before.
`akio-buf`'s `cache_is_bounded_in_bytes` checks the counts per class.
