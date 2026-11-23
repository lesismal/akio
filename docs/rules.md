# `akio` development rules

English | [简体中文](rules.zh-CN.md)

Every change to `akio` follows these rules. They complement the engineering rules in
[DEV-PLAN section 5](DEV-PLAN.md#5-engineering-rules) and the ADRs: those say how the code is
organised and verified; these say what the data plane must never do. They are adapted from
[fit's rules](https://github.com/lesismal/fit/blob/main/docs/rules.md), which hold the same line
for a proxy built on an event-loop library.

## 1. Never block an I/O thread

1. **Nothing on an I/O thread blocks.** Handlers, middleware, protocol state machines and
   completions run on the loop that owns the connection, together with every other connection
   of that thread. They do no synchronous disk I/O (`std::fs`, `File::open/read`, `metadata`),
   no DNS (`to_socket_addrs`), no `thread::sleep`, no wait on a channel, condition variable,
   join handle or future, no blocking `connect`, and hold no lock that another thread may hold
   for long. The slow-callback detector (`Config::slow_callback_threshold`, 100 ms by default)
   reports what slips through.
2. **Work that can only block goes to the logical pool** with `Conn::spawn_blocking` (or a
   detached response completed from the pool, `Context::detach_to_pool`, or a protocol's
   `run_on_pool` switch, ADR-094), and comes back to the loop as a completion. The
   pool is bounded (`Overloaded` when full); a feature that queues work there handles that error.
   Waits between pools and loops go one way only: a pool task never waits for a loop, so they
   cannot deadlock each other.
3. **Library code that must call a blocking API** (a tracker announce resolving a host name, a
   file served on a cache miss) does it on the pool or on a dedicated thread of its own, never
   on the loop that happened to trigger it. Only an in-memory fast path stays on the loop.

## 2. Bodies are streamed and bounded

4. **Bodies are streamed as they arrive** (`BodyMode::Stream`, `on_body`, frame callbacks) and
   forwarded in pieces. Only a feature that really needs the whole message buffers it, and
   always under a limit; past the limit it answers 413 / `ResourceExhausted` / close code 1009,
   or falls back to streaming.
5. **Data handed to a callback is valid for that call only**; keep it past the call by copying
   it, preferably into a pooled buffer (`akio-buf`).
6. **Limits count what the peer controls before any expansion is paid for**: compressed input is
   bounded as well as its decompressed output, partial messages and fragments as well as whole
   ones, the sum over a connection as well as each stream.

## 3. Backpressure is linked, and nothing is unbounded

7. **No queue or buffer anywhere grows without a limit**: per-connection send queues
   (`max_queued_bytes`), per-stream and per-connection pending bytes in multiplexed protocols,
   ordered (pipelined) responses, fan-out queues of slow subscribers, tables keyed by peer input
   (UDP peers, sessions, streams, swarms, caches). Every table has a cap and an eviction rule.
8. **Backpressure is linked**: when one side's pending bytes pass the watermark, reads of the
   other side pause (`hold_reads`), and resume when it drains (`on_drain`). Relays and tunnels
   (SOCKS, CONNECT, WebSocket and gRPC proxies, media fan-out, TURN) apply it both ways.

## 4. Timeouts and limits

9. **Every exchange with the outside has timeouts**: connect, first byte / head, idle and
   total. A trickle of one byte at a time must not keep a half-received head alive (slowloris).
10. **Every resource has a limit, and every limit has a safe default**: connections, streams,
    sessions, peers, header size, body size, message size, decompressed size, concurrency,
    resets per window. A configuration that sets none is still bounded; "no limit" is an
    explicit opt-out, never the default. [ADR-009](adr/009-safe-defaults.md) lists the engine
    defaults.

## 5. The hot path

11. **What can be done when the configuration is built is not left to request time.** Routes,
    middleware chains, fixed header values (CORS, `Allow`, `Server`), compression choices and
    lookup tables are built once. Requests read immutable structures.
12. **Per request or per message: no global locks and as few allocations as possible.** Shared
    counters are per thread or sharded; reference counts shared by every thread are not bumped
    per request; buffers are reused or pooled; nothing is formatted that could have been
    formatted at build time.

## 6. Verification

13. **Every data-plane feature has tests** for slow peers, large bodies, connections cut midway
    and the limit it introduces (just under, at and over), on every backend the feature runs on.
14. **A change that affects throughput or memory is measured before and after** on the quiet
    benchmark host, as rule 16 sizes it, and the numbers go in the commit or the report.
15. **A new dependency comes with an ADR** (ADR-005: the libraries have no required third-party
    dependency).

## 7. Verification sized to the change

Every check costs waiting; each change gets the checks its kind needs, no more.

16. **Benchmarks by kind.**

    | Change | Benchmark |
    | --- | --- |
    | Docs, tests, configuration, control plane | none |
    | Data plane off the hot path (limits, timeouts, error paths) | none, or a micro-benchmark of the crate |
    | The hot path (read/write path, parsers, routing, crypto kernels) | same-run before/after A/B on the quiet host (`quiet.sh`), alternating rounds |
    | A release or a campaign | the full harness (`tools/bench`) and a `docs/BENCHMARKS.md` update |

    In a feature task, this column is left to the separate benchmark tasks (rule 20).

17. **Load tests and benchmarks run on Linux, on the benchmark host.** Numbers from macOS, from
    Docker Desktop or from a loaded host are not used; when the host is loaded, only same-run
    A/B ratios are reported. One session at a time uses the benchmark host.
18. **Tests by reach.** While working, run the tests of the crates a change touches and of those
    that depend on them; the whole workspace suite (macOS, Linux arm64 in Docker with epoll and
    io_uring, x86_64 Linux natively) runs once before a merge or a push. At most two sessions run
    the whole suite at once.

## 8. Cleaning up

19. **Every development, test and benchmark run cleans up after itself and frees the space it
    took.** When the work is done (a feature, a fix, a test or benchmark run, a reproduction),
    remove what it left behind, on this machine and on the benchmark host: build output made for it
    (the `target/` directories of copies and worktrees, test binaries), copies of the tree and git
    worktrees, containers, images and volumes it created, and logs and temporary files no longer
    needed. Caches kept on purpose (a harness's shared target directory, pinned images) stay, but
    are pruned when they grow. The benchmark host's disk is shared by every session: check its free
    space (`df -h /`) before a large build, and never leave it fuller than you found it; a full disk
    stops everyone's builds and runs.

## 9. Feature work and benchmarks

20. **A feature task runs the basic CI tests, not load tests or benchmarks.** A task that develops a
    feature or fixes a bug runs what CI runs: `cargo test` of the crates it touches (and, before a
    push, the workspace suite rule 18 describes), fmt and clippy. It runs no load tests, benchmarks,
    A/B comparisons, perf profiles, full benchmark harness runs, or stress and soak runs (high
    repeat counts, long runs under load), neither here nor on the benchmark host. The benchmark
    host's time belongs to the benchmark tasks the maintainer runs separately (HTTPArena and the
    like); a feature task that loads the host wastes it and skews or delays those runs. Where
    another rule asks for a measurement, the feature task leaves it to such a benchmark task and
    says in its report what should be measured. A feature task runs a benchmark only when the user
    asks for one in that task.

    A feature task whose feature needs a benchmark (rule 16) adds its row to, or keeps it in, the
    benchmark status table of [DEV-PLAN section 4](DEV-PLAN.md#4-benchmark-and-optimization-status),
    marked not benchmarked and not optimized, and names there what should be measured; a benchmark
    task updates the row with what it measured and optimized. A row not benchmarked or not
    optimized is an open todo.
