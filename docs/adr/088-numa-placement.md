# ADR-088: NUMA placement of the engine's threads, off by default

English | [简体中文](088-numa-placement.zh-CN.md)

Status: accepted (2026-11-23). akio-prefork, named in the context, was removed by
[ADR-121](121-akio-prefork-removed.md) (2026-11-25).

## Context

On a machine with several NUMA nodes (two-socket servers, EPYC in NPS2/NPS4 mode), memory and
PCIe devices belong to one node each; a thread on another node reaches them over the
interconnect, at about 1.5–2x the latency. The engine already keeps most state per I/O thread:
a connection lives on one thread for its whole life, buffers come from per-thread pools that the
thread itself first touches, timers are per thread. What it did not do was keep a thread on one
node: the scheduler could move it, and nothing put it near the network interface. Thread pinning
existed only with eBPF CPU steering (`EbpfConfig::pin_threads`, thread `i` on the CPUs
`c % n == i`), which ignores nodes, and in `akio-prefork` (`CpuPinning`). DPDK's mempools are
already allocated on the port's socket.

## Decision

1. **akio-sys `numa`**: `nodes()` reads `/sys/devices/system/node/node<N>/cpulist` (a kernel
   without NUMA reads as one node with the online CPUs), `interface_node(name)` reads
   `/sys/class/net/<name>/device/numa_node` (`None` for `-1`), `parse_cpulist`,
   `set_incoming_cpu` / `incoming_cpu` (`SO_INCOMING_CPU`). Linux only; `Unsupported` elsewhere.
   Interface names are checked (no `/`, no dot names, at most 15 bytes) before they become a
   path.
2. **akio `numa` module, `EngineBuilder::numa(NumaConfig)`**, off by default. `NumaPlacement`:
   `Off`, `Spread` (thread `i` of each group on node `i % n`), `Nodes(ids)` (only those nodes,
   round robin), `Interface(name)` (the interface's node). Nodes are restricted to the CPUs the
   process may use (`sched_getaffinity`, so `taskset` and cgroups still apply); nodes left
   without CPUs drop out. `NumaConfig` fields: `per_cpu` (one CPU per thread, round robin within
   its node, instead of the whole node), `incoming_cpu` (`SO_INCOMING_CPU` on each thread's
   listening socket: the first CPU of its set), `pool` (confine the logical pool's threads to the
   chosen nodes, default true), `strict` (fail the build instead of degrading).
3. **Placement goes through the existing `Group::pin_threads`**: epoll, io_uring and UDP groups
   pin each loop thread when it starts, so nothing changes on the hot path. Sets are computed
   for as many threads as there are usable CPUs, so threads added later by `set_threads` are
   placed too. Groups whose threads eBPF CPU steering pinned (`AccelStatus::Steering` with
   `pinned_threads > 0`) and DPDK groups are left alone: steering needs its own pinning, DPDK
   places its lcores. The pool gets a hidden `PoolConfig::on_start` hook that pins each worker
   when it starts (unless the application set one).
4. **`AKIO_NUMA`** configures it when the builder was not told: `spread`, `nodes:0,1`,
   `iface:eth0`, `off`, with `+cpu`, `+incoming`, `+nopool`, `+strict`
   (`NumaConfig::from_env`), so an unchanged program can be placed and benchmarked.
5. **`Engine::numa_status()`**: `Off`, `Placed(NumaReport)` (nodes, per group and thread the node,
   CPUs and `SO_INCOMING_CPU`, the pool's CPUs) or `Degraded(reason)` (not Linux, topology
   unreadable, an unknown node, an interface without a node; a warning is logged).

Memory needs no separate policy: the kernel's default (local) policy allocates a page on the
node of the thread that first touches it, and the per-thread pools are touched by their thread.

## Consequences

- Additive API: `akio::{NumaConfig, NumaPlacement, NumaStatus, NumaReport, ThreadPlacement}`,
  `EngineBuilder::numa`, `Engine::numa_status`, `akio_sys::numa`. `PoolConfig::on_start` and
  `ThreadHook` are `#[doc(hidden)]`.
- With placement off (the default) the build path only reads `AKIO_NUMA`; the I/O path is the same.
- `incoming_cpu` matches only when the CPU that processes a packet is one a socket names: with
  loopback traffic that is the client's CPU, so on one host it changes nothing; it needs the
  interface's interrupts (RSS / RPS) on the server's CPUs.

Not done: io_uring rings are still created on a helper thread before the loop starts (their
memory follows that thread, not the node), and SQPOLL kernel threads are not placed
(`IORING_SETUP_SQ_AFF`) (both done since, see the update below); no measurement on a multi-node machine (none at hand: gpu51 has one
node), so no claim about the gain there.

## Verification

- akio-sys: CPU list parsing, nodes and interface nodes from a fake sysfs tree (including no node
  directory, malformed lists and refused names), on Linux the real topology and an
  `SO_INCOMING_CPU` round trip.
- akio: the planner (spread, per CPU, allowed-CPU restriction, unknown nodes, interface nodes),
  `AKIO_NUMA` parsing; `tests/numa.rs` on Linux, epoll and io_uring, three runs each on gpu51:
  each `akio-io-*` thread's `Cpus_allowed_list` is the CPU set the report gives (whole node, then
  one CPU each), `SO_INCOMING_CPU` is set on each listening socket, a `spawn_blocking` job runs
  on the pool's CPUs, traffic flows, impossible placements degrade (or fail when strict); off by
  default. On macOS placement degrades (`Unsupported` when strict). akio-pool: the start hook
  runs once per worker.
- Same-run A/B on gpu51 (`tools/bench/numa.sh`, 5 interleaved rounds under `quiet.sh`, server on
  CPUs 0-3 with 4 threads, one node), medians against placement off: HTTP/1.1 plaintext 1.000x
  (spread), 0.996x (spread+cpu), 1.001x (+incoming); pipelined 0.998x / 0.997x / 0.997x; h2c
  0.995x / 1.000x / 1.005x; TCP echo 64 B 1.026x / 1.006x / 0.982x (that case varies by 2–8 %
  between rounds). On one node placement neither helps nor hurts; see BENCHMARKS.

## Update (2026-11-23): io_uring rings on the loop's node, SQPOLL threads placed

This closes the first two "not done" items.

**Why rings are built on a scratch thread.** `io_uring_setup`, and enabling a ring, attach the
calling thread to it; when the ring is torn down the kernel sends every attached thread a
signal-like task_work, which interrupts a blocking call that cannot restart (`EINTR` on a read
with `SO_RCVTIMEO`) long after that thread built the engine. So a ring is never created on the
caller's thread but on a short-lived `akio-uring-setup` thread. The fast setup is single-issuer
with deferred task-run and `IORING_SETUP_R_DISABLED`: the ring belongs to the thread that
enables it, and the loop thread enables it (`IORING_REGISTER_ENABLE_RINGS`) before its first
submission. All of this stays as it was.

**Why not the loop thread itself.** The loops of a group are built (rings included) when the
group is constructed, so that a setup failure (the kernel, memory limits) is a build error; the
CPU sets arrive afterwards, through `Group::pin_threads`, before `start`. Creating the ring on
the loop thread would move setup errors to `start` and need a handshake with every new thread.

**Decision.**

1. When `Group::pin_threads` gives an io_uring group CPU sets (NUMA placement, or eBPF CPU
   steering's `pin_threads`), each loop that is built but not started gets a new ring, created on
   a scratch thread that first pins itself to the loop's set: the kernel allocates the SQ/CQ rings
   and the SQE array on the node of the CPU the setup runs on. The ring the loop was built with is
   dropped (nothing used it: it is enabled and its buffer ring registered only on the loop
   thread). Best effort: if the new ring cannot be created the loop keeps the old one. Loops added
   later by `set_threads` create theirs on their set directly.
2. With `UringConfig::sqpoll`, the ring is created with `IORING_SETUP_SQ_AFF` and
   `sq_thread_cpu` set to one CPU of the loop's set: the first CPU for the first loop with that
   set, the next CPU for the next loop with the same set, and so on (with whole-node sets, loops
   on one node would otherwise stack their polling threads on its first CPU). With `per_cpu` that
   is the loop's own CPU, which the polling thread then shares with the loop thread. If the kernel
   refuses the CPU (offline, outside the task's cpuset) the ring is created without `SQ_AFF`.
3. `ThreadPlacement::sq_thread_cpu` (additive, the struct is `#[non_exhaustive]`) reports the CPU
   each loop's polling thread is pinned to; the backend reports it through a new provided method
   of the `#[doc(hidden)]` `Group` trait, `sq_thread_cpus`.

The provided-buffer memory needs nothing: it is allocated untouched and first written by the
kernel's receives and the buffer-ring setup, both on the (pinned) loop thread.

With placement off nothing changes: `pin_threads` is not called, rings are created exactly as
before (an unpinned scratch thread, the same setup flags). With placement on, each loop's ring is
created twice at build time (a few syscalls and a thread spawn per loop), never on the I/O path.

**Verification.** akio-uring: the choice of SQ CPUs (shared and distinct sets, wrapping, no set);
on gpu51, a ring created with an SQ CPU has one new `iou-sqp-*` thread whose `Cpus_allowed_list`
is exactly that CPU, a CPU that does not exist falls back to an unpinned polling thread, an
unplaced SQPOLL ring and a placed non-SQPOLL ring are created as before. `tests/numa.rs` with
`AKIO_TEST_BACKEND=uring`: SQPOLL engines unplaced, node-wide and one CPU per thread, the
`iou-sqp-*` threads' CPUs equal the reported `sq_thread_cpu`s (one of the loop's CPUs; the
loop's own CPU with `per_cpu`; different CPUs for two loops on one node), the I/O threads are
placed as without SQPOLL, traffic flows. Same-run A/B on gpu51 against main: `tools/bench/numa.sh` with `KIND=akio-uring`, modes off and `spread+cpu`, 5 interleaved rounds under
`quiet.sh` (server on CPUs 0-3, 4 threads), branch / main medians: placement off HTTP/1.1
plaintext 0.999x, pipelined 0.997x, h2c 0.992x, TCP echo 1.035x; `spread+cpu` 1.000x, 0.997x,
0.994x, 0.966x. With placement off both builds run the same code, so that column is the noise
floor (TCP echo varies by up to 20 % between rounds); `spread+cpu` is within it (see
BENCHMARKS). SQPOLL with placement is tested, not benchmarked (the bench servers have no switch
for it).

Still not done: a measurement on a multi-node host (gpu51 has one node, so the ring's memory
node cannot differ there; this change is shown not to regress, not to gain).
