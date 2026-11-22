# ADR-063: Cross-process steering through bpffs, listener migration on reload, and AF_XDP

English | [简体中文](063-shared-steering-migration-af-xdp.zh-CN.md)

Status: accepted (2026-11-21)

## Context

ADR-006 and ADR-027 left four gaps in the eBPF and prefork work:

- **Cross-process steering.** `attach_reuseport` gives each process its own `SK_REUSEPORT`
  program and socket array. In a `SO_REUSEPORT` group shared by prefork workers, every worker
  that attaches replaces the group's program with one that only knows its own sockets, so all new
  connections go to the last worker to attach. akio-prefork could only warn about it.
- **Reloads with `ListenMode::ReusePort`.** When an old worker's listening sockets close, the
  kernel resets the connections in their accept queues and the handshakes still pending on them.
  `net.ipv4.tcp_migrate_req=1` (Linux 5.14+) moves them to a random live listener instead, but it
  is a host-wide setting that is off by default.
- **AF_XDP.** ROADMAP §2.5 names it as a lighter kernel bypass next to DPDK. It was not built.
- **Local VM tests.** The eBPF tests ran in privileged Docker and on the shared x86 host only.

## Decision

### 1. Shared steering pinned in bpffs (`akio_ebpf::SharedSteering`)

- `SharedSteering::create(dir, sockets, steering)` loads one `SK_REUSEPORT` program for a group of
  `sockets` slots. It also creates a `REUSEPORT_SOCKARRAY`, the Maglev slot table (`ARRAY`, used
  by hash steering) and a `meta` array holding the version, the slot count, the policy and the
  migration flag. All four are pinned in `dir`: `prog`, `socks`, `slots`, `meta`. `meta` is
  pinned last, so a group whose `meta` exists is complete.
- The policies are those of `attach_reuseport` over `sockets` threads. `Steering::Cpu` selects
  slot `cpu % sockets`. `Steering::Hash` uses the same hash and the same Maglev table, so
  `expected_index(steering, sockets, peer, local)` names the slot.
- `SharedSteering::open(dir)` opens the pins from another process. Maps are opened with a size
  check: `Map::open_pinned` reads `BPF_OBJ_GET_INFO_BY_FD` and refuses a map whose type, key size
  or value size differs from the typed `Map<K, V>`, which keeps the typed methods sound.
- `at(first, count)` selects a range of slots. `join(fds)` writes this process's sockets into
  its slots, empties the rest of its range and attaches the pinned program to the group. Every
  process attaches the same program, so attaching again changes nothing. A restarted process
  overwrites its slots. A closed socket leaves the array by itself.
- The handle returned by `create` owns the pins and removes them when its last clone is
  dropped. Handles returned by `open` do not.
- Facade: new field `EbpfConfig::shared: Option<SharedSteering>`. With it, the listener joins
  the shared program instead of attaching its own. A failure degrades like any steering
  failure (`AccelStatus::Degraded`), or fails `build` with `strict`. `SteerInfo` gains `shared`
  and `migrate`. With `pin_threads`, thread `t` at slot `first + t` is pinned to the CPUs of
  that slot (`c % sockets == first + t`).
- **akio-prefork**: `Prefork::bpf_steering(BpfSteering { steering, threads, dir, strict })`
  works with `ListenMode::ReusePort` on Linux. The supervisor creates one group per listening
  address under `dir` (default `/sys/fs/bpf/akio-prefork`), named `<ip>_<port>` with `.`
  replaced by `-` because bpffs rejects dots in names. The group has `workers * threads` slots.
  The pin directories reach the workers in `AKIO_PREFORK_BPF`. Worker `i`'s `listener(n)`
  returns a listener with `threads` I/O threads and an `Accel::Ebpf` that joins slots
  `i * threads..(i + 1) * threads`. The supervisor removes the pins when it stops (`wait` or
  drop). A supervisor killed with SIGKILL leaves them, and the next supervisor on the same
  address replaces them. `Supervisor::bpf_steering(i)` returns the handle. The old warning about
  per-worker steering is now limited to engines that attach their own program.
- **Degradation.** No privileges, no bpffs, or a dotted directory name: the supervisor logs a
  warning and starts the workers without the variable, so they use the kernel's `SO_REUSEPORT`
  hash, as before this ADR. With `strict` the spawn fails instead. A worker that cannot open the
  pins logs a warning and serves without an `Accel`.

### 2. Migration on reload (`BPF_SK_REUSEPORT_SELECT_OR_MIGRATE`)

- The shared program is loaded for `BPF_SK_REUSEPORT_SELECT_OR_MIGRATE` (Linux 5.14+); older
  kernels get the plain `SELECT` program, and `SharedSteering::migrates()` reports which one was
  loaded.
- With this attach type the kernel migrates whatever is queued on a closing listener, even when
  `tcp_migrate_req` is 0. That covers the accept queue when the listener closes and requests
  (half-open connections) when their final ACK or data arrives. The program then runs with
  `migrating_sk` set. A prefix added to the program reads `sk_reuseport_md.migrating_sk`. When
  it is set, the program selects `sockarray[hash % sockets]`, the socket currently in the flow's
  slot. An empty slot returns `SK_PASS` without a selection, and the kernel picks a random live
  listener.
- **Reload order.** A reload's new worker `i` joins its slots when its engine is built, before
  it reports ready. From then on new connections for those slots go to it, and the old worker's
  sockets are no longer selected. The supervisor stops the old worker only after the new one is
  ready. When the old listeners close, their queued connections and pending handshakes migrate
  to the new sockets in the same slots. Nothing is reset.
- **Degradation.**
  - Kernels before 5.14, or no shared steering: what is queued migrates only when
    `net.ipv4.tcp_migrate_req=1` (to a random live listener), and is reset otherwise.
  - The supervisor checks the sysctl and the program. It logs a warning at the first
    `ReusePort` reload that will not migrate, and points to `Prefork::bpf_steering` and
    `ListenMode::Inherit`. The sysctl is never changed: it is a host-wide setting.
  - `ListenMode::Inherit` needs no migration: the listening socket stays open in the supervisor.

### 3. AF_XDP as a link of the userspace stack

- **Placement.** AF_XDP is a link type of the existing stack, next to TAP and AF_PACKET:
  `akio_dpdk::Device::AfXdp(AfXdpConfig)`. It is not a new `Backend`. `Backend::Dpdk(DpdkConfig)`
  already means "only's userspace TCP/IP stack over some link", and every listener, dial, metric
  and test of that backend works unchanged on the new link. A separate `Backend::AfXdp` would
  duplicate that configuration for no gain, so none was added. The `dpdk` cargo feature of `akio`
  is enough. `dpdk-pmd` and libdpdk are not needed.
- **Configuration.** `AfXdpConfig { interface, queues, mode: XdpMode, zero_copy: ZeroCopy,
  frames }` (`#[non_exhaustive]`, `AfXdpConfig::new(interface)`).
  - Defaults: one queue; `XdpMode::Auto` (re-exported from `akio_ebpf::xdp`); `ZeroCopy::Auto`
    (`Required`, `Off`); 4096 chunks of 4 KiB per queue.
  - The stack's default MAC is the interface's own, read from sysfs, so a NIC needs no
    promiscuous mode. `DpdkConfig::mac` overrides it.
- **Data path** (`akio_ebpf::xsk`, `#[doc(hidden)]`, unstable; the unsafe code lives here):
  - One socket per queue `0..queues`, each with its own UMEM: an anonymous mapping, unmapped
    only after the socket closes.
  - Fill, completion, RX and TX rings of `min(2048, frames / 2)` entries. Half of the chunks
    start in the fill ring, the other half form the TX pool.
  - Received frames are copied once into the stack's buffer, and their chunk goes straight back
    to the fill ring, so no reference into the UMEM outlives a call. Transmitted frames are
    written in place in a TX chunk, like a DPDK mbuf, and committed to the TX ring. `flush`
    kicks the kernel with `sendmsg` in copy mode, or when the TX ring asks for a wakeup.
    Completed chunks return to the pool.
  - Sockets are bound with `XDP_USE_NEED_WAKEUP` and tried in zero-copy mode first. When the
    driver refuses zero-copy on the queue, a fresh socket is bound in copy mode.
  - The redirect program is hand-assembled like the others: `bpf_redirect_map(xskmap,
    rx_queue_index, XDP_PASS)`. It sends each configured queue to its socket and lets frames of
    other queues reach the kernel. It is attached with the rate limiter's code (refactored into
    `xdp::ProgLink`): BPF link first, then netlink, native first, then generic. A program
    someone else attached is never replaced. The program is detached when the last socket goes,
    or when the process exits.
  - Checksums are not verified on receive, as for AF_PACKET: a veth peer, or the local kernel,
    sends with checksum offload.
  - The I/O thread sleeps in `ppoll` on the socket when idle, as for TAP and AF_PACKET.
    `busy_poll` applies unchanged.
- **Limits.**
  - A frame fits one chunk: at most 3840 bytes, so the MTU is at most 3826. Linux 5.4 or later
    is required. The program needs `CAP_NET_ADMIN`, `CAP_NET_RAW` and `CAP_BPF`.
  - The stack owns the configured queues: the kernel no longer sees their traffic.
  - In native mode on a veth, the kernel turns the peer's GSO off by itself. In generic mode
    the frames are seen after GRO, so the peer must not send GSO aggregates and GRO must be off
    (the tests use `ethtool -K ... tso off gso off gro off`).
  - Copy-mode TX does not pass through the interface's qdisc, so `tc netem` on the stack's side
    has no effect.
  - With several queues, the NIC's RSS spreads flows. Dialed connections use the existing rule
    that a port names its queue.
- `akio_ebpf::Probe` gains `reuseport_migrate` and `af_xdp`. The hidden
  `akio_dpdk::af_xdp_info(interface)` reports native or generic mode, zero-copy and the number
  of queues, for tests and benchmarks.

### 4. Local VM tests

The macOS development machines have no lima, vfkit or QEMU, and no new tool is installed for
this. No VM script is added. The privileged tests run in privileged Docker (`tools/dpdk/test.sh`,
the eBPF Docker jobs) and on the shared x86 host (`gpu51`, Linux 7.0) with veth pairs and network
namespaces only. They never touch a real NIC. The unprivileged fallbacks are tested by running
the same tests without capabilities.

## Consequences

- Everything stays optional and degrades to the previous behaviour.
- A prefork `ReusePort` deployment with `bpf_steering` on Linux 5.14+ reloads without resetting
  connections, and with a policy that spans every worker. The price is privileges for the
  supervisor and the workers, and pins in bpffs while the supervisor runs.
- `Engine::set_threads` stays `Unsupported` for listeners with steering, shared steering
  included: each worker's slot range is fixed by `BpfSteering::threads`.
- New `unsafe` code is confined to `akio-ebpf`: `sys` (`OBJ_PIN`, `OBJ_GET`,
  `OBJ_GET_INFO_BY_FD`, a lookup of `[u32; N]` values) and the new `xsk` module. Every block has
  a `SAFETY:` comment, and docs/unsafe-review lists them.
- API: only additions (`SharedSteering`, `MAX_SHARED_SOCKETS`, `SteerInfo::{shared, migrate}`,
  `Probe::{reuseport_migrate, af_xdp}`, `EbpfConfig::shared`, `BpfSteering`,
  `DEFAULT_BPF_DIR`, `Prefork::bpf_steering`, `Supervisor::bpf_steering`, `Device::AfXdp`,
  `AfXdpConfig`, `ZeroCopy`, the `XdpMode` re-export). The `xsk` module and `af_xdp_info` are
  hidden.

## Verification

Results from `gpu51` (Linux 7.0, Ryzen 7 7800X3D), as root, with `AKIO_TEST_EXPECT_EBPF=1`:

- `akio-ebpf/tests/shared.rs`:
  - Slots of two "processes" follow their owner, also after one is replaced.
  - The pins disappear with the owner while the attached program keeps steering.
  - A closing listener's accept queue (32 connections) migrates to the slot's new socket, and
    `TCPMigrateReqSuccess` counts it.
  - Requests held by `TCP_DEFER_ACCEPT` migrate when their data arrives, so the migration
    branch runs on a real packet.
  - Without the program and with the sysctl off, the same accept queue is reset (control).
- `akio-prefork/tests/bpf.rs`, three workers with two threads each:
  - The answering worker is the one `expected_index` names, also after a worker was killed and
    restarted.
  - Three reloads under 8 client threads of connection churn, for CPU and hash steering: no
    exchange failed, and the workers' accept counts add up exactly to the clients' successful
    exchanges.
  - These reloads migrate nothing (`TCPMigrateReqSuccess` stays put): the new worker takes the
    slots before the old one stops, so the old listeners are empty when they close. Migration is
    exercised by a worker stopped with SIGSTOP under churn and then killed. Its queued connections
    (7–9 per run) migrate and nothing fails, while the control run without the program loses
    8–12. At most one exchange may fail: a connection the worker had accepted but not answered
    when it stopped.
  - The results are the same on epoll and io_uring.
  - A non-bpffs directory falls back to the kernel's hashing, and `strict` fails the spawn.
- `akio-dpdk/tests/kernel_peer.rs`, `af_xdp_*` on veth pairs:
  - Native/auto, generic/copy and IPv6: UDP echo, ECN, fragments, a 2 MiB TCP echo, dials and
    ICMP to the kernel.
  - Two queues with 200 concurrent connections.
  - `ZeroCopy::Required` fails cleanly on a veth.
- Fallback without privileges: the same test binaries run under
  `setpriv --inh-caps=-all --bounding-set=-all` (root without capabilities). The akio-ebpf and
  akio-dpdk tests skip, the prefork test checks that the workers serve with the kernel's
  hashing, and all of them fail when `AKIO_TEST_EXPECT_EBPF=1` is set.

Benchmark (same-run A/B under `quiet.sh`, `tools/bench/afxdp.sh`, one veth pair, AF_XDP in native
copy mode): compared with AF_PACKET, AF_XDP gives 1.68× the UDP request/response rate, 1.58× the
TCP request/response rate, 1.24× the TCP connection rate and 2.97× the single-connection TCP echo
throughput (814.7 vs 274.6 MB/s each way). Details are in docs/BENCHMARKS ("AF_XDP vs AF_PACKET
under the userspace stack").
