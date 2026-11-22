# ADR-027: XDP rate limiting, thread pinning, the eBPF hash tier and spliced SOCKS tunnels

English | [简体中文](027-ebpf-xdp-pinning-socks-splice.zh-CN.md)

Status: accepted (2026-11-18)

## Context

ADR-006 planned three eBPF uses. M5 shipped `SO_REUSEPORT` steering and the sockmap relay but
left five gaps: XDP rate limiting, I/O-thread CPU pinning (without it `Steering::Cpu` picks
thread `cpu % n`, but nothing keeps that thread on that CPU), wiring the relay into akio-socks,
an eBPF tier for hash steering, and a benchmark. Two more problems came up while closing them:

- The classic BPF hash tier returns a socket's *position* in the reuseport group, so it relies
  on the sockets joining in thread order and shifts when one leaves.
- With a psock attached, data that reached a socket *before* it was spliced waits in its
  receive queue until more data arrives (the verdict runs on `data_ready`), and `SIOCINQ` no
  longer reports it. A server that greets first then stalls.

## Decision

1. **`akio_ebpf::xdp`** (new module): `RateLimiter::attach(interface, &XdpLimit)` /
   `attach_index`, `mode()`, `attachment()`, `stats() -> XdpStats { passed, dropped,
   new_sources }`, `forget(IpAddr)`, `detach()`; dropping it detaches. `XdpLimit { rate, burst,
   max_sources, count: Count::{TcpSyn, AllPackets}, mode: XdpMode::{Auto, Native, Generic} }`
   (`#[non_exhaustive]`, defaults per ADR-009: 100 packets/s, burst 200, 16384 sources, SYN
   only, auto mode). `Attachment::{Link, Netlink}`.
   - The program is hand-assembled like the others. Each source (IPv4 mapped to IPv6) has a
     token bucket kept as nanoseconds of credit in an `LRU_PERCPU_HASH`: per CPU, so there are
     no atomics on the packet path, and the limit is per receiving CPU. Counters live in a
     `PERCPU_ARRAY`.
   - Attachment uses a BPF link (5.9+), which the kernel detaches when the process dies.
     Netlink `IFLA_XDP` is the fallback, and its detach replaces only our program (expected fd).
     Native mode is tried first, then generic. A program someone else attached is never replaced
     (`EBUSY`/`EEXIST`).
2. **Pinning**: `EbpfConfig::pin_threads` (default off) pins thread `i` of `n` to the allowed
   CPUs `c` with `c % n == i`. Threads with no such CPU stay unpinned.
   - Public helpers: `akio_ebpf::cpu_pinning(threads)`, `SteerInfo::pinned_threads`, and
     `akio_sys::process::{allowed_cpus, pin_current_thread}`.
   - Backends get a hidden `Group::pin_threads` hook (`doc(hidden)`, not in the snapshots).
3. **eBPF hash tier**: with `AttachOptions::ebpf` (the default) and privileges,
   `Steering::Hash` uses an `SK_REUSEPORT` program that computes the classic tier's hash. A slot
   table in an `ARRAY` map maps the hash to a thread, and the thread's socket comes from a
   `REUSEPORT_SOCKARRAY`, so `expected_index` still holds and thread `i` owns `fds[i]` whatever
   the join order. `Tier::Ebpf` now covers both policies.
4. **Relay**:
   - `Relay::splice` raises `SO_RCVLOWAT` on both sockets while they are inserted, then sets it
     back to 1, which runs the verdict over anything that arrived meanwhile, in order. This
     removes the stall and the half-inserted window in which data would reach a psock queue
     that only userspace reads.
   - New `Relay::splice_inner(&ConnInner, &ConnInner)` and `splice_inner_with(.., f)`. `f` runs
     with both sockets in the map but before any byte is relayed (the SOCKS reply is written
     there). If `f` fails, the splice is undone without losing data.
   - New `relay::byte_counts(&TcpStream) -> ByteCounts { received, written }` (`TCP_INFO` plus
     `SIOCOUTQ`) for following spliced tunnels.
5. **akio-socks**:
   - `ProxyConfig::sockmap: Option<Relay>` and `Socks::sockmap(relay)` (opt-in, default `None`)
     splice SOCKS and HTTP `CONNECT` tunnels as their success reply is written.
   - It falls back to userspace for TLS, client data userspace already holds, or any splice
     error.
   - The idle timeout follows `byte_counts`. When one side closes, the other is closed once
     everything relayed has reached its send queue, because closing a socket drops the kernel's
     relay backlog.
   - If userspace still reads payload from a spliced tunnel while both ends are open (an
     io_uring read that completed before the splice), the tunnel is closed rather than
     reordered.
   - `spliced_tunnels()` (hidden) counts splices.

## Consequences

- Everything stays optional and degrades: unprivileged or old kernels get classic BPF, no XDP,
  and userspace relaying.
- The XDP limit is per source *and per receiving CPU*. Spoofed-source floods are not stopped
  (SYN cookies remain the answer to those), and VLAN-tagged frames are not counted.
- Spliced bytes bypass the engine's write watermarks. The relay still requires Linux 6.15+ by
  default (ADR-006 note).
- New `unsafe` lives only in `akio-sys` (`sched_getaffinity`/`sched_setaffinity`) and
  `akio-ebpf` `sys` (`BPF_LINK_CREATE`, map lookup, netlink socket I/O, `TCP_INFO`,
  `SIOCOUTQ`, `SO_RCVLOWAT`). Every block has a safety comment.
