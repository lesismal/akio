# ADR-006: Role of eBPF

English | [简体中文](006-ebpf-role.zh-CN.md)

Status: accepted (2026-11-13)

## Decision

eBPF is an **acceleration/steering layer**, orthogonal to the I/O backend: `Listener::accel(Accel::Ebpf)` combined with any `Backend`. Planned uses: (1) `SO_REUSEPORT` BPF program choosing the I/O thread (CPU affinity / consistent hash), (2) sockmap / `sk_msg` in-kernel forwarding for proxy and relay paths, (3) optional XDP filtering / rate limiting. AF_XDP is an optional lighter kernel-bypass data path next to DPDK. Without privileges or kernel support, `only` degrades to default `SO_REUSEPORT` hashing. Implemented with `aya` in M5.

## Consequences

- eBPF stays optional and never blocks a deployment.
- No pretence that eBPF itself performs userspace I/O.

## Implementation note (M5, 2026-11-14)

`aya` was not used: building BPF object files needs nightly Rust and `bpf-linker`, and the programs `only` needs are a dozen instructions each. `only-ebpf` hand-assembles them and loads them with raw `bpf(2)` calls, so the default build stays on stable with no BPF toolchain. Steering has two tiers: classic BPF (`SO_ATTACH_REUSEPORT_CBPF`, unprivileged) for CPU and consistent-hash steering, and eBPF (`SK_REUSEPORT` + `REUSEPORT_SOCKARRAY`, privileged) for CPU steering. The sockmap relay uses a `SOCKHASH` keyed by socket cookie with an `sk_skb` stream verdict; by default it requires Linux 6.15+ because older kernels can lose relayed data when the destination's send buffer fills.
