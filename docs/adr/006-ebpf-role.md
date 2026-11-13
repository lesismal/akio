# ADR-006: Role of eBPF

English | [简体中文](006-ebpf-role.zh-CN.md)

Status: accepted (2026-11-13)

## Decision

eBPF is an **acceleration/steering layer**, orthogonal to the I/O backend: `Listener::accel(Accel::Ebpf)` combined with any `Backend`. Planned uses: (1) `SO_REUSEPORT` BPF program choosing the I/O thread (CPU affinity / consistent hash), (2) sockmap / `sk_msg` in-kernel forwarding for proxy and relay paths, (3) optional XDP filtering / rate limiting. AF_XDP is an optional lighter kernel-bypass data path next to DPDK. Without privileges or kernel support, flash degrades to default `SO_REUSEPORT` hashing. Implemented with `aya` in M5.

## Consequences

- eBPF stays optional and never blocks a deployment.
- No pretence that eBPF itself performs userspace I/O.
