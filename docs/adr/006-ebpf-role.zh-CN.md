# ADR-006：eBPF 的定位

[English](006-ebpf-role.md) | 简体中文

状态：已采纳（2026-11-13）

## 决定

eBPF 是**加速/调度层**，与 I/O 后端正交：`Listener::accel(Accel::Ebpf)` 可与任意 `Backend` 组合。计划用途：(1) `SO_REUSEPORT` BPF 程序选择 I/O 线程（CPU 亲和 / 一致性哈希）；(2) sockmap / `sk_msg` 内核态转发，用于代理与 relay；(3) 可选的 XDP 过滤 / 限速。AF_XDP 是 DPDK 之外可选的轻量内核旁路数据面。无特权或内核不支持时，akio 降级为默认的 `SO_REUSEPORT` 哈希。M5 用 `aya` 实现。

## 影响

- eBPF 始终是可选项，不会阻碍部署。
- 不假装 eBPF 本身执行用户态 I/O。

## 实现说明（M5，2026-11-14）

未使用 `aya`：编译 BPF 目标文件需要 nightly Rust 和 `bpf-linker`，而 akio 需要的程序每个只有十来条指令。`akio-ebpf` 手工汇编这些程序并通过原始 `bpf(2)` 调用加载，默认构建保持 stable 且无需 BPF 工具链。调度分两层：经典 BPF（`SO_ATTACH_REUSEPORT_CBPF`，无需特权）支持 CPU 亲和与一致性哈希；eBPF（`SK_REUSEPORT` + `REUSEPORT_SOCKARRAY`，需特权）用于 CPU 亲和。sockmap 转发使用以 socket cookie 为键的 `SOCKHASH` 加 `sk_skb` stream verdict；默认要求 Linux 6.15+，因为更早的内核在目标发送缓冲区写满时可能丢失转发数据。
