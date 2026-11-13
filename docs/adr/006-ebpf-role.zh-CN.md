# ADR-006：eBPF 的定位

[English](006-ebpf-role.md) | 简体中文

状态：已采纳（2026-11-13）

## 决定

eBPF 是**加速/调度层**，与 I/O 后端正交：`Listener::accel(Accel::Ebpf)` 可与任意 `Backend` 组合。计划用途：(1) `SO_REUSEPORT` BPF 程序选择 I/O 线程（CPU 亲和 / 一致性哈希）；(2) sockmap / `sk_msg` 内核态转发，用于代理与 relay；(3) 可选的 XDP 过滤 / 限速。AF_XDP 是 DPDK 之外可选的轻量内核旁路数据面。无特权或内核不支持时，flash 降级为默认的 `SO_REUSEPORT` 哈希。M5 用 `aya` 实现。

## 影响

- eBPF 始终是可选项，不会阻碍部署。
- 不假装 eBPF 本身执行用户态 I/O。
