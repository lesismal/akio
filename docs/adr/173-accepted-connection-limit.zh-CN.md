# ADR-173：只统计接受的连接的连接数上限

[English](173-accepted-connection-limit.md) | 简体中文

状态：已采纳（2026-11-26）。akit 的 A215。

## 背景

`Config::max_connections` 会关闭超过它的接受连接，但统计的是 engine 的所有连接：拨出的连接和 UDP
对端也算在内。上游连接池与 listener 共用同一 engine 拨号的网关，于是把客户端的名额让给了上游连接：
打开 10 万个上限、3 万个上游连接时，第 70001 个客户端就会被拒绝。fit 的 `limits.max_conns` 限制的
是“listener 同时保持打开的客户端连接”。

## 决定

1. **`Config::max_accepted_connections: usize`**（默认 0，不限制），与 `max_connections` 一样可
   重载（`Live::set_max_accepted_connections`）。engine 所有 listener 上超过它的 TCP 接受连接在
   `accept` 之后立即关闭，计入 `rejected`，不论 engine 拨出了多少连接。两个上限同时设置时都生效。
2. **使用 A30 的计数器。** `Telemetry` 记录打开的连接（`open`），并单独记录其中不是 TCP 接受
   连接的那些（`open_other`：拨出的连接、UDP 对端、TUN 设备），`open_accepted()` 即两者之差（akit
   的 A30）。accept 本来就会给 `open` 加一；设置了上限时还会读取同一缓存行上的 `open_other`，当
   `open` 减 `open_other` 达到上限时拒绝该连接。不设置时 accept 路径不变。关闭时归还打开时计入的
   数（每个后端都调用 `conn_closed(accepted)`）。

## 影响

- 在服务所用 engine 上拨号的应用可以单独限制客户端连接。
- 设置了上限时，accept 多一次 relaxed load，读的是 accept 本来就会写的缓存行；不设置时没有。
