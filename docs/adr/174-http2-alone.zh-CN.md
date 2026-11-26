# ADR-174：只服务 HTTP/2 的 HTTP 服务端

[English](174-http2-alone.md) | 简体中文

状态：已采纳（2026-11-26）。akit 的 A168。

## 背景

akio-http 的服务端在连接以客户端 preface 开头（prior knowledge，或 TLS 协商 ALPN `h2`）或收到
`Upgrade: h2c` 请求时使用 HTTP/2，其他情况一律按 HTTP/1 处理。`HttpConfig::h2: None` 可以关闭
HTTP/2，却没有办法关闭 HTTP/1。fit 中 `protocols: [h2c]` 的 listener 只以 prior knowledge 服务
HTTP/2（fib 的 mux 只匹配 preface，其余连接关闭），gRPC listener 和 fit 基准配置的 h2c 端口都是如此。

## 决定

1. **`HttpConfig::http1: bool`**，默认 `true`。为 `false` 时，前几个字节偏离客户端 preface 的连接
   一旦出现不同的字节，就收到带 `PROTOCOL_ERROR` 的 `GOAWAY`（与原本对把 preface 写错的 HTTP/2
   客户端的回应相同）并被关闭；不会读取任何 HTTP/1 请求，因此也不接受 `Upgrade: h2c`。分多次读到的
   preface 仍会开启 HTTP/2。
2. 同时 `h2: None` 时什么都不服务：每个连接在收到第一份数据时关闭。

## 影响

- listener 可以像 fit 的 `[h2c]` 一样只服务 h2c，对 HTTP/1 客户端的回应也相同。
- 在 TLS 上，协商了 `http/1.1` 的客户端同样收到 `GOAWAY`；只服务 HTTP/2 的 TLS listener 应只在
  ALPN 中提供 `h2`。
