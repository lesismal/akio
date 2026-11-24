# ADR-118：请求的对端是受信任 PROXY 头所指的客户端

[English](118-http-peer-from-proxy-header.md) | 简体中文

状态：已采纳（2026-11-24）

## 背景

ADR-095 为 akio-mux 加了监听层 `proxy::ProxyProtocol`：它从受信任的对端读取 PROXY 协议头（v1
或 v2），挂到连接上，再把其余数据交给下一个 acceptor。它没有改 `Conn::peer_addr`，akio-http
仍把套接字的对端作为请求的地址：“在那里使用 `proxy::client_addr` 留给应用或以后的改动”。

应用自己做不到这一点：请求处理函数只看到 `Request::peer` 与 `Context::peer`，看不到连接，因此
拿不到挂在连接上的头。akit（基于 akio 的网关）像 fit 一样在负载均衡器后面提供 HTTP 监听器，此时
受信任的头所指的客户端就是请求的客户端：它的 `X-Forwarded-For`、访问日志、`remote_ip` 匹配、
限流与 `ip_hash` 负载均衡都读 `Request::peer`。akit 以 A105 提出了这一需求
（`akit/docs/akio-api-requests.zh-CN.md`）。

## 决定

akio-http 用 `akio_mux::proxy::client_addr(conn)` 填 `Request::peer`：PROXY 层挂上的头若给出了
地址，就是它的源地址，否则与以前一样是套接字的对端。连接的 span 用同一个地址，HTTP/2 会话（预先
知晓、经 TLS、或经 `h2c` 从 HTTP/1.1 升级）也把它交给各个流的请求。

- 没有关闭它的选项。只有服务端放在 akio-http 前面的 `ProxyProtocol` 层才会挂上头，而且只对其
  `trusted` 检查接受的对端：装了这一层的服务端要的正是它读出的地址。不给出地址的头（`PROXY
  UNKNOWN`、v2 `LOCAL`、未指定或 Unix 地址族）保留套接字的对端。
- `Conn::peer_addr` 与 `RawConn::peer_addr` 不变（ADR-095）：需要这一跳自身地址的代码仍可从连接
  取得。
- akio-http 依赖 akio-mux，后者只依赖 akio-core。akio-mux 对 akio-http 的 dev-dependency 只构成
  经由 dev-dependency 的环，Cargo 允许这样。
- 代价是每个请求读一次连接的一次性附件（`OnceLock::get`）并做一次类型检查；没有附件的连接只付
  `get` 的代价。

## 影响

- 在受信任的负载均衡器后面，akio-http 应用无需自己读头就能看到客户端地址。
- 测试（`crates/akio-http/tests/proxy_peer.rs`）：HTTP/1.1、预先知晓的 HTTP/2、`h2c` 升级与
  HTTPS（头在 TLS 之前）上取头的源地址；v1 `UNKNOWN`、v2 `LOCAL` 与不受信任的对端取套接字的对端。
  epoll 与 io_uring。
- akio-h3 不变：QUIC 上不会有 PROXY 头（ADR-095）。
