# ADR-123：握手之外使用的根证书，以及仅用于握手的 ALPN 协议

[English](123-root-store-and-handshake-only-alpn.md) | 简体中文

状态：已采纳（2026-11-25）

## 背景

akit（基于 akio 的网关）向 akio-tls 提了两项需求（`akit/docs/akio-api-requests.md`）：

- **A57。** fit 只在证书链能对系统根证书验证通过时，才为来自文件的证书装订 OCSP 响应，
  免得别人给的证书（租户的 Kubernetes Secret）让网关去访问它指定的响应方。akit 用
  akio-x509 的 `Verifier` 验证证书链，它接受一个 `RootStore`；`RootCerts::system()` 会加载
  系统根证书（ADR-010、ADR-059），但其存储是私有的，只有握手能用。
- **A58。** 通过 TLS-ALPN-01（RFC 8737）获取证书的监听器在 ALPN 中提供 `acme-tls/1`。
  协商到它的连接只为握手：CA 读到挑战证书就离开。fit 在握手完成后关闭它；akio-http 靠前言
  识别 HTTP/2，不把 TLS 连接的任何信息交给服务，于是会处理在这种连接上发来的 HTTP/1 请求。

## 决定

- **`RootCerts::store(&self) -> &akio_x509::RootStore`** 与 **`From<RootCerts> for
  RootStore`**：把根证书交给调用者自己的 `Verifier`，系统根证书也一样。
- **`ServerConfigBuilder::handshake_only_alpn(protocols)`**：`Tls::server` 的连接若协商到
  其中之一，握手完成即关闭。传输层在每次 `recv` 后检查协商结果（它随 ClientHello 选定）：
  解出的应用数据被丢弃，不会到达处理器（包括 TLS 1.3 早期数据）；握手完成后，它在输出中追加
  `close_notify` 并以 `ErrorKind::ConnectionAborted` 失败，引擎在关闭前把输出发出
  （`Transport` 的约定）。握手计为完成。默认为空。

ALPN 的选择放在 TLS 设置里，而不是 akio-http（需求中另外的建议：`Context::tls()` 或
`HttpConfig` 字段）：它能关闭握手后什么都不发的连接（CA 的连接正是如此），而服务要等到数据
到来才会知道；它也不给请求增加任何开销（akio-http 的 `size_tests` 预算不变）。

## 影响

- akit 的 OCSP 装订对来自文件的证书，在自己的线程上对 `RootCerts::system()` 的存储验证，
  与 fit 相同；使用 TLS-ALPN-01 或按需 TLS 的 akit 监听器把 `acme-tls/1` 列为仅握手协议。
- 测试：`config_tests::roots_verify_a_chain_outside_a_handshake`（对只有一个根的存储验证
  证书链，借用与拥有两种方式，且对系统根证书验证失败）；
  `akio-http/tests/tls_handshake_only.rs`（协商 `acme-tls/1` 的客户端在握手后被关闭，无论它
  发不发请求，请求都不会被处理；同一监听器上协商 `http/1.1` 的客户端照常得到服务），
  在 epoll 与 io_uring 上。
