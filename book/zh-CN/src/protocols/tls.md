# TLS

`flash::tls`（即 `flash-tls` crate）以 sans-io 方式运行 [rustls](https://docs.rs/rustls)，作为
连接之下的一个 **transport 层**。包装任意 acceptor 之后，它的 handler 看到的都是明文：
`on_data` 收到解密后的字节，`Conn::send*` 自动加密。

## 服务端

```rust,ignore
{{#include ../../../../crates/flash/examples/guide-tls.rs:server}}
```

## 客户端

```rust,ignore
{{#include ../../../../crates/flash/examples/guide-tls.rs:client}}
```

`Tls::client(config, server_name, acceptor)` 以 `server_name` 校验服务端证书并把它作为 SNI
发送。名字不是合法的 DNS 名或 IP 地址时返回错误。

两者都可以用 `cargo run -p flash --example guide-tls` 运行。

## 工作方式

- 握手在连接所属的 I/O 线程上进行，与其他连接交错执行，从不阻塞。
- 握手完成前发送的数据（例如在 `on_open` 里发送的）会被暂存，握手一完成就刷出。
- `close_after_send()` 在排队的数据之后发送 `close_notify`。
- 握手失败或收到坏记录时，先刷出 alert 再关闭连接；握手阶段的失败
  （`flash_tls_handshake_failures_total`）和之后的失败（`flash_transport_errors_total`）分别计数。
- 记录按不超过一个 TLS 记录的大小分段封装，所以大块发送没有问题。
- 连接表中显示 `transport: "tls"`。

## 协商结果

`tls_info(&conn)` 返回 `TlsInfo`，包含 `handshaking`、`alpn`、`server_name`（SNI，仅服务端）
和 `version`；非 TLS 连接返回 `None`。

## 配置

一切都通过 rustls 自己的 `ServerConfig` / `ClientConfig` 配置，它们以 `flash::tls::rustls`
重新导出：

| 需求 | rustls 设置 |
|---|---|
| 证书链与私钥 | `with_single_cert(chain, key)` |
| 按 SNI 选择多张证书 | `with_cert_resolver(..)`（`ResolvesServerCert`） |
| ALPN（`h2`、`http/1.1`、自定义） | `config.alpn_protocols` |
| 会话恢复 | `config.ticketer`、`config.session_storage` |
| 客户端证书 | `with_client_cert_verifier(..)` / `with_client_auth_cert(..)` |
| 协议版本 | `builder_with_protocol_versions(..)` |

编译时内置 `ring` 加密实现。加载 PEM 文件由你自己负责（例如使用 `rustls-pemfile` 或
`rustls::pki_types::pem`）。

## 与其他 crate 配合

- flash-http：`Tls::server(cfg, serve(app))`。设置 `alpn_protocols = [h2, http/1.1]` 后，同一个
  listener 会为协商了 `h2` 的客户端提供 HTTP/2。
- flash-ws 客户端：`wss://` 使用 `DialOptions::tls`。
- flash-http 客户端：`Client::with_tls(cfg)`、`H2Client::connect(.., Some((cfg, name)), ..)`。
- QUIC 与 HTTP/3 在 QUIC 内部使用 TLS 1.3：见 `flash_quic::server_config` 等函数。

## 尚未完成

kTLS 卸载；rustls 直接提供的能力之外的 TLS 1.3 early data 与客户端证书辅助功能。

## 编写自己的 transport

`flash_core::Transport` 就是 TLS 实现的 trait：`recv(cipher, plain, out)`、
`seal(plain, out)`、`shutdown(out)`，外加 `name` 和 `handshaking`。从 `Acceptor::transport`
返回一个实现，就能在连接之下叠加任意字节流变换。所有调用都在连接的写锁下按线路顺序进行，
不能阻塞。
