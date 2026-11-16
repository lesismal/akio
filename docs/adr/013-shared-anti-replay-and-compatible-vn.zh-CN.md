# ADR-013：共享的 0-RTT 防重放存储与 QUIC 兼容版本协商

[English](013-shared-anti-replay-and-compatible-vn.md) | 简体中文

状态：已采纳（2026-11-16）

## 背景

TLS 1.3 early data 与 QUIC 0-RTT 落地时留下两项：

1. **跨服务器的防重放。** 服务器记录每个被接受 early data 的 ClientHello 的 PSK binder
   （RFC 8446 第 8.2 节），已见过的 ClientHello 的 early data 一律拒绝。这份记录原本在每个
   `ServerConfig` 里。接受同一批票据的多台服务器（`SO_REUSEPORT` 后的多个进程、负载均衡后的多台
   机器）各有一份，发往其中一台的首个飞行可被截获后重放到另一台，并在那里被接受。何况这些服务器本来
   也无法共享票据：每个配置都用自己随机生成的密钥封装票据。
2. **兼容版本协商**（RFC 9368 第 4 节）。only-quic 支持 QUIC v1 与 v2，也发送并校验
   version_information 传输参数，但服务器总是用客户端的版本应答：把客户端换到另一个版本需要一次
   Version Negotiation 往返。

## 决定

### 防重放存储（only-tls）

1. 一个小的公开 trait，在握手路径上调用：

   ```rust
   pub trait AntiReplayStore: Send + Sync {
       fn check_and_insert(&self, binder: &[u8], ttl: Duration) -> io::Result<bool>;
   }
   ```

   `binder` 是 ClientHello 的第一个 PSK binder（32 或 48 字节，是对 ClientHello 的 HMAC：唯一且
   不可预测，可直接作键）；`ttl` 为新鲜度窗口的两倍（20 秒）。`Ok(true)`：首次出现，接受 early
   data；`Ok(false)`：已见过（或存储已满），拒绝。新鲜度检查（票据年龄误差 10 秒内）仍在服务器内且
   先执行，因此存储只会看到新鲜的 ClientHello，超过 TTL 的键不可能再被接受。
2. **失败即关闭（fail closed）。** 返回 `Err` 时拒绝 early data。握手继续以 1-RTT 恢复完成，客户端
   之后重发同样的数据；存储故障只多花一个往返，不会丢连接，也绝不会接受未经检查的重放。
3. **默认实现：`MemoryAntiReplay`**，即原有的有界窗口（10 万条，满则拒绝），现公开，应用可以包装或
   复用。不使用新选项时行为不变。
4. **构建器选项**：`ServerConfigBuilder::anti_replay_store(Arc<dyn AntiReplayStore>)` 与
   `ServerConfigBuilder::session_ticket_key([u8; 48])`（16 字节密钥名 + 32 字节 ChaCha20-Poly1305
   密钥；同时开启会话票据）——没有共享票据，共享存储也就无从谈起。密钥轮换由调用方负责（构建新配置），
   旧密钥签发的票据随后走完整握手。QUIC 服务器经由其 `only_tls::ServerConfig` 获得这两项。
5. **刻意保持同步。** TLS 核心是 sans-io 的，运行在连接的 I/O 线程上。异步存储需要在 TLS 与 QUIC 中
   为一次查询引入挂起的握手状态；因此 trait 是同步的，文档要求实现保持简短并设超时。只有本会接受
   early data 的 ClientHello（已恢复、新鲜、票据匹配）才会查询存储，所以其负载是 0-RTT 的速率，
   而不是连接速率。

**用 Redis（或 memcached、数据库）实现**：每次调用一条原子命令，

```text
SET only:0rtt:<binder 十六进制> 1 NX PX <ttl 毫秒>  ->  "OK"：Ok(true)   nil：Ok(false)
超时 / 连接错误                                     ->  Err(..)：拒绝 early data
```

客户端设较短超时（局域网内几毫秒）并自带连接池。本书 TLS 章节有示意代码；测试用一个可切换为失败的
内存“远程”存储。

### 兼容版本协商（only-quic）

1. **服务器端选择开启**：`ServerConfig::prefer_version(Version)`。默认无：服务器照旧用客户端的版本
   应答。偏好 v2 的服务器把 v1 客户端换到 v2，偏好 v1 的把 v2 客户端换到 v1（两者双向兼容，RFC 9369
   第 4.1 节）。默认不开启，因为切换后的效果取决于客户端 v2 实现的质量：例如 quic-go 用 v1 的标签推导
   v2 的密钥更新密钥，被切换后会在第一次密钥更新时失败（它不会被切换：它不发送 version_information）。
2. **何时切换**：仅当客户端的 version_information 在可用版本中列出了偏好版本（且其所选版本就是它起始
   使用的版本）。不发送 version_information 的客户端永远不会被切换。
3. **服务器如何做**：在整个 ClientHello 到齐之前（最多 16 KiB；ClientHello 可能跨多个 Initial 包），
   服务器暂不把 Initial 的 CRYPTO 数据交给 TLS，读出其传输参数（`only_tls::quic::client_hello_transport_params`，
   隐藏 API）；若切换，则装上新版本的 Initial 密钥，保留旧密钥以读取客户端首个版本的 Initial（以及
   0-RTT）直到 Initial 空间被丢弃，并以把新版本作为所选版本的 version_information 启动 TLS。此时 TLS
   尚未作出任何应答，因此没有额外往返，也无需回滚 TLS 状态。没有偏好的服务器不会暂存任何数据。
4. **客户端如何做**：握手中的客户端收到自己支持的另一版本的 Initial 时，若该包能用新版本的 Initial
   密钥解密就切换过去（否则撤回，伪造的包无法让它切换）。其 0-RTT 包保持首个版本（RFC 9369 第 4.1
   节）。双方按 RFC 9368 校验 version_information：服务器对照客户端的首个版本，客户端对照当前使用的版本。
5. **互通**：ngtcp2 实现了 RFC 9368；其示例客户端与服务器（在 Docker 中由 Debian 源码包构建，
   `tools/interop/quic/ngtcp2-cvn.sh`）与 only-quic/only-h3 双向切换成功，含 0-RTT。quic-go 未实现
   （不发 version_information，丢弃其他版本的包）：`tools/interop/quic/run.sh` 检查它的客户端在偏好
   另一版本的服务器上保持原版本。

## 影响

- 公开 API（仅新增）：only-tls 的 `AntiReplayStore`、`MemoryAntiReplay`、
  `ServerConfigBuilder::anti_replay_store`、`ServerConfigBuilder::session_ticket_key`；only-quic 的
  `ServerConfig::prefer_version`。`api/` 中的快照已更新。
- 共享存储的防重放强度取决于存储的原子性：对同一个键两次回答 `Ok(true)` 的存储（先读后写的非原子实现、
  跨区域复制延迟）会放过重放。按区域分别部署存储并按区域签发票据可避免复制延迟。
- 慢的存储会拖慢该 I/O 线程上的 0-RTT 握手；失效的存储关闭的是 0-RTT，而不是服务。
- ClientHello 预读只在设置了偏好的服务器上多一次客户端 Initial CRYPTO 数据的拷贝。线路上可见“以 v1
  Initial 开始、以 v2 继续”（按设计如此）。
- 未做：异步存储接口；多把有效密钥并存的票据密钥轮换。
