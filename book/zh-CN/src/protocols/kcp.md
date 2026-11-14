# KCP

`flash-kcp` 在 UDP 上提供可靠、有序的消息，线路格式兼容
[skywind3000/kcp](https://github.com/skywind3000/kcp)，并兼容
[kcp-go](https://github.com/xtaci/kcp-go) 的 FEC 和加密（因此也兼容 kcptun 和 fib 的 kcp）。
与 kcp-go v5 针对六种加密/FEC 组合做过双向互通测试，其中包括经过一个每 7 个数据报丢 1 个的
中继（`tools/interop/kcp/run.sh`）。

## 服务端与客户端

```rust,ignore
{{#include ../../../../crates/flash-kcp/examples/guide-kcp.rs:server}}
```

```rust,ignore
{{#include ../../../../crates/flash-kcp/examples/guide-kcp.rs:config}}
```

```rust,ignore
{{#include ../../../../crates/flash-kcp/examples/guide-kcp.rs:client}}
```

- `KcpServer` 是一个 **UDP listener** 的 acceptor。每个开始会话的对端地址从工厂得到一个
  `Session` 和一个 `KcpHandler`；同一地址的新会话 ID 会替换旧会话。`max_sessions(n)` 限制会话
  数，`sessions()` 返回当前数量。
- `flash_kcp::dial(&engine, addr, cfg, handler)` 以随机会话 ID 发起客户端会话（用 `dial_conv`
  指定 ID）。engine 需要 `udp_client_threads(n)`。可以立即发送消息。
- `KcpHandler::on_message(&mut self, &Session, Vec<u8>)` 在 I/O 线程上按顺序收到完整的消息
  （流模式下是到达的任意字节）；`on_close(&Session, CloseReason)` 执行一次，原因为 `Closed`、
  `DeadLink`、`Replaced`（对端开始了新会话）或 `Transport`（其下的 UDP peer 已关闭：engine 的
  `udp_idle_timeout`、ICMP 错误、停机）。因此，空闲的 KCP 会话会在 `Config::udp_idle_timeout`
  （60 s）后结束，除非应用更频繁地发送保活消息。
- `Session`（可克隆，可在任何线程使用）：`send(msg)`（发送队列满时返回 `KcpError::Full`：排队
  或丢弃，永远不要在回调里等待）、`close()`、`conv()`、`remote_addr()`、`is_open()`、
  `wait_send()`、`stats()`（发送、重传、快速重传、丢失、FEC 恢复）。
- 会话由其 I/O 线程读到的数据报、一个共享的定时器线程（按 KCP 的 `next_flush` 调度）以及
  `send` 驱动。输出按需刷出。

## `Config`

两端应当在 KCP 参数上保持一致，并且**必须**在加密和 FEC 上保持一致。

| 字段 | 默认值 | 含义 |
|---|---|---|
| `nodelay` | 0 | 1 = 快速重传时序 |
| `interval` | 100 | 内部更新间隔，毫秒（10..=5000） |
| `resend` | 0 | 收到这么多重复 ACK 后快速重传（0 关闭） |
| `no_congestion` | false | 关闭拥塞控制 |
| `send_window`、`recv_window` | KCP 默认 | 以段为单位的窗口 |
| `mtu` | KCP 默认 | 最大数据报，含分帧开销（最大 1500） |
| `stream` | false | 流模式（不保留消息边界） |
| `dead_link` | 20 | 同一段传输这么多次后以 `DeadLink` 关闭 |
| `crypt` | 无 | `Crypt::new(name, key)`：`none`、`xor`、`aes`（32 字节密钥）、`aes-128`、`aes-192`、`aes-128-gcm` |
| `data_shards`、`parity_shards` | 0、0 | kcp-go 的 Reed–Solomon FEC（kcptun 用 10/3）；任一为 0 即关闭 |
| `write_queue` | 0 | 等待的段超过此数后 `send` 失败（0 = 发送窗口的两倍） |

`Config::fast()` 即 kcptun 的 "fast3"：nodelay、10 ms 间隔、2 次重复 ACK 后重传、无拥塞控制。
密钥按已派生的形式传入：kcptun 用 PBKDF2-SHA1 从口令派生（salt 为 `kcp-go`，4096 轮，32 字节）。
