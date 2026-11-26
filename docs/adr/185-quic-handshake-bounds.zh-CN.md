# ADR-185：QUIC 服务端的握手限制

[English](185-quic-handshake-bounds.md) | 简体中文

状态：已采纳（2026-11-27）。akit 的 A245。

## 背景

一次 QUIC 握手让服务端付出一个连接的状态、一次 TLS 握手（一次签名）以及最多三倍于所收字节的发送量，
而换来这一切的只是一个 Initial：发送方几乎不付代价，地址还可能是伪造的。fit 的隧道 hub 限制握手能占用
的资源：`handshake_timeout`（10 秒）丢弃未按时完成握手的连接；`max_handshakes`（64）限制进行中的握手数：
超过一半后，客户端须先用 Retry 证明自己的地址，使来自伪造地址的 Initial 最多占一半；全部占满后，新客户端
的 Initial 被丢弃（它会重发，等有握手结束后进入）。akit 的 hub 基于 akio-quic，需要同样的能力。akio-quic
已有 `ServerConfig::max_connections`（所有连接，超出以 `CONNECTION_REFUSED` 拒绝），以及进行中的握手达到
固定的 4096 个时发送 Retry（另有一个隐藏开关可总是发送），但握手耗时除了空闲超时之外没有限制，而客户端
发来的每个包都会刷新空闲超时。

## 决定

1. **`ServerConfig::max_handshakes(n)`**（默认 `DEFAULT_MAX_HANDSHAKES`，8192；`usize::MAX` 表示不限；
   0 视为 1）。端点本就统计进行中的握手（从新连接创建到其 `HandshakeDone` 或 `Drained` 事件，服务器的
   各个克隆共享）。对于新客户端的 Initial，在接入过滤器和 `max_connections` 之后：达到 `n` 时丢弃，不保留
   任何状态、不发送任何内容，并计入 `QuicServer::refused_connections()`；从 `n / 2` 起，没有有效令牌
   （Retry 的或 NEW_TOKEN 的）的客户端收到 Retry，与之前从 4096 起相同。默认值保持原来的阈值（8192 的
   一半），并在其上增加上限。选择丢弃而不是 `CONNECTION_REFUSED`：这种过载是短暂的（一次握手只需几毫秒），
   客户端自己的重传会在有空位时让它进入，与 fit 的监听一致；服务器满载时仍由 `max_connections` 以
   `CONNECTION_REFUSED` 拒绝。
2. **`ServerConfig::handshake_timeout(Option<Duration>)`**（默认 `DEFAULT_HANDSHAKE_TIMEOUT`，10 秒；
   `None`：只受空闲超时限制）。服务端连接创建时设定截止时间，握手被确认时清除（`confirm`，它同时通知
   端点）；它是 `poll_timeout` 中多出的一个定时器，到期时连接立即进入 drained 状态，不发
   `CONNECTION_CLOSE`，与空闲超时相同：handler 的 `on_close` 收到 `TimedOut`，端点忘记该连接，并释放它在
   `max_handshakes` 中的位置。这是关于时间的定时器，不是重试。仅为服务端设置（见“未做”）。
3. **不新增计数器。** 被丢弃的 Initial 计为被拒绝（客户端重发会再次计数）；`refused_connections` 的文档
   写明两种情况。

## 影响

- akit 的 hub 把其 QUIC 监听的 `handshake_timeout` 和 `max_handshakes` 映射到这两个设置上，在自己的配置中
  使用 fit 的默认值（10 秒、64）；握手之后连接在没有链路流的情况下能保持多久，仍由 akit 自己负责（自己的
  定时器，如同 fit 的 `streamWait`）。
- 行为变化：服务端的握手现在默认 10 秒后结束（之前只有 30 秒的空闲超时，而客户端每个包都会刷新它）；
  进行中的握手超过 8192 个时，新客户端需要等待，而不是全部接收。
- 代价：每个新客户端 Initial 多一次比较，服务端连接在握手确认之前定时器中多一个截止时间；之后每个包没有
  任何额外开销。DEV-PLAN 第 4 节写明了基准任务应测量的内容。
- 测试：akio-quic 的模拟（`handshakes_bounded_with_retry_past_half`：不到一半时直接进入，从一半起先 Retry
  再进入，达到上限时不作应答地丢弃，握手结束后重新有空位；`handshake_timeout_drops_a_stalled_handshake`：
  2 秒超时下停滞的握手在 2 到 4 秒之间以 `TimedOut` 结束，已完成的握手超过该时间后仍保留），以及
  `tests/limits.rs` 中经由会让握手停滞的 UDP 中继进行的测试（停滞的握手在超时内消失，已完成的保留，没有
  超时设置时不丢弃；`max_handshakes(2)` 下第二个客户端收到 Retry，第三个客户端等到停滞的握手超时后才进入，
  并计为被拒绝）。
- 未做：单独统计超时的握手（它们与空闲连接一样以 `TimedOut` 结束）；对无效的 Retry 令牌回应
  `INVALID_TOKEN`（仍与之前一样丢弃）；客户端的握手超时。
