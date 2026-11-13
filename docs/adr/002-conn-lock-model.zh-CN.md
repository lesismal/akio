# ADR-002：Conn 句柄与锁模型

[English](002-conn-lock-model.md) | 简体中文

状态：已采纳（2026-11-13）

## 决定

`Conn<H>` 是基于 `Arc<ConnInner>` 的 `Clone + Send + Sync` 句柄。`ConnInner` 包含 generation id、所属 loop 的唤醒通道、原子状态位，以及 `Mutex<WriteState>`（发送队列、cork、水位、关闭状态）。

在 I/O 线程上，队列为空时 `send` 直接写，否则入队并注册可写事件；在其它线程上，`send` 加锁入队并唤醒所属 loop（eventfd / uring `MSG_RING`）。锁只保护发送队列，**持锁期间绝不调用用户代码**。对已关闭连接的操作返回 `Error::Closed`。

## 影响

- 跨线程 send/close 安全，且不向用户暴露 loop。
- 锁范围极小且不含回调，排除锁反转死锁；M1 用 `loom` 验证。
- generation id 防止对被复用的 fd/槽位误操作。
