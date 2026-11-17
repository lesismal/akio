# ADR-023：arpc 中间件、coder 与客户端连接池

[English](023-arpc-middleware-coders-pools.md) | 简体中文

状态：已采纳（2026-11-17）

## 背景

`only-arpc` 已实现 Go arpc 的线路格式（调用、通知、stream、广播、重连），但缺少 Go arpc 应用常用的
三样东西（DEV-PLAN M4 中的"未做"）：

- **中间件**（`Handler.Use`）：在 handler 外层做认证、日志、计时、恢复；
- **coder**（`Handler.UseCoder`、`MessageCoder`）：对整帧做变换，实际使用的是
  `arpcex/extension/middleware/coder` 的 gzip（保留字节第 7 位）和值追加器（tracing，第 0 位），
  后者把消息 `Values` 中的一个值带给对端；
- **客户端连接池**（`ClientPool`）：到同一服务端的多个连接。

Go 的 `Use` 依赖注册顺序：中间件在其后注册的 handler 之前执行，却在其前注册的 handler **之后**
执行，并且除非调用 `Abort`，会自动继续调用链。Go 的 gzip coder 解压没有上限。Go 的
`ClientPool.Next` 是共享原子计数的轮询，不考虑负载，也察觉不到沉默的连接。docs/rules.md 要求
中间件链在构建时完成（规则 11）、每次调用不碰共享计数器（规则 12）、解压有上限（规则 6）、每张表
都有安全的默认上限（规则 10），而等待应答的调用表此前没有上限。

## 决定

`only-arpc` 中新增的 API（`CallError` 新增一个变体；该枚举是 `#[non_exhaustive]`）：

- **中间件**：`Routes::middleware(Fn(&mut Context, Next))`（所有请求和通知，包括未知方法）与
  `Routes::method_middleware(method, ...)`。顺序固定，与注册先后无关：先按添加顺序执行全局
  中间件，再执行该方法的中间件，最后是 handler（或 `METHOD_NOT_FOUND`）。`Next::run(self, ctx)`
  执行剩余部分；其后的代码即"handler 之后"；不调用它直接返回即中止（显式的 `next`，与
  tower/axum 相同，而不是 Go 的隐式继续加 `Abort`）。`Next` 借用不可变 `Routes` 中的切片：每条
  消息既不分配内存也不增减引用计数；没有中间件时直接调用 handler。新增 `Context::values` /
  `values_mut` / `responded`。stream 没有中间件，与 Go 相同。客户端的 `Routes` 处理其服务端发来
  的调用，因此同一条链就是客户端中间件；Go 没有针对发出调用的中间件，这里也没有。
- **Coder**：`pub mod coder`，`trait Coder { encode(&mut Vec<u8>, &Values); decode(&mut Vec<u8>,
  &mut Values, max_body) -> Result<(), CoderError> }` 作用于整帧，用 `Routes::coder(c)` 添加；
  发送时按添加顺序编码，接收时逆序解码（与 Go 相同）。每个 coder 之后自动修正 body 长度；解码后
  body 超过 `max_body_bytes` 或解码出错都会关闭连接；ping 和 pong 不经过 coder。内置：
  `Gzip::new(threshold)`（第 7 位，与 Go 一样压缩第 5 字节起的内容；解压量受 `max_body_bytes`
  限制，借助 `only_deflate::decompress` 的上限，压缩炸弹最多耗费该上限）与
  `Appender::new(name, bit)`（Go 追加器的布局：名字、值、2 字节大端长度；在 Go 会 panic 的地方
  做严格的长度检查）。`Values` 是一个小的字符串 → 字节映射（基于 `Vec`，为空时零开销）。调用用
  `Peer::call_with` / `call_async_with` / `notify_with` 携带值；应答用请求的值编码，与 Go 相同。
  连接配置了 coder 时，解码器输出原始帧（`Decoder::feed_frames`），使经过编码的头部（gzip 会替换
  cmd 字节）不会在解码前被拒绝；没有 coder 时走原来的路径，不变。
- **等待应答的调用有上限**：`Routes::max_pending_calls(n)`，默认每连接
  `DEFAULT_MAX_PENDING_CALLS` = 65536；超出的调用立即以 `CallError::Overloaded` 失败且不发送。
  新增 `Peer::pending_calls()`（每连接一个原子量，在已有的锁内写入）与 `Peer::ping()`。
- **连接池**：`Pool::builder()` → `PoolBuilder { size（4）、balance、heartbeat（15 秒）、
  reconnect_interval（1 秒）、connect_timeout（10 秒） }.dial(engine, addr, routes)`；所有连接都
  必须建立，否则拨号失败并关闭其余连接（与 Go 相同）。`Balance::RoundRobin`（默认；每线程游标，
  无共享计数器）或 `Balance::LeastPending`（`pending_calls` 最少，相同则轮流）。跳过断开的连接
  （每个 peer 一个 `connected` 标志，无锁）；全部断开时调用立即以 `Closed` 失败。心跳每个间隔
  ping 一次，某次 ping 在一个间隔内没有收到任何数据的连接会被关闭，由重连替换。
  `Pool::{peer, peers, connected, call, call_with, call_async, notify, close}`。

互通：`tools/interop/arpc/run.sh` 除原有检查外，还用 fib 的 Go arpc 服务端和客户端（带 arpcex 的
gzip 与追加器 coder，移植到 fib 的 `MessageCoder`，位相同，以及一个拒绝缺少 trace 值的调用的 Go
中间件）对接配置了相同 coder 链、并有同样功能的 Rust 中间件的 only-arpc 服务端和连接池，双向检查；
两端都统计自己解压的压缩帧数。模糊测试：新目标 `arpc_coders`（帧 → coder 链 → 解析，切分无关性、
解码大小上限、编码/解码恒等）。

## 考虑过的其他方案

- **Go 的 `Use` 语义**（隐式继续、`Abort`、依赖注册顺序）：不采用；显式的 `Next` 更不易误用，
  也直接表达了前/后。中间件只在本地生效，不影响 Go 对端。
- **带类型（`Any`）的值**：Go 的是 `map[any]any`；只有字节能上线路，带类型的扩展需要第二张表。
  需要带类型状态的中间件可以把它放在自己的闭包里。
- **coder 作用于 `Message` 而不是字节**：Go 的 coder 改写原始缓冲区，包括头部字节（gzip 会压缩
  cmd 和序号），只有字节级接口才能兼容。
- **共享原子计数的轮询**（Go）：违反规则 12，不采用；每线程游标对单个调用者同样均匀，对多个调用者
  更好。

## 影响

- 只新增 API；已有程序不变，只是一个连接上超过 65536 个等待应答的调用现在会以 `Overloaded`
  失败（可用 `max_pending_calls` 调大）。
- gpu51 上的同轮 A/B（`arpc-bench 8 64 5 64`）：数字见提交与 CHANGELOG；无中间件时与 main 持平，
  一个直通中间件的开销为几个百分点。
- `only-arpc` 现在依赖 `only-deflate`（workspace 内部，不涉及 ADR-005）。
