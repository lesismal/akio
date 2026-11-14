# 故障排查与常见问题

## "slow callback: ... blocked its I/O thread"

某个回调运行超过了 `slow_callback_threshold`（默认 100 ms），同一线程上的其他所有连接都在
等待。从消息里（或 `Engine::slow_callbacks()`、调试端点的 `slow` 视图）找到回调类型和连接，
把阻塞部分移到 `spawn_blocking`、`Context::detach` 或其他线程。常见原因：同步的数据库或 HTTP
客户端、读文件、域名解析（`ToSocketAddrs`）、与其他线程争用的 `Mutex`、写往慢目标的日志、
大文件的静态文件缓存未命中。

## 同一线程上所有连接的延迟尖刺

原因同上，只是低于阈值。比较各线程的 `only_loop_callback_seconds_total`；热点连接无法迁移到
其他线程，可以考虑用 `Steering::Hash` / `Steering::Cpu` 控制放置，或把流量拆分到更多连接上。

## `Error::Overloaded`

来自 `send*`：该连接已经排队了 `max_queued_bytes`，对端读得不够快。暂停生产
（`queued_bytes()`、`on_drain`）或关闭它。来自 `spawn_blocking`：逻辑线程池队列已满。卸载负载
（HTTP 503），或者如果工作本来就是突发的，调高 `PoolConfig` 的上限。

## 保留下来的 `Conn` 返回 `Error::Closed`

连接已关闭（对端离开、空闲超时、出错）。这是停止的正常信号；句柄从不 panic，也从不碰到被
复用的描述符。

## 响应顺序乱了

混用了有序槽位和普通发送：`Conn::send` 不会排在已预留但未填充的 `ResponseSlot` 之后。有序
协议的每个回复都要用槽位。（only-http 已经替你这样做了。）

## 连接在一个请求后自己关闭了

- 某个 `ResponseSlot` 或 `ResponseStream` 未被填充/完成就被丢弃：only 会关闭连接，因为回复流
  无法继续。
- 某个 HTTP handler 既没有响应也没有 detach：客户端收到 500。
- 某个回调 panic：连接被关闭，`on_close` 收到该错误。在 HTTP 中使用 `middleware::recover()`
  把 panic 变成 500。

## `build()` 失败

- `listener without .serve(..)`：每个 listener 都需要一个 acceptor。
- `Address already in use`：另一个进程占用了该端口。给每个 TCP listener 使用自己的地址；同一
  端口号上的一个 TCP listener 和一个 UDP listener 没有问题（例如 443 上的 HTTP/1+2 和 HTTP/3）。
- `... is not supported`：在不支持的内核或平台上使用了 `strict` 的 io_uring 或 eBPF，或对 UDP
  使用了 `strict` 的 io_uring。

## 没有用上 io_uring

内核不支持（早于 5.19，或被 `kernel.io_uring_disabled` / seccomp 配置禁用，许多容器中就是
如此）：only 会记录 `io_uring unavailable (...); using epoll`。设置
`UringConfig::strict = true` 则改为报错。

## eBPF 分流显示 `Degraded`

不是 Linux、没有 `SO_REUSEPORT` socket 组（macOS，或单线程 listener），或程序无法挂载。经典
BPF 不需要特权；eBPF 程序需要 `CAP_BPF` / `CAP_SYS_ADMIN`。原因字符串会说明是哪一种。

## 没有日志输出

only 通过 `only::log` 记日志；请安装一个 logger（`only::log::init(only::log::LevelFilter::Info)`），
或开启 `log` feature 以使用 env_logger 等 `log` crate 的 logger。没有安装时只有错误和慢回调警告会打印（到
stderr）。访问日志需要 `observe::access_log()` 并启用 `only_http::access` target。

## 在 macOS 上测试或工具卡住

macOS 默认的 socket 缓冲区较小，单线程阻塞式测试客户端在读之前写太多数据时会死锁。在不同线程
上读写，或者循环读取。

## 常见问题

**only 是异步的吗？能和 tokio 一起用吗？** only 基于回调，没有运行时。它的句柄是
`Send + Sync`，客户端 future 可以在任何执行器里 await，工作也可以交给 tokio 并从那里答复。见
[从 tokio 迁移](migration/from-tokio.md)。

**连接能迁移到别的线程吗？** 不能。正是这一点让 handler 状态无需加锁。

**为什么我的 handler 不是 `Sync`？** 它不需要是：只有它自己的 I/O 线程会访问它。

**only 支持 Windows 吗？** 不支持（1.0 之前没有 IOCP 后端的计划）。

**支持 DPDK 吗？** 尚未支持，已在计划中（里程碑 M6）。

**如何在一个端口上同时提供 HTTP 和 HTTPS？** 使用 only-mux：`Rule::Tls` 路由到
`Tls::server(cfg, serve(app))`，`Rule::Http` 路由到 `serve(app)`。

**在代理之后如何获得客户端 IP？** `ctx.peer()` 是 TCP 对端；信任代理时自己读取
`X-Forwarded-For` / `Forwarded`。
