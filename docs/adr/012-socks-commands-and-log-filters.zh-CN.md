# ADR-012：SOCKS5 BIND / UDP ASSOCIATE、`Engine::adopt_tcp` 与 only-log 过滤器

[English](012-socks-commands-and-log-filters.md) | 简体中文

状态：已接受（2026-11-16）

## 背景

`docs/DEV-PLAN.zh-CN.md` 中有两项未完成：

- `only-socks` 只支持 SOCKS5 `CONNECT`。`BIND`（主动模式 FTP 等需要对端回连的协议）和
  `UDP ASSOCIATE`（经代理的 DNS、QUIC、游戏）都回复“不支持的命令”。除用户名/密码外，也无法限制
  客户端能访问什么。
- `only-log` 有运行时最大级别和在代码里设置的按 target 上限，但不能从环境变量按 target 设置级别
  （env_logger 的 `RUST_LOG`），也不能把啰嗦的语句从 release 构建中编译掉（`log` crate 的
  `max_level_*` feature）。

`BIND` 需要在运行时打开一个 TCP 监听，并且接受到的连接要像其他连接一样由 engine 转发；而 engine
此前无法接管一个不是它自己 accept 或拨号得到的流。

## 决定

1. **`Engine::adopt_tcp(stream, acceptor, on_error)`**（位于 `only`）：把一个已连接的
   `std::net::TcpStream` 当作刚刚连上的拨号连接来服务，使用与 `dial` 相同的 I/O 线程。后端实现一个
   新的隐藏方法 `Group::adopt`（默认返回 `Unsupported`）；epoll 和 io_uring 的 group 让流走已有的
   拨号路径，已连接的流会立即打开（立刻可写、没有待处理错误）。不新增 reactor 代码。
2. **SOCKS5 `BIND` 与 `UDP ASSOCIATE`（RFC 1928），默认关闭。** `Socks::bind(bool)`、
   `Socks::bind_timeout(Duration)`（60 秒）、`Socks::udp_associate(bool)`、
   `Socks::udp_idle_timeout(Duration)`（120 秒）。默认关闭，因为两者都会应客户端请求在代理主机上
   打开端口；现有部署在显式开启前继续回复“不支持的命令”（回复码 7）。
   - **BIND**：在客户端连到代理的那个地址上（端口 0）监听，第一次回复带上该地址，接受一个连接
     （除非请求的地址未指定，否则只接受来自请求 IP 的连接），第二次回复带上对端地址，之后与
     `CONNECT` 一样做双向带背压的转发。accept 在一个短生命周期线程上每 10 毫秒轮询一次，这样不需要
     reactor 监听 API 也能察觉客户端离开和超时；BIND 很少见且只等一个连接，每个等待中的 BIND 一个
     线程是可以接受的。接受到的流通过第 1 点交给 engine。客户端在第二次回复之前发数据会关闭会话。
   - **UDP ASSOCIATE**：每个关联一个 UDP socket，通过 `Engine::bind_udp` 绑定在客户端连到代理的
     地址上，因此 engine 需要 UDP I/O 线程（`udp_client_threads`）；没有时请求得到回复码 1。规则：
     只有来自控制连接 IP 的数据报才算客户端的，并且端口一旦由请求或第一个数据报确定就只认这一个；
     FRAG 不为 0 的数据报被丢弃（RFC 1928 允许不支持分片的实现丢弃它们）；远端主机的应答只有当
     客户端曾向该地址发送过时才转发（依赖端点的过滤，关联不会成为一个开放的入站端口）；主机名
     目的地在逻辑线程池上解析并按关联缓存；关联随控制连接结束，或在空闲超时后结束，由每个 `Socks`
     一个的清理线程执行（随第一个关联启动，周期 250 毫秒，服务器及其会话都消失后退出）。
3. **访问控制：`Socks::allow(Fn(&Request) -> bool)`。** 在认证之后、任何拨号、绑定或解析之前，对
   每个命令调用：`CONNECT`（SOCKS5、4、4a）、`BIND`、`UDP ASSOCIATE`，以及关联数据报的每个不同
   目的地（每个关联对每个目的地判定一次并缓存）。`Request` 提供版本、客户端地址、用户（RFC 1929
   用户名或 SOCKS4 user id）、`Command` 和 `Dest`（地址，或尚未解析的主机名）。拒绝时 SOCKS5 回复 2
   （“规则集不允许”），SOCKS4 回复 0x5b，UDP 数据报被丢弃。`Command` 是 `#[non_exhaustive]`；
   `Request` 字段私有、通过访问器读取，二者都可以扩展。
4. **only-log 的 `Filter` 与 `init_from_env`。** `Filter` 保存一个默认级别和按 target 的级别，
   解析 env_logger 风格的指令（`info,only_http=debug,only_quic::conn=trace`）：`level`、
   `target=level`、`target`（即 trace）。与 env_logger 有两处不同，都继承自
   `FmtLogger::target_level`：target 只匹配自身和 `target::...`（而不是任意字符串前缀），以及与顺序
   无关、最长匹配者胜出。`/regex` 消息过滤会被拒绝。`init_from_env(default)` 只读取一次
   `ONLY_LOG`，安装带该过滤器的 `FmtLogger`，并把全局最大级别设为过滤器中最详细的级别；未设置时用
   `default`，无法解析时把原因打印到 stderr 并使用 `default`。**需显式调用**：不调用它就没有任何
   代码读取环境变量，`init` 和默认行为不变。`FmtLogger::filter` 和 `init_filtered` 接受在代码中
   构造的 `Filter`；自定义 logger 可以调用 `Filter::enabled`。
5. **编译期上限：`max_level_*` / `release_max_level_*` feature 与 `STATIC_MAX_LEVEL`**，名称和
   规则与 `log` crate 相同（release feature 在没有 `debug_assertions` 时生效并优先；同时开启多个时
   最严格者胜出）。宏的第一道检查变为 `level <= STATIC_MAX_LEVEL && level <= max_level()`；级别是
   字面量时第一项比较是常量，超出上限的语句被编译掉，不开启上限 feature 时代码不变。

## 后果

- 被禁用语句的开销不变：在 macOS 上，针对本改动构建的基准二进制与针对上一个提交构建的逐字节
  相同；在 x86_64（gpu51，安静主机，5 轮交替，取中位数）上，带 2 个键值对的禁用 `trace!` 为
  0.400 → 0.401 ns，`log_enabled!` 0.402 → 0.401 ns，启用的 `info!` 4.250 → 4.251 ns。开启
  `max_level_info` 后禁用的 `trace!` 被移除（0.199 ns，即基准循环本身）。
- Cargo feature 在整个依赖图中合并：库若开启上限会限制应用的所有 crate，因此文档规定只由应用开启。
  这 12 个 feature 不参与 CI 的 feature 幂集（否则规模扩大 4096 倍），由专门的测试覆盖。
- 若设置了 `Config::idle_timeout`，它也作用于 UDP 关联的控制连接，而关联使用期间控制连接上没有
  字节；两者同时使用的部署应调大它。
- 未实现：UDP 分片重组、SOCKS4 `BIND`、GSSAPI 认证、SOCKS 客户端、按关联限速、env_logger 的
  `/regex` 过滤器以及 `tracing` span。今后添加都是增量的。
