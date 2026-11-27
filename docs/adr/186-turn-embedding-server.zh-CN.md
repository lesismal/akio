# ADR-186：供嵌入它的服务器使用的 akio-turn

[English](186-turn-embedding-server.md) | 简体中文

状态：已采纳（2026-11-27）。akit 的 A256；A257（更新 1）；A258（更新 2）。

## 背景

akit 的 TURN 角色（`webrtc.turn`）运行 akio-turn 的 `TurnServer`，使用的是 fit 的角色交给 pion/fib TURN
服务器的那些设置。其中三项在 akio-turn 中没有对应：`port_min`..`port_max`，中继套接字绑定的端口范围（服务器
前面的防火墙开放的范围；fit-examples 的 `webrtc-turn` 设为 49152-49999）；`nonce_secret`，生成 nonce 的密钥，
同一负载均衡器后面的多台服务器共用它，使每台都接受其他服务器发出的 nonce；`max_stream_message`，TCP 或 TLS
客户端可以发送的最大消息，它限制了连接为尚未完整的消息保留的字节（fit 默认 8 KiB）。akio-turn 把每个中继绑定在
`relay_ip` 的 0 端口上，用每台服务器自己的随机字节作为 nonce 密钥、以服务器启动时刻为起点计算有效期，并接受
最长 64 KiB 的流消息。akit 拒绝端口范围，并对另外两项给出“未生效”的警告。

## 决定

1. **`TurnConfig::relay_ports: Option<(u16, u16)>`**（`relay_ports(min, max)`，顺序不限，0 端口从不在内；
   默认 `None`，由内核选择端口）。`TurnServer` 绑定 0 端口的中继时，与 fib 一样从范围内一个随机端口开始依次
   尝试，使刚释放的端口（对端可能仍在向它发送）不会马上再分配出去：自己的中继占用的端口不经系统调用即被跳过
   （查中继表）；其他套接字占用的端口在绑定以 `AddrInUse` 失败时跳过（UDP 中继不设 `SO_REUSEPORT`，内核会如实
   报告）。其他错误结束查找（无法绑定的地址在每个端口上都会失败）。范围用尽是环境的 `open_relay` 的错误，核心
   以 508 应答，与此前绑定失败时相同。指定端口的中继（`EVEN-PORT` 在偶数端口之上预留的奇数端口）必须在范围内。
   `EVEN-PORT` 仍会多次尝试以得到偶数端口，每次都从范围中取。TCP 分配（RFC 6062）的监听套接字也使用该范围；
   它们设了 `SO_REUSEPORT`（到对端的连接从中继地址发出），这会让监听与另一个同样设了该选项的套接字共享端口，
   因此每个端口先用不带该选项的绑定探测一次。两种地址族使用同一个范围。
2. **`TurnConfig::nonce_secret: Option<Vec<u8>>`**（`nonce_secret(&[u8])`）。nonce 密钥由它派生（以固定标签
   对密钥做 HMAC-SHA-256），未设置时仍为随机。要让服务器互相接受对方的 nonce，nonce 就不能再依赖具体的服务器：
   其有效期现在以 UNIX 秒表示（服务器启动时的挂钟秒数加上此后的单调时间，因此启动后的时钟跳变不会影响它），
   校验时使用同一时钟。格式不变（16 位十六进制的有效期，16 位的 HMAC-SHA-1，覆盖有效期与客户端地址）；各服务器
   的时钟需要在几秒内一致。`Debug` 不显示该密钥。
3. **`TurnConfig::max_stream_message: usize`**（默认 `framing::MAX_FRAME`，即 TURN 能承载的任何消息，不设置时
   行为不变）。`framing::FrameReader::with_max(n)` 一旦读到消息头，若其声明的长度超过 `n` 字节（含填充），就以
   新增的 `FrameError::TooLong` 拒绝，因此读取器最多保留 `n` 字节；流接入器的读取器使用该设置，读取器出错的
   连接被关闭，与非 TURN 的流相同。akio-turn 不会抬高过小的值：akit 像 fit 一样检查它接受的下限（2048）。

## 影响

- akit 在成员配置的范围内绑定中继，并去掉其拒绝与两条警告。
- 设置范围后，每次 Allocate 对被其他套接字占用的每个端口付出一次绑定，范围用尽时最多为范围大小；被服务器
  自己的中继占用的端口只需一次哈希查找。
- 旧版服务器的 nonce（有效期从其启动时刻算起）会被视为早已过期：持有它的客户端收到一次 438 和新的 nonce，
  与任何一次重启之后相同。

## 更新 1：供嵌入的服务器使用的钩子（A257）

fit 的角色通过 fib 的 `OnRelay` 限制每个用户名每秒在每个方向上中继的字节数（`user_bandwidth`，每个用户名
每个方向一个令牌桶，超出的数据报被丢弃）；对 fib 的 `OnEvent` 计数并记录日志（分配、刷新、释放及原因、带错误码
的拒绝、凭据失败）；并通过 fib 的 `HoldsRelay` 只允许经由其中继端口访问其自身地址上的对端，使两个客户端可以
互相中继，但任何人都不能经由中继访问服务器的其他监听。akio-turn 的对端过滤器只看到对端，没有针对每个中继数据报
或每个事件运行的回调，`TurnStats` 只统计分配数与数据报数。

1. **`TurnConfig::on_relay`**（`RelayHook`，`Fn(&str, bool, usize) -> bool`）：分配的用户名、是否发往对端、
   负载长度（对端的数据报、indication 的 `DATA`、ChannelData 的应用数据）；返回 false 则丢弃该数据报。它在许可、
   信道、对端策略与 TTL 都放行之后、数据报即将发出之前被询问，因此它计数的就是实际中继的内容；更早失败的数据报
   不会到达它。它在处理数据报的地方运行，即持有该分配所在分片锁的 I/O 线程上：带宽限制器必须在数据报发出前作出
   决定，而把决定移到锁外会让每个数据报多遍历一次分片。因此它不得阻塞，也不得调用服务器中会锁分片的方法。TCP
   分配的连接中的字节不经过核心，直接从一个连接转到另一个（ADR-076），它看不到。
2. **`TurnConfig::on_event`**（`EventHook`，`Fn(&TurnEvent)`）：`TurnEvent { kind, user, client, relay,
   lifetime }`，其中 `TurnEventKind::{Allocated, Refreshed, Freed { reason, to_peer, to_client }, Refused
   { method, code }, AuthFailed { method, code }}`，`FreeReason::{Deleted, Expired, Closed}`，即 fib 的事件。
   核心把事件存入列表（仅在设置了钩子时），`TurnServer` 在对分片的调用结束时取走列表，在分片解锁、应答发出后，
   在处理该消息、执行清理或关闭分配的线程上调用钩子：事件处理程序可以记录日志、计数，并调用服务器的任何方法，
   包括 `stats`，无需顾及锁的顺序。直接驱动的 `TurnCore` 通过 `TurnCore::flush_events` 交付事件。`AuthFailed`
   与 fib 一致：凭据错误（401）或不完整（400），不包括不带凭据的请求（每个客户端都这样开始）和过期的 nonce；
   `Refused` 是对凭据已通过的请求以任何错误应答。被释放的分配会报告它在每个方向上中继的内容（`Traffic`，按分配
   计数，与服务器的总数并存）。
3. **`TurnServer::holds_relay(addr)`**：`addr` 是否是服务器的某个中继地址，无论是告知客户端的地址（位于
   `public_ip` 或 `additional_public_ip`，映射回绑定地址）还是绑定地址：查 UDP 中继表（某个分配的中继，或
   `EVEN-PORT` 预留的端口）和 TCP 中继的监听表。它只锁这些表，从不锁分片，因此对端过滤器（在分片锁下运行）
   可以询问它，无论是自己的服务器还是另一台：锁的顺序是先分片后中继表，与发送数据报时相同。
   `TurnCore::holds_relay` 根据核心自己的表回答。
4. **更多计数**：`TurnStats` 新增 `permissions` 和 `channels`（读取统计时遍历分配得到：用于抓取指标，而非每个
   数据报）、`pending`（已认证、正在锁分片前绑定中继的 Allocate）、`dropped`（服务器未作任何处理的来自客户端或
   对端的数据报：不是 TURN、格式错误、没有分配、许可或信道、被对端策略或 `on_relay` 拒绝、TTL 耗尽）、`refused`
   以及每个方向中继的字节数；`impl AddAssign` 用于汇总多台服务器的统计。`TurnServer::allocations()` 只读一个
   计数器，不锁分片。

akit 在 `on_relay` 中沿用 fit 的限速器，把事件计入 `akit_turn_*` 指标和日志，并在其对端过滤器中通过
`holds_relay` 经由中继端口访问自身地址。

## 更新 2：运行中服务器的设置变更与排空（A258）

fit 的重新加载会就地修改运行中服务器的配额、上限、生存期与凭据（fib 的 `SetLimits` 与 `SetAuth`），保留已有
分配；地址变化时，它启动新服务器并排空旧服务器（`Shutdown` 中 fib 的 `Drain`：新分配以 508 拒绝，已有分配继续
中继与刷新，直到结束或排空时间耗尽）。akio-turn 的 `TurnConfig` 由各分片无锁读取，此后不再修改，`close_all`
是唯一的关闭方式；任何限制的变化都会让 akit 启动新服务器。

1. **`TurnLimits`**（`default_lifetime`、`max_lifetime`、`permission_lifetime`、`channel_lifetime`、
   `nonce_lifetime`、`max_allocations`、`max_allocations_per_user`、`max_permissions`、`max_channels`、
   `max_tcp_connections`；`#[non_exhaustive]`，通过 `TurnConfig::limits()` 或 `TurnServer::limits()` 读取，
   逐字段修改）与 **`TurnServer::set_limits`**（以及 `TurnCore` 的同名方法）。服务器把每项保存在一个原子变量
   中，在请求原本读取配置的地方用 relaxed 读取：任何路径都没有增加锁，数据报也从不读取它们。与请求并发的修改
   可能只被看到一部分，这与在请求之前或之后修改无法区分。它们从下一个请求起生效：超过降低后的配额或上限的已有
   内容保留到结束（超过上限的许可不会被刷新），已授予的生存期照常走完，已发出的 nonce 保持其有效期。
   `max_lifetime` 小于 `default_lifetime` 时按 `default_lifetime` 处理，与 `TurnConfig::lifetimes` 相同。
   `TurnConfig` 的字段仍是服务器创建时的值。
2. **`TurnServer::set_auth(AuthFn)`**（以及 `TurnCore` 的同名方法）：凭据放在共享状态中的读写锁之后；每个请求
   （以及 Allocate 在加锁前的检查）在读锁下克隆 `Arc`，在锁外调用该函数。从下一个请求起生效，包括已有分配的
   请求：被拒绝的用户不能再刷新，其分配随生存期结束。
3. **`TurnServer::drain()`**（以及 `draining()`、`TurnCore::drain`）：一个标志。设置后，没有分配的客户端的
   Allocate 在凭据通过后以 508 应答（产生 `Refused` 事件），包括认领 `EVEN-PORT` 预留端口的请求，也不会为它在
   加锁前绑定中继；建立了分配的那个 Allocate 的重传仍得到原来的应答，刷新、许可、信道、Connect 与中继照常进行。
   它不可撤销。`TurnServer::allocations()` 与 `Freed` 事件表明何时已空；之后由服务器的所有者关闭它（`close_all`
   或关闭其监听），可以立即关闭，也可以在排空时间耗尽时关闭。akio-turn 没有为此等待的定时器。

akit 把配额、上限与生存期从会导致启动新服务器的设置中移出，改为就地设置；被重新加载替换的服务器进入排空，
拒绝新分配，直到时间耗尽。
