# ADR-102：按 UDP 对端记住 QUIC 路由，HTTP/3 服务端默认开启 QPACK 动态表

[English](102-quic-peer-routes-qpack-server-default.md) | 简体中文

状态：已采纳（2026-11-24）

## 背景

gpu51 上的 HttpArena 中，akio 在 HTTP/3 上落后于 fib 与 fib-tuned：

- baseline-h3（64 连接）：akio 195 万请求/秒，服务端 CPU 219%；fib 210 万，fib-tuned 211 万。
- static-h3：akio 39.7 万，fib 40.3 万。

HTTP/2 的各项测试 akio 均领先。

可能的原因有两个：

1. **服务端的共享状态。**
   - 每个 akio-quic 服务端只有一个 `Ep`，其全部 UDP 线程共用它。
   - 每个数据报都要锁端点的 `Mutex<Endpoint>` 来按连接 ID 路由，再锁连接表的互斥锁。
   - 每发送一个数据报都要锁 socket 表的互斥锁。
   - fib 每个 poller 各有一张对端表，不加锁；它的 CID 到连接的映射只用于未知地址。
2. **客户端每个请求要做的工作。**

### 测量

在 gpu51 上测 baseline-h3：服务端在 CPU 0-3,8-11，h2load-h3（`-c 64 -m 64 -t 8`）在 CPU 4-7,12-15，预热后测 15 秒，期间采样 `pidstat` 与 `/proc/net/snmp`。

| | akio | fib-tuned |
| --- | --- | --- |
| 请求/秒 | 194 万（第二次运行 195 万） | 209 万 |
| h2load-h3 CPU | 799%（8 核全满） | 798% |
| 服务端 UDP 线程 | 每个 14-47%，8 个都在工作 | - |
| 响应头字节数（h2load 的 "headers"） | 1.76 GB，每个响应 60.6 B，QPACK 节省 31.6% | 209 MB，每个响应 7.0 B，节省 85.1% |
| UDP 数据报（入方向，15 秒） | 146 万（每个 20.0 个请求） | 127 万（每个 24.7 个请求） |

由此可见：

- **瓶颈在压测端**，akio 与 fib 都是如此。akio 的服务端线程远未满载，64 个连接分布在全部 8 个线程上。
- 服务端的 perf 剖析（999 Hz，4 秒，带调用图）中，前列符号里没有 futex、mutex 或自旋相关的帧；内核锁相关符号均不超过 0.1%。时间花在：
  - 解析请求头（`request_head` 5.3%），
  - 对请求的 QPACK 字段做 Huffman 解码（4.7%），
  - 处理函数，
  - 构造响应。
- 所以在这个负载下共享锁的代价看不出来，也不是这项测试的决定因素。这些锁仍然去掉（规则 12：每个请求不得经过全局锁），因为数据报速率更高时它们会成为问题。
- **差别在于客户端每个响应要接收的字节数。** akio 的每个响应头包含：
  - `date`（以静态名称引用加字面值编码，31 字节），
  - `content-type: text/plain; charset=utf-8`（27 字节：静态表里只有不带空格的 `text/plain;charset=utf-8`），
  - 状态码、内容长度和字段段前缀。
- akio-h3 已有 QPACK 编码器，但默认关闭（ADR-061），所以这些都以字面值发送。
- fib 的响应只有 `:status`、一个静态表中已有的 `content-type` 与长度，约 7 字节。fib 不发送 `date`。

RFC 9110 第 6.6.1 节要求带时钟的源服务器发送 `Date`，所以去掉它不可取。

h2load v1.69 通告 4096 字节的 QPACK 表（`qpack_max_dtable_capacity = --header-table-size`，默认 4 KiB）与 100 个可阻塞的流。开启编码器后，这些字段插入表中之后都只需一字节的引用。

## 决定

### akio-quic：记住路由

- 每个 UDP handler（每个对端地址一个，归一个 I/O 线程所有）记住它上一个路由成功的短头部数据报所去的连接，记为 `(连接 ID, Connection, 代数)`。
- 之后带同一连接 ID 的短头部数据报直接交给该连接，不经端点锁，也不经连接表锁。
- `Endpoint::route_short` 是填充这份记忆的查找；它找不到的数据报照旧走 `handle_ecn`（长头部、未知 ID、无状态重置）。
- 端点每移除一条路由（`RetireCid`、`Drained`、连接离开连接表），`Ep::routes_gen` 就加一。记住的路由只在代数未变时使用。
  - 代数在查找之前读取，所以与查找同时发生的移除会使这条路由失效。
  - 在这个窗口内漏过的数据报，到达的连接要么会忽略它（已排空），要么仍拥有这个 ID（刚刚才退役）。这无害。
- 服务端连接记住上次发送所用的 UDP socket（`Shared::tx_sock`）。只要它仍打开且地址与目的地址相同就继续使用；否则照旧在共享表中查找。
- 客户端保留表查找，因为它只有一个 socket（迁移期间两个）。

### akio-h3：服务端默认开启编码器

- `H3Config::qpack_encoder_capacity` 的默认值改为 4096（原为 0）。`H3ClientOptions::qpack_encoder_capacity` 仍为 0。
- 编码器使用的容量仍不超过对端允许的值；对不通告动态表的对端（curl、quic-go、fib）没有任何变化。
- `date` 现在可以插入表中。它每秒变化一次，而同一秒内的每个响应都重复它，所以每个连接每秒一次插入，即可替换掉每个响应 31 字节的字面值。
- 只要有编码器，`date` 就经过编码器；没有编码器的服务端仍使用按线程缓存的字面行。

### 修复：编码器流放不下的插入

- 编码器原先以 `let _ = c.send(encoder_stream, ..)` 发送插入指令。
- 连接的发送缓冲区满时（大响应在等对端的额度），这次发送以 `Overloaded` 失败，插入随之丢失。
- 引用这些插入的字段段于是永远无法解码：对端的这些流一直等下去。
- 编码器一改为默认开启，已有测试 `many_responses_over_the_connection_buffer` 就发现了这个问题。
- 修复方式：`EncShared::section` 在每个字段段之前把 `Encoder::room` 设为编码器流的 `send_capacity`。`insert` 与 `duplicate` 拒绝放不下的指令，该字段改以字面值发送。
- 不再做任何发不出去的插入。

## 验证

- 单元测试 `encoder_inserts_within_the_stream_room`：没有余量时只有字面值、没有插入；余量刚好容纳一次插入时恰好插入一次；余量充足时，`date` 与 `content-type` 都变成一字节引用。
- 集成测试 `many_connections_over_several_threads_close_and_reconnect`：4 线程服务端上 12 个连接，每个 16 个请求。服务端全部关闭后连接表清空，同一客户端引擎再发起的 12 个新连接都正常工作。
- 新默认值下 akio-h3 测试全部通过，包括背压测试。
- 互通：
  - quic-go 与 fib，双向。
  - ngtcp2（libcurl-gnutls）与 OpenSSL QUIC（libcurl），两者的 HTTP/3 客户端都是 nghttp3。默认配置的服务端现在会对它们使用编码器。
  - curl 与 `openssl s_client -quic`。
  - libnghttp3 的 QPACK 解码器对我方编码器，5 种配置 x 3 个种子（`tools/interop/quic/docker.sh`）。
- `cargo test --workspace` 在 macOS 上通过。gpu51 上的运行中途被停止：epoll 已运行的 37 组测试全部通过，没有失败；io_uring 未运行。两者都有待完成。

## 测量结果

待定。在 A/B 运行之前，gpu51 上的 HttpArena 测试已暂停。

两个变体已登记到共享 A/B 批次：

- `akio-h3`（仅记住路由，1e1fb670）。
- `akio-h3q`（记住路由加 QPACK 默认值，87aef2a8）。

两者各自与 `akio`（main 50a82315）和 fib-tuned 一起，跑 baseline-h3、static-h3、baseline-h2、static-h2、baseline-h2c 与 json-h2c。

## 影响

- HTTP/3 服务端每个响应要为编码器加一次锁（`EncShared`，按连接，无竞争），并处理对端的字段段确认。
  - ADR-061 测得两端都开编码器时，`quic-bench h3` 为默认配置的 0.83 倍，当时瓶颈是 akio 自己的客户端。
  - 这里客户端解码的是更便宜的引用，每个响应少接收约 50 字节。
  - 对 CPU 受限的客户端是否划算，由 A/B 决定。若不划算，默认值改回 0，并在本节说明。
- 显式设置 `qpack_encoder_capacity: 0` 的应用保持原来的线上格式。
- 记住路由的代价是每个 UDP 对端一个 `Connection` 克隆，以及每个数据报一次原子读。
- 在同一地址上交替使用多个连接 ID 的对端，每次切换都回到端点查找：结果正确，只是不更快。
