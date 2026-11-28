# ADR-081：按线程备用的头部存储、池化的响应头、不装箱 Context 的 HTTP/2 请求

[English](081-per-thread-head-storage.md) | 简体中文

状态：已采纳（2026-11-22），2026-11-23 更新

## 背景

ADR-025 之后每个请求还剩这些分配：HTTP/2 的 `Box<Context>`、头部缓冲区和响应的分配。此时 HTTP/1.1
服务端每请求 5.0 次分配器调用，HTTP/1.1 pipeline 5.0，h2c 5.5，`quic-bench h3`（两端在同一进程）9.0。
计数方法：在 gpu51 上用 bpftrace uprobe 统计服务端进程的 malloc、calloc、realloc、posix_memalign 和
aligned_alloc，服务端为 `http-bench`，压测用 h2load。为找出每次分配的来源，另编译一份带帧指针和行号表的
版本，每次调用取 `ustack()`，再对各帧用 `addr2line -i`。

| 来源 | HTTP/1.1 | h2c | HTTP/3 服务端 |
|---|---:|---:|---:|
| 请求头存储（`parse_head`、HTTP/2 `build_request`、akio-h3 `request_head`） | 1 | 1 | 1 |
| `Response::with_body`：头部缓冲区，以及字段位置的向量（它预留 4 个字段，而内联只放 2 个） | 2 | 2 | 2 |
| 响应体：`ctx.text(200, "Hello, World!")` 把 `&str` 转成 `String` | 1 | 1 | 1 |
| HTTP/1.1 响应头（`Vec::with_capacity(192 + body)`） | 1 | | |
| 每个 HTTP/2 请求一个 `Box<Context>` | | 1 | |
| HTTP/2 连接的输出缓冲区，每次 flush 后从空重新增长（realloc） | | 约 0.5 | |

`quic-bench` 的客户端一侧另有 4 次：响应的 `Headers`（缓冲区和位置）、响应体，以及基准程序自己的请求。
QUIC 本身约 1 次。

## 决定

1. **按线程备用的头部存储。** 每个线程为请求头和响应头各留一份备用的 `Headers` 存储。备用存储是一个放
   名字和值的缓冲区加字段位置向量，已清空。请求头取用请求备用：HTTP/1.1 `parse_head`、HTTP/2
   `build_request`，以及 akio-h3（经 `transport::request_headers(fields, bytes)`）。处理函数用完一个
   仍归它所有的请求后，存储随 target 缓冲区（ADR-025）一起交回（`Context::recycle_request`，取代
   `recycle_target`）。
   `Response::with_body` 取用响应备用，`text` 和基于它们的构造方式也一样。响应头编码完成后交回：HTTP/1.1
   的 responder、HTTP/2 的 `send_response`，以及 akio-h3 的 sink（经
   `transport::recycle_response_headers`）。超过 4 KiB 或 64 个字段位置的存储不保留。用两份而不是一份，
   是因为构造响应时请求头仍然存活。按线程而不是按连接，理由同 ADR-025：在本线程解析的下一个头部会发现
   存储仍在缓存中。
2. **`with_body` 的位置内联存放。** 它预留 2 个字段位置（内联），而不是 4 个（需要向量）。第三个字段
   会把位置移入向量，这和以前任何第三个字段一样。
3. **HTTP/1.1 响应头使用 akio-buf 的池。** 头部编码进 `akio_buf::get(192 + body)`，即 512 字节或更大
   的尺寸等级。连接把这样的缓冲区交回写出它的线程的池（`consume`）。在 `on_data` 内，写出发生在回调
   结束时的 I/O 线程上，所以下一个请求到来前缓冲区已经回到池中。akio-core 现在也把 `send_owned` 立即
   完整写出的缓冲区（队列为空时从其他线程发送）交回池中，TLS 刚封装完的明文缓冲区也一样。
4. **HTTP/2 分派请求时不再装箱 Context。** `Action::Dispatch` 携带 `Request` 和该流的 responder。
   `run` 在栈上构造 `Context`，和 HTTP/1.1 一样。流式请求和扩展 CONNECT 仍使用装箱的 context，因为
   它要挂在流上。action 向量是按线程备用的。
5. **HTTP/2 的输出缓冲区来自池。** 向空的输出缓冲区写入响应头时，从 akio-buf 的池取一个 4 KiB 等级的
   缓冲区，而不是从零开始增长。flush 把它交给连接，连接写出后交回池中。没有写入任何内容的缓冲区在
   flush 时交回，所以空闲连接不占用缓冲区。

### 考虑过的其他方案

- **复用响应体。** `Context::text` 和 `Response::text` 接受 `impl Into<String>`，所以 akio-http 拿到
  之前 std 已经把 `&str` 转成了新的 `String`。把约束改为 `AsRef<str>` 会让只实现了 `Into<String>` 的
  调用方编译失败。这次分配保留，每请求一次，发生在处理函数中。
- **把响应头复制进连接的队列。** 先把头部编码进按线程的临时缓冲区，再用新的 `ResponseSlot` 方法把它
  复制进队列尾部的缓冲区，合并 pipeline 的响应。这需要新增 akio-core API，并多一次复制。池化缓冲区
  不需要这两者，分配次数相同。
- **HTTP/2 按线程备用一个 `Box<Context>`。** 这个 box 会把用完的 context 及其请求持有的一切留到下一个
  请求。在栈上构造 context 更简单，也不会推迟任何释放。
- **请求头和响应头共用一份备用。** 两者同时存活，响应总会发现备用已被取走。
- **按连接备用。** ADR-025 测得它是冷的。

## 影响

- 每请求分配器调用，仅服务端（bpftrace，gpu51，epoll 与 io_uring 相同）：
  - HTTP/1.1：5.0 → 1.0。
  - HTTP/1.1 pipeline：5.0 → 1.0。
  - h2c：5.5 → 1.0。
  - `quic-bench h3` 两端：9.0 → 6.0。服务端 1 次；客户端 4 次（响应头 2、响应体 1、基准程序的请求 1）；
    QUIC 约 1 次。
  服务端剩下的 1 次是处理函数的响应体。
- gpu51 上 `quiet.sh` 下的同轮 A/B（7 轮交替，取中位数；服务端在 CPU 0–3，h2load 在 4–11；在 h2load
  运行期间对服务端 `perf stat`）：

| 场景 | req/s 前 → 后 | 倍数 | 服务端每请求用户态周期 | 倍数 | 每请求指令 | 倍数 |
  |---|---:|---:|---:|---:|---:|---:|
  | HTTP/1.1，256 连接 | 580,082 → 579,612 | 0.999 | 4,948 → 4,883 | 0.987 | 6,904 → 6,471 | 0.937 |
  | HTTP/1.1 pipeline 16 × 256 | 3,700,614 → 3,815,779 | 1.031 | 2,484 → 2,329 | 0.938 | 6,055 → 5,436 | 0.898 |
  | h2c 64 连接 × 16 流 | 3,152,801 → 3,285,438 | 1.042 | 4,355 → 4,092 | 0.940 | 9,013 → 8,376 | 0.929 |
  | HTTP/3 GET，单连接，64 个并发（`quic-bench h3 10 64`，CPU 2–5） | 870,751 → 884,259 | 1.016 | | | | |

  普通 HTTP/1.1 受限于客户端和内核（每请求一次读一次写），req/s 不变；它的每请求周期是最不稳定的
  数字（各轮 0.96–1.01 倍）。HTTP/3 上新版本 7 轮中 6 轮更快。

- 内存：每个线程最多保留两份各不超过 4 KiB 的头部存储，外加 1 KiB 的 target。pipeline 的 HTTP/1.1
  响应头排队期间占用 512 字节的缓冲区（以前按实际大小分配）。池中每个尺寸等级每线程最多 64 个缓冲区（ADR-190 起，每级也最多 256 KiB）。
- 从其他线程发送的响应（detach 的请求）在那个线程的池中编码，池为空时分配新缓冲区。它会回到写出它的
  线程的池中。
- API：无公开变化。`#[doc(hidden)]` 的 `akio_http::transport` 中新增 `request_headers` 和
  `recycle_response_headers`，不在快照范围内。akio-http 现在依赖 akio-buf。
- 未完成：
  - 响应体（见上）。
  - HTTP/3 客户端的响应头和响应体。它们归调用方所有，不回收；三个及以上字段的响应需要位置向量。
  - QUIC 自身的分配。

## 更新（2026-11-23）：响应体、HTTP/3 客户端的响应头、QUIC 热路径

### 背景

ADR-081 剩下的分配，用同样的方法统计（bpftrace 对分配器挂 uprobe；调用栈用带帧指针和行号表的构建、
关闭地址随机化运行、`addr2line -i`）：

| 位置 | 每请求 / 每 MB |
|---|---:|
| handler 的响应体：`ctx.text(200, "Hello, World!")` 生成一个 `String`（HTTP/1.1、pipeline、h2c、HTTP/3 服务端） | 1 |
| `quic-bench h3` 客户端：响应的 `Headers`（缓冲区和位置，响应有 3 个字段） | 1.96 |
| `quic-bench h3` 客户端：响应体（`body.to_vec()`，调用方的 `Vec<u8>`） | 0.98 |
| `quic-bench h3`：基准程序自己的请求回调（`Box<dyn FnOnce>`） | 1.0 |
| `quic-bench h3`：QUIC 和 UDP 循环 | 约 0.7 |
| QUIC bulk，每 MB（单连接，约 740 个包）：超出 64 个备用之外的已发送包帧列表 | 208 |
| QUIC bulk：每次 `poll_transmit` 一个数据报缓冲区，即使什么都不返回 | 108 |
| QUIC bulk：ACK 取出的包列表，以及 ACK 帧的区间向量 | 68 |
| QUIC bulk：akio-core 的 `sendmmsg` 映射和 GSO 分片、akio-epoll 与 akio-core 每次 flush 的列表 | 77 |

### 决定

1. **`text` 响应体放进按线程的备用缓冲区。** `Response::text` / `Context::text` 保留
   `impl Into<String>` 约束。隐藏的辅助函数 `akio_buf::text::as_str` 判断参数类型是否为 `&str`
   （任意生命周期；采用 dtolnay 的 `typeid::of` 技巧，这是唯一的 `unsafe`，经 Miri 检查）并返回它。
   `&str` 被复制进本线程的备用响应体缓冲区；其他类型照旧经过 `Into<String>`（`String` 被移动而不是
   复制）。响应体复制进输出之后，transport 把它的缓冲区交回作为本线程的备用（不超过 4 KiB）：
   HTTP/1.1 的 responder、HTTP/2 的单帧路径，以及 akio-h3 的 sink（经隐藏的
   `transport::recycle_response_body`）。transport 不复制的响应体（超过一帧或窗口的 HTTP/2 响应体、
   超过 16 KiB 的 HTTP/3 响应体、文件）不回收。
2. **被丢弃的 `Headers` 存储填充本线程空着的响应备用。** `Headers` 把缓冲区和位置放在一个私有类型里，
   该类型的 `Drop` 在响应备用为空、且存储不超过备用上限时把它们移进去（已有备用时不动，不会连锁）。
   `Drop` 在私有类型上，所以 `Headers` 的 API 和快照不变。HTTP/3 客户端在响应备用里构建响应头（隐藏的
   `transport::response_headers`）；调用方在回调里（客户端 I/O 线程上）丢弃响应，就把存储借给下一个
   响应。
3. **QUIC 热路径。** `poll_transmit` 的数据报缓冲区取自 akio-buf 的池（UDP 层写出后本来就会归还池化
   缓冲区）；空的缓冲区立即归还。ACK 帧的区间由解析器检查后原地读取（`AckRanges`，迭代时再解码），
   不再收集进向量。一次确认取出的包收集进连接保留的列表（最多 1024 项）。备用帧列表最多保留到在途的
   1-RTT 包数（至少 64），因为一个接收批次可能在发送任何东西之前就确认了大部分在途包。
4. **UDP flush。** akio-core 的 `send_datagrams` 把消息映射放在线程局部的批次里，GSO 消息的分片放在
   栈上的数组里。`flush_datagram_peers` 接受任意 `Deref<Target = ConnInner>`，只有一个连接时不构建
   列表；epoll UDP 循环保留它要 flush 的连接列表。

### 考虑过的其他方案

- **响应体取自 akio-buf 的池**（第一版：复制进 `akio_buf::get`，复制出去后 `put`）。分配次数相同，
  但池的尺寸等级查找和两端的 `RefCell` 比 glibc 缓存的 13 字节 malloc/free 更贵：pipeline HTTP/1.1 的
  服务端每请求用户态周期为 1.033 倍（7 轮全部变差），req/s 0.986 倍。改成与头部备用一样的
  `Cell<Vec<u8>>` 备用后回到 1.004 倍。
- **把约束改成 `AsRef<str>`**（ADR-081）：仍然是破坏性变更。
- **给 `Response` 加 `Drop` 以回收客户端响应体。** `Response` 有公开字段；`Drop` 实现会禁止把字段移出
  （`let body = resp.body;`），是破坏性变更。客户端的响应体仍是调用方的分配。
- **直接给 `Headers` 加 `Drop`。** 效果相同，但公开 API 快照里会多出 `impl Drop for Headers`。
- **已发送包的帧用内联小向量。** 会让 `Sent` 变大，而在途包的环形表要移动它；多保留一些备用列表更简单，
  第一轮在途之后就不再分配。

### 后果

- 分配器调用（bpftrace，gpu51）：
  - HTTP/1.1、pipeline HTTP/1.1、h2c，仅服务端：每请求 1.0 → 0（epoll 和 io_uring；在 160 万到
    1100 万请求的运行中约 1,300–3,900 次调用，来自定时器和连接建立）。
  - `quic-bench h3` 两端：每请求 6.0 → 2.03：客户端的响应体（调用方的）和基准程序的请求回调，外加
    QUIC 约 0.03。
  - QUIC bulk（`quic-bench bulk 2000`）：每 MB 482 → 21.5。
- gpu51 上 `quiet.sh` 下与 `main`（`5cc005c0`）的同轮 A/B（7 轮交替，取中位数；HTTP：`http-bench`
  epoll，服务端在 CPU 0–3、4 线程，`h2load` 8 线程在 CPU 4–11，每次 10 秒，对服务端
  `perf stat -e cycles:u,instructions:u`；HTTP/3：`quic-bench h3 10 64`，bulk：`quic-bench bulk 8000`，
  都在 CPU 2–5，`perf stat` 统计整个进程，所以 HTTP/3 的周期是两端合计）：

  | 场景 | req/s 前 → 后 | 倍数 | 每请求用户态周期 | 倍数 | 每请求指令 | 倍数 |
  |---|---:|---:|---:|---:|---:|---:|
  | HTTP/1.1，256 连接 | 578,340 → 580,183 | 1.003 | 4,861 → 4,738 | 0.975 | 6,470 → 6,457 | 0.998 |
  | HTTP/1.1 pipeline 16 × 256 | 3,800,088 → 3,798,787 | 1.000 | 2,304 → 2,314 | 1.004 | 5,435 → 5,416 | 0.997 |
  | h2c 64 连接 × 16 流 | 3,286,046 → 3,313,472 | 1.008 | 4,099 → 4,054 | 0.989 | 8,369 → 8,331 | 0.996 |
  | HTTP/3 GET，单连接，64 个并发（两端） | 790,826 → 794,709 | 1.005 | 6,416 → 6,447 | 1.005 | 17,273 → 16,920 | 0.980 |
  | QUIC bulk，单流（Mbit/s） | 18,550 → 19,007 | 1.025 | | | | |

  pipeline 的每请求周期各轮在 1.000–1.014 倍之间（这个数字的噪声水平；它的指令数下降了）。HTTP/3 的
  周期是固定时长运行中两端的合计；它的指令数下降 2%。bulk 7 轮全部更快。
- 内存：每个线程保留一个不超过 4 KiB 的备用响应体缓冲区。在非 I/O 线程上丢弃的响应（客户端响应被送到
  调用方线程）会填充那个线程的响应备用（不超过 4 KiB）。QUIC 连接保留的备用帧列表数等于它曾经在途的
  1-RTT 包数（每个几十字节加上列表容量），直到连接关闭；另有一个最多 1024 项的确认列表。
- API：无公开变化，快照不变。隐藏的新增：`akio_buf::text::as_str`、
  `akio_http::transport::{response_headers, recycle_response_body}`；akio-core 隐藏的
  `ConnInner::flush_datagram_peers` 对连接句柄泛型化。
- 测试：HTTP/1.1、HTTP/2 和 HTTP/3 上，大小跨越各上限的 `text(&str)` 响应体（pipeline / 顺序，由
  handler 和其他线程发送）；HTTP/3 客户端在回调里检查并丢弃各种大小响应头的响应；备用和 `as_str` 的
  单元测试（`as_str` 也在 Miri 下）；akio-quic 对 `AckRanges` 的 ACK 往返测试（fuzz harness 已适配，
  编译和 clippy 通过，未运行）；quic-go 互通（`tools/interop/quic/run.sh`）通过。
- 未完成：
  - HTTP/3 客户端的响应体：调用方的 `Vec<u8>`（见上）。
  - transport 不复制的响应体（大的 HTTP/2 和 HTTP/3 响应体、文件），以及其他类型的 handler 响应体
    （`String`、`Vec<u8>`）：handler 自己的分配。
  - HTTP/1.1 和 HTTP/2 客户端（`akio_http::client`、`h2client`）每个响应仍为响应头分配。
  - 每个循环线程有很多连接的 QUIC：一次 flush 多个连接时仍构建两个列表。
