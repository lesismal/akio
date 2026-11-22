# ADR-081：按线程备用的头部存储、池化的响应头、不装箱 Context 的 HTTP/2 请求

[English](081-per-thread-head-storage.md) | 简体中文

状态：已采纳（2026-11-22）

## 背景

ADR-025 之后每个请求还剩这些分配：HTTP/2 的 `Box<Context>`、头部缓冲区和响应的分配。此时 HTTP/1.1
服务端每请求 5.0 次分配器调用，HTTP/1.1 pipeline 5.0，h2c 5.5，`quic-bench h3`（两端在同一进程）9.0。
计数方法：在 gpu51 上用 bpftrace uprobe 统计服务端进程的 malloc、calloc、realloc、posix_memalign 和
aligned_alloc，服务端为 `http-bench`，压测用 h2load。为找出每次分配的来源，另编译一份带帧指针和行号表的
版本，每次调用取 `ustack()`，再对各帧用 `addr2line -i`。

| 来源 | HTTP/1.1 | h2c | HTTP/3 服务端 |
|---|---:|---:|---:|
| 请求头存储（`parse_head`、HTTP/2 `build_request`、only-h3 `request_head`） | 1 | 1 | 1 |
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
   `build_request`，以及 only-h3（经 `transport::request_headers(fields, bytes)`）。处理函数用完一个
   仍归它所有的请求后，存储随 target 缓冲区（ADR-025）一起交回（`Context::recycle_request`，取代
   `recycle_target`）。
   `Response::with_body` 取用响应备用，`text` 和基于它们的构造方式也一样。响应头编码完成后交回：HTTP/1.1
   的 responder、HTTP/2 的 `send_response`，以及 only-h3 的 sink（经
   `transport::recycle_response_headers`）。超过 4 KiB 或 64 个字段位置的存储不保留。用两份而不是一份，
   是因为构造响应时请求头仍然存活。按线程而不是按连接，理由同 ADR-025：在本线程解析的下一个头部会发现
   存储仍在缓存中。
2. **`with_body` 的位置内联存放。** 它预留 2 个字段位置（内联），而不是 4 个（需要向量）。第三个字段
   会把位置移入向量，这和以前任何第三个字段一样。
3. **HTTP/1.1 响应头使用 only-buf 的池。** 头部编码进 `only_buf::get(192 + body)`，即 512 字节或更大
   的尺寸等级。连接把这样的缓冲区交回写出它的线程的池（`consume`）。在 `on_data` 内，写出发生在回调
   结束时的 I/O 线程上，所以下一个请求到来前缓冲区已经回到池中。only-core 现在也把 `send_owned` 立即
   完整写出的缓冲区（队列为空时从其他线程发送）交回池中，TLS 刚封装完的明文缓冲区也一样。
4. **HTTP/2 分派请求时不再装箱 Context。** `Action::Dispatch` 携带 `Request` 和该流的 responder。
   `run` 在栈上构造 `Context`，和 HTTP/1.1 一样。流式请求和扩展 CONNECT 仍使用装箱的 context，因为
   它要挂在流上。action 向量是按线程备用的。
5. **HTTP/2 的输出缓冲区来自池。** 向空的输出缓冲区写入响应头时，从 only-buf 的池取一个 4 KiB 等级的
   缓冲区，而不是从零开始增长。flush 把它交给连接，连接写出后交回池中。没有写入任何内容的缓冲区在
   flush 时交回，所以空闲连接不占用缓冲区。

### 考虑过的其他方案

- **复用响应体。** `Context::text` 和 `Response::text` 接受 `impl Into<String>`，所以 only-http 拿到
  之前 std 已经把 `&str` 转成了新的 `String`。把约束改为 `AsRef<str>` 会让只实现了 `Into<String>` 的
  调用方编译失败。这次分配保留，每请求一次，发生在处理函数中。
- **把响应头复制进连接的队列。** 先把头部编码进按线程的临时缓冲区，再用新的 `ResponseSlot` 方法把它
  复制进队列尾部的缓冲区，合并 pipeline 的响应。这需要新增 only-core API，并多一次复制。池化缓冲区
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
  响应头排队期间占用 512 字节的缓冲区（以前按实际大小分配）。池中每个尺寸等级每线程最多 64 个缓冲区。
- 从其他线程发送的响应（detach 的请求）在那个线程的池中编码，池为空时分配新缓冲区。它会回到写出它的
  线程的池中。
- API：无公开变化。`#[doc(hidden)]` 的 `only_http::transport` 中新增 `request_headers` 和
  `recycle_response_headers`，不在快照范围内。only-http 现在依赖 only-buf。
- 未完成：
  - 响应体（见上）。
  - HTTP/3 客户端的响应头和响应体。它们归调用方所有，不回收；三个及以上字段的响应需要位置向量。
  - QUIC 自身的分配。
