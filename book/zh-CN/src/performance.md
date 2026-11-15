# 性能调优

先测量，再调优。这里引用的数据来自
[docs/BENCHMARKS.zh-CN.md](https://github.com/lesismal/only/blob/main/docs/BENCHMARKS.zh-CN.md)：
一台笔记本级 Mac 上的 Docker 虚拟机、回环网络、4 个服务端线程。把它们当作方向参考，而不是
排名。在那份报告中，only 的 TCP echo 与 tokio 同一量级、领先 fib（512 连接时领先 tokio，
64 连接和 16 KiB 消息时落后约 15%），UDP echo 与 fib 持平，把 5 ms 的阻塞工作移到逻辑线程池
后吞吐量约为在 I/O 线程上阻塞时的 58 倍。`tools/bench/run.sh` 可以复现这些测试；
`tools/echo-bench` 是压测工具。

## 1. 保持 I/O 线程空闲

如果回调会阻塞，其他一切都无从谈起。关注 `only_slow_callbacks_total` 和
`only_loop_callback_seconds_total`；在预发布环境把 `slow_callback_threshold` 调低到
1–10 ms 来找出问题代码；把阻塞工作移到 `spawn_blocking`、`Context::detach` 或你自己的线程。
见[阻塞任务](concepts/blocking.md)。

## 2. 线程

- `Listener::threads(n)` 默认是**每个 listener** 每核一个线程。有多个繁忙的 listener 时，总数可能
  超过核数；给次要的 listener 少分一些线程。
- 以客户端连接为主的服务（代理、网关）应设置 `client_threads(n)`，让上游连接不与接入的连接
  争抢线程。
- 逻辑线程池应匹配阻塞任务所等待的资源（数据库连接数、磁盘队列深度），而不是核数。
- 负载按连接均衡。少数非常繁忙的连接（几个复用一切的 HTTP/2 客户端）能用到的线程数不会超过
  连接数。

## 3. 后端选择

- **epoll** 是默认后端和基准。读是水平触发的，每线程一个临时缓冲区；写由调用 `send` 的线程
  直接写 socket。
- **io_uring**（Linux 5.19+）使用 multishot accept/recv 和 provided-buffer ring，空闲连接不占
  读缓冲，归还缓冲区只是一次内存写。在服务端是瓶颈时（单服务端线程、512 连接）它领先 epoll
  10–25%，客户端是瓶颈时两者相差几个百分点、互有胜负。对连接数多、服务端受限的负载可以试试，
  测量后保留更快的那个；按 listener 选择后端允许你混用。`sqpoll` 用一个忙碌的内核线程换取更少
  的系统调用，只在持续高负载下才划算。
- UDP 总是使用就绪通知后端加 `recvmmsg`/`sendmmsg`。

## 4. 缓冲区与写

- `Config::read_buffer`（64 KiB）是每个 I/O 线程一个，不是每个连接一个。更大的值有助于大块
  传输；它也是一次 `on_data` 能收到的最大字节数。io_uring 则在每个线程保留一个由 1024 个
  `min(read_buffer, 16 KiB)` 大小缓冲区组成的 ring（默认 16 MiB）。
- 在回调里发送的数据会合并成一次 `writev`。在其他线程上，用 `cork()` ... `flush()` 批量发送，
  或者拼好一个缓冲区再 `send_owned`。
- 已经拥有所有权的缓冲区用 `send_owned(Vec<u8>)`（排队时不复制）；广播用
  `send_shared(SharedBuf)` / `PreparedMessage` / `Server::broadcast`，只编码一次。
- `write_high_watermark` 限制每个慢读者占用的内存；调高它能提升对快读者发送大响应时的吞吐，
  代价是内存。
- 超过 `max_cached_bytes` 的静态文件在明文 TCP 上用 `sendfile(2)` 发送；内存缓存留给小而热的
  文件。

## 5. UDP：GSO、GRO 与批量

- Linux 上接收使用 `recvmmsg`；为一批接收产生的回复用 `sendmmsg` 发出，发往同一对端、长度相同
  的连续数据报合并成一次 GSO 发送。在 UDP 批量化的工作中，这让突发流量下每个数据报的服务端
  CPU 降低了 30–46%，64 字节 echo 提升约 19%。
- `Conn::send_segments` 一次调用发送多个数据报（only-quic 使用它）。
- `Config::udp_gro`（在内核支持时默认开启）让接收 GSO 流量的大流量接收方（QUIC 下载）一次接收
  整批 GSO 数据：回环上的 QUIC 大流量因此从 6.4 提升到 9.8 Gbit/s，64 字节 UDP echo 没有可测的
  变化。它需要 `read_buffer` >= 64 KiB；`ONLY_UDP_GRO=0` 可关闭。
- `udp_max_peers` 在洪泛下限制每对端状态的数量。

## 6. eBPF 分流

`Accel::Ebpf` 决定每个新连接或新 UDP 对端交给哪个 I/O 线程：

- `Steering::Cpu` 让一个流留在与收到其数据包的 CPU 对应的线程上。配合网卡 RSS/RPS 和绑核的
  I/O 线程可以获得缓存局部性（only 目前还不提供线程绑核本身）。
- `Steering::Hash`（按源 IP，或源 IP 加端口做一致性哈希）让客户端在重连后仍落在同一线程，适合
  按客户端缓存的场景。

经典 BPF 不需要特权；用 `Engine::accel_status()` 查看实际挂载了什么。eBPF 的基准测试尚未发布。

## 7. TLS

在报告中，TLS 吞吐量与 tokio-rustls 的差距在噪声范围内（TLS 1.3，1 KiB 记录）。启用会话恢复
（`ticketer`）让重连更便宜；在 ALPN 中提供 `h2`，让 HTTP 客户端复用连接而不是开更多连接。
不使用内核 TLS：在带 VAES 的 x86_64 上它比 only-tls 自己的记录层慢，大文件的 `sendfile` 也不例外
（[测量结果](https://github.com/lesismal/only/blob/main/docs/BENCHMARKS.zh-CN.md#内核-tlsktls评估)）。

## 8. 操作系统

大量连接的常规 Linux 设置同样适用：调高文件描述符上限（`ulimit -n`），`net.core.somaxconn`
至少等于 `Config::backlog`，对发起大量出站连接的客户端调大本地端口范围。`max_connections` 和
`idle_timeout` 让进程保持在这些限制之内。
