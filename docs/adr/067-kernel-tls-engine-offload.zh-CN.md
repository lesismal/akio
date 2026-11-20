# ADR-067：引擎连接的内核 TLS，硬件优先

[English](067-kernel-tls-engine-offload.md) | 简体中文

状态：已接受（2026-11-21）

## 背景

2026-11-16 的 kTLS 评估（docs/BENCHMARKS.zh-CN.md，“内核 TLS（kTLS）评估”）发现，Linux 7.0
的软件 kTLS 在所有测量情形下都比 only-tls 自己的记录层慢（0.40 到 0.83 倍），因此卸载代码一直放在
实验性的 `experimental-ktls` feature 之后：只有阻塞测试流、一个基准和一个互通模式，没有接入 `Tls`
或引擎。

那次评估没有覆盖的是自己完成记录加解密的网卡（TLS device offload，`ethtool -k` 中的
`tls-hw-tx-offload` / `tls-hw-rx-offload`；NVIDIA ConnectX-6 Dx 及更新型号，部分 Intel 与 Chelsio
网卡）。在这类网卡上，内核把明文记录交给网卡，CPU 不做 AES-GCM，`sendfile` 也真正零拷贝。
引擎里没有 kTLS，服务器就拿不到这些好处。

约束：默认情况下任何地方都不能变慢；不要求 kTLS 的连接不受任何影响；不写厂商专用代码（只用内核的
device offload 接口）；kTLS 关闭或未生效时，`send`、`on_data` 与事件循环的热路径没有可测量的开销。

## 决定

### 1. 策略：`only_tls::Ktls`

`ServerConfigBuilder::ktls` / `ClientConfigBuilder::ktls` 接受：

- `Off`（默认）：什么都不变。
- `Hardware`：只卸载网卡自己完成的部分。连接本地地址所在接口开启了 `tls-hw-tx-offload` 时卸载发送
  方向，同时开启 `tls-hw-rx-offload` 时也卸载接收方向；仅限 AES-GCM。接口表（`getifaddrs` 加上
  ethtool 的 `SIOCETHTOOL` 特性 ioctl，无需特权）缓存 30 秒；只要没有接口支持 TLS 卸载，每个连接的
  检查就只是两次 relaxed 原子读。安装某个方向后，用内核的 `TlsTxDevice` / `TlsRxDevice` 计数器（在
  进程级锁下于安装前后各读一次）确认网卡确实接管了它。如果内核回退到软件（驱动不支持该版本或密钥
  长度），就记住这个接口、版本与 AEAD 的组合，不再交给网卡，所以每种组合最多有一个连接以软件方式运行。
- `Software`：总是卸载两个方向（没有网卡帮忙时为软件 kTLS）。在当前 CPU 上更慢；用于对比、内核
  AES-GCM 更快的 CPU，以及需要 sockmap 的场景。
- `SoftwareTx`：只卸载发送方向。

`ktls_zerocopy_sendfile(true)` 为网卡卸载的连接设置 `TLS_TX_ZEROCOPY_RO`（网卡直接从页缓存读取
`sendfile` 的页面；发送过程中文件不能被修改）。TLS 1.3 需要 Linux 6.14（已卸载方向的密钥更新）；
否则 TLS 1.3 连接留在用户态。`ktls` cargo feature 把卸载编译进来（`experimental-ktls` 保留为它的
别名）；没有该 feature 或不在 Linux 上时，所有模式都等同于 `Off`。

### 2. 引擎钩子（only-core）

`Transport` 新增几个默认方法，均只在 Linux 上存在：

- `wants_offload` / `offload(fd, local, rx_ok) -> Offloaded { tx, rx }`：只要传输层还想卸载，引擎
  就在所属 I/O 线程上、两次读之间、没有待写数据时把 TCP socket 交给它。从不想卸载的连接，每次 flush
  最多多一次 relaxed 原子读。
- 发送方向在内核中：应用数据不再经过 `seal`，原样写入 socket；`send_file` 重新使用 `sendfile(2)`，
  不再经内存读取；`kernel_send(len)` 让传输层在这些数据之前安排 TLS 1.3 密钥更新。控制记录（告警、
  KeyUpdate、close_notify 等）与新的发送密钥变成 `SocketOp`，与数据按顺序排队（`Bytes::Op`，写入
  在它们前面停下）。
- 接收方向在内核中：读到的数据原样交给 `on_data`；读返回 `EIO` 表示下一条是控制记录，事件循环用
  带记录类型控制消息的 `recvmsg` 读出（`ConnInner::kernel_read_record`），交给
  `Transport::kernel_record`；对端的 KeyUpdate 会立即安装新的接收密钥。close_notify 与 EOF 一样结束
  数据流。

只有在没有任何读操作可能持有传输层尚未看到的字节时，接收方向才能移入内核：

- epoll 只在事件循环的两次 flush 之间读取，因此可以立即允许（`set_rx_offload_ok`）。
- io_uring 有一个进行中的 multishot recv：发送方向移入内核后，事件循环取消该 recv，等取消完成且
  没有暂存数据时调用 `offload_rx_now`，再重新挂上 recv（每个连接最多尝试 8 次；从不停在记录边界的
  数据流，其接收方向留在用户态）。`-EIO` 完成事件的处理与 epoll 相同。
- 读缓冲区必须能放下一整条记录（`read_buffer` 不小于 16 KiB）；否则只卸载发送方向。

### 3. only-tls

- 协议核心可以单独移走发送方向（`commit_tx_offload`）：此后它要发送的内容（握手消息、告警、自己的
  密钥更新）以事件形式给出，而不是加密后的字节，记录仍在用户态解开；没有残缺数据缓存时，接收方向
  随后跟上（`commit_rx_offload`）。
- `TlsTransport` 为每个连接保存一个 `KtlsState`（仅当模式不是 `Off` 时）：挂上 `tls` ULP，安装并
  验证发送密钥，再安装接收密钥（TLS 1.3 另设 `TLS_RX_EXPECT_NO_PAD`），在 `TlsStats` 中计数
  （`only_tls_ktls_total{side, dir, path}`），并通过 `TlsInfo::ktls_tx` / `ktls_rx`
  （`KtlsPath::Software` / `Hardware`）报告。内核拒绝时（没有模块、套件不支持），什么都没有改变，
  连接继续在用户态运行。

### 4. 未做

- DPDK、QUIC 与 DTLS：没有内核 socket，或不是 TCP 记录流。
- 只卸载接收方向（只支持 RX 卸载的网卡）：不卸载。
- 撤销 `Hardware` 下落入软件的卸载（内核无法卸下 ULP）：该连接保持软件 kTLS，这个组合不再尝试。
- 硬件验证：测试主机没有 TLS 卸载网卡（igc、atlantic）。设备路径由它所用的内核接口与检测逻辑的单元
  测试覆盖；在真实硬件上测量之前，不对它的效果下结论。

## 影响

- 默认构建与 `Off` 的行为不变，测量的速度也不变（docs/BENCHMARKS.zh-CN.md，“引擎中的内核 TLS”）。
- 在支持 TLS 卸载的网卡上，`Hardware` 让 CPU 不再做记录加解密，并使 TLS 连接的 `sendfile` 零拷贝，
  同时不会让其他主机变慢。
- 工作区外的 `Transport` 实现不受影响（都是默认方法）。

## 测试

- `crates/only/tests/ktls.rs`（epoll 与 io_uring，`--features ktls`）：双向与只发送方向的软件 kTLS，
  TLS 1.3 与 1.2 下的 AES-GCM 与 ChaCha20-Poly1305，6 MiB 回显，对端连续 20 次请求密钥更新，服务端
  每 16 条记录主动更新密钥，经内核的 `sendfile`，双向 close_notify，启用 kTLS 的 `only` 客户端，以及
  `Hardware` / `Off` 在环回接口上保持用户态。内核计数器确认了安装与换钥（`TlsTxSw`、`TlsRxSw`、
  `TlsRxRekeyOk`、`TlsTxRekeyOk`；没有 `TlsDecryptError`）。
- only-sys：ethtool 特性查询与 `ethtool -k lo` 对照、`/proc/net/tls_stat` 解析；only-tls：接口表
  查找（IPv4、IPv6、IPv4 映射地址、已拒绝的组合）。
- 已有的 `experimental-ktls` 测试流测试，以及 `ONLY_INTEROP_KTLS=require` 下的
  `tools/interop/tls/run.sh`。
