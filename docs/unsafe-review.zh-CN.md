# `unsafe` 审查

[English](unsafe-review.md) | 简体中文

状态：1.0 稳定化审查，2026-11-14。每当新增、删除 `unsafe` 或其不变式发生变化时，重新生成清单并更新本页。

flash 是网络库：它的内存安全缺陷就是其使用者的远程代码执行漏洞。本页是 `unsafe` 代码的规范：每个 `unsafe` 位置必须满足的检查清单、新增 `unsafe` 的流程、清单统计，以及 1.0 审查的结论。

## 1. `unsafe` 允许出现的位置

| Crate | 状态 | 原因 |
|---|---|---|
| `flash-sys` | 允许 `unsafe`（整个 crate） | 原始系统调用的唯一归宿：epoll/kqueue、eventfd/pipe、socket、`sendfile`、`recvmmsg`/`sendmmsg` + cmsg、prefork 所需的进程相关调用（`pre_exec`、信号） |
| `flash-uring` | `#![deny(unsafe_code)]`，仅 `group` 与 `reactor` 模块允许 | io_uring 提交项指向内核异步写入的内存 |
| `flash-ebpf` | `#![deny(unsafe_code)]`，仅 `sys` 模块允许 | 原始 `bpf(2)` 调用与 socket 选项（不用 libbpf/aya） |
| `flash-dpdk` | `#![deny(unsafe_code)]`，仅 `pmd` 模块允许 | 通过 C shim `csrc/shim.c` 调用 DPDK 的 FFI（EAL、端口、mbuf 收发 burst），以及 `Sendable`（把 smoltcp 不是 `Send` 的 TAP / AF_PACKET 设备移交给其 I/O 线程） |
| 其它所有 crate（`flash`、`flash-core`、`flash-buf`、`flash-timer`、`flash-pool`、`flash-epoll`、`flash-tls`、`flash-http`、`flash-ws`、`flash-mux`、`flash-socks`、`flash-arpc`、`flash-grpc`、`flash-kcp`、`flash-quic`、`flash-h3`、`flash-turn`、`flash-webrtc`、`tools/echo-bench`） | `#![forbid(unsafe_code)]` | 构建在上述 crate 之上的纯 Rust 代码 |

测试、示例和基准是独立的 crate，可以为仅测试用的 libc 调用（`setrlimit`、`SO_LINGER`、CPU 亲和性、计数分配器）使用 `unsafe`，同样必须写注释。

工作区 lint（`Cargo.toml`），对所有 crate 生效：

- `unsafe_op_in_unsafe_fn = "deny"`：`unsafe fn` 的函数体不再隐式视为 `unsafe` 块，每个操作都需要自己的块和注释。
- `clippy::undocumented_unsafe_blocks = "deny"`：每个 `unsafe` 块和 `unsafe impl` 都有 `// SAFETY:` 注释。
- `clippy::missing_safety_doc = "deny"`：每个公开的 `unsafe fn` 都有 `# Safety` 文档段。
- `clippy::unnecessary_safety_comment` / `unnecessary_safety_doc = "warn"`：安全代码上不留过时的 `SAFETY:` 注释。

Clippy 只检查为当前主机编译的代码，因此 CI 在 Linux 和 macOS 上都运行它，并由 `tools/unsafe-inventory.py --check` 一次性检查所有平台的注释。

## 2. 检查清单：每个 `unsafe` 位置必须满足的条件

只有当 `SAFETY:` 注释（或 `unsafe fn` 的 `# Safety` 段）回答了下列所有适用项，并且代码确实保证了它们时，`unsafe` 块才被接受：

1. **指针有效性。** 交给内核或被解引用的每个指针都非空、按其类型对齐、指向同一个存活的分配，并覆盖所传递的全部长度（`iov_len`、`msg_namelen`、`msg_controllen`、`optlen`、`bpf_attr` 大小……）。长度取自同一对象的 `size_of`/`len()`，绝不取自另一个常量。
2. **跨调用的生命周期。** 系统调用引用的内存存活到调用返回；*异步*操作（io_uring SQE、provided-buffer ring、BPF map 值）引用的内存存活到内核再也无法访问它：完成事件已到达，或持有该引用的 ring / map 先被销毁（字段顺序和 `Drop` 需写明）。
3. **别名。** 在内核可能写入某段内存期间，Rust 不持有覆盖它的 `&`/`&mut`，也不持有对其声明独占的 `Vec`/`Box`；Rust 只借用内核已经交还的范围。对与内核共享的内存（ring 的 tail、条目）的写入通过裸指针或带协议要求内存序的原子操作完成。
4. **初始化。** 读回的值已初始化：只对“全零合法”的 C 结构体使用 `mem::zeroed`；来自内核的长度被截断到缓冲区大小（`min(size)`）；sockaddr 按内核写入的地址族读取。
5. **整数转换。** 决定分配或 iovec 大小的乘法和加法使用带检查的运算；向 C 类型的转换（`u16` 长度、`c_uint` 计数）经过检查或可证明在范围内。
6. **文件描述符所有权。** 原始 fd 在创建它的系统调用之后、任何可能失败的步骤之前，立即且仅一次转换为 `OwnedFd`/`TcpStream`，使每条错误路径都会关闭它；借用的 fd 绝不关闭。
7. **`Send`/`Sync`。** `unsafe impl Send/Sync` 需说明它覆盖了哪个非线程安全字段（裸指针），以及为何其它线程无法访问这些数据（移动而非共享；堆地址稳定）。
8. **ABI 布局。** 传给内核的结构体为 `#[repr(C)]`，与 UAPI 定义逐字段一致（显式填充）；若镜像了其它 crate 的类型，则用编译期断言校验大小。
9. **panic 与栈展开。** 任何 panic 都不能让内核可见的结构处于被后续操作信任的半写状态；回调在 `unsafe` 块之外、在 `catch_unwind` 中执行。
10. **最小范围。** 块中只放 unsafe 操作，不放周围的安全逻辑；优先用类型强制不变式的安全封装（例如 `Map<K, V>` 在创建时固定键/值大小），而不是靠注释。

## 3. 新增 `unsafe` 的流程

1. 先寻找安全的替代方案（`std`、已有的 `flash-sys` 封装、类型化封装）。新的 `unsafe` 放进 `flash-sys`，除非它必须紧挨后端状态（io_uring）或 BPF 加载器；已经 `forbid(unsafe_code)` 的 crate 保持不变。
2. 按上面的检查清单写 `SAFETY:` 注释；`unsafe fn` 要写 `# Safety` 段，说明调用者的义务。
3. 添加验证该不变式的测试（边界、错误路径、回绕）；若代码只是纯内存操作，让测试能在 Miri 下运行（测试中不做系统调用）。
4. 本地运行：在 Linux 和 macOS 上运行 `cargo clippy --workspace --all-targets -- -D warnings`、`python3 tools/unsafe-inventory.py --check`，对适用的 crate 运行 Miri；后端改动还要跑 io_uring 测试（`FLASH_TEST_BACKEND=uring`）。
5. PR 描述列出每个新增或修改的 `unsafe` 位置；由作者以外的审查者对照检查清单审核，并更新下方的清单表。

## 4. 工具

| 工具 | 覆盖内容 | 命令 |
|---|---|---|
| Clippy lint | 注释存在性（当前主机平台） | `cargo clippy --workspace --all-targets -- -D warnings` |
| 清单脚本 | 计数与注释检查，覆盖所有平台 | `python3 tools/unsafe-inventory.py [--markdown] [--check]` |
| Miri | 纯 Rust 代码中的 UB：别名（Stacked Borrows）、越界、未初始化读取、数据竞争 | `cargo +nightly miri test -p <crate> --lib`（Linux nightly 镜像；`MIRIFLAGS=-Zmiri-disable-isolation`） |
| loom | `flash-core` 无锁原语的交错执行 | `RUSTFLAGS="--cfg loom" cargo test -p flash-core --lib --release -- loom` |
| AddressSanitizer | 跨 FFI 的越界 / 释放后使用，包括 Miri 无法运行的系统调用路径 | `RUSTFLAGS=-Zsanitizer=address cargo +nightly test -Zbuild-std --target <host> -p <crate>` |
| ThreadSanitizer | I/O 线程、唤醒器与发送方之间的数据竞争 | 同上，改用 `-Zsanitizer=thread` |
| 模糊测试 | 解析器与协议状态机（远端输入） | `cargo fuzz` 目标（独立工作项） |
| cargo-deny / cargo-audit | 有漏洞、不健全或被撤回（yanked）的依赖 | `cargo deny check`、`cargo audit` |

Miri 无法执行系统调用（socket、epoll、io_uring、bpf），因此系统调用路径由 sanitizer 和 Linux/macOS 测试套件（epoll 与 io_uring 后端）覆盖；io_uring 中与内核共享内存的逻辑（`BufRing`、`KernelBuf`）有不做系统调用的单元测试，可在 Miri 下运行。

## 5. 清单

由 `python3 tools/unsafe-inventory.py --markdown` 生成（`src/` 下的库代码，含单元测试；集成测试、示例与基准计入最后一列）。未列出的 crate 不含 `unsafe`。

| Crate | 块 | `unsafe fn` | `unsafe impl` | 测试/示例/基准 |
|---|---:|---:|---:|---:|
| flash | 0 | 0 | 0 | 12 |
| flash-dpdk | 15 | 0 | 2 | 0 |
| flash-ebpf | 11 | 3 | 0 | 1 |
| flash-http | 0 | 0 | 0 | 8 |
| flash-sys | 68 | 1 | 3 | 0 |
| flash-uring | 18 | 1 | 1 | 0 |
| **合计** | **112** | **5** | **6** | **21** |

按用途：

| 位置 | 数量 | 用途 | 主要不变式 |
|---|---:|---|---|
| `flash-sys/src/net.rs` | 16 | `socket`/`bind`/`listen`/`connect`、`setsockopt`、`sendfile`、`SocketAddr` -> `sockaddr_storage` | sockaddr 长度与地址族一致；fd 在任何可失败步骤前即被拥有 |
| `flash-sys/src/poller.rs` | 12 + `impl Send` | epoll / kqueue 的创建、控制、等待 | 事件缓冲区有 `BATCH` 个已初始化条目；kevent 的 `udata` 只是不透明的 token |
| `flash-sys/src/process.rs` | 15，`unsafe fn errno_location` | prefork 相关：`pre_exec` 钩子（`fcntl` 清除 `FD_CLOEXEC`、`PR_SET_PDEATHSIG`、`sched_setaffinity`）、`take_inherited_fd`、self-pipe 信号处理器（`sigaction`，处理器中 `write`）、`kill` | 钩子只做异步信号安全的调用且不分配内存（所有数据在 `fork` 前准备好）；继承来的 fd 在每个进程中最多被拥有一次（`TAKEN` 集合）；处理器保存并恢复 `errno` |
| `flash-sys/src/waker.rs` | 10 | eventfd（Linux）/ pipe（macOS）唤醒器，io_uring 用的 `EventFd` | fd 立即被拥有；eventfd 写入的 8 字节来自存活的 `u64` |
| `flash-sys/src/udp.rs` | 15 + 2 个 `impl Send` | `recvmmsg`/`sendmmsg`、UDP GSO（`UDP_SEGMENT`）/ GRO cmsg、sockaddr 解析 | iovec 位于同一分配内（大小经检查）；每次调用前重建消息头；用 `CMSG_*` 在 `msg_controllen` 范围内遍历 cmsg；`Batch<'d>` 在调用期间借用待发送数据 |
| `flash-uring/src/reactor.rs` | 12 + 测试中 3 个、`unsafe fn slice`、`impl Send for Loop` | SQE 提交、provided-buffer ring（`BufRing`）、内核写入的缓冲区（`KernelBuf`）、accept 得到的 fd | 释放缓冲区时没有在途操作（全部取消并收割完成事件，否则泄漏而不释放）；内核持有的缓冲区绝不被借用；ring 条目通过裸字段指针写入；tail 以 `Release` 存储 |
| `flash-uring/src/group.rs` | 3 | 探测内核版本用的 `uname` | `utsname` 置零；内核以 NUL 结尾 `release` |
| `flash-dpdk/src/pmd.rs` | 15、`impl Send for Queue`、`impl Send for Sendable` | 调用 C shim（`rte_eal_init`、端口配置、`rte_eth_rx_burst`/`tx_burst`、mbuf 分配/释放）；从 mbuf 借出帧数据；smoltcp TAP / raw socket 设备的 `Sendable` | shim 的 ABI 只有整数和不透明指针（Rust 侧不涉及 DPDK 结构体布局）；EAL argv 故意泄漏（比 EAL 活得久），只初始化一次（`OnceLock`）；每个 mbuf 只归一个 `Queue`/`Mbuf` 所有、只释放一次（`tx_burst` 未取走的帧被释放，收到的帧在 drop 时释放）；切片只覆盖 shim 返回的单个数据段，且不超过 mbuf 的生命周期；`Queue` 与 `Sendable` 设备同一时刻只被一个线程使用（一次性移交给其 I/O 线程） |
| `flash-ebpf/src/sys.rs` | 11，3 个 `unsafe fn` | `bpf(2)`（`MAP_CREATE`、`MAP_UPDATE/DELETE_ELEM`、`PROG_LOAD`、`PROG_ATTACH`）、`SO_ATTACH_REUSEPORT_[CE]BPF`、`SO_COOKIE` | `#[repr(C)]` 的 attr 前缀与 UAPI 一致；指针字段在调用期间存活；键/值大小由 `Map<K, V>` 固定 |

## 6. 1.0 审查结论

本次审查已修复（能观察到的问题都附有回归测试）：

| # | 位置 | 问题 | 修复 |
|---|---|---|---|
| F1 | `flash-sys` `RecvBatch::with_gro` | `slots * size` 未检查：release 构建中乘法溢出会回绕，`bufs` 很小而每个 iovec 仍声称有 `size` 字节，`recvmmsg` 会写出分配范围（公开安全 API 导致的堆溢出）。 | `checked_mul` 加 `u32` 槽位数检查，并在文档中写明 panic 条件；测试 `recv_batch_rejects_overflowing_size`。 |
| F2 | `RecvBatch::recv` / `get` | 遇到 `WouldBlock` 或错误时 `got` 未清零，`get(i)` 会继续返回上一次调用的数据报（仓库内调用方只遍历 `0..n`，不可触发，但 API 行为错误）。 | 每次调用前 `got = 0`；测试 `recv_batch_forgets_previous_datagrams`。 |
| F3 | `RecvBatch::with_gro` | 每个槽位的 iovec 基址取自新的 `&mut bufs[i*size..]`；在 Stacked Borrows 下每次重借用都会使之前派生的指针失效。 | 用 `as_mut_ptr()` 取一次基址，再用 `add` 计算偏移。 |
| F4 | `RecvBatch::reset` | `sockaddr_storage` 保留上一次的地址族；若内核未填写某个消息头，会按过时的地址族解析。 | 每次接收前清除地址族。 |
| F5 | `flash-uring` provided buffers | 缓冲区放在 `Vec<u8>` 中（eventfd 读目标放在 `Box<[u8; 8]>` 中），而内核异步写入它们；`on_recv` 借用 `&self.bufs[..]`，这个共享引用覆盖所有缓冲区，包括内核可能正在由 io-wq worker 写入的那些。按 Rust 的模型这是别名 UB。 | `KernelBuf`：裸分配，不用 `Vec`/`Box`；Rust 只通过 `unsafe fn slice`（带边界检查）借用已完成的那个缓冲区。 |
| F6 | `BufRing::give` | 通过 `&mut BufRingEntry` 写条目；对 0 号条目而言，这个引用还覆盖了内核并发读取的 ring tail（`resv`）。 | 镜像的 `#[repr(C)] RawBuf`（断言大小等于 `io_uring_buf`），通过裸指针写字段；tail 用 `AtomicU16` 以 `Release` 存储。可在 Miri 下运行的测试 `buf_ring_layout_give_and_publish` 用 `io_uring` 的访问器校验布局。 |
| F7 | `BufRing::give` | 缓冲区 id 未对照缓冲区区域检查。 | 断言（`bid < BUF_COUNT` 且槽位在区域内）；测试 `buf_ring_rejects_foreign_buffer_ids`。 |
| F8 | `flash-ebpf` `sys::bpf`、`map_update`、`map_delete` | 安全函数 `fn bpf<T>(cmd, &mut T)` 接受任意 `T`；`map_update<K, V>` 让内核无论 `&K`/`&V` 实际多大都按 map 的 `key_size`/`value_size` 拷贝（越界读入 map）。 | 改为带 `# Safety` 的 `unsafe fn`；调用方使用类型化的 `Map<K, V>`，其键/值大小在创建时取 `size_of::<K/V>()`，因此它的方法是安全的。 |
| F9 | `attach_reuseport_cbpf` | 程序长度被截断为 `u16`。 | 改为返回 `InvalidInput` 错误。 |
| F10 | `flash-sys` 的 macOS 路径（`socket_of`、pipe `Waker`、`kqueue` `Poller`） | 创建后的 `fcntl` 失败时 fd 泄漏。 | 在可失败步骤之前先包装成 `OwnedFd`。 |
| F11 | `flash-uring` 事件循环退出 | `Loop` 先关闭 ring，再释放 provided buffers、buffer ring 和唤醒缓冲区，而此时可能仍有在途操作：内核拆除 ring 的一部分工作在异步 exit work 中进行；并且在关闭超时（或 `io_uring_enter` 出错）后，循环退出时连接及其 multishot `recv` 仍处于挂起状态，迟到的完成事件可能写入已释放的内存。 | 循环统计在途操作数（每个 SQE 恰有一个最终 CQE）；`drain_inflight` 在释放内存前提交 `ASYNC_CANCEL_ANY` 并收割完成事件直到没有在途操作（accept 若仍送来 fd 则关闭它）；若 2 秒内未完成，则有意泄漏这些内存而绝不释放。io_uring 测试套件中没有出现泄漏日志。 |
| F12 | `flash-core` `consume_datagrams` | 仅 Linux 下的死代码使 Linux 上的 `clippy -D warnings` 失败（来自 UDP 批量化改动）。 | `#[cfg(not(target_os = "linux"))]`。 |

已接受（已记录，目前无需改动）：

- **缓冲区 id 只归还一次。** `give_back` 只对完成事件携带的 `bid` 执行，因此在外的条目最多 `BUF_COUNT` 个，tail 所在槽位绝不会是内核正在读取的条目。现在还有范围断言兜底（F7）。
- **`unsafe impl Send`**：`Poller`（kevent 的 `udata` 只是 token，从不解引用）、`RecvBatch`（指针指向自身的堆缓冲区，随结构体一起移动）、`SendBatch`（批次之间指针悬空，但每次发送前都从存活的 `Batch<'d>` 重建）和 `Loop`（在一个线程上构建，之后归其 I/O 线程所有；SQE 指针指向不会移动的堆内存）。它们都没有实现 `Sync`。
- **信任内核提供数据的布局**：sockaddr 地址族、`cmsg_len`、`msg_len`（已截断）、CQE 缓冲区 id（现已做范围检查）。这是内核 ABI 契约。
- **含 `unsafe` 的依赖**（`libc`、`io-uring`、`rustls`/`ring`、`quinn-proto`、RustCrypto、使用 `zlib-rs` 的 `flate2`）被信任，并由 `cargo deny`/`cargo audit` 跟踪。

## 7. 验证结果（本次审查）

- `cargo clippy --workspace --all-targets -- -D warnings`：在启用上述更严格 lint 的情况下，macOS（aarch64）和 Linux（Docker `rust:1`，1.98）均无告警。
- `tools/unsafe-inventory.py --check`：所有位置都有注释。
- 合并 `main`（`fa5f413`，包含更严格的 lint、fuzzing 模块以及 io_uring `graveyard`、复位监视等混沌测试修复）后重新验证：`cargo clippy --workspace --all-targets --all-features -- -D warnings` 与 `RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps --all-features` 在 macOS 和 Linux 上均无告警；`cargo test --workspace` 在 macOS 和 Linux（epoll）上通过；flash、flash-uring、flash-http、flash-ws、flash-kcp、flash-quic 在 `FLASH_TEST_BACKEND=uring` 下通过；io_uring 混沌测试种子 1..30 通过；没有出现在途操作泄漏日志。新的混沌测试代码没有引入 `unsafe`。
- 测试套件（合并前）：macOS `cargo test --workspace` 全部通过；Linux `cargo test --workspace`（epoll）以及 `flash`、`flash-uring`、`flash-sys`、`flash-ebpf`、`flash-http`、`flash-ws`、`flash-kcp`、`flash-quic` 在 `FLASH_TEST_BACKEND=uring` 下全部通过。
- 供应链：`cargo deny check` 输出 `advisories ok, bans ok, licenses ok, sources ok`；`cargo audit -D warnings` 无告警。唯一发现的通告 RUSTSEC-2026-0009（`time` 0.3.45）已在 `deny.toml` 与 `.cargo/audit.toml` 中带理由忽略：它只经由 `rcgen` 引入，而 `rcgen` 是生成测试证书的开发依赖，从不解析 RFC 2822 输入；修复版 `time` 0.3.47 需要 Rust 1.88，高于 CI 检查测试目标时使用的 1.85 MSRV。MSRV 升到 1.88 后删除此例外。

### Miri（nightly 1.102，`-Zmiri-disable-isolation`，Stacked Borrows）

| Crate（`--lib`） | 结果 |
|---|---|
| flash-buf、flash-timer、flash-pool | 通过（4 / 5 / 5 个测试） |
| flash-http | 通过（27 个测试，35 秒） |
| flash-mux、flash-socks、flash-arpc、flash-h3 | 通过（1 / 1 / 3 / 2） |
| flash-kcp | 通过（5 个测试，4-6 分钟） |
| flash-uring（`buf_ring`、`kernel_buf` 测试） | 通过（3 个）：即 F5-F7 中与内核共享内存的代码 |
| flash-ws | 20 个中 15 个通过；其余 5 个（permessage-deflate 往返与穷举拆分循环）在 Miri 下 5-15 分钟内跑不完 |
| flash-core、flash-quic | 除 loom / 集成测试外没有单元测试 |
| flash-ebpf | 15 分钟内跑不完（单元测试在大量输入上运行 cBPF 解释器；均为安全代码，不涉及 `sys` 模块） |
| **flash-grpc** | **在依赖中报告了 UB**：`tests::framing_and_gzip` 在 drop `flate2::write::GzEncoder` 时于 `zlib_rs::allocate::zfree_rust` 失败（`zlib_rs::stable::Deflate::drop` -> `deflate::end` 释放了一块仍被受保护的 `&mut` 函数参数覆盖的内存）。在 Tree Borrows 下同样复现。`zlib-rs` 0.6.8 已是最新版本；flash 在这条路径上没有任何 `unsafe`。 |

`zlib-rs` 的问题是依赖内部违反别名模型，而不是观察到的内存破坏；应附上述复现向上游（trifectatech/zlib-rs）报告。修复之前，CI 的 Miri 任务跳过 `framing_and_gzip` 和 deflate 往返测试；它还跳过回放模糊测试语料的 `fuzzing::` 测试（在 Miri 下每个 crate 需数分钟，而 fuzz 任务会原生运行这些输入）。`flate2` 当初从 `miniz_oxide` 切换到 `zlib-rs`，是因为前者有真实的数据丢失缺陷（见 WebSocket 相关说明），所以不能切回去；改用 C 的 `zlib` 后端则会让 Miri 完全看不到这段代码。

### Sanitizer

本次审查未能运行 ASan 和 TSan：在可用的 Linux 环境（Apple 芯片上的 Docker，linuxkit 6.12 aarch64 内核）中，即使是空的 `fn main` 用 `-Zsanitizer=address` 或 `-Zsanitizer=thread` 构建，启动时也会 SIGSEGV（sanitizer 运行时不支持该虚拟机的地址空间布局；`setarch -R` 无效，`vm.mmap_rnd_bits` 也无法修改）。建议作为 CI 任务在 `ubuntu-latest`（x86_64）上运行，两者在那里都受支持。
