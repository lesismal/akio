# `unsafe` 审查

[English](unsafe-review.md) | 简体中文

状态：1.0 稳定化审查，2026-11-14；2026-11-16 新增 `only-crypto` 的 `fill` 模块（AEAD 输出写入未初始化的空闲容量）。每当新增、删除 `unsafe` 或其不变式发生变化时，重新生成清单并更新本页。

only 是网络库：它的内存安全缺陷就是其使用者的远程代码执行漏洞。本页是 `unsafe` 代码的规范：每个 `unsafe` 位置必须满足的检查清单、新增 `unsafe` 的流程、清单统计，以及 1.0 审查的结论。

## 1. `unsafe` 允许出现的位置

| Crate | 状态 | 原因 |
|---|---|---|
| `only-sys` | 允许 `unsafe`（整个 crate） | 原始系统调用的唯一归宿，也是工作区自有的操作系统绑定（`ffi`：C 类型、常量、`#[repr(C)]` 结构体、`extern "C"` 声明；不再使用 `libc` crate）：epoll/kqueue、eventfd/pipe、socket、`sendfile`、`recvmmsg`/`sendmmsg` + cmsg、prefork 所需的进程相关调用（`pre_exec`、信号）、内核 CSPRNG（`getrandom` / `getentropy`） |
| `only-uring` | `#![deny(unsafe_code)]`，仅 `group`、`reactor` 与 `ring` 模块允许（以及仅测试用的 `eval` 测量工具） | io_uring 提交项指向内核异步写入的内存；`ring` 是自有的 io_uring 绑定（setup/enter/register、mmap 映射的 SQ/CQ ring；不再使用 `io-uring` crate） |
| `only-ebpf` | `#![deny(unsafe_code)]`，仅 `sys` 模块允许 | 原始 `bpf(2)` 调用与 socket 选项（不用 libbpf/aya） |
| `only-dpdk` | `#![deny(unsafe_code)]`，仅 `pmd` 与 `sys` 模块允许；TCP/IP 协议栈（`net`）为 `#![forbid(unsafe_code)]` | 通过 C shim `csrc/shim.c` 调用 DPDK 的 FFI（EAL、端口、mbuf 收发 burst）；通过 `only_sys::ffi` 使用 TAP（`/dev/net/tun`、`TUNSETIFF`）与 AF_PACKET socket |
| `only-crypto` | `#![deny(unsafe_code)]`，仅十二个 CPU 指令模块 `aes::hw`、`gcm::hw`（含 `gcm::hw::vaes`）、`hash::hw`、`crc::hw`、`chacha::hw`（含 `chacha::hw::avx512` 与 `chacha::hw::ifma`）、`cpu::hw`、`ec::hw`、`ec::hw_aarch64`、`curve25519::hw`、`curve25519::hw_aarch64`、`bignum::hw`、`bignum::ifma`，以及 `fill`（基于向量未初始化空闲容量的 AEAD 输出缓冲区）允许 | AES-NI / ARMv8 AES、PCLMULQDQ / PMULL、SHA-NI / ARMv8 SHA、SSE4.2 / ARMv8 CRC32 与 AVX2 intrinsic（`#[target_feature]` 函数），基于 VAES / VPCLMULQDQ 搭配 AVX-512 或 AVX2 的 `asm!` AES-GCM 内核，以及基于 VAES / VPCLMULQDQ + AVX-512 的 CRC 折叠（这些 intrinsic 比 MSRV 新），P-256 与 Curve25519 域运算以及 RSA 的 Montgomery 乘法与平方中使用 BMI2 `mulx` 与 ADX `adcx`/`adox` 的 `asm!` 块，RSA 模幂与 Poly1305 中使用 AVX-512 IFMA 的 `asm!` 块以及 AVX-512 上的 ChaCha20 `asm!` 块（同样在 MSRV 上不稳定），aarch64 上 P-256 与 Curve25519 域运算中使用 `MUL`/`UMULH` 与 `ADDS`/`ADCS` 进位链的 `asm!` 块，以及检测 VAES、AVX-512、IFMA、BMI2 与 ADX 所用的 CPUID / XGETBV；每次调用前都经过 `cpu.rs` 的运行时检测；`fill` 让 TLS 记录层（`#![forbid(unsafe_code)]`）直接在 `Vec` 的空闲容量中加密和解密，不必先清零（16 KiB AES-GCM 记录约 10%），其 `unsafe` 只用于在每个字节都写入后把缓冲区视为字节切片以及 `Vec::set_len`；可移植回退实现与其余公钥代码（可移植的大数运算、点运算公式、RSA 协议代码、DER）均为安全 Rust |
| `tools/ct-dudect` | `#![deny(unsafe_code)]`，仅 `timer` 模块允许 | 统计计时测试（docs/constant-time.zh-CN.md）：两处读取周期计数器的 `asm!`（x86_64 为 `lfence; rdtsc; lfence`，aarch64 为 `isb; mrs cntvct_el0`），只用寄存器、不访问内存；不发布 |
| 其它所有 crate（`only`、`only-core`、`only-x509`、`only-buf`、`only-timer`、`only-pool`、`only-epoll`、`only-tls`、`only-http`、`only-ws`、`only-mux`、`only-socks`、`only-arpc`、`only-grpc`、`only-protobuf`、`only-protobuf-build`、`only-kcp`、`only-quic`、`only-h3`、`only-turn`、`only-dtls`、`only-srtp`、`only-rtp`、`only-sctp`、`only-ice`、`only-webrtc`、`only-media`、`tools/echo-bench`、`tools/protobuf-test`） | `#![forbid(unsafe_code)]` | 构建在上述 crate 之上的纯 Rust 代码 |

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

1. 先寻找安全的替代方案（`std`、已有的 `only-sys` 封装、类型化封装）。新的 `unsafe` 放进 `only-sys`，除非它必须紧挨后端状态（io_uring）或 BPF 加载器；已经 `forbid(unsafe_code)` 的 crate 保持不变。
2. 按上面的检查清单写 `SAFETY:` 注释；`unsafe fn` 要写 `# Safety` 段，说明调用者的义务。
3. 添加验证该不变式的测试（边界、错误路径、回绕）；若代码只是纯内存操作，让测试能在 Miri 下运行（测试中不做系统调用）。
4. 本地运行：在 Linux 和 macOS 上运行 `cargo clippy --workspace --all-targets -- -D warnings`、`python3 tools/unsafe-inventory.py --check`，对适用的 crate 运行 Miri；后端改动还要跑 io_uring 测试（`ONLY_TEST_BACKEND=uring`）。
5. PR 描述列出每个新增或修改的 `unsafe` 位置；由作者以外的审查者对照检查清单审核，并更新下方的清单表。

## 4. 工具

| 工具 | 覆盖内容 | 命令 |
|---|---|---|
| Clippy lint | 注释存在性（当前主机平台） | `cargo clippy --workspace --all-targets -- -D warnings` |
| 清单脚本 | 计数与注释检查，覆盖所有平台 | `python3 tools/unsafe-inventory.py [--markdown] [--check]` |
| Miri | 纯 Rust 代码中的 UB：别名（Stacked Borrows）、越界、未初始化读取、数据竞争 | `cargo +nightly miri test -p <crate> --lib`（Linux nightly 镜像；`MIRIFLAGS=-Zmiri-disable-isolation`） |
| loom | `only-core` 无锁原语的交错执行 | `RUSTFLAGS="--cfg loom" cargo test -p only-core --lib --release -- loom` |
| AddressSanitizer | 跨 FFI 的越界 / 释放后使用，包括 Miri 无法运行的系统调用路径 | `RUSTFLAGS=-Zsanitizer=address cargo +nightly test -Zbuild-std --target <host> -p <crate>` |
| ThreadSanitizer | I/O 线程、唤醒器与发送方之间的数据竞争 | 同上，改用 `-Zsanitizer=thread` |
| 模糊测试 | 解析器与协议状态机（远端输入） | `cargo fuzz` 目标（独立工作项） |
| cargo-deny / cargo-audit | 有漏洞、不健全或被撤回（yanked）的依赖 | `cargo deny check`、`cargo audit` |

Miri 无法执行系统调用（socket、epoll、io_uring、bpf），因此系统调用路径由 sanitizer 和 Linux/macOS 测试套件（epoll 与 io_uring 后端）覆盖；io_uring 中与内核共享内存的逻辑（`BufRing`、`KernelBuf`）有不做系统调用的单元测试，可在 Miri 下运行。

Miri 同样不解释 SIMD intrinsic，也无法执行 `asm!`：在 Miri 下 `only-crypto` 检测不到任何 CPU 特性，只运行可移植实现（`cargo +nightly miri test -p only-crypto --lib -- aes:: gcm:: hash:: crc:: chacha:: field:: ec:: curve25519:: x25519:: …`）。其中包括 `fill` 模块与可移植的追加路径（`-- fill append`），即写入未初始化空闲容量的代码；向量内核非原地写入其中的部分，由原生运行的差分测试检查（0..=600 的每个长度与若干大长度，在每个内核上把追加路径与原地路径比较）。CPU 指令模块改由以下方式验证：单元测试逐一比较硬件路径与可移植路径（`hardware_matches_portable` / `hardware_matches_table`，`ec::hw`、`ec::hw_aarch64`、`curve25519::hw` 与 `curve25519::hw_aarch64` 的 `matches_portable` 覆盖随机值与边界值，`chains_match_portable` 覆盖长串相互依赖的运算（aarch64），`ec::hw` 的 `points_match_portable` 把整点汇编例程与可移植公式逐 limb 比较（随机 `Z` 的随机点、Wycheproof 点、`P + P`、`P + (-P)`、无穷远点），`twin_matches_portable` 覆盖 P-256 各项运算，`safegcd` 的 `matches_fermat`）；所有 KAT（NIST CAVP、RFC、Wycheproof）在 x86_64 与 aarch64 上各跑两遍，一遍默认、一遍设置 `ONLY_CRYPTO_PORTABLE=1`；以及差分模糊测试目标 `crypto_hash`、`crypto_aead` 与 `crypto_sig_verify`。`gcm::hw::vaes` 的 `asm!` 内核在 Miri 下永不执行（检测不到任何特性）；`gcm::tests` 在 0..=600 的每个长度、若干大长度、0..=300 及 512 以上的每种 AAD 长度上，以未对齐、原地与非原地（包括 TLS 1.3 记录层那样输入分散在两个缓冲区）、32 位计数器回绕等情形，把两个内核互相比较（用 `AesGcm::with_cipher_avx2` 强制走 AVX2 内核），并与 128 位内核、可移植实现以及 ring 对比，CAVP 与 Wycheproof 向量（`tests/kat.rs`）同样跑遍每个内核；这些测试必须在具备 VAES 与 AVX-512 的 CPU（Zen 4、Ice Lake 及更新）上原生运行才能覆盖两个内核；`ec::hw` 与 `curve25519::hw` 的比较同样需要 BMI2 与 ADX，`ec::hw_aarch64` 与 `curve25519::hw_aarch64` 的比较则在任何 aarch64 机器上运行（Apple 芯片上的 macOS、Docker 中的 arm64 Linux）。`chacha::hw::avx512` 与 `chacha::hw::ifma` 的 ChaCha20 与 Poly1305 内核以同样方式与 AVX2 路径及可移植实现对比（`chacha::tests`：0..=600 的每个长度与若干大长度，未对齐、原地与非原地、伪造标签、接近回绕的计数器；Poly1305 覆盖全 1 分组与极端的 `r`、`s`），需要 AVX-512 与 IFMA；`crypto_aead` 模糊测试目标同样覆盖它们。

## 5. 清单

由 `python3 tools/unsafe-inventory.py --markdown` 生成（`src/` 下的库代码，含单元测试；集成测试、示例与基准计入最后一列）。未列出的 crate 不含 `unsafe`。

| Crate | 块 | `unsafe fn` | `unsafe impl` | 测试/示例/基准 |
|---|---:|---:|---:|---:|
| only | 0 | 0 | 0 | 12 |
| only-dpdk | 31 | 0 | 1 | 0 |
| only-ebpf | 11 | 3 | 0 | 1 |
| only-http | 0 | 0 | 0 | 8 |
| only-crypto | 138 | 70 | 0 | 0 |
| only-sys | 87 | 3 | 3 | 0 |
| only-uring | 41 | 4 | 1 | 0 |
| ct-dudect | 2 | 0 | 0 | 0 |
| **合计** | **310** | **80** | **5** | **21** |

按用途：

| 位置 | 数量 | 用途 | 主要不变式 |
|---|---:|---|---|
| `only-sys/src/ffi/` | 5 + 布局测试中 7 个，`unsafe fn errno_location`、`cmsg_firsthdr`、`cmsg_nxthdr` | 自有的操作系统绑定：C 库（Linux）/ libSystem（macOS）的 `extern "C"` 声明、常量、`#[repr(C)]` 结构体、`CMSG_*` 辅助函数、`cpu_set_t`、errno | 见下文“自有系统调用层” |
| `only-sys/src/net.rs` | 15 | `socket`/`bind`/`listen`/`connect`、`setsockopt`、`sendfile`、`SocketAddr` -> `sockaddr_storage` | sockaddr 长度与地址族一致；fd 在任何可失败步骤前即被拥有 |
| `only-sys/src/poller.rs` | 12 + `impl Send` | epoll / kqueue 的创建、控制、等待 | 事件缓冲区有 `BATCH` 个已初始化条目；kevent 的 `udata` 只是不透明的 token |
| `only-sys/src/process.rs` | 12 | prefork 相关：`pre_exec` 钩子（`fcntl` 清除 `FD_CLOEXEC`、`PR_SET_PDEATHSIG`、`sched_setaffinity`）、`take_inherited_fd`、self-pipe 信号处理器（`sigaction`，处理器中 `write`）、`kill` | 钩子只做异步信号安全的调用且不分配内存（所有数据在 `fork` 前准备好）；继承来的 fd 在每个进程中最多被拥有一次（`TAKEN` 集合）；处理器保存并恢复 `errno` |
| `only-sys/src/waker.rs` | 10 | eventfd（Linux）/ pipe（macOS）唤醒器，io_uring 用的 `EventFd` | fd 立即被拥有；eventfd 写入的 8 字节来自存活的 `u64` |
| `only-sys/src/ktls.rs` | 9 | 内核 TLS（实验性，only-tls 的 `experimental-ktls`）：`TCP_ULP` 与 `SOL_TLS` 的 `setsockopt`、带记录类型 cmsg 的 `sendmsg`/`recvmsg`、`uname`、擦除复制出的密钥 | crypto-info 结构体在栈上整体构造，并在布局测试中与 `libc` 对照；cmsg 缓冲区 8 字节对齐、长度为 `CMSG_SPACE(1)`；用 `CMSG_*` 在 `msg_controllen` 范围内遍历 cmsg |
| `only-sys/src/udp.rs` | 14 + 2 个 `impl Send` | `recvmmsg`/`sendmmsg`、UDP GSO（`UDP_SEGMENT`）/ GRO cmsg、sockaddr 解析 | iovec 位于同一分配内（大小经检查）；每次调用前重建消息头；用 `CMSG_*` 在 `msg_controllen` 范围内遍历 cmsg；`Batch<'d>` 在调用期间借用待发送数据 |
| `only-crypto/src/aes/hw.rs` | 26 个块、26 个 `unsafe fn`（x86_64 与 aarch64 两套；其他平台 6 个桩函数，永不调用） | AES-NI / ARMv8 AES 的密钥扩展、分组加密与解密，CTR 每次 8 个分组（轮数为常量泛型，完全展开） | 只有在 `cpu::cpu_has(Feature::Aes)`（`is_x86_feature_detected!("aes")` + `sse2` / `is_aarch64_feature_detected!("aes")`）之后才会构造 `hw::Keys`；加载与存储不要求对齐，且不越出 16 字节数组或 `&mut [u8; 128]` 块中的 16 字节片段；密钥扩展中的 `SubWord` 用 AES 指令计算，没有以密钥为下标的查表 |
| `only-crypto/src/gcm/hw.rs` | 25 个块、17 个 `unsafe fn`（其他平台 2 个桩函数） | 基于 PCLMULQDQ / PMULL 的 GHASH（每次归约聚合 8 个分组，Karatsuba），以及单趟融合的 AES-GCM 加解密（同一循环里执行 AES-NI / ARMv8 AES 轮函数与无进位乘法）；对 `vaes` 的调用（AVX-512 内核处理完整分组组与整条消息，AVX2 内核处理完整分组组） | 只有在 `cpu_has(Feature::Clmul)`（PCLMULQDQ + SSSE3 + SSE4.1 / aarch64 AES 扩展）之后才会构造 `Powers`；安全包装函数每次调用前都重新检查 `cpu_has`（融合内核还检查 `Feature::Aes`，AVX2 内核检查 `Aes`、`Clmul` 与 `Vaes`，AVX-512 内核另加 `Avx512`）；每次加载读取的 16 字节都位于长度已被包装函数截为 16（GHASH）或 128（融合）整数倍的切片内；宽内核只拿到同时位于输入与输出切片内的完整 256 字节组，只有原地处理时两个指针才相同；处理整条消息时，AVX-512 内核还拿到 AAD（至多 256 字节，来自存活的切片）与分组组之后的尾部（不足 256 字节，从输入切片紧跟分组组之处读取，写到输出中紧跟分组组之处），字节掩码与幂次指针由 `vaes::Args` 按这些长度推导；输入分散在 `src` 与输出两处时（TLS 1.3 记录层）分两次调用：先非原地处理 `src` 中的完整分组组，再原地处理其余部分；非原地时输出是可能未初始化的 `fill::Fill`：内核拿到 `Fill::next_ptr(n)`（指向接下来 `n` 个未写字节，带边界检查），只往那里写（AVX2 内核只回读自己写入的密文用于 GHASH），每次这样的调用之后紧跟 `Fill::assume_written(n)`（4 个块），`n` 恰为内核写入的字节数（完整分组组，整条消息时再加掩码尾部） |
| `only-crypto/src/gcm/hw/vaes.rs` | 4 个块、2 个 `unsafe fn` | AES-GCM 加密 / 解密，每个内核每个方向一个 `asm!` 块（这些 intrinsic 在 MSRV 下未稳定）：VAES + VPCLMULQDQ + AVX-512 上每次迭代用 4 个 zmm 寄存器处理 16 个分组，GHASH 与 AES 轮函数交织，每组一次 Montgomery 归约，另外处理 AAD、以 AVX-512 字节掩码处理最后一个不完整的组、长度块与 `E(J0)`（短消息的 AAD、数据与长度块只做一次归约）；VAES + VPCLMULQDQ + AVX2 上每次迭代用 8 个 ymm 寄存器处理 16 个分组（轮密钥与常量取自内存），只处理完整分组组 | 只有 `Powers` 带对应种类的宽内核幂次时才进入（幂次只在 `cpu::has` 确认 AES 与 VAES——zmm 内核另加 AVX-512——后生成），且 `avx2_available()` / `wide_available()` 在调用前再次确认 AES-NI、PCLMULQDQ、VAES、VPCLMULQDQ、AVX2 与操作系统保存 YMM 状态（以及 AVX-512 F/BW/VL 与 ZMM、opmask 状态）；读取轮密钥 `rk[0]` 与 `rk[r-13..=r]`（下标 >= 1，r <= 14）、512 字节的幂次表（16 个幂次加 16 个零项：`n` 个分组的幂次指针从第 `16 - n` 项开始，从它读 4 个向量仍在表内）、320 字节常量、`Args` 块、`n * 256` 字节输入，以及掩码选中的 AAD 与尾部字节；写入 `n * 256` 字节输出与其后掩码选中的尾部（每组与尾部都先加载再存储，因此可原地处理）、GHASH 状态与标签；被掩掉的字节既不读也不写（AVX-512 掩码加载会抑制故障）；输出使用显式寄存器，所有向量寄存器、掩码寄存器与标志位声明为被破坏（`clobber_abi("C")`），不使用栈，结尾执行 `vzeroupper`；掩码只取决于长度 |
| `only-crypto/src/fill.rs` | 3 个块、1 个 `unsafe fn` | `Fill`：一个起初可能未初始化的 AEAD 输出缓冲区（`Vec` 的空闲容量），从前往后写入（`push`、`push_xor`，以及内核经 `next_ptr` + `assume_written` 写入），可先写入一段已初始化的后缀（`push_back`，即 TLS 1.3 的内层内容类型）；`append` 在 `Vec::spare_capacity_mut` 上执行一次加密或解密，只有每个字节都已写入才扩展向量 | `Fill` 记录 `pos`（已写前缀）与 `tail`（已写后缀的起点）；`filled()` 先断言 `pos >= tail` 才交出覆盖整个缓冲区的 `&mut [u8]`；`Fill::init` 把已初始化的 `&mut [u8]` 视为 `&mut [MaybeUninit<u8>]`，因为 `Fill` 只会存入 `u8` 值，所以是健全的；`assume_written`（`unsafe fn`）只在内核恰好写入这些字节之后调用；`append` 先预留容量，`set_len` 前断言缓冲区已写满，打开失败时不改长度并把已写的字节清零（空闲容量中不留未验证的明文）；任何位置 panic 都不会改变向量长度。由 `fill::tests` 与可移植的 `append_portable` 测试在 Miri 下覆盖 |
| `only-crypto/src/cpu.rs`（`cpu::hw`） | 5 个块、1 个 `unsafe fn` | 用 CPUID（叶 0、1、7）与 XGETBV（XCR0）检测 VAES、VPCLMULQDQ、AVX-512 以及操作系统是否保存 YMM / ZMM 状态，以及 BMI2 + ADX（叶 7，无需操作系统状态） | 每颗 x86_64 CPU 都有 CPUID，只有叶 0 报告存在时才读取叶 1 与叶 7；只在 CPUID.1:ECX.OSXSAVE 置位后执行 XGETBV；Miri 下不编译 |
| `only-crypto/src/hash/hw.rs` | 8 个块、8 个 `unsafe fn`（2 个桩函数） | 基于 SHA-NI（x86_64）与 ARMv8 SHA1/SHA2 指令的 SHA-1、SHA-256 压缩函数 | 包装函数只在 `cpu_has(Feature::Sha)`（SHA + SSSE3 + SSE4.1 / `sha2`）时调用；加载读取分组切片中 64 字节块内的 16 字节片段，状态从存活的 `[u32; 5]` / `[u32; 8]` 加载并写回 |
| `only-crypto/src/crc/hw.rs` | 15 个块、9 个 `unsafe fn` | CRC-32 / CRC-32C：x86_64 上的 PCLMULQDQ 折叠（4 个 128 位累加器）、从 512 字节起的 VPCLMULQDQ + AVX-512 折叠（4 个 512 位累加器，每步 256 字节，一个 `asm!` 块）与 SSE4.2 `crc32` 指令，aarch64 上的 ARMv8 CRC32 指令 | 只在 `cpu_has(Feature::Clmul)` / `cpu_has(Feature::Crc)` 之后调用（512 位折叠还要求 `Vaes` 与 `Avx512`，调用前由 `wide_available()` 再次确认）；折叠循环只在 `len >= 64` 时运行，在偏移 `o` 处读取 16 字节且满足 `o + 16 <= len`（由循环条件保证）；`asm!` 折叠拿到长度为 256 的非零整数倍的切片并只读取这些字节、80 字节常量（`#[repr(C)]`，偏移固定），写入一个 16 字节数组；折叠常量是公开多项式的编译期函数 |
| `only-crypto/src/chacha/hw.rs` | 11 个块、1 个 `unsafe fn` | AVX2 一次计算 8 个 ChaCha20 分组（8×8 转置还原为分组）；对 `chacha::hw::avx512` 与 `chacha::hw::ifma` 的调用 | `xor8` 只在 `cpu_has(Feature::Avx2)` 之后调用；加载与存储是 `&mut [u8; 512]` 中的 32 字节片段；8 个分组的计数器不会回绕（由调用方检查）；`xor_wide`（原地）与 `xor_wide_into`（非原地写入可能未初始化的 `fill::Fill`）再次检查 `cpu_has(Feature::Avx512)`，只把位于 `dst` / `src` 与 `Fill::next_ptr(n)`（带边界检查，只写）之内的整组交给内核，长度恰好为一组的最后部分直接处理，其他不完整的最后一组经本地缓冲区处理；每次非原地内核调用之后紧跟 `Fill::assume_written(n)`，`n` 恰为内核写入的字节数；`poly_blocks` 再次检查 `cpu_has(Feature::Ifma)`，并断言长度为 128 字节的非零整数倍 |
| `only-crypto/src/chacha/hw/avx512.rs` | 1 个块（经宏每个内核一个，共三个实例）、1 个 `unsafe fn`（仅 x86_64） | ChaCha20 每次迭代处理 16（zmm）、8（ymm）或 4（xmm）个分组，各一个 `asm!` 块（`vprold` 循环移位，128 位通道内 4×4 转置加 `vshufi32x4` 通道转置还原为分组；这些 intrinsic 在 MSRV 上不稳定） | 只经 `xor_wide` 在 `cpu_has(Feature::Avx512)`（AVX-512 F/BW/VL 与操作系统保存 ZMM 状态）之后进入；读取 64 字节状态、128 字节常量与 `src` 中的 `n` 组，向 `dst` 写入 `n` 组（每个 64 字节分组先加载再存储，因此可原地处理），非对齐访问，不使用栈；所有向量寄存器与标志位声明为被破坏（`clobber_abi("C")`），结尾执行 `vzeroupper`；除轮数与组计数器外没有分支 |
| `only-crypto/src/chacha/hw/ifma.rs` | 1 个块、1 个 `unsafe fn`（仅 x86_64） | 基于 AVX-512 IFMA 的 Poly1305，以 44/44/42 位 limb 每次迭代处理 8 个分组（`vpmadd52luq`/`vpmadd52huq`；在 MSRV 上不稳定），一个 `asm!` 块 | 只经 `poly_blocks` 在 `cpu_has(Feature::Ifma)` 之后进入；读取 192 字节的通道累加器、320 字节的幂次、128 字节常量与 `n * 128` 字节消息，写回累加器，不使用栈；limb 始终小于 2⁵²（输入小于 2⁴⁵，乘数小于 2⁵⁰），因此 52 位乘积是精确的；所有向量寄存器与标志位声明为被破坏，结尾执行 `vzeroupper`；除组计数器外没有分支 |
| `only-crypto/src/ec/hw.rs` | 14 个块、2 个 `unsafe fn`（仅 x86_64） | `asm!` 实现的 P-256 运算：模 `p`（专用约简，`-p⁻¹ = 1`）与模群阶 `n` 的 Montgomery 乘法与平方、加法、减法、`2ᵏ·a`、`3·a`；整点 Jacobian 倍点（也可连续 `n` 次）、加法与混合加法，各为一个作用于栈上帧的汇编块；59 步 safegcd divsteps；ECDH 窗口表与宽固定基梳表的 AVX2 扫描（`#[target_feature]` 函数） | 域、群阶与点运算汇编块只在 `cpu::has(Feature::Adx)`（BMI2 + ADX）之后到达：`P256X` 孪生曲线经由 `P256` 的分派进入，标量域在每次调用前检查，每个函数都有 debug 断言；域运算块只读取指针操作数指向的 32 字节 limb 数组（`pure`、`readonly` 或 `nomem`、`nostack`），只写声明的寄存器；点运算块只读写自己的帧（经 `rdi` 传入的局部 `[u64; 48..76]`，每个地址都是 `rdi` 加一个小于帧大小的常量），`nostack`，并把编译器保留的 `rbx`（块内存放移位计数 32）存入帧头、在块结束前恢复；divsteps 块只用寄存器（基础指令）；AVX2 函数只在 `cpu::cpu_has(Feature::Avx2)` 之后调用，从存活表项的每个 4-limb 数组读取 32 字节；除 divsteps 的循环计数外没有分支（修正用 `cmov`/`sbb`/`sar` 掩码） |
| `only-crypto/src/curve25519/hw.rs` | 5 个块（仅 x86_64） | X25519 阶梯在四个 limb 上模 `2²⁵⁵ - 19` 的 `asm!` 运算（乘法、平方、`121665·a`、加法、减法；按 `2²⁵⁶ ≡ 38` 折叠） | 只在 `hw::enabled()`（`cpu::has(Feature::Adx)`）之后调用 `ladder`，每个函数都有 debug 断言；内存与寄存器约束同 `ec/hw.rs`，没有分支 |
| `only-crypto/src/ec/hw_aarch64.rs` | 8 个块（仅 aarch64） | `ec/hw.rs` 的 aarch64 对应实现，`asm!`：模 `p`（不用乘法的专用约简）与模 `n` 的 Montgomery 乘法与平方、加法、减法、`2ᵏ·a`、`3·a`，使用 `MUL`/`UMULH`、`ADDS`/`ADCS`/`SUBS`/`SBCS` 与 `CSEL` | 只用 ARMv8.0-A 基础指令，所有 aarch64 CPU 都具备；只在 `hw_aarch64::enabled()`（`cpu::has(Feature::Umulh)`，aarch64 上 Miri 之外均置位，`ONLY_CRYPTO_PORTABLE` 可关闭）时到达：`P256A` 孪生曲线经由 `P256` 的分派进入，标量域逐次检查；汇编块的操作数全部在寄存器中，不访问内存（`pure`、`nomem`、`nostack`），只写声明的寄存器，没有分支（修正用基于进位标志的 `CSEL` 与 `SBC` 掩码） |
| `only-crypto/src/curve25519/hw_aarch64.rs` | 5 个块（仅 aarch64） | `curve25519/hw.rs` 的 aarch64 对应实现：X25519 阶梯在四个 limb 上模 `2²⁵⁵ - 19` 的 `asm!` 运算（乘法、平方、`121665·a`、加法、减法；用 `CSEL` 按 `2²⁵⁶ ≡ 38` 折叠） | 只在 `hw_aarch64::enabled()`（`cpu::has(Feature::Umulh)`）之后调用 `ladder`；与 `ec/hw_aarch64.rs` 相同的纯寄存器约束，没有分支 |
| `only-crypto/src/bignum/hw.rs` | 5 个块、1 个 `unsafe fn`（仅 x86_64） | RSA 在 16、24、32、48 与 64 个 limb 上的 Montgomery 乘法与平方 `asm!`（BMI2 `mulx` 加 ADX 进位链，行用 `.rept` 展开，最后的减法用 `cmovnz`）；模幂查表的 AVX2 扫描（`#[target_feature]` 函数） | 汇编块只经 `Mont::mul_into` / `sqr_into` 在 `hw::enabled()`（`cpu::has(Feature::Adx)`）之后进入，每个函数都有 debug 断言；读取 `a`、`b`、`m` 指向的 `N` 个 limb，写入 `N` 个 limb 的输出（独占借用）与局部的 `2N` 个 limb 暂存区（`MaybeUninit`，每个 limb 先写后读），所有位移都小于 `16N` 字节，不使用栈；扫描只在 `cpu_has(Feature::Avx2)`（有断言）之后调用，从存活表项的每个 4-limb 块读取 32 字节；除行计数器外没有分支 |
| `only-crypto/src/bignum/ifma.rs` | 3 个块（仅 x86_64；每个宏一个，各三个实例） | 基于 AVX-512 IFMA 的 RSA 模幂：在 `ymm` / `zmm` 寄存器中对 20、32、40 个 52 位数字做几乎 Montgomery 乘法，各一个 `asm!` 块，另有同时处理两组操作数的版本（`amm*_x2`，CRT 两半交错）（`vpmadd52luq`/`vpmadd52huq`、`valignq`、opmask 进位；这些 intrinsic 在 MSRV 上不稳定） | 只经 `Mont::pow` 在 `ifma::enabled()`（`cpu::has(Feature::Ifma)`：AVX-512 F/BW/VL、IFMA 以及操作系统保存 ZMM 与 opmask 状态）之后进入，有 debug 断言；读取 `a`、`b`、`m` 指向的 `D` 个数字，写入 `D` 个数字的输出，非对齐访问，不使用栈；全部向量与掩码寄存器声明为被破坏（`clobber_abi("C")`），循环期间输出指针暂存在 `xmm31`，结尾执行 `vzeroupper`；除数字计数器外没有分支。`amm*_x2`（经 `ifma::pow_x2` 从 `Mont::pow2` 进入，检查相同）：读取 `a`、`b` 指向的 `2D` 个数字与 `m` 指向的 `2D + 2` 个字（两个模数，然后两个 `k0`），写入 `2D` 个数字的输出；输出指针暂存在 `k7`（`kmovq`，AVX-512 BW） |
| `only-sys/src/random.rs` | 2（每个系统一个） | 供 `only-crypto` 使用的 `getrandom(2)`（Linux）、`getentropy(2)`（macOS） | 内核最多向存活的 `&mut [u8]` 写入 `buf.len()` 字节（`getentropy` 每次最多 256 字节）；`getrandom` 读到的字节不足时按返回值前移 |
| `only-uring/src/reactor.rs` | 12 + 测试中 3 个、`unsafe fn slice`、`impl Send for Loop` | SQE 提交、provided-buffer ring（`BufRing`）、内核写入的缓冲区（`KernelBuf`）、accept 得到的 fd | 释放缓冲区时没有在途操作（全部取消并收割完成事件，否则泄漏而不释放）；内核持有的缓冲区绝不被借用；ring 条目通过裸字段指针写入；tail 以 `Release` 存储 |
| `only-uring/src/ring.rs` | 18（其中 2 个只在测试中编译：稀疏 `REGISTER_FILES`、`REGISTER_SEND_MSG_RING`），`unsafe fn push`、`register`、`register_buf_ring` | 自有 io_uring 绑定：经 `syscall(2)` 调用 `io_uring_setup`/`enter`/`register`，`mmap` 映射 SQ/CQ ring 与 SQE 数组，SQ/CQ 的 head/tail 原子量，probe、enable-rings、buffer ring 注册；为 io_uring 特性评估提供稀疏的注册文件表和无需自有 ring 的 `MSG_RING` | 内核给出的偏移在使用前对照各自映射做边界检查；仅在队列未满时写入 SQE 槽位，tail 以 `Release` 发布；在自身 head 与以 `Acquire` 读取的 tail 之间读取 CQE，head 以 `Release` 发布；读取 `SQ_NEED_WAKEUP` 前有 `SeqCst` 栅栏（SQPOLL）；映射与 `Ring` 同生命周期 |
| `only-uring/src/eval.rs`（`#[cfg(test)]`） | 5 | io_uring 特性评估的测量工具（一个 ignored 测试）：SQE 提交、provided buffer 读取、对自己 socket 的 `write`/`close`、`setsockopt(TCP_NODELAY)` | 提交项只指向泄漏的静态响应缓冲区或 provided buffers，二者都不释放（工具随后结束进程）；缓冲区只在其完成事件与归还 ring 之间被借用；只有在没有提交项引用描述符后才关闭它 |
| `only-uring/src/group.rs` | 3 | 探测内核版本用的 `uname` | `utsname` 置零；内核以 NUL 结尾 `release` |
| `only-dpdk/src/pmd.rs` | 17、`impl Send for Queue` | 调用 C shim（`rte_eal_init`、端口配置、`rte_eth_rx_burst`/`tx_burst`、mbuf 分配/释放）；从 mbuf 借出帧数据；就地写入暂存的发送 mbuf | shim 的 ABI 只有整数和不透明指针（Rust 侧不涉及 DPDK 结构体布局）；EAL argv 故意泄漏（比 EAL 活得久），只初始化一次（`OnceLock`）；每个 mbuf 只归一个 `Queue`/`Mbuf` 所有、只释放一次（`tx_burst` 未取走的帧被释放，收到的帧在 drop 时释放）；切片只覆盖 shim 返回的单个数据段，且不超过 mbuf 的生命周期；`Queue` 同一时刻只被一个线程使用（一次性移交给其 I/O 线程）；未提交的暂存发送 mbuf 会被释放 |
| `only-dpdk/src/sys.rs` | 14 | TAP（`open`、`TUNSETIFF`）、AF_PACKET（`socket`、`bind`、`setsockopt`）、`read` / `recvfrom` / `write`、`ppoll` | fd 立即归 `OwnedFd` 所有；`#[repr(C)]` 的 `ifreq` 与 UAPI 大小一致；缓冲区与地址结构在每次调用期间有效，传入的长度就是它们的大小 |
| `only-ebpf/src/sys.rs` | 11，3 个 `unsafe fn` | `bpf(2)`（`MAP_CREATE`、`MAP_UPDATE/DELETE_ELEM`、`PROG_LOAD`、`PROG_ATTACH`）、`SO_ATTACH_REUSEPORT_[CE]BPF`、`SO_COOKIE` | `#[repr(C)]` 的 attr 前缀与 UAPI 一致；指针字段在调用期间存活；键/值大小由 `Map<K, V>` 固定 |

### 自有系统调用层（`only_sys::ffi`、`only-uring` 的 `ring`）

设计：Linux 上声明 C 库函数（`unsafe extern "C"`），链接 `std` 本就链接的 libc（glibc 或 musl）；没有 C 封装的系统调用（`bpf`、`io_uring_*`）经 C 库的可变参数 `syscall(2)` 调用，系统调用号按架构区分。因此 errno、`EINTR` 与 `io::Error::last_os_error()` 的行为与使用 `libc` crate 时完全一致。macOS 没有稳定的系统调用 ABI：同样声明 libSystem 函数。不使用内联 `asm!`。

修改这一层时的审查清单：

1. **函数原型**：每个声明与各受支持目标的 C 头文件一致（参数宽度、指针常量性、返回类型）；C 中的可变参数函数（`fcntl`、`ioctl`、`open`、`prctl`、`syscall`）声明为可变参数（arm64 macOS 把可变参数放在栈上），可变参数以 `c_long`/指针宽度的值传递。
2. **布局**：每个 `#[repr(C)]` 结构体都有编译期大小/对齐断言（io_uring 结构体还有偏移断言）；`epoll_event` 仅在 x86_64 上 packed，`kevent` 为 `packed(4)`；`src/ffi/layout.rs` 在测试运行的每个目标上（macOS aarch64、Linux aarch64、Linux x86_64）将每个结构体的大小、对齐、字段偏移以及每个常量的类型和值与 `libc` crate（dev-dependency）对比。
3. **常量**：按操作系统和架构区分（`SYS_bpf` 在 x86_64 上为 321，通用表为 280；io_uring 调用在所有架构上都是 425-427）；只有具备对应取值的目标才能编译（否则 `compile_error!`）。
4. **errno**：调用后立即用 `io::Error::last_os_error()` 转换，在任何可能覆盖 errno 的操作之前；信号处理器通过 `errno_location` 保存并恢复 errno。
5. **io_uring ring**：内核给出的偏移在使用前对照其映射做边界检查；SQ 索引数组初始化为恒等映射；内存序遵循 `io_uring(7)`（SQ tail `Release` / head `Acquire`，CQ tail `Acquire` / head `Release`，读取 `SQ_NEED_WAKEUP` 前 `SeqCst` 栅栏）；SQE 构造逐字段复现 `io-uring` crate 的结果（单元测试 `sqe_builders`）；已提交 SQE 的缓冲区存活到其最终 CQE（原有的 `KernelBuf` / buffer ring / 在途取消 / graveyard 规则不变）。

## 6. 1.0 审查结论

本次审查已修复（能观察到的问题都附有回归测试）：

| # | 位置 | 问题 | 修复 |
|---|---|---|---|
| F1 | `only-sys` `RecvBatch::with_gro` | `slots * size` 未检查：release 构建中乘法溢出会回绕，`bufs` 很小而每个 iovec 仍声称有 `size` 字节，`recvmmsg` 会写出分配范围（公开安全 API 导致的堆溢出）。 | `checked_mul` 加 `u32` 槽位数检查，并在文档中写明 panic 条件；测试 `recv_batch_rejects_overflowing_size`。 |
| F2 | `RecvBatch::recv` / `get` | 遇到 `WouldBlock` 或错误时 `got` 未清零，`get(i)` 会继续返回上一次调用的数据报（仓库内调用方只遍历 `0..n`，不可触发，但 API 行为错误）。 | 每次调用前 `got = 0`；测试 `recv_batch_forgets_previous_datagrams`。 |
| F3 | `RecvBatch::with_gro` | 每个槽位的 iovec 基址取自新的 `&mut bufs[i*size..]`；在 Stacked Borrows 下每次重借用都会使之前派生的指针失效。 | 用 `as_mut_ptr()` 取一次基址，再用 `add` 计算偏移。 |
| F4 | `RecvBatch::reset` | `sockaddr_storage` 保留上一次的地址族；若内核未填写某个消息头，会按过时的地址族解析。 | 每次接收前清除地址族。 |
| F5 | `only-uring` provided buffers | 缓冲区放在 `Vec<u8>` 中（eventfd 读目标放在 `Box<[u8; 8]>` 中），而内核异步写入它们；`on_recv` 借用 `&self.bufs[..]`，这个共享引用覆盖所有缓冲区，包括内核可能正在由 io-wq worker 写入的那些。按 Rust 的模型这是别名 UB。 | `KernelBuf`：裸分配，不用 `Vec`/`Box`；Rust 只通过 `unsafe fn slice`（带边界检查）借用已完成的那个缓冲区。 |
| F6 | `BufRing::give` | 通过 `&mut BufRingEntry` 写条目；对 0 号条目而言，这个引用还覆盖了内核并发读取的 ring tail（`resv`）。 | 镜像的 `#[repr(C)] RawBuf`（断言大小等于 `io_uring_buf`），通过裸指针写字段；tail 用 `AtomicU16` 以 `Release` 存储。可在 Miri 下运行的测试 `buf_ring_layout_give_and_publish` 用 `io_uring` 的访问器校验布局。 |
| F7 | `BufRing::give` | 缓冲区 id 未对照缓冲区区域检查。 | 断言（`bid < BUF_COUNT` 且槽位在区域内）；测试 `buf_ring_rejects_foreign_buffer_ids`。 |
| F8 | `only-ebpf` `sys::bpf`、`map_update`、`map_delete` | 安全函数 `fn bpf<T>(cmd, &mut T)` 接受任意 `T`；`map_update<K, V>` 让内核无论 `&K`/`&V` 实际多大都按 map 的 `key_size`/`value_size` 拷贝（越界读入 map）。 | 改为带 `# Safety` 的 `unsafe fn`；调用方使用类型化的 `Map<K, V>`，其键/值大小在创建时取 `size_of::<K/V>()`，因此它的方法是安全的。 |
| F9 | `attach_reuseport_cbpf` | 程序长度被截断为 `u16`。 | 改为返回 `InvalidInput` 错误。 |
| F10 | `only-sys` 的 macOS 路径（`socket_of`、pipe `Waker`、`kqueue` `Poller`） | 创建后的 `fcntl` 失败时 fd 泄漏。 | 在可失败步骤之前先包装成 `OwnedFd`。 |
| F11 | `only-uring` 事件循环退出 | `Loop` 先关闭 ring，再释放 provided buffers、buffer ring 和唤醒缓冲区，而此时可能仍有在途操作：内核拆除 ring 的一部分工作在异步 exit work 中进行；并且在关闭超时（或 `io_uring_enter` 出错）后，循环退出时连接及其 multishot `recv` 仍处于挂起状态，迟到的完成事件可能写入已释放的内存。 | 循环统计在途操作数（每个 SQE 恰有一个最终 CQE）；`drain_inflight` 在释放内存前提交 `ASYNC_CANCEL_ANY` 并收割完成事件直到没有在途操作（accept 若仍送来 fd 则关闭它）；若 2 秒内未完成，则有意泄漏这些内存而绝不释放。io_uring 测试套件中没有出现泄漏日志。 |
| F12 | `only-core` `consume_datagrams` | 仅 Linux 下的死代码使 Linux 上的 `clippy -D warnings` 失败（来自 UDP 批量化改动）。 | `#[cfg(not(target_os = "linux"))]`。 |

已接受（已记录，目前无需改动）：

- **缓冲区 id 只归还一次。** `give_back` 只对完成事件携带的 `bid` 执行，因此在外的条目最多 `BUF_COUNT` 个，tail 所在槽位绝不会是内核正在读取的条目。现在还有范围断言兜底（F7）。
- **`unsafe impl Send`**：`Poller`（kevent 的 `udata` 只是 token，从不解引用）、`RecvBatch`（指针指向自身的堆缓冲区，随结构体一起移动）、`SendBatch`（批次之间指针悬空，但每次发送前都从存活的 `Batch<'d>` 重建）和 `Loop`（在一个线程上构建，之后归其 I/O 线程所有；SQE 指针指向不会移动的堆内存）。它们都没有实现 `Sync`。
- **信任内核提供数据的布局**：sockaddr 地址族、`cmsg_len`、`msg_len`（已截断）、CQE 缓冲区 id（现已做范围检查）。这是内核 ABI 契约。
- **库已不再依赖任何含 `unsafe` 的第三方 crate**（rustls/ring 随 quinn-proto 移除，str0m 被自研 WebRTC 栈取代）；dev-dependencies 由 `cargo deny`/`cargo audit` 跟踪。TLS 本身是自研的 `only-tls`（`#![forbid(unsafe_code)]`，第 C 波），基于 `only-crypto` 与 `only-x509`，因此所有 TCP 协议的 TLS 记录层与握手代码中，除 `only-crypto` 的 CPU 指令模块外没有任何 `unsafe`；QUIC 是自研的 `only-quic`（`#![forbid(unsafe_code)]`，第 D 波，替代了内含 `rustls`/`ring` 的 `quinn-proto`），因此 QUIC 与 HTTP/3 的包保护、帧、流与丢包恢复代码中也没有。DEFLATE/zlib/gzip 由自研的 `only-deflate`（`#![forbid(unsafe_code)]`）实现，它替代了使用 `zlib-rs` 的 `flate2`。`libc` 与 `io-uring` crate 已从各库中移除（wave B）：由 `only_sys::ffi` 与 `only-uring` 的 `ring` 取代（`libc` 仍是 dev-dependency，用于布局对比测试和仅测试用的调用）。

## 7. 验证结果（本次审查）

- `cargo clippy --workspace --all-targets -- -D warnings`：在启用上述更严格 lint 的情况下，macOS（aarch64）和 Linux（Docker `rust:1`，1.98）均无告警。
- `tools/unsafe-inventory.py --check`：所有位置都有注释。
- 合并 `main`（`fa5f413`，包含更严格的 lint、fuzzing 模块以及 io_uring `graveyard`、复位监视等混沌测试修复）后重新验证：`cargo clippy --workspace --all-targets --all-features -- -D warnings` 与 `RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps --all-features` 在 macOS 和 Linux 上均无告警；`cargo test --workspace` 在 macOS 和 Linux（epoll）上通过；only、only-uring、only-http、only-ws、only-kcp、only-quic 在 `ONLY_TEST_BACKEND=uring` 下通过；io_uring 混沌测试种子 1..30 通过；没有出现在途操作泄漏日志。新的混沌测试代码没有引入 `unsafe`。
- 测试套件（合并前）：macOS `cargo test --workspace` 全部通过；Linux `cargo test --workspace`（epoll）以及 `only`、`only-uring`、`only-sys`、`only-ebpf`、`only-http`、`only-ws`、`only-kcp`、`only-quic` 在 `ONLY_TEST_BACKEND=uring` 下全部通过。
- 供应链：`cargo deny check` 输出 `advisories ok, bans ok, licenses ok, sources ok`；`cargo audit -D warnings` 无告警。唯一发现的通告 RUSTSEC-2026-0009（`time` 0.3.45）已在 `deny.toml` 与 `.cargo/audit.toml` 中带理由忽略：它只经由 `rcgen` 引入，而 `rcgen` 是生成测试证书的开发依赖，从不解析 RFC 2822 输入；修复版 `time` 0.3.47 需要 Rust 1.88，高于 CI 检查测试目标时使用的 1.85 MSRV。MSRV 升到 1.88 后删除此例外。

### Miri（nightly 1.102，`-Zmiri-disable-isolation`，Stacked Borrows）

| Crate（`--lib`） | 结果 |
|---|---|
| only-buf、only-timer、only-pool | 通过（4 / 5 / 5 个测试） |
| only-http | 通过（27 个测试，35 秒） |
| only-mux、only-socks、only-arpc、only-h3 | 通过（1 / 1 / 3 / 2） |
| only-kcp | 通过（5 个测试，4-6 分钟） |
| only-uring（`buf_ring`、`kernel_buf` 测试） | 通过（3 个）：即 F5-F7 中与内核共享内存的代码 |
| only-ws | 20 个中 15 个通过；其余 5 个（permessage-deflate 往返与穷举拆分循环）在 Miri 下 5-15 分钟内跑不完 |
| only-crypto（`fill`、`append`、`aead_rfc8439`、`gcm_spec_vectors`、`rejects_forgeries`；2026-11-16） | 通过（7 个测试，37 秒；nightly 2026-11-13，x86_64 镜像）：`fill::tests` 以及 AES-GCM 与 ChaCha20-Poly1305 可移植的 `encrypt_append` / `decrypt_append`，覆盖分组与开头分组附近的长度、向量中已有数据、空闲容量恰好 / 更大 / 不足、尾部字节、打开失败；空闲容量中没有任何未初始化字节被读取或暴露 |
| only-tls（`record::` 的 `framing_limits`、`skips_rejected_early_data`、`tampering_and_replay_fail`、`tls13_padding_and_empty_types`；2026-11-16） | 通过（4 个测试，9 秒）：走追加路径的记录层（自身没有 `unsafe`） |
| only-core | 除 loom / 集成测试外没有单元测试 |
| only-quic（第 D 波起为自研 QUIC） | 未在 Miri 下运行：`#![forbid(unsafe_code)]`，自身没有 `unsafe`；其单元测试、模拟网络测试与语料回放测试以原生方式运行 |
| only-ebpf | 15 分钟内跑不完（单元测试在大量输入上运行 cBPF 解释器；均为安全代码，不涉及 `sys` 模块） |
| only-deflate | 通过（全部单元测试；与其他 crate 一样，CI 中跳过语料回放） |
| only-grpc | 通过，gzip 改用 only-deflate 后也包括 `tests::framing_and_gzip`（见下） |
| only-grpc（第 A 波之前，flate2 + zlib-rs） | **在依赖中报告了 UB**：`tests::framing_and_gzip` 在 drop `flate2::write::GzEncoder` 时于 `zlib_rs::allocate::zfree_rust` 失败（`zlib_rs::stable::Deflate::drop` -> `deflate::end` 释放了一块仍被受保护的 `&mut` 函数参数覆盖的内存）。在 Tree Borrows 下同样复现。`zlib-rs` 0.6.8 已是最新版本；only 在这条路径上没有任何 `unsafe`。 |

`zlib-rs` 的问题是依赖内部违反别名模型，而不是观察到的内存破坏（值得附上述复现向上游 trifectatech/zlib-rs 报告）。它已不再影响 only：DEV-PLAN 第 A 波用纯安全 Rust 的 `only-deflate` 替代了 `flate2`/`zlib-rs`，因此 CI 的 Miri 任务重新运行 `framing_and_gzip`，并运行 only-deflate 自身的测试与 only-ws 的 permessage-deflate 往返测试。它仍跳过回放模糊测试语料的 `fuzzing::` 测试（在 Miri 下每个 crate 需数分钟，而 fuzz 任务会原生运行这些输入）。（`flate2` 当初从 `miniz_oxide` 切换到 `zlib-rs`，是因为前者有真实的数据丢失缺陷，见 WebSocket 相关说明；only-deflate 针对这类缺陷有回归测试。）

### Sanitizer

本次审查未能运行 ASan 和 TSan：在可用的 Linux 环境（Apple 芯片上的 Docker，linuxkit 6.12 aarch64 内核）中，即使是空的 `fn main` 用 `-Zsanitizer=address` 或 `-Zsanitizer=thread` 构建，启动时也会 SIGSEGV（sanitizer 运行时不支持该虚拟机的地址空间布局；`setarch -R` 无效，`vm.mmap_rnd_bits` 也无法修改）。建议作为 CI 任务在 `ubuntu-latest`（x86_64）上运行，两者在那里都受支持。
