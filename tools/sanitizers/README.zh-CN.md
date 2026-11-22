# Sanitizer 运行

[English](README.md)

用 AddressSanitizer（含 LeakSanitizer）和 ThreadSanitizer 运行工作区测试，覆盖 Miri 无法运行的部分：系统调用（socket、epoll、io_uring、信号）、I/O 线程以及硬件加密路径。CI 任务 `sanitizers`（`.github/workflows/ci.yml`）运行的是同一个脚本。

```bash
tools/sanitizers/run.sh --docker address            # Linux 容器（macOS 上的 Docker Desktop）
```

```bash
AKIO_TEST_BACKEND=uring tools/sanitizers/run.sh --docker thread akio-uring akio akio-ws
```

```bash
tools/sanitizers/run.sh thread akio-sys akio-crypto  # 在装有 nightly + rust-src 的 Linux 上原生运行
```

不指定 crate 时，运行工作区中所有带库或测试目标的成员，`akio-dpdk` 除外（需要 libdpdk）。每个 crate 执行一次 `cargo test --lib --tests -- --test-threads=1`；脚本输出 `crate rc=… reports=… 秒数`，并在 `target/sanitizers/<sanitizer>[-<后端>-docker]/`（或 `$SAN_LOG_DIR`）为每个 crate 保留一份日志。测试失败、出现 sanitizer 报告（`halt_on_error`）或超过 `SAN_TIMEOUT` 秒（默认 1800）时该 crate 判为失败。

## 脚本设置了什么，为什么

| 设置 | 原因 |
|---|---|
| `-Zbuild-std`、`-Zsanitizer=<san>` | TSan 必须看到 std 的原子操作和锁，因此 std 以插桩方式重新构建。 |
| `RUSTC_WRAPPER=rustc-wrapper.sh` | 构建 `compiler_builtins` 时不加 sanitizer。在 aarch64 上，sanitizer 运行时在自身启动期间调用其 outline-atomics 辅助函数（`__aarch64_swp1_acq` 等）；这些函数一旦被插桩，就会回调尚未初始化的运行时，所有测试二进制在 `main` 之前因 SIGSEGV 崩溃（`__tsan::Initialize` 下的 `__tsan::TraceSwitchPart`）。对 x86_64 没有影响。 |
| `-Cunsafe-allow-abi-mismatch=sanitizer` | `compiler_builtins` 与其余部分不一致后需要此项；其中没有触及 sanitizer 所跟踪的程序内存的代码。 |
| `AKIO_TEST_TIMEOUT_SCALE=10` | 带固定事件期限的测试将期限乘以该值：TSan 使 debug 构建慢 5–15 倍。`akio-ws/tests/client.rs` 使用它。 |
| `ASAN_OPTIONS=detect_leaks=1:detect_stack_use_after_return=1:…` | 在默认检查之外再检查泄漏和栈上返回后使用。 |
| `TSAN_OPTIONS=halt_on_error=1 second_deadlock_stack=1` | 第一份报告即令该 crate 失败；锁顺序反转时给出两个栈。 |
| `lsan.supp`、`tsan.supp` | 抑制列表。目前为空：没有需要抑制的报告。新增的每一条都必须写明原因。 |

`--docker` 构建 `Dockerfile`（nightly、`rust-src`、`llvm-symbolizer`），挂载检出目录后在其中运行脚本。它加上 `--security-opt seccomp=unconfined`（Docker 默认配置会拦截 `io_uring_setup`）和 `--ulimit memlock=-1`：io_uring 把 ring 与 buffer ring 计入用户的 `locked_vm`，而该计数由主机上所有以 root 运行的容器共享，再与本容器的 `RLIMIT_MEMLOCK`（Linux 上的 Docker 默认 8 MiB）比较，因此旁边有其他 io_uring 测试运行时，ring 创建会以 `ENOMEM` 失败。Cargo 的 target 目录默认是卷 `akio-san-target-<san>`，可用 `SAN_TARGET` 指定其他卷或主机路径。在共享的基准测试主机上，`SAN_NICE=19` 让容器内的测试以低优先级运行，`SAN_DOCKER_ARGS` 可附加 `--cpu-shares=64` 之类的参数；`SAN_PLATFORM=linux/arm64` 固定镜像平台。

## 局限

- `asm!` 块不被插桩：硬件加密内核自身的读写不受检查。ASan 仍检查其周围计算指针与长度的 Rust 代码，而且这些运行所执行的单元测试会把内核与可移植实现逐一比较。
- ThreadSanitizer 只能看到程序经由插桩代码和被拦截调用所做的事。io_uring 与内核共享的内存（ring、buffer ring）由内核同步，TSan 看不到；那里的竞争由 Miri 和 loom 负责（`BufRing`、`KernelBuf` 与 `akio-core` 的测试）。
- 在 TSan 下，信号处理函数要等其所在线程进入被拦截的调用后才会执行。发给进程的信号可能落在阻塞于裸 `futex` 系统调用（std 的锁和通道）的线程上，TSan 不拦截该调用，于是处理函数永远不会执行。需要处理函数运行的测试，会在等待信号的那个线程上触发信号。

## 首次运行（2026-11-16）

Nightly 1.102.0（2026-11-13）。arm64：macOS 上的 Docker Desktop（linuxkit 6.12）。x86_64：Zen 4 主机上的 Docker（内核 7.0；具备 AVX-512、IFMA、VAES、BMI2/ADX，因此 x86 汇编路径都运行到了），运行含 unsafe 代码的 crate 与引擎后端。

| 运行 | crate | 结果 |
|---|---|---|
| ASan，arm64，epoll | 全部 36 个 | 通过，1003 个测试 |
| ASan，arm64，io_uring | akio-uring、akio、akio-http、akio-prefork、akio-socks、akio-ws | 通过 |
| TSan，arm64，epoll | 全部 36 个 | 下述修复后通过（一处线程泄漏，第 5 项） |
| TSan，arm64，io_uring | 同 ASan | 下述修复后通过 |
| ASan + TSan，x86_64，epoll | akio-sys、akio-buf、akio-crypto、akio-core、akio-epoll、akio-pool、akio-timer、akio | 通过 |
| ASan + TSan，x86_64，io_uring | akio-uring、akio | 通过 |

没有报告任何内存错误、内存泄漏或数据竞争。这几轮运行发现的问题：

1. 在 aarch64 上使用 `-Zbuild-std` 时，所有插桩二进制都在启动时崩溃，即 docs/unsafe-review.md 曾归因于 Docker 虚拟机地址空间布局的那个 SIGSEGV（不带 `-Zbuild-std` 的 `-Zsanitizer=address` 在那里运行正常）：由 `rustc-wrapper.sh` 解决。
2. `akio-sys` 的 `process::tests::signal_to_pipe` 在 TSan 下挂起（上述信号局限）：测试改为在自身线程上触发信号，并用信号 0 检查 `kill(2)`。
3. `akio-ws` 的 `large_and_fragmented_messages_and_limits` 在 TSan 下超过 10 秒事件期限（debug 构建下带 permessage-deflate 的 8 MiB 消息）：期限现在随 `AKIO_TEST_TIMEOUT_SCALE` 缩放。
4. 在 x86_64 主机的 Docker 中，io_uring ring 创建以 `ENOMEM` 失败：加上 `--ulimit memlock=-1`。
5. TSan 在 `akio-bittorrent`（`tests/swarm.rs`）中报告了**线程泄漏**：`Client::close` 关闭引擎与磁盘线程池后并不等待，因此返回时这些线程仍可能执行回调（以及 `Storage` 调用），而丢弃 client 会使它们脱离（detach）。现在它会等待 I/O 线程、磁盘线程池与维护线程退出。
6. 等待之后暴露出第二个问题：akio-http 的客户端在引擎优雅关闭期间仍保持空闲的 keep-alive 连接，因此 `Engine::wait`（以及现在带 HTTP tracker 的 `Client::close`）要等满整个 `shutdown_timeout`，默认 10 秒。现在空闲的客户端连接在关闭时立即关闭，有请求在途的连接在收到响应后关闭（回归测试 `engine_shutdown_does_not_wait_for_idle_keep_alive_connections`）。
7. CI 任务原先只覆盖八个 crate，也没有覆盖 `akio-crypto` 的硬件路径；现在通过本脚本运行整个工作区。
