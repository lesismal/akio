# ADR-029：`AKIO_DEFAULT_BACKEND` 为未选择后端的 listener 选用 io_uring

[English](029-default-backend-env.md) | 简体中文

状态：已采纳（2026-11-17）

## 背景

listener 的后端在代码中选择（`Listener::backend`，ADR-004）；不调用时为 epoll（macOS 上为 kqueue）。
测试套件通过 `AKIO_TEST_BACKEND=uring` 在 io_uring 上运行引擎，但这个变量由各个测试文件自己读取，
再由它们自己调用 `.backend(..)`。因此从不选择后端的程序（包括手册的 `guide-*` 示例）不改代码就无法在
io_uring 上运行。要在 epoll 与 io_uring 上分别运行全部指南示例（`book/check-guides.sh`），需要一个程序
之外的开关。

`akio` 已有若干环境变量开关，供测试和运维在不重新构建的情况下切换平台特性：`AKIO_CRYPTO_PORTABLE`、
`AKIO_UDP_GSO`、`AKIO_UDP_GRO`、`AKIO_UDP_ECN`。

## 决定

`akio::Engine::build` 每次构建时读取一次 `AKIO_DEFAULT_BACKEND`，仅在 Linux 上：

- `uring` 或 `io_uring`：每个未调用 `Listener::backend` 的 **TCP** listener 由
  `Backend::IoUring(UringConfig::default())` 服务，它不是 strict 的：内核或沙箱缺少 io_uring 时，该
  listener 回退到 epoll 并记录一条警告，与显式的非 strict io_uring listener 完全一样。
- 未设置、为空或 `epoll`：不变。其他值被忽略并给出警告。
- 用 `Listener::backend` 选定的后端总是优先，无论是什么（显式的 `Backend::Epoll` 仍是 epoll）。
  UDP listener（任何情况下都由 epoll UDP 后端服务）以及 `client_threads` / `udp_client_threads`
  线程组不受影响。
- 其他平台上忽略该变量。

它在配置参考中被记为测试与诊断开关，而不是调优设置：需要 io_uring 的生产代码应通过
`Listener::backend` 明确表达。

没有公共项变化：`Listener` 新增一个私有字段，记录是否调用过 `backend`。该变量只在构建时读取，
I/O 路径不受影响。

## 备选方案

- 让 `AKIO_TEST_BACKEND` 本身决定默认后端。否决：这会改变现有 `uring` 测试分支所运行的内容（每个使用默认
  listener 的测试文件都会切换），那是另一个决定；用不同的名字可保持测试套件行为不变。
- 让每个指南示例读取变量并设置后端。否决：这会给手册展示的每个代码片段增加样板代码，其他程序仍然没有开关。
- 把 `Backend::default()` 改为新的 `Auto` 变体。否决：为测试需要而改动公共 API。

## 影响

- `AKIO_DEFAULT_BACKEND=uring book/check-guides.sh` 在 io_uring 上运行每个指南示例；若某个示例的引擎
  回退到了 epoll，脚本判其失败。
- 热路径：该变量只在 `build` 中读取。在 gpu51 上，由 main 与本改动分别构建的 release `echo` 二进制中
  `akio_core` / `akio_epoll` 的机器码完全相同（54,412 条指令，地址已归一化）；同一轮次的 echo A/B（12 轮）
  落在机器噪声范围内（总计 0.98x，各轮 0.83-1.11x）。
- 测试：`crates/akio/tests/default_backend.rs`（Linux）在子进程中分别以未设置、`epoll`、`uring`、
  `io_uring` 和未知值运行，检查默认 TCP listener 随之变化，而显式 `Backend::Epoll` 的 listener 与 UDP
  listener 不变。
