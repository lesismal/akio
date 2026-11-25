# ADR-129：删除 akio-prefork

[English](129-akio-prefork-removed.md) | 简体中文

状态：已采纳（2026-11-25）。取代 [ADR-028](028-hot-reload-buffers-backlog-threads.zh-CN.md) 与
[ADR-063](063-shared-steering-migration-af-xdp.zh-CN.md) 中关于 akio-prefork 的部分。

## 背景

`akio-prefork`（M6，可选）让一个程序由多个 worker 进程提供服务：supervisor 以 worker 身份重新执行
二进制，通过 `SO_REUSEPORT` 或继承的套接字共享监听，重启崩溃的 worker，收到 SIGTERM 时排空，收到
SIGHUP 时切换代际，收到 SIGUSR1 时原地重载（ADR-028），并且借助 `Prefork::bpf_steering` 在所有
worker 的套接字上维持同一个 BPF 分流程序，使重载不重置任何连接（ADR-063）。

akio 和 akit 不使用 prefork：Rust 没有需要靠多进程掩盖停顿的垃圾回收器，一个引擎已经能用满所有核，
akit 在单个进程内重载配置。2026-11-25 早些时候该 crate 被暂停维护（cb49a04b）：它仍参与构建，但 CI
的工作区测试步骤、sanitizer 运行和完整测试都用 `--exclude akio-prefork` 排除了它，是否删除留待以后
决定。没有测试运行、也没有人使用的代码只会增加审查、构建和 API 面的负担，并且悄悄腐坏。

## 决定

删除 `akio-prefork`，以及只为它存在的一切。每一项都在工作区（crate、测试、示例、工具、fuzz 目标、
文档）和 akit 中搜索过；只删除没有其他使用者的项。

已删除：

- crate `crates/akio-prefork`（supervisor、worker、`Prefork`、`BpfSteering`、`ListenMode`、
  `Controller`、`Supervisor`、`Status`、`WorkerInfo`、`Worker`、`CpuPinning`），它的示例
  `prefork-http`、测试（`prefork`、`bpf`）、README、工作区条目、API 快照 `api/akio-prefork.txt`、
  书中“多进程服务（prefork）”一章（英文与中文），以及对它的引用（README 的 crate 表、书中的 crate
  表、可观测性一章的重载小节、`book/check-guides.sh`、docs/api-stability、CI 中的 semver-checks
  列表与 `--exclude akio-prefork`、`tools/sanitizers/run.sh`、`tools/api/public-api.sh`、规则 18
  的附注）。
- `akio::EbpfConfig::shared` 及引擎分流设置中对应的分支：只有 akio-prefork 的 worker 设置它。
  `EbpfConfig` 是 `#[non_exhaustive]`，不能用结构体字面量设置该字段；给它赋值的代码将无法编译。
- `akio_sys::process` 中的 `ChildSetup`、`configure_child`（`pre_exec` 钩子：继承 fd、
  `PR_SET_PDEATHSIG`、子进程的 CPU 亲和性）、`take_inherited_fd`、`reserve_reuseport`（以及它背后
  crate 私有的 `net::bind_reuseport`）、`SIGQUIT` 和 `SIGUSR1`。隐藏的 `akio_sys::ffi` 中的
  `prctl`、`PR_SET_PDEATHSIG`、`getpid`、`getppid`、`ESRCH`、`SIGQUIT`、`SIGUSR1`（及其布局检查）。
  akio-sys 少了六个 `unsafe` 块。

保留，只从文档中去掉 prefork 的字样：

- `Listener::tcp_from_std`：服务一个由 systemd socket 激活传入、从父进程继承、或以 akio 不设置的
  选项绑定的监听套接字。
- `akio_ebpf::SharedSteering`（以及 `expected_index`、`HashKey`、`SteerInfo::shared`）：独立的
  akio-ebpf API，有自己的测试（`crates/akio-ebpf/tests/shared.rs`：共享槽位，以及 Linux 5.14+ 上
  accept 队列与未完成握手的迁移）。akio 中不再有任何地方把它接到监听器上；跨进程共享
  `SO_REUSEPORT` 组的程序仍可直接使用它。
- `akio_sys::process::{allowed_cpus, pin_current_thread}`：引擎的 NUMA 放置、
  `EbpfConfig::pin_threads`、akio-epoll 与 akio-uring 用它们绑定线程。
- `akio_sys::process::{signal_pipe, kill, SIGHUP, SIGINT, SIGTERM, SIGUSR2}`：akit 的主循环用
  `signal_pipe` 把 SIGHUP/SIGINT/SIGTERM 变成字节，akit 的集成测试用 `kill` 给二进制发信号；
  `SIGUSR2` 是 `signal_pipe` 自身测试发出的信号。

## 备选方案

- **冻结保留**（cb49a04b 之后的状态）：没有测试、不修 bug，但仍构建、仍发布。否决：一个未经测试的
  公开 crate 仍在宣称可用，还让 `EbpfConfig::shared` 和进程相关调用留在其他 crate 的公开 API 中，
  而且引擎或 akio-sys 的每次改动都得让它继续编译。如果以后又需要 prefork，该 crate 在 git 历史中
  （最后版本在 2bced7f3），可以连同 ADR 和测试一起恢复。
- **删除 crate，但保留 `EbpfConfig::shared` 和整个 `akio_sys::process`。** 否决：没有其他代码使用
  它们，“以防万一”保留的 API 只是换了个更小形式的冻结代码。

## 影响

- 少了一个需要构建、测试、编写文档和发布的 crate；akio-sys 的 unsafe 面更小。
- 上面删除的公开项对外部使用者是破坏性变更；目前没有已知的外部使用者，工作区也尚未发布 1.0.0。
  akio 与 akio-sys 的 API 快照已重新生成。
- 不再提供多进程服务：在负载均衡器后面运行多个进程，或者用一个引擎配更多 I/O 线程。
