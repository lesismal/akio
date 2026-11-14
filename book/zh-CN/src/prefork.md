# 多进程服务（prefork）

`only-prefork` 用多个 worker 进程服务同一个程序，每个 worker 运行自己的 `Engine`，由一个 supervisor 负责：
重启崩溃的 worker、关闭时让它们排空、重载时替换它们。它带来隔离（崩溃或卡住的回调只影响一个 worker）、
不停机升级，以及各进程独占、不跨核争用的资源。在 worker 内部，一切都是普通的 only。

## worker 与 supervisor

worker 是一个函数：在 supervisor 准备好的监听器上构建引擎，并交给 `Worker::serve`：

```rust,ignore
{{#include ../../../crates/only-prefork/examples/prefork-http.rs:worker}}
```

`main` 配置 supervisor，并用这个函数调用 `run`：

```rust,ignore
{{#include ../../../crates/only-prefork/examples/prefork-http.rs:supervisor}}
```

同一个 `main` 在每个进程中运行。在 supervisor 中，`run` 绑定地址，用相同的参数加上 `ONLY_PREFORK_*` 环境
变量**重新执行当前二进制**来启动 worker，并监管它们；它从不调用 worker 函数。在 worker 中，`run` 发现这些
变量，以一个 `Worker` 调用 worker 函数。用重新执行代替 `fork`，避开了对多线程进程 fork 的隐患：每个 worker 都
从 `main` 开始，地址空间是干净的。只有 worker 需要的启动工作应放在 worker 函数里。

`Worker` 告诉 worker 它是谁：`index()`（从 0 开始，重启或重载产生的替代者保持同一序号）、`workers()`（用于
按进程分摊整机限制，例如数据库连接数）、`generation()`（起始为 0，每次重载加一）和 `addrs()`。`listener(i)`
返回地址 `i` 的 `only::Listener`，照常用 `.threads()`、`.backend()`、`.serve()` 配置。

## 共享端口

| `ListenMode` | 套接字 | 均衡 | worker 退出时 |
|---|---|---|---|
| `ReusePort`（Linux 默认） | 每个 worker 以 `SO_REUSEPORT` 绑定，每个 I/O 线程一个套接字；supervisor 只保留端口、不监听 | 内核按哈希分到所有 worker 的套接字 | 正在关闭的 worker 套接字上已排队的连接会被重置，除非设置 `net.ipv4.tcp_migrate_req=1`（Linux 5.14+） |
| `Inherit`（macOS 默认） | supervisor 监听一次；worker 继承该套接字（`Listener::tcp_from_std`） | 谁先 accept 谁处理 | 不拒绝任何连接：supervisor 让套接字一直处于监听状态 |

macOS 允许多个进程以 `SO_REUSEPORT` 绑定同一端口，但把所有连接交给最后一个，所以 `Auto` 在那里选择
`Inherit`。在 Linux 上使用 io_uring 时应优先用 `ReusePort`：共享继承来的套接字时，某个 ring 的 multishot
accept 往往拿走所有连接。

单进程服务也可以用 `Listener::tcp_from_std` 服务一个不是自己绑定的套接字，例如来自 systemd socket activation。

## 生命周期与信号

| 事件 | 结果 |
|---|---|
| 向 supervisor 发送 SIGTERM / SIGINT，或 `Supervisor::shutdown` | 要求每个 worker 停止：`Worker::serve` 调用 `Engine::shutdown`（停止 accept，完成进行中的请求）后返回；超过 `shutdown_timeout` 仍在运行的 worker 被杀掉；第二次信号立即杀掉 |
| SIGHUP，或 `Supervisor::reload` | 启动新一代；每个旧 worker 在其替代者报告就绪后停止；在 `ready_timeout` 内未就绪的替代者被杀掉，旧 worker 保留 |
| worker 自行退出 | 按 `restart_backoff`（100 ms 翻倍到 10 s）以相同序号重启 |
| supervisor 退出 | worker 发现控制套接字关闭（Linux 上还会通过 `PR_SET_PDEATHSIG` 收到 SIGTERM），于是排空 |
| 向 worker 发送 SIGTERM / SIGINT | 像收到停止请求一样排空 |

worker 运行在自己的进程组中，所以终端的 Ctrl-C 只到达 supervisor，再由它排空 worker。`Worker::serve` 在
`Engine::start` 之后报告就绪；以其他方式运行引擎的 worker 要自己调用 `Worker::ready`，否则重载永远不会替换它。
`Prefork::spawn` 返回一个 `Supervisor` 句柄（用于测试和管理端点），提供 `status()`、`reload()`、`shutdown()`、
`wait()`，并且不安装信号处理器。

要升级二进制，先替换程序文件，再发送 SIGHUP：新一代运行新代码，旧一代排空。

使用 `Inherit` 时，重载不会拒绝或重置任何连接。还剩一个缺口：旧 worker 在开始排空前刚 accept、但请求尚未
到达的连接，会被 only-http 的优雅关闭关掉（它关闭没有进行中请求的连接；测试中持续负载下重载期间约每 5000 个
请求出现一次）。

## CPU 绑核

`pin_cpus(CpuPinning::PerWorker)` 让 worker `i` 运行在 CPU `i % CPU 数` 上，`CpuPinning::Sets` 指定 CPU 列表。
亲和性在子进程 `exec` 之前设置，worker 的所有线程都继承它。仅 Linux。

## eBPF 分流与 prefork

`Accel::Ebpf` 把分流程序挂到监听器的 reuseport 组上。在 `ReusePort` 模式的 prefork 中，所有 worker 的套接字
组成同一个组，从某个 worker 挂载的程序会替换组上的程序，而且只索引该 worker 的套接字：所有新连接都会去往最后
挂载的 worker。不要把两者一起使用（`Worker::serve` 发现时会警告）。在 `Inherit` 模式下，worker 的监听器不构成
reuseport 组，`Accel::Ebpf` 报告 `Degraded`。通过 bpffs 中固定的程序做跨进程分流尚未实现。

## 测试

集成测试（`crates/only-prefork/tests/prefork.rs`）把测试二进制自身作为 worker 运行：请求由多个 PID 应答，
崩溃的 worker 被替换，关闭时进行中的请求得以完成，持续负载下的重载替换了所有 worker 且没有被拒绝的连接。
