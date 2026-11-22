# akio-prefork

[English](README.md) | 简体中文

用多个 worker 进程服务同一个程序，每个 worker 运行自己的 akio `Engine`，由一个 supervisor 负责：重启崩溃
的 worker、关闭时让它们排空、重载时用新 worker 替换旧 worker。对应 fib 的 `prefork` 包。

akio 已经每核一个事件循环，为什么还要多进程？隔离（崩溃、泄漏或卡住的回调只影响一个 worker，而不是整个
服务）、不停机升级（重载时先启动新二进制再停旧的），以及各进程独占的资源（分配器 arena、缓存）不会跨核
争用。

```rust
use akio::{Conn, Engine, Handler, fn_acceptor};
use akio_prefork::Prefork;

struct Echo;
impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
}

fn main() -> std::io::Result<()> {
    Prefork::new()
        .workers(4)
        .listen("0.0.0.0:8080".parse().unwrap())
        .run(|worker| {
            let engine = Engine::builder()
                .listen(worker.listener(0)?.threads(2).serve(fn_acceptor(|_c: &Conn<Echo>| Echo)))
                .build()?;
            worker.serve(&engine)
        })
}
```

同一个 `main` 既在 supervisor 中运行，也在每个 worker 中运行：supervisor 用相同的参数和若干
`AKIO_PREFORK_*` 环境变量重新执行当前二进制，`run` 只在 worker 中调用闭包。用重新执行代替 `fork`，可以避开
“多线程之后 fork”的隐患（其他线程持有的锁、分配器状态）：每个 worker 都从 `main` 开始。只有 worker 需要的
工作（加载数据、建立连接池）应放在闭包里。

完整的 HTTP 示例：[`examples/prefork-http.rs`](examples/prefork-http.rs)
（`cargo run --release -p akio-prefork --example prefork-http`）。

## 监听套接字

| `ListenMode` | 方式 | 负载均衡 | 重启 / 重载 |
|---|---|---|---|
| `ReusePort`（Linux 默认） | 每个 worker 以 `SO_REUSEPORT` 绑定地址（每个 I/O 线程一个套接字）；supervisor 只保留端口：绑定但不监听 | 内核按哈希把连接分到所有 worker 的套接字上 | 正在关闭的 worker 的套接字上已排队的连接会被重置，除非它们被迁移：使用 `bpf_steering`（Linux 5.14+）时迁到新 worker，设置 `sysctl net.ipv4.tcp_migrate_req=1` 时迁到随机一个存活的 worker |
| `Inherit`（macOS 默认） | supervisor 绑定并监听一次；worker 继承这个套接字，其线程共享它 | 谁先 accept 谁处理 | 不会拒绝任何连接：套接字一直在 supervisor 中监听 |
| `Auto` | Linux 上为 `ReusePort`，其他平台为 `Inherit` | | |

macOS 允许多个进程以 `SO_REUSEPORT` 绑定同一地址，但不做均衡（最后绑定的套接字拿到所有连接），所以那里用
`Inherit`。Linux 上使用 io_uring 后端时，`Inherit` 均衡很差（某个 ring 的 multishot accept 往往拿走所有连接），
应优先用 `ReusePort`。

## 生命周期

- **启动**：`Prefork::run`（或返回句柄的 `Prefork::spawn`）先绑定或保留地址（端口 0 只解析一次），再启动
  worker；程序无法启动时调用直接失败。worker 运行在自己的进程组中，stdin 关闭。
- **就绪**：`Worker::serve` 启动引擎后，通过私有的控制套接字向 supervisor 报告就绪（自己运行引擎时调用
  `Worker::ready`）。
- **崩溃**：未被要求就退出的 worker 会以相同序号、按指数退避重启（`restart_backoff`，从 100 ms 翻倍到 10 s；
  worker 存活达到该时长后重置）。
- **关闭**：向 supervisor 发送 SIGTERM 或 SIGINT（或调用 `Supervisor::shutdown`）会要求每个 worker 停止；
  `Worker::serve` 随后调用 `Engine::shutdown`（停止 accept，让进行中的请求完成）并返回。超过
  `shutdown_timeout`（30 s）仍未退出的 worker 会被杀掉；第二次信号立即杀掉。终端的 Ctrl-C 只到达
  supervisor，由它排空 worker。
- **重载**：SIGHUP（或 `Supervisor::reload`）启动新一代 worker；每个旧 worker 在其替代者报告就绪后才被要求
  停止。在 `ready_timeout` 内未就绪的替代者会被杀掉，旧 worker 保留。要升级二进制，先替换程序文件。使用
  `Inherit` 时不会有连接被拒绝或重置；一个例外：旧 worker 在开始排空前刚 accept、但请求尚未到达的连接，会被
  akio-http 的优雅关闭关掉（它关闭没有进行中请求的连接）。测试中，持续负载下重载期间约每 5000 个请求出现一次。
- **supervisor 退出**：worker 发现控制套接字关闭（在 Linux 上还会通过 `PR_SET_PDEATHSIG` 收到 SIGTERM），
  于是排空退出。
- **发给 worker 的信号**：SIGTERM / SIGINT 让它像收到停止请求一样排空。

`Supervisor::status()` 列出各 worker（序号、pid、代数、是否就绪、是否在排空），并统计重启和重载次数。

## Worker API

`Worker::index()`（从 0 开始，重启和重载后保持不变）、`workers()`（用于按进程分摊整机资源，例如数据库连接
上限）、`generation()`、`addrs()`、`listener(i)`（地址 `i` 的 `akio::Listener`，可继续 `.threads()`、
`.backend()`、`.serve()`）、`serve(&engine)`、`ready()`、`wait_for_stop()`。

`Prefork::workers(0)` 会在 supervisor 自己的进程里运行闭包，只有一个自行绑定地址的 worker，便于用调试器调试。

## CPU 绑核

`pin_cpus(CpuPinning::PerWorker)` 让 worker `i` 运行在 CPU `i % CPU 数` 上；`CpuPinning::Sets` 为每个 worker
指定一组 CPU。亲和性在子进程 `exec` 之前设置，因此 worker 的所有线程都继承它。仅 Linux（macOS 没有亲和性
API，会记录一条警告）。

## 跨 worker 的 eBPF 分流（`bpf_steering`）

在 `ReusePort` 模式下，**所有** worker 的套接字组成同一个内核 reuseport 组，分流程序属于整个组。worker 自己的
`Accel::Ebpf` 会把它换成只认识该 worker 套接字的程序，于是所有新连接都去往最后挂载的那个 worker（`Worker::serve`
会警告）。请改用共享程序（ADR-063）：

```rust,ignore
use akio::ebpf::{HashKey, Steering};
use akio_prefork::{BpfSteering, Prefork};

Prefork::new()
    .workers(4)
    .listen("0.0.0.0:8080".parse().unwrap())
    .bpf_steering(BpfSteering::new(Steering::Hash(HashKey::SrcIp), 2)) // 每个 worker 2 个 I/O 线程
    .run(|worker| {
        // listener(0) 已设好 2 个线程，并加入本 worker 的槽位。
        let engine = Engine::builder().listen(worker.listener(0)?.serve(app)).build()?;
        worker.serve(&engine)
    })
```

- supervisor 为每个地址加载一个 `SK_REUSEPORT` 程序和 socket 数组，共 `workers * threads` 个槽位，并把它们固定
  在 `/sys/fs/bpf/akio-prefork/<ip>_<port>`（`BpfSteering::dir`）下，停止时删除。
- worker `i` 把自己的套接字放进槽位 `i * threads..(i + 1) * threads`，重启或重载后的 worker 接管同样的槽位。
- `Steering::Cpu` 把流发往槽位 `cpu % slots`。`Steering::Hash` 使用 `attach_reuseport` 的 Maglev 表，因此
  `akio::ebpf::expected_index(steering, workers * threads, peer, local)` 给出槽位，槽位除以 `threads` 即 worker。
- **重载不丢连接**（Linux 5.14+，`BPF_SK_REUSEPORT_SELECT_OR_MIGRATE`）。新 worker 的 engine 一构建完成就接管
  其槽位。旧 worker 的监听器关闭时，其中仍在排队的连接（已完成与未完成握手的）迁移到其槽位当前的套接字。死掉的
  worker 的队列迁移到其他 worker。不需要任何 sysctl。
- **需要** supervisor 与 worker 有 root（或 `CAP_BPF`）权限，并且有 bpffs。不满足时会记录警告，worker 使用内核
  哈希；设置 `BpfSteering::strict` 则 spawn 失败。`Supervisor::bpf_steering(i)` 说明是否生效。
- 保持 listener 为 `threads` 个 I/O 线程；对有分流的 listener，`Engine::set_threads` 返回 `Unsupported`。

在 `Inherit` 模式下，worker 的监听器不构成自己的 reuseport 组：`Accel::Ebpf` 报告 `Degraded`，`bpf_steering`
被忽略（那里也不需要迁移）。

## 平台支持

Linux 与 macOS。supervisor 和 worker 都是普通进程：不在多线程之后 fork，子进程在 `exec` 之前不做任何非
异步信号安全的工作（只有 `fcntl`、`prctl`、`sched_setaffinity`）。

手册：[多进程服务（prefork）](https://lesismal.github.io/akio/zh-CN/prefork.html)。
