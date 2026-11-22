# akio-dpdk

[English](README.md)

[akio](https://github.com/lesismal/akio) 的内核旁路后端（**实验性**）：由 akio I/O 线程驱动的
自研用户态 TCP/IP 协议栈（以太网、ARP、带分片的 IPv4、ICMP、带 NDP、ICMPv6 与分片的 IPv6（双栈
listener）、UDP，以及支持 SACK、快速恢复、CUBIC / NewReno、窗口缩放、时间戳、SYN cookie、可选 ECN 与
pacing 的 TCP；UDP 数据报双向携带 ECN 码点；安全 Rust，`#![forbid(unsafe_code)]`，
无依赖），底层可以是

- **DPDK** 端口（feature `pmd`，Linux，通过 `pkg-config` 链接 libdpdk）：按 `EalConfig` 初始化
  EAL，每个 rx/tx 队列对一个 I/O 线程，mbuf 批量收发，RSS；
- 经 **AF_XDP** socket 使用现有 Linux 接口（`Device::AfXdp`，ADR-063）：XDP 程序把每个 RX 队列重定向到由 I/O
  线程轮询的 socket，驱动支持时零拷贝（同一个协议栈，无需 DPDK）；
- Linux **TAP** 接口或 **AF_PACKET** socket（同一个协议栈，无需 DPDK）；
- 进程内的**内存链路**（任意平台；用于测试与示例）。

通过启用 `dpdk` feature（DPDK 端口需 `dpdk-pmd`）的 `akio` 使用：

```rust,ignore
use akio::{Backend, Listener, dpdk::{Device, DpdkConfig}};

let cfg = DpdkConfig::new(Device::Tap("ftap0".into()), "10.0.0.2".parse()?);
let listener = Listener::udp("10.0.0.2:7000".parse()?).backend(Backend::Dpdk(cfg)).serve(acceptor);
```

UDP listener 每次 `on_data` 交付一个数据报，TCP listener 交付字节流；`dial`、`dial_udp`、背压、
空闲超时、遥测与优雅关闭的行为与内核后端一致，因此协议 crate（akio-kcp 等）无需修改即可运行。

- 指南：[内核旁路（DPDK）](https://lesismal.github.io/akio/zh-CN/dpdk.html)
- 示例：`cargo run -p akio-dpdk --example guide-dpdk`
- 基准：`cargo run --release -p akio-dpdk --example stack-bench`
- 测试：`cargo test -p akio-dpdk`（逐层单元测试、模拟的丢包/乱序链路、内存链路；任意平台）；
  `tools/dpdk/test.sh`（Docker：DPDK `net_tap`、TAP 与 AF_PACKET，以 Linux 内核协议栈为对端，
  含 `tc netem` 丢包）；`fuzz/` 中的 `dpdk_*` 模糊测试目标

`unsafe` 只出现在 `src/pmd.rs`（经由 `csrc/shim.c` 的 DPDK FFI）与 `src/sys.rs`（TAP /
AF_PACKET）中；协议栈本身（`src/net/`）禁止 unsafe。见
[docs/unsafe-review.zh-CN.md](../../docs/unsafe-review.zh-CN.md)。实验性：不在 semver 承诺范围内
（[docs/api-stability.zh-CN.md](../../docs/api-stability.zh-CN.md)）。

许可证：MIT。
