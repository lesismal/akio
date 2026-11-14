# flash-dpdk

[English](README.md)

[flash](https://github.com/lesismal/flash) 的内核旁路后端（**实验性**）：由 flash I/O 线程驱动的
用户态 TCP/IP 协议栈（[smoltcp](https://docs.rs/smoltcp)，IPv4），底层可以是

- **DPDK** 端口（feature `pmd`，Linux，通过 `pkg-config` 链接 libdpdk）：按 `EalConfig` 初始化
  EAL，每个 rx/tx 队列对一个 I/O 线程，mbuf 批量收发，RSS；
- Linux **TAP** 接口或 **AF_PACKET** socket（同一个协议栈，无需 DPDK）；
- 进程内的**内存链路**（任意平台；用于测试与示例）。

通过启用 `dpdk` feature（DPDK 端口需 `dpdk-pmd`）的 `flash` 使用：

```rust,ignore
use flash::{Backend, Listener, dpdk::{Device, DpdkConfig}};

let cfg = DpdkConfig::new(Device::Tap("ftap0".into()), "10.0.0.2".parse()?);
let listener = Listener::udp("10.0.0.2:7000".parse()?).backend(Backend::Dpdk(cfg)).serve(acceptor);
```

UDP listener 每次 `on_data` 交付一个数据报，TCP listener 交付字节流；`dial`、`dial_udp`、背压、
空闲超时、遥测与优雅关闭的行为与内核后端一致，因此协议 crate（flash-kcp 等）无需修改即可运行。

- 指南：[内核旁路（DPDK）](https://lesismal.github.io/flash/zh-CN/dpdk.html)
- 示例：`cargo run -p flash-dpdk --example guide-dpdk`
- 测试：`cargo test -p flash-dpdk`（内存链路，任意平台）；`tools/dpdk/test.sh`（Docker：DPDK
  `net_tap` 与 TAP，以 Linux 内核协议栈为对端）

`unsafe` 只出现在 `src/pmd.rs`（经由 `csrc/shim.c` 的 DPDK FFI）中，见
[docs/unsafe-review.zh-CN.md](../../docs/unsafe-review.zh-CN.md)。实验性：不在 semver 承诺范围内
（[docs/api-stability.zh-CN.md](../../docs/api-stability.zh-CN.md)）。

许可证：MIT。
