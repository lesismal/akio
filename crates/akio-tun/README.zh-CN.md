# akio-tun

[English](README.md)

[`akio`](https://github.com/lesismal/akio) 的 TUN 设备：在 akio I/O 线程上服务的三层虚拟接口，每次 `on_data` 与每次
`send` 一个 IP 包（ADR-096）。

- **Linux**：以 `IFF_TUN | IFF_NO_PI` 打开 `/dev/net/tun`，可选多队列（`IFF_MULTI_QUEUE`，每个队列一个 I/O 线程）。需要
  `CAP_NET_ADMIN`。
- **macOS**：`utun`（4 字节地址族头在读时去掉、写时加上，包不复制）。需要 root。

```rust,ignore
use akio::{Conn, Engine, Handler, fn_acceptor};
use akio::tun::{TunConfig, TunDevice};

struct Node;
impl Handler for Node {
    fn on_data(&mut self, _c: &Conn<Self>, packet: &[u8]) { /* 路由它 */ }
}

let engine = Engine::builder().build()?;
engine.start()?;
let dev = TunDevice::create(&TunConfig::new().mtu(1280).address("10.7.0.1".parse()?, 24))?;
let server = engine.serve_tun(dev, fn_acceptor(|_c: &Conn<Node>| Node))?;
server.writer().send(&packet_from_peer)?; // 任意线程、非阻塞、有界队列
```

通过 `akio = { features = ["tun"] }` 启用。handler 在队列的 I/O 线程上以借用切片拿到包；写入按队列排队，上限为
`Config::max_queued_bytes`（超出返回 `Overloaded`），配合 `on_drain` 与 `hold_reads` 实现联动背压。需要设备的测试在没有
特权时跳过；`AKIO_TEST_EXPECT_TUN=1` 把跳过变为失败。
