# akio-tun

[中文](README.zh-CN.md)

TUN devices for [`akio`](https://github.com/lesismal/akio): layer-3 virtual interfaces served on
akio I/O threads, one IP packet per `on_data` and per `send` (ADR-096).

- **Linux**: `/dev/net/tun` with `IFF_TUN | IFF_NO_PI`, optionally multi-queue (`IFF_MULTI_QUEUE`,
  one I/O thread per queue). Needs `CAP_NET_ADMIN`.
- **macOS**: `utun` (the 4-byte family header is stripped and added without copying packets).
  Needs root.

```rust,ignore
use akio::{Conn, Engine, Handler, fn_acceptor};
use akio::tun::{TunConfig, TunDevice};

struct Node;
impl Handler for Node {
    fn on_data(&mut self, _c: &Conn<Self>, packet: &[u8]) { /* route it */ }
}

let engine = Engine::builder().build()?;
engine.start()?;
let dev = TunDevice::create(&TunConfig::new().mtu(1280).address("10.7.0.1".parse()?, 24))?;
let server = engine.serve_tun(dev, fn_acceptor(|_c: &Conn<Node>| Node))?;
server.writer().send(&packet_from_peer)?; // any thread, non-blocking, bounded queue
```

Enable it with `akio = { features = ["tun"] }`. The handler gets packets as borrowed slices on the
queue's I/O thread; writes are queued per queue under `Config::max_queued_bytes` (`Overloaded`
past it), with `on_drain` and `hold_reads` for linked backpressure. Tests that need a device skip
without privileges; `AKIO_TEST_EXPECT_TUN=1` turns a skip into a failure.
