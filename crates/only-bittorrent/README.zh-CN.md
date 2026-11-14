# only-bittorrent

[English](README.md)

运行在 [only](https://github.com/lesismal/flash) 上的 BitTorrent：bencode 编码、.torrent 文件与
磁力链接、HTTP 和 UDP tracker（客户端与服务端）、带 Fast 扩展、扩展协议、元数据交换、PEX 和消息流
加密的 peer wire 协议、带 LEDBAT 的 uTP、主线 DHT，以及一个在同一个 only engine、同一个端口号上
用上述全部能力下载和做种的客户端。与 libtorrent 和 aria2 线路兼容
（`tools/interop/bittorrent/run.sh`）。

```rust,no_run
use only_bittorrent::client::{AddOptions, Client, ClientConfig};
use std::time::Duration;

let mut cfg = ClientConfig::default(); // 0.0.0.0:6881，TCP + uTP，优先 MSE，DHT，PEX
cfg.data_dir = "downloads".into();
let client = Client::new(cfg).unwrap();
let t = client
    .add_magnet("magnet:?xt=urn:btih:...", AddOptions::default())
    .unwrap();
t.wait_complete(Duration::from_secs(3600));
println!("{:?}", t.stats());
```

| 模块 | 内容 | BEP |
|---|---|---|
| `bencode` | `Value`、严格解码（限制深度）、规范编码、原始字节区间 | 3 |
| `metainfo` | v1 .torrent、info hash、分片/文件布局、路径安全检查、`Builder` | 3、12、19、27、47 |
| `magnet` | 磁力链接（十六进制与 base32） | 9 |
| `wire` | 握手、消息、`Parser`、`Bitfield`、扩展载荷、allowed-fast 集合 | 3、5、6、9、10、11 |
| `mse` | MSE/PE：DH-768 + RC4，不含 I/O 的 `Initiator` 与 `Receiver` | MSE |
| `tracker` | HTTP 与 UDP 编解码、`TrackerClient`、`TrackerServer` | 3、7、15、23、48 |
| `utp` | 不含 I/O 的 uTP `Connection`：SACK、快速重传、RTO、LEDBAT | 29 |
| `dht` | 不含 I/O 的 DHT `Node`：路由表、token、迭代查找 | 5、43 |
| `port` | `UdpPort`：uTP 与 DHT 共享一个 only UDP listener，并从它的端口发送 | – |
| `client` | `Client`、`Torrent`、最稀有优先选片、残局模式、choke、在逻辑池上读写存储 | – |

尚未实现：BitTorrent v2/混合种子（BEP 52）、web seed、LSD、BEP 44、IPv6 DHT、快速续传文件、限速。
指南：[BitTorrent](https://lesismal.github.io/flash/zh-CN/protocols/bittorrent.html)。
