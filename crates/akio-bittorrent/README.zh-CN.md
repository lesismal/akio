# akio-bittorrent

[English](README.md)

运行在 [akio](https://github.com/lesismal/akio) 上的 BitTorrent：bencode 编码、v1、v2 与混合
.torrent 文件及磁力链接（BEP 52）、HTTP 和 UDP tracker（客户端与服务端）、带 Fast 扩展、扩展协议、
元数据交换、PEX 和消息流加密的 peer wire 协议、带 LEDBAT 的 uTP、支持 IPv4 与 IPv6 的主线 DHT、
本地服务发现、web seed，以及一个在同一个 akio engine、同一个端口号上用上述全部能力下载和做种、支持
速率与做种限制的客户端。与 libtorrent 和 aria2 线路兼容
（`tools/interop/bittorrent/run.sh`）。

```rust,no_run
use akio_bittorrent::client::{AddOptions, Client, ClientConfig};
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
| `metainfo` | v1、v2 与混合 .torrent、info hash、分片/文件布局、分片层、路径安全检查、`Builder` | 3、12、19、27、47、52 |
| `merkle` | SHA-256 默克尔树：根、分片层、哈希请求证明 | 52 |
| `magnet` | 磁力链接（`btih` 十六进制与 base32、`btmh`） | 9、52 |
| `wire` | 握手、消息、`Parser`、`Bitfield`、扩展载荷、allowed-fast 集合、哈希消息 | 3、5、6、9、10、11、52 |
| `mse` | MSE/PE：DH-768 + RC4，不含 I/O 的 `Initiator` 与 `Receiver` | MSE |
| `tracker` | HTTP 与 UDP 编解码、`TrackerClient`、`TrackerServer` | 3、7、15、23、48 |
| `utp` | 不含 I/O 的 uTP `Connection`：SACK、快速重传、RTO、LEDBAT | 29 |
| `dht` | 不含 I/O 的 DHT `Node`：路由表（IPv4、IPv6）、token、迭代查找 | 5、32、43 |
| `lsd` | 本地服务发现公告 | 14 |
| `port` | `UdpPort`：uTP 与 DHT 共享一个 akio UDP listener，并从它的端口发送 | – |
| `client` | `Client`、`Torrent`、最稀有优先选片、残局模式、choke、在逻辑池上读写存储、web seed、LSD、速率与做种限制、快速续传（ADR-033） | 19、14 |

有意不实现 BEP 44（ADR-018）。
指南：[BitTorrent](https://lesismal.github.io/akio/zh-CN/protocols/bittorrent.html)。
