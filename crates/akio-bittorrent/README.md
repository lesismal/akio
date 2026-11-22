# akio-bittorrent

[中文](README.zh-CN.md)

BitTorrent on [`akio`](https://github.com/lesismal/akio): bencoding, v1, v2 and hybrid .torrent
files and magnet links (BEP 52), HTTP and UDP trackers (client and server), the peer wire protocol
with the Fast extension, the extension protocol, metadata exchange, PEX and Message Stream
Encryption, uTP with LEDBAT, the mainline DHT over IPv4 and IPv6, Local Service Discovery, web
seeds, and a client that downloads and seeds with all of them on one `akio` engine and one port
number, with rate and seed limits. Wire compatible with libtorrent and aria2
(`tools/interop/bittorrent/run.sh`).

```rust,no_run
use akio_bittorrent::client::{AddOptions, Client, ClientConfig};
use std::time::Duration;

let mut cfg = ClientConfig::default(); // 0.0.0.0:6881, TCP + uTP, MSE preferred, DHT, PEX
cfg.data_dir = "downloads".into();
let client = Client::new(cfg).unwrap();
let t = client
    .add_magnet("magnet:?xt=urn:btih:...", AddOptions::default())
    .unwrap();
t.wait_complete(Duration::from_secs(3600));
println!("{:?}", t.stats());
```

| Module | What it is | BEPs |
|---|---|---|
| `bencode` | `Value`, strict decoding (depth-limited), canonical encoding, raw spans | 3 |
| `metainfo` | .torrent v1, v2 and hybrid, info hashes, piece/file layout, piece layers, path safety, `Builder` | 3, 12, 19, 27, 47, 52 |
| `merkle` | SHA-256 merkle trees: roots, piece layers, hash request proofs | 52 |
| `magnet` | magnet links (`btih` hex and base32, `btmh`) | 9, 52 |
| `wire` | handshake, messages, `Parser`, `Bitfield`, extension payloads, allowed-fast set, hash messages | 3, 5, 6, 9, 10, 11, 52 |
| `mse` | MSE/PE: DH-768 + RC4, `Initiator` and `Receiver` without I/O | MSE |
| `tracker` | HTTP and UDP codecs, `TrackerClient`, `TrackerServer` | 3, 7, 15, 23, 48 |
| `utp` | uTP `Connection` without I/O: SACK, fast retransmit, RTO, LEDBAT | 29 |
| `dht` | DHT `Node` without I/O: routing tables (IPv4, IPv6), tokens, iterative lookups | 5, 32, 43 |
| `lsd` | Local Service Discovery announcements | 14 |
| `port` | `UdpPort`: uTP + DHT on one `akio` UDP listener, sending from its port | – |
| `client` | `Client`, `Torrent`, rarest-first picker, endgame, choking, storage on the pool, web seeds, LSD, rate and seed limits, fast resume (ADR-033) | 19, 14 |

BEP 44 is left out on purpose (ADR-018). Guide: [BitTorrent](https://lesismal.github.io/akio/en/protocols/bittorrent.html).
