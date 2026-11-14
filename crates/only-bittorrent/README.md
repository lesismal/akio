# only-bittorrent

[中文](README.zh-CN.md)

BitTorrent on [`only`](https://github.com/lesismal/only): bencoding, .torrent files and magnet
links, HTTP and UDP trackers (client and server), the peer wire protocol with the Fast extension,
the extension protocol, metadata exchange, PEX and Message Stream Encryption, uTP with LEDBAT,
the mainline DHT, and a client that downloads and seeds with all of them on one `only` engine
and one port number. Wire compatible with libtorrent and aria2
(`tools/interop/bittorrent/run.sh`).

```rust,no_run
use only_bittorrent::client::{AddOptions, Client, ClientConfig};
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
| `metainfo` | .torrent v1, info hash, piece/file layout, path safety, `Builder` | 3, 12, 19, 27, 47 |
| `magnet` | magnet links (hex and base32) | 9 |
| `wire` | handshake, messages, `Parser`, `Bitfield`, extension payloads, allowed-fast set | 3, 5, 6, 9, 10, 11 |
| `mse` | MSE/PE: DH-768 + RC4, `Initiator` and `Receiver` without I/O | MSE |
| `tracker` | HTTP and UDP codecs, `TrackerClient`, `TrackerServer` | 3, 7, 15, 23, 48 |
| `utp` | uTP `Connection` without I/O: SACK, fast retransmit, RTO, LEDBAT | 29 |
| `dht` | DHT `Node` without I/O: routing table, tokens, iterative lookups | 5, 43 |
| `port` | `UdpPort`: uTP + DHT on one `only` UDP listener, sending from its port | – |
| `client` | `Client`, `Torrent`, rarest-first picker, endgame, choking, storage on the pool | – |

Not done yet: BitTorrent v2/hybrid (BEP 52), web seeds, LSD, BEP 44, IPv6 DHT, fast-resume files,
rate limits. Guide: [BitTorrent](https://lesismal.github.io/only/en/protocols/bittorrent.html).
