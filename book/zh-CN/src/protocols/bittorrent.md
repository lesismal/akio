# BitTorrent

`only-bittorrent` 是运行在 only 上的 BitTorrent：bencode 编码、.torrent 文件与磁力链接、HTTP
和 UDP tracker（客户端与服务端）、带扩展和消息流加密（MSE）的 peer wire 协议、uTP、主线 DHT，
以及一个用上述全部能力下载和做种的客户端。它移植自 fib 的 `bittorrent` 包，与主流客户端线路兼容：
`tools/interop/bittorrent/run.sh` 针对 **libtorrent 2.0**（RC4 加密的 uTP、TCP、双向磁力链接、
双向 DHT）和 **aria2 1.37**（双向传输、MSE、磁力链接、HTTP 与 UDP tracker）做了互通测试。

## 一个 tracker、一个做种者和一个下载者

```rust,ignore
{{#include ../../../../crates/only-bittorrent/examples/guide-bittorrent.rs:tracker}}
```

`TrackerServer` 用一个内存存储同时服务两种协议：`http()` 是一个 only-http service（处理以
`announce` 和 `scrape` 结尾的路径，支持紧凑与字典形式的 peer 列表以及 `peers6`），`udp()` 是
UDP listener 的 acceptor（BEP 15；连接 ID 是密钥、当前分钟和客户端地址的 HMAC，因此不为每个
客户端保存状态）。

该存储是有界的：`TrackerConfig::max_swarms`（100 000）限制同时跟踪的种子数，超过后新种子的
announce 得到失败原因 `tracker full`；`max_peers_per_swarm`（1000）限制每个种子的 peer 数，
超过后新来者仍能拿到 peer 列表但不会被记录。种子的最后一个 peer 离开或过期（`peer_ttl`，1 小时）
时该 swarm 被删除；过期处理每次 announce 只需 O(1)，不再扫描整个 swarm，存储分为 16 个各自加锁的分片。

```rust,ignore
{{#include ../../../../crates/only-bittorrent/examples/guide-bittorrent.rs:torrent}}
```

`metainfo::Builder` 把字节、内存中的文件或一个路径（流式读取）哈希成 v1 种子，可设置 tracker
（BEP 12 分层）、DHT 节点、web seed 和私有标志。`MetaInfo::parse` 拒绝客户端不应信任的内容：
可能逃出下载目录的路径、相互冲突的路径、与总长度不符的分片哈希。仅 v2 的种子会被拒绝；混合
种子按其 v1 部分读取。

```rust,ignore
{{#include ../../../../crates/only-bittorrent/examples/guide-bittorrent.rs:seeder}}
```

```rust,ignore
{{#include ../../../../crates/only-bittorrent/examples/guide-bittorrent.rs:leecher}}
```

## 客户端

一个 `Client` 是一个 only engine 加 **一个端口号**：TCP listener 接受 peer 连接，UDP listener
通过 `port::UdpPort` 由 uTP 和 DHT 共享。tracker 请求经由同一 engine 上的
`tracker::TrackerClient`（HTTP(S) 用 only-http，UDP 用 `dial_udp` 套接字）。存储读写和每一次
SHA-1 校验都在逻辑池（`only-pool`）上运行，从不占用 I/O 线程。
tracker 主机名在调用线程之外解析（UDP tracker 用 `only::dns`，HTTP tracker 经由 only-http 的客户端），
从不在触发 announce 的 I/O 线程上解析。

- **种子**来自 `MetaInfo`（`add_torrent`）或磁力链接（`add_magnet`，info 字典通过 ut_metadata
  从 peer 获取，BEP 9/10）。`AddOptions` 可以为种子指定独立存储（`MemoryStorage`，或任何实现
  `Storage` 的类型；默认是 `ClientConfig::data_dir` 下的 `FileStorage`）、额外的 peer 和
  tracker、`paused`，以及 `seed`（把所有分片视为已拥有，用于刚由其数据制作的种子）。种子启动时
  会对存储中已有的数据做哈希校验，所以中断的下载可以续传。
- **`Torrent`** 提供 `stats()`、`peers()`（地址、客户端、uTP 或 TCP、是否加密、分片数、双向
  字节数、choke 状态）、`info()`、`metainfo()`、`add_peers`、`pause`/`resume`、`wait_metadata`
  和 `wait_complete`。`ClientConfig::on_event` 按顺序（在种子的锁释放之后）收到元数据到达、校验
  完成、分片校验通过、哈希失败、下载完成、peer 连接与断开、状态变化、tracker 错误和其他错误。
- **选片**：最稀有优先，并列时随机（前 4 个分片随机挑选），优先完成进行中的分片；16 KiB 的块
  按 peer 的 `reqq`（最多 64）流水线请求，回应过半后补满；残局阶段对最后的块重复请求并取消较慢
  的那个。请求 30 秒超时；60 秒未发来数据的 peer 被视为 snubbed。
- **Choke**：`upload_slots`（4）个上传槽给下载速度最快的 peer（做种时给拿得最多的），外加一个
  每 30 秒轮换的乐观 unchoke，每 10 秒重新评估；有空槽时对感兴趣的 peer 立即 unchoke。Fast
  扩展（BEP 6）：have-all 与 have-none、10 个 allowed-fast 分片、拒绝被 choke 的 peer 的请求。
- **连接**优先用 uTP 拨号（`ClientConfig::utp`），uTP 无应答时回退到 TCP；`Policy::Prefer`
  （默认）先尝试 MSE、被拒后用明文，`Policy::Require` 只用 RC4，`Policy::Disabled` 只用明文。
  入站连接按首字节区分（明文握手或 MSE）。同一 peer ID 的第二个连接会被拒绝；通过 peer ID 识别
  连到自己的连接。
- **Peer 来源**：tracker（`started`、`completed`、`stopped`，遵守间隔，失败后退避重试）、DHT
  （每 15 分钟执行 `get_peers` 和 `announce_peer`，peer 较少时每分钟一次；双向 `port` 消息）、
  PEX（BEP 11，每个 peer 每分钟一条消息）、磁力链接的 `x.pe` 以及 `add_peers`。私有种子
  （BEP 27）只使用其 tracker。

## 一个 UDP 端口：`UdpPort`

```text
数据报 ─┬─ uTP 头（版本 1，类型 ≤ 4）──► uTP 连接 ──► peer 会话
        └─ 其他（'d…' = DHT）        ──► on_datagram ──► dht::Node
```

`UdpPort` 是一个 only UDP listener 的 acceptor。它按首字节分拣数据报，用 10 ms 定时器驱动 uTP
连接，并且 **从 listener 自己的端口发送**：要联系尚未先发来数据的地址时，它用
`Engine::dial_udp_from` 在 listener 套接字上打开一个 peer，这样 DHT 节点在它宣告的端口上可达，
uTP 对端看到的也是被告知的端口。`port.connect(addr, handler)` 发起 uTP 连接；`on_accept` 接收
入站流；`send_to` 和 `on_datagram` 处理其余数据报。
同时存在的入站 uTP 连接最多 `set_max_inbound(n)`（1024）个；超过时 SYN 被直接丢弃、不作应答
（SYN 发送成本为零且源地址可能被伪造）。

## 协议层

每个协议都可以单独使用，且不含 I/O：

- `bencode`：`Value`、`decode`（严格：不允许前导零和 `-0`，深度上限 256）、`decode_prefix`
  （ut_metadata 消息中字典之后跟随的数据）、`encode`（键排序）、`raw_value`（info 字典的原始
  字节，用于计算 info hash）。
- `wire`：`Handshake`（BEP 10、DHT 和 Fast 扩展的保留位）、`Message`（BEP 3、`port`、BEP 6）、
  增量 `Parser`、`Bitfield`、`ExtendedHandshake`、`MetadataMsg`、`Pex`、`allowed_fast_set`
  （BEP 6 的算法，已用其测试向量验证）。
- `mse`：`Initiator` 和 `Receiver` 接收字节、返回要写出的字节，直到 `Established`（基于
  Montgomery 运算的 768 位 Diffie-Hellman、丢弃前 1024 字节的 RC4、crypto_provide/select、填充、
  按 `HASH('req2', info_hash)` 查找 SKEY）。
- `utp`：`Header` 和 `Connection`：SYN/DATA/STATE/FIN/RESET、libutp 的连接 ID 规则、16 位回绕
  序号、双向选择性确认、三次重复 ACK 或 SACK 越过空洞时快速重传、基于平滑 RTT 的 RTO（最小
  500 ms，指数退避）、带慢启动的 LEDBAT（目标延迟 100 ms）、保活、FIN 和空闲超时。
- `dht`：`Node` 接收数据报和时钟，排队待发数据报和 `DhtEvent`：K = 8 的 k-bucket 路由表（只有
  回应过的节点才进入；新的查询方先被 ping）、带 `implied_port` 的 ping/find_node/get_peers/
  announce_peer、绑定请求方 IP 并每 5 分钟轮换的 token、3 个并发查询的迭代查找、BEP 43 只读模式。
- `tracker`：`http` 与 `udp` 编解码、`TrackerClient`、`TrackerServer`。

## 测试与互通

- 每一层都有单元测试（uTP 连接跑在会丢包和乱序的模拟网络上；40 节点的内存 DHT；MSE 双方角色；
  BEP 6 测试向量），以及基于真实套接字的本地 swarm 测试（`tests/swarm.rs`）：一个做种者和多个
  下载者，经 TCP 和 uTP、有无 MSE，通过 HTTP 和 UDP tracker 发现 peer，磁力链接，磁盘文件与续传，
  DHT 和 PEX。
- `tools/interop/bittorrent/run.sh` 在一个 Debian 容器中以 127.0.0.1 运行全部场景：aria2 从
  only 下载（明文、强制 MSE、磁力链接）以及向 only 做种（UDP tracker，明文与 MSE）；libtorrent
  经 RC4 加密的 uTP 和经 TCP 从 only 下载，以及通过磁力链接下载；libtorrent 以同样三种方式向
  only 做种；以及双向 DHT（only 节点为 libtorrent 引导；双方都只凭磁力链接通过 DHT 找到对方的
  做种者）。
- 模糊测试目标：`bt_bencode`（bencode、metainfo、磁力链接）、`bt_peer_wire`、`bt_krpc`、
  `bt_utp`、`bt_tracker`、`bt_mse`，其种子语料由 `cargo test` 回放。

尚未实现：BitTorrent v2 与混合种子（BEP 52）、web seed（BEP 19，已解析但未使用）、本地服务发现
（BEP 14）、BEP 44 DHT 数据项、IPv6 DHT（BEP 32）、快速续传文件、分享率上限、限速。
