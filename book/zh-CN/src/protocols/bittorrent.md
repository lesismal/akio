# BitTorrent

`only-bittorrent` 是运行在 only 上的 BitTorrent：bencode 编码、v1、v2 与混合 .torrent 文件及磁力
链接、HTTP 和 UDP tracker（客户端与服务端）、带扩展和消息流加密（MSE）的 peer wire 协议、uTP、
支持 IPv4 与 IPv6 的主线 DHT、本地服务发现、web seed，以及一个用上述全部能力下载和做种、支持速率
与做种限制的客户端。它移植自 fib 的 `bittorrent` 包，与主流客户端线路兼容：
`tools/interop/bittorrent/run.sh` 针对 **libtorrent 2.0**（RC4 加密的 uTP、TCP、双向磁力链接、
双向 DHT、双向 v2 与混合种子、Docker 网络上的双向 LSD）和 **aria2 1.37**（双向传输、MSE、磁力
链接、HTTP 与 UDP tracker、混合种子）做了互通测试，并以 nginx 测试 web seed。

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

`metainfo::Builder` 把字节、内存中的文件或一个路径（流式读取）哈希成 v1、v2 或混合种子
（`Builder::version`），可设置 tracker（BEP 12 分层）、DHT 节点、web seed 和私有标志。
`MetaInfo::parse` 拒绝客户端不应信任的内容：可能逃出下载目录的路径、相互冲突的路径、与总长度不符
的分片哈希、与文件根不符的 v2 分片层，以及两部分描述不同文件的混合种子。

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

## v2 与混合种子（BEP 52）

v2 种子把每个文件单独哈希成以 16 KiB 块为叶子的 SHA-256 默克尔树：info 字典带有每个文件的根
（`FileEntry::pieces_root`），.torrent 的 `piece layers` 带有树中每个哈希恰好覆盖一个分片的那一层
（`MetaInfo::piece_layers`，按根校验）。混合种子为同一组文件同时携带两种格式。

- **一个分片空间。** v2 让每个文件从分片边界开始。混合种子在 v1 文件列表中用 BEP 47 填充文件
  实现这一点；对纯 v2 种子，解析器补上填充文件（`.pad/<大小>`，`padding: true`）。于是第 `i` 个
  分片在各视图中是相同的字节，存储从不写填充，`Info::verify_piece_with(layers, i, data)` 在同一
  缓冲区上同时校验 SHA-1 与默克尔哈希。
- **哈希。** `InfoHashV2` 是 info 字典的 SHA-256；`MetaInfo::info_hash` 是对等方使用的哈希：v1 与
  混合种子为 SHA-1，纯 v2 种子为截断的 v2 哈希。磁力链接携带 `urn:btmh:1220<hex>`
  （`Magnet::info_hash_v2`）。
- **客户端** 用两个哈希公告混合种子（tracker、DHT、LSD），并接受以任一哈希发起的连接，包括用 v2
  哈希回应我们 v1 握手的对等方。磁力链接得到的种子用哈希请求向支持 v2 的对等方获取缺失的分片层
  （每次 512 个哈希，证明到文件根；每个对等方 4 个在途，超时 10 秒），在纯 v2 文件的分片层已知前
  不选取其分片。客户端为已有的分片层和已有分片的块哈希（在池上读取）应答哈希请求。
- `merkle` 提供树运算：`file_root`、`piece_root`、`root_from_piece_layer`、`MerkleTree`（按
  libtorrent 期望的方式应答 `hashes`/`uncles`）和 `verify_hashes`。

## Web seed、LSD、IPv6 与限制

- **Web seed（BEP 19）**：种子的 `url-list`、`AddOptions::web_seeds` 与 `Torrent::add_web_seed`
  （最多 16 个）。空闲的 web seed 取一个缺失分片（优先没有已连接对等方拥有的分片），经 only-http
  客户端用不超过 4 MiB 的 `Range` 请求获取，跳过填充；之后像来自对等方的分片一样校验并写入。失败或
  校验失败会让该 web seed 退避（10 秒起翻倍，最多 10 分钟）并上报 `TorrentEvent::WebSeedError`。
  单文件种子的 URL 指向文件本身（以 `/` 结尾时为目录）；多文件种子的 URL 是包含 `<name>/<path>`
  的目录。
- **LSD（BEP 14）**：`ClientConfig::lsd`（默认开启，私有种子从不使用）在独立线程上向
  239.192.152.143:6771（双栈时还有 `[ff15::efc0:988f]:6771`）多播 `BT-SEARCH` 公告：种子加入时
  一次、之后每 5 分钟一次，并添加听到的对等方（每秒最多 50 条公告，每条 16 个哈希；用 cookie 识别
  自己的公告）。`lsd` 模块是其编解码。
- **IPv6**：监听 `[::]:port` 时，一对双栈 TCP 与 UDP 套接字同时服务 IPv4 和 IPv6；IPv4 对等方保持
  普通地址。此时 DHT 还维护一张 IPv6 路由表（BEP 32：`nodes6`、`want`；`Client::dht_nodes6`）。
  PEX 与 tracker 传递 IPv6 对等方。
- **速率限制**：`RateLimits { upload, download }`，单位字节每秒，客户端级
  （`ClientConfig::rate_limits`、`Client::set_rate_limits`）与单种子级（`AddOptions::rate_limits`、
  `Torrent::set_rate_limits`）。请求发出前消耗下载令牌；上传在读取存储前等待上传令牌。
- **做种限制**：`SeedLimits { ratio, time }`（`ClientConfig::seed_limits`、
  `AddOptions::seed_limits`、`Torrent::set_seed_limits`）：完成的种子达到分享率（本次会话上传量
  除以下载量，若未下载则除以种子大小）或做种时间后暂停，并上报 `TorrentEvent::SeedLimitReached`。
  有续传数据时，分享率与时间跨会话累计。

## 快速续传

设置 `ClientConfig::resume_dir` 后，重启或崩溃后再次添加的种子会从已有的进度开始，而不是对数据做
哈希检查（[ADR-033](https://github.com/lesismal/only/blob/main/docs/adr/033-bittorrent-fast-resume.zh-CN.md)）：

```rust,ignore
let mut cfg = ClientConfig::default();
cfg.resume_dir = Some("resume".into()); // 每个种子一个 <info hash 十六进制>.resume
let client = Client::new(cfg)?;
let t = client.add_torrent(MetaInfo::load("file.torrent")?, AddOptions::default())?;
// ……之后，或在另一个进程里：
client.close(); // 在最后一次写入完成后保存每个种子
```

- **保存什么**：一个带版本、以 SHA-256 校验和收尾的 bencode 字典：已有分片、info 字典（磁力链接
  重启无需元数据交换）、从对等方获取的 v2 分片层、每个文件的大小与修改时间、至多 200 个对等方、
  tracker 与 web seed、跨会话累计以及种子的限制。有改动时每隔 `ClientConfig::resume_interval`
  （30 秒）保存一次，暂停后不久与 `Client::close` 时也保存；每次保存都原子替换文件（临时文件、
  fsync、rename）。`Client::remove` 删除它。
- **信任什么**：大小或修改时间变了的文件，其所有分片都重新检查
  （`TorrentEvent::ResumeAccepted { pieces, rechecking }`）；其余视为已有
  （`TorrentStats::pieces_checked` 统计读回的分片数）。崩溃后，客户端仍在写入的文件出于无害的
  原因比上次保存更新，因此按大小信任；那次保存之后下载的分片会重新下载。损坏、截断或属于其他种子
  的数据会被拒绝（`TorrentEvent::ResumeRejected`），数据做完整检查。
- **存到别处**：`Torrent::resume_data()` 返回字节；用 `AddOptions::resume_data` 交回，或用
  `Client::add_resume` 仅凭它们添加种子。自定义 `Storage` 通过 `Storage::file_stamps` 报告其文件
  （未实现时，若 `may_have_data()` 则信任续传数据）。

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
- `wire`：`Handshake`（BEP 10、DHT、Fast 扩展和 v2 的保留位）、`Message`（BEP 3、`port`、
  BEP 6、BEP 52 的 hash request、hashes 与 hash reject）、
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
  announce_peer、绑定请求方 IP 并每 5 分钟轮换的 token、3 个并发查询的迭代查找、BEP 43 只读模式，
  以及 BEP 32（`set_ipv6`：IPv6 节点的第二张路由表、`nodes6`、`want`）。
- `merkle`：BEP 52 默克尔树（见上）。`lsd`：BEP 14 公告。
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
  做种者）。套件 `v2`：only 与 libtorrent 各自生成的纯 v2 与混合多文件种子，双方通过 .torrent 和
  磁力链接互相下载（v2 磁力链接双向检验哈希请求），以及 aria2 下载并做种混合种子。套件 `webseed`：
  只从 nginx 下载 v1、混合与 v2 种子。套件 `lsd`：Docker 网络上的两个容器通过 LSD 双向发现彼此。
- `tests/extensions.rs`：v2 与混合 swarm、v2 磁力链接获取分片层、通过 v2 哈希访问混合种子、从
  only-http 文件服务器获取 web seed、LSD、双栈做种者与 IPv4/IPv6 下载者、仅 IPv6 的 DHT、速率
  限制、做种限制。
- `tests/resume.rs`：v1、v2 与混合种子的快速续传：`close` 后在没有对等方的情况下重启且没有任何
  分片被重新哈希；下载中途被 `SIGKILL` 的客户端重启后完成下载，且不哈希它已有的分片；改动的文件
  单独重新检查；拒绝损坏与属于其他种子的续传文件；导出与导入；恢复 v2 磁力链接的分片层。
- 模糊测试目标：`bt_bencode`（bencode、v1/v2/混合 metainfo、磁力链接）、`bt_peer_wire`（含哈希
  消息）、`bt_krpc`（IPv4 与双栈节点）、`bt_utp`、`bt_tracker`、`bt_mse`、`bt_lsd`、`bt_merkle`、
  `bt_resume`，其种子语料由 `cargo test` 回放。

有意不实现 BEP 44（DHT 任意数据）：下载与做种从不需要它，而它会给 DHT 增加
按远端输入索引、需签名校验的条目存储（[ADR-018](https://github.com/lesismal/only/blob/main/docs/adr/018-bittorrent-v2-webseeds-lsd-ipv6-limits.zh-CN.md)）。
