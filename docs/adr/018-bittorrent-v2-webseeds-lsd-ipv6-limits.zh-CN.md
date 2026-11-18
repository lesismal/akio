# ADR-018：BitTorrent v2 与混合种子、Web 种子、LSD、IPv6 DHT、速率与做种限制

[English](018-bittorrent-v2-webseeds-lsd-ipv6-limits.md) | 简体中文

状态：已接受（2026-11-17）

## 背景

`only-bittorrent` 此前只支持 v1 种子。`docs/DEV-PLAN.md`（M7）列出了剩余工作：BEP 52（v2
与混合种子）、Web 种子（BEP 19）、本地服务发现 LSD（BEP 14）、BEP 44、IPv6 DHT（BEP 32），以及
速率与做种限制。纯 v2 种子会以 `MetaError::Unsupported` 拒绝；混合种子只按其 v1 部分读取。客户端
每个种子只有一个 `InfoHash`，只监听一个地址族，并且传输速度不受限制。

这些都会改变 `metainfo`、`magnet`、`wire`、`dht` 和 `client` 的公开 API，并新增模块。

## 决定

1. **v2 哈希与默克尔树（BEP 52）。**
   - 新模块 `merkle`：以 16 KiB 块为叶子的 SHA-256 树，用全零叶子补齐到 2 的幂
     （`pad_hash`、`subtree_root`、`piece_root`、`file_root`、`root_from_piece_layer`）；
     `MerkleTree`（从分片层向上的单文件树，用于应答哈希请求：`hashes`、`uncles`）；
     `verify_hashes` 与 `uncle_count`。叔哈希与 libtorrent 一致：从 `log2(length)` 层到
     `proof layers` 层每层一个，自叶向根（即 BEP 52 所说"被省略的层仍然计数"）。
   - `metainfo`：`InfoHashV2`（32 字节，`truncated()`）、`TorrentVersion { V1, V2, Hybrid }`
     （`Info::version`）、`FileEntry::pieces_root`、`PieceLayers`（按文件根校验）、
     `MetaInfo::{info_hash_v2, piece_layers, verify_piece}`、`Info::{info_hash_v1,
     info_hash_v2, has_v1, has_v2, piece_file, file_pieces, needs_piece_layer, file_of_root,
     check_piece_layer, verify_piece_with, can_verify}`、`Builder::version`。
     `MetaError::Unsupported` 现在只表示 `meta version` 大于 2。
   - **三种种子共用一个分片空间。** v2 让每个非空文件从分片边界开始。混合种子的 v1 文件列表本就
     带有 BEP 47 填充文件；纯 v2 种子由解析器合成填充文件（`.pad/<大小>`，`padding: true`）。于是
     第 `i` 个分片在各视图中覆盖相同字节，存储（从不写填充）与选片逻辑保持不变，v1 与 v2 校验作用
     于同一缓冲区。
   - **`MetaInfo::info_hash` 即对等方使用的哈希**：v1 与混合种子为 SHA-1，纯 v2 种子为截断的
     SHA-256。按 `info_hash` 索引种子的代码无需修改。
   - 解析时拒绝：不是 2 的幂或小于 16 KiB 的 v2 分片长度、文件树中不安全或冲突的名称、带子节点的
     文件节点、缺失或不匹配的分片层，以及 v1 与 v2 部分描述的文件或偏移不一致的混合种子。
   - `Builder` 生成 v2 与混合种子时按路径排序文件（文件树是字典），混合种子用 BEP 47 填充文件
     对齐。
2. **磁力链接**：`urn:btmh:1220<hex>`（`Magnet::info_hash_v2`、`is_v2_only`）；纯 v2 链接的
   `info_hash` 为截断哈希。
3. **对等协议**：`Handshake::with_v2` 设置 v2 位（保留字节 7 的 `0x10`），`Handshake::v2` 读取它；
   客户端只为 v2 与混合种子设置该位（libtorrent 对 v1 种子收到带该位的明文握手会以 "invalid
   info-hash" 关闭连接），并向 v2 种子的任何对等方请求哈希（libtorrent 应答的握手不带 v2 位）；
   新增 `Message::{HashRequest, Hashes, HashReject}` 与 `HashRequest`。
4. **客户端与 v2。** 混合种子是同一个种子的两个哈希：tracker 与 DHT 都会用两个哈希公告和查找，
   传入握手与 MSE 接受任一哈希；对方用 v2 哈希回应我们的 v1 握手（BEP 52 的升级）时保留连接。
   分片按适用情况用 SHA-1 和默克尔树校验。磁力链接得到的种子会向支持 v2 的对等方获取缺失的分片层：
   每次请求 512 个哈希并附带到根的证明，每个对等方最多 4 个在途请求，超时 10 秒，拒绝或超时三次的
   对等方不再询问；纯 v2 文件的分片层未知前不选取其分片。客户端为已有的分片层、以及已有分片的块哈希
   （在逻辑池上读取，每个对等方最多 8 个）应答哈希请求，其余一律回复 hash reject。用于应答的默克尔
   树缓存有上限（64）。
5. **IPv6。** 不另开一对套接字：监听 `[::]:port` 时引擎套接字为双栈（`only-sys` 绑定 IPv6 套接字时
   已关闭 `IPV6_V6ONLY`），`UdpPort` 与 TCP 接收端以普通 IPv4 地址（而非 `::ffff:a.b.c.d`）报告
   IPv4 对等方，发送时再映射回去。DHT `Node` 在 IPv4 路由表之外维护一张 IPv6 路由表（BEP 32）：
   `compact_nodes6`、`parse_compact_nodes6`、`Node::{set_ipv6, table6_len}`，应答中的 `nodes6`
   与 `want`，以及按询问方地址族返回的 values；客户端在双栈监听时自动开启（`Client::dht_nodes6`）。
   PEX 与 tracker 本已支持 IPv6 对等方。
6. **Web 种子（BEP 19）** 经由 only-http 客户端（最多 5 次重定向，每个请求 60 秒，每个范围请求
   不超过 4 MiB，响应体也以此为上限）：每个 Web 种子同时只取一个分片，每个种子最多 16 个 Web 种子，
   优先选择已连接对等方都没有的分片，从不请求填充，要求 `206`（整文件时可为 `200`），失败或哈希
   校验失败后从 10 秒起指数退避到 10 分钟，并上报 `TorrentEvent::WebSeedError`。
   `ClientConfig::web_seeds`（默认开启）、`AddOptions::web_seeds`、`Torrent::add_web_seed`。
7. **LSD（BEP 14）**：模块 `lsd`（`Announce`、多播组、`MAX_MESSAGE` 1400、`MAX_INFO_HASHES` 16）
   与 `ClientConfig::lsd`（默认开启，私有种子从不使用）。客户端在独立线程上运行它，使用 6771 端口上
   设置了 `SO_REUSEADDR`/`SO_REUSEPORT` 的套接字（IPv4，双栈时加 IPv6）；种子加入时及之后每 5 分钟
   公告一次（每分钟最多一次），用 cookie 识别自己的公告，每秒最多读取 50 条公告。端口或多播组不可用
   时客户端不启用 LSD。选择独立线程而非引擎监听器：引擎没有加入多播组的 API，而 LSD 每分钟只有几个
   数据报。
8. **速率限制**：`RateLimits { upload, download }`（字节每秒，`None` 表示不限），客户端级
   （`ClientConfig::rate_limits`、`Client::set_rate_limits`）与单种子级（`AddOptions::rate_limits`、
   `Torrent::set_rate_limits`）。令牌桶按时钟补充，最多容纳 200 毫秒的量（至少一个块）；发往对等方与
   Web 种子的请求在发出前消耗下载令牌，上传请求在读取存储前排队（受每个对等方的请求上限约束）等待上传
   令牌。不限速时每个块只多一次 relaxed 原子读取。
9. **做种限制**：`SeedLimits { ratio, time }`（`ClientConfig::seed_limits`、
   `AddOptions::seed_limits`、`Torrent::set_seed_limits`）；完成的种子达到任一限制即暂停，并上报
   `TorrentEvent::SeedLimitReached`。分享率：本次会话上传量除以下载量（若未下载则除以种子大小）。
   `TorrentStats` 新增 `seeding_time` 与 `web_seeds_active`。
10. **不实现 BEP 44（DHT 任意数据存储）。** 它为其他应用存储可变与不可变条目；下载和做种从不需要，
    唯一完整实现它的客户端 libtorrent 也不在种子流程中使用它。它会给 DHT 增加按远端输入索引的条目
    存储、每次 `put` 的 Ed25519 签名校验以及 salt/序号状态机，扩大攻击面。`dht::Node` 只需新增方法
    即可在以后加入它，不会破坏 API。

## 影响

- 纯 v2 种子与磁力链接现在可以加载，不再报 `Unsupported`；混合种子按两种格式校验。分片层缺失或
  错误的种子按 BEP 52 要求被拒绝。
- `Handshake::new` 不变（不带 v2 位）；`PeerInfo::v2` 报告对方的 v2 位。
- 纯 v2 种子的最后一个文件也补齐到整分片（libtorrent 会请求最后一个分片的整块），`FileStorage`
  会创建空文件。
- `ClientConfig::lsd` 与 `web_seeds` 默认开启（与 libtorrent 相同）；在同一主机上运行多个客户端的
  测试会关闭 LSD。
- 互操作（`tools/interop/bittorrent/run.sh`，套件 `v2`、`webseed`、`lsd`；连同原有套件 32/32）：双方各自生成的 v2 与
  混合种子，通过 .torrent 和磁力链接，与 libtorrent 2.0 双向互通；与 aria2 1.37（不支持 v2）双向
  互通混合种子；从 nginx 获取 Web 种子；Docker 网络上两个容器之间的 LSD。
- 新增模糊测试目标 `bt_lsd` 与 `bt_merkle`；`bt_bencode`、`bt_peer_wire` 与 `bt_krpc` 覆盖 v2
  元信息、哈希消息与 BEP 32。
