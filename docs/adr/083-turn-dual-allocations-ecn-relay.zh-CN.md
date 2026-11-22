# ADR-083：TURN 双分配与经中继保留 ECN

[English](083-turn-dual-allocations-ecn-relay.md) | 简体中文

状态：已采纳（2026-11-22）

## 背景

`akio-turn` 的两项遗留工作，其他文档都把它们列为未完成：

- **双分配。** ADR-076 列出"`ADDITIONAL-ADDRESS-FAMILY` 双分配（UDP 也不支持）"。RFC 8656
  允许一次 Allocate 同时请求一个 IPv4 与一个 IPv6 中继地址。服务器只从一个 `relay_ip` 中继，因此只有一个
  地址族：请求另一地址族的 `REQUESTED-ADDRESS-FAMILY` 得到 440，该属性被忽略。
- **经中继保留 ECN。** ADR-077 加入了 ECN 管道：每个收到的 UDP 数据报的码点（`Conn::rx_ecn`，在 Linux
  与 macOS 上来自 `IP_RECVTOS` / `IPV6_RECVTCLASS`），以及带标记的发送（`UdpBinding::send_to_ecn`、
  `Conn::send_segments_ecn`）。ADR-082 让 akio-webrtc 给经 UDP 发往 TURN 服务器的数据打标记，依赖服务器
  复制码点。它把"在 akio-turn 自己的中继里复制码点"列为未完成：经过 `akio-turn` 的路径在几次探测后 ECN
  验证失败。

RFC 8656 概要：

- **Allocate（7.2 节）。**
  - 同时带 `REQUESTED-ADDRESS-FAMILY` 与 `ADDITIONAL-ADDRESS-FAMILY`：400。
  - `RESERVATION-TOKEN` 与二者之一同时出现，或与 `EVEN-PORT` 同时出现：400。
  - 带 R 位的 `EVEN-PORT` 与 `ADDITIONAL-ADDRESS-FAMILY` 同时出现：400（需要两个令牌）。
  - `ADDITIONAL-ADDRESS-FAMILY` 不是 IPv6（0x02）：400。
  - 服务器不中继的请求地址族：440。两个属性都没有时分配 IPv4。
  - 服务器只能部分满足的双分配请求也成功，带 IPv4 地址，并以 `ADDRESS-ERROR-CODE`（地址族，440 或 508）
    说明另一个。
  - 完全成功时带两个 `XOR-RELAYED-ADDRESS`。
- **Refresh（8 节）。**
  - `REQUESTED-ADDRESS-FAMILY` 选择刷新哪个地址族，生存期为 0 时删除它。
  - 不带时作用于所有地址族。
  - 分配没有的地址族：443。
  - 删除一个地址族会带走它的权限与通道，另一个的保留。
- **权限与通道（9、10、12 节）。**
  - 对端必须属于分配所具有的地址族，否则 443。
  - 一个 CreatePermission 可以列出两个地址族的对端。
- **ECN（14 节，UDP 到 UDP）。**
  - 推荐行为：两个方向都把发出的码点设为收到的码点。
  - 客户端经 TCP 时（15、16 节）没有可复制的：发出 Not-ECT，丢弃对端的码点。

## 决定

### 服务器：双分配

**配置。** `TurnConfig::additional_relay_ip` 是与 `relay_ip` 不同地址族的地址，`additional_public_ip`
是它的 1:1 NAT 地址。二者都可选，默认 `None`；与 `relay_ip` 同地址族的地址会被忽略。

**分配。** 一个分配持有一个或两个中继地址（`RelayAddr`：绑定地址、公开地址、到期时间），各有自己的生存期。

- 只要有一个还活着，分配就活着；最后一个结束时，分配及其配额随之释放。
- 双分配按一个分配计入配额。
- 权限仍按 IP 地址、通道仍按对端地址为键，因此各自天然属于自己的地址族。
- 发往对端的数据从对端所属地址族的中继地址发出。
- 对端的数据报只在其所属地址族的中继地址上被接受，要求该地址还活着并且有权限。

**地址族规则**（`families()`，Allocate 与预绑定共用的一个函数）：

- 严格按 7.2 节，按其顺序。
- 两个属性都没有时：服务器中继 IPv4 就分配 IPv4。只配置了 IPv6 `relay_ip` 的服务器仍分配 IPv6（与以前
  相同），而不是像 RFC 所说回 440，现有的纯 IPv6 部署因此不受影响。
- 双分配请求需要 IPv4（纯 IPv6 服务器回 440）。

**部分成功。**

- 没有配置 IPv6 中继：IPv4 地址加 `ADDRESS-ERROR-CODE`（IPv6，440）。
- IPv6 socket 绑定失败：同上，错误码 508。
- IPv4 socket 绑定失败：整个请求回 508。
- 重传的 Allocate 得到同样的应答，因此该错误码随分配保存。
- 不带 R 位的 `EVEN-PORT` 对两个地址族都生效。

**Refresh、权限、通道、Connect：** 按 RFC（443；Refresh 中未知的地址族值回 400）。到期按地址族计算：清扫
单独关闭一个到期的中继地址，连同它的权限与通道。

**coturn 的码点。** coturn 4.6 按 draft-ietf-tram-turnbis 的编号，把 `ADDITIONAL-ADDRESS-FAMILY` 编为
0x8032，`ADDRESS-ERROR-CODE` 编为 0x8033。RFC 8656 分配的是 0x8000 与 0x8001；0x8032 与 0x8033 在 IANA
未分配。互通测试中看到：

- coturn 的 `turnutils_uclient -Z` 对 akio-turn 只得到一个中继地址，随后它的 IPv6 权限得到 443。
- 我方客户端对 coturn 只得到一个中继地址，也没有错误码。

因此服务器把 0x8032 当作别名，规则相同。对使用它的请求，应答在两个码点上都带 `ADDRESS-ERROR-CODE`。两个
属性都是可选理解的，认识其一的服务器会忽略另一个。

**TCP 分配**（RFC 6062）只有一个中继地址。经 TCP 或 TLS 的双分配请求得到 IPv4 监听地址与
`ADDRESS-ERROR-CODE`（IPv6，440），而不是错误，这样总是请求两者的客户端仍能得到分配。

**预绑定。** 与以前一样，经过认证的 Allocate 在取分片锁之前就绑定好中继 socket。`Shared::prebind_ips`
现在返回要绑定的地址：一个；服务器能满足的双分配请求则是两个；格式不对的请求一个也没有。`Env::open_relay`
取地址匹配的预绑定 socket，未用的在释放分片后关闭。

### 服务器：经中继保留 ECN

- `TurnEnv` 新增 `send_to_client_ecn` 与 `send_to_peer_ecn`。默认实现调用原有方法并丢弃码点，现有的环境
  无需修改即可编译。
- `TurnCore` 新增 `handle_client_ecn` 与 `handle_peer_ecn`，带上数据报的码点。原有入口传 0。
- ChannelData 与 Send 指示带着客户端的码点发往对端。对端的数据报以 ChannelData 或 Data 指示带着对端的码点
  发往客户端。
- 请求与响应从不带码点。
- `TurnServer` 在监听连接（UDP 客户端，以及 DTLS 客户端：数据报的码点随它所含的每条记录）与中继连接
  （对端）上读取 `Conn::rx_ecn()`。
- 发往对端：带标记的数据报用 `UdpBinding::send_to_ecn` 发出（一次带 `IP_TOS` / `IPV6_TCLASS` 控制消息的
  `sendmsg`），不带标记的用 `send_to`。
- 发往客户端：`Conn::send_segments_ecn(data, 0, ecn)` 经合并发送路径排队一个带码点的数据报；DTLS 记录也
  走这条路。
- 流客户端既不提供也不接收码点（15、16 节）。
- 不带标记的流量完全走原来的路径（只检查一次码点）。平台不报告 ECN 时 `rx_ecn` 为 0，一切照旧。

### 客户端

- `ClientConfig::dual_allocation`（false）在 Allocate 中加入 `ADDITIONAL-ADDRESS-FAMILY` IPv6，同时用
  0x8000 与 coturn 的 0x8032。`address_error` 两个码点都读取。
- `Client::relayed_addrs` 给出一个或两个地址，IPv4 在前；`relayed_addr` 仍是第一个。
  `relayed_addr_for(peer)` 选出对端所属地址族的那个。
- `Client::address_error` 给出 `ADDRESS-ERROR-CODE`（地址族、错误码、原因）。
- Refresh 不带地址族，因此两者都被刷新。
- 权限与通道仍按对端设立。服务器按地址族路由它们，缺少的地址族的对端得到 443
  （`ClientEvent::PeerFailed`）。
- `ClientEvent::Allocated` 不变（`relayed` 是第一个地址）。增加字段会破坏穷尽匹配。
- STUN 编解码：`attr::ADDRESS_ERROR_CODE`、`Message::address_error_code`、
  `MessageBuilder::address_error`。

### akio-webrtc：只改中继收集

- `RelayServer::dual_allocation(true)` 请求双分配。
- `Endpoint::gather_relay_via` 于是每个地址族加一个中继候选，并返回 IPv4 的那个。丢失的分配会连同两者重新
  建立。
- 来自服务器的数据归属于对端所属地址族的中继地址，ICE 因此看到正确的本地候选。
- 需要显式开启，普通的 `gather_relay` 仍只请求一个地址族：
  - 双分配要占用服务器的第二个端口；
  - IPv6 中继候选只对有 IPv6 候选的对端有用；
  - pion/turn 忽略该属性，无论如何只返回一个地址。
- akio-webrtc 的其他部分不变。另一个会话在做 WebRTC ECN，而 akio-webrtc 已经保留中继输入的码点
  （ADR-082）。

### 未完成

- ICMP 中继（`ICMP` 属性，11.5 节）。不变。
- DSCP 复制（14 节也推荐）。只经现有 API 复制两个 ECN 位；TOS 字节的高六位仍是 socket 自己的。
- 客户端 Refresh 中按地址族的 `REQUESTED-ADDRESS-FAMILY`（刷新或删除一个地址族）。服务器支持；客户端总是
  刷新两者。
- `Endpoint::gather_relay` 默认双分配（见上）。

## 影响

- 行为变化：配置了 `additional_relay_ip` 的服务器上，请求另一地址族的 `REQUESTED-ADDRESS-FAMILY` 现在成功，
  而不是 440。`relay_ip` 为 IPv6、`additional_relay_ip` 为 IPv4 时，不带该属性的 Allocate 现在得到 IPv4
  （RFC 8656）。没有 `additional_relay_ip` 时，除了双分配请求会得到 `ADDRESS-ERROR-CODE` 应答（以前该属性
  被忽略）之外，一切不变。
- ECN 验证（ADR-077 / ADR-082）现在经 UDP 与 DTLS 穿过 `akio-turn` 时可以成功。
- 公开 API：只有新增（`api/akio-turn.txt`、`api/akio-webrtc.txt`）。
- 性能：gpu51 上 UDP 中继与 main 的 A/B（`turn-relay-bench 8 6 4`，`quiet.sh` 下交替）：
  - 6 轮：中位数 29.75 万 vs 29.73 万数据报/秒；
  - 再 10 轮：平均 30.57 万 vs 30.46 万；
  - 各轮波动约 ±20%，因此：没有可测出的变化。
  - 每个数据报都带标记（由中继复制）：约为不带标记的 0.94 倍，在波动之内。
  - 表格见 docs/BENCHMARKS.zh-CN.md。

测试：

- 核心单元测试（`core/tests_dual.rs`）：
  - 双分配成功及其重传、按地址族的公开地址；
  - 所有 400 / 440 情形；纯 IPv4、纯 IPv6 与 IPv6 在前的服务器；
  - 带 440 与 508 的部分成功；缺少地址族时的 443；
  - 两个方向按地址族的权限与通道，在另一地址族中继上的对端被丢弃；
  - 只刷新一个地址族（另一个单独到期，它的通道消失，另一个的保留），之后的 443，先删一个地址族再删最后一个，
    刷新与删除全部；
  - 带双分配请求的 TCP 分配；
  - ChannelData、Send 与 Data 指示两个方向都复制码点，响应不带；
  - 按地址族预绑定。
- 客户端单元测试：双分配经 30 分钟的刷新、两个地址族的对端，关闭；带 440 的部分成功，IPv6 对端被拒绝。
- 真实 socket 上的 `tests/dual_ecn.rs`：127.0.0.1 与 ::1 中继，每个地址族两个方向都复制 ECT(1)、ECT(0)
  与 CE，不带标记的仍不带。一个故意丢弃码点的服务器会使它失败。
- akio-webrtc `tests/relay.rs`：IPv4 端点经双分配的 IPv6 中继候选到达纯 IPv6 端点。
- 平台：macOS，gpu51 epoll 与 io_uring。clippy 无警告。
- 互通（`tools/interop/webrtc/turn-dual.sh`，gpu51 上的 Docker，coturn 4.6 从 127.0.0.1 与 ::1 中继，
  pion/turn v5.1.3）：
  - coturn 的 `turnutils_uclient` 用双分配（`-Z`）与 IPv6 中继（`-x`），客户端互相发往对方的中继地址，
    对 akio-turn 与对 coturn：40 与 80 条消息，无丢失。
  - 请求双分配的 akio_turn 客户端：
    - 对 coturn：两个中继地址，每个地址族回显 20 个数据报；
    - 对 pion/turn：一个，因为它忽略该属性，也不发送错误码；
    - 对 akio-turn：两个。
  - ECN：akio-turn 在两个地址族上都复制客户端到对端的 ECT(0) 与对端到客户端的 ECT(1)。coturn 也复制。
    pion/turn 把两者都清除。
  - pion/turn 客户端用 `REQUESTED-ADDRESS-FAMILY` IPv4 与 IPv6 对 akio-turn 与 coturn：得到该地址族的中继，
    回显 20 个数据报。
- Fuzz：`turn_server` 现在用支持双分配的服务器，由选择字节决定 IPv6 对端与 ECN 码点，并断言中继的数据保留
  码点、从对端所属地址族的已打开中继发出，以及最后全部关闭。新种子：一次双分配会话。`turn_stream` 的
  客户端一侧请求双分配。在 gpu51 上每个目标运行 5 分钟（libFuzzer，按 cargo-fuzz 的方式构建）：`turn_server`
  1110 万次，`turn_stream` 1400 万次，`turn_tcp` 1020 万次，`turn_dtls` 730 万次（后两者也基于改动后的服务器），
  没有发现问题。
