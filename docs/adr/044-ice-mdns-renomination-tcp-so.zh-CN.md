# ADR-044：mDNS ICE 候选、重新提名与激进提名、同时打开的 ICE-TCP

[English](044-ice-mdns-renomination-tcp-so.md) | 简体中文

状态：已采纳（2026-11-19）

## 背景

浏览器会隐藏自己的主机地址：Chrome（以及 Firefox、Safari）把每个主机候选写成随机的
`<uuid>.local` 名字（draft-ietf-mmusic-mdns-ice-candidates），并在本地网络上应答针对它的
组播 DNS 查询（RFC 6762）。`only-ice` 把这类候选行解析为 `ParseError::Mdns`，`only-webrtc`
直接跳过，于是 `Endpoint` 只能借助浏览器自己的连通性检查产生的对端反射候选来连到同一局域网上的
浏览器：浏览器无法先连到我们时不行，双方都隐藏地址时更不行。`Endpoint` 也无法隐藏自己的主机地址。

控制方只做常规提名（RFC 8445 §8.1.1），一旦提名就不再看其他候选对，因此后来出现的更好候选对
（晚到的 trickle 候选、IPv6 路径）永远用不上；为 RFC 5245 构建的对端有时期望激进提名；而受控方
总是切到对端最后提名的候选对，这在对端激进提名（多次提名，最好的那个胜出）和重新提名
（draft-thatcher-ice-renomination：NOMINATION 值最大者胜出）时都是错的。同时打开的 ICE-TCP
（RFC 6544 `tcptype so`）候选可以解析，但无法创建本地候选。

多组件（RTP 与 RTCP 使用不同候选）不在范围内：所有 WebRTC 对端都使用 rtcp-mux 与 BUNDLE，本栈
自己的 SDP offer 和 answer 也是如此。

## 决定

1. **mDNS 编解码**（`only_ice::mdns`，sans-io）：`Message::parse`（问题，以及回答段和附加段中的
   `A` / `AAAA` 记录；压缩指针只允许向前跳回、每个名字最多 16 次，名字转为小写，最多 32 个问题、
   64 条记录，其他记录类型跳过，opcode 或 rcode 非 0 的消息拒绝）、`Message::query(name, qtype,
   unicast)`（每条消息一个问题：Chromium 的应答器会忽略含多个问题的消息，我们最初的双问题查询
   正是因此得不到应答）、`Message::response(id, questions, records)`、`random_name()`（与浏览器
   相同的 v4 UUID `.local` 名字）、`is_mdns_name`、`valid_name`。模糊测试目标 `ice_mdns`。
2. **带名字的候选**：`Candidate::parse_resolved(line, resolve)` 对格式正确、地址为名字的行
   （mDNS 名字会转为小写，或其他 FQDN）调用一次 `resolve`，采用其返回的 IP（返回 `None` 则仍是
   `ParseError::Mdns` / `Fqdn`），名字保存为 `Candidate::hostname()`；`Candidate::with_hostname(name)`
   让 SDP 写名字而非 IP，代理仍使用地址；`Candidate::with_related(addr)` 设置或隐藏（`0.0.0.0:0`）
   相关地址。`Candidate::parse` 即不带解析器的 `parse_resolved`。
3. **解析器与应答器**（`Endpoint::resolve_mdns(&engine, timeout)`）：一个由引擎 I/O 线程服务、
   从不阻塞的套接字：与系统应答器共享的 mDNS 端口（`Engine::bind_udp_multicast`：`0.0.0.0:5353`，
   `SO_REUSEADDR` / `SO_REUSEPORT`，加入 `224.0.0.251`），绑定不了时改用临时端口发送传统单播的
   一次性查询（RFC 6762 §6.7）。描述中的或经 `Peer::add_remote_candidate` trickle 来的远端 `.local`
   候选由对端排队后解析：立即发送 `A` 和 `AAAA` 查询，1 秒、2 秒后再发，之后每 2 秒一次直到超时；
   所有应答（无论是否请求过）按 TTL 缓存（最多 2 分钟、256 个名字：浏览器会在其描述到达前不久
   通告自己的名字，此后同一记录每秒最多应答一次，RFC 6762 §6），只接受来自 5353 端口的应答。每个
   等待的对端按名字的每个地址得到一个候选，除非其远端 ufrag 在此期间变了（ICE 重启）。上限：同时
   解析 64 个名字，每个名字 16 个对端，每个对端 32 行待解析。
4. **隐藏我方主机地址**（`Endpoint::conceal_host_candidates()`，需先在共享端口上 `resolve_mdns`）：
   新对端把每个主机候选（UDP 与 TCP）以随机名字发出（每个地址一个名字），其他候选的相关地址写为
   `0.0.0.0:0`；套接字应答对这些名字的 `A` / `AAAA` / `ANY` 查询（TTL 120 秒，cache-flush，组播；
   所有问题都带 QU 位时单播；传统单播查询原样带回 id 与问题，TTL 10 秒，无 cache-flush）。
5. **提名**：`IceConfig::aggressive_nomination`（控制方：每个检查都带 USE-CANDIDATE；第一个成功的
   候选对立即选中，之后成功的更好候选对会替换它；选中后对更好候选对的检查继续进行）与
   `IceConfig::renomination` 加 `IceAgent::set_remote_renomination`（双方都支持 draft-thatcher
   重新提名：控制方在提名后继续检查更好的候选对，更好的有效候选对会以更大的 NOMINATION 值（属性
   0xC001）再次提名：没有更好的候选对待检时立即进行，否则在它生效后等 `nomination_delay`）。受控方
   现在会在多个提名中选择：带 NOMINATION 时取最大值，不带时只有优先级更高的提名候选对才替换已选中的
   （lite 代理：取最后一次提名，除非其 NOMINATION 值不更大）。常规提名不变，仍为默认。`only-webrtc`
   以 `RtcConfig::enable_ice_renomination`（offer 中写 `a=ice-options:trickle renomination`，读取
   远端的 `ice-options`）和 `RtcConfig::enable_ice_aggressive_nomination` 提供它们。
6. **同时打开的 ICE-TCP**（`Endpoint::listen_tcp_so(&engine, addr)`）：一个 `tcptype so` 主机
   候选，其端口在监听（`SO_REUSEPORT`），发往远端 `so` 候选的检查也从这个端口拨出
   （`Engine::dial_from`）：无论哪边的 SYN 先到，结果都是一条连接（双方 connect 交叉即 TCP 同时
   打开；否则监听端接受对方的连接，我方的 connect 随后以 `EADDRNOTAVAIL` 失败，其排队的数据在被接受
   的连接交给引擎后经它发出，2 秒内有效）。被接受的连接与被动候选一样，由第一个检查识别归属。在
   only-ice 中，本地主动候选和 `so` 候选本来就能发送检查；README 中相反的说法已更正。
7. **引擎原语**（`only`）：`Engine::bind_udp_multicast(group, acceptor)` 与
   `Engine::dial_from(local, addr, acceptor, on_error)`，基于 `only_sys::connect_nonblocking_from`
   （以 `SO_REUSEADDR` / `SO_REUSEPORT` 绑定后非阻塞 connect：两个 `unsafe` 块，即 `bind` 与
   `connect` 调用，与已有的写法和注释一致）以及新的后端钩子 `Group::dial_stream`（epoll 与
   io_uring：connect 进行中的流走拨号路径）。

## 影响

- 公共 API：only-ice（内部层级）的 `mdns` 模块、`Candidate::{parse_resolved, with_hostname,
  hostname, with_related}`、`IceConfig::{aggressive_nomination, renomination}`、
  `IceAgent::set_remote_renomination`；only-webrtc 的 `Endpoint::{resolve_mdns,
  conceal_host_candidates, listen_tcp_so}`、`RtcConfig::{enable_ice_renomination,
  enable_ice_aggressive_nomination}`；`only` 的 `Engine::{bind_udp_multicast, dial_from}`；
  only-sys 的 `connect_nonblocking_from`；only-core（隐藏）的 `Group::dial_stream`。全部为新增；
  不调用它们时 SDP 与行为不变，唯一例外是受控方会忽略后来在更低优先级候选对上的 USE-CANDIDATE
  （RFC 5245 激进提名语义；常规提名下每代只有一次提名）。端点解析名字时，以 mDNS 行调用
  `Peer::add_remote_candidate` 返回 `Ok`，否则仍返回原来的错误。only-webrtc 依赖 only-sys（`so`
  监听），`only` 改为以普通依赖使用 only-sys。
- 测试：编解码（往返、压缩、指针环、截断、计数、opcode）；带名字的候选；模拟网络中提名后 trickle
  出更好候选对时，常规提名（保持不变）、激进提名与重新提名（双方都迁移，含 10% 丢包，仅重新提名时
  带 NOMINATION），激进提名最终落在最佳候选对，受控方遵循最大 NOMINATION 值而忽略旧值；两个都隐藏
  地址的端点经本机 mDNS 互相解析（offer 中的候选与 trickle 的候选；超时设为 0 时失败，说明连通靠的
  正是解析）；只有 `so` 候选的端点三轮；引擎的 `dial_from`（同一端口两条连接）与
  `bind_udp_multicast`（同一组播组两个绑定）。macOS 与 gpu51（epoll 与 io_uring）。
- 互通（`tools/interop/webrtc/browser.sh`，无头 Chrome 157）：隐藏自身地址的 `Endpoint` 向开启
  mDNS 隐藏（默认）的第二个 Chrome 发起 offer：Chrome 解析我们的名字（我方应答器应答其查询），我们
  解析 Chrome 的名字（其应答器在一毫秒内应答我们的单问题查询；修复前只有它主动发出的通告能用），
  Chrome 选中主机对主机，回显 100 条消息，共三轮；启用激进提名的 `Endpoint` 向 Chrome 发起 offer
  （数据通道回显）。pion/webrtc v4（`run.sh`）：启用激进提名的 `Endpoint`，以及在 offer 中提供重新
  提名的 `Endpoint`（pion 不通告它，因此运行常规提名），数据通道回显正常；`run.sh` 其余部分照常通过。
  浏览器和 pion 都没有 `so` 候选，也都不通告重新提名，所以这两项只在我方代理与端点之间测试。
- 模糊测试：`ice_mdns`（消息以及带名字的候选行，种子来自编解码器和一个仿浏览器的压缩应答），
  `ice_stun` 现在也驱动启用激进提名与重新提名的代理。在 gpu51 上各运行 11 分钟：`ice_mdns` 2720 万次、
  `ice_stun` 470 万次，代码中没有发现问题；最初几次运行停在测试框架一个过严的检查上（从端口不是 9 的
  行读入的主动 TCP 候选，写回时端口按 RFC 6544 为 9），已放宽，并把这些输入留作种子。
- 未做：多组件（WebRTC 中 rtcp-mux 是通行做法）；候选收集（STUN / TURN 客户端仍由调用方负责）；
  IPv6 组播上的 mDNS（`ff02::fb`；名字仍可解析为 IPv6 地址）以及对我方名字的探测 / 通告（它们是随机
  UUID，预计不会冲突）；通过 DNS 解析 FQDN 候选；远端不通告时的重新提名（此时应使用 ICE 重启）。

注（2026-11-22）：IPv6 组播上的 mDNS 已完成。ADR-054（2026-11-20）加入了 `ff02::fb` 套接字（按接口加入
组播组、在查询所来的链路上应答 AAAA、记住远端链路本地地址的作用域 ID）；ADR-078 以跳数限制 255 发送
（RFC 6762 §11），在纯 IPv6 链路上也能隐藏地址，并与 Chrome 157、avahi 0.8 和 mDNSResponder 互通验证
（`tools/interop/webrtc/mdns6.sh`、`browser.sh`）。对我方名字的探测 / 通告仍未做。
