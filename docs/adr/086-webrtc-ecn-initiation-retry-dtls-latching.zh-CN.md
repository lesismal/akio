# ADR-086：RFC 6679 的 "ice" 与 "leap" ECN 启动方式、对端的 `ect=`、ECN 重试、锁定 RTCP 的 DTLS 以及 DTLS 客户端

[English](086-webrtc-ecn-initiation-retry-dtls-latching.md) | 简体中文

状态：已采纳（2026-11-22）

## 背景

ADR-082 留下了以下 WebRTC 事项：

- **启动方式。** RFC 6679 §7.2 定义了在一条路径上启动 ECN 的三种方式，只实现了 "rtp"：
  先标记四分之一的包，直到反馈确认。"ice"（一次带 ECN 标记的 STUN 检查）和 "leap"
  （一开始就全部标记）都没有实现。
- **`ect=`。** 对端偏好的码点被忽略，两边各自标记自己配置的码点。
- **失败的路径一直不再标记**，直到路径本身改变。
- **RTCP 自己的 DTLS**（分量 2，不复用 rtcp-mux）在密钥出现之前不会锁定。
- **DTLS 客户端角色。** 本端必须发起握手时（对端写了 `passive`），ClientHello 发往对端 SDP
  里的私网地址，什么也锁定不了。
- **DTLS 重新协商密钥**不可用。

约束与 ADR-082 相同：默认行为不变，默认的收发路径不增加工作。

## 决定

### 1. 启动方式（akio-ice `ecn.rs`；akio-webrtc `rtc/ecn.rs`、`rtc/ecn_fb.rs`）

- **SDP。**
  - 打开 ECN 标记、使用 ICE 且是完整代理时，各节提供
    `a=ecn-capable-rtp:ice,rtp mode=setread; ect=N`。没有 ICE 或者是 lite 代理时只提供 `rtp`。
    此时 `a=ice-options` 带上 `rtp+ecn`（§6.4）。
  - 新增的 `RtcConfig::set_ecn_initiation(EcnInitiation::LeapOfFaith)` 把 `leap` 放在最前。
    不设置时从不提供 `leap`。
  - 应答时按我们的偏好顺序，取 offer 列出的第一个方式：配置了 leap 时先 `leap`，然后 `ice`
    （只在能发检查时），然后 `rtp`，最后 `leap`。因此只提供 `leap` 的对端，无论怎样配置都会得到
    `leap`。
- **"rtp"** 就是 ADR-077 的试探，没有变化。
- **"leap"**（§7.2.3）：启动阶段从第一个 RTP 包起全部标记，并用与试探相同的方式判断：
  - 码点被清除或改写，路径失败；
  - 被标记的包持续丢失，路径也失败；
  - 收到十个带标记的包且没有丢失，路径可用。

  不用 RFC 6679 时（Chrome，只有 RFC 8888），`LeapOfFaith` 同样生效。
- **"ice"**（§7.2.2）：
  - ICE 选定路径对后，`IceAgent::check_ecn` 在该对上多发一个 Binding 请求。请求用该码点标记，
    带 V = 0 的 ECN-CHECK（0x802D）。
  - 响应方（`IceAgent::handle_receive_ecn`，传入数据报的码点）回答 V = 1 的 ECN-CHECK 和它读到的
    码点。经普通的 `handle_receive` 时忽略该属性，与不能读取 ECN 的代理一样。
  - 发送：共 5 次，间隔 500 ms，即 "并行模式" 的间隔 Ta x k、k = 10，因为期间媒体照常流动；RFC
    建议至少重传 4 次。最后一次之后 500 ms 放弃。
  - V = 0 的回答要求立即发下一次。
  - `IceEvent::EcnChecked { local, remote, ecn }` 报告对端看到的码点。没有回答、或回答不带该属性
    时为 `None`。
  - `IceAgent::poll_transmit_ecn` 返回数据报及其码点，只有这些检查带码点。akio-webrtc 通过它
    发送 ICE 的数据报。
  - 结果到来之前路径（`Phase::Verifying`）不标记任何包：
    - 结果是我们的码点或 CE：可用，每个包都标记；
    - 其他：失败。

    之后与其他方式一样，依据反馈做失败检测。
  - 无法发检查的地方（固定路径对、lite 代理），改用试探。

### 2. 对端的 `ect=`

- `ect=` 是接收方的偏好（§6.1）。缺省时为 "0"，并且 "是否遵从由发送方决定"。
- 对协商了 RFC 6679 的对端，路径标记第一个已协商的节所要求的码点：`ect=0` 标 ECT(0)，`ect=1`
  标 ECT(1)，`random` 保留我们自己的。
- 估计器对 CE 的响应跟随实际标记的码点（RFC 9331 §4.3）：ECT(1) 用可扩展响应，ECT(0) 用经典
  响应。重新协商改变码点时，重新启动。
- 我们自己应答中的 `ect=` 仍然表示我们配置的偏好。
- **后果：** 配置为 `EcnMarking::Ect1` 的一方，对不写 `ect=` 的 RFC 6679 对端会标记 ECT(0)。
  没有 RFC 6679 的对端（浏览器）不受影响。

### 3. 重试失败的路径（RFC 6679 §7.4.1，第一种做法）

- 失败的路径 10 s 后重新启动，之后 20、40……直到 300 s。重试用试探；用 "ice" 时则发一次新的
  STUN 检查。
- 进入全部标记后，等待时间回到 10 s。
- 同一路径上从全部标记回退三次（标记已确认，后来丢失或被清除）后不再尝试：§7.4.1 建议此时放弃。
- 新路径从头开始。
- 重试在要标记一个 RTP 包时检查，不增加定时器。

### 4. 锁定 RTCP 自己的 DTLS 握手（`rtc/latch.rs`）

- ADR-082 §4 的暂定握手现在按 ICE 分量分别存在。
- 分量 2（RTCP 在自己的端口上）以同样方式处理其本地地址上来自未知来源的 ClientHello：先做无状态
  的 cookie 交换，再把路径对暂时移到该来源。握手以描述中的指纹完成时锁定。
- 失败、关闭、或 4 s 内未完成，路径对移回。
- 分量 2 不必再等 SRTCP 密钥。

### 5. 作为 DTLS 客户端锁定

- **条件。** 没有 ICE、配置了锁定、DTLS-SRTP 且本端是客户端、该分量的握手未完成、尚未收到描述
  中地址发来的任何东西。
- **触发。** 该分量本地地址上来自未知来源的数据报：STUN 消息（RFC 6263 保活、Binding 请求），
  或在有密钥之前的 RTP。
- **做法。**
  - 该分量的路径对暂时移到这个来源。
  - 向它重新开始一次客户端握手，其服务端必须证明描述中的指纹。
  - 失败、关闭或 4 s 后路径对移回，握手再重新发往描述中的地址。
  - endpoint 现在也会把未知来源、且没有 ICE 代理认领的 STUN 交给正在锁定的 peer。
- **安全。**
  - 只有正确的证书才能锁定。
  - 每个分量同时只有一次尝试，所以伪造的触发每 4 s 最多让本端向伪造的地址发送握手的几次
    ClientHello 传输。
- **保活。** 位于 NAT 后的 DTLS 服务端在收到客户端消息之前，不会发出 NAT 允许通过的任何东西。
  所以新增的 `RtcConfig::set_plain_keepalive(every)` 在没有 ICE 时发送 RFC 6263 保活：在每个分量
  的路径上发 STUN Binding Indication（28 字节），路径一出现就发，之后每隔 `every` 发一次。它也让
  NAT 映射在静默期间保持打开。默认关闭。

### 6. DTLS 重新协商密钥：未做，以及原因

- **DTLS 1.2。** 给 DTLS-SRTP 换密钥需要一次新的握手，在 DTLS 1.2 里就是重协商。Chrome
  （BoringSSL）和 pion 都拒绝重协商，akio-dtls 也没有实现（它有过攻击的历史，RFC 5746）。
  没有可以互通的对端。
- **DTLS 1.3。** KeyUpdate 改变记录层密钥，但不改变从握手导出的 SRTP 密钥。
- **新的关联。** 标准的替代办法是用改变后的 `a=tls-id` 发出信号建立新关联（RFC 8842）。这同时
  会重启 SCTP（数据通道），而浏览器只在 ICE 重启时这样做。
- **需要程度。** SRTP 自身的上限（每个密钥 2^48 个包）使得一次会话内不需要换密钥。
- **保留的部分。** ADR-082 的 MKI 仍然按握手计数，将来的新关联可以借此区分。

### API

只有新增。

- akio-ice：`IceAgent::{check_ecn, ecn_checking, handle_receive_ecn, poll_transmit_ecn}`、
  `IceEvent::EcnChecked`、`ECN_CHECK_SENDS`、`ECN_CHECK_INTERVAL`、`ECN_CHECK_GIVE_UP`。
- akio-webrtc：`EcnInitiation`、`RtcConfig::{set_ecn_initiation, set_plain_keepalive}`。
- 统计项 `ecn_state` 还可能是 "verifying"。

### 顺带修复

没有 ICE 且没有 BUNDLE（每节一个传输）时，DTLS-SRTP 从不读取对端指纹，所以握手不会开始。现在
会读取。RTCP 在自己端口上的普通 DTLS 正是这种情形。

## 后果

- **默认行为**不变。
  - 打开 ECN 标记并使用 ICE 时，offer 写 `ice,rtp` 和 `a=ice-options:... rtp+ecn`。浏览器忽略
    两者：Chrome 157 下 `ecn.sh` 仍通过 RFC 8888 验证路径。
  - 有 RFC 6679 的对端，其 `ect=` 现在会被遵从。
- **测试**（模拟网络）：
  - "ice" 在标记任何 RTP 之前，用一次带标记的 STUN 检查验证路径；清除码点的路径失败，且不标记
    RTP。
  - "leap" 在 RFC 8888 下、在 ICE 上的 RFC 6679 下、以及不带 ICE 的 RFC 6679 下都标记每个包，
    在清除码点的路径上仍会失败。
  - 不带 ICE 的 "rtp"。
  - 对端的 `ect=0` 让 `Ect1` 的一方标记 ECT(0)，并使用经典响应。
  - 失败的路径在清除消失后重试并恢复（RFC 8888，带与不带 ICE 的 RFC 6679）。
  - RTCP 自己的握手在两种 offer 方向下都锁定，带 cookie 交换，并且 RTCP 在分量 2 上双向流动。
  - DTLS 客户端锁定到保活上，带与不带 rtcp-mux，没有保活时不锁定。
  - DTLS 客户端拒绝攻击者的服务端（外来证书），之后锁定到话机上。
  - 保活的时机。
  - 单元测试：ECN-CHECK 的布局、回显、重传和放弃；路径状态机（leap、verifying、退避、回退）；
    协商（方式的选择、`ect=`）。
- **模糊测试：** 见 CHANGELOG / DEV-PLAN 条目。`ice_stun` 让每个数据报都经过
  `handle_receive_ecn` 并运行检查，其种子包含 ECN-CHECK 请求和响应。`webrtc_sdp` 的种子覆盖
  `leap` / `ice` / `ect=random` / `setonly` 列表和 `setup:passive` 的 offer，以及一个带 leap 和保活的
  配置。
- **互通：** 见 CHANGELOG / DEV-PLAN 条目。
  - `latch.sh`：iptables NAT 后面，RTCP 自己的握手与客户端角色。
  - 新的 `ecn6679.sh`：两个 akio 端之间、经过真实 Linux NAT 的 rtp / leap / ice，以及一条先清除
    ECN、再被删除的路由器规则（失败、重试、恢复）。我们能运行的浏览器或 SIP 栈都没有实现 RFC 6679
    的 "ice" 或 "leap"，所以这些只在 akio 端之间运行。
- **性能：** gpu51 上与 main da0637aa 的同轮 `webrtc-bench` A/B：媒体 0.999 倍，数据通道 0.997 倍，
  区间重叠（docs/BENCHMARKS.zh-CN.md）。
- **未做：**
  - DTLS 换密钥（第 6 节）。
  - 在 akio-turn 的中继里复制码点：另一个会话在做。
