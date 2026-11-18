# SRT

`only_media::srt` 实现 live 模式的 SRT（Secure Reliable Transport，draft-sharabayko-srt-01）：
在 UDP 上传 MPEG-TS，丢包在固定延迟内靠重传修复，ffmpeg、OBS 和硬件编码器都这样推流。
`SrtServer` 位于媒体 [hub](media.md) 之前，接收推流、播放流；`dial`、`push`、`pull` 是主叫（caller）一侧。

与 ffmpeg 的 libsrt 互通已测试（`crates/only-media/tests/srt_ffmpeg.rs`，在 Linux Docker 里用 Debian
的 ffmpeg 运行；ffmpeg 不带 SRT 时（如 Homebrew 版）测试自动跳过）：ffmpeg 推流进来、ffprobe / ffmpeg
播放出去，带或不带密码；以及 only 向 `mode=listener` 的 ffmpeg 推流和从它拉流。rendezvous 与 libsrt 1.5.4
的 `srt-live-transmit` 做了测试（`tests/srt_rendezvous.rs`，Docker 中 Debian 的 `srt-tools`：
`SRT_LIVE_TRANSMIT="docker run --rm -i --network host <image> srt-live-transmit"`）：only 拉取它从 ffmpeg
转发的流，并推送一路 hub 流由它写出给 ffprobe 检查，明文与加密、cookie 竞争的两种角色都覆盖。（ffmpeg 自身的
`mode=rendezvous` 绑定到 URL 中的地址并连接同一地址，无法与别处的对端会合。）

## 服务端

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media-srt.rs:server}}
```

- 服务端是一个 **UDP 监听器** 的 acceptor：每个对端地址有自己的 handler；同一地址的 caller 重启
  （换了新的 socket ID）会替换旧会话。
- **Stream ID** 指明流：普通写法（`live/s`、`live/s?token=x`，表示播放）或访问控制语法
  （`#!::r=live/s,m=publish,u=alice`）。`m=publish` 推流，`m=request`（默认）播放，`bidirectional` 被拒绝。
  普通 stream ID 里的查询串会作为 `PeerInfo::query` 交给 hub 的 `on_publish` / `on_subscribe` 钩子。
- `SrtConfig::on_connect` 能看到请求（地址、stream ID、延迟、是否加密）和解析后的 `StreamId`，
  可以用任意 `RejectReason` 拒绝（`FORBIDDEN` = 1403 等），caller 在握手中收到拒绝码。
- `SrtConfig::max_conns`（1024；0 表示不限）限制连接数：超出后 caller 以 `OVERLOAD`（1402）被拒绝。
- **推流者** 在握手期间预留路径（`Hub::reserve`），所以同一路径的第二个推流者在握手时就被拒绝
  （`CONFLICT`，1409）。它的 MPEG-TS 经解复用（`only_media::mpegts::demux`），节目的轨道
  （H.264、H.265、AAC、Opus、MP3）都已知后流才上线。
- **播放者** 订阅 hub，收到复用成 MPEG-TS 的流，每个 SRT 包 7 个 TS 包，每个关键帧前重发 PAT/PMT，
  重新推流时时间戳继续递增；默认从 GOP 缓存开始（`play_gop_cache`）。对端确认太少
  （`max_send_backlog`，2 MiB）时丢包，视频丢到下一个关键帧（`hub::Dropper`）。没有设置 `play_wait`
  时，播放未上线的流会被拒绝（`NOT_FOUND`，1404）；设置后播放者等待推流者。
- **加密**：设置 `passphrase` 后每个 caller 都必须用同一密码加密（AES-CTR，密钥 128/192/256 位由 caller
  的 `pbkeylen` 决定）；密码错误以 `BAD_SECRET` 拒绝，不加密的 caller 以 `UNSECURE` 拒绝。

## 主叫（caller）

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media-srt.rs:publish}}
```

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media-srt.rs:player}}
```

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media-srt.rs:play}}
```

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media-srt.rs:relay}}
```

- `srt::dial(&engine, addr, Config, handler)` 打开一个原始 caller 会话（engine 需要 `udp_client_threads`）；
  socket 打开后即返回，握手在后台进行（`SrtSession::is_connected`）。`SrtSession::send` 接受最长 1456
  字节的负载（MPEG-TS 用 1316），缓冲满时返回 `BufferFull` 而不阻塞。`SrtHandler` 按序、在投递时间收到负载，
  最后以原因调用 `on_close`（`Rejected(reason)`、`PeerClosed`、`PeerIdle`、`HandshakeTimeout` 等）。
- `srt::push(&engine, addr, Config, &hub, path)` 把 hub 中的流发给监听方（stream ID 带 `m=publish` 的 SRT
  服务器，或 `ffmpeg -i 'srt://:port?mode=listener'`）；`srt::pull` 从监听方播放并发布到 hub 路径，
  该路径会立即被预留。
- `srt::rendezvous(&engine, local, remote, Config, handler)`、`srt::push_rendezvous` 与
  `srt::pull_rendezvous` 经 rendezvous 完成同样的事：双方几乎同时互相连接（例如穿过各自打开的 NAT），从绑定在
  `local` 的 UDP socket 连向对端 `remote`。cookie 竞争决定发起方（initiator），它发送 HSREQ，有密码时（双方需
  相同）也由它生成密钥；应答方（responder）回复 HSRSP，收到发起方的 AGREEMENT（丢失时则是其下一个包）后连接。
  不发送 stream ID。握手等待 `handshake_timeout` 的十倍，与 libsrt 等待 rendezvous 对端的时间一致。

  ```rust,ignore
  // 本端 0.0.0.0:5000，对端 198.51.100.7:5000（通常两端端口相同）。
  let s = srt::pull_rendezvous(&engine, "0.0.0.0:5000".parse()?, "198.51.100.7:5000".parse()?,
                               Config::default().passphrase("shared secret"), &hub, "live/peer")?;
  ```
- `Config`：`latency`（双方取较大者，默认 120 ms）、`passphrase` 和 `pbkeylen`、`stream_id`、
  `flow_window` / `send_buffer_packets`（各 8192 包）、`handshake_timeout`（3 秒）、`peer_idle_timeout`（5 秒）。

## 不含 I/O 的协议核心

`srt::Conn` 是以状态机形式实现的完整协议：喂入数据报（`handle`）和时间（在 `next_timeout` 调用
`handle_timeout`），取出 `take_output` 和 `poll_event`。`srt::Listener` 用 SYN cookie 无状态地应答
induction，并把接受的 conclusion 变成已连接的 `Conn`。上面的服务端和 caller 驱动的就是它们，
单元测试也在模拟的丢包链路上运行它们。它们实现了：

- HSv5 握手，含 HSREQ/HSRSP（TSBPD、过晚丢弃、周期 NAK、重传标志）、KMREQ/KMRSP 和 stream ID 扩展，
  双向拒绝码；
- 每 10 ms 完整 ACK、每 64 包轻量 ACK、ACKACK 与 RTT 估计；出现空洞立即 NAK，未修复的丢失每
  `(RTT + 4 * RTTVar) / 2` 周期 NAK；受发送缓冲和对端流量窗口限制的重传；发送方放弃的包发 DROPREQ；
- 基于时间戳的投递（TSBPD），时间基准跟随所见最小延迟和漂移的发送端时钟；后续包到期时仍缺失的包作为过晚丢弃；
- keepalive、SHUTDOWN、对端空闲超时；安装对端发来的密钥更新（KMREQ 控制包）。

未实现：文件模式及其拥塞控制、AES-GCM、包过滤（FEC）、socket 组（bonding）、SRT 1.3 之前的 HSv4 握手
（主叫与 rendezvous），以及主动发起密钥更新（一个连接沿用其密钥，约 2^31 个包）。
