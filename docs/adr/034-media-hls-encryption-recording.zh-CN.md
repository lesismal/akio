# ADR-034：流媒体 Hub 的 HLS 加密与录制

[English](034-media-hls-encryption-recording.md) | 简体中文

状态：已接受（2026-11-18）

## 背景

`only-media` 列出的两项缺口让它进不了常见的部署。HLS 只能明文提供：付费或私有的流至少需要
`EXT-X-KEY:METHOD=AES-128`，这是所有 HLS 播放器（Safari、hls.js、ExoPlayer、ffmpeg）在没有 DRM
时都支持的唯一加密方式，由应用把密钥发给它选定的观众，并定期轮换。另外，Hub 中的流无法写到
磁盘，而这是每个流媒体服务器都会被要求的功能（归档、合规、直播转点播）。`only-crypto` 有 AES
的 CTR 和 GCM 模式，但没有 CBC。

两者都涉及数据面：HLS 分片在推流方的 I/O 线程上切割，录制则是磁盘 I/O，而 docs/rules.md 第 1
节要求磁盘 I/O 不能在 I/O 线程上进行。

## 决定

所有改动都是新增。

1. **`only-crypto` 的 AES-CBC。** `Aes::encrypt_cbc` / `decrypt_cbc`（原地处理整数个分组，链值
   传入并传出，因此一条消息可以分段处理；解密一次处理四个分组）以及
   `Aes::encrypt_cbc_padded` / `decrypt_cbc_padded`（PKCS #7；填充以常数时间检查，文档提醒了
   填充预言攻击）。用 SP 800-38A 向量（AES-128 与 AES-256，硬件与可移植路径，整段与分段）测试，
   PKCS #7 输出与 OpenSSL 对照。
2. **HLS AES-128。** `HlsConfig::encryption: Option<HlsEncryption>`（`keys: Arc<dyn
   KeyProvider>`，每 `rotate_every` 个分片轮换，0 表示不轮换）。每个分片和每个 LL-HLS part 都
   整体用 AES-128-CBC 与 PKCS #7 加密，MPEG-TS 与 fMP4 相同：
   - **IV**：媒体序列号，即 RFC 8216 5.2 在 `EXT-X-KEY` 没有 `IV` 属性时的定义。part 是独立的
     资源，因此用其所属分片的 IV 单独加密（hls.js 与 Safari 就是这样解密 part 的）。从不写
     `IV` 属性：否则一个标签就会让直到下一个标签的所有分片使用同一个 IV。
   - **播放列表**：在密钥 `n` 的第一条媒体行（part 或分片）之前写
     `#EXT-X-KEY:METHOD=AES-128,URI="key-<n>.key"`，之后只在密钥变化时再写。fMP4 的初始化分片
     保持明文：`EXT-X-KEY` 作用于其后的 `EXT-X-MAP`，而加密的 map 必须带 `IV` 属性，所以出现在
     密钥之后的 map 前面先写 `#EXT-X-KEY:METHOD=NONE`，并在下一个分片之前重新写出密钥。与
     不连续点或新 map 一样，需要新密钥标签的分片在第一个 part 产出之前不写预加载提示。
   - **密钥**：`KeyProvider::key(path, n) -> HlsKey`（16 字节和可选的 URI）在某个分片开始且需要
     密钥 `n` 时（第一个分片，之后每 `rotate_every` 个分片）于推流方线程上调用，不得阻塞，并且每次都必须返回新的密钥：重启的 muxer 会让密钥序号和媒体序列号（即
     IV）都从 0 重新开始。
     `KeyProvider::authorize(path, n, &Context)` 决定每个 `/<path>/key-<n>.key` 请求（拒绝时
     403；默认允许），在请求方的 I/O 线程上运行。密钥以 `application/octet-stream` 和
     `Cache-Control: private, no-store` 返回，并且只在仍有保留的分片使用它时提供；
     `HlsKey::with_uri` 可以让播放器改去应用自己的密钥服务器取。`RandomKeys` 用由操作系统播种的
     ChaCha20 生成器产生密钥。`MediaHttp` 把 `.key` 交给 `Hls`。
   - **推流方线程上的开销**：正在写的分片的密文随分片增长按 64 KiB 一段生成，因此分片结束时的
     开销不超过一个 part；part 在切出时加密。正在写的分片的密文计入 `max_bytes`。未加密的流每个
     包只多一次 `None` 检查。
3. **录制**（`only_media::record`）。`Recorder::new(hub, RecordConfig)` /
   `with_hooks(.., impl RecordHooks)`、`start(path)`、`stop(path)`、`stop_all`、`active`、
   `dropped`、`queued_bytes`。`RecordConfig`：`dir`、`format`（默认 `RecordFormat::Fmp4`，或
   `Flv`）、`segment_duration`、`segment_bytes`、`max_files`（每次录制的轮换）、
   `max_queued_bytes`（32 MiB）、`wait`（10 秒：录制可以在推流方出现之前开始，并跨越重新推流；
   `None` 要求流已在推）、`flv`（编码选项）。
   - sink 在推流方线程上用现有的复用器（`fmp4::Muxer`、`flv::Encoder`）封装，把字节按最多
     256 KiB 一块（以及在视频关键帧处）交给录制器的**写线程**；写线程拥有所有文件：创建（含目录）、
     经 256 KiB 缓冲写入、关闭时 `sync_all`、轮换时删除，并运行所有钩子。docs/rules.md 1.2 更倾向
     使用引擎的逻辑池，但 Hub 的 sink 没有连接可以借以到达它（`Conn::spawn_blocking`），规则 1.3
     允许专用线程；每个录制器一个线程，使一个文件的写入保持有序而无需加锁。
   - 文件从视频关键帧开始（纯音频流从任意包开始），每个文件的时间戳从 0 开始；在超过
     `segment_duration` 或 `segment_bytes` 之后的第一个关键帧处切换文件（没有关键帧时在
     `segment_bytes` 的四倍处切换），每次重新推流或轨道变化时也切换。fMP4 的 fragment 在关键帧处
     切割，且最长一秒。
   - **背压**：排队字节超过 `max_queued_bytes` 时，关闭当前文件并丢弃数据包（计入 `dropped`），
     直到队列降到一半且来了关键帧，开始下一个文件：慢磁盘的代价是文件之间的空档，绝不会产生损坏
     的文件或无界的内存，也绝不会卡住推流方。
   - **钩子**（`RecordHooks`，在写线程上运行，因此可以阻塞）：`file_name(stream, index,
     started, ext)`（相对 `dir`；含 `..` 或绝对路径的名字回退到默认的
     `<stream>-<unix 毫秒>-<index>.<ext>`；在推流方线程上调用）、`on_start(&RecordFile)`、文件
     同步之后的 `on_stop(&RecordFile, Result<(), &io::Error>)`、轮换时的 `on_remove(&Path)`。
     `RecordFile` 包含流、路径、序号、开始时间、媒体时长和大小。

## 后果

- 加密的流无需 DRM 就能在所有 HLS 播放器中播放；密钥可以轮换、按请求授权，或由应用提供。
  测试：单元测试（分片与 part 的密文对照未加密的流、轮换、map 与不连续点前后的密钥标签、提供者的
  URI、增量加密对照一次性加密），以及 `tests/hls_encryption.rs`（MPEG-TS 与 fMP4，普通与
  LL-HLS：没有提供者要求的请求头时拒绝密钥请求，每个分片和 part 用返回的密钥解密，ffmpeg 用
  `-headers` 解码在线的加密播放列表，并解码每个解密后的分片）。
- 录制在有界队列下写出有效的文件，从不在 I/O 线程上碰磁盘。测试（`tests/record.rs`）：按时长和
  大小切换、带 `on_remove` 的轮换、换成 H.265 的重新推流、被卡住的写线程（丢包、队列有界、文件
  依旧完整）、钩子命名；ffprobe / ffmpeg 能解码每个文件，文件以 0 时刻的关键帧开头，时长与
  `on_stop` 报告的一致。
- 未完成：`SAMPLE-AES` 与 CBCS（fMP4 的 `encv`/`enca` + `sinf` + `senc`）。H.264 和 H.265 的
  CBCS 要求每个 slice header 保持明文，这需要逐个 NAL 单元解析 slice header（依赖 PPS，含参考
  列表与加权预测语法），而 MPEG-TS 中的 SAMPLE-AES 需要按编码重写基本流；两者都无法干净地放进这次
  改动，而 AES-128 已经到处都能播放。同样未完成：多码率播放列表中的 `EXT-X-SESSION-KEY`、来自
  播放列表查询串的密钥令牌（播放器不会把它带到密钥 URI：提供者应检查请求头或 cookie，或自己指定
  URI）、录制为 MPEG-TS、带总时长的 `moov`（文件是分片式的；播放器读取各个 fragment）。
- 每个录制器一个写线程：一个录制器把许多流写到同一块慢磁盘时，它们分享该磁盘的速度；第二个录制器
  会有第二个线程。
