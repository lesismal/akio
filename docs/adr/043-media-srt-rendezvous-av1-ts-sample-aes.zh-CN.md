# ADR-043：SRT rendezvous、MPEG-TS 中的 AV1、录制为 MPEG-TS、HLS SAMPLE-AES

[English](043-media-srt-rendezvous-av1-ts-sample-aes.md) | 简体中文

状态：已接受（2026-11-19）

## 背景

`akio-media` 列为不支持的有：HLS SAMPLE-AES / CBCS、SRT rendezvous、MPEG-TS 中的 VP8 / VP9 / AV1、录制为
MPEG-TS、转码。

- **SRT rendezvous** 是两个位于 NAT 之后的 SRT 端点会合的方式：双方都不监听，都从已知端口向对方发送握手。
  其握手（draft-sharabayko-srt-01 4.3.2）不同于 caller / listener：双方都“挥手”，由 cookie 竞争选出发起方。
- **MPEG-TS 中的 AV1** 由开放媒体联盟规定（"Carriage of AV1 in MPEG-2 TS"）：私有数据（流类型 0x06），带
  `AV01` 注册描述符与 AV1 视频描述符，OBU 采用起始码格式。目前没有已发布的 ffmpeg 能解封装（相关补丁仍在评审），
  GStreamer 使用自己的临时映射（`AV1G`，裸 OBU）。**VP8 与 VP9 根本没有 MPEG-TS 映射**：任何地方都没有定义
  流类型、注册标识或描述符，也没有解封装器读取，因此无从实现。
- **录制**（ADR-034）只写 fMP4 与 FLV；许多归档与广播工具期望的是 MPEG-TS。
- **SAMPLE-AES**（ADR-034 未做）在容器内部加密样本，某些分发链路与 FairPlay 类流程需要它。ADR-034 的理由：
  H.264 的 CBCS 必须让每个 slice 头保持明文，这需要解析 slice 头（依赖 SPS 与 PPS、参考列表修改、加权预测与
  参考帧标记），而 MPEG-TS 中的 SAMPLE-AES 需要按编码改写基本流。这里重新评估：Apple 的 MPEG-TS 格式不解析
  slice 头（固定 32 字节明文），且只涵盖 H.264 与 AAC（以及 hub 不承载的 AC-3）；H.264 slice 头解析器约 200 行，
  可以用 ffmpeg 的 `trace_headers` 核对；ffmpeg 能解密两种格式，因此两者都可以端到端测试。H.265 的 `cbcs` 需要
  H.265 slice segment 头（短期参考图像集等），不在本次范围。

转码仍不在范围内（它需要编解码器，而不是容器）。

## 决策

全部为新增。

1. **SRT rendezvous**（`srt::Conn::rendezvous(cfg, remote, now)`、`Conn::is_rendezvous`；在用
   `Engine::bind_udp` 绑定的 UDP socket 上运行的 `srt::rendezvous`、`push_rendezvous`、
   `pull_rendezvous(engine, local, remote, ..)`，忽略来自其它地址的数据报）。仅 HSv5：
   - 双方每 250 ms 发送 `WAVEAHAND`（版本 5，扩展字段 0，加密字段为密钥长度），直到收到对端。cookie 竞争与
     libsrt 相同（两个 cookie 的 32 位差值；较大者为发起方；平局则换一个 cookie）。
   - **发起方**发送带 HSREQ 的 `CONCLUSION`（有密码时还带它生成的密钥的 KMREQ），并以此回应每个不含 HSRSP
     的握手；收到应答方的 HSRSP（和 KMRSP）后即连接并发送 `AGREEMENT`，应答方重发 HSRSP 时再次发送。
   - **应答方**以空的 `CONCLUSION` 回应挥手；收到 HSREQ 后用自己的密码解开发起方的 KMREQ（不一致则双向拒绝，
     `BAD_SECRET` / `UNSECURE`），采用延迟（仍取较大者），回复 HSRSP（和 KMRSP），在收到 `AGREEMENT`
     时连接，或在其丢失时于发起方的下一个包到达时连接。
   - 双方各自从自己的初始序号发送，从对端的初始序号接收。不发送 stream ID（libsrt 在 rendezvous 中不用）。
     握手等待 `handshake_timeout` 的十倍，与 libsrt 相同。拒绝 HSv4 rendezvous（SRT 1.3 之前）。
2. **MPEG-TS 中的 AV1**，封装与解封装：流类型 0x06，PES stream ID 0xbd，先是 `AV01` 注册描述符，再是 AV1
   视频描述符（tag 0x80：marker、版本 1、`av1C` 的 profile / level / tier / 色彩字段，`hdr_wcg_idc` 3，无初始
   呈现延迟）。每个 PES 一个时间单元并置 `data_alignment_indicator`；先是时间分隔符，然后每个 OBU（带规范推荐的
   `obu_size`）置于 `00 00 01` 之后并加入防竞争字节；缺少序列头的关键帧前补上配置中的序列头。解封装器按
   `obu_size` 切分每个 OBU（无大小的 OBU 去掉末尾的零字节），丢弃时间分隔符，从第一个关键帧的序列头得到配置，
   并且也读取 GStreamer 的 `AV1G`（裸 OBU）。VP8 / VP9 不进入 MPEG-TS（写入文档）。
3. **录制为 MPEG-TS**：`RecordFormat::MpegTs`（`.ts`；H.264、H.265、AV1、AAC、Opus、MP3），使用现有的
   `mpegts::Muxer`；每个文件以 PAT 与 PMT 开头，并在每个视频关键帧前（以及至少每秒）重复，因此文件可从任一关键帧播放。
4. **HLS SAMPLE-AES**：`EncryptionMethod::{Aes128（默认）, SampleAes}`、`HlsEncryption::method`。密钥、
   提供者、轮换与密钥 URI 均不变；`#EXT-X-KEY:METHOD=SAMPLE-AES`。只承载 H.264 与 AAC 轨道（其它轨道不进入分段，
   而不是以明文发出）；分片与初始化分段无需额外处理。
   - **MPEG-TS**（Apple，MPEG-2 Stream Encryption Format for HLS）：流类型 0xdb / 0xcf，
     `private_data_indicator` `zavc` / `aacd`，带音频设置信息（`zaac`、`AudioSpecificConfig`）的 `apad`
     注册描述符。长于 48 字节的编码 slice（NAL 类型 1、5）：去除防竞争字节，32 字节明文，之后只要剩余多于 16
     字节，每十个 16 字节块加密一个，每个 NAL 单元都从 IV 开始 CBC，再重新加入防竞争字节。AAC：ADTS 头与其后
     16 字节明文，其后完整的块加密，每帧从 IV 开始 CBC。**IV 为每个密钥一个随机 IV，写为 `IV` 属性**，而不是
     媒体序号：ffmpeg 用当前分段的 IV 解密它跨分段边界预读的包（以及结束时冲刷出的包），每分段不同的 IV 会损坏
     那些帧；Apple 自己的工具也写 `IV` 属性。
   - **fMP4：`cbcs`**（ISO/IEC 23001-7 10.4）：`encv` / `enca` 样本条目带 `sinf`（`frma`、`schm` `cbcs`
     1.0、`tenc` 版本 1：受保护，视频 1:9 模式、音频无模式，`Per_Sample_IV_Size` 0，全零 KID，每个封装器一个随机
     16 字节常量 IV）。视频样本：每个编码 slice 一个子样本，其明文部分为 4 字节长度、NAL 头与 slice 头（按
     H.264 7.3.3 依据配置记录与带内的 SPS / PPS 解析：帧号、场标志、POC、冗余图像计数、参考索引覆盖、参考列表
     修改、加权预测表、参考帧标记、CABAC 初始化、QP 增量、去块；向上取整到整字节，计入防竞争字节），slice 数据从
     常量 IV 起按 1:9 模式加密；其它 NAL 单元明文（slice 头无法解析的 slice，例如带 slice group，也保持明文）。
     每个分片带 `senc`（子样本标志）与 `saiz` / `saio`（某个样本超过 42 个子样本时 `saiz` 无法表示其大小，
     只写 `senc`）。音频样本：所有完整的块，不写 `senc`。
   - `sps_size` 背后的 H.264 SPS 解析器现在也返回 slice 所依赖的字段；slice 头解析器在测试样本的每个 slice 上
     都与 ffmpeg 的 `trace_headers` 一致。

## 影响

- 位于 NAT 之后的 SRT 端点可以会合；已与 libsrt 1.5.4 测试（Docker 中 Debian `srt-tools` 的
  `srt-live-transmit`，`tests/srt_rendezvous.rs`）：akio 拉取 srt-live-transmit 从 ffmpeg 转发的流，并推送一路
  流由它写成文件，ffprobe / ffmpeg 解码，明文与加密都覆盖，两个 akio engine 也能互相会合；单元测试覆盖两种
  cookie 顺序、丢失的 AGREEMENT、丢失的挥手、不一致的密码与超时。ffmpeg 的 `mode=rendezvous` 绑定到 URL 中的
  地址并连接同一地址，无法与其它主机或端口上的对端会合，因此未使用。
- AV1 可经 SRT、HLS MPEG-TS 与 MPEG-TS 录制发出，也可经 SRT 接收。按 AOM 规范核对，并通过封装器与解封装器的
  往返验证（AV1 + Opus 样本，带与不带带内序列头，以及 GStreamer 的映射），并手工验证一次：ffmpeg 9 把该流作为
  数据流解封装，其 PES 负载经另一个独立（Python）实现的起始码格式读回后，用 dav1d 解码出的帧与源完全相同（全部 50
  帧的 MD5）。目前还没有已发布的播放器能解封装 MPEG-TS 中的 AV1。
- 录制可以是 MPEG-TS；ffprobe / ffmpeg 能解码每个文件（按时长切分、按大小切分并轮换、H.265 重新推流）。
- SAMPLE-AES 在 ffmpeg 中逐帧正确播放（`tests/hls_encryption.rs` 将每个解码帧的 MD5 与源比较，MPEG-TS 与
  fMP4，普通与 LL-HLS）；在密钥轮换下，测试中独立实现的解密器解开 TS 分段，每个 slice 与 AAC 帧都与源相同，
  `cbcs` 单元测试解密两把密钥下的分片。ffmpeg 自身无法跟随密钥变化（它对预读的数据使用同一把密钥，fMP4 则一直
  使用打开时的密钥），因此其播放检查在不轮换的情况下进行。没有密钥直接读取的分段解码不出源的画面。
- 开销：不加密与 AES-128 的流在 TS 与 fMP4 封装器中每个包多一次 `Option` 检查（SAMPLE-AES / `cbcs` 的工作
  放在不内联的函数中，HLS 正在写入的分段也没有变大：SAMPLE-AES 把密钥放在 AES-128 存放密文状态的位置）。gpu51 上的
  `bench_segmenting`（静默、绑核、7 轮交替、取中位数，head / main）：TS 1.027、TS-LL 0.999、fMP4 1.017、
  fMP4-LL 0.984，AES-128 各项 0.996 到 1.005；退休指令数 +0.7%（TS 与 fMP4），其余为代码布局的影响。
  SAMPLE-AES 在 MPEG-TS 中每包约 470 ns（AES-128：500），fMP4 的 `cbcs` 约 300 ns（每 160 字节 slice 数据一个
  AES 块，外加 slice 头解析）。
- 未做：H.265（其 slice segment 头）、AC-3 / E-AC-3、Opus 等编码的 SAMPLE-AES；`EXT-X-SESSION-KEY`；
  FairPlay 密钥系统（identity 以外的 `KEYFORMAT`）；SRT HSv4 rendezvous；MPEG-TS 中的 VP8 / VP9（无规范）；转码。
