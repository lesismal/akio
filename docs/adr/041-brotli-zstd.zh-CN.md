# ADR-041：自研 brotli 与 Zstandard，用于证书压缩和 HTTP

[English](041-brotli-zstd.md) | 简体中文

状态：已采纳（2026-11-19）

## 背景

`only-tls` 的证书压缩（RFC 8879）只有 zlib（经由 `only-deflate`），因为没有自研的 brotli 或
zstd，而工作区不引入第三方库依赖。浏览器和 CDN 更偏好另外两种：Chrome 只提供 brotli，Firefox
提供 zlib、brotli 和 zstd，Cloudflare 一类的服务器发送 brotli。只提供 zlib 的客户端从只支持
brotli 的服务器那里收到的是未压缩的证书链；只支持 zlib 的服务器发给 Chrome 的证书链也不压缩。
HTTP 也一样：`only-http` 的压缩中间件只回应 `gzip` / `deflate`，静态文件服务 `.br` 和 `.gz`
副本，但没有 `.zst`。

## 决定

1. **两个新的内部 crate**，组织方式同 `only-deflate`（纯安全 Rust、无依赖、
   `#![forbid(unsafe_code)]`、供 `fuzz/` 使用的 `fuzzing` feature、`examples/bench.rs`、在缺少
   命令行工具时跳过的 CLI 互通测试），属于 docs/api-stability.md 的“内部”一级：
   - **`only-brotli`**（RFC 7932）：`decompress(data, limit)`（完整格式：窗口 2^10..2^24、未压缩
     与元数据 meta-block、简单和复杂前缀码、块切换、四种上下文模式与上下文映射、
     NPOSTFIX/NDIRECT 距离、静态字典及其 121 种变换）和 `compress(Level, data)`（基于哈希链的
     LZ77、每个 meta-block 一套 Huffman 码，更小时用未压缩 meta-block）；`Level` 采用 brotli 的
     质量刻度 0..=11。
   - **`only-zstd`**（RFC 8878）：`decompress(data, limit)`（拼接帧与可跳过帧、raw / RLE /
     压缩块、raw / RLE / Huffman / treeless 字面量（1 或 4 路流）、predefined / RLE / FSE /
     repeat 序列表、重复偏移、校验 XXH64 内容校验和与内容大小）和 `compress(Level, data)`（单帧，
     带内容大小与校验和；基于哈希链的 LZ77、Huffman 字面量、FSE 或预定义序列表，更小时用
     raw / RLE 块）；`Level` 采用 zstd 的刻度 1..=22。
   - 只有一次性 API：输出本身就是窗口，因此内存受 `limit` 约束（不会按输入声明的、超过 limit
     的大小分配），工作量与输入加输出成线性；解压炸弹在 `limit` 处以 `Error::TooLarge` 停止。
     字典（zstd 的 `Dictionary_ID`、brotli 的共享字典）和流式接口未实现：工作区目前没有地方需要。
2. **`only-tls`** 提供并接受 brotli、zstd 和 zlib（在 `compress_certificate` 扩展中按此顺序）。
   服务器用客户端提供且自己开启的每种算法压缩证书链，每个证书每种算法只压缩一次（缓存，同以前的
   zlib），发送最小的那个；都不更小时发送普通 Certificate。客户端对自己的证书按
   CertificateRequest 中的算法做同样的事。新增公共 API：`CertCompression { Zlib, Brotli, Zstd }`
   （`#[non_exhaustive]`，带 `id()`），以及两个 builder 上的
   `certificate_compression_algorithms(&[CertCompression])`（`certificate_compression(true)` 即三种
   全开；默认值不变：服务器开、客户端关）。收到的证书链仍最多解压到 128 KiB，且必须正好是声明的
   长度；未提供的算法是 `illegal_parameter`。
3. **`only-http`**，新增：`Compress::brotli` 和 `Compress::zstd`（`Option` 级别，默认 `None`）
   让压缩中间件对接受它们的客户端回应 `br` 或 `zstd`，顺序为 br、zstd、gzip、deflate；两者都为
   `None` 时行为与以前相同。`Files` 也服务 `file.zst` 副本（`Content-Encoding: zstd`），优先级在
   `.br` 与 `.gz` 之间。

## 后果

- 开启压缩的客户端（`certificate_compression(true)`）能从只支持 brotli 或 zstd 的服务器收到压缩
  证书链；服务器在每个客户端允许的范围内节省最多字节。每个证书每种算法的第一次握手付出一次压缩
  开销。
- 测试：brotli `tests/testdata` 的全部 44 个流（提交了 23 个）；zstd 的 golden-decompression（4 个）、
  golden-decompression-errors（3 个，均被拒绝）和 golden-compression 文件，以及 1000 个 `decodecorpus` 帧；
  `brotli` 与 `zstd` 命令行双向互通（各级别、窗口大小、小块、无校验和或内容大小、拼接帧与可跳过帧）；
  往返、每种截断与位翻转、上限与解压炸弹（817 字节、可展开到 1 GiB 的 brotli 流在上限处停止，分配不超过
  上限）。only-tls 中：每种算法单独与同时开启、选出最小者、没有共同算法、每个字节与长度上的畸形消息；
  only-http 中：对 Chrome 与 Firefox 的 `Accept-Encoding` 选择的编码、`q=0`、`.zst` 副本。
- 互通（在 `tools/interop/tls/certcomp.Dockerfile` 中运行 `tools/interop/tls/run.sh`，OpenSSL 3.5.4 以
  brotli、zstd、zlib 构建）：服务器与客户端证书分别以每种算法双向压缩，以及 OpenSSL 客户端同时提供三种：
  gpu51（x86-64）上 151 个用例全部通过。
- 模糊测试：`brotli_decompress` 与 `zstd_decompress` 是差分的（Google 解码器即关闭大窗口扩展的
  `brotli-decompressor`；不含旧格式帧的 libzstd 1.5.7），只容忍我们更严格之处：命令超出声明长度的
  meta-block（C 解码器同样拒绝）、未恰好在符号结束处结束的 Huffman 字面量流、超过 Block_Maximum_Size
  的块。在 gpu51 上各运行 961 秒，无失败：分别 0.97M、6.6M 个输入；`brotli_roundtrip` 38k（最后一次编码器修改后又 36k），
  `zstd_roundtrip` 2.3M。
- 性能（Apple M 系列，仅供参考，不作门槛）：解码速度在文本上是 `brotli` 命令行的 0.55–0.75 倍（JSON 上
  更快），libzstd 的 0.35–0.5 倍；2.7–4 KB 的证书链解码耗时 2.5–7 µs（zstd）、7–10 µs（zlib）、16–25 µs
  （brotli）。以最高级别压缩一次耗时 0.1 ms（zstd）到 0.4–3 ms（brotli）。几 KB 证书链上的压缩率：brotli
  11 级比 zlib 9 级小 1–3%（比 `brotli -q 11` 大 2–5%），zstd 22 级与 zlib 9 级相差 1% 以内（比 libzstd
  -19 大 1.5%）；单个 375 字节的叶证书压缩为 353 字节（brotli）、357（zstd）、348（zlib）。
- 多了两个需要维护的 crate。编码器追求正确性，以及在证书链上不差于 zlib 最高级别的压缩率，而不是
  参考编码器的压缩率（没有上下文建模搜索，没有最优解析）：它们每个证书只用一次，HTTP 响应体只有
  在应用开启时才用。
