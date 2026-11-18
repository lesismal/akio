# only-brotli

[English](README.md)

[`only`](https://github.com/lesismal/only) 的 Brotli（RFC 7932）实现，纯安全 Rust
（`#![forbid(unsafe_code)]`），无依赖。它是 `only-http` 压缩中间件的 `br` 内容编码，也是
`only-tls` 中 TLS 证书压缩（RFC 8879）的 brotli 算法。这是内部 crate（docs/api-stability.md）：
请通过上述 crate 使用。

- `decompress(data, limit)`：把一个完整的 brotli 流一次性解压为至多 `limit` 字节。实现了完整
  格式：窗口 2^10..2^24（拒绝非标准的 large-window 扩展）；空、元数据（跳过）与未压缩
  meta-block；简单与复杂前缀码；字面量、命令和距离三类的块类型与块计数；四种字面量上下文
  模式；带游程与逆 move-to-front 的上下文映射；`NPOSTFIX` / `NDIRECT` 距离码；四项距离环及其
  16 个短码；静态字典（122,784 字节，Google v1.1.0 的 `dictionary.bin`，已与 RFC 7932 附录 A
  核对）及全部 121 种变换。它与 `brotli-decompressor`（Google 解码器的 Rust 移植）接受和拒绝
  相同的流（必须为零的填充位、多余的长度半字节、保留位、过满或不完整的前缀码、简单码中重复
  的符号、越过末尾的上下文映射游程与重复、无效距离和字典引用）；流结束后还有数据视为错误
  （`TrailingData`）。在 `brotli-decompressor` 5 与 Google C 解码器 v1.1.0 不一致之处，本 crate
  遵循 C 解码器：命令产生的字节多于头部声明长度的 meta-block 在任何位置都被拒绝
  （`BadBlockLength`），而不仅是最后一个。恶意输入无法让它 panic，也无法让它分配超过 `limit` 的内存：每次插入、
  复制和字典词在写入前都对照 meta-block 长度与上限检查；输出向量（同时也是窗口）按几何级数
  增长但绝不超过上限；前缀码表的大小受格式约束（至多几 MB）。读到输入末尾之后得到的零位会被
  计数，并且每个字面量、每条命令至少检查一次，因此截断的输入代价不超过其长度加输出。解码使用
  64 位位读取器和两级前缀码表（根表 8 位）。
- `compress(level, data)`：0..=11 级，即 brotli 的质量刻度（`Level::FASTEST` = 1，
  `Level::DEFAULT` = 6，`Level::BEST` = 11）。在后续四字节的哈希链上做 LZ77：0..=3 级贪心，
  4..=9 级惰性匹配（Google 的反向引用评分，最多向前看四步），10 和 11 级在全部候选匹配上做
  最短路径解析，用上一遍的符号代价定价（10 级一遍，11 级两遍），长匹配整体采用。距离环中的
  四个距离始终是候选（用短码代替额外位）。meta-block 为 1 MiB（10、11 级为 256 KiB），每类
  一个块类型，`NPOSTFIX` = `NDIRECT` = 0；从 5 级起字面量使用上下文映射：对每种上下文模式
  （5..=6 级为 UTF-8 与 signed，7 级起四种都试）的 64 个上下文，按其直方图的估计代价贪心聚类，
  且只有当映射使 meta-block 更小时才保留。前缀码长度限制为 15 位，至多四个符号时用简单形式
  写出，码长序列采用 Google 的游程编码；上下文映射尝试 move-to-front 与每种游程设置，取最短者。
  压缩后比原字节更大的 meta-block 以未压缩形式存储。窗口取 2^16..2^22 中能容纳输入的最小值。

```rust
use only_brotli::{Level, compress, decompress};

let data = b"the quick brown fox jumps over the lazy dog; ".repeat(100);
let packed = compress(Level::DEFAULT, &data);
assert_eq!(decompress(&packed, data.len()).unwrap(), data);
```

测试：Google 的测试向量（brotli v1.1.0 `tests/testdata` 的一个子集提交在 `tests/data` 下，
解码后按长度和 FNV-1a 哈希比较；`BROTLI_TESTDATA=<目录>` 运行全部向量）；安装了 `brotli(1)`
时双向互通（它在质量 0..=11、窗口 2^10..2^24 下的输出以及数 MiB 的距离都能被我们解码；我们
在每个级别的输出都能被 `brotli -d` 解码）；在文本、JSON、二进制、随机、低熵、长周期和混合
数据、空输入及长度 0..300 上的每级往返；11 级下 DER 证书链不大于 zlib 9 级（only-deflate）；
流的每个前缀、每个单比特翻转和随机垃圾（报错，绝不 panic）；精确上限；手工构造的流，覆盖
每种窗口大小、元数据、未压缩 meta-block、错误的头部和填充、字典词与变换、无效字典引用和
距离；以及解压炸弹（817 字节，展开后为 1 GiB）在不分配超过上限内存的情况下以 `TooLarge`
拒绝。模糊测试目标 `brotli_decompress`（与 `brotli-decompressor` 差分：结论相同、输出相同）
和 `brotli_roundtrip`（我们的输出能被两个解码器解码）。

基准：`cargo run --release -p only-brotli --example brotli-bench [FILE...]` 在生成的文本、JSON、
随机数据以及给定的每个文件上，打印 0..=11 级（`BENCH_LEVELS=1,6,11` 选择部分级别）的大小、
压缩比以及压缩和解压吞吐量，并以 zlib 9 级的大小作为基线；安装了 `brotli(1)` 时还显示它在
同一质量下的大小，以及它解码我们的流所用的时间。

局限：解压是一次性的（整个流输入、整个输出返回，这正是证书压缩和缓冲的 HTTP body 所需）；
没有流式解码器或编码器。编码器每类只用一个块类型（无块分割），不使用静态字典引用，也不支持
自定义字典，因此在文本上它的输出比 Google 同质量的输出大几个百分点。前缀码按精确码长或按为游程
编码平滑过的计数（zopfli 的 `OptimizeHuffmanForRle`）存储，取总代价较小者，这对小输入很重要：在几 KB 的 DER
证书链上 11 级比 zlib 9 级小 1–3%（单个小叶证书约大 1%），比 `brotli -q 11` 大 2–5%（375 字节的叶证书：353 字节，zlib 348，
`brotli` 352；github.com 的证书链：1693、1719、1615；wikipedia.org 的：2515、2589、2430）。
