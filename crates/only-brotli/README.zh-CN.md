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
  增长但绝不超过上限（并提前至多 128 KiB 清零，以便匹配按 16 字节为块复制）；前缀码表的大小受格式
  约束（至多几 MB）。读到输入末尾之后得到的零位会被计数，并且每条命令至少检查一次，因此截断的输入
  代价不超过其长度加输出。解码使用 64 位位读取器（补充时不依剩余位数分支，每次补充解码三个字面量）
  和两级前缀码表（根表 8 位）；上下文映射只有一棵树的块类型，其字面量不计算上下文。
- `compress(level, data)`：0..=11 级，即 brotli 的质量刻度（`Level::FASTEST` = 1，
  `Level::DEFAULT` = 6，`Level::BEST` = 11）。LZ77 采用 Google 的匹配查找方式：0..=6 级每个哈希值
  一个桶，保存其最近的 1、2、2、4、4、16 或 32 个位置（对应 Google 的 `H2`..`H6`；以后续四字节为键，
  5、6 级为五字节），7..=11 级用哈希链；0..=3 级贪心，4..=9 级惰性匹配（Google 的反向引用评分，最多
  向前看四步），10 和 11 级在全部候选匹配上做最短路径解析，用上一遍的符号代价定价（10 级一遍，11 级
  两遍），长匹配整体采用；此时静态字典的词也是候选：词按其前四字节的小写形式建立索引，在每个位置对输入
  开头匹配的每个变换前缀之后查找，并按恒等、大写（首字母或全部，ASCII）与省略末尾的变换及其后缀核对，
  每个长度保留地址最小者（与解码器一致，字典引用不改变距离环）。10 级以下，连续 64 个字面量没有匹配后只查看每隔一个的位置，320 个之后每隔
  三个（Google 针对不可压缩数据的启发式）。距离环中的四个距离始终是候选（用短码代替额外位）。
  meta-block 为 1 MiB（10、11 级最多为窗口的两倍，按 256 KiB 的块解析，字面量或命令数达到其八分之一时提前
  结束，与 Google 相同；流式压缩时为 256 KiB），`NPOSTFIX` = `NDIRECT` = 0；从 5 级起
  字面量使用上下文映射：对每种上下文模式（5..=6 级为 UTF-8 与 signed，7 级起四种都试）的 64 个上下文，
  按其直方图的估计代价贪心聚类（字面量少于 32 个的上下文起始时归为一类；10 级以下 meta-block 需有
  4096 个字面量才做聚类），估计表明值得时保留映射。从 4 级起做块分割：字面量、插入-复制符号和距离各自
  分成块类型并写出块切换命令。4..=9 级对 64 KiB 及以上的 meta-block 像 Google 的贪心 `BlockSplitter`
  一样一遍完成（一个 512 或 1024 个符号的块，若与最近两个类型中任一个合并编码都要多花超过阈值的比特，
  就成为新类型），每个字面量块类型在值得的地方为上下文映射的各个聚类使用自己的码，其余地方使用所有类型
  共享的码；只有估计表明能省下 meta-block 至少 1% 时才保留这些类型（写块切换要花时间：JSON 与 HTML
  不分割，混合或二进制数据分割）。10、11 级对 8 KiB 及以上的 meta-block 像 Google 的
  `block_splitter` 一样分割：从样本得到初始直方图，做三轮（10 级）或十轮（11 级）带块切换代价的最便宜路径
  分配（每个符号分给一个直方图），再把各块聚类为至多 256 个类型；每个字面量块类型选用代价最小的上下文模式，
  所有字面量块类型的上下文（每个距离块类型 4 个距离上下文）用 Google 按直方图代价的聚类合成一个上下文映射。
  10、11 级分别用一个字面量码、上下文映射和块类型写出 meta-block，保留最小者。11 级第二遍解析时，
  每个字面量的代价取自第一遍字面量分割后其位置所在字面量块类型的直方图，使解析贴合实际编码所用的块。
  前缀码长度限制为 15 位，至多四个符号时用简单形式
  写出，码长序列采用 Google 的游程编码；上下文映射尝试 move-to-front 与每种游程设置，取最短者。
  压缩后比原字节更大的 meta-block 以未压缩形式存储。窗口取 2^16..2^22 中能容纳输入的最小值。

- `Compressor` / `Decompressor`：流式。压缩器分片接收输入，每次写出一个 meta-block；`Flush::Flush`
  结束当前 meta-block，并用一个空的元数据块填充到字节边界（同 Google 的 `BROTLI_OPERATION_FLUSH`），
  `Flush::Finish` 结束流（若在写出任何内容之前全部输入已到达，流与 `compress` 写出的相同）。流式输出的
  窗口为 2^22 字节（可用 `window_bits(10..=24)` 指定），压缩器的缓冲区滑动，保留窗口。它的匹配表从几 KB
  起步，随流增长（从缓冲区重新插入），最大为该级别对一个窗口大小输入所用的尺寸，因此建立一个流只需几微秒，
  始终很短的流也一直很小；前缀码的构建与写出时间主要与 meta-block 用到的符号数成正比，一次小事件的刷新写入
  约 2 us（ADR-074 的 2026-11-22 更新）。解压器接收任意
  大小分片的流，用一次性解码器的代码解码，在输入用尽处从最后一个完整单元继续：一条命令，或 meta-block
  头部的一部分（一个块类型描述、一个上下文映射项、一个前缀码）。用到了输入之外比特的单元会被撤销（输出、
  比特位置、距离环与块切换状态回到单元开始处），等有更多输入时重来，因此无论在何处切分输入（包括逐字节），
  代价都与整体输入相差无几。输出至多比交付提前解码 1 MiB，在大小上限下输出（`decompress_vec`）或输出到
  切片（`decompress`），窗口持有两倍流窗口的数据后滑动；`max_window_bits` 拒绝更大的窗口
  （`Error::WindowTooLarge`）。无论输入如何，内存都有界：至多两倍窗口、1 MiB 输出、meta-block 的前缀码
  以及一个单元的输入。
- `compress_with_dictionary` / `decompress_with_dictionary`（以及流式类型上的 `with_dictionary`）：
  原始（LZ77 前缀）字典，用法同 `brotli -D` 与 Google 的
  `BrotliDecoderAttachDictionary(BROTLI_SHARED_DICTIONARY_RAW, ...)`：刚超出窗口可达范围（输出比窗口
  短时即迄今的输出）的距离从字典复制，如同字典位于输出之前，复制不越出字典；静态字典的地址排在其后。
  输出在窗口之内时，编码器把字典中的位置当作匹配候选。
- `SharedDictionary`、`decompress_with_shared_dictionary`、`Decompressor::with_shared_dictionary`、
  `compress_with_shared_dictionary`：RFC 9841 共享字典，即 Google 的 `BROTLI_SHARED_DICTIONARY_SERIALIZED`
  （以 `BROTLI_EXPERIMENTAL` 构建）所接受的字典。`SharedDictionary::new` 解析序列化格式（LZ77 前缀、由 4 到
  31 字节的词组成的自定义词表、包含全部 23 种操作（含 `ShiftFirst` / `ShiftAll`）的自定义变换表、至多 64 个
  将二者配对的字典（任一半都可以是 brotli 自带的），以及从 64 个字面量上下文到首选字典的可选映射），格式错误
  一律以 `Error::BadDictionary` 拒绝；变换按 Google 代码中的布局（前缀、操作、后缀），而 RFC 9841 的文字把
  操作放在最后。解码器在最后两个输出字节的字面量上下文（按当前字面量块类型的上下文模式）对应的字典中解析
  静态引用，超出其末尾时按顺序落到其他字典，与 Google 的解码器一致。编码器只使用前缀，字典带自定义词时完全
  不使用静态字典词。

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
拒绝。流式与字典（`tests/stream.rs`）：0..=11 级、多种分片大小与刷新方式的流式输出都能被两个解码器
解码，整体输入、分片与逐字节输入均可；1 KiB 到 256 KiB 的窗口与滑动缓冲区；每次刷新后已有内容都可解码，0..=11 级下窗口滑动与否的小块刷新写入在每次刷新后都能被两个解码器和
`brotli -d` 解码；压缩器的表随流增长；
输出上限、切片输出、截断、尾随字节；流的每个截断与比特翻转，流式（3 字节分片）与一次性解码结论相同；
每个级别的原始字典，窗口之内与之外；以及与 `brotli(1)`：我们的流可由 `brotli -d` 解码，它在质量
0..=11、窗口 2^16 与 2^24 下的流可流式解码，字典流用 `-D` 双向互通。模糊测试目标
`brotli_decompress`（与 `brotli-decompressor` 差分：结论相同、输出相同）、`brotli_roundtrip`（我们的
输出能被两个解码器解码）、`brotli_stream`（分片输入的流式解码器与一次性解码器结果一致，带或不带原始
字典）与 `brotli_stream_roundtrip`（流式压缩器的分片大小、刷新、窗口与字典取自输入：每次刷新后均可
解码，两个解码器与 `brotli-decompressor` 都得到原输入）以及 `brotli_shared`（任意序列化字典都不会 panic；
随机字典配手工构造的引用流按模型解码，一次性与流式一致，并能经编码器往返）。共享字典（`src/shared.rs` 单元
测试、`tests/shared.rs`）：每种变换操作、1 到 4 字节标量的移位、各上下文模式下的上下文选择、跨字典回退、
格式错误的字典；libbrotli 编码器用四种字典生成的流；以及 `tools/interop/brotli-shared/run.sh`：它以
`BROTLI_EXPERIMENTAL` 构建 libbrotli，用其解码器核对 20,000 个随机字典与引用流（输出相同或双方都拒绝），
用我们的解码器核对其编码器在 alice29.txt 上的输出，并用其解码器核对我们的输出。

基准：`cargo run --release -p only-brotli --example brotli-bench [FILE...]` 在生成的文本、JSON、
随机数据以及给定的每个文件上，打印 0..=11 级（`BENCH_LEVELS=1,6,11` 选择部分级别）的大小、
压缩比以及压缩和解压吞吐量，并以 zlib 9 级的大小作为基线；安装了 `brotli(1)` 时还显示它在
同一质量下的大小，以及它解码我们的流所用的时间。`cargo run --release -p only-brotli --example stream-cost
[QUALITY [WINDOW_BITS]]` 测量流式压缩器的固定开销：一次 87 字节事件的刷新写入、新建一个流、一个 16 事件
的响应、流在 3 个和 30,000 个事件后占用的内存，以及以 16 KiB 刷新写入的 HTML。

与 C 库在同一进程内对比（Silesia 语料与 HTTP 负载，见 docs/BENCHMARKS.zh-CN.md）：先用
`tools/codec-bench/corpus.sh` 构造语料，再运行
`cargo run --release --manifest-path tools/codec-bench/Cargo.toml brotli FILE...`。

局限：编码器只在 10、11 级搜索静态字典且不搜索省略开头的变换，总是使用 `NPOSTFIX` = `NDIRECT` = 0，
不搜索共享字典的自定义词表；未实现 RFC 9841 的大窗口 brotli 与封装格式。11 级
输出在基准语料的 HTTP 负载上比 Google 的大 0.9–1.3%，在其 Silesia 部分小 4.5%（docs/BENCHMARKS.zh-CN.md，
“brotli 块分割”）。
前缀码按精确码长或按为游程编码平滑过的计数（zopfli 的 `OptimizeHuffmanForRle`）存储，取总代价较小者，
这对小输入很重要：在几 KB 的 DER 证书链上 11 级比 zlib 9 级小 4–5%，比 `brotli -q 11` 大 1–1.5%
（github.com 的证书链：1640，zlib 1719，`brotli` 1615；wikipedia.org 的：2454、2589、2430）。
