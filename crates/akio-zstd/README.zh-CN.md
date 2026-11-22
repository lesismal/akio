# akio-zstd

[English](README.md)

[`akio`](https://github.com/lesismal/akio) 的 Zstandard（RFC 8878）实现：纯安全 Rust
（`#![forbid(unsafe_code)]`），没有任何依赖。它是 `akio-tls` 中 TLS 证书压缩（RFC 8879）的 `zstd`
算法，也是 `akio-http` 的 `zstd` 内容编码。这是内部 crate（见 docs/api-stability.zh-CN.md）：请通过
上述 crate 使用。

- `decompress(data, limit)`：一次性解压一个或多个首尾相接的帧（包括可跳过帧），输出至多 `limit`
  字节（超出则返回 `Error::TooLarge`，用于防御解压炸弹）。支持完整格式：raw、RLE 与压缩块；raw、
  RLE、Huffman（单流或四流，树描述可为直接表示或 FSE 压缩，码长至多 12 位）与 treeless 字面量；
  预定义、RLE、FSE 压缩与重复使用的序列表；重复偏移；校验 Frame_Content_Size 与 XXH64
  Content_Checksum。Frame_Content_Size 只作为提示：声明超过上限的帧会被立即拒绝，预留的内存至多为
  上限。Huffman 与 FSE 流通过 64 位容器反向读取，并以查表方式解码：四个字面量流交错同步解码（libzstd
  的快速循环：位在寄存器中左对齐，按标记位的位置补充；字面量段按 libzstd 的规则足够大时，改用每次查表
  给出一个或两个符号的双符号表，尚未结束的流继续一起解码），序列以 64 个为一批先解码再执行（附加位允许时
  每个序列只读一次位），所用的表按免边界检查查找的大小存放；字面量与匹配以 16 字节为块复制到提前一个块
  清零的窗口中（仍从不超过上限）。解码表与字面量缓冲区按线程在调用之间保留，如同 libzstd 复用的上下文
  （约 36 KB，另加至多 32 KiB 字面量）。
- `compress(level, data)`：输出一个带 Frame_Content_Size 与内容校验和的帧；输入不超过 8 MiB 时为
  单段（single segment），更大的输入使用 8 MiB 窗口（RFC 9659 为 HTTP 规定的上限）。级别沿用 zstd 的
  1..=22（`Level::FASTEST` 为 1，`DEFAULT` 为 3，`BEST` 为 22）。
- `Compressor` / `Decompressor`：流式。压缩器分片接收输入，每次写出一个块（128 KiB）；
  `Flush::Flush` 把已收到的全部内容写成完整的块，`Flush::Finish` 结束帧（若在写出任何内容之前全部输入
  已到达，帧与 `compress` 写出的相同）。流式帧不带内容大小，窗口按级别从 512 KiB（级别 1）到 8 MiB
  （级别 16 起），或由 `window_log(10..=23)` 指定；压缩器的缓冲区滑动，保留窗口，匹配表按窗口确定大小
  （级别 19..=22、8 MiB 窗口时为 16 MiB 哈希头与 64 MiB 树链接，与 libzstd 相同）。解压器接收任意大小
  分片的拼接帧与可跳过帧：至多收集一个块的输入（128 KiB，或一个头部），用一次性解码器的块解码逻辑解码到
  一个窗口中，持有帧窗口两倍的数据后滑动，并在大小上限下输出（`decompress_vec`）或输出到切片
  （`decompress`）；窗口大于 `max_window`（默认 8 MiB，即 RFC 9659 对 HTTP 的上限）的帧以
  `Error::WindowTooLarge` 拒绝。无论输入如何，内存都有界：约为两倍窗口加两个块。
- `Dictionary`：原始内容（任意字节，Dictionary_ID 为 0）或 `zstd --train` 写出的训练格式（魔数、
  Dictionary_ID、Huffman 与 FSE 表、重复偏移、内容；按 libzstd 的方式校验，`Error::BadDictionary`）。
  `compress_with_dictionary`、`decompress_with_dictionary`、`Compressor::with_dictionary` 与
  `Decompressor::with_dictionary` 使用它：帧在其窗口之内时匹配可以引用字典内容，训练字典的重复偏移作为
  帧的初始值，其码表可被最初的块复用（Treeless_Literals_Block 与 Repeat_Mode），帧中写明
  Dictionary_ID。指定了其他字典的帧被拒绝（`Error::WrongDictionary`）；未指定字典的帧使用所给的字典，
  与 libzstd 相同。
- `xxh64(data, seed)`：XXH64，其低 32 位即内容校验和。

```rust
use akio_zstd::{Error, Level, compress, decompress};

let data = b"the quick brown fox jumps over the lazy dog; ".repeat(100);
let packed = compress(Level::BEST, &data);
assert_eq!(decompress(&packed, data.len()).unwrap(), data);
assert_eq!(decompress(&packed, data.len() - 1), Err(Error::TooLarge));
```

**解码器一致性。** 解码器接受与拒绝的输入与 libzstd 一致：表描述读取器移植自 libzstd 的
`FSE_readNCount`（包括它在输入末尾附近的读取方式），Huffman 权重按相同的双状态终止规则解码，并按
`HUF_readStats` 的方式检查；字面量、序列与帧的检查遵循 `zstd_decompress.c` /
`zstd_decompress_block.c`（Block_Maximum_Size、四流至少 6 个字面量、只有在含序列的块之后才能重复使用
表、偏移为零或越过帧起点、位流必须恰好在最后一个序列后结束、最后一帧之后的多余字节）。与 libzstd 的
一次性 API 相同，接受至多 2³¹ · 15/8 字节的窗口（窗口就是输出本身，受上限约束），空输入或只含可跳过
帧的输入解码为空。以下差异是有意为之，且都更严格，差分模糊测试目标只容忍这些差异：

- 每个 Huffman 编码的字面量流必须恰好在其符号结束处结束（`Error::BadHuffmanStream`）；libzstd 的快速
  四流解码器不检查这一点（在 libzstd 中由内容校验和发现此类损坏）；
- 解码后大于 Block_Maximum_Size 的块会被拒绝（`Error::BadBlock`），与 libzstd 的流式解码器以及 1.5.7
  之后的一次性解码器一致；
- 不支持旧版（1.0 之前）帧（`Error::BadMagic`）。

未提供字典时，指定了字典的帧会被拒绝（`Error::DictionaryRequired`），与 libzstd 相同。流式解码器
持有的是帧的窗口而不是整个帧，因此回溯超过其所持数据（至少一个窗口）的匹配会被拒绝
（`Error::BadOffset`），与 libzstd 的流式解码器相同；一次性解码器允许匹配回溯到帧的开头。

**编码器。** LZ77，窗口与输入一样大（至多 8 MiB），采用 libzstd 的匹配查找方式：级别 1、2 为 `fast`
（一张以后续 6 字节为键的哈希表，每个位置一个候选，在没有匹配的数据中更快地向前跳），级别 3、4 为
`double_fast`（以后续 8 字节和 5 字节为键的两张表；长匹配优先，短匹配会与后移一个字节处的长匹配比较），
两者都是贪心匹配，先尝试后移一个字节处的第一个重复偏移，并在匹配之后直接接上第二个重复偏移的连续匹配；
级别 5..=15 先尝试三个重复偏移，再沿 4 字节哈希链搜索（从级别 5 的 8 个候选到级别 15 的 160 个候选，
达到 “足够长” 的长度即停止），级别 5 为惰性匹配，6..=15 为 lazy2（后移一或两个字节若有更好的匹配则采用），
与 zstd 一样以匹配长度减去偏移的编码代价来比较匹配。级别 16..=22 做最优解析，如同 libzstd 的
`btopt` / `btultra`：每个位置的候选匹配来自按 4 字节哈希划分的后缀二叉树（libzstd 的 `bt` 匹配查找：
插入一个位置时围绕它重新链接这棵树，访问 48 到 512 个节点，每个节点从它那一侧已共有的长度开始比较；只取
长度递增者，保留最长的 16 个；处于 “足够长” 匹配之内的位置不再搜索，长于 384 字节的匹配之后至多 192 个
位置不插入），然后在块内求最短路径，代价为字面量以及字面量长度、匹配长度与偏移码的位数（取自上一个块的
解析结果，第一个块则由块内字节与预定义分布估算；之后取自上一遍：级别 16 一遍，17、18 两遍，19 起三遍，
第一个块至少两遍），字面量长度码的代价
随字面量逐个计入，沿每条路径跟踪三个重复偏移（包括重复偏移处长度为 3 的匹配），长匹配整体采用。每块至多 128 KiB。字面量使用 Huffman 编码（普通 Huffman 码长，超过 11 位时改用 package-merge 限制在 11 位，少于
256 个字面量用单流，否则用四流；树描述在 FSE 压缩权重与每个权重 4 位之间取较小者），若 raw 或 RLE
更小则改用它们；若上一个块（或训练字典）的码能编码全部字面量且更省，则不带描述直接复用。三个序列字段
各自在 RLE 表、预定义表、FSE 压缩表（在每个有意义的精度对数下归一化）与上一个块的表（Repeat_Mode）中
选择估算位数最少者。不能变小的块按 raw 存储，只含同一字节的块写成 RLE 块。

测试：XXH64 已知答案（已与 `xxhash.h` 核对）；facebook/zstd 的官方向量
`tests/golden-decompression`（全部解码为与 libzstd 相同的输出）、`tests/golden-decompression-errors`
（全部被拒绝）与 `tests/golden-compression`（每个级别往返，并经 `zstd -d` 验证），连同其许可证复制在
`tests/data` 下；在文本、二进制、不可压缩、空、单字节、长周期、包含所有字节值以及大于一个块的数据上
逐级往返，并且每次都验证以精确大小为上限时成功、少一个字节时返回 `TooLarge`；安装了 `zstd(1)` 时双向
互通：级别 1..=19、`--ultra -22`、`--long`、`--fast`、小窗口（1 KiB 的块）、较小的目标块大小、
`--no-check`、`--no-content-size`、多种策略产生的帧，以及中间夹有可跳过帧的多个帧，都能由本 crate
解码，本 crate 每个级别的输出都能通过 `zstd -d` 与 `zstd -t`；在每个字节处截断以及在每个字节处翻转
比特（得到错误，或在有校验和时得到原数据；绝不 panic）；解压炸弹（10 000 个 RLE 块、声明 1 TB 内容的
帧）在上限之内被立即拒绝；10 万个空帧或空块以线性时间解码；逐一测试帧级错误。

流式与字典（`tests/stream.rs`）：多个级别、分片大小与刷新方式的流式帧都能由两个解码器解码，整体输入、
4 KiB 分片与逐字节输入均可；1 KiB 到 512 KiB 的窗口与滑动缓冲区；每次刷新后已有内容都可解码；单次调用内
的输出上限、切片输出、截断、错误保持、拼接帧与可跳过帧；训练字典 `tests/data/records.dict`（由
`zstd --train --dictID=1234567` 生成）与原始字典在多个级别上一次性与流式往返，并让小 JSON 记录的大小减半；
畸形字典；以及与 `zstd(1)`：本 crate 的流式帧与字典帧（训练与原始）可由 `zstd -d [-D]` 解码，它的帧
（从管道流式输入，不带内容大小）与字典帧可由本 crate 解码。

模糊测试目标 `zstd_decompress`（绝不 panic、上限精确、通过 `zstd` crate 与 libzstd 差分对比，只容忍
上述差异）、`zstd_roundtrip`（本 crate 的输出可由本 crate 与 libzstd 解码回输入）、`zstd_stream`（分片
输入的流式解码器与一次性解码器结果一致，带或不带训练字典；任意字节作为字典解析绝不 panic，能解析的字典
可往返一个样例）与 `zstd_stream_roundtrip`（流式压缩器的分片大小、刷新、窗口与字典取自输入：每次刷新后
均可解码，两个解码器与 libzstd 都得到原输入）。针对 libzstd 1.5.7
的基于变异的差分运行共测试 1000 万个输入，没有发现其他差异。

基准测试：`cargo run --release -p akio-zstd --example zstd-bench [FILE...]` 按级别（`BENCH_LEVELS=1,3,19`
可选择部分级别；默认 1、3、9、19、22）输出压缩率，并与 zlib 级别 9（akio-deflate）及 libzstd
（安装了 CLI 时用 `zstd -b`）对比，同时输出压缩与解压速度并与 libzstd 对比；语料为由
`fuzz/corpus/x509_parse` 中证书链构造的 TLS 1.3 Certificate 消息、生成的文本、JSON 与随机数据，以及
命令行给出的每个文件。

与 C 库在同一进程内对比（Silesia 语料与 HTTP 负载，见 docs/BENCHMARKS.zh-CN.md）：先用
`tools/codec-bench/corpus.sh` 构造语料，再运行
`cargo run --release --manifest-path tools/codec-bench/Cargo.toml zstd FILE...`。

局限：没有长距离匹配、多线程与字典训练；编码器的最优解析找不到 3 字节匹配（它的树按 4 字节哈希），
因此级别 19 在基准语料上比 libzstd 大 0.3–1.4%（docs/BENCHMARKS.zh-CN.md）。
