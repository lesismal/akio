# only-zstd

[English](README.md)

[`only`](https://github.com/lesismal/only) 的 Zstandard（RFC 8878）实现：纯安全 Rust
（`#![forbid(unsafe_code)]`），没有任何依赖。它是 `only-tls` 中 TLS 证书压缩（RFC 8879）的 `zstd`
算法，也是 `only-http` 的 `zstd` 内容编码。这是内部 crate（见 docs/api-stability.zh-CN.md）：请通过
上述 crate 使用。

- `decompress(data, limit)`：一次性解压一个或多个首尾相接的帧（包括可跳过帧），输出至多 `limit`
  字节（超出则返回 `Error::TooLarge`，用于防御解压炸弹）。支持完整格式：raw、RLE 与压缩块；raw、
  RLE、Huffman（单流或四流，树描述可为直接表示或 FSE 压缩，码长至多 12 位）与 treeless 字面量；
  预定义、RLE、FSE 压缩与重复使用的序列表；重复偏移；校验 Frame_Content_Size 与 XXH64
  Content_Checksum。Frame_Content_Size 只作为提示：声明超过上限的帧会被立即拒绝，预留的内存至多为
  上限。Huffman 与 FSE 流通过 64 位容器反向读取，并以查表方式解码：四个字面量流交错同步解码（libzstd
  的快速循环：位在寄存器中左对齐，按标记位的位置补充），序列以 64 个为一批先解码再执行（附加位允许时
  每个序列只读一次位），所用的表按免边界检查查找的大小存放；字面量与匹配以 16 字节为块复制到提前一个块
  清零的窗口中（仍从不超过上限）。解码表与字面量缓冲区按线程在调用之间保留，如同 libzstd 复用的上下文
  （约 20 KB，另加至多 32 KiB 字面量）。
- `compress(level, data)`：输出一个带 Frame_Content_Size 与内容校验和的帧；输入不超过 8 MiB 时为
  单段（single segment），更大的输入使用 8 MiB 窗口（RFC 9659 为 HTTP 规定的上限）。级别沿用 zstd 的
  1..=22（`Level::FASTEST` 为 1，`DEFAULT` 为 3，`BEST` 为 22）。
- `xxh64(data, seed)`：XXH64，其低 32 位即内容校验和。

```rust
use only_zstd::{Error, Level, compress, decompress};

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

指定了字典的帧会被拒绝（`Error::DictionaryRequired`），与没有字典的 libzstd 相同。

**编码器。** LZ77，窗口与输入一样大（至多 8 MiB），采用 libzstd 的匹配查找方式：级别 1、2 为 `fast`
（一张以后续 6 字节为键的哈希表，每个位置一个候选，在没有匹配的数据中更快地向前跳），级别 3、4 为
`double_fast`（以后续 8 字节和 5 字节为键的两张表；长匹配优先，短匹配会与后移一个字节处的长匹配比较），
两者都是贪心匹配，先尝试后移一个字节处的第一个重复偏移，并在匹配之后直接接上第二个重复偏移的连续匹配；
级别 5..=22 先尝试三个重复偏移，再沿 4 字节哈希链搜索（从级别 5 的 8 个候选到级别 22 的 768 个候选，
达到 “足够长” 的长度即停止），级别 5 为惰性匹配，6..=22 为 lazy2（后移一或两个字节若有更好的匹配则采用），
与 zstd 一样以匹配长度减去偏移的编码代价来比较匹配。每块至多 128 KiB。字面量使用 Huffman 编码（普通 Huffman 码长，超过 11 位时改用 package-merge 限制在 11 位，少于
256 个字面量用单流，否则用四流；树描述在 FSE 压缩权重与每个权重 4 位之间取较小者），若 raw 或 RLE
更小则改用它们。三个序列字段各自在 RLE 表、预定义表与 FSE 压缩表（在每个有意义的精度对数下归一化）
中选择估算位数最少者。不能变小的块按 raw 存储，只含同一字节的块写成 RLE 块。

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

模糊测试目标 `zstd_decompress`（绝不 panic、上限精确、通过 `zstd` crate 与 libzstd 差分对比，只容忍
上述差异）与 `zstd_roundtrip`（本 crate 的输出可由本 crate 与 libzstd 解码回输入）。针对 libzstd 1.5.7
的基于变异的差分运行共测试 1000 万个输入，没有发现其他差异。

基准测试：`cargo run --release -p only-zstd --example zstd-bench [FILE...]` 按级别（`BENCH_LEVELS=1,3,19`
可选择部分级别；默认 1、3、9、19、22）输出压缩率，并与 zlib 级别 9（only-deflate）及 libzstd
（安装了 CLI 时用 `zstd -b`）对比，同时输出压缩与解压速度并与 libzstd 对比；语料为由
`fuzz/corpus/x509_parse` 中证书链构造的 TLS 1.3 Certificate 消息、生成的文本、JSON 与随机数据，以及
命令行给出的每个文件。

与 C 库在同一进程内对比（Silesia 语料与 HTTP 负载，见 docs/BENCHMARKS.zh-CN.md）：先用
`tools/codec-bench/corpus.sh` 构造语料，再运行
`cargo run --release --manifest-path tools/codec-bench/Cargo.toml zstd FILE...`。

局限：没有流式 API（解码器需要完整输入并保留完整输出，这正是证书压缩与缓冲的 HTTP 消息体所需要的）；
不支持字典；编码器没有长距离匹配、最优解析与多线程，因此在最高级别上的压缩率不及 libzstd；编码器从不
输出 treeless 字面量或重复使用的序列表（解码器两者都支持）。
