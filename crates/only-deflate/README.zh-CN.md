# only-deflate

[English](README.md)

[`only`](https://github.com/lesismal/only) 的 DEFLATE（RFC 1951）、zlib（RFC 1950）与 gzip（RFC 1952）
实现：纯安全 Rust（`#![forbid(unsafe_code)]`），没有任何依赖。它是 `only-ws` 中 permessage-deflate、
`only-http` 压缩中间件以及 `only-grpc` gzip 消息背后的压缩实现。这是内部 crate
（见 docs/api-stability.zh-CN.md）：请通过上述 crate 使用。

- `Inflater`：raw DEFLATE、zlib、gzip 的流式解压。输入可在任意位置拆分，输出可按任意大小分段取出；
  `decompress_vec` 接受大小上限（防御解压炸弹）；窗口大小 2^8..2^15；`reset` 与
  `reset_keep_window`（跨最终块保留上下文）。解码器对 Huffman 编码描述执行与 zlib 相同的检查
  （超额与不完整编码、重复码、缺少块结束码），因此接受与拒绝的流与 zlib 一致；差分模糊测试目标
  会与 zlib-rs 对比验证这一点。快速路径每次 64 位补充比特后解码三个字面量或一个长度/距离对，
  并以 8 或 16 字节为单位复制匹配。
- `Deflater`：基于后续四字节（级别 9 为三字节）哈希链的 LZ77，采用 zlib-ng / zlib-rs 的级别表与
  匹配策略：`quick`（级别 1：每个位置只探测一次，直接写出固定编码块，若存储块更小则改用存储块）、
  `fast`（级别 2：贪心）、`medium`（级别 3..=6：贪心，级别 5 起向前多看一个匹配）、
  `slow`（级别 7..=9：惰性匹配；级别 9 沿当前匹配内回溯最远的那条字符串链搜索）。候选匹配每次比较
  8 字节；级别 0 为存储块。每个块在动态 Huffman 编码（码长限制为 15 位，码长编码限制为 7 位）、
  固定编码与存储块中选最小者输出。支持 `Flush::Sync`（`00 00 ff ff` 标记）、`Flush::Full`、
  `Flush::Finish`；窗口大小 2^8..2^15（8 按 9 布局，距离最多 250，因此输出对 256 字节窗口有效）；
  `reset` 用于不保留上下文（no context takeover），短流之后只清空该流用过的哈希槽。
- `compress` / `decompress`：一次性辅助函数；`Adler32` / `Crc32`（slicing-by-8）。

```rust
use only_deflate::{Deflater, Flush, Format, Inflater, Level};

// permessage-deflate 风格：一个流，每条消息一次同步刷新，保留历史。
let mut d = Deflater::with_window_bits(Format::Raw, Level::DEFAULT, 15);
let mut inf = Inflater::new(Format::Raw);
for msg in [&b"hello websocket"[..], b"hello websocket again"] {
    let mut wire = Vec::new();
    d.compress(msg, &mut wire, Flush::Sync);
    let mut out = Vec::new();
    inf.decompress_vec(&wire, &mut out, 1 << 20).unwrap();
    assert_eq!(out, msg);
}
```

测试：文本、二进制、不可压缩、空、单字节重复与长周期数据在每个级别、格式与窗口下的往返；与
zlib-rs（经由开发依赖 flate2）及 `gzip(1)` 的双向互通；经固定编码的所有字面量、长度与距离；
保留上下文时的同步刷新边界（即 Autobahn 曾发现的 miniz_oxide 缺陷那一类）；输入输出按各种大小拆分；
每个级别、窗口大小与刷新方式下的流式压缩；截断、比特翻转与校验和错误。模糊测试目标
`deflate_inflate`（与 zlib-rs 差分）和 `deflate_roundtrip`。Miri 运行全部单元测试。

基准：`cargo run --release -p only-deflate --example bench [FILE...]` 输出级别 1..=9
（`BENCH_LEVELS=1,6,9` 可选部分级别）下与 flate2（zlib-rs）对比的压缩率与吞吐量，语料为生成的
文本、JSON 与随机数据以及传入的各个文件；`pmd_echo` 示例测量 permessage-deflate 回显。在 x86-64
上各级别输出与 zlib-rs 一样小（最多大 0.5%），压缩速度为其 0.94-1.48 倍，解压为 0.82-1.23 倍
（存储块 0.4 倍）；见 docs/BENCHMARKS.zh-CN.md。
