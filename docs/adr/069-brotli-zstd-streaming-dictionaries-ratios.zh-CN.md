# ADR-069：only-brotli 与 only-zstd 的流式 API、字典与最高级别压缩率

[English](069-brotli-zstd-streaming-dictionaries-ratios.md) | 简体中文

状态：已采纳（2026-11-21）

## 背景

ADR-041 新增的 `only-brotli` 与 `only-zstd` 只有一次性 API：输出向量就是窗口，内存由调用方的上限
约束，这正是证书压缩与缓冲的 HTTP 消息体所需要的。它没有做流式与字典（“工作区里还没有用到”），也不以
参考编码器的压缩率为目标：在基准语料上 brotli 11 比 libbrotli 大 3.5–11%，zstd 19 比 libzstd 大
1.3–7.6%（没有块分割、没有静态字典引用，zstd 没有最优解析）。DEV-PLAN 把这三项列为未完成。约束：解码
不能变慢（一次性解码器已对照 C 库调优，见 docs/BENCHMARKS.zh-CN.md）；仍为 `#![forbid(unsafe_code)]`、
没有 BMI2 路径；每个新入口无论输入如何声明，内存都有界。

## 决定

### 1. 流式 API，形状同 only-deflate

两个 crate 都新增 `Compressor`（`compress(input, &mut out, Flush)`、`Flush::{None, Flush, Finish}`、
`reset`、`total_in`、`is_finished`、窗口设置）与 `Decompressor`（`decompress_vec(input, &mut out,
limit)` 与 `decompress(input, &mut [u8])`，返回 `Progress { consumed, produced, done }`；`is_done`、
`reset`、`total_in` / `total_out`、窗口上限），与 `Deflater` / `Inflater` 一致。错误在 `reset` 之前
一直保持。一次性函数不变。

- **zstd 解码器**：帧以块为单位自定界，因此解码器跨调用至多收集一个块的输入（或一个头部），用一次性
  解码器的块解码逻辑解码到窗口缓冲区，再在调用方的上限下交付输出。窗口持有帧窗口再加同样大小后滑动
  （一次复制）；窗口超过 `max_window`（默认 8 MiB，即 RFC 9659 对 HTTP 的上限）的帧被拒绝。XXH64
  增量计算。由于持有的是帧的窗口而不是整个帧，回溯超过所持数据的匹配为 `BadOffset`，与 libzstd 的流式
  解码器相同。
- **brotli 解码器**：meta-block 不按字节对齐，也没有压缩后长度，若每来一些输入就从 meta-block 开头重新
  解码，代价是平方级的（一个 16 MiB 的 meta-block 以 1460 字节的分段到达）。因此把一次性解码器的各部分
  改为可在单元边界处继续：meta-block 头部按单元读取（一个块类型描述、距离参数、上下文映射的树码或它的
  一项、一个前缀码），命令循环在每条命令处记录检查点（位读取器、输出位置、距离环、块切换状态）。用到了
  输入之外比特的单元，或在此之后失败的单元，回滚到检查点，等有更多输入时重来；只有未用到输入之外任何
  比特时，错误才属于流本身。最坏情况下每个输入字节重读一个前缀码或一条命令。命令循环以
  `const STREAM: bool` 泛型实现：一次性的实例中，检查点、暂停与窗口基址都被编译掉。解码器还会在比交付
  提前 1 MiB 的命令边界处暂停，所以内存为窗口（达到两倍时滑动）、1 MiB、前缀码与一个单元的输入。
- **编码器**：一个保存历史与待压缩输入的缓冲区；块（zstd，128 KiB）或 meta-block（brotli，1 MiB，
  10–11 级为 256 KiB）满了或遇到 `Flush` 时压缩。匹配查找的状态在块之间保留（缓冲区按链表大小的整数倍
  滑动时重定位置）。zstd 的 `Flush` 把待压缩输入写成一个块（块按字节对齐）；brotli 的 `Flush` 结束
  meta-block 并用空的元数据块填充，与 `BROTLI_OPERATION_FLUSH` 相同。若在写出任何内容之前全部输入已到达，
  流就是一次性的输出，包括内容大小。

### 2. 字典

- **zstd**：`Dictionary::new(bytes)` 解析 `zstd --train` 的训练格式（Dictionary_ID、Huffman 与 FSE
  表、重复偏移、内容；按 libzstd 的方式校验），其他字节一律作为原始内容（`Dictionary::raw` 强制如此）；
  克隆时共享。解码时把内容放在窗口中帧之前，并以字典的表与重复偏移开始帧；指定了其他 Dictionary_ID 的帧
  为 `WrongDictionary`，未指定的帧使用所给字典（libzstd 的规则）。一次性的 `decompress_with_dictionary`
  基于流式解码器。编码时把内容放在输入之前供匹配查找，从字典的重复偏移开始，并让最初的块复用其码表。为此
  编码器现在跟踪解码器所持有的表，因此每个块在估算更省时都可以复用上一个块的 Huffman 码
  （Treeless_Literals_Block）或序列表（Repeat_Mode）。字典引用与 libzstd 的编码器一样，限制在从内容末尾
  起的帧窗口之内。
- **brotli**：原始（LZ77 前缀）字典，即 `brotli -D` 与 RFC 9842 的 `dcb` 编码所用的那种，语义同 Google
  的解码器（`BrotliDecoderAttachDictionary` 搭配 `BROTLI_SHARED_DICTIONARY_RAW`）：超出窗口可达范围的
  距离先指向该字典（复制必须留在字典之内），再指向静态字典（地址加上字典长度）。输出在窗口之内时，编码器
  把字典中的位置当作候选。未实现 RFC 9841 的序列化共享字典格式（自定义词表与变换）：Google 的命令行工具
  无法生成它，这里没有用到它，而解码它会改变热循环中的静态字典路径。

### 3. 最高级别的压缩率

- **zstd 16..=22**：每个块做最短路径解析（libzstd 的 `btopt` / `btultra`），候选来自 libzstd 的二叉树
  匹配查找（按 4 字节哈希划分的后缀树，每插入一个位置就围绕它重新链接；长度递增，至多 16 个）。最初用的
  是哈希链：在 JSON 上，大量几乎相同的候选组成的长链使 19 级比之前慢 30 倍、比 libzstd 慢 5 倍，缩短链又
  损失压缩率；二叉树用少得多的时间找到更好的候选。路径代价为字面量以及字面量长度 / 匹配长度 / 偏移码的
  代价，取自上一个块的解析结果（libzstd 同样沿用统计；每个块都从预定义分布开始时，16 级在 Silesia 上比它
  所取代的惰性解析大 3.7%），第一个块由估算开始且至少两遍，之后取自上一遍（16 级一遍，17–18 级两遍，
  19 级起三遍），字面量长度码随字面量逐个计价（libzstd 的定价方式），沿每条路径跟踪重复偏移。没有移植
  3 字节匹配。
- **brotli 10–11**：静态字典引用，这是主要缺失的部分：按词的前四字节小写形式建立字典词索引，在每个
  位置对每个变换前缀之后查找，并按恒等、大写与省略末尾的变换及其后缀核对；引用作为最短路径的候选（复制
  长度 = 词长，距离 = 窗口可达范围 + 1 + 原始字典长度 + 地址，不改变距离环）。没有做块分割：它需要块类型
  与块长度码、每种类型的上下文映射以及分割器（Google 的迭代直方图分配），主要在混合二进制数据上有收益。
  曾尝试 10–11 级使用更大的 meta-block，后放弃（JSON 小 0.3%，Silesia 大 0.17%）。

### 4. HTTP

检查了 `only-http` 是否有缓冲：缓冲的响应由 `compress` 中间件整体压缩（一次性，压缩率最好，
`Content-Length` 已知）；流式响应（`Context::stream_response`）对任何编码都不压缩发送，包括 gzip：
响应过滤器不作用于它们。没有地方缓冲流式消息体，所以那里现在不做改动。压缩流式响应（每个流一个编码器，
为 server-sent events 每次写入刷新一次，一个 `Compress` 开关，缩小每个流的内存）是一项独立的功能，留待
以后；流式 API 使其成为可能。HTTP 客户端不解码任何内容编码。

## 影响

- 两个 crate 的 API 都是增量的（`Compressor`、`Decompressor`、`Flush`、`Progress`、
  `compress_with_dictionary`、`decompress_with_dictionary`；zstd 的 `Dictionary`、
  `DEFAULT_MAX_WINDOW`；新的 `Error` 变体 `WrongDictionary`、`BadDictionary`（zstd）与
  `WindowTooLarge`（brotli）；这些枚举都是 `#[non_exhaustive]`）。快照已更新。
- 输出变化：zstd 各级别的帧都可能复用码表（多块输入更小），16–22 级做最优解析；brotli 10–11 级使用静态
  字典词。我们的解码器、`zstd -d`、`brotli -d`、libzstd 与 brotli-decompressor 都能解码（测试与模糊测试
  目标）。
- 压缩率，基准语料上与 C 库的大小对比（确定性结果）：zstd 19 从 +1.3..7.6% 降到 +0.3..1.4%（Silesia
  20 MB 6,160,823 → 5,785,046，libzstd 5,723,399；JSON 46,894 → 44,386 / 44,267；HTML 7,173 → 6,985 /
  6,967；JavaScript 20,726 → 20,190 / 20,102；证书链 1,736 → 1,724 / 1,701 与 2,563 → 2,545 / 2,531），
  级别 16 在 Silesia 与 JSON 上比 libzstd 更小；
  brotli 11 从 +3.5..11.4% 降到 +0.9..4.7%（HTML 6,739 → 6,202，libbrotli 6,048；JSON 43,638 → 42,754 /
  41,813；JavaScript 19,936 → 19,252 / 19,077；证书链 1,693 → 1,640 / 1,615 与 2,515 → 2,454 / 2,430；
  Silesia 不变，5,599,939 / 5,348,162）。
- 最高级别的压缩变慢，与 libzstd 中最优解析的代价一样：zstd 19 为 3.5–10.9 MB/s（之前 7–59；libzstd
  3.9–12），zstd 16 为 6.5–14（libzstd 9.6–18.6），brotli 10–11 在文本上约为之前速度的一半。树链接使
  16–22 级的 zstd 匹配表翻倍（19–22 级、8 MiB 窗口时 64 MiB，与 libzstd 相同）。
- 解码速度：在安静主机上与 main 同批 A/B，zstd 每格 −1.8..+3.1%，brotli −2.2..+4.9%；在专门针对小证书链
  的循环中 zstd −1.1..+2.3%、brotli 0..+2.0%（每条证书链至多约 0.15 µs，brotli 部分来自按单元读取头部），
  随构建配置而不同（docs/BENCHMARKS.zh-CN.md，“流式、字典与压缩率”）。
- 四个模糊测试目标：`zstd_stream`、`brotli_stream`（分片输入的流式解码器对照一次性解码器，带或不带
  字典；任意字节作为 zstd 字典）、`zstd_stream_roundtrip`、`brotli_stream_roundtrip`（流式压缩器的分片、
  刷新、窗口与字典取自输入；每次刷新后均可解码；以 libzstd 与 brotli-decompressor 为参照）。
