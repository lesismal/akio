# ADR-061：完整的 QPACK 编码器与 HTTP/3 客户端流式响应

[English](061-qpack-encoder-h3-streamed-responses.md) | 简体中文

状态：已采纳（2026-11-20）

## 背景

ADR-011 让 akio-h3 两端都有了 QPACK 动态表，但本端编码器仍只是 RFC 9204 的子集：插入只用静态名称
引用或字面名称，从不使用 Duplicate 指令，从不引用自己表中的名称，并且只引用对端已确认的条目，因此
对端给出的阻塞流预算（`SETTINGS_QPACK_BLOCKED_STREAMS`）从未使用，一个字段要等插入它的那条消息
被确认之后，下一条消息才能压缩它。客户端缓冲每个响应（`H3Client::request`，受 `max_body_bytes`
限制），而 HTTP/2 客户端早已支持流式响应（`H2Client::open`、`H2Event`）。服务器推送是 ADR-011
剩下的最后一项，本次不做（见下文）。

## 决定

### 1. 编码器（akio-h3，`qtable::Encoder`）

- **插入**：使用静态名称引用、动态名称引用（同名的最新条目，且该条目不在即将驱逐之列）或字面名称。
- **保守插入**：字段第二次出现时才插入（256 槽直接映射的指纹过滤器记住第一次），每条消息都变或敏感的
  字段从不插入（`:path`、`date`、`content-length`、校验器、范围、`age`、`expires`、凭据、cookie；
  RFC 9204 §7.1），单个条目最多占表的四分之一。一次性的值因此不占编码器流的任何字节。
- **引用**：字段段的 Base 是它开始时的 Insert Count；编码过程中插入的条目使用 post-base 索引
  （索引行与带名称引用的字面行，RFC 9204 §4.5.3、§4.5.5），因此字段第二次出现时就已是一字节引用。
  名称在表中时，字面行使用动态名称引用。
- **在对端预算内阻塞**：字段段只有在下列情况下才可引用对端尚未确认（Known Received Count 之上）的
  条目：它所在的流已有一个这样的段在途，或者已有这样段的流少于对端的 `SETTINGS_QPACK_BLOCKED_STREAMS`
  （无论对端给多少，最多 64）；否则只使用已确认条目、静态引用和字面量。预算为 0 时编码器的行为与
  ADR-011 相同（从不阻塞）。这一判断每段只做一次，在第一个需要它的引用处惰性进行。
- **Duplicate**：满表中最旧四分之一（"即将驱逐"）里被引用的条目，在副本放得下且不驱逐任何仍需要的
  条目时被复制（RFC 9204 §4.3.4）；该段随后引用副本（若允许阻塞）或仍引用旧条目，后续段找到的是副本，
  旧条目因而可以被驱逐。
- **驱逐**：只驱逐 Known Received Count 之下、且没有未确认段（包括正在编码的段）引用的条目，也从不驱逐
  插入或 Duplicate 指令所指的条目。
- **确认**：Section Acknowledgement 取该流最早的未确认段，并把 Known Received Count 提升到该段的
  Required Insert Count；Stream Cancellation 删除该流的所有段（释放它占用的阻塞预算）；Insert Count
  Increment 提升计数，增量为 0 或超出已插入数量时报 `QPACK_DECODER_STREAM_ERROR`。最多跟踪 1024 个
  未确认段，超过后的段不使用动态引用，因此从不确认的对端无法让编码器增长。
- **配置不变**：`H3Config` / `H3ClientOptions` 中的 `qpack_encoder_capacity`，以及对端的
  `SETTINGS_QPACK_MAX_TABLE_CAPACITY` 与 `SETTINGS_QPACK_BLOCKED_STREAMS`（现从其 SETTINGS 读取）。
- **默认仍关闭**（0），由下面的基准决定：编码器开启时，每条消息都要拿编码器的互斥锁，每个使用动态表的
  段都必须在解码器流上被确认；`quic-bench h3`（消息很小、重复字段很少）为此付出代价却省不了多少，而且
  我们互通矩阵中的对端（quic-go、curl 的 nghttp3、fib）通告的解码器表容量都是 0，编码器多半只是没人用
  的每连接状态。对于对端带表解码且消息重复字段较多的部署，它只是一个配置项。

### 2. 客户端流式响应

- `H3Client::open(method, path, headers, on_event) -> H3Upload`，与 `H2Client::open` 对应：请求体通过
  返回的 `H3Upload` 写入（`write`；没有请求体时立即 `finish`；`queued_bytes`），响应在连接的 I/O 线程上
  报告给 `on_event`：`H3Event::Head { status, headers }`、每块到达时的 `Data(&[u8])`（从不缓冲，不受
  `max_body_bytes` 限制）、`Trailers(&Headers)`，然后是 `End` 或 `Error(H3Error)`。`H3Event` 为
  `#[non_exhaustive]`。上传与下载可同时进行（同一请求上的全双工）。
- **背压**：`H3Upload::hold_reads(bool)` 暂停与恢复读取响应；暂停期间，流的接收窗口用完后 QUIC 流量控制
  让服务器停下，所以慢消费者让一个响应占用的内存有界（窗口，加上已收到的字节）。这需要 akio-quic 新增
  `Connection::hold_reads(id, bool)`：被暂停的流的数据留在其接收缓冲区，在恢复前不提高其
  `MAX_STREAM_DATA`；`stop` 丢弃暂停中保留的数据。可从任意线程调用，包括事件回调内。
- **取消**：`H3Upload::cancel()` 重置流并发送 `STOP_SENDING`（`H3_REQUEST_CANCELLED`），此后不再报告
  任何事件。
- **超时**：`request_timeout` 只作用到响应头到达为止（与 WebSocket 相同），之后不再适用（下载可以持续到
  消费者愿意为止，`cancel` 可随时结束）。
- **实现**：流式请求是一种单独的请求类型。响应头到达前，它与缓冲响应走同一个读取器（包括 QPACK 阻塞）；
  响应头到达时，它移到由 I/O 线程独占的每连接映射中，用从不保存 DATA 负载的流式帧读取器读取。等待
  QPACK 插入的 trailers 会暂停该流的读取（`hold_reads`），因此它之后到达的数据受窗口约束。缓冲路径的
  快速路径（整个到达的响应）与每请求开销不变：普通请求没有新增状态，每个流数据块多一次 `is_empty` 检查。

### 3. 不做服务器推送

HTTP/3 服务器推送（`PUSH_PROMISE`、推送流、`MAX_PUSH_ID`）不实现：Chrome 已移除 HTTP/2 推送且从未在
HTTP/3 上提供推送，Firefox 也已关闭，而它唯一的用途（预加载）已被 103 Early Hints 取代。客户端从不发送
`MAX_PUSH_ID`，所以服务器不得推送（RFC 9114 §4.6）；与以前一样，到达客户端的推送流以 `STOP_SENDING`
拒绝，客户端的推送流或 `PUSH_PROMISE` 到达服务器则是连接错误。`Context::push` 仍只用于 HTTP/2。API 中
没有为推送预留任何东西。

## 影响

- 公共 API 只有新增：`H3Client::open`、`H3Event`、`H3Upload::hold_reads`、`H3Upload::cancel`
  （akio-h3）；`Connection::hold_reads`（akio-quic）。`api/akio-h3.txt` 与 `api/akio-quic.txt` 只多出
  这些行。
- 基准（gpu51，`quic-bench h3 5 64`，CPU 2-5，经 `quiet.sh` 对 main b22519ae 做两次同轮 A/B，各 7 轮交替）：默认配置（编码器关闭）持平，两次分别为 0.997 倍和 1.001 倍（14 轮合计 0.999 倍，86.39 万 vs 86.48 万请求/秒；客户端请求路径只多了一次流式响应检查）；两端编码器都开启时为旧编码器同样开启时的 0.991 倍（72.21 万 vs 72.89 万），即默认配置的 0.833 倍（旧编码器为 0.839 倍），因此编码器默认仍关闭。
- 验证：针对每条编码器指令与规则的单元测试（post-base 引用与阻塞预算、Duplicate 与驱逐、动态名称、
  驱逐下限）；随机化的编码器对解码器测试（`qpack_encoder`，同时是新的 fuzz 目标），它延迟并拆分编码器流、
  延迟确认与增量、取消流，检查每个段都解码为原字段、对端阻塞的流从不超过它允许的数量、表不超过容量（5 分钟 108 万次，无问题）；
  `tools/interop/h3/nghttp3-qpack.py` 通过 `qpack-pipe` 示例，以多种表容量/预算配置用 libnghttp3 的
  QPACK 解码器（curl 使用的那个）解码我方编码器的输出，并把它的解码器流送回（线上的第三方对端都通告
  解码器表为 0，这是让第三方解码器检验编码器的方式）；流式响应的端到端测试（分块、trailers、暂停时的
  背压、取消、响应头超时、两端编码器都开启时的全双工）；akio-quic 中 `hold_reads` 的模拟测试。网络互通
  不变（quic-go、fib、Docker 中的 curl/ngtcp2 与 OpenSSL QUIC，服务器编码器开与关）。
- 客户端每连接状态多了两个空映射；一个流式请求多一个装箱回调及其 `H3Upload` 状态。
