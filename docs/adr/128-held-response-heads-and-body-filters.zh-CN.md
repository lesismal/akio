# ADR-128：由别处的工作扣住响应头、过滤响应 body

[English](128-held-response-heads-and-body-filters.md) | 简体中文

状态：已采纳（2026-11-25）

## 背景

ADR-125 第 5 节把 Proxy-Wasm 的回调对应到 akio-http 的钩子上。其请求阶段用 akio-http 已有的能力即可
（`Context::suspend`，ADR-109；`Context::req_mut`，ADR-126）。响应阶段不行：`proxy_on_response_headers`、
`proxy_on_response_body` 和 `proxy_on_response_trailers` 必须在插件的池上运行（`akio_wasm::InstancePool`，绝不
在 I/O 线程上），而响应过滤器（`add_response_filter`）、body tap（ADR-116）和流编码（ADR-074、ADR-112）都在写出
响应的地方运行并当场决定。fit 在 fib 上遇到同样的缺口，用 fib 的 A41（`OnHeaderAsync`）和 A46
（`OnBodyFilterAsync`）补上；ADR-125 把它们在 akio 中的版本称为 H1 和 H2（里程碑 W6），akit 为 I72 以 A166 和
A167 提出。

## 决定

两者都建在各传输层之上、`Context` 的响应路径中：HTTP/1.1、HTTP/2 和 HTTP/3 的响应头都在那里确定，`BodyStream`
可以从任意线程写入，所以一份实现即可服务三种协议、整体与流式 body，以及文件 body。

### 扣住的响应头（H1，A166）

`Context::hold_response_head(timeout: Duration, f: impl FnOnce(HeldHead, &Request) + Send)`。

- `f` 在发送响应的线程上运行，时机是普通响应过滤器运行之后、`add_response_header` 的字段加上之后：插件看到的响应头
  就是客户端将得到的，只差外层过滤器（ADR-116），它们在其后运行，于是前面的缓存能看到插件的修改。多个扣住的响应头按
  添加顺序依次进行。
- `HeldHead` 提供 `status()`、`headers()`、`headers_mut()`、`body()`（整体 body，即过滤器留下的样子；流式、文件
  或被过滤的 body 为 `None`）、`is_live()`，以及三种出口，可从任意线程调用：`resume()`（交给下一个扣住的响应头，或
  发给客户端）、`respond(Response)`（本地响应，在外层过滤器之后整体发出以取而代之：因为此时什么都还没发出，所以可行，
  而 fit 只能让它失败）和 `fail()`。未应答即被丢弃时，等同失败。
- 失败即切断响应：关闭 HTTP/1 连接，重置 HTTP/2 或 HTTP/3 的流（`H2Responder::reset`，以及不公开的传输接口上
  新增的带默认实现的 `ConnSink::reset`，由 akio-h3 实现），请求以 `End::Gone` 结束（ADR-127）。
- 超过 `timeout` 时响应被切断，如同 `fail`；之后的应答不起作用（`is_live` 会说明）。计时器是 akio-http 唯一的
  计时线程，只持有弱引用。
- 期间，整体发送的响应整体等待；流式响应中处理器写入的内容被扣住，计入其 `queued_bytes`（按其限速的生产者像遇到慢
  客户端一样等待，`on_drain` 在响应头发出、字节排空后运行），最多 4 MiB，超出后写入以 `Overloaded` 失败，响应被
  切断。
- 对 `CONNECT` 的响应（隧道，ADR-113、ADR-122）和升级的响应立即发出，与 fit 相同。

### body 过滤器（H2，A167）

`Context::add_body_filter(filter: impl BodyFilter)`，其中

```rust
pub trait BodyFilter: Send + 'static {
    fn filter(&mut self, chunk: BodyChunk, done: FilterDone);
    fn abort(&mut self) {}
}
pub struct BodyChunk { pub data: Vec<u8>, pub end: bool, pub trailers: Headers }
impl FilterDone { pub fn done(self, data: Vec<u8>, trailers: Headers); pub fn fail(self); }
```

- 一次一个调用，带上次以来写入的全部内容；`done` 从任意线程、立即或稍后给出替代它发出的内容。期间写入的内容被扣住
  （最多 4 MiB，同上），整体交给下一次调用。最后一次调用设置 `end`，并带 body 的 trailer（没有则为空），可以修改或
  添加；它们跟在 body 之后发出（HTTP/1.1 分块 trailer，HTTP/2 和 HTTP/3 的 trailer 字段段）。把 body 扣到末尾的
  过滤器对其他调用回应空内容，Proxy-Wasm SDK 的 `http_body` 示例就是这样。
- 响应头发出之后（在扣住的响应头之后）过滤器才得到 body。其输出交给下一个 body 过滤器（按添加顺序运行，与响应过滤器
  相同），然后经过某个响应过滤器设置的流编码和 body tap，发往客户端：编码作用于过滤器的输出，因此即使在 `compress`
  之后，插件看到的也是未编码的 body。
- 整体发送的响应以流式发送：在响应过滤器运行之前就标记为流式（于是 `compress` 选择流编码而不是压缩整个 body，
  `etag` 不处理它），去掉 `Content-Length`，body 在一次最后调用中给出。文件 body 在磁盘池上分块读入过滤器，与
  ADR-124 读取需编码的文件相同；不使用 `sendfile`。只需要响应头的插件不注册 body 过滤器，其文件 body 仍用
  `sendfile`。
- 限速：过滤器的输出一返回即写出；输出流积压超过 256 KiB 时，下一次调用等待其排空。HTTP/3 在发送缓冲区满时整体拒绝
  一次写入（`Overloaded`，数据未被接收）：gate 保留它，在流排空后重新写入。其他写入失败则切断。
- 失败：`fail`、被丢弃的 `FilterDone`、4 MiB 上限，或处理器未完成即丢弃其流，都会切断响应（在 HTTP/2 和 HTTP/3
  上重置流，在 HTTP/1.1 上关闭连接，无论响应头是否已发出），并在进行中的调用返回后调用过滤器的 `abort`，除非最后一次
  调用已经发出（即使它失败了）。
- 对没有 body 的响应（对 `HEAD` 的响应，或 `1xx`、`204`、`304`，过滤器也可能使之如此）以及 `CONNECT` 或升级，
  不调用过滤器：过滤器被丢弃。

### done、log 与 delete 回调

它们只需要 ADR-127 的 `on_end`：过滤后的流的结束守卫就是响应自己的，因此 `End::Sent` 在最后一次调用的输出交给连接
之后到来，响应被切断时则为 `End::Gone`。Proxy-Wasm 宿主据此把 `proxy_on_done`、`proxy_on_log` 和
`proxy_on_delete` 排给该实例（`InstancePool::submit_to`），排在那里尚未执行的 body 调用之后。

### 实现方式

新的私有模块 `gate`：`Gate` 是响应头被扣住或有调用未返回时扣住 body 的地方，带有过滤器、待处理的字节和输出
（`BodyStream`，也可能是另一个 gate）。同一时刻只有一个线程处理输出，它把输出从 gate 的状态中取出，因此调用过滤器、
写入、结束或注册排空回调（其回调可能立即运行）时都不持有锁。写入方的 `on_drain` 在 gate 中没有积压、且输出自己的
排空回调已运行时执行：HTTP/3 的排空意味着“还有空间”，此时可能仍有字节在排队，所以 gate 在那里不等待
`queued_bytes` 归零（否则会立即重复注册，永远等待下去）。`BodyStream` 增加第四种内部变体，即 gate 的写入端。
`Finish` 增加一个装箱字段，只有注册了钩子的请求才分配；未注册的请求没有任何变化（`Session` 不变：`size_tests`
仍通过；`Out` 仍为 24 字节）。

## 影响

- akit 的 I72 可以在其池上调用 `proxy_on_response_headers`、`_body` 和 `_trailers`，覆盖三种协议，具备 fit 决定
  023 的保证，外加它缺少的两项：扣住响应头之后的本地响应，以及被过滤的文件 body。
- 被过滤的响应要为每次写入付出一次拷贝进 gate 的开销，并在没有调用进行时到来的每一段 body 上付出一次别处的调用；
  只扣住响应头的整体响应在发出前没有额外开销。
- 在 HTTP/3 上，没有过滤器时未完成即被丢弃的 `BodyStream` 仍不会被重置（传输层的 `BodySink` 没有 `Drop`）：这里
  的切断路径显式重置它（`BodySink::reset`）。让单纯的丢弃也重置流留给单独的修改。
- 未实现：请求 body 的过滤器（A75）、不经调用恢复 body 过滤器暂停的输出（`continue_stream`），以及修改扣住的响应头
  的状态码（改用 `HeldHead::respond` 替换整个响应）。
