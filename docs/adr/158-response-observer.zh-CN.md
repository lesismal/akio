# ADR-158：监听器的响应观察者，每个请求不分配内存

[English](158-response-observer.md) | 简体中文

状态：已采纳（2026-11-26）

## 背景

访问日志和请求指标在发送响应的线程上得知每个响应；被代理的请求，这个线程就是其上游应答所在的
线程。akio-http 提供的唯一途径是响应过滤器（`Context::add_response_filter`），一个装箱的闭包：
闭包只要携带任何东西（开始时间、指标槽位、日志分片），每个请求就要分配一次内存，而规则 12 不让
热路径这样做。akit 的分发器为每个请求注册一个（akit 的需求 A29）；akio 自己的 `HttpMetrics`
中间件也一样，并且每个请求克隆一个 `Arc`。

## 决定

每个监听器设置一次的观察者，以及请求内联携带的两个字：

```rust
pub trait ResponseObserver: Send + Sync + 'static {
    fn on_response(&self, resp: &Response, req: &Request, words: [u64; 2], started: Instant);
}
impl<S> HttpAcceptor<S> { pub fn observer(self, observer: Arc<dyn ResponseObserver>) -> Self; }
impl Context { pub fn set_observed(&mut self, words: [u64; 2]) -> bool; }
pub fn akio_h3::serve_with_observer(quic, cfg, service, observer) -> QuicServer;
```

- `set_observed` 把这两个字和 `Instant::now()`（首次调用时的；之后的调用替换这两个字）存进请求的
  `Finish`，即上下文中随响应一起走的部分（走到 `Detached`、挂起的上下文、扣住响应头的
  `Going`）。监听器没有观察者、或响应已被取走时返回 `false`，什么也不存。
- 每个被观察的请求，观察者在其响应交给连接时运行一次，在发送它的线程上，位于 `Finish::apply`
  的最后：在响应过滤器、额外响应头、耗时头之后；有扣住的响应头时（ADR-128），在外层过滤器之后、
  响应头发出之时。流式响应在其响应头发出时被观察（其结束由 `on_end` 得知，ADR-127）。
- 客户端离开后才发出的响应（分离的请求应答到已关闭的连接）照发出时的样子被观察。响应从未发出的
  请求（其上下文、`Detached` 或 `Suspended` 未应答就被丢弃；扣住的响应头被切断）不被观察：
  `on_end`（`End::Gone`）能得知这些，代价是它的钩子。
- HTTP/1.1 和 HTTP/2 通过 `HttpAcceptor::observer`；HTTP/3 通过 `akio_h3::serve_with_observer`，
  借助新的 `ConnSink::observer`（默认没有），`Context::new_ext` 会询问它，所以 `transport`
  接缝上的任何传输都能携带观察者。

**没有所有线程共享的计数。** 每个连接在打开时生成自己对观察者的句柄（包装监听器观察者的
`Arc<dyn ResponseObserver>`：每个连接一次分配，且只在有观察者时），每个请求把这个句柄克隆进自己
的 `Finish`：它增加的是该连接的计数，由该连接自己的线程（以及在别处应答的请求所在的线程）触碰，
绝不是所有 I/O 线程都写的计数。不调用 `set_observed` 的请求只付出一次连接句柄的克隆和一次 `None`
判断；没有观察者的监听器什么也不付出。

HTTP/2 会话现在装箱在 HTTP/1 会话里（每个 HTTP/2 连接一次分配）：连接和其 HTTP/2 驱动的句柄让
空闲的 HTTP/1 连接超出了 256 字节的预算（`size_tests`）。

**否决的方案。** 在响应时调用 `Service` 的方法：发送线程手里是上下文的响应，不是服务。每个监听器
泄漏一次的 `'static` 观察者：重载时监听器来来去去。按这两个字索引的全局注册表：每个响应一次加锁
或一次共享计数。

## 影响

- akit 的分发器把路由的指标槽位和日志分片设为这两个字，其观察者写访问日志行并计数；
  `Dispatcher::track` 去掉。
- `Finish` 增加句柄和两个字（48 字节），`Context` 随之变大。

## 测试

`crates/akio-http/tests/observer.rs`（HTTP/1.1 和 HTTP/2）：内联发送的响应，分离的响应（在应答
线程上被观察，带耗时），带过滤器和额外响应头的响应（都能看到），之后的 `set_observed` 替换这两个
字，流式响应（在响应头时），扣住的响应头（头发出之后），挂起的请求；没有要求的请求和要求太晚的
请求不被观察；没有被观察两次的；客户端离开后才发出的响应被观察，从未发出的不被观察；没有观察者时
`set_observed` 为 `false`。`crates/akio-http/tests/observer_allocs.rs`：用计数的全局分配器，被观察
的 HTTP/1.1 keep-alive 请求在稳态下不分配内存，而装箱的响应过滤器每个请求分配一次。
`crates/akio-h3/tests/observer.rs`：HTTP/3。
