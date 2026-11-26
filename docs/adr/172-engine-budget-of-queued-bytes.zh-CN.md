# ADR-172：engine 所有连接排队字节的预算

[English](172-engine-budget-of-queued-bytes.md) | 简体中文

状态：已采纳（2026-11-26）。akit 的 A214。

## 背景

`Config::write_high_watermark` 在单个连接自己的待发数据超过它时暂停该连接的读，`max_queued_bytes`
拒绝超过单连接上限的发送。两者都不限制总和：水位为 256 KiB 时，10 万个慢客户端可以让一个 engine
排队 25 GiB。fit（基于 fib）有 `limits.max_pending_bytes`，默认为内存的一半：超过后，所有连接都
停止读，直到有数据发出。akio 的路线图承诺过 engine 级的 `max_pending_bytes`，但代码里没有；应用
也无法在其上自行实现：它得从拥有各连接的 I/O 线程之外暂停每个连接的读。

## 决定

1. **`Config::max_pending_bytes: Option<usize>`**（默认 `None`；`Some(0)` 也表示没有），可重载，
   也可用 `Live::set_max_pending_bytes`。当 engine 所有连接待发送的字节达到它时，每个连接在当前这次
   读之后暂停读；总和回落到它的四分之三时恢复。
2. **总和在 I/O 线程之外计算。** 每个 I/O 线程本来就在一个 gauge 中记录自己的待发字节
   （`LoopStats::queued_bytes`，数据入队和写出时更新）。设置了预算时，一个监视线程（`akio-budget`，
   每个 engine 的 telemetry 一个）在总和不低于预算一半时每毫秒、低于一半时每 10 毫秒对这些 gauge
   求和，并升起或放下一个标志。写路径不变，没有为它增加共享计数器。预算是软的：两次求和之间入队的
   数据可以越过它，最多是 engine 一两毫秒内写的量，而每个连接仍受 `max_queued_bytes` 约束。
3. **通过 `ConnInner::read_held` 暂停读。** 每个后端（epoll/kqueue 事件循环、轮次调度、io_uring、
   DPDK、tun）在每次读之后以及重新开启读时都会询问它。标志升起时它回答“是”，并把连接*挂起*，每轮
   一次：把连接的 id 和所属事件循环记入一张表（连接上的轮次号说明它是否在本轮的表里）。放下标志时
   清空该表，并通过各自的事件循环唤醒每个挂起的连接（`wake_conn`，与 `hold_reads(false)` 相同），
   使其重新开启读。不读数据的连接永远不会被挂起，也没有开销；挂起期间关闭的连接会离开该表。表的大小
   以打开的连接数为界。检查标志只需对一个仅在一轮开始或结束时写入的缓存行做一次 relaxed load。
4. **所有连接都暂停**，无论是接受的还是拨出的：代理的上游读正是填满其客户端队列的来源。写照常进行，
   所以队列会排空；从不读的对端由 `write_timeout` 关闭。UDP 对端不暂停（没有可暂停的流）。
5. **Telemetry。** `LoopCounters::budget_pauses`（`akio_budget_pauses_total`）按轮统计被暂停的
   连接；`Telemetry::pending_bytes` 是总和，`Telemetry::over_budget` 是该标志。

## 影响

- 设置了预算的 engine 能像 fit 一样限制许多慢对端合起来占用的内存。
- 设置预算时每个 engine 有一个线程，每秒唤醒 100 到 1000 次；不设置时没有。
- 询问 `read_held()` 的 handler 也会看到预算造成的暂停（HTTP 客户端因此像对待 `hold_reads` 一样，
  不把暂停的时间计入 body 空闲超时）。
- 应用无法按连接区分预算暂停与水位暂停；计数器可以区分。

## 未做

- 以内存份额（“50%”）作为预算：由应用计算字节数（akit 像 fit 的 `sysmem` 一样计算）。
