# Concepts

`akio` has a small core and a few rules that every protocol crate follows. Learn them once:

| Rule | Chapter |
|---|---|
| An **engine** owns **listeners**; each listener has its own **backend** and I/O threads. | [Engine, listeners and backends](engine.md) |
| A connection lives on **one I/O thread**; its **handler** is its state and its callbacks run inline there. `Conn` is a thread-safe handle. | [Handlers, acceptors and `Conn`](handlers.md) |
| Callbacks **must not block**. Blocking work goes to the **logical pool**; results come back to the connection's thread, in order if you reserved a slot. | [Blocking work](blocking.md) |
| `send` never blocks; queues are bounded; reads pause when a peer does not keep up. | [Backpressure](backpressure.md) |
| Shutdown is graceful: stop accepting, notify, drain, force after a timeout. | [Lifecycle and shutdown](lifecycle.md) |

The snippets in these chapters come from
[`crates/akio/examples/guide-basics.rs`](https://github.com/lesismal/akio/blob/main/crates/akio/examples/guide-basics.rs)
(run it with `cargo run -p akio --example guide-basics`).
