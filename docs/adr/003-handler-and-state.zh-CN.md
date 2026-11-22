# ADR-003：Handler 与每连接状态

[English](003-handler-and-state.md) | 简体中文

状态：已采纳（2026-11-13）

## 决定

每连接状态**就是** handler 值本身：`trait Handler: Send + Sized + 'static`，含 `on_data(&mut self, &Conn<Self>, &[u8])`、`on_close`、`on_hangup`。`Acceptor`（共享、`Sync`）在 `on_open` 中为每个连接创建一个 `Handler`。`Conn<H>` 仅为了让 `spawn_blocking` 的完成回调能写成带类型的 `FnOnce(&mut H, &Conn<H>, R)` 才对 handler 类型泛型；借助 `PhantomData<fn() -> H>`，句柄对任意 `H` 都是 `Send + Sync`。

已原型验证并否决的方案：(a) 无类型 `Conn` + `Box<dyn Any>` 状态：每次回调都要 downcast，且失去类型安全；(b) 共享 `&self` handler + 关联的每连接状态类型：`done` 回调难以写出类型。`crates/akio-core` 中的原型可编译，并由 `tests/api.rs` 覆盖。

## 影响

- Handler 可以持有 `Cell` 等 `!Sync` 数据；热路径上没有任何 `Sync` 约束。
- 引擎内部用类型擦除存储（`Box<dyn ErasedHandler>`），一个 Engine 可服务不同 handler 类型的 listener。
- 原型发现：`impl Acceptor for Fn(&Conn<H>) -> H` 这类 blanket impl 会因 `H` 无约束被一致性检查拒绝，因此闭包通过 `fn_acceptor` 包装。
