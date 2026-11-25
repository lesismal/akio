# akio-wasm

[English](README.md)

为 [`akio`](https://github.com/lesismal/akio) 提供的插件用 WebAssembly 运行时，安全 Rust 实现
（`#![forbid(unsafe_code)]`），无依赖（ADR-125）。模块只解码、验证、翻译一次，翻译成寄存器形式由解释器运行，
所有资源都有上界：没有 `unsafe`，没有可执行内存，所以缺陷只会是错误的结果或陷入（trap），不会破坏宿主进程的内存。
它是 akit WASM 插件（fit 的 ABI 与 Proxy-Wasm）的运行时。也可通过 `akio::wasm`（feature `wasm`）使用。

**实验性**：按里程碑实现，在 W4 之前其 API 可能在任何发布中变化（docs/api-stability.zh-CN.md）。本次发布包含 **W1**：解码器与验证器，以及 **W2**：翻译与解释器。

- `Module::new(&bytes, &ModuleLimits)`：一遍完成二进制模块的解码与验证，时间与模块大小成线性。`Module` 列出导入、导出
  （`export(name)`）、类型、函数类型、表、内存、全局变量和 start 函数；它是 `Send + Sync`，由从它创建的所有实例共享。
- **WebAssembly 2.0 去掉 SIMD**：1.0（MVP）加上可变全局变量、符号扩展运算、不陷入的浮点转整数、批量内存、多返回值和引用类型
  （`funcref`、`externref`、多个表），一个 32 位内存。这正是 Go、TinyGo 和 Rust `wasm32-wasip1` 默认生成的内容。
- **其他特性在加载时拒绝**，以 `ErrorKind::Unsupported(Feature)` 给出名字：SIMD（含 relaxed SIMD）、线程与原子操作、异常处理、
  尾调用、64 位内存、多个内存、扩展常量表达式、类型化函数引用、GC、custom page sizes、wide arithmetic 以及组件模型二进制。
  其他拒绝为 `Malformed` 或 `Invalid`，带规范的措辞（`"type mismatch"`）和字节偏移。
- **加载上限**（`ModuleLimits`），每个计数在为其分配任何东西之前检查：模块大小（64 MiB）、类型（100 000）及其元数（1 000）、
  函数（100 000）、导入和导出（各 10 000）、表（100）及其初始大小（10 M 个元素）、全局变量（100 000）、每个函数的局部变量
  （50 000）、块嵌套（1 000）、`br_table` 目标（100 000）、元素段和数据段（各 100 000）。超过任何一个的模块以
  `ErrorKind::Limit(Limit)` 拒绝。

- **寄存器形式**：每个函数在同一遍中翻译一次，操作数栈的每个位置都是帧中固定的槽：指令直接读写槽（`local.get` 不复制、
  常量成为立即数、比较与其后的分支合为一条指令），每字节代码至多四条 16 字节的指令。
- **解释器**：带显式帧的 `match` 循环，从不使用原生递归；深递归是陷入，不是栈溢出。浮点遵循规范（规范 NaN、
  `nearest` 就近取偶），执行是确定的。
- **`Store`**：实例、宿主函数（`func_new`）和宿主状态；`Send`，不是 `Sync`。`InstanceLimits` 限制每个内存
  （128 MiB，超过时 `memory.grow` 返回 `-1`）、每个表（10 M 个元素）、值栈（1 Mi 个槽）和调用深度（10 000）。
  **陷入会结束 store**：之后的调用返回 `Trap::Ended`。
- **`Budget`**：每次调用的截止时间、燃料和 `InterruptHandle`，在进入基本块时大约每 10 000 条指令检查一次
  （批量内存与表指令按字节计费），所以调用在截止时间后几十微秒内停止，无需看门狗线程。

```rust
use std::{sync::Arc, time::{Duration, Instant}};
use akio_wasm::{Budget, InstanceLimits, Module, ModuleLimits, Store, Trap, Value};

let bytes = std::fs::read("plugin.wasm")?;
let module = Arc::new(Module::new(&bytes, &ModuleLimits::default())?);
let mut store = Store::new((), InstanceLimits::default());
let inst = store.instantiate(&module, &[], &Budget::unlimited())?;
let run = store.export_func(inst, "run").ok_or("no run")?;
let mut out = [Value::I32(0)];
let budget = Budget::deadline(Instant::now() + Duration::from_millis(100));
match store.call(run, &[], &mut out, &budget) {
    Ok(()) => println!("{:?}", out[0]),
    Err(Trap::Deadline) => eprintln!("太慢：另建一个 store"),
    Err(t) => eprintln!("陷入：{t}"),
}
```

测试：WebAssembly 2.0 规范测试集的全部命令（`tests/spec`，由 `tools/wasm-spec/convert.sh` 从 `WebAssembly/testsuite`
转换，Apache 2.0）：21 453 个 `assert_return`、2 354 个 `assert_trap`、链接与实例化；被拒绝特性的提案作为拒绝检查；
每个加载与运行上限的低于/等于/超过；预算；线性时间的翻译。模糊测试目标 `wasm_decode`、`wasm_exec`（`wasm-smith` 生成的模块，
小上限下运行）和 `wasm_diff`（与 wasmi 对比）在 `fuzz/` 中。

后续：W3 宿主 API（`Linker`、类型化宿主函数）与 WASI preview 1 子集，W4 实例池，W5 性能优化，
W6 为 Proxy-Wasm 响应回调提供的 akio-http 钩子。
