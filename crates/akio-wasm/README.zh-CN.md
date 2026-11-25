# akio-wasm

[English](README.md)

为 [`akio`](https://github.com/lesismal/akio) 提供的插件用 WebAssembly 运行时，安全 Rust 实现
（`#![forbid(unsafe_code)]`），无依赖（ADR-125）。模块只解码、验证一次，之后（从里程碑 W2 起）翻译成寄存器形式由解释器运行，
所有资源都有上界：没有 `unsafe`，没有可执行内存，所以缺陷只会是错误的结果或陷入（trap），不会破坏宿主进程的内存。
它是 akit WASM 插件（fit 的 ABI 与 Proxy-Wasm）的运行时。也可通过 `akio::wasm`（feature `wasm`）使用。

**实验性**：按里程碑实现，在 W4 之前其 API 可能在任何发布中变化（docs/api-stability.zh-CN.md）。本次发布包含 **W1**：解码器与验证器。

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

```rust
use akio_wasm::{ErrorKind, Module, ModuleLimits};

let bytes = std::fs::read("plugin.wasm")?;
match Module::new(&bytes, &ModuleLimits::default()) {
    Ok(module) => {
        for i in module.imports() {
            println!("needs {}::{}: {:?}", i.module, i.name, i.ty);
        }
    }
    Err(e) if matches!(e.kind(), ErrorKind::Unsupported(_)) => eprintln!("{e}"),
    Err(e) => return Err(e.into()),
}
```

测试：WebAssembly 2.0 规范测试集的解码与验证命令（`tests/spec`，由 `tools/wasm-spec/convert.sh` 从 `WebAssembly/testsuite`
转换，Apache 2.0）、被拒绝特性的提案作为拒绝检查、每个上限的低于/等于/超过，以及默认上限处的模块在有界时间内加载。
模糊测试目标 `wasm_decode` 在 `fuzz/` 中。

后续：W2 解释器（计量、预算、陷入），W3 宿主 API 与 WASI preview 1 子集，W4 实例池，W5 性能优化，
W6 为 Proxy-Wasm 响应回调提供的 akio-http 钩子。
