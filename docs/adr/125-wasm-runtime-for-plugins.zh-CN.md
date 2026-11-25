# ADR-125：插件用的 WebAssembly 运行时：独立 crate 中的安全解释器

[English](125-wasm-runtime-for-plugins.md) | 简体中文

状态：已采纳（2026-11-25）。按第 8 节的里程碑实现；W1（解码器与验证器）已完成，见文末“实现记录”。

## 背景

akit（在 akio 上用 Rust 重写的 fit）有两个与 WebAssembly 插件相关的迭代：

- **I71，WASM I：运行时与 ABI。** 路由对每个请求运行一个插件，处于沙箱中，在独立的池上运行，有时间和内存上限。
  完成标准：fit 的改头部插件（`plugin/wasm/testdata/headers`）不加修改即可运行，且开销经过测量、有上界。
- **I72，WASM II：Proxy-Wasm 子集。** 完成标准：移植过来的 fit 的 Proxy-Wasm 测试通过。

akit 不使用 `unsafe`，也不使用异步运行时；akio 缺的东西加到 akio 里（akit 规则 21），所以运行时由 akio 提供。
akit 以 A165 提出了这一请求。

**fit 运行的是什么**（fit `7daee573`，`plugin/wasm`，决策 017、018 和 023）：

- **运行时是 wazero**（纯 Go，在 amd64 和 arm64 上编译为机器码）。每个插件按代码哈希和内存上限编译一次，
  在重载之间共享；每个实例有自己的内存，有上限（`max_memory_bytes`，默认 128 MiB）。
- **插件是 WASI reactor**：Go（`GOOS=wasip1 -buildmode=c-shared`）、TinyGo 或 Rust。Go 的 guest 导入 17 个
  `wasi_snapshot_preview1` 函数（args、environ、时钟、`random_get`、`fd_write`、`poll_oneoff`、`proc_exit`、
  `sched_yield`，以及几个 `fd_*` 桩）。
- **fit 自己的 ABI**（I71）：插件导出 `fit_on_request() -> i32`（0 继续，1 已应答），并从模块 `fit` 导入：
  `header_get/set/add/del(kind, ...)`、`request_get(field, ...)`、`respond(status, body, len)` 和
  `log(level, msg, len)`。字符串以指向插件内存的指针加长度传递；违反上限的宿主调用（字段超过 64 KiB、body
  超过 1 MiB、对响应的修改超过 256 次）使本次调用失败。对响应字段的修改先记录下来，在响应头确定时应用。guest
  包还导入了模块 `fit_sync`（sync 的插件），所以每个 Go guest 即使从不调用这些名字，也需要它们能被解析。
- **Proxy-Wasm v0.2.0/0.2.1**：根上下文，带 `vm_config` 和插件 `config`；每个请求创建一个上下文，调用
  `proxy_on_request_headers`，然后 done、log、delete。已实现：头部映射（含 `:method`、`:path`、`:authority`、
  `:scheme`）、本地响应、配置缓冲区、属性、日志和指标；I81（决策 023）起还有 `proxy_on_response_headers`、
  `_body` 和 `_trailers`，在池上运行，通过 fib 的 `OnHeaderAsync` 和 `OnBodyFilterAsync`。外部调用、共享数据和
  队列、tick、外部函数、`set_property`、请求的 body 和 trailer 回调以及恢复已暂停的流，返回 `Unimplemented`。
- **池**：每个实例一个 goroutine（CPU 数，最多 16），有界队列（1024，超出则 `503`），等待超时（1 s），调用超时
  （100 ms），超时则停止调用并重建实例，`on_error: fail | skip`。Proxy-Wasm 的上下文属于创建它的实例，所以响应
  的回调排到该实例的队列里，先于新请求执行；一个实例同时最多跟随 `max_streams` 个响应（1024）。
- **开销**：fit 的决策 018 记录，在基准测试主机上，经过插件的请求约 5 µs，经过 Proxy-Wasm 过滤器约 8 µs。

**guest 需要运行时支持什么：一次试验。** 用 Go 1.27 构建 fit 的三个测试 guest（`headers`，以及 Proxy-Wasm SDK
的 `http_routing` 和 `http_body`），逐条扫描其指令：

| Guest | 大小 | 函数数 | 指令数 | 用到的特性 |
| --- | --- | --- | --- | --- |
| `headers`（fit ABI） | 4.6 MB | 2537 | 1.42 M | MVP、符号扩展（`i64.extend32_s` 等）、饱和浮点转整数、`memory.copy` / `memory.fill` |
| `http_routing`（Proxy-Wasm） | 2.9 MB | 1939 | 0.83 M | 同上 |
| `http_body`（Proxy-Wasm） | 2.6 MB | 1707 | 0.74 M | 同上 |

没有多返回值块、没有引用类型、没有 SIMD、没有线程；一个表、八个全局变量，内存 37–48 页（2.3–3 MiB），没有
最大值。Rust 的 `wasm32-wasip1` 目标（1.82 起）默认还启用多返回值和引用类型，较新的 LLVM 默认启用 bulk memory
和饱和转换；TinyGo 用的特性与 Go 相同。

**解释器的代价：第二次试验。** 在 wazero 的编译器上运行 fit 自己的基准测试，再在其他条件不变的情况下（用
`go test -overlay` 把 `NewRuntimeConfig` 换成 `NewRuntimeConfigInterpreter`）在 wazero 的解释器上运行，
同一次运行，在一台 Apple M 系列笔记本上（macOS 上的数字不用于决策，规则 17；这里看的是同次运行的比值）：

| 基准测试（fit `plugin/wasm`） | wazero 编译器 | wazero 解释器 | 比值 |
| --- | --- | --- | --- |
| `BenchmarkGuestCall`（仅 headers 插件的调用） | 3.6 µs | 29.6 µs | 8.1× |
| `BenchmarkWASM/plugin`（经过它的请求，含交给池的开销） | 5.5 µs | 32.8 µs | 6.0× |
| `BenchmarkProxyWasm`（经过 `http_routing` 的请求） | 13.3 µs | 84.0 µs | 6.3× |
| `BenchmarkWASM/none`（无插件） | 0.29 µs | 0.31 µs | – |

wazero 的解释器是在其自身 IR 上的朴素栈机，为可移植性而非速度而设计；先翻译成寄存器（槽位）形式的解释器，
例如 wasmi，通常比它快 2–4 倍。Go guest 的一次调用主要是 Go 运行时在工作（分配、写屏障、字符串转换），
几次宿主调用伴随数千条指令；TinyGo 和 Rust 的 guest 实现同样的插件，指令要少得多。

**akio 的约束。** 没有异步运行时；I/O 线程上不做任何阻塞（规则 1）；一切有界、线性时间（规则 3、4、10）；
`unsafe` 只在 `akio-sys`、各后端、`akio-buf` 和 `akio-crypto` 的指定模块中，其他 crate 一律
`#![forbid(unsafe_code)]`（ADR-005，`docs/unsafe-review.md`）；新增依赖需要 ADR（规则 15），而 akio 已经用
自己的代码替换掉库里原有的全部依赖（TLS、QUIC、deflate、regex、brotli、zstd），第三方 crate 只作为参照留在
`fuzz/` 和 `tools/` 中。

## 决策

### 1. 解释器，安全 Rust，放在新 crate `akio-wasm` 中

- **`akio-wasm`**，`#![forbid(unsafe_code)]`，没有第三方依赖（依赖 akio-log，以及为 `random_get` 依赖
  akio-crypto）。通过门面 crate 的 `wasm` 特性以 `akio::wasm` 重新导出。
- **解释器，而非编译器。** 模块只解码、校验、翻译一次，每个函数一遍线性扫描，翻译成寄存器形式：WebAssembly
  值栈上的每个位置都是帧里固定的槽位（每条指令处的栈高度是静态的），于是指令直接读写槽位，而不是压栈出栈；
  常量变成立即数，比较后接 `br_if` 合成一条指令，分支目标预先解析，每个基本块带上自己的指令数用于计量
  （第 3 节）。执行是对这种形式的 `match` 循环，帧显式放在 `Vec` 上，不用原生递归：guest 的深递归是 trap，
  绝不会是原生栈溢出；宿主调用不能重入 guest。
- **为什么解释器对 fit 的用法足够。** 插件只在配置了它的路由上运行，在自己的池上，绝不在 I/O 线程上，每个
  请求的工作量也小。试验显示 wazero 的解释器在 fit 的 guest 上是其编译器的 6–8 倍；寄存器解释器应在 2–4 倍
  左右（待测，里程碑 W5），比 fit 的 5 µs 多几微秒，每次调用有上界。这是插件路由上的开销，不是每个请求的开销。
  用 TinyGo 或 Rust 构建的 guest 每次调用比 Go 便宜得多，插件指南会写明这一点。
- **为什么不用编译器。** 生成机器码的编译器需要 `unsafe` 和可执行内存：在 `akio-sys` 中把页先映射为可写、
  再改为可执行（W^X；Apple silicon 上要 `MAP_JIT` 和 `pthread_jit_write_protect_np`；aarch64 上要刷新指令
  缓存），通过函数指针调用生成的代码，以及两套代码生成器（x86_64、aarch64），约 1.5–2.5 万行，其中每个缺陷
  都是网关进程中的内存不安全，而且提供插件的人就能触发。边界检查要在生成的代码里显式进行（保护页需要信号处理
  函数，这是 akio 不接受的进程级状态）。**如果** W5 表明解释器的开销挡住了 akit 的基准测试行，编译器另立 ADR，
  放在 `akio-wasm::jit` 模块中，只在那里允许 `#![deny(unsafe_code)]` 的例外，页映射放在 `akio-sys`，并以
  解释器作为对它做模糊测试的参照。目前不在计划中。
- **为什么不用第三方运行时。** wasmtime（Cranelift）是编译器，有上述风险，且依赖一百多个 crate；wasmi 是成熟
  的解释器，但其执行器使用 `unsafe`，而且是第三方依赖，而 akio 的库已经去掉了所有第三方依赖。两者在库之外
  仍然有用：作为 `fuzz/` 中的差分参照和 `tools/` 中的基准（第 6 节）。

### 2. 支持哪些 WebAssembly 特性

- **支持**：WebAssembly 1.0（MVP），加上可变全局变量、符号扩展运算、不 trap（饱和）的浮点转整数、bulk memory
  （`memory.copy`、`memory.fill`、`memory.init`、`data.drop` 及表操作）、多返回值（函数和块）和引用类型
  （`funcref`、`externref`、多个表、`table.get/set/size/grow/fill`）。这正是 Go、TinyGo 和 Rust 的
  `wasm32-wasip1` 目前默认生成的。一个内存，32 位。
- **加载时拒绝，错误中写明特性名**：定宽 SIMD（236 条指令；fit 测试中没有 guest 用到，以后的 ADR 可以加）、
  线程与原子操作、异常处理、尾调用、64 位内存、多内存、扩展常量表达式、类型化函数引用与 GC、relaxed SIMD、
  组件模型。
- **浮点**遵循规范：`f32`/`f64` 运算同 Rust，`nearest` 用 `round_ties_even`，`min`/`max` 按 WebAssembly 对
  NaN 和带符号零的规则，NaN 载荷规范化。除时钟和随机数宿主函数外，执行是确定性的。

### 3. 宿主 API，以及调用如何保持有界

形状如下（名字在实现时确定）：

```rust
// 加载：解码、校验、翻译。与模块大小成线性；在池上运行，绝不在事件循环上。
let module: Arc<Module> = Module::new(&bytes, &ModuleLimits::default())?;

// 有类型的宿主函数，在创建实例时按 (模块, 名字) 解析。
let mut linker: Linker<State> = Linker::new();
linker.func("fit", "header_get", &[I32; 5], &[I32], |caller: &mut Caller<State>, args, results| {
    let name = caller.memory().slice(args[1].u32(), args[2].u32())?; // 带边界检查的视图
    ...
    Ok(())
})?;
linker.wasi_preview1(WasiConfig::default())?; // 见下文的子集
linker.trap_unresolved(true);                 // 未用到的导入（fit_sync）只在被调用时 trap

// 实例：其内存、表、全局变量和宿主状态；`Send`，非 `Sync`。
let mut inst: Instance<State> = linker.instantiate(&module, state, &InstanceLimits { .. })?;
let f = inst.export_func("fit_on_request")?;          // 类型只检查一次
let r = inst.call(f, &[], &mut out, Budget::deadline(Instant::now() + timeout))?;
```

- **内存**是每个实例一个 `Vec<u8>`，由 `memory.grow` 增长，最多到 `InstanceLimits::max_memory`（默认 128 MiB，
  与 fit 相同）；超出时按规范返回 `-1`。每次加载和存储都检查范围；宿主函数只能通过带边界检查的切片看到内存
  （`Caller::memory().slice/write`），所以 guest 给出的指针和长度永远到不了内存之外。
- **加载上限**，在解码时逐项检查，使校验保持线性、恶意模块尽早被拒：模块大小（64 MiB）、函数（100 000）、
  导入和导出（各 10 000）、每个函数的局部变量（50 000）、块嵌套（1 000）、`br_table` 目标（100 000）、表大小
  （1000 万个元素）、数据段和元素段（100 000），翻译结果不超过输入的固定倍数。
- **运行上限**：以槽位计的值栈（1 Mi 个槽位，8 MiB）和调用深度（10 000 帧），超过即 trap；内存如上；表不超过
  其声明的最大值和 `max_table_elements`。
- **计量**：每个基本块的第一条指令从解释器循环里的计数器中减去该块的指令数。计数器用完时，解释器检查本次调用
  的**预算**：截止时间（与 `Instant::now()` 比较）、设置了的话还有 fuel，以及所有者可从其他线程置位的中断标志
  （`InterruptHandle`，一个 `Arc<AtomicBool>`）；都允许时，用一片（约 10 000 条指令，几十微秒）重新填满计数器
  继续执行，否则 trap（`Trap::Deadline`、`OutOfFuel`、`Interrupted`）。循环逃不出它（每条回边都开始一个新块），
  也不需要看门狗线程：调用在截止时间后的一片之内停止。宿主函数受其自身上限约束，并可读取预算（`poll_oneoff`
  的睡眠在截止时间结束）。
- **trap 即结束实例。** 其内存可能只更新了一半，所以 trap 过的实例由其所有者丢弃并新建（与 fit 相同）；重建
  （包括 Go 的 `_initialize`）有自己的截止时间（`init_timeout`，默认 1 s）。
- **WASI preview 1 的子集**（`Linker::wasi_preview1`）：`args` 和 `environ` 除非给出否则为空；`clock_time_get`
  （实时和单调时钟）；`random_get` 取自 akio-crypto 的生成器；`fd_write` 写 1 和 2 时交给调用者提供的接收端
  （akit 把它送进自己的日志，并限速）；`poll_oneoff` 只支持时钟订阅，睡眠不超过本次调用的截止时间（它在池线程
  上运行）；`sched_yield` 为空操作；`proc_exit` 是 trap；没有预打开目录，其他 `fd_*` 和 `path_*` 调用返回
  `EBADF` 或 `ENOSYS`。没有文件系统，没有套接字。

### 4. 调用在哪里运行：绝不在 I/O 线程上

- 加载（`Module::new`）和创建实例在 akio 的逻辑池或插件池上运行，绝不在事件循环上：Go guest 有几 MB、数千个
  函数。
- **`akio_wasm::InstancePool<S>`**：固定数量的线程，每个线程拥有一个实例（实例不是 `Sync`），就像 fit 的池
  每个实例有一个 goroutine：
  - `submit(job) -> Result<(), Overloaded>`：通过一个有界队列（`queue`，默认 1024）交给任一空闲实例；在
    `wait_timeout` 内未开始的任务作为过期交还（akit 应答 `503`）；
  - `submit_to(instance, job)`：通过该实例自己的有界队列交给指定实例，先于共享队列处理：Proxy-Wasm 上下文
    属于创建它的实例，所以响应的回调要回到它那里；
  - 每个任务以 `FnOnce(&mut Instance<S>) -> R` 运行，带池的每次调用截止时间，结果通过调用者给的完成回调送回
    （akit 在那个线程上通过 akio-http 的 `Suspended::resume` 继续请求）；
  - trap 时丢弃实例，并在线程取下一个任务前重建；一直无法启动的实例把池标记为失败（之后每个任务都得到该错误）；
  - 统计（排队、运行中、重建、过期、按种类分的 trap），供 akit 的指标使用。
- 每个池的内存有上界：实例数 × `max_memory`，加上共享的已翻译模块。

### 5. Proxy-Wasm 映射到 akio-http 的钩子

ABI 层本身，即 fit 自己的 ABI 和 Proxy-Wasm 的，属于 akit（`akit-plugin`）：它们是基于上述安全 API 的宿主函数，
不需要 `unsafe`，而且是网关的策略。akio 要提供的是请求及其响应如何到达池、再如何回来：

| Proxy-Wasm | akio-http | 状态 |
| --- | --- | --- |
| `proxy_on_context_create`（根）、`proxy_on_vm_start`、`proxy_on_configure` | 无：在创建实例时于池上运行 | – |
| `proxy_on_context_create`、`proxy_on_request_headers` | `Context::suspend()` → `InstancePool::submit` → 在池线程上调用 `Suspended::resume(f)`，继续执行下一个 handler（ADR-109） | 已有 |
| 对请求的 `proxy_get_header_map_value`、`_pairs` | 调用期间用 `Suspended::req()` | 已有 |
| 对请求的 `proxy_add/replace/remove_header_map_value`、`set_header_map_pairs`，以及 `:path`、`:method`、`:authority` | 在 `resume` 中通过 `Context::req_mut` 应用 | **A33**（akit I40 提出） |
| 请求阶段对响应的同类操作 | 记录下来，由响应过滤器（`add_response_filter`）在响应头确定时应用 | 已有 |
| `proxy_send_local_response` | 在 `resume` 中 `Context::respond` | 已有 |
| `proxy_get_property`、`proxy_get_buffer_bytes`（配置）、`proxy_log`、指标 | 仅宿主状态 | – |
| `proxy_on_response_headers` | 一个响应过滤器，扣住响应头，直到别处的调用把它交回，带截止时间；期间 body 在响应的上限内被扣住 | **新增（H1）** |
| `proxy_on_response_body`、`proxy_on_response_trailers` | 一个流式 body 过滤器，其调用在别处完成，一次一个，通过 `done` 回调返回；写入方像遇到慢客户端一样被限速（待发字节超过水位线即扣住生产者，规则 8）；最后一次调用带 trailer，可以修改；body 最多扣住 `max_body_bytes`（1 MiB） | **新增（H2）** |
| `proxy_on_done`、`proxy_on_log`、`proxy_on_delete` | 响应已发出或客户端已离开时：流式 body 用 body tap 的 `end`（ADR-116），其余用 akio-http 的请求结束钩子 | tap 已有；其余需 **A48**（akit I41 提出） |
| 请求 body 和 trailer 回调、`proxy_http_call`、共享数据和队列、tick、外部函数、`set_property`、`continue_stream` | fit 也没有：`Unimplemented` | – |

H1 和 H2 是 fit 的 A41（`OnHeaderAsync`）和 A46（`OnBodyFilterAsync`）在 akio 中的形态，覆盖 HTTP/1.1、HTTP/2
和 HTTP/3，整体和流式 body，包括用 `sendfile` 发送的文件（此时以读取的方式经过过滤器，或在插件只要头部时绕过它）。
它们在 I72 开始时再详细设计，并由 akit 提出请求；在此之前，Proxy-Wasm 过滤器的响应回调不会被调用（即 fit 在其
I81 之前的状态）。body 为流式的请求不能挂起（ADR-109）；插件路由在其上限内要求完整 body，或等待 A75。

### 6. 依赖

`akio-wasm` 在 akio 之外没有依赖。第三方 crate 只出现在 akio 已允许的、库之外的地方：

- `fuzz/`：`wasm-smith`（从模糊测试字节生成合法模块，特性集为第 2 节所列）和作为差分参照的 `wasmi`；
- `tools/wasm-spec/`：一个脚本，用 `wasm-tools json-from-wast` 把官方规范测试（`.wast`）转换为 JSON 命令和二进制
  模块，在锁定的测试套件提交变化时手动运行，输出提交入库（运行测试不需要任何工具）；
- `tools/wasm-bench/`（不发布）：在 fit 的 guest 上比较 wasmi 以及作为量级参照的 wasmtime 与 `akio-wasm`。

### 7. 测试

- **规范测试套件**（`WebAssembly/testsuite`，Apache 2.0，锁定提交），按上述方式转换，由 `akio-wasm` 中读取命令
  的测试运行：`module`、`register`、`invoke`、`assert_return`（含 NaN 类别）、`assert_trap`、`assert_exhaustion`、
  `assert_invalid`、`assert_malformed`（仅二进制模块）、`assert_unlinkable`。核心套件和第 2 节采纳的提案的每个
  文件都要运行；被拒特性的文件列为跳过并写明原因，且必须校验失败，而不是崩溃。
- **模糊测试**，`fuzz/` 中的三个 cargo-fuzz 目标，最小化语料像 akio 其他目标一样由稳定测试回放：`wasm_decode`
  （任意字节：解码和校验从不 panic、保持线性、遵守加载上限）、`wasm_exec`（用小预算运行 `wasm-smith` 生成的
  模块：不 panic，每个上限都干净地 trap）和 `wasm_diff`（同样的模块和输入分别在 `akio-wasm` 和 `wasmi` 上运行：
  结果相同、trap 相同、调用后的内存相同）。实现时每个目标在基准测试主机上跑 16 分钟，之后进入夜间任务。
- **guest**：fit 的 `headers`、`http_routing`、`http_body`、`properties` 和 `response` guest 以及其 Rust sync
  guest，分别用 Go、TinyGo 和 Rust 构建，通过测试用的 linker 运行；Go 的 `_initialize` 和预算下的调用；`/loop`
  在截止时间停止，`/grow` 在内存上限处失败，`/panic` trap；每次之后都重建实例。
- **上限**：第 3 节的每个上限都测刚好低于、等于和超过；处在每个加载上限的模块以线性时间加载（带时间上界的
  测试，规则 21）。
- **InstancePool**：队列满、等待过期、`submit_to` 先于共享队列、trap 后重建实例、因实例无法启动而失败的池、
  有任务排队时关闭。
- 不需要 Miri 或 sanitizer：该 crate 是安全 Rust。解释器自身运算（地址、计数器）中的整数溢出，由 debug 构建下
  的测试和开启溢出检查构建的模糊测试目标检查。

### 8. 里程碑

每个里程碑是一个带测试的 akio 分支；规模以 Rust 行数（不含测试）和一个会话的工作量计。

| # | 里程碑 | 规模 | 用于 |
| --- | --- | --- | --- |
| W1 | 第 2 节特性的解码器和校验器、加载上限、`wasm_decode` 模糊测试目标 | 约 3 000 行，1–2 天 | I71 |
| W2 | 翻译为寄存器形式与解释器：数值运算、内存、表、全局变量、调用、trap、计量与预算；通过规范套件；`wasm_exec` 和 `wasm_diff` | 约 6 000 行，3–5 天 | I71 |
| W3 | 宿主 API（`Linker`、`Caller`、有类型的宿主函数、调用即 trap 的未解析导入）、WASI preview 1 子集；fit 的 guest（Go、TinyGo、Rust）能加载、初始化、运行 | 约 2 000 行，1–2 天 | I71 |
| W4 | `InstancePool`：拥有实例的线程、共享的和每实例的有界队列、截止时间、重建、统计 | 约 1 000 行，1 天 | I71 |
| W5 | 性能轮：针对 Go 生成的常见指令序列的融合指令、局部变量槽位放在循环的寄存器里，由基准测试任务在基准测试主机上与 fit（wazero）对比测量；DEV-PLAN 第 4 节中的行 | 1–2 天，加上基准测试任务 | I71 的“经测量、有上界的开销” |
| W6 | akio-http 的 H1 和 H2（扣住的响应头、异步 body 过滤器），覆盖 HTTP/1.1、h2 和 h3；若 A48 仍未完成则一并完成 | 约 1 500 行，2–3 天 | I72 |

**I71** 需要 W1–W4（请求修改还需要 A33；报告其开销需要 W5）；akit 一侧随后是 `akit-plugin`，包含 fit 的 ABI 和
基于 `InstancePool` 的池，几天工作量。**I72** 的请求阶段不再需要别的；响应阶段需要 W6。合计 akio 中约 13 000 行，
两到三周的会话，其中较大的部分（W1–W2）是一个自成一体的解释器，可以在 akit 使用之前构建并测试。

## 后果

- akio 获得一个不含 `unsafe` 的、用于不受信任代码的沙箱：解释器的缺陷表现为错误结果或 trap，而不是网关中的
  内存损坏；`docs/unsafe-review.md` 无需改动。
- 插件每次调用比 fit 中更贵（解释对比编译），受池和调用截止时间约束，且只在插件路由上；具体多少由 W5 给出。
  通往编译器的路仍然开着，并已写明，需另立 ADR。
- 加载插件与其大小成线性，且在事件循环之外完成；重载相同代码时复用已翻译的模块（共享，按哈希和上限做键，
  与 fit 相同）。
- akio-http 为 I72 获得的（H1、H2）可服务于任何需要在事件循环之外处理响应的过滤器，不仅是 WASM。
- 实现前仍待定：确切的 API 名字、fuel 片的大小，以及在有 guest 需要之前是否值得保留 `externref`（代价很小；
  规范测试覆盖它）。

## 实现记录

### W1：解码器与验证器（2026-11-25）

crate `akio-wasm`（`#![forbid(unsafe_code)]`，无依赖）：`Module::new(&bytes, &ModuleLimits)` 一遍完成解码与验证，
函数体边解码边验证；`Module` 给出导入、导出、类型、函数、表、内存、全局变量和 start 函数，并保留代码供 W2 使用。
拒绝时返回 `Error`，带 `ErrorKind`（`Malformed`、`Invalid`、`Unsupported(Feature)`、`Limit(Limit)`）、字节偏移和规范的措辞。
门面 crate 在 `wasm` feature 下以 `akio::wasm` 重新导出。实现中做出的决定：

- **规范测试用 WebAssembly 2.0 的**：`WebAssembly/testsuite` 固定在 `a8101597`（2025-09-11），这是顶层仍为 2.0
  测试集的最后一个提交；其后顶层换成 3.0 草案，它按 3.0 的规则重测 2.0（例如常量表达式可用任意不可变全局变量），而第 2 节没有采纳这些。2.0 的文件全部运行；其中的 `simd_*` 文件以及被拒绝特性的提案（threads、relaxed SIMD、
  custom page sizes、wide arithmetic，以及 3.0 草案中 memory64、多内存、尾调用、异常、GC 和类型化函数引用的文件）作为拒绝检查运行：
  每个模块要么被接受，要么以“不支持”拒绝，不得以“格式错误”或“无效”拒绝。一个例外：threads 提案早于引用类型，
  它的三个“multiple tables”模块在这里是有效的。转换后的测试集 5.7 MB，位于 `crates/akio-wasm/tests/spec`（不随 crate 发布）；
  `tools/wasm-spec/convert.sh` 去掉被拒绝特性文件中的动作命令（它们永远不会运行）。W1 运行解码与验证命令（1 598 个模块、
  2 146 个 `assert_invalid`、719 个二进制 `assert_malformed`、117 个只在链接或实例化时失败的模块）；其余命令等 W2。
- **常量表达式遵循 2.0**：`global.get` 只能引用导入的、不可变的全局变量。
- **第 3 节之外的加载上限**，使每个计数都有界：类型（100 000）、一个类型的参数和结果（各 1 000）、表（100）、
  全局变量（100 000）。表的上限（10 M）限制的是表的初始大小；其最大值可以更大，增长属于实例的上限（W3）。
  “翻译后的形式至多是输入的固定倍数”属于 W2。局部变量计数包括参数。局部变量总数超过 `u32::MAX` 时按规范判为格式错误，先于上限检查。
- **拒绝的特性**：第 2 节所列，另加 custom page sizes 和 wide arithmetic，各自给出名字。relaxed SIMD 报告为 SIMD：
  它的指令操作 `v128` 值，模块总会先遇到 SIMD。
- **crate 属于实验层**（docs/api-stability.zh-CN.md），直到 W4 定下 API；快照 `api/akio-wasm.txt` 让改动可见。
  门面的 `wasm` feature 不在 akio 的快照中，与 `dpdk` 相同。
- **模糊测试**：`wasm_decode` 对每个输入分别在默认上限和小上限下加载；在小上限下接受的模块满足每个上限，
  在小上限下因上限以外的原因被拒的模块，在默认上限下以同样的方式、在同样的偏移被拒。
