# ADR-125：插件用的 WebAssembly 运行时：独立 crate 中的安全解释器

[English](125-wasm-runtime-for-plugins.md) | 简体中文

状态：已采纳（2026-11-25）。按第 8 节的里程碑实现；W1 至 W6 已完成（W5 即性能优化，2026-11-26），见文末“实现记录”。

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
  绝不会是原生栈溢出。（W3 允许宿主函数回调进 guest，这是 Proxy-Wasm 宿主必需的，每层嵌套调用占一层原生调用，
  至多 64 层：见“实现记录：W3”。）
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
| `proxy_on_response_headers` | 一个响应过滤器，扣住响应头，直到别处的调用把它交回，带截止时间；期间 body 在响应的上限内被扣住 | W6 已实现：`Context::hold_response_head`（ADR-128，A166） |
| `proxy_on_response_body`、`proxy_on_response_trailers` | 一个流式 body 过滤器，其调用在别处完成，一次一个，通过 `done` 回调返回；写入方像遇到慢客户端一样被限速（待发字节超过水位线即扣住生产者，规则 8）；最后一次调用带 trailer，可以修改；body 最多扣住 `max_body_bytes`（1 MiB） | W6 已实现：`Context::add_body_filter`（ADR-128，A167） |
| `proxy_on_done`、`proxy_on_log`、`proxy_on_delete` | 响应已发出或客户端已离开时：流式 body 用 body tap 的 `end`（ADR-116），其余用 akio-http 的请求结束钩子 | `Context::on_end`（ADR-127，A48），在过滤后 body 的最后一次调用之后（ADR-128） |
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

### W2：翻译与解释器（2026-11-25）

每个函数体在验证之后立即翻译，与模块的解析在同一遍中，翻译成第 1 节的寄存器形式（`instr.rs`、`translate.rs`）；
`exec.rs` 运行它。WebAssembly 2.0 规范测试集现在全部通过，每一类命令：21 453 个 `assert_return`、2 354 个 `assert_trap`、
15 个 `assert_exhaustion`、83 个 `assert_unlinkable`、34 个 `assert_uninstantiable`、`register` 以及 `spectest` 导入。
模糊测试目标 `wasm_exec` 和 `wasm_diff`（与 wasmi 2.0 对比）在 `fuzz/` 中。实现中做出的决定：

- **用 `Store<S>` 而不是 `Instance<S>`。** 第 3 节的草图让实例自己拥有内存、表和全局变量。W2 把它们放进 `Store<S>`：
  它持有实例、宿主函数和宿主状态，并给出句柄（`Func`、`Memory`、`Table`、`Global`、`Instance`），因为 WebAssembly 允许一个实例
  导入另一个实例的内存、表、全局变量和函数并看到同一个对象（测试集的 `register` 和链接测试需要它；两个实例共享的表里
  有两者的函数）。插件的 store 只有一个实例；实例池（W4）每个线程拥有一个 store，W3 的 `Linker` 实例化到 store 中。
  store 是 `Send`，不是 `Sync`。其他 store 的句柄在调用时被拒绝（`Trap::BadCall`），在访问器中导致 panic，与 wasmtime 相同。
- **陷入结束 store**，并强制执行：之后的调用和实例化返回 `Trap::Ended`（第 3 节把这留给所有者）。
  `Store::set_trap_ends(false)` 保留规范的语义，即陷入后 store 继续可用；测试集这样运行，其他场合不应使用。
  `Trap::BadCall`（参数个数或类型不对）什么也不运行，也不结束 store。
- **`Trap`** 是枚举：规范定义的陷入（`message()` 给出规范的措辞）、两个运行上限的 `CallStackExhausted` 和
  `ValueStackExhausted`、`Deadline`、`OutOfFuel`、`Interrupted`、宿主函数失败的 `Host(message)`，以及两种拒绝。
  实例化以 `InstantiateError::{Unlinkable, Limit, Trap}` 失败；失败段之前的活动段已写入的内容保留，与 2.0 相同。
- **寄存器形式**：帧是函数的局部变量，加上操作数栈每个位置一个槽；指令 16 字节，指名槽位。翻译器维护一个栈，记录每个值
  在哪里：在自己的槽里、仍在某个局部变量里（`local.get` 不生成指令，直到该局部变量改变时，先复制所有待读的值），或是常量
  （对有立即数形式的 `i32`、`i64` 运算作为立即数）。结果交给 `local.set` 的指令直接写局部变量；比较后接 `br_if` 或 `if`
  合为一条指令；调用的参数已经在被调函数帧的起点，结果也回到那里。带参数和结果的块只在跳到栈中更低位置的标签时移动值
  （`CopyRange`），需要移动值的 `br_table` 目标各有一个桩。不可达代码被跳过。
- **翻译结果的上界**是结构性的：每条 WebAssembly 指令至多生成三条指令（包括把它压入的值落到槽里），所以函数体至多
  `4 × 字节数 + 4` 条指令，并做检查；不需要 `ModuleLimits` 字段。翻译是线性的：待读的局部变量放在列表中，每个至多复制一次
  （有测试构造对粗心的翻译器是二次的情形：读 20 000 个局部变量再逐个赋值，以及每个目标都要移动两个值的 20 000 目标 `br_table`）。
  翻译完成后模块丢弃代码字节。
- **计量**：函数开头和每个分支可达的基本块（循环头、有跳入的标签、`else`）以 `Fuel(n)` 指令开始，`n` 是到下一个此类指令为止的
  WebAssembly 指令数。燃料按 WebAssembly 指令计；此外批量内存指令、`memory.grow` 和调用时清零局部变量按每 64 字节一个单位计，
  表指令按每 8 个元素一个单位计，使一个时间片在时间上也保持短。时间片为 `Budget::SLICE`，10 000。燃料是精确的：付不起的块不会开始
  （`OutOfFuel`），`Store::fuel_used()` 报告上一次调用的用量。调用的第一个块就检查预算，所以已过截止时间的调用不会开始。
- **运行上限**（`InstanceLimits`，取第 3 节的值）：`max_memory`（字节，128 MiB）与内存声明的最大值，`max_table_elements`
  （10 M）用于 `table.grow` 和实例化时创建的表，`max_value_stack`（1 Mi 个槽）在每次调用时按被调函数的整个帧检查，
  `max_call_depth`（10 000）。分配失败的增长同样返回 `-1`（`try_reserve`），分配失败永远不会中止进程。
- **浮点**：结果为 NaN 的算术运算给出规范 NaN（正、静默），结果不依赖硬件的 NaN 传播（x86 与 Arm 不同）；`abs`、`neg`、
  `copysign`、加载、存储和重新解释保留位模式。
- **值**：`Value::{I32, I64, F32, F64, FuncRef(Option<Func>), ExternRef(Option<ExternRef>)}`，浮点用 Rust 的浮点（位模式不变）。
  保留 `externref`（第 3 节的待定问题）：它在解释器中没有开销，`ExternRef` 是由宿主赋予含义的 `u32`。
- **宿主函数，W2 只做最少的部分**：`Store::func_new(FuncType, Fn(&mut Caller<S>, &[Value], &mut [Value]) -> Result<(), Trap>)`，
  `Caller::state(_mut)` 和 `memory(_mut)`（调用方实例的内存切片）。它们不能回调客户代码。W3 加入 `Linker`、类型化宿主函数、
  带边界检查的视图以及调用时才陷入的未解析导入。
- **模糊测试**：`wasm_exec` 用 `wasm-smith` 生成模块（第 2 节的特性、至多一个内存、较小的规模），检查每个都能加载（翻译从不拒绝有效模块），
  并在小上限和少量燃料下运行：结果类型正确，或者陷入并结束 store。它在 stable 上的回放把 `wasm_decode` 的语料（输入就是模块）
  交给 `fuzzing::exec`（`wasm_exec` 的输入是 `wasm-smith` 的种子）。`wasm_diff` 在 akio-wasm 和 wasmi 上运行同一个模块（无导入；
  wasmi 开启 `deterministic` feature，像 akio-wasm 一样规范化算术 NaN，并使用 portable dispatch，因为尾调用分派在 ASan 下会原生递归），
  以相同参数调用每个导出函数，比较结果（浮点按位精确比较）、陷入，以及之后每个导出的全局变量和内存；
  akio-wasm 燃料耗尽或任一方栈耗尽时停止比较，因为两者的上限不同。两个目标的语料都不提交：
  输入是 `wasm-smith` 的种子，最小化后仍有几十 MB，且只有 `wasm-smith` 能把它们变成模块；每次运行重新生成。

### W3：宿主 API 与 WASI（2026-11-25）

`Linker<S>`、类型化宿主函数、`Caller` 的带边界检查视图、调用时才陷入的未解析导入、WASI preview 1 子集，以及 fit 的客户模块
能够运行：Go 的 `headers`（fit 的 ABI）、Proxy-Wasm Go SDK 的 `http_routing`，以及 fit 的 Rust 同步插件，以 gzip 形式提交在
`crates/akio-wasm/tests/guests`（2.1 MB；由 `tests/guests/build.sh` 重新构建，不进入发布的 crate）。实现时确定的：

- **宿主函数可以回调进 guest**（`Caller::call`），第 1 节原本排除了这一点。Proxy-Wasm 需要它：返回头部或缓冲区的宿主函数要用
  `proxy_on_memory_allocate` 向 guest 申请内存再写入（fit 的 `give`，wazero 在宿主函数里调用 `CallWithStack`），没有它 I72
  无法实现。嵌套调用在同一个帧栈上运行，位于调用该宿主函数的帧之上，直到返回到它们；使用同一预算，同一 `max_call_depth` 与
  `max_value_stack`；每层是解释器循环的一次原生调用，所以嵌套有界（64 层，之后 `CallStackExhausted`），不会无界地原生递归。
  嵌套调用中的陷入会以该陷入结束外层调用，无论宿主函数返回什么，并结束 store。
- **链接器不属于任何 store。** `Linker<S>` 以 (模块, 名字) 保存宿主函数（`Arc`），`Clone + Send + Sync`；
  `instantiate(&mut Store<S>, &Arc<Module>, &Budget)` 为每个导入创建一个 store 函数，检查其类型（不同则 `Unlinkable`），
  对没有定义的导入以 `InstantiateError::UnknownImport` 拒绝并给出名字。于是 W4 的池在各线程间共享一个链接器，每个线程有自己的
  store。链接器只定义函数；内存、表和全局变量仍属于 store（`Store::memory_new` 等），fit 的客户模块都不导入它们。
- **类型化宿主函数与调用**：`func_wrap(module, name, |caller, params: P| -> Result<R, Trap>)`，`P` 是至多 12 个
  `i32`、`u32`、`i64`、`u64`、`f32`、`f64` 组成的元组（或单个），`R` 同样或为 `()`；`Store::typed_func::<P, R>(func)`
  只检查一次类型，得到 `TypedFunc`，可由宿主或宿主函数（`call_from`）调用。基于 `Value` 的 `func_new` 保留给运行时才知道类型的情形。
- **`trap_unresolved`** 只作用于函数导入；替身函数以 `Trap::Host("called unresolved import module.name")` 陷入，日志里能看到名字。
- **`Caller`**：`read`、`read_mut`、`write`、`read_u32`、`read_u64`、`write_u32`、`write_u64`，越出内存时都返回
  `Trap::MemoryOutOfBounds`（宿主函数用 `?` 返回即可），以及 `export`、`func_type`、`instance`、`call`、`deadline`、
  `is_interrupted` 和 `consume_fuel`（宿主函数自己的工作计入调用的燃料，如 WASI 的复制，每 64 字节一个单位）。
- **WASI**：preview 1 的全部 46 个函数都有定义，导入其中任何一个的 guest 都能加载。第 3 节的子集照写，另外：
  `fd_fdstat_get`、`fd_filestat_get`、`fd_fdstat_set_flags` 和 `fd_close` 对 0 到 2 描述一个字符设备（Go 的运行时启动时会询问），
  对它们的 `fd_seek` 和 `fd_tell` 返回 `ESPIPE`，对 0 的 `fd_read` 是空输入；`clock_res_get` 为 1 ns；进程与线程 CPU 时钟返回
  `EINVAL`；`poll_oneoff` 也把标准流报告为立即就绪（其他描述符报告为 `EBADF` 事件），并以 5 ms 为片睡眠以便看到调用的中断。
  guest 给出的指针越出其内存时返回 `EFAULT`，而不是陷入，与 wazero 相同。`proc_exit` 是新的陷入 `Trap::Exit(code)`。
  输出送往调用者给的接收函数（`WasiConfig::output`），每个缓冲区一次调用；限速由 akit 负责。
- **Reactor**：`Store::initialize_reactor` 在实例导出 `_initialize` 时运行它（初始化的截止时间由所有者给出）。Go reactor 的
  致命错误（panic、内存不足）打印到标准错误后以 `unreachable` 结束，而不是 `proc_exit`；Rust 的 `panic = "abort"` 也一样。
  Go 的 `headers` 初始化需要 180 万条指令，一个请求约 1 万条。
- **TinyGo 的客户模块**（fit 的同步插件，由 TinyGo 0.44 构建）尚未提交：构建脚本在 `tinygo` 位于 PATH 中时会构建它。
- **模糊测试**：`wasm_exec` 的导入函数现在每隔一次调用就回调进调用方实例（按计数选择一个导出），所以嵌套调用、其上限与陷入
  也一并被模糊测试。

### W4：实例池（2026-11-25）

`InstancePool<S>` 位于 `src/pool.rs`，没有超出 W3 的依赖：线程是它自己的（每个实例一个，另加一个 reaper），不是 akio 的逻辑线程池，
它也不了解 akio-core 或 akio-http。按第 4 节实现，并作出以下决定：

- **任务与其完成回调是两个参数，拒绝时两者都交还**：`submit(job, done) -> Result<(), Refused<J, D>>`，而不是
  `submit(job) -> Result<(), Overloaded>`。akit 的完成回调持有挂起的请求；被立即拒绝时（`Refusal::Overloaded`、`Closed`、`Failed`、
  `Remade`）它拿回请求，自己在 I/O 线程上应答 `503`。被接受后，`done` 恰好调用一次，参数为 `Result<R, JobError>`：结果，或者
  `Expired`、`Remade`、`Closed`、`Failed`、`Panicked`。
- **交回方式**：`done` 在任务结束后立即在池的线程上运行：任务已计入统计，失败的实例尚未重建（或者在 reaper 上，或在关闭池的线程上），不阻塞地把结果交出去：akit 在那里
  调用 akio-http 的 `Suspended::resume`，挂起到 akio 逻辑线程池的请求也是这样回来的。所以 akio-wasm 不需要自己的 I/O 线程 API。
- **任务看到的是 `Pooled<S>`**，而不是第 3 节的 `Instance<S>`（W2 已把句柄命名为 `Instance`）：store、实例、它的 `InstanceId`、
  任务的 `Budget`，以及 `call`、`call_typed`、`typed_func`、`export_func`、`state_mut` 和 `discard`（不经陷入而重建，用于宿主发现
  客户代码状态有误的情形）。
- **截止时间按任务计**：从任务开始起 `call_timeout`（100 ms，与 fit 相同），覆盖任务发出的每次调用，并带池的中断。创建实例
  （实例化、reactor 的 `_initialize`、供 Proxy-Wasm 的 `proxy_on_vm_start` 与 `proxy_on_configure` 使用的 `on_start` 钩子）
  总共 `init_timeout`（1 s）。
- **按时过期**：在 `wait_timeout`（1 s）内没有开始的任务，在等待到期时交回，由一个 reaper 线程负责，它睡到最早排队任务的过期时间，
  所以 akit 的 `503` 不必等忙碌的实例空出来。线程取出已过期的任务时也会交回。
- **实例有代数**：`InstanceId { index, generation }`。Proxy-Wasm 上下文随实例一起消亡，所以对 id 取得之后已经重建的实例
  `submit_to` 会被拒绝（`Refusal::Remade`），实例被丢弃时排给它的任务得到 `JobError::Remade`。
- **重建**：发生陷入（store 新增的 `Store::trap()` 说明是哪种，用于统计）、任务或完成回调 panic（`JobError::Panicked`；宿主状态
  可能只更新了一半）或 `discard` 之后，线程在任务的完成回调运行后丢弃实例，并在取下一个任务之前创建新实例。同一实例连续
  `start_attempts`（3）次创建失败会使池失败。`build()` 等待每个实例的首次创建，池失败时返回 `StartError`（无法实例化的模块在这里
  失败，而不是在第一个请求时）。
- **关闭**（`close()` 或丢弃池）拒绝新任务，以 `Closed` 交回排队的任务，触发每个实例的中断，让运行中的客户代码在一个切片内停止，
  并 join 各线程；如果最后一个句柄是在完成回调中丢弃的，则不 join 调用者自己的线程。
- **统计**（`PoolStats`）：就绪的实例、共享队列与每个实例队列的深度、运行中、调用数、拒绝、过期、panic、重建、创建失败，以及按种类
  的 `TrapStats`（截止时间、燃料、中断、栈、内存越界、`unreachable`、宿主、退出、其他）。
- 一把互斥锁保护队列与计数器；每个线程等待自己的条件变量，所以 `submit_to` 唤醒它指定的实例，`submit` 唤醒最近空闲的实例。
  W5 会测量这把锁相对解释器是否重要。

### W5：性能优化（2026-11-26，akit 的 A180）

先测量再削减，用 `crates/akio-wasm/examples/wasm-bench.rs` 和 fit 的 `BenchmarkGuestCall`（wazero），同一个
`.wasm`；数字见 docs/BENCHMARKS（“WebAssembly guest 调用”）。在 gpu51 上，于热实例上调用一次 fit 的 Go
`headers` guest 需 9.1 µs，wazero 编译器为 3.5 µs（其解释器 42 µs）。其中 89% 在解释器循环：每次调用约 3,000 条
寄存器指令，每条约 15 个周期。进入 guest 为 75 ns，9 次宿主调用约 250 ns；`c-shared` 的 Go 导出函数每个请求
不做 WASI 调用（Go 的调度器在 guest 中恢复运行），除宿主函数读写的部分外也不复制 guest 内存。因此这一轮针对的是
分派，削减的是 Go 的 `wasm` 代码产生而解释器并不需要的那些。实现时的决定：

- **翻译时折叠**：`i64.extend_i32_u` 不生成指令，因为槽中的 `i32` 是零扩展的（每个写 `i32` 的地方本就保持这一
  不变式，现在依赖它：类型化宿主函数的结果也这样写）；常量的整数转换（`wrap`、各种 `extend`）直接得出常量。结果
  只用作 load/store 地址的 `i32.wrap_i64` 被去掉，访存直接读 64 位的槽，其低 32 位就是地址；两者之间没有指令执行，
  也没有分支落在其间（每个分支目标都以 `Fuel` 开头，或紧跟在产生它的分支之后）。
- **融合指令**：存储常量（`Store8I`、`Store16I`、`Store32I`，以及常量可用 32 位有符号数表示时的
  `Store64I`）、返回常量（`Return1C`）、第一个参数是常量的调用（`CallC`：Go 给每个函数都传 0）、对
  `eqz(eqz x)` 的 `br_if` 变为对 `x` 的测试，以及写入局部变量又写入全局变量的 `x ± imm`（`I32AddGlobal`，
  即 Go 的栈指针，全局变量下标须能放进 16 位）。指令仍是 16 字节。
- **燃料由分支收取**：目标以 `Fuel { n }` 开头的分支收取 `n` 并跳过它；不跳转的 `br_if` 收取其后的 `Fuel`
  （`f`，即燃料加一）；调用收取被调函数首块的燃料；`br_table` 收取所选 `Br` 的燃料并直接跳转，不再分派那条
  `Br`。收取的燃料以及调用在何处耗尽都与之前相同（测试检查经过这些分支后燃料仍然精确）；比较分支只收取能放进
  16 位的燃料。
- **类型化宿主函数直接操作槽**：`func_wrap` 的函数从槽中取参数并把结果写回槽（`WasmParams::from_slots`、
  `WasmResults::write_slots`，文档隐藏，`WasmResults` 若在别处实现则有默认实现），每次调用不经 `Value`、
  不做类型检查：类型在链接导入时已经检查过。`func_new` 和 WASI 的函数仍用 `Value`。`call_host` 不再克隆函数类型。
- **未做的，各占百分之几**：Go 经其恢复循环跳到某个块（`PC_B = k; br loop; br_table`，每次调用约 60 次分派）
  本可直接跳到表的目标，但会一次收取两个块的燃料；`br_if` 以外指令之后落入的 `Fuel` 仍是一次分派；宿主调用仍
  克隆函数的 `Arc`（两次原子操作）；把少见的处理（表、批量内存）移出循环测过，反而变慢（5.3 到 5.5 µs）。
  第 8 节说的“局部变量槽位放在循环的寄存器里”只能交给编译器：安全 Rust 无法指定。
- **不做编译器。** 调用为 5.1 µs，是 wazero 编译器的 1.44 倍（之前 2.58 倍），比 wazero 解释器快 8.2 倍：差距
  缩小了 72%，剩下的是分派本身。第 1 节另立编译器 ADR 的条件（“如果 W5 表明解释器的开销挡住了 akit 的基准测试
  行”）不成立。
- **池的交接**（从 `submit` 到完成，一次一个作业）在实例线程于作业之间睡眠时给调用增加 6.7 µs，前后相同：这是
  一次唤醒，负载下发现下一个作业已在排队的线程不必付出。池的那把锁在剖析中没有出现。

### W6：扣住的响应头与异步 body 过滤器（2026-11-25）

以 ADR-128 实现（akit 的 A166 和 A167），位于 akio-http `Context` 的响应路径中、各传输层之上：HTTP/1.1、HTTP/2
和 HTTP/3 共用一份实现。

- **H1** 即 `Context::hold_response_head(timeout, f)`：普通响应过滤器运行之后，`f` 得到一个 `HeldHead`（状态码、
  可修改的字段、整体发送时的 body），从任意线程恢复（resume）后响应继续，经过外层过滤器发出。也可以用本地响应替换它
  （`HeldHead::respond`，fit 做不到）或使其失败；截止时间一到即切断（关闭连接、重置流）。
- **H2** 即 `Context::add_body_filter(impl BodyFilter)`：一次一个调用，带上次以来写入的全部内容，从任意线程经
  `FilterDone::done(data, trailers)` 应答；最后一次调用带 trailer。响应头被扣住或有调用未返回时，写入的字节最多扣住
  4 MiB（计入 `BodyStream::queued_bytes`，按其限速的生产者像遇到慢客户端一样等待）；过滤器的输出由客户端限速。整体
  body 与文件 body 以流的形式经过它，不带 `Content-Length`（文件在磁盘池上读取，不用 `sendfile`）；流编码作用于过滤器
  的输出。多个过滤器按添加顺序串联。
- **done、log 与 delete** 回调只需要 A48 的 `on_end`（ADR-127）：过滤后的流的结束就是响应的结束，`End::Sent`
  在最后一次调用的输出之后。
- 与第 5 节草案的不同：响应头在普通过滤器之后、外层过滤器之前扣住（缓存能看到插件的修改）；被扣住 body 的上限是
  akio-http 的 4 MiB，插件自己的 `max_body_bytes` 仍由 akit 执行；在 HTTP/2（`H2Responder::reset`）和 HTTP/3
  （不公开的传输接口中的 `ConnSink::reset`、`BodySink::reset`，由 akio-h3 实现）上，切断需要显式重置，因为在那里
  丢弃未应答的响应会让流保持打开。
- 测试：`crates/akio-http/tests/response_hooks.rs`（HTTP/1.1 与 h2）和 `crates/akio-h3/tests/response_hooks.rs`
  （h3）：扣住并恢复的响应头（整体、流式、两次）、本地响应、截止时间、带 trailer 的流式/整体/文件 body 过滤、扣到末尾
  的 body、串联的过滤器、过滤器之后的 `compress`、失败的调用、不受影响的 `HEAD` 与 `204`、经过过滤器限速的
  2–3 MiB body，以及 h3 上一次写出超过流发送缓冲区的 2 MiB 输出。
