# ADR-178：akio-crypto 中的 Argon2id，其 lane 在作用域线程上运行

[English](178-argon2id.md) | 简体中文

状态：已采纳（2026-11-26）。akit 的 A230（连同 A231 XChaCha20-Poly1305，后者没有新增设计）。

## 背景

akit 要打开和写入 fit 的加密存储（`fitstore`），其密钥由口令经 Argon2id（RFC 9106）派生，时间、
内存和 lane 数由文件头指定：fit 写入时用 3 遍、64 MiB、4 个 lane，读取时最多接受 16 遍和 1 GiB。
akio-crypto 原有 HKDF、PBKDF2 和 bcrypt，没有 Argon2，也没有 Argon2 所依赖的 BLAKE2b。Argon2 是本
crate 第一个由调用方以兆字节和秒为单位选择内存与时间、且其 lane 本就设计为并行运行的函数；本 crate
其他函数只需微秒级时间，也几乎不分配内存。

## 决定

1. **`hash::Blake2b`**（RFC 7693）：创建时选定 1 到 64 字节的摘要长度和最长 64 字节的密钥（`new`、
   `new_keyed`、`update`、`finalize_into`、一次性的 `digest`），以及实现 `Hash` trait 的
   **`hash::Blake2b512`**（可用于 HMAC、HKDF）。可移植 Rust，按构造即为常数时间。
2. **`kdf::argon2id(password, salt, time, memory_kib, lanes: u8, out)`**：Argon2id 0x13 版，没有
   secret 和关联数据，与 Go 的 `argon2.IDKey` 相同。先检查 RFC 9106 的界限，越界返回错误而不是
   panic：盐短于 8 字节、输出短于 4 字节或某个输入超过 `u32::MAX` 字节为 `Error::InvalidLength`；
   `time` 或 `lanes` 为 0、`memory_kib` 每个 lane 不足 8，为新增的 `Error::InvalidParameter`。
   （Go 会把每 lane 不足 8 的内存提升到下限；fit 从不写出这种值。）
3. **内存在任何计算之前一次性、可失败地分配**（`Vec::try_reserve_exact`）：`m' = 4·p·⌊m / 4p⌋` 个
   1 KiB 的块，调用返回时释放。分配器拒绝的大小返回新增的 `Error::OutOfMemory`，而不是 abort。
   来自外部的参数由调用方限定（akit 在派生之前按 fit 的界限检查文件头），因为允许 overcommit 的
   操作系统可能答应一个它无法兑现的大小。
4. **lane 在作用域线程上运行。** 每一遍的每个 slice 填充各 lane 的 segment，RFC 9106 允许并行：
   一个 segment 只读取之前 slice 的块（任意 lane）和自己 segment 中更早的块。每个 slice 用
   `split_at_mut` 把内存切成各 lane 的 segment（`&mut`）和它前后的块（`&`），因此线程之间没有
   共享的可变状态，不需要锁，也不需要 `unsafe`。最多使用 `min(lanes, available_parallelism)` 个
   线程（`std::thread::scope`，线程名 `akio-argon2`），最后一组 lane 在调用线程上运行；无法启动的
   线程，其 lane 交给调用线程。输出与线程数无关（测试覆盖 1 到 16 个线程）。
5. **该函数会阻塞**，耗时与 `time × memory_kib` 成正比（fit 的设置需要
   零点几秒）。它用于控制线程或逻辑池，绝不用于 I/O 线程（规则 1–3）；文档中写明了这一点。

## 后果

- akit 像 fit 一样在控制线程上一次调用派生存储的密钥，并能读取 fit 的存储。测试：RFC 9106 的
  Argon2id 向量（带 secret 和关联数据，通过 crate 内部接受它们的形式）、Go 的 `IDKey` 在八种设置下
  的输出（含 fit 的设置；`tests/data/go_x_crypto.txt`，由 `go_x_crypto.go` 基于
  golang.org/x/crypto v0.58.0 打印）、RFC 7693 以及 Go 的 BLAKE2b 在 100 组长度和密钥下的输出，
  以及各项界限。
- akio-crypto 第一次启动线程，只为一次调用、限定在其作用域内：没有线程比 `argon2id` 活得更久，
  拒绝创建线程的主机在单线程上得到相同的结果。
- 时序：第一遍的前半部分按与口令无关的方式寻址内存（Argon2i）；其余部分按由口令派生的下标读取块，
  这是设计使然（Argon2d 抵抗时间-内存折中的方式）。这是 RFC 9106 的 Argon2id 本身，不是本实现的
  泄漏；BLAKE2b 和压缩函数是常数时间的（`docs/constant-time.md`）。
- 未做：压缩函数的 SIMD（Go 和 libargon2 使用 SSE/AVX2 或 NEON）；单独的 Argon2i 和 Argon2d；
  公开 API 中的 secret 或关联数据。与 Go 和 RustCrypto `argon2` 的速度对比留给基准任务
  （DEV-PLAN 第 4 节）。
