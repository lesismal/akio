# `unsafe` review

English | [简体中文](unsafe-review.zh-CN.md)

Status: 1.0 stabilization review, 2026-11-14. Re-run the inventory and update this page whenever
`unsafe` is added, removed or its invariant changes.

`only` is a network library: a memory-safety bug in it is a remote-code-execution bug in its
users. This page is the policy for `unsafe` code, the checklist each `unsafe` site must pass,
the procedure for adding new ones, the inventory, and the findings of the 1.0 review.

## 1. Where `unsafe` may live

| Crate | Status | Why |
|---|---|---|
| `only-sys` | `unsafe` allowed (crate-wide) | the one place for raw syscalls, and the workspace's own OS bindings (`ffi`: C types, constants, `#[repr(C)]` structs, `extern "C"` declarations; no `libc` crate): epoll/kqueue, eventfd/pipe, sockets, `sendfile`, `recvmmsg`/`sendmmsg` + cmsg, process plumbing for prefork (`pre_exec`, signals), the kernel CSPRNG (`getrandom` / `getentropy`) |
| `only-uring` | `#![deny(unsafe_code)]`, allowed in `group`, `reactor` and `ring` only | io_uring submission entries point into memory the kernel writes asynchronously; `ring` is the own io_uring binding (setup/enter/register, mmap'd SQ/CQ rings; no `io-uring` crate) |
| `only-ebpf` | `#![deny(unsafe_code)]`, allowed in `sys` only | raw `bpf(2)` and socket options (no libbpf/aya) |
| `only-dpdk` | `#![deny(unsafe_code)]`, allowed in `pmd` and `sys` only; the TCP/IP stack (`net`) is `#![forbid(unsafe_code)]` | FFI to DPDK through the C shim `csrc/shim.c` (EAL, ports, mbuf rx/tx bursts); TAP (`/dev/net/tun`, `TUNSETIFF`) and AF_PACKET sockets through `only_sys::ffi` |
| `only-crypto` | `#![deny(unsafe_code)]`, allowed in the ten CPU-instruction modules `aes::hw`, `gcm::hw` (with `gcm::hw::vaes`), `hash::hw`, `crc::hw`, `chacha::hw`, `cpu::hw`, `ec::hw`, `curve25519::hw`, `bignum::hw`, `bignum::ifma` only | AES-NI / ARMv8 AES, PCLMULQDQ / PMULL, SHA-NI / ARMv8 SHA, SSE4.2 / ARMv8 CRC32 and AVX2 intrinsics (`#[target_feature]` functions), `asm!` for the AES-GCM kernel and the CRC fold on VAES / VPCLMULQDQ + AVX-512 (those intrinsics are newer than the MSRV), `asm!` with BMI2 `mulx` and ADX `adcx`/`adox` for the P-256 and Curve25519 field arithmetic and the RSA Montgomery multiplication and squaring, `asm!` with AVX-512 IFMA for the RSA exponentiation (not stable at the MSRV either), CPUID / XGETBV for detecting VAES, AVX-512, IFMA, BMI2 and ADX; each call behind the run-time detection of `cpu.rs`; the portable fallbacks and the rest of the public-key code (portable bignum arithmetic, point formulas, the RSA protocol code, DER) are safe Rust |
| `tools/ct-dudect` | `#![deny(unsafe_code)]`, allowed in `timer` only | the statistical timing test (docs/constant-time.md): two `asm!` reads of the cycle counter (`lfence; rdtsc; lfence` on x86_64, `isb; mrs cntvct_el0` on aarch64), registers only, no memory; not published |
| every other crate (`only`, `only-core`, `only-x509`, `only-buf`, `only-timer`, `only-pool`, `only-epoll`, `only-tls`, `only-http`, `only-ws`, `only-mux`, `only-socks`, `only-arpc`, `only-grpc`, `only-protobuf`, `only-protobuf-build`, `only-kcp`, `only-quic`, `only-h3`, `only-turn`, `only-dtls`, `only-srtp`, `only-rtp`, `only-sctp`, `only-ice`, `only-webrtc`, `only-media`, `tools/echo-bench`, `tools/protobuf-test`) | `#![forbid(unsafe_code)]` | pure Rust on top of the above |

Tests, examples and benches are separate crates; they may use `unsafe` for test-only libc calls
(`setrlimit`, `SO_LINGER`, CPU affinity, a counting allocator), held to the same comment rule.

Workspace lints (`Cargo.toml`), on for every crate:

- `unsafe_op_in_unsafe_fn = "deny"`: the body of an `unsafe fn` is not an implicit `unsafe`
  block; each operation needs its own block and comment.
- `clippy::undocumented_unsafe_blocks = "deny"`: every `unsafe` block and `unsafe impl` has a
  `// SAFETY:` comment.
- `clippy::missing_safety_doc = "deny"`: every public `unsafe fn` has a `# Safety` section.
- `clippy::unnecessary_safety_comment` / `unnecessary_safety_doc = "warn"`: no stale `SAFETY:`
  comments on safe code.

Clippy only sees code compiled for the host, so CI runs it on Linux and macOS, and
`tools/unsafe-inventory.py --check` checks the comments on all platforms at once.

## 2. Checklist: what every `unsafe` site must satisfy

An `unsafe` block is accepted only if its `SAFETY:` comment (or the `# Safety` section of an
`unsafe fn`) answers each item that applies, and the code makes it true:

1. **Validity of pointers.** Every pointer handed to the kernel or dereferenced is non-null,
   aligned for its type, points into one live allocation, and covers the full length passed
   (`iov_len`, `msg_namelen`, `msg_controllen`, `optlen`, `bpf_attr` size...). Lengths come
   from `size_of`/`len()` of the same object, never from a separate constant.
2. **Lifetime across the call.** Memory referenced by a syscall lives until the syscall returns;
   memory referenced by an *asynchronous* operation (io_uring SQE, provided-buffer ring, BPF map
   value) lives until the kernel can no longer touch it: the completion arrived, or the ring /
   map that holds the reference is destroyed first (field order and `Drop` documented).
3. **Aliasing.** While the kernel may write a region, Rust holds no `&`/`&mut` that covers it,
   and no `Vec`/`Box` that asserts uniqueness over it; Rust borrows only a range the kernel has
   handed back. Writes to memory shared with the kernel (ring tails, entries) go through raw
   pointers or atomics with the ordering the protocol requires.
4. **Initialisation.** Values read back are initialised: plain-old-data zeroed with
   `mem::zeroed` only for C structs where all-zero is valid; lengths from the kernel are clamped
   to the buffer (`min(size)`); a sockaddr is read according to the family the kernel wrote.
5. **Integer conversions.** Products and sums that size an allocation or an iovec use checked
   arithmetic; casts to C types (`u16` lengths, `c_uint` counts) are checked or proven in range.
6. **Ownership of file descriptors.** A raw fd becomes an `OwnedFd`/`TcpStream` exactly once,
   immediately after the syscall that created it and before any fallible step, so every error
   path closes it; a borrowed fd is never closed.
7. **`Send`/`Sync`.** An `unsafe impl Send/Sync` says which non-thread-safe field (raw pointer)
   it overrides and why no other thread can reach the data (moved, not shared; heap address
   stable).
8. **ABI layout.** Structs passed to the kernel are `#[repr(C)]`, field-for-field identical to
   the UAPI definition (padding explicit), with compile-time size assertions where a mirror of
   another crate's type is used.
9. **Panics and unwinding.** No panic can leave a kernel-visible structure half-written in a way
   that a later operation trusts; callbacks run outside `unsafe` blocks under `catch_unwind`.
10. **Smallest scope.** The block contains only the unsafe operations, not surrounding safe
    logic; prefer a safe wrapper with the invariant enforced by types (e.g. `Map<K, V>` fixes
    key/value sizes at creation) over a comment.

## 3. Procedure for new `unsafe`

1. First look for a safe alternative (`std`, an existing `only-sys` wrapper, a typed wrapper).
   New `unsafe` goes into `only-sys` unless it must live next to backend state (io_uring) or
   the BPF loader; a crate that is `forbid(unsafe_code)` stays so.
2. Write the `SAFETY:` comment against the checklist above; for an `unsafe fn` write a
   `# Safety` section with the caller's obligations.
3. Add a test that exercises the invariant (bounds, error paths, wrap-around); if the code is
   pure memory manipulation, make it runnable under Miri (no syscalls in that test).
4. Run locally: `cargo clippy --workspace --all-targets -- -D warnings` on Linux and macOS,
   `python3 tools/unsafe-inventory.py --check`, Miri for the touched crate where it applies,
   and the io_uring suite (`ONLY_TEST_BACKEND=uring`) for backend changes.
5. The PR description lists each new or changed `unsafe` site; a reviewer other than the author
   checks it against the checklist. Update the inventory table below.

## 4. Tools

| Tool | What it covers | Command |
|---|---|---|
| Clippy lints | comments present (host platform) | `cargo clippy --workspace --all-targets -- -D warnings` |
| Inventory script | counts and comment check, all platforms | `python3 tools/unsafe-inventory.py [--markdown] [--check]` |
| Miri | UB in pure-Rust code: aliasing (Stacked Borrows), out-of-bounds, uninitialised reads, data races | `cargo +nightly miri test -p <crate> --lib` (Linux nightly image; `MIRIFLAGS=-Zmiri-disable-isolation`) |
| loom | interleavings of `only-core`'s lock-free primitives | `RUSTFLAGS="--cfg loom" cargo test -p only-core --lib --release -- loom` |
| AddressSanitizer | out-of-bounds / use-after-free across FFI, including syscall paths Miri cannot run | `RUSTFLAGS=-Zsanitizer=address cargo +nightly test -Zbuild-std --target <host> -p <crate>` |
| ThreadSanitizer | data races between I/O threads, wakers and senders | as above with `-Zsanitizer=thread` |
| Fuzzing | parsers and protocol state machines (remote input) | `cargo fuzz` targets (separate work item) |
| cargo-deny / cargo-audit | vulnerable, unsound or yanked dependencies | `cargo deny check`, `cargo audit` |

Miri cannot execute syscalls (sockets, epoll, io_uring, bpf), so the syscall paths are covered
by the sanitizers and the Linux/macOS test suites (epoll and io_uring backends); the
kernel-shared memory logic of io_uring (`BufRing`, `KernelBuf`) has syscall-free unit tests that
do run under Miri.

Miri does not interpret SIMD intrinsics either: under Miri `only-crypto` detects no CPU feature
and runs its portable code (`cargo +nightly miri test -p only-crypto --lib -- aes:: gcm:: hash::
crc:: chacha:: field:: ec:: curve25519:: x25519:: …`; it cannot run `asm!` either). The
CPU-instruction modules are checked instead by comparing every hardware path with the portable
one (unit tests `hardware_matches_portable` / `hardware_matches_table`, `ec::hw` and
`curve25519::hw` `matches_portable` on random and edge values, `ec::hw` `points_match_portable`
for the whole-point routines against the portable formulas limb for limb (random points with
random `Z`, Wycheproof points, `P + P`, `P + (-P)`, the identity), `twin_matches_portable` for the
P-256 operations, `safegcd` `matches_fermat`), by running all KATs (NIST CAVP, RFC, Wycheproof) twice, normally and with
`ONLY_CRYPTO_PORTABLE=1`, on x86_64 and aarch64, and by the differential fuzz targets
`crypto_hash`, `crypto_aead` and `crypto_sig_verify`. The `asm!` kernel of `gcm::hw::vaes` never runs under Miri
(nothing is detected) and is compared with the 128-bit kernel and the portable code at every
length 0..=600 and at large sizes, misaligned, in place and out of place, with the 32-bit
counter wrapping, and against ring (`gcm::tests`); those tests must run natively on a CPU with
VAES and AVX-512 (Zen 4, Ice Lake and later) to cover it; the `ec::hw` and `curve25519::hw`
comparisons likewise need BMI2 and ADX.

## 5. Inventory

Produced by `python3 tools/unsafe-inventory.py --markdown` (library code under `src/`, unit
tests included; integration tests, examples and benches in the last column). Crates not listed
contain no `unsafe`.

| Crate | blocks | `unsafe fn` | `unsafe impl` | tests/examples/benches |
|---|---:|---:|---:|---:|
| `only` | 0 | 0 | 0 | 12 |
| only-dpdk | 31 | 0 | 1 | 0 |
| only-ebpf | 11 | 3 | 0 | 1 |
| only-http | 0 | 0 | 0 | 8 |
| only-crypto | 102 | 66 | 0 | 0 |
| only-sys | 77 | 3 | 3 | 0 |
| only-uring | 34 | 4 | 1 | 0 |
| ct-dudect | 2 | 0 | 0 | 0 |
| **total** | **257** | **76** | **5** | **21** |

By purpose:

| Where | Count | Purpose | Main invariants |
|---|---:|---|---|
| `only-sys/src/ffi/` | 5 + 7 in the layout tests, `unsafe fn errno_location`, `cmsg_firsthdr`, `cmsg_nxthdr` | the own OS bindings: `extern "C"` declarations of the C library (Linux) / libSystem (macOS), constants, `#[repr(C)]` structs, the `CMSG_*` helpers, `cpu_set_t`, errno | see "The own syscall layer" below |
| `only-sys/src/net.rs` | 15 | `socket`/`bind`/`listen`/`connect`, `setsockopt`, `sendfile`, `SocketAddr` -> `sockaddr_storage` | sockaddr length matches family; fd owned before any fallible step |
| `only-sys/src/poller.rs` | 12 + `impl Send` | epoll / kqueue create, ctl, wait | event buffer has `BATCH` initialised entries; kevent `udata` is an opaque token |
| `only-sys/src/process.rs` | 12 | prefork plumbing: `pre_exec` hook (`fcntl` clearing `FD_CLOEXEC`, `PR_SET_PDEATHSIG`, `sched_setaffinity`), `take_inherited_fd`, self-pipe signal handler (`sigaction`, `write` from the handler), `kill` | the hook only makes async-signal-safe calls and allocates nothing (all data built before `fork`); an inherited fd is owned at most once per process (`TAKEN` set); the handler saves and restores `errno` |
| `only-sys/src/waker.rs` | 10 | eventfd (Linux) / pipe (macOS) waker, `EventFd` for io_uring | fds owned immediately; 8-byte eventfd writes from a live `u64` |
| `only-sys/src/udp.rs` | 14 + 2 `impl Send` | `recvmmsg`/`sendmmsg`, UDP GSO (`UDP_SEGMENT`) / GRO cmsgs, sockaddr parsing | iovecs inside one allocation (checked size); headers rebuilt before each call; cmsg walked with `CMSG_*` within `msg_controllen`; `Batch<'d>` borrows send data for the call |
| `only-crypto/src/aes/hw.rs` | 26, 26 `unsafe fn` (x86_64 and aarch64 variants; 6 stubs for other targets, never called) | AES-NI / ARMv8 AES key schedule, block encryption and decryption, CTR eight blocks at a time (round count as a const generic, unrolled) | a `hw::Keys` is only constructed after `cpu::cpu_has(Feature::Aes)` (`is_x86_feature_detected!("aes")` + `sse2` / `is_aarch64_feature_detected!("aes")`); loads and stores are unaligned and stay within 16-byte arrays or 16-byte pieces of a `&mut [u8; 128]` chunk; `SubWord` in the key schedule uses the AES instruction, no key-indexed table |
| `only-crypto/src/gcm/hw.rs` | 18, 17 `unsafe fn` (2 stubs for other targets) | GHASH on PCLMULQDQ / PMULL (eight blocks per reduction, Karatsuba) and AES-GCM encryption/decryption fused into one pass (AES-NI / ARMv8 AES rounds and the carry-less products in the same loop); the call into `vaes` | `Powers` exist only after `cpu_has(Feature::Clmul)` (PCLMULQDQ + SSSE3 + SSE4.1 / the aarch64 AES extension); the safe wrappers re-check `cpu_has` (and `Feature::Aes` for the fused kernel, `Aes`, `Clmul`, `Vaes` and `Avx512` for the wide one) before every call; every load reads 16 bytes inside a slice whose length the wrapper made a multiple of 16 (GHASH) or 128 (fused); the wide kernel gets whole 256-byte groups within both the input and the output slice, and the same pointer twice only when working in place |
| `only-crypto/src/gcm/hw/vaes.rs` | 2, 1 `unsafe fn` | AES-GCM seal / open on VAES + VPCLMULQDQ + AVX-512 as one `asm!` block per direction (sixteen blocks per iteration in four zmm registers, GHASH interleaved with the AES rounds, one Montgomery reduction per group; the intrinsics are not stable at the MSRV) | entered only when `Powers` carry wide powers (made only after `cpu::has` of AES, VAES, AVX-512) and `wide_available()` re-confirms AES-NI, PCLMULQDQ, VAES, VPCLMULQDQ, AVX2, AVX-512 F/BW/VL and the OS ZMM state just before; reads the round keys `rk[0]` and `rk[r-13..=r]` (index >= 1, r <= 14), 256 bytes of powers and constants, and `n * 256` bytes of input, writes `n * 256` bytes of output (a group is loaded before it is stored, so in place works) and the 16-byte GHASH state; outputs in explicit registers, all vector registers and flags clobbered (`clobber_abi("C")`), no stack, `vzeroupper` at the end |
| `only-crypto/src/cpu.rs` (`cpu::hw`) | 5, 1 `unsafe fn` | CPUID (leaves 0, 1, 7) and XGETBV (XCR0) for VAES, VPCLMULQDQ, AVX-512 and the OS YMM / ZMM state, and BMI2 + ADX (leaf 7, no OS state) | CPUID exists on every x86_64 CPU and leaves 1 and 7 are read only when leaf 0 reports them; XGETBV only after CPUID.1:ECX.OSXSAVE; not compiled under Miri |
| `only-crypto/src/hash/hw.rs` | 8, 8 `unsafe fn` (2 stubs) | SHA-1 and SHA-256 compression on SHA-NI (x86_64) and the ARMv8 SHA1/SHA2 instructions | the wrappers call only when `cpu_has(Feature::Sha)` (SHA + SSSE3 + SSE4.1 / `sha2`); loads read 16-byte pieces of the 64-byte chunks of the block slice, the state is loaded from and stored to the live `[u32; 5]` / `[u32; 8]` |
| `only-crypto/src/crc/hw.rs` | 15, 9 `unsafe fn` | CRC-32 / CRC-32C: PCLMULQDQ folding (four 128-bit accumulators), from 512 bytes VPCLMULQDQ + AVX-512 folding (four 512-bit accumulators, 256 bytes per step, one `asm!` block), and the SSE4.2 `crc32` instruction on x86_64, the ARMv8 CRC32 instructions on aarch64 | called only after `cpu_has(Feature::Clmul)` / `cpu_has(Feature::Crc)` (the 512-bit fold also `Vaes` and `Avx512`, re-checked by `wide_available()` before the call); the folding loop reads 16 bytes at offsets `o` with `o + 16 <= len` (checked by the loop conditions), only with `len >= 64`; the `asm!` fold gets a slice of a nonzero multiple of 256 bytes and reads exactly that, the 80 bytes of constants (`#[repr(C)]`, offsets fixed) and writes a 16-byte array; the fold constants are compile-time functions of the public polynomials |
| `only-crypto/src/chacha/hw.rs` | 2, 1 `unsafe fn` | ChaCha20 eight blocks at a time with AVX2 (8×8 transpose back into blocks) | called only after `cpu_has(Feature::Avx2)`; loads and stores are 32-byte pieces of a `&mut [u8; 512]`; the counter of the eight blocks cannot wrap (checked by the caller) |
| `only-crypto/src/ec/hw.rs` | 14, 2 `unsafe fn` (x86_64 only) | P-256 in `asm!`: Montgomery multiplication and squaring modulo `p` (special reduction, `-p⁻¹ = 1`) and modulo the order `n`, addition, subtraction, `2ᵏ·a`, `3·a`; whole Jacobian doubling (also `n` in a row), addition and mixed addition as one block each over a stack frame; 59 safegcd divsteps; AVX2 scans of the ECDH window table and of the wide fixed-base comb (`#[target_feature]` functions) | the field, order and point blocks are reached only after `cpu::has(Feature::Adx)` (BMI2 + ADX): the `P256X` twin curve is entered through `P256`'s dispatch, the scalar field checks before each call, every function debug-asserts it; the field blocks read only the 32-byte limb arrays behind their pointer operands (`pure`, `readonly` or `nomem`, `nostack`) and write only declared registers; a point block reads and writes only its frame (a local `[u64; 48..76]` passed in `rdi`; every address is `rdi` plus a constant below the frame size), `nostack`, and keeps the compiler-reserved `rbx` (its shift count 32) in the frame header, restoring it before the block ends; the divsteps block is registers only (base instructions); the AVX2 functions are called only after `cpu::cpu_has(Feature::Avx2)` and load 32 bytes from each 4-limb array of a live table entry; no branches but the divsteps loop counter (corrections by `cmov`/`sbb`/`sar` masks) |
| `only-crypto/src/curve25519/hw.rs` | 5 (x86_64 only) | the X25519 ladder's arithmetic modulo `2²⁵⁵ - 19` on four limbs in `asm!` (multiplication, squaring, `121665·a`, addition, subtraction; folds by `2²⁵⁶ ≡ 38`) | `ladder` is called only after `hw::enabled()` (`cpu::has(Feature::Adx)`), debug-asserted in each function; same memory and register discipline as `ec/hw.rs`, no branches |
| `only-crypto/src/bignum/hw.rs` | 5, 1 `unsafe fn` (x86_64 only) | RSA Montgomery multiplication and squaring in `asm!` for 16, 24, 32, 48 and 64 limbs (BMI2 `mulx` with the ADX carry chains, rows unrolled with `.rept`, the final subtraction by `cmovnz`); the AVX2 scan of the exponentiation table (`#[target_feature]` function) | the blocks are reached only from `Mont::mul_into` / `sqr_into` after `hw::enabled()` (`cpu::has(Feature::Adx)`), debug-asserted in each function; they read the `N`-limb arrays behind `a`, `b`, `m` and write the `N`-limb output (an exclusive borrow) and a local `2N`-limb scratch buffer (`MaybeUninit`, every limb written before it is read), every displacement below `16N` bytes, no stack; the scan is called only after `cpu_has(Feature::Avx2)` (asserted) and loads 32 bytes from each 4-limb chunk of a live table entry; no branches but the row counters |
| `only-crypto/src/bignum/ifma.rs` | 2 (x86_64 only; one per macro, three instances) | RSA exponentiation on AVX-512 IFMA: almost Montgomery multiplication over 20, 32 and 40 digits of 52 bits in `ymm` / `zmm` registers, one `asm!` block each (`vpmadd52luq`/`vpmadd52huq`, `valignq`, opmask carries; the intrinsics are not stable at the MSRV) | reached only from `Mont::pow` after `ifma::enabled()` (`cpu::has(Feature::Ifma)`: AVX-512 F/BW/VL, IFMA and the OS ZMM and opmask state), debug-asserted; reads the `D`-digit arrays behind `a`, `b`, `m`, writes the `D`-digit output, unaligned, no stack; all vector and mask registers clobbered (`clobber_abi("C")`), the output pointer parked in `xmm31` during the loop, `vzeroupper` at the end; no branches but the digit counter |
| `only-sys/src/random.rs` | 2 (one per OS) | `getrandom(2)` (Linux), `getentropy(2)` (macOS) for `only-crypto` | the kernel writes at most `buf.len()` bytes into a live `&mut [u8]` (`getentropy` at most 256 per call); a short `getrandom` read advances by the returned count |
| `only-uring/src/reactor.rs` | 12 + 3 in tests, `unsafe fn slice`, `impl Send for Loop` | SQE push, provided-buffer ring (`BufRing`), kernel-written buffers (`KernelBuf`), accepted fds | nothing in flight when buffers are freed (cancel-all + drain, else leak); kernel-owned buffers never borrowed; ring entries written by raw field pointers; tail stored with `Release` |
| `only-uring/src/ring.rs` | 16, `unsafe fn push`, `register`, `register_buf_ring` | own io_uring binding: `io_uring_setup`/`enter`/`register` through `syscall(2)`, `mmap` of the SQ/CQ rings and SQE array, SQ/CQ head and tail atomics, probe, enable-rings, buffer-ring registration | offsets from the kernel bounds-checked against each mapping; SQE slot written only when the queue is not full, tail published with `Release`; CQEs read between our head and the `Acquire`-loaded tail, head published with `Release`; `SeqCst` fence before reading `SQ_NEED_WAKEUP` (SQPOLL); mappings live as long as the `Ring` |
| `only-uring/src/group.rs` | 3 | `uname` for the kernel-version probe | zeroed `utsname`; kernel NUL-terminates `release` |
| `only-dpdk/src/pmd.rs` | 17, `impl Send for Queue` | calls into the C shim (`rte_eal_init`, port setup, `rte_eth_rx_burst`/`tx_burst`, mbuf alloc/free); frames borrowed from mbufs; a staged tx mbuf written in place | the shim's ABI is integers and opaque pointers only (no DPDK struct layouts in Rust); EAL argv leaked (outlives the EAL), init once (`OnceLock`); an mbuf is owned by exactly one `Queue`/`Mbuf` and freed once (frames not taken by `tx_burst` freed, received ones freed on drop); slices only over the single data segment the shim returned, for the mbuf's lifetime; a `Queue` is used by one thread at a time (moved once to its I/O thread); the staged tx mbuf is freed if not committed |
| `only-dpdk/src/sys.rs` | 14 | TAP (`open`, `TUNSETIFF`), AF_PACKET (`socket`, `bind`, `setsockopt`), `read` / `recvfrom` / `write`, `ppoll` | fds owned immediately (`OwnedFd`); `#[repr(C)]` `ifreq` with the UAPI size; buffers and address structs live across each call, lengths passed are their sizes |
| `only-ebpf/src/sys.rs` | 11, 3 `unsafe fn` | `bpf(2)` (`MAP_CREATE`, `MAP_UPDATE/DELETE_ELEM`, `PROG_LOAD`, `PROG_ATTACH`), `SO_ATTACH_REUSEPORT_[CE]BPF`, `SO_COOKIE` | `#[repr(C)]` attr prefixes identical to UAPI; pointer fields live for the call; key/value sizes fixed by `Map<K, V>` |

### The own syscall layer (`only_sys::ffi`, `only-uring` `ring`)

Design: on Linux the C library's functions are declared (`unsafe extern "C"`) and linked from the
libc `std` already links (glibc or musl); system calls without a wrapper (`bpf`, `io_uring_*`)
go through the C library's variadic `syscall(2)` with per-architecture numbers. Errno, `EINTR`
and `io::Error::last_os_error()` therefore behave exactly as with the `libc` crate. macOS has no
stable syscall ABI: the libSystem functions are declared the same way. No inline `asm!`.

Review checklist for a change to this layer:

1. **Prototypes**: every declaration matches the C header for each supported target (argument
   widths, pointer constness, return type); variadic C functions (`fcntl`, `ioctl`, `open`,
   `prctl`, `syscall`) are declared variadic (arm64 macOS passes variadic arguments on the
   stack) and their variadic arguments are passed as `c_long`/pointer-sized values.
2. **Layouts**: each `#[repr(C)]` struct has compile-time size/alignment (and for io_uring,
   offset) assertions; `epoll_event` is packed on x86_64 only, `kevent` is `packed(4)`;
   `src/ffi/layout.rs` compares every struct's size, alignment and field offsets and every
   constant's type and value with the `libc` crate (dev-dependency) on each target the tests
   run on (macOS aarch64, Linux aarch64, Linux x86_64).
3. **Constants**: per OS and per architecture (`SYS_bpf` 321 on x86_64, 280 on the generic
   table; the io_uring calls are 425-427 everywhere); only targets whose values are present
   compile (`compile_error!` otherwise).
4. **Errno**: results are converted with `io::Error::last_os_error()` right after the call,
   before anything else can clobber errno; the signal handler saves and restores errno via
   `errno_location`.
5. **io_uring rings**: kernel-provided offsets are bounds-checked against their mapping before
   use; the SQ index array is initialised to the identity; memory ordering as in `io_uring(7)`
   (SQ tail `Release` / head `Acquire`, CQ tail `Acquire` / head `Release`, `SeqCst` fence
   before `SQ_NEED_WAKEUP`); SQE builders reproduce what the `io-uring` crate produced, field
   by field (unit test `sqe_builders`); a pushed SQE's buffers outlive its final CQE (the
   existing `KernelBuf` / buffer ring / in-flight cancel / graveyard rules are unchanged).

## 6. Findings of the 1.0 review

Fixed in this review (each with a regression test where one can observe it):

| # | Where | Issue | Fix |
|---|---|---|---|
| F1 | `only-sys` `RecvBatch::with_gro` | `slots * size` unchecked: in release builds an overflowing product wraps, `bufs` is tiny while each iovec still claims `size` bytes, so `recvmmsg` would write past the allocation (heap overflow from a public safe API). | `checked_mul` + `u32` slot check, panic documented; test `recv_batch_rejects_overflowing_size`. |
| F2 | `RecvBatch::recv` / `get` | `got` was not reset on `WouldBlock` or error, so `get(i)` kept returning the previous call's datagrams (in-tree callers iterate `0..n`, so not reachable, but the API was wrong). | `got = 0` before each call; test `recv_batch_forgets_previous_datagrams`. |
| F3 | `RecvBatch::with_gro` | iovec bases were taken from a fresh `&mut bufs[i*size..]` per slot; under Stacked Borrows each reborrow invalidates the pointers derived earlier. | One base pointer from `as_mut_ptr()`, offsets with `add`. |
| F4 | `RecvBatch::reset` | `sockaddr_storage` kept the previous family; a header the kernel left unfilled would be parsed with a stale family. | Family cleared before each receive. |
| F5 | `only-uring` provided buffers | Buffers lived in a `Vec<u8>` (and the eventfd target in a `Box<[u8; 8]>`) while the kernel fills them asynchronously; `on_recv` borrowed `&self.bufs[..]`, a shared reference covering every buffer, including ones the kernel may be writing from an io-wq worker. Aliasing UB in Rust's model. | `KernelBuf`: raw allocation, no `Vec`/`Box`; Rust borrows only the completed buffer through `unsafe fn slice` (bounds-checked). |
| F6 | `BufRing::give` | Wrote entries through `&mut BufRingEntry`; for entry 0 that reference also covers the ring tail (`resv`) the kernel reads concurrently. | Mirrored `#[repr(C)] RawBuf` (size asserted equal to `io_uring_buf`), fields written via raw pointers; tail via `AtomicU16` with `Release`. Miri-runnable test `buf_ring_layout_give_and_publish` checks the layout against `io_uring`'s accessors. |
| F7 | `BufRing::give` | Buffer id not checked against the area. | Asserted (`bid < BUF_COUNT` and slot inside the area); test `buf_ring_rejects_foreign_buffer_ids`. |
| F8 | `only-ebpf` `sys::bpf`, `map_update`, `map_delete` | Safe `fn bpf<T>(cmd, &mut T)` accepted any `T`; `map_update<K, V>` let the kernel copy the map's `key_size`/`value_size` bytes from `&K`/`&V` whatever their real size (out-of-bounds read into the map). | Made `unsafe fn` with `# Safety`; callers use a typed `Map<K, V>` whose key/value sizes are `size_of::<K/V>()` at creation, so its methods are safe. |
| F9 | `attach_reuseport_cbpf` | Program length truncated to `u16`. | `InvalidInput` error instead. |
| F10 | `only-sys` macOS paths (`socket_of`, pipe `Waker`, `kqueue` `Poller`) | fd leaked when the `fcntl` after creation failed. | Wrapped in `OwnedFd` before the fallible step. |
| F11 | `only-uring` loop teardown | `Loop` closed the ring and then freed the provided buffers, buffer ring and wake buffer while operations could still be in flight: part of the kernel's ring teardown runs in asynchronous exit work, and after the shutdown timeout (or an `io_uring_enter` error) the loop exited with connections and their multishot `recv`s still armed, so a late completion could write freed memory. | The loop counts operations in flight (one final CQE per SQE); `drain_inflight` submits `ASYNC_CANCEL_ANY` and reaps completions until none is left before the memory is dropped (closing any fd an accept still delivers); if that does not finish within 2 s the memory is deliberately leaked, never freed. The io_uring suites log no leak. |
| F12 | `only-core` `consume_datagrams` | Linux-only dead code made `clippy -D warnings` fail on Linux (from the UDP batching change). | `#[cfg(not(target_os = "linux"))]`. |

Accepted (documented, no change needed now):

- **Buffer ids given back once.** `give_back` runs only for a `bid` carried by a completion,
  so at most `BUF_COUNT` entries are outstanding and the slot at the tail is never one the kernel
  is reading. Now also guarded by the range assertion (F7).
- **`unsafe impl Send`** for `Poller` (kevent `udata` is a token, never dereferenced),
  `RecvBatch` (pointers into its own heap buffers, which move with it), `SendBatch` (pointers
  dangle between batches but are rebuilt from a live `Batch<'d>` before each send) and `Loop`
  (built on one thread, then owned by its I/O thread; SQE pointers target heap memory that does
  not move). None of them implements `Sync`.
- **Kernel-provided data is trusted for layout**: sockaddr family, `cmsg_len`, `msg_len`
  (clamped), CQE buffer ids (now range-checked). This is the kernel ABI contract.
- **No library dependency with `unsafe`** remains (rustls/ring left with quinn-proto, str0m with the own WebRTC stack); dev-dependencies are tracked with `cargo deny`/`cargo audit`. TLS itself is the own `only-tls` (`#![forbid(unsafe_code)]`, wave C) on `only-crypto` and `only-x509`, so the TLS record and handshake code of every TCP protocol carries no `unsafe` outside `only-crypto`'s CPU-instruction modules; QUIC is the own `only-quic` (`#![forbid(unsafe_code)]`, wave D, replacing `quinn-proto` with `rustls`/`ring` inside it), so packet protection, frames, streams and recovery of QUIC and HTTP/3 carry none either. DEFLATE/zlib/gzip is the
  own `only-deflate` (`#![forbid(unsafe_code)]`), which replaced `flate2` with `zlib-rs`. The
  `libc` and `io-uring` crates are gone from the libraries (wave B): `only_sys::ffi` and
  `only-uring`'s `ring` replace them (`libc` stays a dev-dependency, for the layout comparison
  and test-only calls).

## 7. Verification results (this review)

- `cargo clippy --workspace --all-targets -- -D warnings`: clean on macOS (aarch64) and Linux
  (Docker `rust:1`, 1.98), with the stricter lints above.
- `tools/unsafe-inventory.py --check`: every site documented.
- Re-verified after merging `main` at `fa5f413` (strict lints, fuzzing modules, chaos fixes
  such as the io_uring `graveyard` and reset watch): `cargo clippy --workspace --all-targets
  --all-features -- -D warnings` and `RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps
  --all-features` clean on macOS and Linux; `cargo test --workspace` green on macOS and Linux
  (epoll); `ONLY_TEST_BACKEND=uring` green for `only`, only-uring, only-http, only-ws,
  only-kcp and only-quic; chaos seeds 1..30 on io_uring green; no in-flight leak logged. The
  new chaos code added no `unsafe`.
- Test suites (before the merge): macOS `cargo test --workspace` green; Linux `cargo test --workspace` (epoll) and
  `ONLY_TEST_BACKEND=uring` for `only`, `only-uring`, `only-sys`, `only-ebpf`, `only-http`,
  `only-ws`, `only-kcp`, `only-quic` green.
- Supply chain: `cargo deny check` reports `advisories ok, bans ok, licenses ok, sources ok`;
  `cargo audit -D warnings` is clean. The only advisory found, RUSTSEC-2026-0009 in `time`
  0.3.45, is ignored with its reason in `deny.toml` and `.cargo/audit.toml`: it is reached only
  through `rcgen`, a dev-dependency that generates test certificates and never parses RFC 2822
  input, and the fixed `time` 0.3.47 needs Rust 1.88, above the 1.85 MSRV the CI checks test
  targets against. Remove the exception when the MSRV moves to 1.88.

### Miri (nightly 1.102, `-Zmiri-disable-isolation`, Stacked Borrows)

| Crate (`--lib`) | Result |
|---|---|
| only-buf, only-timer, only-pool | pass (4 / 5 / 5 tests) |
| only-http | pass (27 tests, 35 s) |
| only-mux, only-socks, only-arpc, only-h3 | pass (1 / 1 / 3 / 2) |
| only-kcp | pass (5 tests, 4-6 min) |
| only-uring (`buf_ring`, `kernel_buf` tests) | pass (3): the kernel-shared memory code of F5-F7 |
| only-ws | 15 of 20 pass; the other 5 (permessage-deflate round trips and exhaustive split loops) do not finish within 5-15 min under Miri |
| only-core | no unit tests outside loom / integration tests |
| only-quic (own QUIC since wave D) | not run under Miri: `#![forbid(unsafe_code)]` with no `unsafe` of its own; its unit, simulated-network and corpus replay tests run natively |
| only-ebpf | does not finish within 15 min (its unit tests run a cBPF interpreter over large input sets; safe code, the `sys` module is not exercised) |
| only-deflate | pass (all unit tests; the corpus replays are skipped in CI like elsewhere) |
| only-grpc | pass, including `tests::framing_and_gzip` since gzip moved to only-deflate (below) |
| only-grpc (before wave A, flate2 + zlib-rs) | **UB reported in a dependency**: `tests::framing_and_gzip` fails in `zlib_rs::allocate::zfree_rust` while dropping a `flate2::write::GzEncoder` (`zlib_rs::stable::Deflate::drop` -> `deflate::end` deallocates memory that a protected `&mut` function argument still covers). Reproduces under Tree Borrows. `zlib-rs` 0.6.8 is the latest release; `only` itself has no `unsafe` on that path. |

The `zlib-rs` finding was an aliasing-model violation inside the dependency, not an observed
memory corruption (worth reporting upstream to trifectatech/zlib-rs with the reproduction above).
It no longer applies to `only`: DEV-PLAN wave A replaced `flate2`/`zlib-rs` with the pure safe
Rust `only-deflate`, so the CI Miri job runs `framing_and_gzip` again, and also only-deflate's
own tests and only-ws's permessage-deflate round trips. It still skips the `fuzzing::`
corpus-replay tests (minutes per crate under Miri; the fuzz job runs those inputs natively).
(`flate2` had been moved from `miniz_oxide` to `zlib-rs` because of a real data-loss bug in the
former, see the WebSocket notes; only-deflate has regression tests for that class of bug.)

### Sanitizers

ASan and TSan could not be run in this review: in the available Linux environment (Docker on
Apple silicon, linuxkit 6.12 aarch64 kernel) even an empty `fn main` built with
`-Zsanitizer=address` or `-Zsanitizer=thread` crashes with SIGSEGV at start-up (the sanitizer
runtimes do not support that VM's address-space layout; `setarch -R` does not help and
`vm.mmap_rnd_bits` cannot be changed). They are proposed as a CI job on `ubuntu-latest`
(x86_64), where both are supported.
