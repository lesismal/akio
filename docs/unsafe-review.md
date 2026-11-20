# `unsafe` review

English | [简体中文](unsafe-review.zh-CN.md)

Status: 1.0 stabilization review, 2026-11-14; `only-crypto`'s `fill` module (AEAD output into
uninitialised spare capacity) added 2026-11-16; `only-buf`'s `slab` module (UDP receive slabs,
ADR-024) added 2026-11-17. Re-run the inventory and update this page
whenever `unsafe` is added, removed or its invariant changes.

`only` is a network library: a memory-safety bug in it is a remote-code-execution bug in its
users. This page is the policy for `unsafe` code, the checklist each `unsafe` site must pass,
the procedure for adding new ones, the inventory, and the findings of the 1.0 review.

## 1. Where `unsafe` may live

| Crate | Status | Why |
|---|---|---|
| `only-sys` | `unsafe` allowed (crate-wide) | the one place for raw syscalls, and the workspace's own OS bindings (`ffi`: C types, constants, `#[repr(C)]` structs, `extern "C"` declarations; no `libc` crate): epoll/kqueue, eventfd/pipe, sockets, `sendfile`, `recvmmsg`/`sendmmsg` + cmsg, process plumbing for prefork (`pre_exec`, signals), the kernel CSPRNG (`getrandom` / `getentropy`) |
| `only-uring` | `#![deny(unsafe_code)]`, allowed in `group`, `reactor` and `ring` only (and the test-only `eval` harness) | io_uring submission entries point into memory the kernel writes asynchronously; `ring` is the own io_uring binding (setup/enter/register, mmap'd SQ/CQ rings; no `io-uring` crate) |
| `only-ebpf` | `#![deny(unsafe_code)]`, allowed in `sys` and `xsk` only | raw `bpf(2)` and socket options (no libbpf/aya); AF_XDP sockets, their UMEM and rings (`xsk`, ADR-063) |
| `only-dpdk` | `#![deny(unsafe_code)]`, allowed in `pmd` and `sys` only; the TCP/IP stack (`net`) is `#![forbid(unsafe_code)]` | FFI to DPDK through the C shim `csrc/shim.c` (EAL, ports, mbuf rx/tx bursts); TAP (`/dev/net/tun`, `TUNSETIFF`) and AF_PACKET sockets through `only_sys::ffi` |
| `only-buf` | `#![deny(unsafe_code)]`, allowed in `slab` only | receive slabs (ADR-024): one allocation viewed through disjoint owned handles (`ChunkMut` exclusive and writable, `Chunk` shared and read-only), so a received datagram can be handed from the `recvmmsg` slot to only-quic and decrypted in place without a copy; `Arc` reference counting, a raw pointer to the allocation and a `Send`/`Sync` impl for the allocation; the size-class pool and `SharedBuf` stay safe Rust |
| `only-crypto` | `#![deny(unsafe_code)]`, allowed in the twelve CPU-instruction modules `aes::hw`, `gcm::hw` (with `gcm::hw::vaes`), `hash::hw`, `crc::hw`, `chacha::hw` (with `chacha::hw::avx512` and `chacha::hw::ifma`), `cpu::hw`, `ec::hw`, `ec::hw_aarch64`, `curve25519::hw`, `curve25519::hw_aarch64`, `bignum::hw`, `bignum::ifma`, and in `fill` (the AEAD output buffer over a vector's uninitialised spare capacity) only | AES-NI / ARMv8 AES, PCLMULQDQ / PMULL, SHA-NI / ARMv8 SHA, SSE4.2 / ARMv8 CRC32 and AVX2 intrinsics (`#[target_feature]` functions), `asm!` for the AES-GCM kernels on VAES / VPCLMULQDQ with AVX-512 or AVX2 and the CRC fold on VAES / VPCLMULQDQ + AVX-512 (those intrinsics are newer than the MSRV), `asm!` with BMI2 `mulx` and ADX `adcx`/`adox` for the P-256 and Curve25519 field arithmetic and the RSA Montgomery multiplication and squaring, `asm!` with `MUL`/`UMULH` and `ADDS`/`ADCS` chains for the P-256 and Curve25519 field arithmetic on aarch64, `asm!` with AVX-512 IFMA for the RSA exponentiation and Poly1305 and `asm!` for ChaCha20 on AVX-512 (not stable at the MSRV either), CPUID / XGETBV for detecting VAES, AVX-512, IFMA, BMI2 and ADX; each call behind the run-time detection of `cpu.rs`; `fill` so that the TLS record layer (`#![forbid(unsafe_code)]`) can seal and open into a `Vec`'s spare capacity without zero-filling it first (about 10% of a 16 KiB AES-GCM record), with the `unsafe` kept to viewing the buffer as bytes once every byte is written and `Vec::set_len`; the portable fallbacks and the rest of the public-key code (portable bignum arithmetic, point formulas, the RSA protocol code, DER) are safe Rust |
| `tools/ct-dudect` | `#![deny(unsafe_code)]`, allowed in `timer` only | the statistical timing test (docs/constant-time.md): two `asm!` reads of the cycle counter (`lfence; rdtsc; lfence` on x86_64, `isb; mrs cntvct_el0` on aarch64), registers only, no memory; not published |
| `tools/codec-bench` | not published, its own workspace | the benchmark's three one-shot calls into Google's C libbrotli (`brotlic-sys`) to compare only-brotli against it (docs/BENCHMARKS.md); libzstd is called through the safe `zstd` crate |
| every other crate (`only`, `only-core`, `only-x509`, `only-timer`, `only-pool`, `only-epoll`, `only-tls`, `only-http`, `only-ws`, `only-mux`, `only-socks`, `only-arpc`, `only-grpc`, `only-protobuf`, `only-protobuf-build`, `only-kcp`, `only-quic`, `only-h3`, `only-turn`, `only-dtls`, `only-srtp`, `only-rtp`, `only-sctp`, `only-ice`, `only-webrtc`, `only-media`, `tools/echo-bench`, `tools/protobuf-test`) | `#![forbid(unsafe_code)]` | pure Rust on top of the above |

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
| loom | interleavings of `only-core`'s lock-free primitives and of `only-buf`'s slab reuse | `RUSTFLAGS="--cfg loom" cargo test -p only-core -p only-buf --lib --release -- loom` |
| AddressSanitizer | out-of-bounds / use-after-free / leaks across FFI, including syscall paths Miri cannot run | `tools/sanitizers/run.sh [--docker] address [crate...]` (README there) |
| ThreadSanitizer | data races between I/O threads, wakers and senders | `tools/sanitizers/run.sh [--docker] thread [crate...]` |
| Fuzzing | parsers and protocol state machines (remote input) | `cargo fuzz` targets (separate work item) |
| cargo-deny / cargo-audit | vulnerable, unsound or yanked dependencies | `cargo deny check`, `cargo audit` |

Miri cannot execute syscalls (sockets, epoll, io_uring, bpf), so the syscall paths are covered
by the sanitizers and the Linux/macOS test suites (epoll and io_uring backends); the
kernel-shared memory logic of io_uring (`BufRing`, `KernelBuf`) has syscall-free unit tests that
do run under Miri.

Miri does not interpret SIMD intrinsics either: under Miri `only-crypto` detects no CPU feature
and runs its portable code (`cargo +nightly miri test -p only-crypto --lib -- aes:: gcm:: hash::
crc:: chacha:: field:: ec:: curve25519:: x25519:: …`; it cannot run `asm!` either). That
includes the `fill` module and the portable append paths (`-- fill append`), the code that
writes into uninitialised spare capacity; the vector kernels' out-of-place writes into it are
checked natively by the differential tests (every length 0..=600 and large sizes, append
against in place, on every kernel). The
CPU-instruction modules are checked instead by comparing every hardware path with the portable
one (unit tests `hardware_matches_portable` / `hardware_matches_table`, `ec::hw`,
`ec::hw_aarch64`, `curve25519::hw` and `curve25519::hw_aarch64` `matches_portable` on random
and edge values, `chains_match_portable` on long chains of dependent operations (aarch64), `ec::hw` `points_match_portable`
for the whole-point routines against the portable formulas limb for limb (random points with
random `Z`, Wycheproof points, `P + P`, `P + (-P)`, the identity), `twin_matches_portable` for the
P-256 operations, `safegcd` `matches_fermat`), by running all KATs (NIST CAVP, RFC, Wycheproof) twice, normally and with
`ONLY_CRYPTO_PORTABLE=1`, on x86_64 and aarch64, and by the differential fuzz targets
`crypto_hash`, `crypto_aead` and `crypto_sig_verify`. The `asm!` kernels of `gcm::hw::vaes` never run under Miri
(nothing is detected) and are compared with each other (the AVX2 one forced with
`AesGcm::with_cipher_avx2`), the 128-bit kernel and the portable code at every length 0..=600,
at large sizes and with every AAD length 0..=300 and past 512, misaligned, in place and out of
place (with the input split between two buffers as the TLS 1.3 record layer has it), with the
32-bit counter wrapping, against ring (`gcm::tests`), and on the CAVP and Wycheproof vectors
(`tests/kat.rs`); those tests must run natively on a CPU with VAES and AVX-512 (Zen 4, Ice
Lake and later) to cover both; the `ec::hw` and `curve25519::hw`
comparisons likewise need BMI2 and ADX, the `ec::hw_aarch64` and `curve25519::hw_aarch64` ones
run on every aarch64 machine (macOS on Apple silicon, arm64 Linux in Docker). The ChaCha20 and
Poly1305 kernels of `chacha::hw::avx512` and `chacha::hw::ifma` are compared the same way with
the AVX2 path and the portable code (`chacha::tests`: every length 0..=600 and large sizes,
misaligned, in place and out of place, forged tags, counters near the wrap; Poly1305 on all-ones
blocks and extreme `r` and `s`), which needs AVX-512 and IFMA, and by `crypto_aead`.

## 5. Inventory

Produced by `python3 tools/unsafe-inventory.py --markdown` (library code under `src/`, unit
tests included; integration tests, examples and benches in the last column). Crates not listed
contain no `unsafe`.

| Crate | blocks | `unsafe fn` | `unsafe impl` | tests/examples/benches |
|---|---:|---:|---:|---:|
| `only` | 0 | 0 | 0 | 13 |
| only-dpdk | 32 | 0 | 1 | 0 |
| only-ebpf | 48 | 4 | 2 | 2 |
| only-http | 0 | 0 | 0 | 8 |
| only-brotli | 0 | 0 | 0 | 7 |
| only-crypto | 150 | 72 | 0 | 0 |
| only-sys | 111 | 3 | 3 | 0 |
| only-buf | 5 | 0 | 2 | 0 |
| only-uring | 43 | 5 | 2 | 0 |
| ct-dudect | 2 | 0 | 0 | 0 |
| codec-bench | 3 | 0 | 0 | 0 |
| **total** | **394** | **84** | **10** | **30** |

By purpose:

| Where | Count | Purpose | Main invariants |
|---|---:|---|---|
| `only-sys/src/ffi/` | 5 + 8 in the layout tests, `unsafe fn errno_location`, `cmsg_firsthdr`, `cmsg_nxthdr` | the own OS bindings: `extern "C"` declarations of the C library (Linux) / libSystem (macOS), constants, `#[repr(C)]` structs, the `CMSG_*` helpers, `cpu_set_t`, errno | see "The own syscall layer" below |
| `only-sys/src/net.rs` | 21 | `socket`/`bind`/`listen`/`connect` (also a connect from a bound, shared port for TCP simultaneous open, ADR-044), `setsockopt`, `sendfile`, `SocketAddr` <-> `sockaddr_storage`, `listen` again on a live socket (backlog reload), `TCP_INFO` read of a listener's backlog (tests) | sockaddr length matches family; fd owned before any fallible step |
| `only-sys/src/poller.rs` | 12 + `impl Send` | epoll / kqueue create, ctl, wait | event buffer has `BATCH` initialised entries; kevent `udata` is an opaque token |
| `only-sys/src/process.rs` | 14 | `allowed_cpus` / `pin_current_thread` (`sched_getaffinity` / `sched_setaffinity` on the calling thread, a `cpu_set_t` of the size passed); prefork plumbing: `pre_exec` hook (`fcntl` clearing `FD_CLOEXEC`, `PR_SET_PDEATHSIG`, `sched_setaffinity`), `take_inherited_fd`, self-pipe signal handler (`sigaction`, `write` from the handler), `kill` | the hook only makes async-signal-safe calls and allocates nothing (all data built before `fork`); an inherited fd is owned at most once per process (`TAKEN` set); the handler saves and restores `errno` |
| `only-sys/src/fswatch.rs` | 12 (7 Linux, 5 macOS) | change notification for only-http's static file cache: `inotify_init1` / `inotify_add_watch` / `inotify_rm_watch`, `ppoll` on the inotify fd and an eventfd, `read` of events (Linux); `kqueue`, `fcntl`, `kevent` changes and waits with `EVFILT_VNODE` / `EVFILT_USER` (macOS) | fds owned immediately; paths are NUL-terminated `CString`s; reads stay within the buffer and records are parsed from bytes; the kevent `udata` is a watch id, never dereferenced; `O_EVTONLY` descriptors are opened by `std` and owned by the watcher |
| `only-sys/src/waker.rs` | 10 | eventfd (Linux) / pipe (macOS) waker, `EventFd` for io_uring | fds owned immediately; 8-byte eventfd writes from a live `u64` |
| `only-sys/src/ktls.rs` | 9 | kernel TLS (experimental, only-tls `experimental-ktls`): `TCP_ULP` and `SOL_TLS` `setsockopt`, `sendmsg`/`recvmsg` with the record-type cmsg, `uname`, wiping the copied key | crypto-info structs built whole on the stack and checked against `libc` in the layout tests; the cmsg buffer is 8-aligned and `CMSG_SPACE(1)` long; cmsgs walked with `CMSG_*` within `msg_controllen` |
| `only-sys/src/udp.rs` | 12 + 2 `impl Send` | `recvmmsg`/`sendmmsg`, UDP GSO (`UDP_SEGMENT`) / GRO / ECN cmsgs | each receive iovec covers the first `size` bytes of a slot's exclusive slab range (`only_buf::slab::ChunkMut`, at least `size` long, checked before each call and borrowed mutably for it); headers rebuilt before each call; cmsg walked with `CMSG_*` within `msg_controllen`; `Batch<'d>` borrows send data for the call |
| `only-sys/src/udp_mac.rs` | 5 | macOS: one datagram per `sendmsg` / `recvmsg` with its ECN codepoint (`IP_TOS` / `IPV6_TCLASS` cmsg), `IP_RECVTOS` / `IPV6_RECVTCLASS` `setsockopt` | `msghdr` points only at live locals (`sockaddr_storage`, one iovec over the caller's slice, a 64-byte 8-aligned control buffer) with their lengths, or null with length 0; the control data is built and parsed as bytes, bounded by `msg_controllen` (no `CMSG_*` pointer walking) |
| `only-crypto/src/aes/hw.rs` | 26, 26 `unsafe fn` (x86_64 and aarch64 variants; 6 stubs for other targets, never called) | AES-NI / ARMv8 AES key schedule, block encryption and decryption, CTR eight blocks at a time (round count as a const generic, unrolled) | a `hw::Keys` is only constructed after `cpu::cpu_has(Feature::Aes)` (`is_x86_feature_detected!("aes")` + `sse2` / `is_aarch64_feature_detected!("aes")`); loads and stores are unaligned and stay within 16-byte arrays or 16-byte pieces of a `&mut [u8; 128]` chunk; `SubWord` in the key schedule uses the AES instruction, no key-indexed table |
| `only-crypto/src/gcm/hw.rs` | 30, 17 `unsafe fn` (2 stubs for other targets) | GHASH on PCLMULQDQ / PMULL (eight blocks per reduction, Karatsuba) and AES-GCM encryption/decryption fused into one pass (AES-NI / ARMv8 AES rounds and the carry-less products in the same loop); the calls into `vaes` (both kernels for whole groups and for whole messages) | `Powers` exist only after `cpu_has(Feature::Clmul)` (PCLMULQDQ + SSSE3 + SSE4.1 / the aarch64 AES extension); the safe wrappers re-check `cpu_has` (and `Feature::Aes` for the fused kernel, `Aes`, `Clmul` and `Vaes` for the AVX2 kernel, those and `Avx512` for the AVX-512 one) before every call; every load reads 16 bytes inside a slice whose length the wrapper made a multiple of 16 (GHASH) or 128 (fused); the wide kernels get whole 256-byte groups within both the input and the output slice, and the same pointer twice only when working in place; for a whole message the AVX-512 kernel also gets the AAD (at most 256 bytes, a live slice) and the tail after the groups (under 256 bytes, read from the input slice right after the groups, written right after them in the output), with byte masks and power pointers that `vaes::Args` derives from those lengths; for a whole message the AVX2 kernel gets the AAD, the tail and the length block copied into a stack `vaes::TailBuf` (AVX2 has no byte masks), its pointers set by `vaes::Args2` from that buffer, and the processed tail is copied out after the call; input split between `src` and the output (the TLS 1.3 record layer) runs as two calls, `src`'s whole groups out of place, then the rest in place; out of place the output is a `fill::Fill` that may be uninitialised: the kernels get `Fill::next_ptr(n)` (a pointer to the next `n` unwritten bytes, bounds-checked), only write there (the AVX2 kernel reads back only the ciphertext it stored, for GHASH), and each such call is followed by `Fill::assume_written(n)` (6 blocks) for exactly the bytes the kernel stores (whole groups, plus the masked tail of a whole message on the AVX-512 kernel; the AVX2 kernel's tail reaches the output by `Fill::push`) |
| `only-crypto/src/gcm/hw/vaes.rs` | 4, 2 `unsafe fn` | AES-GCM seal / open as one `asm!` block per direction and kernel (the intrinsics are not stable at the MSRV): on VAES + VPCLMULQDQ + AVX-512 sixteen blocks per iteration in four zmm registers, GHASH interleaved with the AES rounds, one Montgomery reduction per group, plus the AAD, the last partial group under AVX-512 byte masks, the length block and `E(J0)` (a short message's AAD, data and length block under one reduction); on VAES + VPCLMULQDQ + AVX2 sixteen blocks per iteration in eight ymm registers (round keys and constants from memory), plus `E(J0)`, GHASH passes of up to sixteen blocks over the AAD and over the tail and length block, the tail (under 256 bytes) in place in a zero-padded stack buffer on four or eight ymm vectors, its keystream masked by a constant table (sealing) | entered only when `Powers` carry wide powers of that kind (made only after `cpu::has` of AES and VAES, and AVX-512 for the zmm kernel) and `avx2_available()` / `wide_available()` re-confirm AES-NI, PCLMULQDQ, VAES, VPCLMULQDQ, AVX2 and the OS YMM state (and AVX-512 F/BW/VL with the ZMM and opmask state) just before; reads the round keys `rk[0]` and `rk[r-13..=r]` (index >= 1, r <= 14), the 512-byte power table (sixteen powers and sixteen zero entries: a power pointer for `n` blocks starts at entry `16 - n`, so four vectors from it stay inside), 320 bytes of constants (the AVX2 kernel also up to 256 bytes of the 512-byte mask table from `MASK + 256 - t`), the `Args` / `Args2` block, `n * 256` bytes of input and, under masks, the AAD and tail bytes (the AVX2 kernel: the blocks of its `TailBuf`, rounded up to whole vectors inside the buffer, which has a spare block); writes `n * 256` bytes of output and the masked tail after them (every group and the tail is loaded before it is stored, so in place works), the GHASH state and the tag; masked-off bytes are neither read nor written (AVX-512 masked loads suppress faults); outputs in explicit registers, all vector and mask registers and flags clobbered (`clobber_abi("C")`), no stack, `vzeroupper` at the end; the masks depend only on lengths |
| `only-crypto/src/fill.rs` | 3, 1 `unsafe fn` | `Fill`, an AEAD output buffer that may start uninitialised (a `Vec`'s spare capacity): written front to back (`push`, `push_xor`, and kernels through `next_ptr` + `assume_written`) with an optional initialised suffix written first (`push_back`, the TLS 1.3 inner content type); `append` runs a seal or open into `Vec::spare_capacity_mut` and extends the vector only when every byte was written | `Fill` tracks `pos` (written prefix) and `tail` (start of the written suffix); `filled()` hands out `&mut [u8]` over the whole buffer only after asserting `pos >= tail`; `Fill::init` views an initialised `&mut [u8]` as `&mut [MaybeUninit<u8>]`, sound because `Fill` only ever stores `u8` values; `assume_written` (`unsafe fn`) is called only right after a kernel stored exactly those bytes; `append` reserves first, asserts the buffer is full before `set_len`, and on a failed open leaves the length and zeroes the bytes the open wrote (no unverified plaintext left in the spare capacity); a panic anywhere leaves the vector's length unchanged. Covered under Miri by `fill::tests` and the portable `append_portable` tests |
| `only-crypto/src/cpu.rs` (`cpu::hw`) | 5, 1 `unsafe fn` | CPUID (leaves 0, 1, 7) and XGETBV (XCR0) for VAES, VPCLMULQDQ, AVX-512 and the OS YMM / ZMM state, and BMI2 + ADX (leaf 7, no OS state) | CPUID exists on every x86_64 CPU and leaves 1 and 7 are read only when leaf 0 reports them; XGETBV only after CPUID.1:ECX.OSXSAVE; not compiled under Miri |
| `only-crypto/src/hash/hw.rs` | 8, 8 `unsafe fn` (2 stubs) | SHA-1 and SHA-256 compression on SHA-NI (x86_64) and the ARMv8 SHA1/SHA2 instructions | the wrappers call only when `cpu_has(Feature::Sha)` (SHA + SSSE3 + SSE4.1 / `sha2`); loads read 16-byte pieces of the 64-byte chunks of the block slice, the state is loaded from and stored to the live `[u32; 5]` / `[u32; 8]` |
| `only-crypto/src/crc/hw.rs` | 15, 9 `unsafe fn` | CRC-32 / CRC-32C: PCLMULQDQ folding (four 128-bit accumulators), from 512 bytes VPCLMULQDQ + AVX-512 folding (four 512-bit accumulators, 256 bytes per step, one `asm!` block), and the SSE4.2 `crc32` instruction on x86_64, the ARMv8 CRC32 instructions on aarch64 | called only after `cpu_has(Feature::Clmul)` / `cpu_has(Feature::Crc)` (the 512-bit fold also `Vaes` and `Avx512`, re-checked by `wide_available()` before the call); the folding loop reads 16 bytes at offsets `o` with `o + 16 <= len` (checked by the loop conditions), only with `len >= 64`; the `asm!` fold gets a slice of a nonzero multiple of 256 bytes and reads exactly that, the 80 bytes of constants (`#[repr(C)]`, offsets fixed) and writes a 16-byte array; the fold constants are compile-time functions of the public polynomials |
| `only-crypto/src/chacha/hw.rs` | 11, 2 `unsafe fn` | ChaCha20 eight blocks at a time with AVX2 (8×8 transpose back into blocks); Poly1305 four blocks at a time with AVX2 in radix 2²⁶ (`vpmuludq`); the calls into `chacha::hw::avx512` and `chacha::hw::ifma` | `xor8` is called only after `cpu_has(Feature::Avx2)`; loads and stores are 32-byte pieces of a `&mut [u8; 512]`; the counter of the eight blocks cannot wrap (checked by the caller); `xor_wide` (in place) and `xor_wide_into` (out of place into a possibly uninitialised `fill::Fill`) re-check `cpu_has(Feature::Avx512)` and hand the kernel whole groups inside `dst` / `src` and `Fill::next_ptr(n)` (bounds-checked, only written), a last partial group as one masked kernel call over exactly the remaining bytes; `Fill::assume_written(n)` follows each out-of-place kernel call for exactly the bytes it stored; `poly_blocks` re-checks `cpu_has(Feature::Ifma)` and asserts a nonzero multiple of 128 bytes; `poly_avx2` re-checks `cpu_has(Feature::Avx2)`, asserts a nonzero multiple of 64 bytes and loads 32-byte pieces of each 64-byte group and of the 32-byte power rows |
| `only-crypto/src/chacha/hw/avx512.rs` | 2 (one per kernel through a macro: three instances for whole groups, three for a masked last group), 2 `unsafe fn` (x86_64 only) | ChaCha20 sixteen (zmm) or eight (ymm) blocks per iteration word-sliced, or four with one row per zmm register, as one `asm!` block each (`vprold` rotations, 4×4 in-lane transposes, `vpshufd` diagonal turns and `vshufi32x4` lane transposes back into blocks; the intrinsics are not stable at the MSRV); `xor_masked` runs one last group under AVX-512 BW byte masks | reached only from `xor_wide` / `xor_wide_into` after `cpu_has(Feature::Avx512)` (AVX-512 F/BW/VL and the OS ZMM and opmask state); reads the 64-byte state, 256 bytes of constants and `n` groups from `src`, writes `n` groups to `dst` (each 64-byte block is loaded before it is stored, so in place works), unaligned, no stack; `xor_masked` also reads its 128-byte mask array (built from `len`) and touches only `src[..len]` / `dst[..len]`: a block whose mask is all ones is read and written whole, one whose mask is zero is skipped, the partial block goes through `vmovdqu8` under its mask (masked-off bytes are neither read nor written, no fault); all vector and mask registers and flags clobbered (`clobber_abi("C")`), `vzeroupper` at the end; no branches but the round and group counters and, in `xor_masked`, the per-block tests of the public length |
| `only-crypto/src/chacha/hw/ifma.rs` | 1, 1 `unsafe fn` (x86_64 only) | Poly1305 on AVX-512 IFMA, eight blocks per iteration in 44/44/42-bit limbs (`vpmadd52luq`/`vpmadd52huq`; not stable at the MSRV), one `asm!` block | reached only from `poly_blocks` after `cpu_has(Feature::Ifma)`; reads the 192-byte lane accumulator, 320 bytes of powers, 128 bytes of constants and `n * 128` message bytes, writes the accumulator, no stack; limbs stay below 2⁵² (inputs below 2⁴⁵, multipliers below 2⁵⁰), so the 52-bit products are exact; all vector registers and flags clobbered, `vzeroupper` at the end; no branches but the group counter |
| `only-crypto/src/ec/hw.rs` | 15, 2 `unsafe fn` (x86_64 only) | P-256 in `asm!`: Montgomery multiplication and squaring modulo `p` (special reduction, `-p⁻¹ = 1`) and modulo the order `n`, addition, subtraction, `2ᵏ·a`, `3·a`; whole Jacobian doubling (also `n` in a row), addition and mixed addition as one block each over a stack frame; 59 safegcd divsteps; AVX2 scans of the ECDH window table and of the wide fixed-base comb (`#[target_feature]` functions) | the field, order and point blocks are reached only after `cpu::has(Feature::Adx)` (BMI2 + ADX): the `P256X` twin curve is entered through `P256`'s dispatch, the scalar field checks before each call, every function debug-asserts it; the field blocks read only the 32-byte limb arrays behind their pointer operands (`pure`, `readonly` or `nomem`, `nostack`) and write only declared registers; a point block reads and writes only its frame (a local `[u64; 48..76]` passed in `rdi`; every address is `rdi` plus a constant below the frame size), `nostack`, and keeps the compiler-reserved `rbx` (its shift count 32) in the frame header, restoring it before the block ends; the divsteps block is registers only (base instructions); the AVX2 functions are called only after `cpu::cpu_has(Feature::Avx2)` and load 32 bytes from each 4-limb array of a live table entry; no branches but the divsteps loop counter (corrections by `cmov`/`sbb`/`sar` masks) |
| `only-crypto/src/curve25519/hw.rs` | 5 (x86_64 only) | the X25519 ladder's arithmetic modulo `2²⁵⁵ - 19` on four limbs in `asm!` (multiplication, squaring, `121665·a`, addition, subtraction; folds by `2²⁵⁶ ≡ 38`) | `ladder` is called only after `hw::enabled()` (`cpu::has(Feature::Adx)`), debug-asserted in each function; same memory and register discipline as `ec/hw.rs`, no branches |
| `only-crypto/src/ec/hw_aarch64.rs` | 9 (aarch64 only) | the aarch64 counterpart of `ec/hw.rs` in `asm!`: Montgomery multiplication and squaring modulo `p` (special reduction without multiplications) and modulo `n`, addition, subtraction, `2ᵏ·a`, `3·a`, with `MUL`/`UMULH`, `ADDS`/`ADCS`/`SUBS`/`SBCS` and `CSEL`; 59 safegcd divsteps (masks by `ASR`/`SBFX`, a loop of fixed count) | base ARMv8.0-A instructions, present on every aarch64 CPU; reached only when `hw_aarch64::enabled()` (`cpu::has(Feature::Umulh)`, set on aarch64 outside Miri, cleared by `ONLY_CRYPTO_PORTABLE`): the `P256A` twin through `P256`'s dispatch, the scalar field per call; the blocks take every operand in registers and touch no memory (`pure`, `nomem`, `nostack`), write only declared registers, and have no branches (corrections by `CSEL` on the carry flag, an `SBC` mask) but the divsteps loop counter |
| `only-crypto/src/curve25519/hw_aarch64.rs` | 5 (aarch64 only) | the aarch64 counterpart of `curve25519/hw.rs`: the X25519 ladder's arithmetic modulo `2²⁵⁵ - 19` on four limbs in `asm!` (multiplication, squaring, `121665·a`, addition, subtraction; folds by `2²⁵⁶ ≡ 38` with `CSEL`) | `ladder` is called only after `hw_aarch64::enabled()` (`cpu::has(Feature::Umulh)`); same register-only discipline as `ec/hw_aarch64.rs`, no branches |
| `only-crypto/src/bignum/hw.rs` | 7, 1 `unsafe fn` (x86_64 only) | RSA Montgomery multiplication and squaring in `asm!` for 16, 24, 32, 48 and 64 limbs (BMI2 `mulx` with the ADX carry chains, rows unrolled with `.rept`, the final subtraction by `cmovnz`; squaring at 48 and 64 limbs as one level of Karatsuba, the product phase `sqr_wide` and the reduction `redc` as blocks of their own); the AVX2 scan of the exponentiation table (`#[target_feature]` function) | the blocks are reached only from `Mont::mul_into` / `sqr_into` after `hw::enabled()` (`cpu::has(Feature::Adx)`), debug-asserted in each function; they read the `N`-limb arrays behind `a`, `b`, `m` and write the `N`-limb output (an exclusive borrow) and a local `2N`-limb scratch buffer (`MaybeUninit`, every limb written before it is read), every displacement below `16N` bytes, no stack; the scan is called only after `cpu_has(Feature::Avx2)` (asserted) and loads 32 bytes from each 4-limb chunk of a live table entry; no branches but the row counters |
| `only-crypto/src/bignum/ifma.rs` | 4 (x86_64 only; one per macro, three or four instances each, plus `amm80`) | RSA exponentiation on AVX-512 IFMA: almost Montgomery multiplication over 20, 32, 40, 64 (60 steps) and 80 digits of 52 bits in `ymm` / `zmm` registers, one `asm!` block each, and the same for two operand pairs at once (`amm*_x2`, the CRT halves interleaved) (`vpmadd52luq`/`vpmadd52huq`, `valignq`, opmask carries; the intrinsics are not stable at the MSRV) | reached only from `Mont::pow` (20–40 digits) and `Mont::pow_public` (40, 64 and 80 digits, via `ifma::pow_public`) after `ifma::enabled()` (`cpu::has(Feature::Ifma)`: AVX-512 F/BW/VL, IFMA and the OS ZMM and opmask state), debug-asserted; reads the `D`-digit arrays behind `a`, `b`, `m`, writes the `D`-digit output, unaligned, no stack; all vector and mask registers clobbered (`clobber_abi("C")`), the output pointer parked in `xmm31` during the loop, `vzeroupper` at the end; no branches but the digit counter. `amm*_x2` (from `Mont::pow2` via `ifma::pow_x2`, same checks): reads the `2D` digits behind `a`, `b` and the `2D + 2` words behind `m` (both moduli, then both `k0`), writes the `2D`-digit output; the output pointer parked in `k7` (`kmovq`, AVX-512 BW). `amm64` reads only the first 60 digits of `b` (the step count; the top four digits of every operand are zero). `amm80` (30 of the 32 vector registers for the operands): the output pointer in `k7`, the top lane's zero shifted in by zero-masking (`k3`), the constants set after the loop; its carry ripple uses rsi and rdi, declared as clobbered `inout` operands |
| `only-buf/src/slab.rs` | 5, `impl Send`/`Sync for Mem` | receive slabs: `Mem` (a leaked `Box<[u8]>`, freed in `Drop`), `ChunkMut` / `Chunk` views of a range (`deref`, `deref_mut`, `as_mut_ptr`), `SlabPool` reuse | live `ChunkMut` ranges are disjoint from each other and from live `Chunk` ranges: a `ChunkMut` is made only over a whole slab nobody else references (`Arc::get_mut`, which also synchronises with drops on other threads) or by `split_to` of another one, a `Chunk` only by `freeze`; bytes are reached only through the allocation's raw pointer, at offsets within `start <= end <= len` (u32, slab size asserted); memory is zeroed at allocation, so every byte read is initialised; the kernel writes a slab only through a `RecvBatch` iovec over a `ChunkMut` it holds mutably for the call. Miri (`cargo +nightly miri test -p only-buf`, including a cross-thread drop under the data-race detector) and loom (`RUSTFLAGS="--cfg loom" cargo test -p only-buf --lib --release -- loom`) |
| `only-sys/src/random.rs` | 2 (one per OS) | `getrandom(2)` (Linux), `getentropy(2)` (macOS) for `only-crypto` | the kernel writes at most `buf.len()` bytes into a live `&mut [u8]` (`getentropy` at most 256 per call); a short `getrandom` read advances by the returned count |
| `only-uring/src/reactor.rs` | 13 + 3 in tests, `unsafe fn slice`, `impl Send for Loop` | SQE push, provided-buffer rings (`BufRing`, a second `BufGroup` while a read-buffer reload swaps them), kernel-written buffers (`KernelBuf`), accepted fds | nothing in flight when buffers are freed (cancel-all + drain, else leak); a replaced buffer group is unregistered only once no receive armed on it is in flight (`armed == 0`), and leaked if the kernel refuses; kernel-owned buffers never borrowed; ring entries written by raw field pointers; tail stored with `Release` |
| `only-uring/src/ring.rs` | 19 (2 compiled for tests only: sparse `REGISTER_FILES`, `REGISTER_SEND_MSG_RING`), `unsafe fn push`, `register`, `register_buf_ring`, `unregister_buf_ring` | own io_uring binding: `io_uring_setup`/`enter`/`register` through `syscall(2)`, `mmap` of the SQ/CQ rings and SQE array, SQ/CQ head and tail atomics, probe, enable-rings, buffer-ring registration; for the io_uring features evaluation, a sparse registered-file table and a ringless `MSG_RING` | offsets from the kernel bounds-checked against each mapping; SQE slot written only when the queue is not full, tail published with `Release`; CQEs read between our head and the `Acquire`-loaded tail, head published with `Release`; `SeqCst` fence before reading `SQ_NEED_WAKEUP` (SQPOLL); mappings live as long as the `Ring` |
| `only-uring/src/eval.rs` (`#[cfg(test)]`) | 5 | the io_uring features evaluation harness (an ignored test): SQE push, provided-buffer reads, `write`/`close` of its own sockets, `setsockopt(TCP_NODELAY)` | entries point only into a leaked static response buffer or the provided buffers, which are never freed (the harness ends the process); a buffer is borrowed only between its completion and its return to the ring; a descriptor is closed only once no entry refers to it |
| `only-uring/src/group.rs` | 3 | `uname` for the kernel-version probe | zeroed `utsname`; kernel NUL-terminates `release` |
| `only-dpdk/src/pmd.rs` | 17, `impl Send for Queue` | calls into the C shim (`rte_eal_init`, port setup, `rte_eth_rx_burst`/`tx_burst`, mbuf alloc/free); frames borrowed from mbufs; a staged tx mbuf written in place | the shim's ABI is integers and opaque pointers only (no DPDK struct layouts in Rust); EAL argv leaked (outlives the EAL), init once (`OnceLock`); an mbuf is owned by exactly one `Queue`/`Mbuf` and freed once (frames not taken by `tx_burst` freed, received ones freed on drop); slices only over the single data segment the shim returned, for the mbuf's lifetime; a `Queue` is used by one thread at a time (moved once to its I/O thread); the staged tx mbuf is freed if not committed |
| `only-dpdk/src/sys.rs` | 15 | TAP (`open`, `TUNSETIFF`), AF_PACKET (`socket`, `bind`, `setsockopt`, including the all-multicast `PACKET_ADD_MEMBERSHIP`), `read` / `recvfrom` / `write`, `ppoll` | fds owned immediately (`OwnedFd`); `#[repr(C)]` `ifreq` and `packet_mreq` with the UAPI sizes (compile-time asserted); buffers and address structs live across each call, lengths passed are their sizes |
| `only-ebpf/src/sys.rs` | 25, 4 `unsafe fn` | `bpf(2)` (`MAP_CREATE`, `MAP_LOOKUP/UPDATE/DELETE_ELEM`, `PROG_LOAD`, `PROG_ATTACH`, `LINK_CREATE`, `OBJ_PIN`, `OBJ_GET`, `OBJ_GET_INFO_BY_FD`), `SO_ATTACH_REUSEPORT_[CE]BPF`, `SO_COOKIE`, `SO_RCVLOWAT`, `TCP_INFO`, `SIOCOUTQ`, a `NETLINK_ROUTE` socket (`socket`/`write`/`read`), `if_nametoindex` | `#[repr(C)]` attr prefixes identical to UAPI; pointer fields (including the NUL-terminated pin path and the info buffer) live for the call; key/value sizes fixed by `Map<K, V>`, and a map opened from bpffs (`Map::open_pinned`) is checked to have exactly those sizes (`OBJ_GET_INFO_BY_FD`) before its typed methods can be used; per-CPU lookups write into a buffer of 8 bytes per possible CPU (`Map<K, u64>` only), plain lookups into `4 * N` bytes (`Map<K, [u32; N]>` only); getsockopt/ioctl outputs sized by the length passed |
| `only-ebpf/src/xsk.rs` | 23, `impl Send` for `Ring<E>` and `UmemMem` | AF_XDP (ADR-063): `socket(AF_XDP)`, `setsockopt`/`getsockopt` (`XDP_UMEM_REG`, ring sizes, `XDP_MMAP_OFFSETS`, `XDP_OPTIONS`, `XDP_STATISTICS`), `bind(sockaddr_xdp)`, `mmap`/`munmap` of the four rings and of the UMEM (anonymous), ring entries and producer/consumer words read and written through raw pointers, slices over UMEM chunks, `sendmsg`/`recvfrom` wake-ups, `ppoll` | the UMEM is its own anonymous mapping, unmapped only after the socket closed (field order), so the kernel's pinned pages are never handed to another allocation; ring pointers come from `XDP_MMAP_OFFSETS` inside the mapping and the producer/consumer words are accessed as `AtomicU32` with acquire/release (the kernel's protocol), entries only at `index & mask < size`; a chunk is read only between its RX descriptor and its return to the fill ring (bounds checked against the UMEM), and written only while it is in the userspace TX pool, through a slice that borrows the socket mutably; `#[repr(C)]` UAPI structs with compile-time size asserts; one socket is used by one thread at a time (moved once to its I/O thread) |

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
| only-buf (with `slab`; 2026-11-17) | pass (9 tests, 13 s; nightly, aarch64 macOS): splits, freezes, disjoint writes, pool reuse only of free slabs, the bound, and parts written and dropped on another thread under the data-race detector |
| only-http | pass (27 tests, 35 s) |
| only-mux, only-socks, only-arpc, only-h3 | pass (1 / 1 / 3 / 2) |
| only-kcp | pass (5 tests, 4-6 min) |
| only-uring (`buf_ring`, `kernel_buf` tests) | pass (3): the kernel-shared memory code of F5-F7 |
| only-ws | 15 of 20 pass; the other 5 (permessage-deflate round trips and exhaustive split loops) do not finish within 5-15 min under Miri |
| only-crypto (`fill`, `append`, `aead_rfc8439`, `gcm_spec_vectors`, `rejects_forgeries`; 2026-11-16) | pass (7 tests, 37 s; nightly 2026-11-13, x86_64 image): `fill::tests` and the portable `encrypt_append` / `decrypt_append` of AES-GCM and ChaCha20-Poly1305 at lengths around the block and head sizes, with bytes already in the vector, exact / larger / missing spare capacity, a trailer, failed opens; no uninitialised byte of the spare capacity is read or exposed |
| only-tls (`record::` `framing_limits`, `skips_rejected_early_data`, `tampering_and_replay_fail`, `tls13_padding_and_empty_types`; 2026-11-16) | pass (4 tests, 9 s): the record layer on the append paths (no `unsafe` of its own) |
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

First run 2026-11-16 (`tools/sanitizers/`, details and the full table in its README):
AddressSanitizer with LeakSanitizer and ThreadSanitizer over every workspace crate's tests in
Linux arm64 Docker, epoll and io_uring, and the crates with unsafe code plus the engine backends
natively on x86_64 (Zen 4, so the AVX-512/IFMA/VAES/BMI2 assembly paths ran). No memory error,
memory leak or data race was reported; the suppression files are empty. TSan did report a thread
leak: only-bittorrent's `Client::close` returned without waiting for the engine and disk-pool
threads (fixed, together with only-http's client keeping idle keep-alive connections open through
a graceful engine shutdown, which made waiting take the full `shutdown_timeout`).

The start-up SIGSEGV that an earlier version of this section put down to the Docker VM's address
space was in fact `-Zbuild-std` instrumenting `compiler_builtins`: on aarch64 the sanitizer
runtimes call its outline-atomics helpers while they initialise. `tools/sanitizers/rustc-wrapper.sh`
builds that one crate without the sanitizer. The runs also turned up a test that hung under TSan
(a process-directed signal landing on a thread in a raw `futex` wait, where TSan never runs the
deferred handler; `only-sys` `signal_to_pipe` now raises the signal on its own thread) and a
WebSocket test whose 10 s deadline was too short under TSan. Not covered: the loads and stores
inside `asm!` blocks (not instrumented) and memory synchronised by the kernel (io_uring rings),
which is Miri's and loom's part.
