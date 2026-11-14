# `unsafe` review

English | [简体中文](unsafe-review.zh-CN.md)

Status: 1.0 stabilization review, 2026-11-14. Re-run the inventory and update this page whenever
`unsafe` is added, removed or its invariant changes.

flash is a network library: a memory-safety bug in it is a remote-code-execution bug in its
users. This page is the policy for `unsafe` code, the checklist each `unsafe` site must pass,
the procedure for adding new ones, the inventory, and the findings of the 1.0 review.

## 1. Where `unsafe` may live

| Crate | Status | Why |
|---|---|---|
| `flash-sys` | `unsafe` allowed (crate-wide) | the one place for raw syscalls: epoll/kqueue, eventfd/pipe, sockets, `sendfile`, `recvmmsg`/`sendmmsg` + cmsg |
| `flash-uring` | `#![deny(unsafe_code)]`, allowed in `group` and `reactor` only | io_uring submission entries point into memory the kernel writes asynchronously |
| `flash-ebpf` | `#![deny(unsafe_code)]`, allowed in `sys` only | raw `bpf(2)` and socket options (no libbpf/aya) |
| every other crate (`flash`, `flash-core`, `flash-buf`, `flash-timer`, `flash-pool`, `flash-epoll`, `flash-tls`, `flash-http`, `flash-ws`, `flash-mux`, `flash-socks`, `flash-arpc`, `flash-grpc`, `flash-kcp`, `flash-quic`, `flash-h3`, `tools/echo-bench`) | `#![forbid(unsafe_code)]` | pure Rust on top of the above |

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

1. First look for a safe alternative (`std`, an existing `flash-sys` wrapper, a typed wrapper).
   New `unsafe` goes into `flash-sys` unless it must live next to backend state (io_uring) or
   the BPF loader; a crate that is `forbid(unsafe_code)` stays so.
2. Write the `SAFETY:` comment against the checklist above; for an `unsafe fn` write a
   `# Safety` section with the caller's obligations.
3. Add a test that exercises the invariant (bounds, error paths, wrap-around); if the code is
   pure memory manipulation, make it runnable under Miri (no syscalls in that test).
4. Run locally: `cargo clippy --workspace --all-targets -- -D warnings` on Linux and macOS,
   `python3 tools/unsafe-inventory.py --check`, Miri for the touched crate where it applies,
   and the io_uring suite (`FLASH_TEST_BACKEND=uring`) for backend changes.
5. The PR description lists each new or changed `unsafe` site; a reviewer other than the author
   checks it against the checklist. Update the inventory table below.

## 4. Tools

| Tool | What it covers | Command |
|---|---|---|
| Clippy lints | comments present (host platform) | `cargo clippy --workspace --all-targets -- -D warnings` |
| Inventory script | counts and comment check, all platforms | `python3 tools/unsafe-inventory.py [--markdown] [--check]` |
| Miri | UB in pure-Rust code: aliasing (Stacked Borrows), out-of-bounds, uninitialised reads, data races | `cargo +nightly miri test -p <crate> --lib` (Linux nightly image; `MIRIFLAGS=-Zmiri-disable-isolation`) |
| loom | interleavings of `flash-core`'s lock-free primitives | `RUSTFLAGS="--cfg loom" cargo test -p flash-core --lib --release -- loom` |
| AddressSanitizer | out-of-bounds / use-after-free across FFI, including syscall paths Miri cannot run | `RUSTFLAGS=-Zsanitizer=address cargo +nightly test -Zbuild-std --target <host> -p <crate>` |
| ThreadSanitizer | data races between I/O threads, wakers and senders | as above with `-Zsanitizer=thread` |
| Fuzzing | parsers and protocol state machines (remote input) | `cargo fuzz` targets (separate work item) |
| cargo-deny / cargo-audit | vulnerable, unsound or yanked dependencies | `cargo deny check`, `cargo audit` |

Miri cannot execute syscalls (sockets, epoll, io_uring, bpf), so the syscall paths are covered
by the sanitizers and the Linux/macOS test suites (epoll and io_uring backends); the
kernel-shared memory logic of io_uring (`BufRing`, `KernelBuf`) has syscall-free unit tests that
do run under Miri.

## 5. Inventory

Produced by `python3 tools/unsafe-inventory.py --markdown` (library code under `src/`, unit
tests included; integration tests, examples and benches in the last column). Crates not listed
contain no `unsafe`.

| Crate | blocks | `unsafe fn` | `unsafe impl` | tests/examples/benches |
|---|---:|---:|---:|---:|
| flash | 0 | 0 | 0 | 3 |
| flash-ebpf | 11 | 3 | 0 | 1 |
| flash-http | 0 | 0 | 0 | 7 |
| flash-sys | 51 | 0 | 3 | 0 |
| flash-uring | 18 | 1 | 1 | 0 |
| **total** | **80** | **4** | **4** | **11** |

By purpose:

| Where | Count | Purpose | Main invariants |
|---|---:|---|---|
| `flash-sys/src/net.rs` | 14 | `socket`/`bind`/`listen`/`connect`, `setsockopt`, `sendfile`, `SocketAddr` -> `sockaddr_storage` | sockaddr length matches family; fd owned before any fallible step |
| `flash-sys/src/poller.rs` | 12 + `impl Send` | epoll / kqueue create, ctl, wait | event buffer has `BATCH` initialised entries; kevent `udata` is an opaque token |
| `flash-sys/src/waker.rs` | 10 | eventfd (Linux) / pipe (macOS) waker, `EventFd` for io_uring | fds owned immediately; 8-byte eventfd writes from a live `u64` |
| `flash-sys/src/udp.rs` | 15 + 2 `impl Send` | `recvmmsg`/`sendmmsg`, UDP GSO (`UDP_SEGMENT`) / GRO cmsgs, sockaddr parsing | iovecs inside one allocation (checked size); headers rebuilt before each call; cmsg walked with `CMSG_*` within `msg_controllen`; `Batch<'d>` borrows send data for the call |
| `flash-uring/src/reactor.rs` | 12 + 3 in tests, `unsafe fn slice`, `impl Send for Loop` | SQE push, provided-buffer ring (`BufRing`), kernel-written buffers (`KernelBuf`), accepted fds | nothing in flight when buffers are freed (cancel-all + drain, else leak); kernel-owned buffers never borrowed; ring entries written by raw field pointers; tail stored with `Release` |
| `flash-uring/src/group.rs` | 3 | `uname` for the kernel-version probe | zeroed `utsname`; kernel NUL-terminates `release` |
| `flash-ebpf/src/sys.rs` | 11, 3 `unsafe fn` | `bpf(2)` (`MAP_CREATE`, `MAP_UPDATE/DELETE_ELEM`, `PROG_LOAD`, `PROG_ATTACH`), `SO_ATTACH_REUSEPORT_[CE]BPF`, `SO_COOKIE` | `#[repr(C)]` attr prefixes identical to UAPI; pointer fields live for the call; key/value sizes fixed by `Map<K, V>` |

## 6. Findings of the 1.0 review

Fixed in this review (each with a regression test where one can observe it):

| # | Where | Issue | Fix |
|---|---|---|---|
| F1 | `flash-sys` `RecvBatch::with_gro` | `slots * size` unchecked: in release builds an overflowing product wraps, `bufs` is tiny while each iovec still claims `size` bytes, so `recvmmsg` would write past the allocation (heap overflow from a public safe API). | `checked_mul` + `u32` slot check, panic documented; test `recv_batch_rejects_overflowing_size`. |
| F2 | `RecvBatch::recv` / `get` | `got` was not reset on `WouldBlock` or error, so `get(i)` kept returning the previous call's datagrams (in-tree callers iterate `0..n`, so not reachable, but the API was wrong). | `got = 0` before each call; test `recv_batch_forgets_previous_datagrams`. |
| F3 | `RecvBatch::with_gro` | iovec bases were taken from a fresh `&mut bufs[i*size..]` per slot; under Stacked Borrows each reborrow invalidates the pointers derived earlier. | One base pointer from `as_mut_ptr()`, offsets with `add`. |
| F4 | `RecvBatch::reset` | `sockaddr_storage` kept the previous family; a header the kernel left unfilled would be parsed with a stale family. | Family cleared before each receive. |
| F5 | `flash-uring` provided buffers | Buffers lived in a `Vec<u8>` (and the eventfd target in a `Box<[u8; 8]>`) while the kernel fills them asynchronously; `on_recv` borrowed `&self.bufs[..]`, a shared reference covering every buffer, including ones the kernel may be writing from an io-wq worker. Aliasing UB in Rust's model. | `KernelBuf`: raw allocation, no `Vec`/`Box`; Rust borrows only the completed buffer through `unsafe fn slice` (bounds-checked). |
| F6 | `BufRing::give` | Wrote entries through `&mut BufRingEntry`; for entry 0 that reference also covers the ring tail (`resv`) the kernel reads concurrently. | Mirrored `#[repr(C)] RawBuf` (size asserted equal to `io_uring_buf`), fields written via raw pointers; tail via `AtomicU16` with `Release`. Miri-runnable test `buf_ring_layout_give_and_publish` checks the layout against `io_uring`'s accessors. |
| F7 | `BufRing::give` | Buffer id not checked against the area. | Asserted (`bid < BUF_COUNT` and slot inside the area); test `buf_ring_rejects_foreign_buffer_ids`. |
| F8 | `flash-ebpf` `sys::bpf`, `map_update`, `map_delete` | Safe `fn bpf<T>(cmd, &mut T)` accepted any `T`; `map_update<K, V>` let the kernel copy the map's `key_size`/`value_size` bytes from `&K`/`&V` whatever their real size (out-of-bounds read into the map). | Made `unsafe fn` with `# Safety`; callers use a typed `Map<K, V>` whose key/value sizes are `size_of::<K/V>()` at creation, so its methods are safe. |
| F9 | `attach_reuseport_cbpf` | Program length truncated to `u16`. | `InvalidInput` error instead. |
| F10 | `flash-sys` macOS paths (`socket_of`, pipe `Waker`, `kqueue` `Poller`) | fd leaked when the `fcntl` after creation failed. | Wrapped in `OwnedFd` before the fallible step. |
| F11 | `flash-uring` loop teardown | `Loop` closed the ring and then freed the provided buffers, buffer ring and wake buffer while operations could still be in flight: part of the kernel's ring teardown runs in asynchronous exit work, and after the shutdown timeout (or an `io_uring_enter` error) the loop exited with connections and their multishot `recv`s still armed, so a late completion could write freed memory. | The loop counts operations in flight (one final CQE per SQE); `drain_inflight` submits `ASYNC_CANCEL_ANY` and reaps completions until none is left before the memory is dropped (closing any fd an accept still delivers); if that does not finish within 2 s the memory is deliberately leaked, never freed. The io_uring suites log no leak. |
| F12 | `flash-core` `consume_datagrams` | Linux-only dead code made `clippy -D warnings` fail on Linux (from the UDP batching change). | `#[cfg(not(target_os = "linux"))]`. |

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
- **Dependencies with `unsafe`** (`libc`, `io-uring`, `rustls`/`ring`, `quinn-proto`,
  RustCrypto, `flate2` with `zlib-rs`) are trusted and tracked with `cargo deny`/`cargo audit`.

## 7. Verification results (this review)

- `cargo clippy --workspace --all-targets -- -D warnings`: clean on macOS (aarch64) and Linux
  (Docker `rust:1`, 1.98), with the stricter lints above.
- `tools/unsafe-inventory.py --check`: every site documented.
- Test suites: macOS `cargo test --workspace` green; Linux `cargo test --workspace` (epoll) and
  `FLASH_TEST_BACKEND=uring` for `flash`, `flash-uring`, `flash-sys`, `flash-ebpf`, `flash-http`,
  `flash-ws`, `flash-kcp`, `flash-quic` green.
- Miri and sanitizers: see below.
