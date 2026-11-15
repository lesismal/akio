# Changelog

[中文](CHANGELOG.zh-CN.md)

All notable changes to `only` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and `only` adheres to
[Semantic Versioning](https://semver.org/) from 1.0.0 on, as defined in
[docs/api-stability.md](docs/api-stability.md). Deprecations follow
[docs/deprecation.md](docs/deprecation.md). All crates of the workspace share one version.

## [Unreleased]

### Renamed: the project is now `only`

The crates.io name `flash` is taken, so the project was renamed from **flash** to **only**
(DEV-PLAN "1.0.0 release decisions"). Every crate, path, identifier and name changed with it;
the entries below already use the new names.

| Before | After |
|---|---|
| crate `flash` (`use flash::...`) | `only` (`use only::...`) |
| crates `flash-*` (`flash_*` in code), directories `crates/flash-*` | `only-*` (`only_*`), `crates/only-*`: `flash-sys` → `only-sys`, `flash-buf` → `only-buf`, `flash-timer` → `only-timer`, `flash-pool` → `only-pool`, `flash-core` → `only-core`, `flash-epoll` → `only-epoll`, `flash-uring` → `only-uring`, `flash-tls` → `only-tls`, `flash-http` → `only-http`, `flash-ws` → `only-ws`, `flash-mux` → `only-mux`, `flash-socks` → `only-socks`, `flash-arpc` → `only-arpc`, `flash-grpc` → `only-grpc`, `flash-kcp` → `only-kcp`, `flash-quic` → `only-quic`, `flash-h3` → `only-h3`, `flash-ebpf` → `only-ebpf`, `flash-prefork` → `only-prefork`, `flash-dpdk` → `only-dpdk`, `flash-turn` → `only-turn`, `flash-webrtc` → `only-webrtc`, `flash-media` → `only-media`, `flash-bittorrent` → `only-bittorrent` |
| environment variables `FLASH_*` (`FLASH_TEST_BACKEND`, `FLASH_UDP_GSO`, `FLASH_UDP_GRO`, `FLASH_PREFORK_*`, `FLASH_CHAOS*`, `FLASH_DPDK_*` ...) | `ONLY_*` |
| Prometheus series `flash_*` (`flash_connections_open`, `flash_http_requests_total`, `flash_tls_handshake_failures_total` ...) | `only_*` |
| log targets `flash`, `flash_http::access`, `flash_webrtc` ... | `only`, `only_http::access`, `only_webrtc` ... |
| thread names `flash-io-*`, `flash-pool`, `flash-quic-timer` ... | `only-io-*`, `only-pool`, `only-quic-timer` ... |
| `flash_media::srt` alias `FlashConn` | `OnlyConn` |
| API snapshots `api/flash-*.txt`, tool Docker images and volumes `flash-*` | `api/only-*.txt`, `only-*` |

The GitHub repository and the documentation site keep their `lesismal/only` URLs until the
repository itself is renamed.

### Evaluated: kernel TLS offload (not adopted, experimental feature)

- Handing only-tls's record keys to the Linux kernel after the handshake (kTLS) was measured on
  Linux 7.0 / Ryzen 7 7800X3D with HTTP/1.1 over TLS (`tools/bench/ktls.sh`): the kernel's
  software TLS reached 0.83x of only-tls's own record layer at 1 KiB responses, 0.65x at 16 KiB,
  0.40x at 256 KiB, and 0.48x when it sent a 10 MB file with `sendfile` against only-tls's
  `pread` plus sealing, with 1.3x to 2.5x the server CPU per byte (docs/BENCHMARKS.md, "Kernel TLS
  (kTLS) evaluation"). It is not wired into `Tls` or the engine.
- The offload stays for re-measuring behind a new **experimental** `only-tls` feature,
  `experimental-ktls` (off by default, outside the semver promise, no public API): the blocking
  test stream (`only_tls::stream`, hidden) can offload after the handshake (TLS 1.3 and 1.2,
  AES-128/256-GCM and ChaCha20-Poly1305, alerts, close_notify, NewSessionTicket and KeyUpdate in
  both directions on Linux 6.14+, fallback to user space), with the `ktls-bench` example,
  `tls-interop --ktls` / `ONLY_INTEROP_KTLS=require tools/interop/tls/run.sh` (107/107 against
  OpenSSL and Go) and `crates/only-tls/tests/ktls.rs` (skipped without the `tls` kernel module).
  `only-sys` gained the hidden `ktls` module (`TCP_ULP`, `SOL_TLS`, record-type cmsgs) with the
  `linux/tls.h` structures checked against `libc` in the layout tests.
- Docs: the stale "rustls underneath" wording in the README, the book's crate list and the fib
  migration guide, and the ROADMAP's TLS row, now say what is true (own TLS 1.3 / 1.2).

### Performance: AES-GCM on VAES-AVX2 and masked tails in the AVX-512 kernel (`only-crypto`)

No public API change (a new `#[doc(hidden)]` `AesGcm::with_cipher_avx2` and `AesGcm::kernel`
for tests and benchmarks).

- x86_64 with VAES, VPCLMULQDQ and AVX-512: the whole message runs in one call of the 512-bit
  kernel. An AAD of up to 256 bytes is hashed in the kernel, the last partial group (1 to 255
  bytes) is loaded and stored under AVX-512 byte masks instead of going through the 128-bit path,
  and the length block and `E(J0)` give the tag in the same call; messages under 256 bytes hash
  their AAD, data and length block under one reduction. AES-128-GCM seal 1 KiB 7,902 → 10,433
  MB/s (1.00× → 1.32× ring), 1400 B 8,356 → 10,632 (1.10× → 1.46×), 64 B 1,204 → 1,383
  (1.11× → 1.29×); open 1 KiB 1.04× → 1.22×; 16–64 KiB unchanged (1.16–1.18×).
- x86_64 with VAES and VPCLMULQDQ but no AVX-512 (Zen 3, Alder Lake / Raptor Lake): a new
  VAES-AVX2 kernel, sixteen blocks per iteration in eight 256-bit registers with one GHASH
  reduction per group, for whole 256-byte groups (the rest on the 128-bit path). Measured on
  Zen 4 with the AVX-512 kernel switched off (no Zen 3 available): 1.55–2.35× the 128-bit kernel
  those CPUs used before (AES-128 seal 16 KiB 6,310 → 12,671 MB/s).
- TLS 1.3 records in `only-tls` follow: AES-128-GCM 1 KiB 1.51× → 1.58× rustls + ring, 16 KiB
  1.56× → 1.60×. The record layer still zero-fills its output before the AEAD writes it: copying
  the plaintext in and sealing in place measured 6% slower at 16 KiB, a reused buffer would trade
  the memset for a copy, and skipping the fill (+10% at 16 KiB) needs `unsafe` in a
  `#![forbid(unsafe_code)]` crate, so it was not done (docs/BENCHMARKS.md).
- Tests: every kernel (AVX-512, AVX2, 128-bit, portable) against the others at every length
  0..=600, large sizes, every AAD length 0..=300 and past 512, misaligned, in place and out of
  place, and on the CAVP and Wycheproof vectors; the `crypto_aead` fuzz target compares the AVX2
  kernel too. Run natively on Zen 4, also with `ONLY_CRYPTO_PORTABLE=1`.
- `unsafe`: +5 blocks and +1 `unsafe fn` in `gcm::hw` / `gcm::hw::vaes` (the AVX2 kernel's two
  `asm!` blocks, the whole-message calls), documented in docs/unsafe-review.md. Miri never
  reaches the `asm!`.

### Fixed: SOCKS and HTTP CONNECT tunnels could hang under backpressure

- `only-socks`: a tunnel (SOCKS5/4/4a or HTTP `CONNECT`) could stop for good while relaying a
  large transfer. The engine's write backpressure (`Config::write_high_watermark`) paused reading
  the upstream connection whenever client data was queued for it, but those reads feed the
  client, not that queue. An upstream that does not read while its own writes are blocked (an
  echo server, most request/response servers) then waited on the proxy while the proxy waited on
  it. It showed up as a rare 10-second hang of `socks5_ipv4_domain_and_backpressure` on a loaded
  machine (kqueue, epoll and io_uring alike); an upstream that sends before it reads hung every
  time. Both ends of a tunnel are now paced only by the relay's own pause/resume. Backends honour
  a new hidden `ConnInner::set_relayed` (epoll, kqueue, io_uring, DPDK). No public API change.

### Performance: HTTP/3 request handling in `only-h3`, keyed fast hashing in `only-quic`

HTTP/3 GET with 64 requests in flight on one connection went from 429,038 to 838,721 req/s
(1.95×, median of seven alternating rounds; AMD Ryzen 7 7800X3D, loopback, CPUs 2–5); QUIC bulk
+5%, handshakes flat. In the profile the allocator fell from 31.8% to 11.2% of the samples and
SipHash from 7.3% to 0.1%. No API change; interop with quic-go and fib passes both ways.

- only-h3: request and response frames are read in place from the received stream data (only a
  trailing partial frame is buffered); a field section is decoded into one reused flat buffer,
  checked as UTF-8 in one pass and copied once into the request's or response's `Headers`, where
  it used to cost two `Vec`s per field, a `String` per name and value and a second header list.
- only-h3: HEADERS frames are QPACK-encoded straight into the outgoing buffer, with `:status`,
  `date` (formatted once a second per thread) and `content-length` written there instead of being
  added to the response's headers; static-table references are found by name length instead of
  two SipHash maps; a response's HEADERS, a body up to 16 KiB and its trailers go to QUIC in one
  write (larger bodies follow without a copy).
- only-h3: a request that arrives whole is read without entering the stream table; the stream
  tables are hashed with a multiply-fold (they are bounded by the stream limits we grant).
- only-quic: the endpoint's connection-ID tables and the tables of connections and client
  sockets (by peer address) use a hasher keyed with fresh random words per table (folded
  64×64→128-bit multiplies) instead of SipHash; a client chooses the connection ID of its first
  Initial, so the key keeps colliding IDs from being computed in advance. Connection IDs hash
  only their used bytes. On its own this is +3% bulk (a lookup per datagram); HTTP/3 with many
  requests per datagram does not notice it.
- only-quic: in-order stream acknowledgments move the send buffer's front directly instead of
  through the acknowledged-range tree (a node allocated and freed per acknowledgment), and the
  first chunk of a stream's send buffer is held inline, so a stream written once costs no queue
  allocation.
- only-http: `Response::text` and `Response::with_body` size the header storage once instead of
  growing it field by field.

### Performance: ChaCha20-Poly1305 on AVX-512 and IFMA in `only-crypto`, out-of-place TLS records

On x86_64 ChaCha20-Poly1305 seals 16 KiB at 4,597 MB/s (1,752 before, 1.30× ring), 1400 B at
2,541 (1,070, 0.96× ring) and 64 B at 412 (283, 0.83×); TLS 1.3 records with
TLS_CHACHA20_POLY1305_SHA256 went from 0.55× to 1.42× rustls + ring at 16 KiB and from 0.64× to
1.02× at 1 KiB (AMD Ryzen 7 7800X3D; docs/BENCHMARKS.md). No API change.

- ChaCha20 sixteen blocks per iteration in zmm registers with `vprold` rotations, the rest of a
  message in one group of sixteen, eight (ymm) or four (xmm) blocks, as `asm!` kernels
  (`chacha::hw::avx512`; the AVX-512 intrinsics are not stable at the MSRV). AVX2 stays the
  path for CPUs without AVX-512.
- Poly1305 eight blocks per step on AVX-512 IFMA (`chacha::hw::ifma`, `vpmadd52luq` /
  `vpmadd52huq` on 44-bit limbs) for runs of 256 bytes and more, detected through
  `Feature::Ifma`; elsewhere, and everywhere on other CPUs and on aarch64, a radix-2⁶⁴ scalar
  loop replaces the 44-bit two-block one (1.3× at 16 KiB on the AVX2 path).
- `ChaCha20Poly1305::encrypt_detached_from` / `decrypt_detached_from` (`#[doc(hidden)]`, like the
  AES-GCM ones): only-tls seals and opens ChaCha20-Poly1305 records out of place instead of
  copying first. `new_avx2` / `new_portable` (`#[doc(hidden)]`) pin a key to a narrower path
  for tests, the `crypto_aead` fuzz target and `examples/chacha-sizes.rs` (sizes against ring).
- Correctness: every length 0..=600 and large sizes through the AVX-512 / IFMA, AVX2 and
  portable paths, misaligned, in place and out of place, forged tags, counters near the wrap,
  Poly1305 on all-ones blocks and extreme `r` / `s`, run natively on Zen 4 with and without
  `ONLY_CRYPTO_PORTABLE=1`. `unsafe`: +6 blocks, +2 `unsafe fn` (docs/unsafe-review.md).

### Added: aarch64 assembly for P-256 and X25519 in `only-crypto` (not benchmarked yet)

On aarch64 the P-256 field and group-order arithmetic and the X25519 ladder's field now run in
inline assembly (`ec::hw_aarch64`, `curve25519::hw_aarch64`), the counterparts of the x86_64
BMI2 + ADX code; no API change.

- P-256: Montgomery multiplication and squaring modulo `p` and `n`, addition, subtraction,
  `2ᵏ·a` and `3·a` on four 64-bit limbs with `MUL`/`UMULH` products, `ADDS`/`ADCS`/`SUBS`/`SBCS`
  carry chains and `CSEL` corrections; the reduction modulo `p` needs shifts and subtractions
  only (as OpenSSL's `ecp_nistz256-armv8`), modulo `n` two of the four limb products are shifts.
  `P256` dispatches to a twin curve on this field, as on x86_64; inversions are safegcd (portable
  divsteps) with the final multiplication in assembly, and the twin keeps the portable defaults of
  the `Curve::jac_*` hooks (point formulas, table scans, 4-bit comb) over the assembly field.
- X25519: the ladder's field on four 64-bit limbs (16 `MUL` + 16 `UMULH` per product instead of
  the 25 128-bit products of radix 2⁵¹), folds by `2²⁵⁶ ≡ 38` with `CSEL`, masked swaps.
- Every ARMv8.0 CPU has these instructions: `hardware_features()` reports `umulh` on aarch64;
  `ONLY_CRYPTO_PORTABLE=1` / `set_portable(true)` switch back to the portable code, and Miri
  never runs the assembly.
- Correctness: differential tests against the portable field code on random and edge values and
  on chains of 20,000–50,000 dependent operations, the twin curve against the portable curve
  (key generation, ECDH, signing, verification), the RFC 7748 vectors (including the
  1,000,000-iteration one, `--ignored`), Wycheproof, all on macOS (Apple silicon) and arm64
  Linux. The release code of the secret paths was disassembled: no conditional branch in the
  assembly, and around it only loop counters, public bounds, CPU-feature checks and the final
  identity test.
- **Not benchmarked yet**: the design follows the instruction counts; no aarch64 speed-up is
  claimed until it is measured.

### Performance: HTTP/2 and pipelined HTTP/1 hot paths in `only-http`

Re-profiled after the in-house replacements (DEV-PLAN "Performance pass"); no API change.

- HTTP/2: frames are parsed in place from the read buffer (no copy per frame, the leftover moved
  once per read); decoded header fields go into one reused buffer instead of two `Vec`s per
  field; header blocks are HPACK-encoded straight into the output, with `:status`, `date` and
  `content-length` written there; a body that fits one DATA frame and the flow-control windows
  skips the stream queue; the stream table uses a multiply-fold hasher instead of SipHash.
- HTTP/2: everything one read produces, including the responses the service sends on the I/O
  thread, is handed to the connection in a single write at the end of the read (one TLS record
  for the batch instead of one per response); responses sent from other threads join the batch
  while a read is being handled and go out immediately otherwise.
- HTTP/2 flow control: the connection and stream receive windows are given back once a quarter
  of them is owed, instead of two WINDOW_UPDATE frames per DATA frame.
- HTTP/1: request heads are parsed with room for 32 fields first (100 only when needed), and the
  fields framing needs (`Host`, `Connection`, `Content-Length`, `Transfer-Encoding`, `Expect`)
  are found in one pass.
- Ryzen 7 7800X3D, 4 server threads (epoll): h2c 64 connections x 16 streams 2.28M → 4.05M
  req/s (1.78x, now 1.25x fib), h2c 16 x 128 2.37M → 4.71M, HTTP/2 over TLS 1.58M → 4.03M (2.5x,
  1.33x fib), pipelined HTTP/1.1 x16 3.99M → 4.26M (+7%, 1.14x fib). h2spec: 147/147. Tables
  in docs/BENCHMARKS.md; the harness (`tools/bench`, now with a README) drives HTTP/1.1 with
  `h2load --h1` when wrk is missing and gained h2-over-TLS and many-streams cases.

### Performance: CPU acceleration in `only-crypto`

`only-crypto` now uses CPU instructions where the CPU has them, detected at run time, each with
the constant-time portable code as fallback (DEV-PLAN "Performance pass"); no API change.

- x86_64: SHA-NI for SHA-1 / SHA-256, AES-NI CTR eight blocks at a time, AES-GCM with PCLMULQDQ
  GHASH (eight blocks per reduction) fused into the CTR pass, PCLMULQDQ folding for CRC-32 and
  CRC-32C plus the SSE4.2 `crc32` instruction, AVX2 ChaCha20 (eight blocks).
- aarch64: ARMv8 SHA1/SHA2, ARMv8 AES CTR, PMULL GHASH fused with CTR, ARMv8 CRC32 instructions;
  ChaCha20 in a 4-block lane layout the compiler vectorizes (also the portable path elsewhere).
- Safe Rust: Poly1305 in 44-bit limbs (two blocks per step); P-256 with a dedicated Montgomery
  reduction, an addition-chain inversion, a signed comb of affine points for `[k]G` and Jacobian
  wNAF verification without inversion; Ed25519 verification by interleaved wNAF; squaring
  routines for Curve25519, the NIST fields and RSA; fixed-size RSA Montgomery multiplication;
  windowed exponentiation for the remaining inversions.
- `unsafe` stays confined to the instruction modules (`aes::hw`, `gcm::hw`, `hash::hw`,
  `crc::hw`, `chacha::hw`), every call behind detection (docs/unsafe-review.md).
  `ONLY_CRYPTO_PORTABLE=1` forces the portable code (tests, benchmarks); Miri runs it.
- Ryzen 7 7800X3D, one core: SHA-1 3.6x and SHA-256 6.5x (equal to the RustCrypto crates),
  AES-128-GCM 364 → 6 484 MB/s, CRC-32 2.7 → 20 GB/s, ChaCha20-Poly1305 3x, P-256 verify 1.67x /
  sign 1.46x, Ed25519 verify 1.49x, RSA-2048 sign 1.38x; TLS 1.3 handshakes 1.5x and 16 KiB
  AES-GCM records 15x (0.60x and 0.64x rustls + ring). Tables in docs/BENCHMARKS.md.

### Performance: faster TLS 1.3 handshakes (P-256 and X25519 in `only-crypto`)

The handshake profile was >98% curve arithmetic; no API change (`tools/api/public-api.sh`
unchanged). Measured in memory on one core of the bench host, against rustls 0.23 + ring:
full handshakes 3,055 → 5,027/s with X25519 (0.61× → 1.00× rustls) and 2,306 → 4,552/s with
secp256r1 (0.45× → 0.89×).

- P-256 on x86_64 with BMI2 + ADX (run-time detection, new `cpu` feature `adx`): Montgomery
  multiplication and squaring modulo `p` and modulo the group order, addition, subtraction and
  small multiples in inline assembly (`mulx`, `adcx`/`adox`, `cmov`; new hardware module
  `ec::hw`). The operations run on a twin curve type that shares the Montgomery form and the
  base point tables, so the dispatch happens once per operation.
- Constant-time scalar multiplication in Jacobian coordinates with the `a = -3` formulas:
  Booth-recoded signed 5-bit windows for the variable base (ECDH) and the signed comb with mixed
  additions for the fixed base (key generation, signing). The identity cases are masked selects;
  equal operands cannot occur for scalars in `[1, n)` (proof in the code, `n mod 32 ≥ 17` checked
  by a test). Doublings are 4M + 4S with fused `2ᵏ·a`/`3·a`.
- The P-256 scalar inversion uses a dedicated chain (255 squarings, 40 multiplications); ECDSA
  verification inverts `s` (public) with a binary extended Euclidean algorithm and builds its
  table from projective keys without an inversion. Public keys from `SecretKey::public_key` stay
  projective until encoded (one constant-time inversion then).
- X25519: public keys are `[k]B` on edwards25519 mapped to `u = (1 + y)/(1 - y)` (the Ed25519
  base table, now affine Niels entries with signed digits: 7M per digit), and on x86_64 with
  BMI2 + ADX the ladder runs on four 64-bit limbs in inline assembly (`curve25519::hw`); the
  radix-2⁵¹ ladder stays the portable path.
- Micro-benchmarks against ring (`--example pk_bench`, op/s, before → after): P-256 sign
  34,152 → 59,837 (0.45× → 0.79×), verify 13,404 → 25,138 (0.51× → 0.96×), ECDH 10,380 → 27,288
  (0.35× → 0.91×), key generation 54,581 → 108,263 (0.49× → 0.96×); X25519 30,696 → 36,488
  (0.84× → 1.00×); Ed25519 sign 1.15× → 1.53× ring; P-384 sign, verify, ECDH and key generation
  1.13–1.47× faster than before. RSA is unchanged.
- Constant-time evidence: the disassembly of the secret-scalar paths (x86_64 with the assembly,
  aarch64 portable) has conditional branches only on loop counters, public indices, the public
  exponent bits of the inversion chains, CPU-feature checks and the "result is the identity"
  test (`ct.rs`). Every assembly routine is compared with the portable code on random and edge
  values, and all known-answer tests run with and without `ONLY_CRYPTO_PORTABLE=1`.
- `unsafe`: +13 `asm!` blocks in `only-crypto` (8 in `ec::hw`, 5 in `curve25519::hw`; see
  docs/unsafe-review.md).

### Performance: wide AES-GCM and CRC in `only-crypto`, out-of-place TLS records

No public API change (new `#[doc(hidden)]` helpers only).

- x86_64 with VAES, VPCLMULQDQ and AVX-512 (Zen 4, Ice Lake and later; detected with CPUID and
  XCR0): AES-GCM seal and open run as one 512-bit pass, sixteen blocks per loop iteration with
  the AES rounds interleaved with the GHASH of the previous group and one reduction per sixteen
  blocks (the BoringSSL / Linux `aes-gcm-avx10` design, written as `asm!` because those
  intrinsics are newer than the MSRV). The 512-bit kernel was faster than the same kernel on
  256-bit registers at every size on Zen 4, so only it ships; other CPUs keep the AES-NI +
  PCLMULQDQ kernel. CRC-32 / CRC-32C fold 256 bytes per step on 512-bit registers from 512 bytes.
- Every CPU with AES and carry-less multiplication: the last bytes of a message and `J0` go
  through AES in one call, and a short AAD, the tail ciphertext and the length block through one
  GHASH call (64-byte messages 1.8–2.1x).
- `only-tls` seals and opens records out of place: the AEAD reads the caller's plaintext or the
  received record and writes its output once, instead of copying first and working in place
  (the copy was 30% of a 16 KiB record).
- Ryzen 7 7800X3D, one core: AES-128-GCM seal 16 KiB 6,455 → 15,048 MB/s (0.51x → 1.19x ring),
  1400 B 4,249 → 8,163, 64 B 611 → 1,185; TLS 1.3 records seal + open 16 KiB 2,739 → 6,603 MB/s
  (0.69x → 1.65x rustls + ring); CRC-32 16 KiB 20.0 → 74.9 GB/s (0.27x → 1.02x crc32fast). Tables
  in docs/BENCHMARKS.md.
- `unsafe`: the new `gcm::hw::vaes` kernel, the `asm!` CRC fold and CPUID / XGETBV (`cpu::hw`),
  each documented in docs/unsafe-review.md. Miri never reaches the `asm!` (nothing is detected).

### Performance: P-256 whole-point assembly, wide comb and safegcd in `only-crypto`

No API change (`tools/api/public-api.sh` unchanged). Measured on one core of the bench host
against ring 0.17 / rustls 0.23 in the same run (median of five alternating rounds; the host was
loaded by another benchmark, so absolute rates are 20–30% low, see docs/BENCHMARKS.md): P-256
sign 0.77× → 1.25× ring, key generation 0.94× → 1.33×, verify 0.98× → 1.04×, ECDH 0.94× → 0.96×;
TLS 1.3 secp256r1 handshakes 0.94× → 1.12× rustls.

- x86_64 with BMI2 + ADX: the Jacobian doubling (`a = -3`), addition and mixed addition of the
  P-256 twin are each one `asm!` block over a small stack frame, the products and reductions
  fused with the modular additions, subtractions and doublings around them (the accumulator stays
  in registers; the low half of each product is reduced on its own and the high half added
  after). Consecutive doublings (five per ECDH window, runs between additions in verification)
  share one frame. A doubling costs ~355 cycles instead of ~480. The curve trait gained hooks
  for these routines and the table scans, so an aarch64 twin can plug in the same way.
- Fixed base (key generation, signing) on the twin with AVX2: Booth-recoded signed 6-bit digits
  over a 43-row comb of 32 affine points each (88 KiB, built on first use), 43 mixed additions
  instead of 65; every row is scanned with 256-bit loads and `vpcmpeqq` masks. 6- and 7-bit combs
  measured equal, 5 and 8 bits slower. The ECDH window table is scanned the same way. Without
  AVX2 the 4-bit comb stays.
- Inversion modulo the P-256 prime and order by safegcd (Bernstein–Yang divsteps in
  libsecp256k1's form, new module `safegcd`), constant time, with the divsteps in assembly on
  x86_64 and masked Rust elsewhere: the scalar inversion of signing 20.9k → 7.0k cycles, the
  field inversion ~12.7k → ~7–9k. It replaces the Fermat chains on every path, portable included.
- Correctness: the whole-point routines are compared limb for limb with the portable formulas
  on random points with random `Z`, every valid Wycheproof ECDH point, `P + P`, `P + (-P)` and
  the identity; safegcd against Fermat on random and edge inputs for both moduli; the wide comb
  against the complete-formula reference on random and edge scalars (every top digit); the
  equal-operand argument for the wide comb is in `ec/hw.rs`.
- Constant-time evidence (Zen 4 release disassembly): no conditional branch in the point
  routines, the AVX2 scans and `Fe::invert`; one (the loop counter) in each `divsteps_59`; in
  `ecdh_x_impl`, `sign_impl` and `hw::mul_base` only CPU-feature and `OnceLock` checks, loop
  counters, public digit positions and bounds, the output length and the final identity test.
- `unsafe`: +6 blocks and +2 `unsafe fn` in `ec::hw` (the point blocks share one, the divsteps
  block, two AVX2 scans and their two calls; docs/unsafe-review.md).

### Performance: cheaper P-256 point formulas on x86_64 in `only-crypto`

No API change (`tools/api/public-api.sh` unchanged). Measured on a quiet bench host (Zen 4, CPU 2,
median of five alternating rounds, ring 0.17 in the same run): P-256 ECDH 1.08× → 1.12× ring
(32,351 → 33,904 op/s), sign 1.36× → 1.38×, verify 1.08× → 1.10×, key generation 1.36× →
1.40×. The 0.96× of the previous entry was measured on a loaded host; quiet, the code before this
change already did 1.08×. TLS 1.3 handshakes did not move (secp256r1 1.07×, X25519 1.08× rustls):
one ECDH is about 1% of a handshake.

- The whole-point assembly of the P-256 twin uses the formulas of OpenSSL's `ecp_nistz256`: the
  addition is 12M + 4S with seven modular additions and subtractions instead of add-2007-bl's
  11M + 5S with thirteen (the products cost the same as the squares here, the linear operations
  do not), the mixed addition 8M + 3S instead of 7M + 4S (seven against fourteen), and the
  doubling computes `2Y` first, so `Z₃ = 2Y·Z`, `4β = X·(2Y)²` and `8γ² = ((2Y)²)²/2` (a new
  modular halving) need ten linear operations instead of fourteen. The additions return another
  representative of the same point (`(X, Y, Z)` instead of `(4X, 8Y, 2Z)`); the doubling the same
  limbs.
- The Montgomery reduction inside the point routines keeps `p₃` in `rdx` for its four steps and
  splits `m·2⁹⁶` with `shlx`/`shrx` (the compiler-reserved `rbx` holds the count 32, saved and
  restored in the frame): ten instructions per step become seven.
- Cycles (`perf stat`, Zen 4): addition 745 → 721, mixed addition 537 → 508, doubling 355 → 348,
  variable-base multiplication 148.1k → 140.6k, fixed-base (comb) 29.8k → 28.9k. The doubling
  measures as a fixed ~44 cycles per product: reordering it (independent products first, or the
  `Y` chain first) made it 8–10% slower, an OpenSSL-style reduction interleaved with the product
  rows was neutral, and replacing the `cmov` selections by `xor`/`and` masks was 10% slower, so
  none of them is in.
- Correctness: `points_match_portable` compares the doublings limb for limb and the additions as
  points (cross-multiplied, `Z = 0` exactly where the portable formulas give it), now also with
  the all-zero identity on either side; the halving is checked on random and edge values.
- Constant time: the release disassembly on Zen 4 has the same conditional branches as before in
  `ecdh_x_impl` (17: loop counters, public digit positions and bounds, CPU-feature checks, the
  output length and the final identity test), `hw::mul_base`, `divsteps_59` and `safegcd::inv_with`,
  and none in the point routines.
- `unsafe`: no new block; the point block saves and restores `rbx` (docs/unsafe-review.md).

### Performance: RSA on BMI2 + ADX and AVX-512 IFMA in `only-crypto`

No API change (`tools/api/public-api.sh` unchanged). Measured on a quiet bench host (Zen 4,
CPU 2, three alternating rounds of the old and new binaries, ring 0.17 in the same run, op/s):
RSA-2048 PKCS#1 v1.5 sign 1,192 → 3,910 (0.49× → 1.61× ring), RSA-3072 371 → 1,455 (0.47× →
1.85×), RSA-4096 156 → 755 (0.45× → 2.19×); verify 39,250 → 79,970 (0.60× → 1.22×), 18,300 →
33,440 (1.10×), 10,110 → 19,090 (1.09×); verify including the public-key parse (one
certificate signature; ring parses on every call) 5,850 → 67,090 (0.09× → 1.02×), 0.95× and
0.95× at 3072 and 4096 bits. only-tls full handshakes with an RSA-2048 certificate (new
`tls-bench` row): 775 → 2,586/s, 0.43× → 1.44× rustls + ring.

- On x86_64 with AVX-512 IFMA (new `cpu` feature `ifma`: CPUID leaf 7 with the AVX-512 state)
  the CRT exponentiations of 2048-, 3072- and 4096-bit keys run in radix 2⁵² (`bignum::ifma`):
  almost Montgomery multiplication over 20, 32 or 40 digits, one `asm!` block per product with
  the operands in registers (`ymm` for 20 and 32 digits, `zmm` for 40), two accumulators at 20
  digits so each register takes two dependent multiply-adds per step, the low digit and the next
  `yᵢ` computed in general-purpose registers so that chain bypasses the vector unit, the carries
  normalized with a generate / propagate mask word. Results stay below `2p` through the whole
  exponentiation; one masked subtraction at the end. A 1024-bit multiplication takes 416 cycles.
- Without IFMA, with BMI2 + ADX: Montgomery multiplication and squaring for 16 to 64 limbs in
  `asm!` (`bignum::hw`; operand scanning with `mulx` and the two carry chains, rows unrolled with
  the assembler's `.rept`, the next reduction factor taken from a register, a dedicated squaring
  up to 32 limbs, the final subtraction by `cmovnz`): a 1024-bit multiplication 1,240 → 805
  cycles, squaring 1,490 → 681; RSA-2048 signing on this path alone measured 0.99× ring,
  verification 1.20×.
- Exponentiation: fixed 5-bit windows (were 4) over a flat table built with squarings for the
  even entries, every lookup one pass over all 32 entries with AVX2 `vpcmpeqq` masks (the
  constant-time `ct` masks without AVX2).
- `R² mod m`: `64 + k` doublings and six Montgomery squarings instead of `128k` doublings for the
  secret primes (constant time), one long division for public moduli; key parsing is no longer
  the cost of a certificate check. The private operation keeps the blinding (now squared with
  the dedicated squaring), drops four 2048-bit conversions and reduces the blinded input into
  each prime field with three multiplications.
- Karatsuba was not tried: at these sizes the assembly row loops leave little to save.
- Correctness: `asm_matches_generic` (the BMI2 + ADX code at every size against the generic CIOS
  on random values and 0, 1, m - 1, m - 2, R - 1, R - m, full and short top limbs, a 200-step
  chain), `ifma_pow_matches` (the IFMA exponentiation against square-and-multiply, edge bases and
  exponents), `r2_constructions`; `rsa_vs_ring` now signs with 2048-, 3072- (new) and 4096-bit
  (new) keys and requires byte-identical PKCS#1 v1.5 signatures, also with the portable code
  forced; the Wycheproof RSA vectors are unchanged and pass on both paths.
- Constant time: the release disassembly on Zen 4 lists only loop counters, the public limb- and
  digit-count dispatch, CPU-feature, slice and allocation checks, public window offsets, the
  blinding cache and the final fault check in `Mont::mul_into` / `sqr_into`, `ifma::amm`,
  `ifma::pow`, `Mont::pow`, the table scans, `Mont::new`, `crt_combine` and `private_op`
  (counts in `src/ct.rs`).
- `unsafe`: +7 blocks and +1 `unsafe fn` in `only-crypto` (`bignum::hw`: the two Montgomery
  blocks and the AVX2 scan; `bignum::ifma`: the IFMA blocks); see docs/unsafe-review.md.

### Added: statistical timing test for `only-crypto` (`tools/ct-dudect`)

A dudect-style test (Welch's t-test of fixed vs random secrets, random interleaving, `rdtsc` /
`cntvct_el0`, percentile cropping and a second-order test, `|t| > 4.5` a leak) of the
secret-dependent paths on the hardware and the portable code: P-256 ECDH, key generation and
signing, X25519 and its key generation, Ed25519 signing, RSA-2048 signing, AES-GCM and
ChaCha20-Poly1305 tag checks, HMAC verification, `ct_eq` and the `ct.rs` primitives, with an A/A
test and two deliberately leaky functions as sanity checks. A new workspace-internal tool (not
published, no new dependency); runs in CI as the informational job `ct-dudect` (not part of
`ci-ok`, t-values kept as an artifact). On Zen 4 nothing leaks beyond two small, intermittent
differences under investigation (the degenerate all-zero X25519 scalar, P-256 portable signing
at the threshold); method and results in [docs/constant-time.md](docs/constant-time.md).

### Performance: stored blocks copied once in `only-deflate`

No API change; compressed output is byte-identical. Measured on the bench host (Zen 4, CPU 2,
five alternating rounds of the old and new `bench` binaries, zlib-rs in the same run):
inflating random data at level 6 (stored blocks) 15,456 → 34,278 MB/s (0.43× → 0.94×
zlib-rs), level 9 15,357 → 34,003 MB/s. Text and JSON (literals and matches) are unchanged.

- Stored blocks are copied straight from the input to the caller's output instead of through
  the window, and only the last window's worth of a run of stored data (up to 32 KiB, once per
  call, before a compressed block or the trailer needs it) enters the history afterwards.
- `Inflater::decompress_vec` appends stored data with `extend_from_slice` (no zero-filled room
  to copy into); block headers are decoded with no output space. `decompress` reserves room for
  twice the input (at most the limit) up front.
- Tested with stored blocks split at every input byte and every output size in the three
  formats, through `decompress` and `decompress_vec`, and stored blocks longer than the window
  (up to 65,535 bytes) followed by matches at the largest distance, for 512-byte, 4 KiB and
  32 KiB windows.
- Tried and dropped: decoding up to five literals per refill instead of three on the
  literal-heavy path made no measurable difference.

### Performance: QUIC datapath (GRO by default, per-batch ACKs, pooled receive buffers)

No API change (`tools/api/public-api.sh` unchanged: the new hook is `#[doc(hidden)]`). One
default changed: `Config::udp_gro` is now `true`. Measured on the bench host (Zen 4, loopback,
`quic-bench` client and server on CPUs 2–5, median of seven alternating old/new rounds, an
outside workload on the host during some of them): one-stream bulk 6,378 → 16,066 Mbit/s
(2.52×), HTTP/3 427,901 → 443,299 req/s (1.04×), full handshakes 9,294 → 9,542/s (flat). The
quinn-proto build of the same program did 4,613 Mbit/s and 56,934 req/s in the same run as
15,999 Mbit/s and 430,098 req/s for this one (3.5× and 7.6×).

- `only-core`: `Handler::on_batch_end` (`#[doc(hidden)]`, default no-op, outside the stability
  promise) tells a UDP handler that the receive batch that called its `on_data` is over. The UDP
  loop of only-epoll, which also serves UDP on the io_uring backend and on macOS, calls it once
  per connection and batch (one `recvmmsg`; up to 32 `recv_from`/`recv` calls on macOS), before
  the batch's replies are flushed; dialed connections that fill a whole batch now flush after
  each one instead of after up to eight. Other backends (only-dpdk) never call it.
- `Config::udp_gro` defaults to `true` (Linux, where the kernel supports `UDP_GRO`; probed once,
  `ONLY_UDP_GRO=0` still turns it off, `read_buffer` must stay at least 64 KiB). Coalesced
  receives are split by the `UDP_GRO` segment size on server, bound and dialed sockets as before,
  so `on_data` still sees one datagram per call (only-kcp, only-turn, only-webrtc and DNS tests
  pass unchanged). Bulk QUIC 6.4 → 9.8 Gbit/s on its own: a GSO batch from the sender reaches the
  receiving socket whole instead of being segmented. 64-byte UDP echo with GRO on and off, 15
  alternating rounds each: no difference beyond the noise of the case.
- The UDP loop reads the clock once per receive call and chains the end of each timed callback
  into the start of the next (as the TCP loops do): three clock reads per datagram become one.
- only-quic acknowledges once per receive batch: after each datagram the handler runs and data
  that is ready goes out right away, but an ACK-only packet waits for `on_batch_end` (one per
  batch instead of one per two packets); the QUIC timer is armed once per batch too. A variant
  that also deferred handler events and data to the batch end measured 1.45× on bulk but cost
  28% on HTTP/3 (64 requests in flight became one lock-step batch per round trip), so it is not
  in. Until a socket's first `on_batch_end` (and on backends without it) every datagram is
  driven on its own, as before.
- Received datagrams are copied once into a per-thread pool of buffers (`Arc<Vec<u8>>`) and
  decrypted in place; stream data and datagrams are `Bytes` slices of them, and a buffer is reused
  once all its slices are dropped (on any thread). This replaces two allocations per packet (the
  copy and the `Arc` around it). A copy remains: the handler gets the `recvmmsg` slot by
  reference, and decrypting in place needs a buffer this side owns alone.
- Sent packets are kept in a ring indexed by packet number (`proto/conn/sent.rs`) instead of a
  `BTreeMap`, and the frame lists of acknowledged or lost packets are reused for new packets.
- Profile notes not acted on: SipHash on the peer address and connection ID maps (~2% of the
  receiver), and allocations and header hashing in only-h3/only-http (`encode_fields`,
  `Headers`), which dominate the HTTP/3 profile.

### Changed (breaking, before 1.0.0): pre-1.0 dependencies wrapped

rustls 0.23, quinn-proto 0.11, str0m 0.24 and prost 0.13 no longer appear in the covered API, so
upgrading them (or replacing them with in-house code) is not a breaking change after 1.0.0.
Raw access moved behind new `unstable` cargo features (`only`, `only-tls`, `only-quic`,
`only-webrtc`), outside the semver promise like the `prost` feature of `only-grpc`
(docs/api-stability.md, "Public dependencies").

| Before | After |
|---|---|
| `only::tls::rustls` (re-export) | `unstable` feature only |
| `rustls::ServerConfig::builder()...with_single_cert(chain, key)` + `alpn_protocols` | `only::tls::ServerConfig::builder(chain, key).alpn([..]).build()?` (also `sni_cert`, `client_auth_required` / `_optional`, `session_cache`, `session_tickets`, `tls13_only`) |
| `rustls::ClientConfig::builder().with_root_certificates(roots)...` | `only::tls::ClientConfig::builder().roots(roots).alpn([..]).build()?` (also `client_cert`, `sni`, `resumption`, `tls13_only`, `insecure_skip_verify`) |
| `CertificateDer`, `PrivateKeyDer`, `RootCertStore` | `only::tls::{Certificate, PrivateKey, RootCerts}` (`from_pem`, `from_der`, `from_pkcs8_der`) |
| `Tls::server(Arc<rustls::ServerConfig>, a)`, `Tls::client(Arc<rustls::ClientConfig>, ..)` | `Tls::server(ServerConfig, a)`, `Tls::client(ClientConfig, ..)` |
| `Client::with_tls(Arc<rustls::ClientConfig>)`, `H2Client::dial(.., Some((Arc<..>, name)), ..)`, `DialOptions::tls: Option<Arc<..>>` | the same with `only::tls::ClientConfig` |
| `only_quic::{proto, rustls}` re-exports, `VarInt` | `unstable` feature only (`proto`); `VarInt` removed |
| `only_quic::{StreamId, Dir, ConnectionError, TransportConfig}` (quinn's) | `only`'s own types (plus `Side`, `Congestion`, `UdpStats`); `ConnectionError` variants are struct-like (`ApplicationClosed { code, reason }`, `TransportError { code, reason }`) |
| `Connection::stats() -> quinn_proto::ConnectionStats` | `ConnectionStats` (`udp_tx`, `udp_rx`, `rtt`, `cwnd`, `lost_packets` ...) |
| `server_config(Vec<CertificateDer>, PrivateKeyDer, alpn) -> quinn_proto::ServerConfig` | `server_config(Vec<Certificate>, PrivateKey, alpn) -> only_quic::ServerConfig` (`.transport(&TransportConfig)`, `.migration(bool)`) |
| `server_config_from(rustls::ServerConfig)`, `client_config(RootCertStore, ..)`, `client_config_from(rustls::ClientConfig)` | `server_config_from(&only::tls::ServerConfig)`, `client_config(RootCerts, ..)`, `client_config_from(&only::tls::ClientConfig)` |
| `Error::Connect(quinn_proto::ConnectError)` | `Error::Connect(String)` |
| `only_h3::server_config(Vec<CertificateDer>, PrivateKeyDer)`, `serve(quinn_proto::ServerConfig, ..)`, `H3Client::dial(.., quinn_proto::ClientConfig)` | `Certificate` / `PrivateKey`, `only_quic::ServerConfig`, `only_quic::ClientConfig` |
| `only_grpc::codec::{encode, decode}` bound on `prost::Message` | bound on `only_grpc::codec::Message` (`encode_to`, `decode_from`); the `prost` feature implements it for prost messages |
| `only_webrtc::str0m` re-export, `Peer::with_rtc`, `crypto_provider`, `generate_certificate` | `unstable` feature only (`str0m`, `with_rtc`, `crypto_provider_str0m`); `generate_certificate` is internal |
| str0m's `ChannelId`, `ChannelConfig`, `Reliability`, `Mid`, `Pt`, `MediaKind`, `Direction`, `Frequency`, `MediaTime`, `MediaData`, `MediaAdded`, `KeyframeRequest(Kind)`, `RtpPacket`, `Candidate`, `IceConnectionState`, `RtcConfig`, `Event` | `only`'s own types of the same names (`ChannelConfig` is `#[non_exhaustive]`: `ChannelConfig::new(label)` then set fields; `MediaData::data` / `RtpPacket::payload` are `Arc<[u8]>`) |
| `create_offer(h, \|api: &mut SdpApi\| ..)`, `renegotiate(..)`; `api.add_channel(label.into())`, `api.add_media(kind, dir, None, None, None)` | `SdpChanges`: `add_channel(label)`, `add_channel_with_config(&cfg)`, `add_media(kind, dir, None, None)`, `set_direction`, `stop_media`, `ice_restart` |
| `Peer::open_channel(ChannelConfig)`, `payload_type(mid, str0m::format::Codec)` | `open_channel(&ChannelConfig)`, `payload_type(mid, only_webrtc::Codec)` |
| `PeerHandler::on_event(&str0m::Event)` | `on_event(&Event)`: `Event::ChannelBufferedAmountLow(id)` or `Event::Other(OtherEvent)` |
| `Error::Rtc(str0m::RtcError)`, `impl From<str0m::RtcError> for Error` | `Error::Rtc(only_webrtc::RtcError)`; new `Error::InvalidCandidate` |
| `Endpoint::add_candidate(str0m::Candidate)` | `Candidate::host(addr)` / `server_reflexive(addr, base)` / `relayed(addr, base)` / `parse(sdp)` |

### Changed (breaking, before 1.0.0): own logging facade `only-log` replaces `log`

DEV-PLAN wave B. `only` no longer depends on the `log` crate; it logs through the new public
crate `only-log` (no dependencies, re-exported as `only::log`): levels, targets, structured
key-values with `log`'s macro syntax, a global maximum level in an atomic (a disabled statement
costs one relaxed load: 0.25-0.29 ns against `log`'s 0.36 ns), a `Logger` trait with
`set_logger` / `set_boxed_logger`, and built-in loggers (`only::log::init(level)` for formatted
lines on stderr, `StderrLogger`). Targets, messages and key names are unchanged; without a
logger, errors and slow-callback warnings still go to stderr. The new `log` cargo feature
(`only`, `only-core`, `only-log`; outside the semver promise) bridges to the `log` crate: records
go to `log`'s logger while no only-log logger is installed (and `Config::log_level` also sets
`log::max_level`, as before), and `only::log::bridge::route_log_to_only()` sends `log` records
(str0m, rustls ...) to the only-log logger.

Migration:

| Before | After |
|---|---|
| `env_logger::init()` (or any `log` logger) | unchanged, with `features = ["log"]` on `only`; or drop it for `only::log::init(only::log::LevelFilter::Info)` |
| `cfg.log_level = Some(log::LevelFilter::Info)` | `Some(only::log::LevelFilter::Info)` (with the `log` feature, `Some(log::LevelFilter::Info.into())` also works) |
| `Telemetry::set_log_level(log::LevelFilter)` | `set_log_level(only::log::LevelFilter)` |
| `impl log::Log for MyLogger` | `impl only::log::Logger for MyLogger` (`enabled` and `flush` have defaults); install with `only::log::set_logger` |
| `record.key_values().visit(&mut visitor)` | `record.key_values().iter()` / `.get("conn_id")`; values implement `Display` |
| `log::max_level()` | `only::log::max_level()` |

### Changed: in-house cryptography (`only-crypto`, DEV-PLAN wave A)

- New internal crate `only-crypto` (std only, `#![deny(unsafe_code)]` except its AES-NI / ARMv8
  AES module): SHA-1, SHA-224/256, SHA-384/512, MD5, HMAC, HKDF, PBKDF2, CRC-32 / CRC-32C,
  AES-128/192/256 (CPU instructions when detected, else constant-time fixsliced software) with CTR, AES-GCM with a constant-time GHASH, ChaCha20-Poly1305, base64 (strict decoding), OS
  randomness and a ChaCha20 generator. Tested against NIST CAVP, RFC and Wycheproof vectors and
  cross-checked (tests and fuzz targets) against the crates it replaces.
- `only-kcp`, `only-turn`, `only-ws`, `only-http`, `only-media`, `only-bittorrent` and
  `only-webrtc` use it instead of sha1, sha2, md-5, hmac, pbkdf2, aes, aes-gcm, ctr, crc32fast,
  base64 and getrandom (those remain dev-/fuzz-only references, and transitively under
  str0m/dimpl until wave D). Public APIs and wire formats are unchanged (KCP crypt incl. golden
  datagrams sealed by the old code, TURN MESSAGE-INTEGRITY/FINGERPRINT, WebSocket accept keys,
  BitTorrent info hashes and MSE, SRT key wrap and AES-CTR, RTMP digest handshake, SRTP).
- `only-sys` (internal, `#[doc(hidden)]`): `fill_random` over `getrandom(2)` / `getentropy(2)`
  with a `/dev/urandom` fallback.
### Added: public-key cryptography and X.509 (`only-crypto`, new `only-x509`, DEV-PLAN wave B)

Groundwork for the own TLS 1.2/1.3, DTLS, QUIC and WebRTC stacks (waves C and D); nothing uses
it in the protocol crates yet, so no behaviour changes.

- `only-crypto` (internal tier; additive API): X25519 (RFC 7748), Ed25519 (RFC 8032, strict
  verification: canonical `S`, encoded-`R` comparison), ECDH and ECDSA on P-256 and P-384
  (RFC 6979 deterministic nonces, DER and fixed-width signatures, SEC1 points with validation),
  RSA PKCS#1 v1.5 and PSS sign/verify with SHA-256/384/512 (SHA-1 verify only) for 2048–8192-bit
  moduli (CRT, blinding, result check), strict DER reader/writer, PEM, and key encodings
  (PKCS#8 v1/v2, SEC1, PKCS#1, SubjectPublicKeyInfo) behind `pkey::{PrivateKey, PublicKey,
  SignatureAlgorithm}`. New `Error` variants `InvalidKey`, `Encoding`, `Unsupported`, `Random`,
  `ZeroSharedSecret`. Constant-time field arithmetic (Montgomery for P-256/P-384 and scalars,
  radix 2⁵¹ for Curve25519), complete addition formulas, table lookups that read every entry.
- New internal crate `only-x509` (`#![forbid(unsafe_code)]`): certificate parsing (strict DER;
  subjectAltName, basicConstraints, keyUsage, extKeyUsage, nameConstraints, key identifiers),
  chain building and validation against a `RootStore` (validity, CA/pathLen, key usage, EKU,
  DNS/IP/directoryName name constraints, unknown critical extensions, a signature-check budget),
  RFC 6125 server-name matching (leftmost-label wildcards, IP SANs), and generation of
  self-signed and CA-signed certificates (`CertificateParams`, `generate_simple_self_signed`).
- Tests: Wycheproof (X25519, Ed25519, ECDSA P-256/P-384 DER and P1363, ECDH P-256/P-384, RSA
  PKCS#1 v1.5 and PSS verification, RSA signature generation), RFC 7748 / 8032 / 6979 vectors,
  identical signatures and mutual verification with ring and RustCrypto p256/p384, real-world
  chains (Google Trust Services, Let's Encrypt ECDSA and RSA), OpenSSL-made chains and keys
  (RSA-PSS, P-384, Ed25519), rcgen and rustls-webpki interop, constructed negative chains; fuzz
  targets `x509_parse` and `crypto_sig_verify` (differential against ring) with corpus replays.

### Added: own DTLS 1.2 (new `only-dtls`, DEV-PLAN wave C)

The DTLS layer of the in-house WebRTC stack (wave D will replace str0m's `dimpl` with it);
nothing uses it yet, so no behaviour changes.

- New internal crate `only-dtls` (`#![forbid(unsafe_code)]`, depends only on `only-crypto` and
  `only-x509`): a sans-io DTLS 1.2 (RFC 6347) `Connection` for either role, driven by
  `handle_datagram`, `poll_transmit`, `poll_event`, `poll_timeout` / `handle_timeout` and
  `send_application_data`. Record layer with epochs, 48-bit sequence numbers and a 64-record
  anti-replay window; handshake fragmentation to the configured MTU and out-of-order
  reassembly; flight retransmission with exponential backoff (RFC 6347 §4.2.4) and on a
  repeated peer flight; stateless HMAC-SHA-256 HelloVerifyRequest cookies (`HelloVerifier` for
  listeners that allocate nothing before return routability is proven).
- Cipher suites `TLS_ECDHE_{ECDSA,RSA}_WITH_{AES_128_GCM_SHA256, AES_256_GCM_SHA384,
  CHACHA20_POLY1305_SHA256}`, groups X25519 / P-256 / P-384, ECDSA, Ed25519, RSA-PSS and
  RSA PKCS#1 signatures; extended master secret (RFC 7627, required by default); renegotiation
  refused (RFC 5746).
- WebRTC: `Config::webrtc`, mutual authentication with self-signed certificates checked by
  `PeerVerifier::Fingerprints` (SDP `a=fingerprint`), a callback, or deferred to the caller;
  `Identity::generate_self_signed`, `Fingerprint` (SDP form), `use_srtp` (RFC 5764) with
  `SRTP_AEAD_AES_128_GCM`, `SRTP_AEAD_AES_256_GCM`, `SRTP_AES128_CM_HMAC_SHA1_80/32`, SRTP master
  keys in `Event::Connected`, and the RFC 5705 exporter (`export_keying_material`).
- Tests: handshakes over a simulated link with 25 % loss, duplication and reordering at MTU 256,
  every suite with ECDSA P-256/P-384, Ed25519 and RSA certificates, negative cases (wrong
  fingerprints, replays, tampered records, bad cookies, timeouts, missing client certificates,
  no shared suite); interop both directions with OpenSSL `s_client`/`s_server -dtls1_2`
  (3.5 in Docker, 4.1; `-use_srtp` and `-keymatexport` keys identical) and pion/dtls v3
  (`tools/interop/dtls/run.sh`), and in memory with `dimpl` (`tests/dimpl.rs`); fuzz targets
  `dtls_record` and `dtls_handshake` with corpus replays. Not implemented: DTLS 1.3 (RFC 9147),
  connection IDs, session resumption, PSK.
### Changed: own TLS 1.3 and 1.2 in `only-tls` (DEV-PLAN wave C; no more rustls, ring)

`only-tls` now implements TLS itself, from the RFCs, on `only-crypto` and `only-x509`
(`#![forbid(unsafe_code)]`, no third-party dependencies). The covered API is unchanged
(`api/only-tls.txt` is identical): `ServerConfig` / `ClientConfig` builders, `Certificate`,
`PrivateKey`, `RootCerts`, `Error`, `Tls`, `TlsInfo`, `tls_info`; only-http (HTTP/1.1, HTTP/2 by
ALPN), only-ws (`wss://`), only-socks, only-grpc and only-mux run on it unchanged.

- TLS 1.3 (RFC 8446): full handshake both sides, HelloRetryRequest (with cookie echo), key
  schedule, KeyUpdate (answered, and sent proactively before the AES-GCM record limit),
  NewSessionTicket and PSK resumption (`psk_dhe_ke`; stateless tickets with
  `session_tickets(true)`, single-use cached tickets with the session cache), client
  certificates, middlebox compatibility mode, 0-RTT rejected (skipped as RFC 8446 4.2.10 says).
- TLS 1.2 (RFC 5246 + RFC 7627 extended master secret + RFC 5746 renegotiation indication,
  renegotiation refused with a `no_renegotiation` warning): ECDHE with ECDSA, Ed25519 or RSA
  certificates and AEAD suites only, resumption by session ID and by RFC 5077 tickets, client
  certificates; the RFC 8446 downgrade sentinel is set and checked.
- Suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 and the six
  ECDHE-ECDSA/RSA AES-GCM / ChaCha20-Poly1305 TLS 1.2 suites. Groups X25519, secp256r1,
  secp384r1. Signatures ECDSA P-256/P-384, Ed25519, RSA-PSS (rsae) and RSA PKCS#1 v1.5 (TLS 1.2
  and certificates). Extensions: SNI, ALPN, supported_versions, key_share, signature_algorithms,
  psk_key_exchange_modes, pre_shared_key, early_data, cookie, extended_master_secret,
  renegotiation_info, session_ticket, ec_point_formats; unknown ones ignored.
- Record layer: 16 KiB fragments, TLS 1.3 inner content types and padding, strict state
  machines, handshake messages reassembled across records (and refused across key changes),
  close_notify, alerts, bounded warning alerts; certificates verified with `only-x509`
  (chain, validity, EKU, DNS names and IP addresses); `insecure_skip_verify` unchanged.
- QUIC-facing core (`only_tls::quic`, `#[doc(hidden)]`, internal): the same TLS 1.3 machines
  without records, driven per encryption level (handshake bytes in and out, traffic secrets per
  level, quic_transport_parameters, ALPN required, no compatibility mode, RFC 9001 key
  derivation helpers with its Appendix A vectors), ready for the in-house QUIC of wave D. Until
  then only-quic keeps quinn-proto, whose rustls configuration it now builds itself from the
  only-tls configs (rustls stays a dependency of only-quic only).
- Tests: RFC 8448 traces (simple 1-RTT, resumption binder, HelloRetryRequest: key schedule,
  transcript, Finished, records byte for byte), in-memory handshakes over every suite, group,
  key type and version, resumption, client authentication, fragmentation down to one byte,
  KeyUpdate, downgrade detection and negative cases; interop matrix
  (`tools/interop/tls/run.sh`, 107 cases: OpenSSL `s_server`/`s_client`, Go `crypto/tls` both
  ways, curl with HTTP/1.1 and HTTP/2), a TLS leg in `tools/interop/grpc/run.sh`, rustls clients
  in `only`'s TLS tests; tlsfuzzer against the server (`tools/interop/tls/tlsfuzzer.sh`: 33
  applicable TLS 1.3 / 1.2 scripts, 985 probes, 5 known and documented failures); fuzz targets
  `tls_server`, `tls_client`, `tls_record` with corpus replays.
- Performance (Apple M4 Pro, 2 server threads, rustls client): full handshakes about 0.7x
  rustls+ring (P-256 ECDSA and X25519 in `only-crypto` are slower than ring's assembly), small
  records on par, bulk throughput about 0.45x (`only-crypto`'s GHASH is portable; PMULL /
  PCLMULQDQ is a wave A follow-up).

Migration: the `unstable` feature of only-tls (and `only/unstable` for TLS) no longer exposes
anything: `only::tls::rustls`, `ServerConfig::from_rustls` / `as_rustls` and
`ClientConfig::from_rustls` / `as_rustls` are removed (they were outside the semver promise).
`ServerConfigBuilder::build` now also fails when the private key does not belong to the
certificate. rcgen and rustls left the dev-dependencies of only-tls, only-http, only-ws,
only-mux, only-h3, only-quic and only-grpc (test certificates come from `only-x509`); `only`
keeps a rustls client in its TLS tests as an interop peer.

### Changed: own QUIC v1 in `only-quic` (DEV-PLAN wave D; no more quinn-proto, rustls, bytes)

`only-quic` now implements QUIC itself, from RFC 9000, 9001 and 9002 plus RFC 9221 datagrams, as
a sans-io core on `only-tls` (its record-free TLS 1.3, `only_tls::quic`) and `only-crypto`
(`#![forbid(unsafe_code)]`, no third-party dependencies). quinn-proto, the rustls inside it
(with ring) and the `bytes` crate left only-quic and only-h3; no library of the workspace
depends on rustls any more. The API is the same apart from the payload type (migration below):
`QuicServer`, `dial`, `Connection`, `QuicHandler`, `ServerConfig` / `ClientConfig` /
`TransportConfig`, `StreamId`, `ConnectionError`, `ConnectionStats`; only-h3's API is unchanged
(`api/only-h3.txt` is identical).

- Packets: long and short headers, the three packet number spaces, packet number encoding,
  header protection (AES, ChaCha20), AES-128/256-GCM and ChaCha20-Poly1305 packet protection,
  coalesced packets, Initial and path-validation padding, Version Negotiation, Retry with the
  integrity tag, stateless resets (sent for unknown connection IDs, detected by token), 1-RTT
  key updates (started every few million packets, followed when the peer starts one).
- Frames: every RFC 9000 frame and DATAGRAM, with the per-packet-type rules; streams with stream
  and connection flow control, stream limits (MAX_STREAMS in batches), BLOCKED frames, final
  size checks, RESET_STREAM in answer to STOP_SENDING.
- Recovery (RFC 9002): RTT estimation, packet and time threshold loss detection, probe timeouts
  and handshake anti-deadlock probes, persistent congestion, NewReno and CUBIC (RFC 9438),
  pacing, the 3x anti-amplification limit, ACK delay rules, idle timeout, keep-alive, path MTU
  discovery up to 1452 bytes.
- Endpoint: routing by connection ID (8-byte IDs issued with NEW_CONNECTION_ID, retired and
  replaced), Retry under handshake load, NEW_TOKEN address validation (tokens kept per server
  name in `ClientConfig`), migration with path validation (`ServerConfig::migration(false)`
  refuses it), transport parameter and connection ID checks, session resumption by ticket
  (`server_config` enables tickets).
- I/O: full-size datagrams leave in GSO batches (`Conn::send_segments`, up to 10); writes made
  from a connection's own callbacks are corked and leave with the acknowledgments once the
  callback returns, so an HTTP/3 response's headers, body and FIN usually share one packet.
- Tests: RFC 9001 Appendix A vectors, unit tests per component and a simulated network (loss,
  reordering, duplication, MTU, blackouts, virtual clock) for handshakes, bulk transfers, many
  streams, migration, key updates, Retry, resumption, resets and timeouts; interop with quic-go
  in both directions as raw QUIC (`tools/interop/quic/run.sh`, new: streams and datagrams, then
  Retry, key updates and a 150 MB stream) and as HTTP/3 with quic-go and fib
  (`tools/interop/h3/run.sh`); in Docker, ngtcp2 1.11 (through libcurl-gnutls) and OpenSSL 3.5's
  QUIC (curl, libcurl, `openssl s_client -quic`) as clients of our servers
  (`tools/interop/quic/docker.sh`, new); fuzz targets `quic_packet`, `quic_frame`, `quic_conn` with corpus
  replays.
- Performance against the quinn-proto version, same loopback benchmark
  (`crates/only-h3/examples/quic-bench.rs`): on an AMD Ryzen 7 7800X3D (Linux, loopback, 3 alternating rounds) full handshakes 6705-6785/s against 6536-6674/s (about 1.0x), bulk throughput on one stream 3.1-3.6 Gbit/s against 4.6-4.7 Gbit/s (about 0.72x; packet protection uses `only-crypto`'s hardware AES-GCM), and HTTP/3 requests on one connection with 64 in flight 171k/s against 58k/s (about 2.9x, since responses, FINs and acknowledgments share packets).

Migration: stream and datagram payloads are `only_quic::Bytes` instead of `bytes::Bytes`, the
only signature change (`QuicHandler::on_stream_data`, `QuicHandler::on_datagram`,
`Connection::send` and `Connection::send_datagram` take `impl Into<only_quic::Bytes>`). It has
the same shape (reference counted; `new`, `from_static`, `copy_from_slice`, `slice`,
`split_to`, `split_off`, `truncate`, `advance`, `Deref<Target = [u8]>`, `From<Vec<u8>>`,
`From<&'static [u8]>`, `From<&'static str>`, `From<String>`, `Vec<u8>: From<Bytes>`), so code
usually only changes its import: `use bytes::Bytes;` becomes `use only_quic::Bytes;`. The
`unstable` feature of only-quic is reserved and empty: `only_quic::proto`,
`ServerConfig::from_quinn` / `as_quinn_mut` and `ClientConfig::from_quinn` / `as_quinn_mut` are
removed (they were outside the semver promise). `Congestion::Bbr` (experimental) runs CUBIC.
`Connection::queued_bytes` counts bytes not sent yet. A dialed connection's UDP socket is now closed once the connection is gone (it used to stay open until the engine stopped), and `open_bi` / `open_uni` never run handler callbacks, so they may be called while holding locks the handler takes. Not implemented: 0-RTT, sending ECN marks,
client-initiated migration, preferred_address, QUIC v2.

### Changed: own WebRTC stack in `only-webrtc` (DEV-PLAN wave D; no more str0m, dimpl, p256)

`only-webrtc` runs on an in-house, sans-io WebRTC stack with no third-party dependencies, behind
the unchanged API (`RtcServer`, `Endpoint`, `Peer`, `PeerHandler` and its ordering guarantees,
`ChannelConfig`, `Codec`, `SdpChanges`, `Event`, `RtcError` ...). Four new internal crates, all
`#![forbid(unsafe_code)]` on `only-crypto`:

- `only-ice`: ICE (RFC 8445) full agent and ICE-lite: candidate priorities and foundations,
  checklists with pacing and retransmission, peer-reflexive candidates, regular nomination, role
  conflicts (487), checks before the remote credentials, consent freshness (RFC 7675), trickle
  (RFC 8838) and restarts; STUN through `only-turn`'s codec. RFC 5769 vectors; pion/ice interop.
- `only-srtp`: SRTP/SRTCP (RFC 3711, RFC 7714) with AES-CM-HMAC-SHA1-80/32 and
  AEAD-AES-128/256-GCM, ROC estimation, replay windows; RFC 3711 and RFC 7714 vectors and
  byte-exact cross-checks with pion/srtp.
- `only-rtp`: RTP header extensions (one- and two-byte), RTCP (SR, RR, SDES, BYE, generic NACK,
  PLI, FIR, REMB, transport-wide CC feedback), send/receive streams with NACK + RTX (RFC 4588),
  reports and RTT, TWCC and a delay- and loss-based bandwidth estimator; payload formats for
  Opus, G.711, G.722, VP8, VP9, H.264 (RFC 6184), H.265 (RFC 7798) and AV1 with a jitter-free
  frame assembler. Byte-exact cross-checks with pion/rtp, pion/rtcp and pion/interceptor.
- `only-sctp`: SCTP over DTLS (RFC 8261; RFC 9260 essentials) with congestion control, fast
  retransmit, PR-SCTP FORWARD-TSN (RFC 3758), stream reset (RFC 6525), DCEP data channels
  (RFC 8831/8832); interop with pion/sctp 1.8 and 1.12 over UDP.

`only-webrtc` itself gained the SDP offer/answer (BUNDLE, rtcp-mux, codec / RTX / rtcp-fb /
extmap negotiation, ssrc and FID groups, setup roles and fingerprints, ICE-lite, candidates,
sctp-port / max-message-size, renegotiation and ICE restarts) and the sans-io peer that glues
the layers together. Tested on a simulated lossy link (ICE + DTLS + SCTP + media) and against
pion (data channels, Opus/VP8 echo, PLI, a TURN relay, both offer directions), fib's Go WebRTC
(both directions) and headless Chrome (`tools/interop/webrtc/browser.sh`: data channels, Chrome's
camera and microphone echoed back and decoded, both offer directions). New fuzz targets
`ice_stun`, `srtp_unprotect`, `rtp_rtcp`, `rtp_codec`, `sctp_packet`; `webrtc_sdp` now drives the
new SDP code.

Migration notes:

- The `unstable` feature of `only-webrtc` is now reserved and empty: `only_webrtc::str0m`,
  `crypto_provider_str0m`, `Peer::with_rtc`, `RtcConfig::with_str0m` and
  `OtherEvent::as_str0m` are gone (they were outside the semver promise).
- The covered API is unchanged except that `Event`, `OtherEvent`, `RtcConfig`, `RtcError` and
  `SdpChanges` are now `RefUnwindSafe` (and `RtcError` `UnwindSafe`): auto traits gained, nothing
  lost.
- Behaviour: H.265 is no longer offered by default (`RtcConfig::enable_h265(true)` turns it on),
  DTLS is 1.2 only (browsers and pion negotiate 1.2), the answerer takes the DTLS client role
  (`a=setup:active`), `OtherEvent`'s `Debug` output changed (it was never stable), and
  `Endpoint` still has no TURN client (relayed candidates must come from elsewhere, as before).
- Dependencies: str0m, dimpl, p256 / ecdsa / elliptic-curve, the RustCrypto crates they pulled
  and rand 0.9 left the library graph; only-dtls's in-memory interop test against dimpl was
  removed. p256/p384 0.13 remain dev-dependencies of only-crypto's cross-checks, so the
  RUSTSEC-2026-0387 (crypto-bigint) ignore in `deny.toml` now only covers them.

### Changed: in-house HTTP codecs (no more httparse, loona-hpack, regex)

DEV-PLAN "no third-party dependencies", wave A. The public API is unchanged.

- HTTP/1 head parsing (only-http requests, chunked trailers and client responses, only-ws client
  handshake responses) uses an in-house parser, `only_ws::http1` (`#[doc(hidden)]`): zero-copy,
  incremental (a head arriving in many reads is scanned once instead of re-parsed from the start
  on every read; the session also stops copying the buffered bytes on every read) and strict per
  RFC 9110/9112: token methods and field names, visible-ASCII request targets (non-ASCII bytes,
  which httparse let through, are now 400), exactly one SP between request-line elements, a bare
  CR, whitespace before a colon or the first field and obsolete line folding are rejected (also
  in responses), CRLF or bare LF line ends. Header values are no longer `str::trim`med (only
  SP/HTAB around them are removed, as RFC 9110 says). Speed is on par with httparse (SIMD) using
  word-at-a-time scanning in safe code (`tools/codec-bench`).
- HPACK is in-house (`only_http::hpack`, `#[doc(hidden)]`): encoder with dynamic table, Huffman
  coding when not longer, never-indexed literals for `authorization` / `proxy-authorization` /
  short `cookie`s and the table size updates RFC 7541 §4.2 requires after the peer changes
  `SETTINGS_HEADER_TABLE_SIZE` (loona-hpack sent none); decoder with dynamic table, size updates
  only at the start of a block and within our setting, 32-bit integers, and a header list limit
  applied while decoding (the whole block is still processed so the table stays in step); the
  Huffman decoder walks 4 bits at a time. RFC 7541 Appendix C vectors pass both ways; h2spec
  147/147.
- Route constraints (`{id:[0-9]+}`) use an in-house linear-time engine (`only_http::re`): literals,
  `.`, classes with ranges/negation/escapes, ASCII `\d \w \s` (and negations), groups (named
  ones too, nothing is captured), `|`, `* + ? {m} {m,} {m,n}` with lazy variants, `^`/`$`;
  unsupported syntax (flags, `\b`, `\p{..}`, backreferences, POSIX classes, class set
  operations, counts above 1000) panics at registration naming the problem. Regexp parameters are
  always available; the `regex` cargo feature of only-http is kept as a no-op for compatibility.
- Fuzzing: `http1_request` / `http1_client` compare the head parser with httparse, `hpack` with
  loona-hpack (both directions of encode/decode too), new `regex_match` with the `regex` crate;
  those crates remain only as dependencies of `fuzz/` and of the `tools/codec-bench` micro
  benchmarks (both outside the library workspace).
### Changed (internal): own syscall and io_uring bindings (no more `libc`, `io-uring`)

DEV-PLAN "no third-party dependencies", wave B. No public API changes; behaviour, errno and
`EINTR` handling are unchanged.

- `only-sys` declares its own OS bindings in `only_sys::ffi` (`#[doc(hidden)]`, internal): C
  types, constants, `#[repr(C)]` structs (`sockaddr_in`/`in6`/`storage`/`ll`, `msghdr`,
  `mmsghdr`, `cmsghdr` with the `CMSG_*` helpers, `iovec`, `epoll_event` (packed on x86_64),
  `kevent`, `timespec`, `pollfd`, `cpu_set_t`, `sigaction`, `utsname`) and `extern "C"`
  declarations of the C library (Linux, glibc or musl) and libSystem (macOS). System calls
  without a C wrapper (`bpf`, `io_uring_*`) use `syscall(2)` with per-architecture numbers.
  Linux x86_64 and aarch64 (riscv64 / loongarch64 share the generic layouts) and macOS
  aarch64 / x86_64; other Linux architectures fail to compile with a clear message instead of
  silently using wrong layouts.
- Every layout and constant is compared with the `libc` crate in a test-only module (`libc` is
  now a dev-dependency only), verified on macOS aarch64, Linux aarch64 and Linux x86_64.
- `only-uring` has its own io_uring binding (`ring`): `io_uring_setup` / `io_uring_enter` /
  `io_uring_register`, the mmap'd SQ/CQ rings and SQE array with the kernel's memory ordering,
  the submission entries the reactor uses (multishot accept, multishot recv with buffer
  selection, poll add, async cancel and cancel-any, read), CQE flags, opcode probing and
  `IORING_FEAT_*` checks (the probe now also requires `IORING_FEAT_EXT_ARG`), SQPOLL and the
  cooperative / single-issuer / deferred task-run setup. The buffer-ring, `KernelBuf`,
  in-flight cancel and graveyard logic is unchanged.
- `only-ebpf` and `only-dpdk` (TAP, AF_PACKET) use `only_sys::ffi`.

### Changed (experimental tier): only-dpdk runs its own TCP/IP stack

`only-dpdk` no longer depends on smoltcp (DEV-PLAN "no third-party dependencies", wave A): the
userspace stack is now `only`'s own, in `crates/only-dpdk/src/net` (safe Rust,
`#![forbid(unsafe_code)]`, no dependencies), with the same `Device` kinds, `DpdkConfig` and
`Backend::Dpdk` integration.

- Ethernet II; ARP with a 60 s cache and a queue of packets awaiting resolution (the first SYN to
  a new neighbour is no longer dropped, which cost the smoltcp version a 1 s SYN retransmission);
  IPv4 with fragmentation on send and bounded reassembly (UDP datagrams larger than the MTU now
  work); ICMP echo replies, port / protocol unreachable, and received unreachables delivered to
  dialed UDP connections (closed with `ConnectionRefused`, as on the kernel backends).
- TCP per RFC 9293: RTT / RTO per RFC 6298, SACK (RFC 2018) with RFC 6675-style recovery,
  NewReno fast recovery (RFC 6582), CUBIC (RFC 9438, the default) or NewReno, window scaling and
  timestamps with PAWS (RFC 7323), delayed ACKs, keepalive, TIME-WAIT with reuse, RFC 5961
  challenge ACKs, a listen backlog with SYN cookies.
- The I/O loop is event-driven with a per-connection timer heap (the smoltcp version re-examined
  every connection on each busy iteration); ACKs are coalesced per receive burst; a memory-wire
  end wakes its peer's thread when it sends.
- Dialing works on multi-queue DPDK ports (was `Unsupported`): local ports name their queue and
  replies RSS puts elsewhere are handed over.
- New `DpdkConfig` fields: `syn_cookies` (default `true`), `congestion`
  (new `only::dpdk::Congestion`, default `Cubic`), `tcp_keepalive` (default `None`).
  `udp_buffer` now bounds the datagrams queued per UDP port.
- TAP and AF_PACKET devices use `libc` directly (`src/sys.rs`); the AF_PACKET socket gets an 8 MiB
  receive buffer and skips the host's outgoing frames.
- Tests: per-layer unit tests, a simulated lossy / reordering link in virtual time, the kernel
  peer suite extended with `tc netem` loss, a 4 MiB window over 20 ms, 500 concurrent
  connections, dials to the kernel and ping; fuzz targets `dpdk_ethernet`, `dpdk_arp`,
  `dpdk_ipv4`, `dpdk_tcp`, `dpdk_udp`, `dpdk_icmp`, `dpdk_stack`. Benchmark example
  `stack-bench`; A/B against the smoltcp version in docs/BENCHMARKS.md.
- `deny.toml`: the 0BSD license and the `bitflags@1` duplicate (both smoltcp's) are gone.

### Changed (performance): QUIC and TLS hot paths (DEV-PLAN performance pass)

No API change. Ryzen 7 7800X3D, loopback, three alternating rounds (docs/BENCHMARKS.md):

- `only-quic`: single-stream bulk 3.4-3.7 → 5.7-5.8 Gbit/s (1.25x the quinn-proto version, was
  0.72x), HTTP/3 requests on one connection with 64 in flight 171k → 415-426k/s, handshakes +2%.
  The pacer floored the RTT at 1 ms and, once empty, woke the sender for every packet through the
  timer thread; it now uses the measured RTT and waits for a whole burst to refill (as
  quinn-proto does), so paced data leaves in GSO batches from the I/O thread (per GiB: futex calls
  423k → 5.6k, context switches 182k → 9.5k). Also cheaper per-packet bookkeeping (stream maps
  without SipHash, in-order range inserts with one lookup, no per-datagram allocations for the
  batch buffer and space selection).
- `only-tls`: received records are copied once, straight into the caller's plaintext buffer, and
  decrypted there (they used to go through the receive buffer and be copied out); large writes
  reserve room for all their records at once. Seal + open +5-7% for 16-64 KiB records. Handshakes
  were profiled: over 98% is curve arithmetic and hashing, so they are unchanged. New
  `crates/only-tls/examples/tls-bench.rs` compares against rustls 0.23 + ring (dev-dependency
  only).

### Changed (performance): only-deflate at zlib-rs speed (DEV-PLAN performance pass)

`only-deflate` (still `#![forbid(unsafe_code)]`, no dependencies, no SIMD) now compresses at
0.94-1.48x the speed of flate2 with the zlib-rs backend (was 0.25-0.9x) with output at most 0.5%
larger (identical in 36 of 45 level × corpus cases), and decompresses at 0.82-1.23x (was
0.7-0.85x); measured on x86-64, tables in docs/BENCHMARKS.md. The streams are as valid as before
for every window size (8 laid out as 9); no API change.

- Compression uses zlib-ng's / zlib-rs's level table and match finders: a hash of four bytes
  (three at level 9), `quick` at level 1 (one probe per position, fixed-code blocks written
  directly, replaced by stored blocks when those are smaller), `fast` at level 2, `medium` at
  levels 3-6 (greedy, from level 5 looking one match ahead), lazy `slow` at 7-9 with zlib-ng's
  chain-jumping search at level 9. Candidates are compared 8 bytes at a time with a cheap
  rejection first. **Level 1 output is now up to 40% larger than before** (like zlib-ng's and
  zlib-rs's level 1) and 1.7-2.9x faster; levels 2-9 are 1.03-4x faster, with output between
  12% smaller and 3.4% larger than before.
- `Deflater::reset` (permessage-deflate without context takeover) clears only the hash slots a
  short stream used instead of the whole table; stored blocks are written straight from the
  window; Huffman code construction counts lengths without store-forwarding stalls.
- Decompression: a fast path refills 64 bits without branches and decodes up to three literals
  or a length/distance pair per refill; matches are copied 8 or 16 bytes at a time (also for
  overlapping matches); decoding tables of complete codes are no longer cleared first.
- permessage-deflate echo (`pmd_echo`, level 6, context takeover) against zlib-rs: 1.84x for 64 B
  messages, 1.04x for 512 B, 1.00x for 4 KiB, 0.98x for 64 KiB (was 1.36x / 0.62x / 0.75x /
  0.54x), with the same bytes on the wire as zlib-rs.
- The `bench` example covers levels 1..=9 (`BENCH_LEVELS`), generated corpora plus files and a
  profiling mode (`BENCH_PROFILE`); a new streaming test covers every level, window size and
  flush kind.

### Added

- `only-protobuf` and `only-protobuf-build` (DEV-PLAN "no third-party dependencies", wave A):
  an in-house protobuf runtime and code generator replacing prost, with no dependencies.
  - `only-protobuf`: the wire format, `Message` (encode, decode, merge, length-delimited),
    open enums (`Enumeration`), unknown-field preservation (`UnknownFields`), `Name`, bounded
    decoding (100 nesting levels, checked lengths, UTF-8; a field with an unexpected wire type
    is kept as an unknown field, as in C++ and Go), and `well_known` (`Empty`, `Timestamp`,
    `Duration`, `Any`, wrappers, `FieldMask`, `Struct` / `Value` / `ListValue`, with `std`
    conversions and `Any::pack` / `unpack`). Encodes byte for byte as protoc's C++ runtime.
  - `only-protobuf-build`: a `.proto` parser (proto3 and proto2: messages, nested types, enums,
    `optional`, `required`, `repeated`, `map`, `oneof`, defaults, packages, imports, built-in
    well-known types) and Rust generator for `build.rs` (`compile(&["x.proto"], out_dir)`,
    `Config`), no `protoc`. Services become `only-grpc` stubs: a `<service>_server` trait with
    `register`, and a typed `<service>_client`; messages then implement
    `only_grpc::codec::Message`.
  - Checked against golden encodings from protoc, differentially against prost (tests and the
    `protobuf_diff` fuzz target), and with grpc-go's generated route_guide / helloworld code in
    both directions (`tools/interop/grpc/run.sh`, new `tools/protobuf-test`).
- `only-grpc`: `Sink::send_message` and `ClientSink::send_message` (encode a `codec::Message`
  and send it), and the re-export `only_grpc::Headers`.

- `only-prefork` (M6, optional): serve one program from several worker processes. A supervisor
  re-executes the current binary as N workers (no fork after threads), each running its own
  `Engine`; listeners are shared with `SO_REUSEPORT` (Linux default) or inherited from the
  supervisor (`ListenMode::Inherit`, the macOS default; no connection is refused across restarts
  and reloads); crashed workers are restarted with exponential backoff; SIGTERM/SIGINT drain the
  workers, SIGHUP (or `Supervisor::reload`) starts a new generation and stops each old worker once
  its replacement is ready; optional CPU pinning (Linux); `Worker` gives the index, worker count
  and generation. Example `prefork-http`, book chapter "Multi-process serving (prefork)".
- `only::Listener::tcp_from_std`: serve an already bound and listening socket (inherited from a
  supervisor, systemd socket activation); internal `EpollGroup::bind_listener` /
  `UringGroup::bind_listener`.
- `only-sys` (internal): `process` module (child fd inheritance, CPU affinity and parent-death
  signal in `pre_exec`, `take_inherited_fd`, `reserve_reuseport`, a self-pipe `signal_pipe`, `kill`).
- `only-deflate` (internal, DEV-PLAN "no third-party dependencies", wave A): DEFLATE, zlib and
  gzip in pure safe Rust without dependencies, replacing `flate2`/`zlib-rs` in `only-ws`
  (permessage-deflate), `only-http` (compression middleware) and `only-grpc` (gzip messages).
  Streaming `Inflater` (any input split, bounded output, windows 2^8..2^15, zlib's code checks)
  and `Deflater` (hash chains, lazy matching, zlib levels 0..=9, length-limited dynamic Huffman,
  fixed or stored blocks, sync/full flush, windows 2^8..2^15), Adler-32 and CRC-32. Interop both
  ways with zlib-rs and `gzip(1)`; fuzz targets `deflate_inflate` (differential against zlib-rs)
  and `deflate_roundtrip`; Miri runs its tests, and the Miri job runs the only-grpc gzip test
  again (the zlib-rs aliasing report in docs/unsafe-review.md no longer applies). Public APIs of
  the other crates are unchanged.
- `only-ws`: permessage-deflate with a window of 8 bits. A server accepts
  `server_max_window_bits=8` (it used to decline such an offer) and a client told
  `client_max_window_bits=8` compresses (it used to send uncompressed); the compressor keeps
  distances within 250 bytes there. `deflate::Deflater`, `deflate::Inflater` and
  `protocol::Decoder` are now `UnwindSafe` (they no longer hold zlib-rs state).

### Deprecated

- The `prost` feature of `only-grpc` (outside the semver promise): it still works; use
  `only-protobuf` / `only-protobuf-build` instead. It may be removed in a minor release.

### Fixed

- `only-ws`: every WebSocket connection carried ~2 KB of inline permessage-deflate state (the
  only-deflate inflater and deflater inside `Option`s), even when compression was not negotiated;
  the state is now boxed. An idle connection after upgrade + one echo: 3,486 → 1,426 bytes.
- io_uring: during a graceful shutdown, connections the multishot accept completed before its
  cancellation took effect were reset; they are now served (`on_shutdown` after their first data),
  and the drain ends only once the accept has ended, so the listening socket is really closed.
- `only-dpdk` (experimental, M6): a kernel-bypass backend. A userspace TCP/IP stack (smoltcp,
  IPv4) runs on `only` I/O threads over a DPDK port (EAL init from `EalConfig`, one rx/tx queue
  pair and one thread per queue, mbuf rx/tx bursts, RSS with ARP fanned out between queues), a
  Linux TAP interface, an AF_PACKET socket or an in-process `MemoryWire`. UDP listeners deliver one
  datagram per `on_data` and TCP listeners a byte stream, with `dial` / `dial_udp`, backpressure,
  idle timeouts, telemetry and graceful shutdown, so protocol crates (only-kcp, ...) run
  unchanged. Listeners on the same device share its stack and threads.
- `only`: cargo features `dpdk` (`Backend::Dpdk(DpdkConfig)`, re-export `only::dpdk`) and
  `dpdk-pmd` (also DPDK ports; links libdpdk found with pkg-config). Experimental: outside the
  semver promise (docs/api-stability.md).
- `only-core` (backend-facing, `#[doc(hidden)]`): `ConnInner::new_virtual` and
  `ConnInner::drain_output` for connections whose bytes a userspace stack moves.
- `tools/dpdk/` (Dockerfile + `test.sh`) and the heavy CI job `dpdk`: builds against the
  distribution's DPDK and runs UDP/TCP echo against the kernel stack over DPDK's `net_tap` PMD
  (one and two queues), over smoltcp's TAP device and over AF_PACKET on a veth pair.
- `Engine::bind_udp` and `UdpBinding` (`only`, only-core): an unconnected UDP socket bound
  while the engine runs, served like a UDP listener (one connection per peer address), that
  sends to any address with `UdpBinding::send_to`. What ICE agents and TURN relays need.
- `only-turn` (new crate): the STUN codec (RFC 8489, with the TURN and ICE attributes,
  `MESSAGE-INTEGRITY`, `FINGERPRINT`), `StunServer`, and `TurnServer`, a TURN relay over UDP
  (RFC 8656): allocations with long-term credentials (`static_auth`, `ephemeral_auth` for the
  TURN REST API), permissions, channels, Send/Data indications, refresh, `EVEN-PORT` and
  `RESERVATION-TOKEN`, stateless nonces, quotas, and a peer policy refusing private and
  loopback peers by default; `TurnCore` is the same server as a sans-io state machine. Interop:
  pion/turn client and coturn's `turnutils_uclient`.
- `only-webrtc` (new crate): WebRTC on the sans-io `str0m` 0.24 over `only` UDP. `RtcServer`
  serves a UDP listener (ICE-lite by default, peers demultiplexed by ICE username and source
  address); `Endpoint` runs a full ICE agent on a `bind_udp` socket, with server-reflexive
  candidates from a STUN server. `Peer` (any thread) sends on data channels, writes media,
  requests keyframes, renegotiates; `PeerHandler` callbacks run one at a time per peer. DTLS
  1.2/1.3 with fingerprint verification, SRTP (AES-CM, AES-GCM), SCTP data channels (reliable or
  not, ordered or not), RTP/RTCP with NACK, PLI/FIR, TWCC. A pure-Rust crypto provider
  (RustCrypto and `dimpl`, no C toolchain). Interop with pion (data channels and media in both
  offer directions, through a `only` TURN relay) and with fib's Go WebRTC (data channels);
  `tools/interop/webrtc/run.sh`.
- Fuzz targets `stun_message`, `turn_server` and `webrtc_sdp`.
- `only-media` (M7 streaming media), a new crate: one stream hub with RTMP, RTSP, SRT,
  HTTP-FLV, WS-FLV, HLS and WHIP/WHEP signalling around it.
  - `hub`: streams by path, one publisher and many subscribers, GOP cache for fast start,
    `Dropper` (slow players drop to the next keyframe), publish / play auth hooks, reserve
    before the tracks are known, waiting for (re)publishers, `Timeline` timestamp
    normalization, per-stream statistics.
  - RTMP server: simple and Flash digest handshake, chunk stream, publish / play, Enhanced RTMP
    (H.265 `hvc1`, Opus); AMF0 / AMF3; FLV mux / demux (legacy and enhanced tags).
  - HTTP-FLV and WS-FLV playback (`HttpFlv`), HLS with MPEG-TS segments, LL-HLS parts,
    preload hints and blocking reload (`Hls`), `MediaHttp` dispatching both; MPEG-TS muxer.
  - RTSP 1.0 server (ANNOUNCE/RECORD, DESCRIBE/SETUP/PLAY over TCP-interleaved and UDP,
    Digest/Basic auth), RTP packetization for H.264/H.265/AAC/Opus/G.711 with decode times
    derived for B-frame video, SDP, and WHIP/WHEP HTTP signalling with a `WebRtcEngine`
    integration trait.
  - SRT live mode (HSv5 caller/listener, ARQ, TSBPD, AES-CTR encryption with passphrase,
    stream ID access control) with a hub-backed `SrtServer` and `srt::dial` / `push` / `pull`;
    incremental MPEG-TS demuxer (`mpegts::demux`).
  - Interop-tested with ffmpeg / ffprobe as publisher and player (SRT with libsrt in Docker);
    fuzz targets `rtmp_server`, `flv_demux`, `amf_decode`, `rtsp_server`, `sdp_parse`,
    `rtp_depacketize`, `mpegts_demux`, `srt_listener`, `srt_conn`.
- `only_ws::WsSender::queued_bytes`, for pacing a producer that streams to a slow peer.
- `only-bittorrent` (M7): bencode; .torrent v1 files (path safety, `Builder`) and magnet links;
  HTTP and UDP trackers as codecs, a `TrackerClient` (only-http, `dial_udp`) and a
  `TrackerServer` (a only-http service and a UDP acceptor on one store); the peer wire protocol
  with the Fast extension, the extension protocol, ut_metadata and ut_pex; MSE/PE (DH-768, RC4);
  uTP with LEDBAT; the mainline DHT; `port::UdpPort`, uTP and the DHT on one `only` UDP listener;
  and a `client::Client` (magnets, rarest-first picker with endgame, pipelining, choking with
  optimistic unchoke, storage and SHA-1 on a logical pool, PEX, DHT, trackers, events). Interop
  with libtorrent 2.0 and aria2 1.37 (`tools/interop/bittorrent/run.sh`); fuzz targets
  `bt_bencode`, `bt_peer_wire`, `bt_krpc`, `bt_utp`, `bt_tracker`, `bt_mse`.
- `Engine::dial_udp_from`: a peer connection on a UDP listener's own socket, so datagrams to a
  new address leave from the listener's port (DHT nodes, uTP).

### Fixed

- `Engine::dial` no longer picks a UDP group (and fails) when the engine has both TCP listeners
  and UDP listeners or UDP client threads, but no `client_threads`.

## [1.0.0-rc.1] - 2026-11-14

First release candidate of 1.0: the API is frozen for review. The public API of every crate is
recorded in `api/<crate>.txt` and checked in CI.

### Added

**Core engine (M0–M1)**
- Thread-per-core event loops: each I/O thread owns its reactor, connections, buffers and timer
  wheel; callbacks run inline on the owning thread, so per-connection handler state needs no lock
  (ADR-001..004).
- `Handler` / `Acceptor` / `fn_acceptor`, and `Conn`: a cloneable `Send + Sync` handle with
  `send`, `send_owned`, `send_shared` (`SharedBuf`), `send_segments`, `cork`/`flush`,
  `close`/`close_after_send`, `hold_reads`, `on_drain`; using a closed handle returns
  `Error::Closed`.
- Backends: epoll (Linux) and kqueue (macOS) in `only-epoll`; `SO_REUSEPORT` accept distribution;
  asynchronous `Engine::dial`.
- Backpressure (write high watermark, `max_queued_bytes`), idle and write timeouts, connection
  limit, graceful shutdown with a timeout.
- `loom` models for the connection send path, stress tests with 5,000 simultaneous and 100,000
  idle connections.

**Logical pool, io_uring, UDP, TLS (M2)**
- `only-pool` adaptive bounded pool; `Conn::spawn_blocking` with the completion back on the
  connection's I/O thread; ordered response slots (`Conn::reserve_response`, `ResponseSlot`,
  `ResponseStream`).
- Slow-callback detection (`Config::slow_callback_threshold`, `slow_hook`).
- `only-uring`: io_uring backend (multishot accept/recv, provided-buffer rings, kernel probe with
  fallback to epoll); per-listener backend choice (`Listener::backend`).
- UDP: `Listener::udp` (one `Conn` per peer), `Engine::dial_udp`, `recvmmsg`/`sendmmsg`, UDP
  GSO/GRO, `udp_max_peers`.
- `only-tls`: rustls as a sans-io transport layer under `Conn` (`Tls::server`, `Tls::client`,
  `tls_info`).

**HTTP and WebSocket (M3)**
- `only-http`: HTTP/1.1 server with pipelining, chunked bodies and trailers, streaming request
  and response bodies, `Router` (static > `:param` > `*wildcard`, regex parameters, nesting,
  layers), middleware (recover, request id, CORS, logger, response time, compress, etag, csrf,
  limiter), static files (`files::Files`: ranges, precompressed twins, cache, `sendfile`), HTTP/1
  client (`client::Client`, `ResponseFuture`).
- `only-ws`: RFC 6455 with permessage-deflate, `PreparedMessage` broadcast, subprotocols, origin
  check; server upgrade (`Context::upgrade_websocket`) and client (`only_ws::client`); Autobahn
  suite clean.

**HTTP/2 and more protocols (M4)**
- HTTP/2 server on the same `Service` (h2c prior knowledge and upgrade, ALPN `h2`, flow control,
  HPACK, push) and `h2client::H2Client`; h2spec clean.
- `only-mux` (several protocols on one port), `only-arpc` (lesismal/arpc wire format),
  `only-grpc` (unary and streaming gRPC on only-http, gzip, deadlines, interceptors, optional
  prost helpers), `only-socks` (SOCKS5/4/4a and HTTP CONNECT).

**QUIC, HTTP/3, KCP, eBPF (M5)**
- `only-quic` (quinn-proto over `only` UDP) and `only-h3` (HTTP/3 with QPACK, client and server).
- `only-kcp`: KCP compatible with skywind3000/kcp and kcp-go (crypts, Reed–Solomon FEC).
- `only-ebpf`: `SO_REUSEPORT` steering by CPU or consistent hash (classic BPF unprivileged, eBPF
  when privileged) via `Accel::Ebpf`, and an in-kernel sockmap `Relay`.

**Production readiness (M6)**
- Telemetry: per-thread counters, `Engine::metrics` (Prometheus and JSON), connection table,
  slow-callback ring, live reload of settings (`Engine::reload`), `only_http::observe` endpoints
  and HTTP metrics.
- Seeded chaos test suites (engine, fd exhaustion, TLS, HTTP/WebSocket).

**1.0 stabilization**
- 21 fuzz targets with corpora and coverage reporting; `cargo-deny`/`cargo-audit` gate; unsafe
  review (docs/unsafe-review.md), Miri and sanitizer jobs; strict lint set; mdBook guide in English
  and Chinese with migration guides; benchmark report.
- API freeze: `docs/api-stability.md` (semver, MSRV and platform policy), `docs/deprecation.md`,
  this changelog, public API snapshots (`api/*.txt`, `tools/api/public-api.sh`) checked by the CI
  job `public-api`, and a `semver-checks` job that activates once 1.0.0 is published.
- New API from the review: `AnyAcceptor` and `Listener::serve_any` (type-erased acceptors, used
  by `only-mux`); `Request::new`, `ClientRequest::new`/`body`, `FileBody::new`; re-exports of
  `Part`, `ResponseStream`, `Transport` and `SharedBuf` from `only` (and `SharedBuf` from
  `only-core`); `only_h3::H3Error`; `Display`/`Error` for `InflateError`, `ProtocolError`
  (ws), `FrameError` (arpc) and `QpackError`; `only_core::Error::source` returns the I/O error.
- Every public type implements `Debug`; builder methods are `#[must_use]`.

### Changed (breaking, with migration)

Config and report structs and the enums that may grow are now `#[non_exhaustive]`: struct
literals no longer compile outside `only`. Start from `Default` (or a preset) and assign fields:

```rust
// before
let cfg = Config { idle_timeout: Some(d), ..Config::default() };
// after
let mut cfg = Config::default();
cfg.idle_timeout = Some(d);
```

Affected structs: `only`: `Config`, `UringConfig`, `EbpfConfig`, `PoolConfig`, `PoolStats`,
`SlowCallback`, `UdpStats`, `ConnInfo`, `LoopMeta`, `LoopCounters`, `LoopMetrics`, `Metrics`,
`ReloadReport`, `SlowRecord`; `only-tls`: `TlsInfo`; `only-http`: `HttpConfig`, `H2Config`,
`H2Options`, `WsOptions`, `Request`, `Response`, `FileBody`, `ClientRequest`, `ClientResponse`,
`Cors`, `Compress`, `LogRecord`, `HttpSnapshot`; `only-ws`: `WsConfig`, `DialOptions`, `PmdOffer`,
`PmdParams`, `ProtocolError`; `only-grpc`: `CallOptions`, `Status`, `Metadata`; `only-kcp`:
`KcpConfig`, `Stats`; `only-h3`: `H3Config`; `only-ebpf`: `AttachOptions`, `SteerInfo`, `Probe`;
`only-arpc`: `proto::Message`. Enums (add a wildcard arm to `match`): `only::Error`, `Part`,
`Backend`, `Accel`, `AccelStatus`, `only_http::Method`, `Version`, `BodyMode`, `ClientError`,
`only_ws::client::WsClientError`, `deflate::InflateError`, `only_mux::Rule`,
`only_arpc::CallError`, `proto::Cmd`, `only_quic::Error`, `only_h3::qpack::QpackError`,
`only_kcp::KcpError`, `CloseReason`, `only_ebpf::Steering`, `HashKey`, `Tier`.

Renames and signature changes:

| Crate | Before | After |
|---|---|---|
| `only` | `Listener::serve_dyn(Arc<dyn DynAcceptor>)` (hidden) | `Listener::serve_any(impl Into<AnyAcceptor>)` |
| only-mux | `Mux::into_dyn() -> Arc<dyn DynAcceptor>` | `Mux::into_any() -> AnyAcceptor` (also `From<Mux> for AnyAcceptor`; pass the `Mux` to `serve_any` directly) |
| only-mux | `Mux::route_dyn(rule, Arc<dyn DynAcceptor>)` | `Mux::route_any(rule, impl Into<AnyAcceptor>)` |
| only-mux | `Mux::max_sniff(n)` | `Mux::max_sniff_bytes(n)` |
| only-http | `H2Client::connect(..)` | `H2Client::dial(..)` |
| only-http | `H2Client::connect_blocking(..)` | `H2Client::dial_blocking(..)` |
| only-ws | `client::connect(..)` (blocking) | `client::dial_blocking(..)` |
| only-ws | `INTERNAL_ERROR` | `protocol::close::INTERNAL` |
| only-arpc | `dial(..)` (blocking) | `dial_blocking(..)` |
| only-arpc | `Routes::max_body(n)` | `Routes::max_body_bytes(n)` |
| only-grpc | `GrpcClient::gzip(bool)` | `GrpcClient::compress(bool)` (same name as `GrpcServer::compress`) |
| only-grpc | `GrpcServer::max_message(n)` | `GrpcServer::max_message_bytes(n)` |
| only-h3 | `H3Client::connect(..)` | `H3Client::dial(..)` |
| only-h3 | `server(quic, service)` | `serve(quic, service)` |
| only-h3 | `server_with(quic, service, cfg)` | `serve_with(quic, cfg, service)` (config before service, as in `only_http::serve_with`) |
| only-h3 | `H3Config::max_body`, `max_field_section` | `max_body_bytes`, `max_field_section_bytes` |
| only-h3 | `Result<Response, String>` from `request`, `request_blocking`, `get` | `Result<Response, H3Error>` (`Closed`, `Reset(code)`, `Protocol`, `Timeout`) |
| only-kcp | `Config` | `KcpConfig` |
| only-kcp | `KcpServer::new`, `dial`, `dial_conv`, `Crypt::new` returning `Result<_, String>` | `std::io::Result<_>` (`InvalidInput` for bad settings) |
| only-kcp | `Kcp::stats: [u64; 4]` (public field) | private; use `Session::stats()` |
| only-ebpf | `Relay::new_unchecked(pairs)` | `Relay::new_any_kernel(pairs)` |
| only-ebpf | `Relay::splice_conns(&Arc<ConnInner>, &Arc<ConnInner>)` | `Relay::splice_conns(&Conn<A>, &Conn<B>)` |

Moved out of the covered API (now `#[doc(hidden)]`; backend-facing or test helpers that may change
in any release): `only_core::{LoopLink, Task, Pool, LoopStats, telemetry::Counter,
telemetry::json_str, telemetry::prometheus_header}` and backend-only `Telemetry` methods,
`only::{DynAcceptor, DynHandler}` re-exports, `only_http::transport`, `only_ws::WsSession`,
`only_ebpf::{cbpf, SLOTS, slot_table, expected_index}`.

Versioning: all crates are at `1.0.0-rc.1` and depend on each other with exact (`=`) versions;
`only-sys`, `only-buf`, `only-timer`, `only-pool`, `only-epoll` and `only-uring` are internal
crates without a semver promise of their own (see docs/api-stability.md).

[Unreleased]: https://github.com/lesismal/only/compare/v1.0.0-rc.1...HEAD
[1.0.0-rc.1]: https://github.com/lesismal/only/releases/tag/v1.0.0-rc.1
