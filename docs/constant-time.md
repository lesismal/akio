# Constant time: statistical timing test

English | [简体中文](constant-time.zh-CN.md)

`only-crypto` argues constant time from the code and the disassembly: no branch or memory
index depends on a secret, and the release builds of the secret-scalar paths were disassembled
and every conditional branch listed (`crates/only-crypto/src/ct.rs` has the recipe and the
last result). `tools/ct-dudect` adds an independent, black-box check: it measures the real
binaries and asks whether their running time depends on the secret.

## Method

`ct-dudect` follows dudect (Reparaz, Balasch, Verbauwhede, "Dude, is my code constant time?",
DATE 2017), written from scratch in the tool (no dependency besides `only-crypto`):

- **Two classes of input** per target: class 0 a fixed secret (chosen to be special: scalar 1,
  an all-zero X25519 scalar or Ed25519 seed, an all-zero RSA digest, a tag wrong only in its
  last byte, all-zero limbs), class 1 a fresh random secret for every measurement. All other
  inputs (peer keys, messages, nonces) are the same in both classes.
- **Random interleaving**: each measurement's class is a coin flip; inputs of both classes are
  built before the timed loop as separate objects in measurement order, so neither class stays
  hotter in cache.
- **Timer**: `lfence; rdtsc; lfence` on x86_64 (an invariant TSC: constant-rate reference
  cycles), `isb; mrs cntvct_el0` on aarch64 (the generic timer, 24 MHz to 1 GHz depending on
  the machine, so coarse: a difference shows as a shift of the tick distribution), else
  `std::time::Instant`. One counter read before and one after each call.
- **Welch's t-test** between the two classes' timings, online (Welford), in the dudect set of
  tests: all measurements; 100 croppings that keep only measurements below the
  `1 - 0.5^(10(i+1)/100)` quantile of a discarded warm-up batch (interrupts and cache misses add
  a long upper tail that can hide a small shift); and a second-order test on the squared
  distance from the class mean (after 10,000 measurements). The statistic is the largest `|t|`
  over the tests with at least 1,000 measurements per class.
- **Verdict**: `|t| > 4.5` is a leak (for equal means the chance of that is about 7·10⁻⁶ per
  test). A small `|t|` is not a proof: it says no difference was seen at this number of
  measurements on this machine.
- **Sanity**: an A/A test (`sanity-null`, both classes identical) must stay below 4.5 (the
  false-positive check), and two deliberately leaky functions must be found: an early-exit
  256-byte compare (`sanity-leaky-memcmp`) and a square-and-multiply that branches on each
  exponent bit (`sanity-leaky-modexp`). A unit test (`cargo test -p ct-dudect`) also checks the
  early-exit compare is detected, and the t-test against synthetic distributions.
- **Paths**: each target runs on the hardware paths, then with `ONLY_CRYPTO_PORTABLE=1` on the
  portable code. Targets without a hardware path (the `ct.rs` primitives, `ct_eq`, the sanity
  checks) run in the first pass only.
- **`--fixed-random X`**: class 0 becomes a fixed random-looking secret drawn from seed X
  instead of the special value, to tell a difference that only the special value shows from a
  general one.

## Targets

| Target | Class 0 (fixed) vs class 1 (random) |
|---|---|
| `p256-ecdh` | P-256 ECDH `d·Q`: scalar 1 vs random scalar, fixed peer |
| `p256-keygen` | P-256 public key `d·G` (fixed-base comb): scalar 1 vs random |
| `p256-sign` | ECDSA P-256 sign (RFC 6979 nonce, `k·G`, `k⁻¹`): key 1 vs random key, fixed message |
| `x25519` | X25519 ladder: all-zero scalar (2²⁵⁴ after clamping) vs random, fixed peer |
| `x25519-keygen` | X25519 public key (Edwards fixed-base): all-zero vs random scalar |
| `ed25519-sign` | Ed25519 sign: all-zero seed vs random seed, fixed message |
| `x448` | X448 ladder: all-zero scalar (2⁴⁴⁷ after clamping) vs random, fixed peer (portable only: no hardware path, first pass) |
| `ed448-keygen` | Ed448 key from a seed (SHAKE256, `[s]B` with masked table scans): all-zero vs random seed |
| `ed448-sign` | Ed448 sign (`[r]B`, scalar arithmetic modulo ℓ): all-zero vs random seed, fixed message |
| `p521-ecdh` | P-521 ECDH `d·Q`: scalar 1 vs random scalar, fixed peer (portable only, first pass; ADR-049) |
| `p521-keygen` | P-521 public key `d·G` (signed 4-bit comb): scalar 1 vs random |
| `p521-sign` | ECDSA P-521 sign (RFC 6979 nonce, `k·G`, `k⁻¹`): key 1 vs random key, fixed message |
| `rsa2048-sign-msg` | RSA-2048 PKCS#1 v1.5 sign (CRT, blinding): all-zero digest vs random digest |
| `rsa2048-sign-key` | RSA-2048 sign: test key A vs test key B (two fixed keys: a random 2048-bit key per measurement is too slow to make) |
| `aes128-gcm-open-tag` | AES-128-GCM open, 256 bytes: tag wrong in the last byte vs random tag (how much of the tag matches) |
| `chacha20poly1305-open-tag` | the same for ChaCha20-Poly1305 |
| `chacha20poly1305-open-tag-64` | the same at 64 bytes: the short-message head (one row-kernel call on AVX-512 that hands the Poly1305 key over in registers, up to 192 bytes) |
| `hmac-sha256-verify-tag` | `Hmac::verify`: tag wrong in the last byte vs random tag |
| `hmac-sha256-verify-valid` | `Hmac::verify`: valid tag vs random tag (both compute the MAC and compare in full) |
| `aes128-gcm-open-valid`, `chacha20poly1305-open-valid` | valid tag vs random tag; **public**: the caller learns anyway whether the tag verified, and the work differs by design (ChaCha20-Poly1305 decrypts only after a valid tag; the fused AES-GCM pass undoes the decryption on failure). Reported, never a leak |
| `seed-key` | SEED key schedule and CTR over 256 bytes (one sixteen-block batch): all-zero key vs random key (portable only: no hardware path, first pass; ADR-052) |
| `seed-block` | SEED one block (the one-word G path of CCM's CBC-MAC), fixed key: all-zero block vs random block |
| `ct-eq` | `only_crypto::ct_eq`, 32 bytes: equal but the last byte vs random |
| `ct-word` | `ct.rs` `mask`, `is_zero`, `eq`, `select` over 64 words: zeros vs random |
| `ct-limbs` | `ct.rs` `add_limbs`, `sub_limbs`, `lt_limbs`, `is_zero_limbs`, `assign`, `swap` on 2048-bit limb arrays: zeros vs random |

`ct.rs` is private to `only-crypto`; the tool compiles the same source file (`#[path]`), so
the primitives are measured as written, inlined into the harness as they are inlined into
their callers.

## Running it

```sh
cargo build --release -p ct-dudect
taskset -c 2 target/release/ct-dudect --seconds 60 --json hw.json
ONLY_CRYPTO_PORTABLE=1 taskset -c 2 target/release/ct-dudect --seconds 60 --json portable.json
target/release/ct-dudect --list                # the targets
target/release/ct-dudect --seconds 5 p256 x25519   # a subset (substring match)
```

The exit status is 1 if a secret target leaks or a sanity target is missed. Use a quiet
machine and pin the process to one core: the test measures timing differences of a few cycles
against the noise of everything else on the machine. A `|t|` slightly above 4.5 on a busy or
shared machine is a reason to re-run there, quietly and longer, before reading anything into it.

CI runs it as the informational job `ct-dudect` (`.github/workflows/ci.yml`, which runs only on a
pre-release or a manual run; 15 s per target on both paths; the job has
`continue-on-error: true` and is not part of `ci-ok`). The tables are in the job summary, the
JSON t-values in the `ct-dudect` artifact.

## Latest results

2026-11-16, AMD Ryzen 7 7800X3D (Zen 4: AES-NI, VAES, AVX-512, IFMA, BMI2 + ADX), Linux, the bench
host quieted (desktop, remote desktop and a local Kubernetes cluster stopped, power profile
`performance`), pinned to core 2, `rdtsc`, 60 s or 10⁸ measurements per target and path. Load
average 1.2–1.6 during the run (an outside single-threaded workload on another core). Max `|t|`
over the 102 tests, measurements in parentheses:

| Target | Kind | Hardware path | Portable (`ONLY_CRYPTO_PORTABLE=1`) |
|---|---|---:|---:|
| `p256-ecdh` | secret | 2.56 (2.0M) | 1.63 (965k) |
| `p256-keygen` | secret | 1.56 (9.9M) | 3.53 (4.2M) |
| `p256-sign` | secret | 2.69 (6.3M) | **5.26** (2.7M), rerun 2.66 (5.5M) |
| `x25519` | secret | 1.76 (2.2M) | 1.97 (1.8M) |
| `x25519-keygen` | secret | **40.38** (5.9M), rerun 1.91 (11.8M) | **5.15** (5.9M), rerun **11.52** (11.4M) |
| `ed25519-sign` | secret | 3.25 (2.8M) | 2.32 (2.8M) |
| `rsa2048-sign-msg` | secret | 1.53 (235k) | 2.04 (74k) |
| `rsa2048-sign-key` | secret | 3.29 (235k) | 1.42 (74k) |
| `aes128-gcm-open-tag` | secret | 1.27 (100M) | 2.40 (56.5M) |
| `chacha20poly1305-open-tag` | secret | 2.19 (100M) | 2.40 (100M) |
| `hmac-sha256-verify-tag` | secret | 1.10 (100M) | 0.93 (37.4M) |
| `hmac-sha256-verify-valid` | secret | 1.61 (100M) | 1.51 (37.5M) |
| `ct-eq` | secret | 1.79 (100M) | — |
| `ct-word` | secret | 1.24 (100M) | — |
| `ct-limbs` | secret | 0.96 (100M) | — |
| `aes128-gcm-open-valid` | public | 31,600 (100M) | 23,697 (36.3M) |
| `chacha20poly1305-open-valid` | public | 293,434 (100M) | 213,062 (100M) |
| `sanity-null` (A/A) | must stay low | 3.26 (100M) | — |
| `sanity-leaky-memcmp` | must be found | 126,686 (100M): found | — |
| `sanity-leaky-modexp` | must be found | 29,847 (100M): found | — |

The Edwards code (X25519 key generation, Ed25519) has no assembly, so both columns of
`x25519-keygen` and `ed25519-sign` run the same code.

Reading:

- The harness works: the A/A test stays below 4.5 at 10⁸ measurements, both leaky functions are
  found with `|t|` in the tens of thousands, and the public valid-vs-invalid AEAD difference is
  found as expected (hundreds of cycles: the failure path skips or undoes the decryption).
- RSA (both exponentiation paths, CRT and blinding), P-256 ECDH and key generation, X25519,
  Ed25519 signing, tag verification in both AEADs and HMAC, `ct_eq` and the `ct.rs` primitives:
  no difference seen on either path.
- **`x25519-keygen`, all-zero scalar only.** The fixed class (scalar 2²⁵⁴ after clamping: 63 of
  the 64 comb digits are zero, so the accumulator stays the identity until the last row) is
  faster by 0.1 to 2.5 reference cycles out of about 42,000 (≤ 60 ppm), significant in some runs
  (`|t|` 40.4 in the fastest 2.6 % of the hardware pass, 11.5 over half the measurements of a
  portable rerun) and not in others (1.91 in a hardware rerun with 11.8M measurements). With
  `--fixed-random 1` (a fixed random-looking scalar instead of the special one) neither path
  shows a difference (2.21 portable, 1.71 hardware, 11.7M each). The code is the same branch-free
  portable code on both paths (`Point::mul_base`: digit recoding, full-row masked selects,
  `add_niels` with no data-dependent branch; `to_montgomery_u`: a fixed inversion chain; checked
  in the disassembly, `src/ct.rs`). A difference of a cycle or two that appears only for an
  operand stream that is almost all identity-point constants (0 and 1 limbs), and comes and
  goes between runs, fits a data-dependent power or clock effect (fewer toggling bits, less
  voltage droop and clock stretching; the TSC counts at a fixed rate while the core clock moves)
  better than a code path; it is not explained or fixed here. A real X25519 key is clamped
  random bits, never this scalar.
- **`p256-sign` portable, borderline.** 5.26 in the first pass (crop48), 2.66 on a rerun with
  the special key, 4.91 on a rerun with a fixed random key (crop8), hardware path 2.69; the
  means differ by under 5 cycles of 91,000. Not reproducible as a stable signal; consistent with
  the noise floor at millions of measurements on a host with an outside workload (load 1.5–3
  during the reruns). The nonce derivation (RFC 6979 with a constant-time range check), the comb
  and the inversion have no secret-dependent branch in the disassembly.
- Neither finding changes code. A longer run on a quiet host (and on a fixed core clock) is the
  next step for both.

Ed448 and X448 (2026-11-19, ADR-046), same host and method, through `quiet.sh`, core 2, 60 s per
target; these targets have no hardware path, so one pass covers them: `x448` 0.79 (226,650
measurements), `ed448-keygen` 1.68 (232,300), `ed448-sign` 1.34 (105,600), `sanity-null` 2.05
(10⁸). No difference seen.

P-521 (2026-11-19, ADR-049), same host and method, through `quiet.sh`, core 2, 60 s per target,
one pass (no hardware path): `p521-ecdh` 0.96 (134,400 measurements), `p521-keygen` 1.42
(579,000), `p521-sign` 2.09 (278,100), `sanity-null` 0.88 (10⁸). No difference seen. The P-521
code was not disassembled; its argument is the source (masked selects and full-table scans,
complete formulas without special cases, fixed inversion chains) plus this measurement.

aarch64 (2026-11-19, after the assembly divsteps and the OpenSSL addition formulas of the P-256
twin): Apple M4 Pro, macOS, hardware path, `cntvct_el0` (1 GHz on this chip, judging by the means:
a P-256 ECDH reads about 26,000 ticks, the 27 µs it takes; one tick is a few core cycles), 60 s
per target, the machine shared with other builds (load average 7–10): `p256-ecdh` 2.21 (2.3M
measurements), `p256-keygen` 1.74 (10.5M), `p256-sign` 2.25 (6.5M), `x25519` 3.26 (3.4M),
`sanity-null` 1.51 (10⁸); both leaky sanity targets found (26,208 and 17,221). `x25519-keygen`
showed the all-zero-scalar effect described above (24.59 in the fastest 3% of 8.9M
measurements; the same portable Edwards code on both paths, not touched here); with
`--fixed-random 1` it was 2.25 (9.0M), and `p256-sign` 3.48 (6.4M). No difference seen in the
P-256 paths, the new divsteps included.

SEED (2026-11-20, ADR-052), the same host quieted (`quiet.sh`), core 2, `rdtsc`, 60 s per
target; SEED has no hardware path, so one pass: `seed-key` 1.50 (15.5M measurements; key
schedule and a sixteen-block CTR pass, about 15,700 cycles either way) and `seed-block` 1.52
(50.6M; the one-word path, about 4,480 cycles either way). No difference seen.

only-crypto short-message open and P-256 reduction (2026-11-22): the quiet host (`quiet.sh`),
core 2, `rdtsc`. Hardware path, 60 s per target: `p256-ecdh` 2.74 (2.1M measurements),
`p256-keygen` 2.07 (11.4M), `p256-sign` 1.98 (6.8M), `chacha20poly1305-open-tag` 1.98 (10⁸),
the new `chacha20poly1305-open-tag-64` 0.67 (10⁸; the row-kernel head with the key in
registers, about 600 cycles per open). Portable path, 30 s: `chacha20poly1305-open-tag` 1.29,
`chacha20poly1305-open-tag-64` 0.99. `chacha20poly1305-open-valid` differs as it should
(public). No difference seen.
