# ADR-178: Argon2id in akio-crypto, its lanes on scoped threads

English | [简体中文](178-argon2id.zh-CN.md)

Status: accepted (2026-11-26). akit's A230 (with A231, XChaCha20-Poly1305, which adds no design).

## Context

akit is to open and write fit's encrypted store (`fitstore`), whose key is derived from a password
with Argon2id (RFC 9106) at the time, memory and lanes its header names: fit writes 3 passes over
64 MiB in 4 lanes and reads up to 16 passes and 1 GiB. akio-crypto had HKDF, PBKDF2 and bcrypt,
no Argon2 and no BLAKE2b, on which Argon2 is built. Argon2 is the first function of the crate
that takes memory and time a caller chooses by the megabyte and the second, and whose lanes are
meant to run in parallel; the crate's other functions take microseconds and no allocation worth
mentioning.

## Decision

1. **`hash::Blake2b`** (RFC 7693): a digest of 1 to 64 bytes and a key of up to 64 chosen when it
   is made (`new`, `new_keyed`, `update`, `finalize_into`, one-shot `digest`), and
   **`hash::Blake2b512`** behind the `Hash` trait (HMAC, HKDF). Portable Rust, constant time by
   construction.
2. **`kdf::argon2id(password, salt, time, memory_kib, lanes: u8, out)`**: Argon2id version 0x13
   with no secret and no associated data, as Go's `argon2.IDKey`. RFC 9106's bounds are checked
   first and are errors, never panics: a salt under 8 bytes, an output under 4 bytes or an input
   over `u32::MAX` bytes are `Error::InvalidLength`; `time` or `lanes` of 0, or `memory_kib`
   under 8 per lane, the new `Error::InvalidParameter`. (Go raises a memory under 8 per lane to
   that minimum instead; fit never writes one.)
3. **The memory is one allocation made fallibly before any work** (`Vec::try_reserve_exact`):
   `m' = 4·p·⌊m / 4p⌋` blocks of 1 KiB, freed when the call returns. A size the allocator refuses
   is the new `Error::OutOfMemory`, not an abort. The caller bounds what comes from outside (akit
   checks a header against fit's bounds before deriving), since an operating system that
   overcommits may grant a size it cannot back.
4. **Lanes run on scoped threads.** Each slice of each pass fills every lane's segment, which RFC
   9106 allows in parallel: a segment reads only blocks of earlier slices (any lane) and earlier
   blocks of its own segment. The memory is split for each slice with `split_at_mut` into each
   lane's segment (`&mut`) and the blocks before and after it (`&`), so the threads share nothing
   mutable, need no lock and no `unsafe`. Up to `min(lanes, available_parallelism)` threads
   (`std::thread::scope`, named `akio-argon2`), the last group of lanes on the calling thread; a
   thread that cannot start leaves its lanes to the calling thread. The output does not depend on
   the number of threads (tested with 1 to 16).
5. **The function blocks**, for a time in proportion to `time × memory_kib` (fit's setting
   takes a fraction of a second). It is for a control thread or the
   logical pool, never an I/O thread (rules 1–3); the docs say so.

## Consequences

- akit derives a store's key in one call on its control thread, as fit does, and reads fit's
  stores. Tests: RFC 9106's Argon2id vector (with a secret and associated data, through the
  crate-private form that takes them), Go's `IDKey` for eight settings, fit's among them
  (`tests/data/go_x_crypto.txt`, printed by `go_x_crypto.go` from golang.org/x/crypto v0.58.0),
  RFC 7693 and Go's BLAKE2b for 100 lengths and keys, and the bounds.
- akio-crypto starts threads for the first time, for one call and scoped to it: no thread
  outlives `argon2id`, and a host that refuses threads gets the same result on one.
- Timing: the first half of the first pass addresses memory independently of the password
  (Argon2i); the rest reads blocks at indices derived from it, by design (Argon2d's resistance to
  trade-offs). That is RFC 9106's Argon2id, not a leak of this implementation; BLAKE2b and the
  compression function are constant time (`docs/constant-time.md`).
- Not done: SIMD for the compression function (Go and libargon2 use SSE/AVX2 or NEON); Argon2i
  and Argon2d on their own; a secret or associated data in the public API. The speed against Go
  and RustCrypto's `argon2` is a benchmark task's (DEV-PLAN section 4).
