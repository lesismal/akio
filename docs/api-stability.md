# API stability and semver policy

[中文](api-stability.zh-CN.md)

This document says what `only` promises from 1.0.0 on: which crates and items are covered by
[Semantic Versioning](https://semver.org/), what counts as a breaking change, how the minimum
supported Rust version (MSRV) moves, and which platforms are supported at which level. The
deprecation process is in [deprecation.md](deprecation.md); the history of changes in
[CHANGELOG.md](../CHANGELOG.md).

## 1. Versioning

- **Lockstep.** All crates of the workspace share one version (`[workspace.package] version`)
  and are released together. Workspace crates depend on each other with exact requirements
  (`=1.2.3`), so a build always combines crates of one release.
- **Semver from 1.0.0.** For the covered API (section 2): a patch release (`1.2.x`) only fixes
  bugs; a minor release (`1.x.0`) may add API and deprecate API; only a major release (`x.0.0`)
  may remove or change covered API. Because the crates are released in lockstep, a breaking change
  in any covered crate means a new major version for all of them; such releases are planned and
  rare.
- **Pre-releases** (`1.0.0-rc.N`) may still change anything; release candidates exist to find what
  has to change before the promise starts.

## 2. What is covered

### Crates

| Tier | Crates | Promise |
|---|---|---|
| Public | `only`, `only-core`, `only-tls`, `only-http`, `only-ws`, `only-mux`, `only-socks`, `only-arpc`, `only-grpc`, `only-protobuf`, `only-protobuf-build`, `only-kcp`, `only-quic`, `only-h3`, `only-ebpf`, `only-prefork`, `only-turn`, `only-webrtc`, `only-media` | Full semver for their public API (below). |
| Internal | `only-sys`, `only-buf`, `only-timer`, `only-pool`, `only-epoll`, `only-uring` | Implementation crates, published only because the public crates depend on them. Their own APIs may change in **any** release; depend on `only` / `only-core` instead. The types they contribute to the public API (`SharedBuf`, `PoolConfig`, `PoolStats`) are covered through the re-exports in `only-core` and `only`. |
| Experimental | `only-dpdk`, and the `dpdk` / `dpdk-pmd` features of `only` (`Backend::Dpdk`, `only::dpdk`) | The kernel-bypass backend is new and its configuration may still change in any release. It becomes covered (public tier) once it has been used in production; until then the snapshot `api/only-dpdk.txt` only makes changes visible. |

`tools/` and `fuzz/` are not published.

### Items

Covered: every item reachable from a public crate's root that appears in its rustdoc, including
trait implementations and auto traits (`Send`, `Sync`, `Unpin`, `UnwindSafe`) of public types.

Not covered:

- items marked `#[doc(hidden)]` and everything reachable only through them. These are
  backend-facing plumbing shared between workspace crates (`ConnInner`, `LoopLink`, `Group`,
  `DynAcceptor`, `DynHandler`, `LoopStats`, `Pool`, `only_http::transport`, `only_ws::WsSession`,
  `only_ebpf::cbpf`, `Conn::inner`, telemetry helpers ...). They may change in any release.
- the `fuzzing` cargo features and the `fuzzing` modules they enable (entry points for `fuzz/`).
- the `unstable` cargo features (`only`, `only-tls`, `only-quic`, `only-webrtc`) and
  everything they enable: raw access to the wrapped dependencies (`only::tls::rustls`,
  `ServerConfig::from_rustls` / `as_rustls`, `only_quic::proto`, `from_quinn` /
  `as_quinn_mut`, `only_webrtc::str0m`, `Peer::with_rtc`, `RtcConfig::with_str0m`,
  `OtherEvent::as_str0m` ...). Their signatures change whenever the wrapped crate is upgraded,
  which may happen in a minor release. Anything public that cannot be promised yet goes under
  `#[doc(hidden)]` or behind `unstable`, never into the covered API silently.
- the `prost` feature of `only-grpc` (the `codec::Message` implementation for prost messages;
  deprecated in favour of `only-protobuf`, which generated messages implement directly):
  it names prost's types, so a prost upgrade may come in a minor release.
- the exact text of `Display` output, log messages and panic messages.
- behaviour documented as unspecified, and performance characteristics.

Also part of the promise, although not Rust API: the wire formats of the protocol crates (HTTP/1.1,
HTTP/2, HTTP/3, WebSocket, arpc, gRPC, KCP, SOCKS stay interoperable), the names and labels of the
Prometheus metrics and the fields of the JSON debug endpoints (fields and metrics may be added in
minor releases; removed or renamed only in a major one).

### Public dependencies

The covered API uses types of only two other crates: `bytes` (`Bytes` in the QUIC and stream
APIs) and `log` (`Config::log_level`), both at 1.x / 0.4 for years. Upgrading one of them to a
semver-incompatible version is a breaking change for `only` and happens only in a major release.

The pre-1.0 dependencies that do the protocol work (rustls, quinn-proto, str0m, prost) are
**wrapped**: the covered API uses `only`'s own types instead (`only::tls::{ServerConfig,
ClientConfig, Certificate, PrivateKey, RootCerts, Error}`, `only_quic::{ServerConfig,
ClientConfig, TransportConfig, StreamId, Dir, Side, ConnectionError, ConnectionStats}`,
`only_webrtc::{ChannelId, Mid, Pt, Codec, MediaData, RtcConfig, SdpChanges, Event, ...}`,
`only_grpc::codec::Message`). Upgrading them, or replacing them with in-house implementations,
is not a breaking change. They are reachable only through the `unstable` features and the
`prost` feature above, which are excluded from the promise.

## 3. What counts as breaking

Breaking (major release only), for covered items:

- removing or renaming an item, a module, a re-export, a public field or an enum variant;
- changing a function signature: parameters, return type, generic parameters, adding bounds;
- adding a variant to an exhaustive enum or a public field to an exhaustive struct (see section 4
  for the types where this is allowed);
- adding a required method (one without a default) to a trait users implement, or changing an
  existing method's signature;
- removing a trait implementation, including losing an auto trait such as `Send` or `Sync`;
- raising the minimum required version of a public dependency to a new semver-incompatible
  release;
- changing documented behaviour in a way correct programs can observe (a default value that
  changes what a program does, a wire format), except to fix a bug.

Not breaking (allowed in minor releases):

- adding items, modules, trait implementations and inherent methods;
- adding fields to `#[non_exhaustive]` structs and variants to `#[non_exhaustive]` enums;
- adding provided (defaulted) methods to traits; this can, rarely, cause a name clash with a
  method of the user's type, which is accepted as in the Rust API guidelines;
- deprecating items (see [deprecation.md](deprecation.md));
- raising the MSRV (section 5);
- anything about items that are not covered.

Patch releases contain bug fixes only; a fix may change behaviour that contradicted the
documentation.

## 4. Conventions that keep the API extensible

These are checked by lints or review, so new API follows them too:

- **Config structs** (`Config`, `HttpConfig`, `H2Config`, `WsConfig`, `KcpConfig`, `H3Config`,
  `PoolConfig`, `UringConfig`, `EbpfConfig`, `H2Options`, `WsOptions`, `DialOptions`, `CallOptions`,
  the middleware configs, ...) are `#[non_exhaustive]` with public fields and a `Default`. Start
  from `Default::default()` (or a preset like `KcpConfig::fast()`) and assign fields:

  ```rust
  let mut cfg = only::Config::default();
  cfg.idle_timeout = Some(std::time::Duration::from_secs(30));
  ```

  Struct literals do not compile outside the defining crate, which is what lets new settings
  appear in minor releases. We chose public fields over builder methods: one way to set a value,
  readable `Debug` output, no doubling of the API, and the fields are documented where they are.
  `*Config` names the settings of a server, engine or protocol instance; `*Options` the arguments
  of one operation (a dial, a call, an upgrade).
- **Report structs** that `only` fills and users read (`Metrics`, `LoopCounters`, `ConnInfo`,
  `SlowRecord`, `PoolStats`, `UdpStats`, `TlsInfo`, `ClientResponse`, `Stats`, ...) and the
  message types `Request` / `Response` are `#[non_exhaustive]`; build messages with their
  constructors (`Request::new`, `Response::new`, `ClientRequest::new`, `FileBody::new`).
- **Error enums** and enums that will grow (`Backend`, `Accel`, `Rule`, `Method`, `Version`,
  `Steering`, `CloseReason`, ...) are `#[non_exhaustive]`: match them with a wildcard arm. Every
  error type implements `std::error::Error + Display + Debug + Send + Sync`. Enums whose variants
  are complete by definition stay exhaustive so `match` needs no wildcard: event enums
  (`BodyEvent`, `H2Event`, `StreamEvent`, `Message`, `Event`), protocol constants fixed by a
  specification (`Opcode`, `Role`, `grpc::Code`) and `Decision`.
- **Every public type implements `Debug`** (lint `missing_debug_implementations`); builder
  methods returning `Self` are `#[must_use]` (clippy `return_self_not_must_use`).
- **Traits**: the traits users implement (`Handler`, `Acceptor`, `Transport`, `Service`,
  `Middleware`, `WsHandler`, `RawHandler`, `QuicHandler`, `KcpHandler`) only gain methods with a
  default. A trait that users should call but not implement is sealed (a private supertrait), so
  methods can be added to it freely; `only` 1.0 has none, and backend-facing traits are
  `#[doc(hidden)]` instead.
- **Naming**: `dial` starts a client connection without blocking (a callback, or a handle that
  becomes ready later); `dial_blocking` waits until it is established; `serve` / `serve_with(cfg,
  service)` build server acceptors; byte limits end in `_bytes`; per-connection callbacks are
  `on_*`.

## 5. Minimum supported Rust version

- The MSRV is the `rust-version` in the workspace `Cargo.toml`, currently **1.85** (edition 2024).
  CI builds and tests with exactly that toolchain (`msrv` job).
- Raising it is not a breaking change, but it happens only in a **minor** release, never in a patch
  release, is listed in the changelog, and the new MSRV has been a stable release for at least six
  months, unless a security fix needs a newer one.

## 6. Platform support

| Tier | Platform | What it means |
|---|---|---|
| 1 | Linux x86_64 and aarch64 (glibc): epoll backend on any supported kernel; io_uring backend on 5.19+; UDP GSO/GRO, `sendmmsg`/`recvmmsg`; BPF steering (classic BPF unprivileged, eBPF with `CAP_BPF`); sockmap relay on 6.15+ (or `Relay::new_any_kernel`) | Built and fully tested on every commit (both backends); benchmarked; bugs block releases. Features missing from the running kernel are probed and fall back (io_uring to epoll, eBPF to classic BPF or none) unless `strict` is set. |
| 2 | macOS (aarch64, x86_64): kqueue backend | Built and tested in CI; meant for development. Not tuned for performance; Linux-only features (io_uring, BPF, UDP GSO/GRO) report `Unsupported` or fall back as documented. |
| 3 | Other Unix systems | May compile; not tested. `Engine::build` returns `Unsupported` where no backend exists. |
| — | Windows | Not supported before 2.0 (no IOCP backend). |

Moving a platform to a lower tier is announced in the changelog and happens only in a minor or
major release.

## 7. How the promise is enforced

- **API snapshots.** `api/<crate>.txt` holds the public API of every published crate as printed by
  [`cargo public-api`](https://github.com/cargo-public-api/cargo-public-api) on Linux (hidden
  items and `fuzzing` features excluded). The CI job `public-api` (a gate of `ci-ok`) runs
  `tools/api/public-api.sh` and fails when the API differs from the snapshot. A deliberate change
  is committed together with the regenerated snapshot (`tools/api/public-api.sh --bless`) and a
  `CHANGELOG.md` entry, which makes every API change visible in review.
- **Semver checks.** Once 1.0.0 is published, the CI job `semver-checks` runs
  [`cargo-semver-checks`](https://github.com/obi1kenobi/cargo-semver-checks) against the latest
  release on crates.io for the public-tier crates and fails on a breaking change in a non-major
  release. Until a baseline is published the job is skipped (it detects that no release exists).
