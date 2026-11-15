# TLS

`only::tls` (the `only-tls` crate) is a **transport layer** under the connection, with its own
TLS 1.3 and 1.2 implementation: written from the RFCs on `only-crypto` and `only-x509`, sans-io,
`#![forbid(unsafe_code)]`, no third-party dependencies. Wrap any acceptor and its handlers see plaintext:
`on_data` receives decrypted bytes, `Conn::send*` encrypts.

## Server

```rust,ignore
{{#include ../../../../crates/only/examples/guide-tls.rs:server}}
```

## Client

```rust,ignore
{{#include ../../../../crates/only/examples/guide-tls.rs:client}}
```

`Tls::client(config, server_name, acceptor)` verifies the server as `server_name` and sends it as
SNI. It returns an error for a name that is not a valid DNS name or IP address.

Run both with `cargo run -p only --example guide-tls`.

## How it works

- The handshake runs on the connection's I/O thread, interleaved with other connections, and
  never blocks.
- Bytes you send before the handshake completes (for example from `on_open`) are held back and
  flushed as soon as it does.
- `close_after_send()` sends `close_notify` after the queued data.
- A failed handshake or a bad record closes the connection after flushing the alert; failures
  are counted separately for the handshake (`only_tls_handshake_failures_total`) and afterwards
  (`only_transport_errors_total`).
- Records are sealed in pieces of at most one TLS record, so large sends are fine.
- The connection table shows `transport: "tls"`.

## What it negotiated

`tls_info(&conn)` returns a `TlsInfo` with `handshaking`, `alpn`, `server_name` (SNI, server
side) and `version`, or `None` for a non-TLS connection.

## Protocol support

| | TLS 1.3 (RFC 8446) | TLS 1.2 (RFC 5246) |
|---|---|---|
| key exchange | X25519, secp256r1, secp384r1; HelloRetryRequest | ECDHE on the same groups (no RSA key exchange, no static DH) |
| cipher suites | AES-128-GCM-SHA256, AES-256-GCM-SHA384, CHACHA20-POLY1305-SHA256 | ECDHE-ECDSA / ECDHE-RSA with AES-128/256-GCM and CHACHA20-POLY1305 (no CBC) |
| certificates | ECDSA P-256/P-384, Ed25519, RSA (PSS signatures) | the same, RSA also with PKCS#1 v1.5 |
| resumption | tickets + PSK (`psk_dhe_ke`): stateless with `.session_tickets(true)`, single-use cached tickets with the session cache | session IDs (cache) and RFC 5077 tickets |
| other | KeyUpdate (answered, and sent before the AES-GCM record limit), client certificates, middlebox compatibility mode, 0-RTT offered by a client is rejected and skipped | extended master secret (RFC 7627), renegotiation indication (RFC 5746), renegotiation refused |

Both: SNI, ALPN, close_notify, 16 KiB records, TLS 1.3 inner content types and padding, the
downgrade sentinel, strict state machines (unexpected messages, empty or interleaved records,
handshake data across key changes are fatal). Certificates are verified with `only-x509`:
chain to the roots, validity, extended key usage, DNS names (RFC 6125 wildcards) and IP
addresses. The client prefers AES-128-GCM, then AES-256-GCM, then ChaCha20-Poly1305; the server
picks by its own preference and prefers the client's key share (no HelloRetryRequest when one
fits).

Conformance: RFC 8448 traces as unit tests, tlsfuzzer (`tools/interop/tls/tlsfuzzer.sh`), and an interop matrix against OpenSSL, Go
`crypto/tls`, curl and rustls (`tools/interop/tls/run.sh`, `tools/interop/grpc/run.sh`, the
`only` crate's TLS tests). Speed against rustls 0.23 with ring (`tls-bench`, x86_64 with VAES):
X25519 full handshakes on par, AES-128-GCM records 1.5x at 1 KiB and 1.65x at 16 KiB.

## Configuration

Configuration uses `only`'s own types; the protocol internals are not part of the API. `Certificate::from_pem` / `from_der`, `PrivateKey::from_pem` / `from_der` /
`from_pkcs8_der` and `RootCerts` load the material.

| Need | Server: `ServerConfig::builder(chain, key)` | Client: `ClientConfig::builder()` |
|---|---|---|
| certificates | the chain and key; `.sni_cert(name, chain, key)` per SNI name | `.client_cert(chain, key)` |
| trust | `.client_auth_required(roots)` / `.client_auth_optional(roots)` | `.roots(roots)` |
| ALPN (`h2`, `http/1.1`, custom) | `.alpn(["h2", "http/1.1"])` | `.alpn([..])` |
| session resumption | `.session_cache(entries)`, `.session_tickets(true)` | `.resumption(false)` to disable |
| protocol versions | `.tls13_only(true)` | `.tls13_only(true)` |
| SNI | | `.sni(false)` to stop sending it |
| tests only | | `.insecure_skip_verify()` |

`.build()` checks the certificates and key (including that the key belongs to the leaf
certificate) and returns the config or a `only::tls::Error`; configs are cheap to clone. The
`unstable` cargo feature, which used to expose the wrapped rustls, is empty now (kept so that
builds naming it keep working).

## With other crates

- only-http: `Tls::server(cfg, serve(app))`. With `alpn_protocols = [h2, http/1.1]` the same
  listener serves HTTP/2 to clients that negotiate `h2`.
- only-ws client: `DialOptions::tls` for `wss://`.
- only-http clients: `Client::with_tls(cfg)`, `H2Client::dial(.., Some((cfg, name)), ..)`.
- QUIC and HTTP/3 use TLS 1.3 inside QUIC: see `only_quic::server_config` and
  `server_config_from(&tls_config)`. `only-quic`'s own QUIC (DEV-PLAN wave D) drives the
  record-free TLS 1.3 core inside `only-tls` (internal API) with the same `only::tls`
  configurations.

## Kernel TLS

Not used: kernel TLS offload (handing the record keys to Linux after the handshake, so that
`sendfile` works under TLS) was measured and is slower than only-tls's own record layer, by
0.83x at 1 KiB responses down to 0.40x at 256 KiB and 0.48x for `sendfile` of a 10 MB file
against `pread` plus sealing ([measurements](https://github.com/lesismal/only/blob/main/docs/BENCHMARKS.md#kernel-tls-ktls-evaluation)). The offload is
kept behind the experimental `experimental-ktls` cargo feature (blocking test stream and
benchmark only, not wired into `Tls`, outside the semver promise) for re-measuring, for example
on a NIC with TLS offload.

## Not done

Sending or accepting TLS 1.3 early data (0-RTT); record_size_limit, certificate
compression, OCSP stapling (status_request is ignored); RSA-PSS keys (`rsa_pss_pss_*`);
P-521; system root certificates (load them into `RootCerts`).

## Writing your own transport

`only_core::Transport` is the trait TLS implements: `recv(cipher, plain, out)`, `seal(plain,
out)`, `shutdown(out)`, plus `name` and `handshaking`. Return one from `Acceptor::transport` to
layer any byte-stream transformation under a connection. All calls happen under the connection's
write lock, in wire order, and must not block.
