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
side), `version`, `early_data` and `early_data_len` (see [Early data](#early-data-0-rtt)) and
`ocsp_response` (client side, see [OCSP stapling](#ocsp-stapling)), or `None` for a non-TLS
connection.

## Protocol support

| | TLS 1.3 (RFC 8446) | TLS 1.2 (RFC 5246) |
|---|---|---|
| key exchange | X25519, secp256r1, secp384r1; HelloRetryRequest | ECDHE on the same groups (no RSA key exchange, no static DH) |
| cipher suites | AES-128-GCM-SHA256, AES-256-GCM-SHA384, CHACHA20-POLY1305-SHA256 | ECDHE-ECDSA / ECDHE-RSA with AES-128/256-GCM and CHACHA20-POLY1305 (no CBC) |
| certificates | ECDSA P-256/P-384, Ed25519, RSA (PSS signatures) | the same, RSA also with PKCS#1 v1.5 |
| resumption | tickets + PSK (`psk_dhe_ke`): stateless with `.session_tickets(true)`, single-use cached tickets with the session cache | session IDs (cache) and RFC 5077 tickets |
| other | KeyUpdate (answered, and sent before the AES-GCM record limit), client certificates, middlebox compatibility mode, early data (0-RTT) when both sides enable it (else rejected and skipped), certificate compression (RFC 8879, zlib) | extended master secret (RFC 7627), renegotiation indication (RFC 5746), renegotiation refused |
| record_size_limit (RFC 8449) | yes | yes |

Both: SNI, ALPN, close_notify, 16 KiB records (smaller under a peer's record_size_limit), OCSP
stapling, TLS 1.3 inner content types and padding, the
downgrade sentinel, strict state machines (unexpected messages, empty or interleaved records,
handshake data across key changes are fatal). Certificates are verified with `only-x509`:
chain to the roots, validity, extended key usage, DNS names (RFC 6125 wildcards) and IP
addresses. The client prefers AES-128-GCM, then AES-256-GCM, then ChaCha20-Poly1305; the server
picks by its own preference and prefers the client's key share (no HelloRetryRequest when one
fits).

Conformance: RFC 8448 traces as unit tests, tlsfuzzer (`tools/interop/tls/tlsfuzzer.sh`), and an interop matrix against OpenSSL, Go
`crypto/tls`, curl and rustls (`tools/interop/tls/run.sh`, `tools/interop/grpc/run.sh`, the
`only` crate's TLS tests). Speed against rustls 0.23 with ring (`tls-bench`, x86_64 with VAES):
X25519 full handshakes on par, AES-128-GCM records about 1.6x at 1 KiB and at 16 KiB.

## Configuration

Configuration uses `only`'s own types; the protocol internals are not part of the API. `Certificate::from_pem` / `from_der`, `PrivateKey::from_pem` / `from_der` /
`from_pkcs8_der` and `RootCerts` load the material. `RootCerts::system()` is the operating
system's trust store, read once per process: `SSL_CERT_FILE` / `SSL_CERT_DIR` when set, the
system keychains on macOS (exported with `/usr/bin/security`; trust settings are not applied),
the distribution's CA bundle or certificate directory on other Unix systems. The HTTP and
WebSocket clients use it when no `ClientConfig` is given (ADR-010).

| Need | Server: `ServerConfig::builder(chain, key)` | Client: `ClientConfig::builder()` |
|---|---|---|
| certificates | the chain and key; `.sni_cert(name, chain, key)` per SNI name | `.client_cert(chain, key)` |
| trust | `.client_auth_required(roots)` / `.client_auth_optional(roots)` | `.roots(roots)` |
| ALPN (`h2`, `http/1.1`, custom) | `.alpn(["h2", "http/1.1"])` | `.alpn([..])` |
| session resumption | `.session_cache(entries)`, `.session_tickets(true)` | `.resumption(false)` to disable |
| protocol versions | `.tls13_only(true)` | `.tls13_only(true)` |
| SNI | | `.sni(false)` to stop sending it |
| early data (0-RTT) | `.early_data(max_bytes)` | `.early_data(true)` |
| record size limit (RFC 8449) | `.record_size_limit(bytes)` | `.record_size_limit(bytes)` |
| certificate compression | on by default; `.certificate_compression(false)` to disable | `.certificate_compression(true)` to offer it |
| OCSP stapling | `.ocsp_response(der)`, `.sni_ocsp_response(name, der)` | `.ocsp_stapling(true)` |
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

## Early data (0-RTT)

Off by default; both sides must enable it. A server with `.early_data(max_bytes)` (and session
resumption) issues tickets allowing that much early data; a client with `.early_data(true)` that
resumes with such a ticket sends what the application writes before the handshake completes
right behind its ClientHello, saving a round trip. The server reads it before the handshake
completes, so `on_data` can see a request one round trip earlier.

- The server accepts early data only for the ticket's first PSK, cipher suite, ALPN protocol
  and SNI name, never after a HelloRetryRequest, and never more than it allowed.
- When the server rejects it (another configuration, a HelloRetryRequest, a suspected replay),
  it skips the early records; the client sends the same bytes again after the handshake, so
  the application sees the same stream either way.
- `TlsInfo::early_data` tells `NotAttempted`, `Pending` (client, before the answer), `Accepted`
  or `Rejected`; `TlsInfo::early_data_len` is how many bytes at the start of the stream went
  early. only-http marks HTTP/1.1 requests in that range with `Early-Data: 1` (RFC 8470; on
  HTTP/2, every request of a connection that started with early data).

**Replay protection** is always on with early data: the server accepts it only when the
client's view of the ticket age is within 10 seconds of its own (RFC 8446 section 8.3) and
records the PSK binder of each accepted ClientHello for 30 seconds (section 8.2: twice the window, plus one for clocks of servers sharing a store to differ by); a ClientHello
seen before gets its early data rejected and continues as an ordinary resumption. The record
holds 100,000 ClientHellos per `ServerConfig`; when full, early data is rejected.

**Servers sharing tickets** ([ADR-013](https://github.com/lesismal/only/blob/main/docs/adr/013-shared-anti-replay-and-compatible-vn.md)).
Several processes or machines accept each other's tickets when built with the same
`.session_ticket_key(key)` (48 secret random bytes: a 16-byte key name and a 32-byte key; rotate
by building new configurations). They then also need one replay record, or a first flight
recorded on its way to one server can be replayed to another: `.anti_replay_store(store)` takes
any `Arc<dyn AntiReplayStore>`, whose one method records a ClientHello's binder for a time and
says whether it was new. It is called on the I/O thread during the handshake, only for
ClientHellos whose early data would otherwise be accepted, so keep it short and bounded by a
timeout. Errors **fail closed**: the early data is rejected and the client sends it again after
the handshake. The default is `MemoryAntiReplay` (the per-configuration record above). With
Redis, one atomic `SET key 1 NX PX ttl` per call:

```rust,ignore
use std::{io, sync::Arc, time::Duration};
use only_tls::{AntiReplayStore, ServerConfig};

struct RedisReplay { pool: MyRedisPool } // any client with a short timeout

impl AntiReplayStore for RedisReplay {
    fn check_and_insert(&self, binder: &[u8], ttl: Duration) -> io::Result<bool> {
        let key = format!("only:0rtt:{}", hex(binder));
        // "OK" if the key was set (first time), nil if it existed (a replay).
        let reply = self.pool.set_nx_px(&key, "1", ttl.as_millis() as u64)
            .map_err(io::Error::other)?; // timeouts too: early data rejected
        Ok(reply.is_some())
    }
}

let cfg = ServerConfig::builder(chain, key)
    .session_ticket_key(ticket_key)          // the same on every server
    .early_data(16384)
    .anti_replay_store(Arc::new(RedisReplay { pool }))
    .build()?;
```

The store must be atomic (a read then a write lets a concurrent replay through); across regions
with replication lag, give each region its own store and ticket key. QUIC servers get both
through `only_quic::server_config_from(&cfg)`.

**Security trade-offs.** Early data is not forward secret and can be replayed: the record stops
replays to the same server (or the servers sharing its store) within the window, not a request
the client itself is made to send again. Enable it only for requests that are safe to
repeat (reads without side effects), and answer the others `425 Too Early`:

```rust,ignore
.post("/pay", |ctx: &mut Context| {
    if ctx.header("early-data") == Some("1") {
        return ctx.text(425, "too early"); // the client retries after the handshake
    }
    // ...
})
```

## Record size limit, certificate compression, OCSP stapling

Decided in [ADR-008](https://github.com/lesismal/only/blob/main/docs/adr/008-tls-extensions.md).

**record_size_limit** (RFC 8449, TLS 1.3 and 1.2). `.record_size_limit(n)` on either side sets
the largest record it accepts: 64 to 16385 bytes counted as the RFC does (in TLS 1.3 the value
includes the one-byte content type; TLS 1.2 caps it at 16384), default 16385. The client always
sends its value and the server answers with its own whenever the client sent one; from then on
each side cuts the protected records it writes to the peer's limit and refuses records over its
own (`record_overflow`). Unprotected handshake records are not limited, and early data goes under
the limit of the connection that issued the ticket. Peers without the extension (OpenSSL, Go)
neither get nor apply a limit. Not used inside QUIC (no records).

```rust,ignore
// A small device that cannot buffer 16 KiB records.
let cfg = ClientConfig::builder().roots(roots).record_size_limit(1024).build()?;
```

**Certificate compression** (RFC 8879, TLS 1.3). On by default on the server: it sends its chain
compressed to clients that offer zlib, when that is smaller (each chain is compressed once and
reused, so handshakes cost nothing more), and its CertificateRequest offers it for client
certificates. Off by default on the client: inflating a received chain costs about 1–2 µs, about
1% of an in-memory full handshake, for tens to hundreds of bytes saved; turn it on with
`.certificate_compression(true)` when bytes on the wire matter more. zlib only (through the
in-house `only-deflate`; there is no in-house brotli or zstd). Received certificates are inflated
into at most 128 KiB and must have exactly the announced length.

### OCSP stapling

The server staples a DER OCSP response for clients that ask (TLS 1.3: in the leaf's
CertificateEntry; TLS 1.2: a CertificateStatus message; never on resumption):

```rust,ignore
let ocsp = std::fs::read("leaf.ocsp.der")?; // fetched from the CA's responder, refreshed by you
let cfg = ServerConfig::builder(chain, key).ocsp_response(ocsp).build()?;
```

`.build()` only checks that it looks like a successful `OCSPResponse`. Responses expire (often
within days): fetch a new one and build a new configuration before then.

A client with `.ocsp_stapling(true)` asks for one, and `tls_info(&conn).ocsp_response` holds the
DER bytes. **They are not verified**: `only-x509` does not check OCSP yet (the responder's
signature, validity, the certificate ID), so an application that cares about revocation must
verify the response itself.

## Kernel TLS

Not used: kernel TLS offload (handing the record keys to Linux after the handshake, so that
`sendfile` works under TLS) was measured and is slower than only-tls's own record layer, by
0.83x at 1 KiB responses down to 0.40x at 256 KiB and 0.48x for `sendfile` of a 10 MB file
against `pread` plus sealing ([measurements](https://github.com/lesismal/only/blob/main/docs/BENCHMARKS.md#kernel-tls-ktls-evaluation)). The offload is
kept behind the experimental `experimental-ktls` cargo feature (blocking test stream and
benchmark only, not wired into `Tls`, outside the semver promise) for re-measuring, for example
on a NIC with TLS offload.

## Not done

OCSP response validation, brotli/zstd certificate compression, `status_request_v2`; RSA-PSS keys
(`rsa_pss_pss_*`); P-521; the Windows certificate store and macOS trust settings.

## Writing your own transport

`only_core::Transport` is the trait TLS implements: `recv(cipher, plain, out)`, `seal(plain,
out)`, `shutdown(out)`, plus `name` and `handshaking`. Return one from `Acceptor::transport` to
layer any byte-stream transformation under a connection. All calls happen under the connection's
write lock, in wire order, and must not block.
