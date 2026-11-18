# only-tls

[中文](README.zh-CN.md)

TLS 1.3 and 1.2 for [`only`](https://github.com/lesismal/only), implemented in this crate from
the RFCs on [`only-crypto`](../only-crypto) and [`only-x509`](../only-x509) (and
[`only-deflate`](../only-deflate) for certificate compression): sans-io, safe Rust
(`#![forbid(unsafe_code)]`), no third-party dependencies. It replaced rustls and ring (DEV-PLAN
wave C) behind an unchanged API.

Wrap any acceptor in `Tls::server` (or `Tls::client` for `Engine::dial`) and its handlers see
plaintext; the handshake runs on the connection's I/O thread and never blocks. Configure with
`ServerConfig::builder(chain, key)` (SNI certificates, ALPN, client authentication, session cache
and tickets, `tls13_only`, record size limit, certificate compression, stapled OCSP responses)
and `ClientConfig::builder()` (roots, ALPN, client certificate, SNI, resumption, record size
limit, certificate compression, OCSP stapling and its validation, CRLs, `insecure_skip_verify`
for tests); `tls_info` reads what was negotiated.

```rust,no_run
use only_tls::{Certificate, PrivateKey, ServerConfig, Tls};
# struct Echo; impl only_core::Handler for Echo { fn on_data(&mut self, _: &only_core::Conn<Self>, _: &[u8]) {} }
let chain = Certificate::from_pem(&std::fs::read("cert.pem").unwrap()).unwrap();
let key = PrivateKey::from_pem(&std::fs::read("key.pem").unwrap()).unwrap();
let cfg = ServerConfig::builder(chain, key).alpn(["h2", "http/1.1"]).build().unwrap();
let acceptor = Tls::server(cfg, only_core::fn_acceptor(|_c: &only_core::Conn<Echo>| Echo));
# let _ = acceptor;
```

## Protocol

- **TLS 1.3** (RFC 8446): full handshake on both sides, HelloRetryRequest (cookie echoed), the key
  schedule, KeyUpdate (answered; sent before the AES-GCM record limit), NewSessionTicket and
  PSK resumption with `psk_dhe_ke` (stateless tickets, or single-use tickets from the session
  cache), client certificates (CertificateRequest), middlebox compatibility mode; early data
  (0-RTT) when both sides enable it (see below), else rejected and skipped as RFC 8446 4.2.10
  says.
- **TLS 1.2** (RFC 5246, RFC 7627 extended master secret, RFC 5746 renegotiation indication):
  ECDHE with ECDSA, Ed25519 or RSA certificates and AEAD suites only (no CBC, no RSA key
  exchange, no static DH), session IDs and RFC 5077 tickets, client certificates; renegotiation
  is refused with a `no_renegotiation` warning.
- Suites `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`,
  `ECDHE-{ECDSA,RSA}-AES{128,256}-GCM` and `ECDHE-{ECDSA,RSA}-CHACHA20-POLY1305`; groups X25519,
  secp256r1, secp384r1; signature schemes ECDSA P-256/P-384, Ed25519, RSA-PSS (rsae),
  RSA PKCS#1 v1.5 (TLS 1.2 and certificates).
- Record layer: 16 KiB fragments, TLS 1.3 inner content types and padding, version negotiation
  with the downgrade sentinel, strict state machines, handshake messages reassembled across
  records and never across key changes, alerts and close_notify, constant-time Finished / binder
  checks.
- Certificates are verified with `only-x509` (chain, validity, EKU, DNS names and IP addresses).
- Extensions: record_size_limit (RFC 8449), certificate compression (RFC 8879, zlib) and OCSP
  stapling (RFC 6066 / RFC 8446 4.4.2.1), below.

### record_size_limit, certificate compression, OCSP stapling

Decided in [ADR-008](../../docs/adr/008-tls-extensions.md).

- **record_size_limit** (RFC 8449, TLS 1.3 and 1.2, not over QUIC):
  `record_size_limit(n)` on either builder sets the largest record we accept, 64 to 16385 bytes
  as the RFC counts them (TLS 1.3 includes the content type; TLS 1.2 caps at 16384); default
  16385. The client always sends its value; the server answers with its own whenever the client
  sent one. Then each side cuts the protected records it writes to the peer's limit and refuses
  protected records over its own with `record_overflow`; unprotected records are not limited.
  Early data goes under the limit of the connection that issued the ticket. A peer without the
  extension (OpenSSL, Go) gets and applies no limit. OpenSSL's max_fragment_length (RFC 6066) is
  not implemented: the offer is ignored, as RFC 8449 recommends when record_size_limit is
  supported.
- **Certificate compression** (RFC 8879, TLS 1.3): zlib only, through `only-deflate` (no
  in-house brotli or zstd). On by default on the server, which sends its chain compressed to
  clients that offer it when that is smaller (compressed once per certificate, then reused: no
  cost per handshake) and offers it in its CertificateRequest for client certificates. Off by
  default on the client (`certificate_compression(true)` offers it): each compressed chain
  received costs an inflate of about 1–2 µs, about 1% of an in-memory full handshake. Received compressed certificates are inflated into at most 128 KiB and must
  have exactly the announced length (`bad_certificate`); another algorithm is
  `illegal_parameter`.
- **OCSP stapling**: `ServerConfigBuilder::ocsp_response(der)` (and `sni_ocsp_response` for an
  SNI chain) staples a DER OCSP response for clients that ask (TLS 1.3: in the leaf's
  CertificateEntry; TLS 1.2: `status_request` in the ServerHello plus a CertificateStatus
  message; not on resumption). The response is only checked to look like a successful
  `OCSPResponse`; refreshing it is the caller's job. `ClientConfigBuilder::ocsp_stapling(true)`
  asks for one and `TlsInfo::ocsp_response` holds what came.
- **Revocation** (ADR-038; no network access: the application fetches responses and CRLs):
  `ClientConfigBuilder::ocsp_policy(RevocationPolicy::{Off, SoftFail, HardFail})` validates the
  stapled response for the leaf (RFC 6960 via `only-x509`: signed by the issuer or a delegated
  responder with id-kp-OCSPSigning, about this certificate, thisUpdate / nextUpdate current
  within 5 minutes; TLS 1.3 and 1.2) and asks for stapling when not off. Soft fail rejects only
  a valid "revoked" (`certificate_revoked`); hard fail requires a valid "good" and otherwise
  fails with `bad_certificate_status_response`. `ClientConfigBuilder::crls(Crls, policy)` and
  `ServerConfigBuilder::client_crls(Crls, policy)` check every certificate of the peer's chain
  below the root against CRLs (complete and delta, RFC 5280); under hard fail a certificate no
  current CRL covers fails (`certificate_unknown`). Resumed sessions are not re-checked;
  refreshing CRLs means building a new configuration. All off by default, at no cost.

### Early data (0-RTT)

Off by default on both sides. `ServerConfigBuilder::early_data(max_bytes)` makes new tickets
carry `max_early_data_size` and accepts early data from clients resuming with them;
`ClientConfigBuilder::early_data(true)` makes a client send what the application writes before
the handshake completes as early data (up to the ticket's limit), right behind the ClientHello.

- **Accepted** only for the first PSK, with the ticket's cipher suite, ALPN protocol and SNI
  name, and not after a HelloRetryRequest (RFC 8446 4.2.10); the server reads it before the
  handshake completes and EndOfEarlyData ends it. A server reading more than it allowed fails
  with `unexpected_message`.
- **Rejected** early data is skipped by the server; the client keeps a copy and sends it again
  as ordinary data after the handshake, so the byte stream is the same either way.
- **Visible**: `TlsInfo::early_data` (`NotAttempted`, `Pending`, `Accepted`, `Rejected`) and
  `TlsInfo::early_data_len` (the first that many bytes of the stream went early). only-http
  marks HTTP/1.1 requests that arrived early with `Early-Data: 1` (RFC 8470; on HTTP/2 every
  request of such a connection), so a handler can answer `425 Too Early`.
- **Replay protection** (mandatory, always on with early data): the server accepts early data
  only when the ticket age the client reports is within 10 seconds of the age the server
  computes (RFC 8446 8.3), and records the PSK binder of every ClientHello whose early data it
  accepted, for twice that window (RFC 8446 8.2, "ClientHello recording"); a ClientHello whose
  binder is recorded has its early data rejected (the handshake still completes, in 1-RTT). The
  record is bounded (100,000 entries per `ServerConfig`): when it is full, early data is
  rejected until entries expire. Chosen over single-use tickets because it works with stateless
  tickets and costs one lookup per resumed ClientHello.

**Security trade-offs.** Early data is not forward secret (it is protected by the resumption
secret only) and can be **replayed**: the record above stops replays to the same server process
within the window, but not to another process or machine sharing tickets, nor a replay of the
same request in a new ClientHello by an attacker who can make the client retry. Only enable it
for requests that are safe to repeat (idempotent reads), check `TlsInfo::early_data` /
`Early-Data: 1` before acting on anything else, and answer `425 Too Early` to the rest.

Not implemented: brotli/zstd certificate compression, a client's OCSP response in TLS 1.3
client authentication, `status_request_v2` (OCSP for intermediates), fetching OCSP responses or
CRLs (the application does; `only-x509` gives the URLs), RSA-PSS keys, P-521. Kernel TLS offload was evaluated and
is not used: it was slower than this crate's record layer in every case measured, `sendfile`
included (docs/BENCHMARKS.md, "Kernel TLS (kTLS) evaluation"); the code stays behind the
experimental `experimental-ktls` feature (test stream and benchmark only, outside the semver
promise).

## Internals

- `proto`: the record layer, the TLS 1.3 / 1.2 client and server state machines (they emit
  ordered actions: handshake messages per encryption level, key changes, alerts), the key
  schedule and TLS 1.2 PRF, sessions and tickets.
- `quic` (`#[doc(hidden)]`, internal): the same TLS 1.3 machines without records for a QUIC
  implementation: handshake bytes in and out per encryption level, traffic secrets per level,
  the quic_transport_parameters extension, ALPN required, no compatibility mode, RFC 9001 key
  derivation helpers. `only-quic`'s own QUIC (DEV-PLAN wave D) drives it.
- `stream` (`#[doc(hidden)]`): a blocking TLS stream over `Read + Write`, for tests, examples
  and the interop driver (`examples/tls-interop.rs`).
- The `unstable` feature is empty (it used to expose rustls); `fuzzing` enables the fuzz entry
  points.

## Testing

- RFC 8448 trace vectors (simple 1-RTT, resumption binder, HelloRetryRequest): key schedule,
  transcript, Finished values and protected records byte for byte; RFC 9001 Appendix A key
  derivation vectors.
- In-memory handshakes over every suite, group, certificate type and version, resumption,
  client authentication, SNI / ALPN, KeyUpdate, fragmentation down to one byte, close_notify,
  downgrade detection, tampering, unexpected and garbage records; record_size_limit (both
  versions, limits from 64 bytes both ways, records over the limit, early data under the
  ticket's limit), certificate compression (server and client certificates, either side off,
  malformed messages) and OCSP stapling (both versions, SNI, resumption), alone and together;
  revocation: every policy against good, delegated, revoked, unknown, expired, forged, foreign,
  opaque and missing staples in both versions, CRLs for server and client chains.
- Interop (`tools/interop/tls/run.sh`): OpenSSL `s_server` / `s_client` and Go `crypto/tls` in
  both directions over every suite, group, key type, client authentication, resumption, HRR,
  ALPN, KeyUpdate, early data and OCSP stapling (verified by `s_client`), zlib certificate
  compression with OpenSSL 3.2+ built with zlib (Debian's), only's client validating
  `s_server -status_file` staples (good, revoked, missing; soft and hard fail) and checking
  OpenSSL-made CRLs, record_size_limit and OCSP with
  GnuTLS when installed, plus curl against only-http (HTTP/1.1 and HTTP/2); needs
  OpenSSL 3.0 or later (the early-data cases run `s_server` without `-www`, which 3.0 refuses
  with `-early_data`; the client sends, closes and checks `s_server`'s log); gRPC over TLS with
  grpc-go (`tools/interop/grpc/run.sh`); rustls clients in the `only` crate's TLS tests.
- tlsfuzzer against the server (`tools/interop/tls/tlsfuzzer.sh`, Docker): the 36 scripts that
  apply (no CBC, RSA key exchange, FFDHE, external PSK ...), record_size_limit and certificate
  compression (server and client certificates) included, 1,096 probes; the known failures
  (probes of otherwise applicable scripts that use CBC suites, the RSA key exchange or TLS
  1.0/1.1, and a few others) are listed in the script with their reasons.
- Fuzzing: `tls_server`, `tls_client`, `tls_record` in `fuzz/`; `fuzzing::tests` replays their
  corpora on stable.
