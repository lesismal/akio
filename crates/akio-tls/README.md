# akio-tls

[中文](README.zh-CN.md)

TLS 1.3 and 1.2 for [`akio`](https://github.com/lesismal/akio), implemented in this crate from
the RFCs on [`akio-crypto`](../akio-crypto) and [`akio-x509`](../akio-x509) (and
[`akio-deflate`](../akio-deflate), [`akio-brotli`](../akio-brotli) and
[`akio-zstd`](../akio-zstd) for certificate compression): sans-io, safe Rust
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
use akio_tls::{Certificate, PrivateKey, ServerConfig, Tls};
# struct Echo; impl akio_core::Handler for Echo { fn on_data(&mut self, _: &akio_core::Conn<Self>, _: &[u8]) {} }
let chain = Certificate::from_pem(&std::fs::read("cert.pem").unwrap()).unwrap();
let key = PrivateKey::from_pem(&std::fs::read("key.pem").unwrap()).unwrap();
let cfg = ServerConfig::builder(chain, key).alpn(["h2", "http/1.1"]).build().unwrap();
let acceptor = Tls::server(cfg, akio_core::fn_acceptor(|_c: &akio_core::Conn<Echo>| Echo));
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
  ECDHE with ECDSA, Ed25519, Ed448 or RSA certificates and AEAD suites only (no CBC, no RSA key
  exchange, no static DH), session IDs and RFC 5077 tickets, client certificates; renegotiation
  is refused with a `no_renegotiation` warning.
- Suites `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`,
  `ECDHE-{ECDSA,RSA}-AES{128,256}-GCM` and `ECDHE-{ECDSA,RSA}-CHACHA20-POLY1305`; groups X25519,
  secp256r1, secp384r1, x448 (ADR-046), secp521r1 (offered last; ADR-049); signature schemes
  ECDSA P-256/P-384/P-521, Ed25519, Ed448, RSA-PSS with `rsaEncryption` keys (`rsa_pss_rsae_*`)
  and with `id-RSASSA-PSS` keys (`rsa_pss_pss_*`, within the key's parameters, TLS 1.3 and 1.2;
  ADR-049), RSA PKCS#1 v1.5 (TLS 1.2 and certificates).
- Record layer: 16 KiB fragments, TLS 1.3 inner content types and padding, version negotiation
  with the downgrade sentinel, strict state machines, handshake messages reassembled across
  records and never across key changes, alerts and close_notify, constant-time Finished / binder
  checks.
- Certificates are verified with `akio-x509` (chain, validity, EKU, DNS names and IP addresses,
  certificate policies with the default inputs).
- Extensions: record_size_limit (RFC 8449), certificate compression (RFC 8879: zlib, brotli, zstd) and OCSP
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
- **Certificate compression** (RFC 8879, TLS 1.3): zlib, brotli and zstd, through the in-house
  `akio-deflate`, `akio-brotli` and `akio-zstd` ([ADR-041](../../docs/adr/041-brotli-zstd.md)).
  On by default on the server, which sends its chain compressed to clients that offer it, with
  whichever offered algorithm makes it smallest, when that is smaller than the plain chain
  (compressed once per certificate and algorithm, then reused: no cost per handshake), and
  offers all three in its CertificateRequest for client certificates. Off by default on the
  client (`certificate_compression(true)` offers brotli, zstd and zlib): each compressed chain
  received costs a decompression of a few microseconds, a percent or two of an in-memory full
  handshake. `certificate_compression_algorithms(&[CertCompression])` on either builder takes
  only some algorithms. Received compressed certificates are decompressed into at most 128 KiB
  and must have exactly the announced length (`bad_certificate`); an algorithm not offered is
  `illegal_parameter`.
- **OCSP stapling**: `ServerConfigBuilder::ocsp_response(der)` (and `sni_ocsp_response` for an
  SNI chain) staples a DER OCSP response for clients that ask (TLS 1.3: in the leaf's
  CertificateEntry; TLS 1.2: `status_request` in the ServerHello plus a CertificateStatus
  message; not on resumption). The response is only checked to look like a successful
  `OCSPResponse`; refreshing it is the caller's job. `ClientConfigBuilder::ocsp_stapling(true)`
  asks for one and `TlsInfo::ocsp_response` holds what came.
- **Revocation** (ADR-038; no network access: the application fetches responses and CRLs):
  `ClientConfigBuilder::ocsp_policy(RevocationPolicy::{Off, SoftFail, HardFail})` validates the
  stapled response for the leaf (RFC 6960 via `akio-x509`: signed by the issuer or a delegated
  responder with id-kp-OCSPSigning, about this certificate, thisUpdate / nextUpdate current
  within 5 minutes; TLS 1.3 and 1.2) and asks for stapling when not off. Soft fail rejects only
  a valid "revoked" (`certificate_revoked`); hard fail requires a valid "good" and otherwise
  fails with `bad_certificate_status_response`. `ClientConfigBuilder::crls(Crls, policy)` and
  `ServerConfigBuilder::client_crls(Crls, policy)` check every certificate of the peer's chain
  below the root against CRLs (complete and delta, RFC 5280); under hard fail a certificate no
  current CRL covers fails (`certificate_unknown`). Resumed sessions are not re-checked;
  refreshing CRLs means building a new configuration. All off by default, at no cost.
- **The client's OCSP response** (TLS 1.3 client authentication, RFC 8446 4.4.2.1; ADR-049):
  `ServerConfigBuilder::client_ocsp_policy(policy)` asks for it (an empty status_request in the
  CertificateRequest) and validates what the client staples to its leaf's CertificateEntry
  under the same policies and rules as above; `ClientConfigBuilder::client_cert_ocsp_response(der)`
  is what the client staples when asked. TLS 1.2 cannot carry one, so under hard fail TLS 1.2
  client certificates are refused; OpenSSL and Go neither send nor ask for one (their clients
  ignore the request: soft fail passes them). The server's `TlsInfo::ocsp_response` is the
  client's response.

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
  `TlsInfo::early_data_len` (the first that many bytes of the stream went early). akio-http
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

Not implemented: `status_request_v2` (RFC 6961, OCSP for intermediates; TLS 1.2 only, never
widely deployed and superseded by TLS 1.3's per-CertificateEntry status, ADR-049), fetching OCSP
responses or CRLs (the application does; `akio-x509` gives the URLs), RSA-PSS signing with a
salt other than the hash length.

Kernel TLS (the `ktls` feature, ADR-067): `ServerConfigBuilder::ktls` / `ClientConfigBuilder::ktls`
move the record layer of engine connections into Linux after the handshake. `Ktls::Hardware`
offloads only what a NIC with TLS offload does itself (checked per interface, confirmed by the
kernel's counters) and changes nothing on other hosts; `Ktls::Software` / `SoftwareTx` use the
kernel's software record layer, which is slower than this crate's on current CPUs, `sendfile`
included (docs/BENCHMARKS.md, "Kernel TLS (kTLS) evaluation"). Off by default.

## Internals

- `proto`: the record layer, the TLS 1.3 / 1.2 client and server state machines (they emit
  ordered actions: handshake messages per encryption level, key changes, alerts), the key
  schedule and TLS 1.2 PRF, sessions and tickets.
- `quic` (`#[doc(hidden)]`, internal): the same TLS 1.3 machines without records for a QUIC
  implementation: handshake bytes in and out per encryption level, traffic secrets per level,
  the quic_transport_parameters extension, ALPN required, no compatibility mode, RFC 9001 key
  derivation helpers. `akio-quic`'s own QUIC (DEV-PLAN wave D) drives it.
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
  opaque and missing staples in both versions, CRLs for server and client chains, the client's
  OCSP response (good, delegated, revoked, unknown, foreign, missing; TLS 1.2 under each
  policy); P-521 and RSA-PSS-key (`id-RSASSA-PSS`) server and client certificates, secp521r1.
- Interop (`tools/interop/tls/run.sh`): OpenSSL `s_server` / `s_client` and Go `crypto/tls` in
  both directions over every suite, group, key type, client authentication, resumption, HRR,
  ALPN, KeyUpdate, early data and OCSP stapling (verified by `s_client`), secp521r1, P-521 and
  RSA-PSS-key certificates (`rsa_pss_pss_sha256`, TLS 1.3 and 1.2; with OpenSSL only, Go has no
  RSA-PSS keys) for servers and clients, the client OCSP request against OpenSSL (which ignores
  it) and between akio's client and server over TCP (good, revoked, missing), zlib, brotli and zstd
  certificate compression with OpenSSL 3.2+ built with them (Debian's has zlib and zstd;
  `tools/interop/tls/certcomp.Dockerfile` builds one with all three), akio's client validating
  `s_server -status_file` staples (good, revoked, missing; soft and hard fail) and checking
  OpenSSL-made CRLs, record_size_limit and OCSP with
  GnuTLS when installed, plus curl against akio-http (HTTP/1.1 and HTTP/2); needs
  OpenSSL 3.0 or later (the early-data cases run `s_server` without `-www`, which 3.0 refuses
  with `-early_data`; the client sends, closes and checks `s_server`'s log); gRPC over TLS with
  grpc-go (`tools/interop/grpc/run.sh`); rustls clients in the `akio` crate's TLS tests.
- tlsfuzzer against the server (`tools/interop/tls/tlsfuzzer.sh`, Docker): the 36 scripts that
  apply (no CBC, RSA key exchange, FFDHE, external PSK ...), record_size_limit and certificate
  compression (server and client certificates) included, 1,096 probes; the known failures
  (probes of otherwise applicable scripts that use CBC suites, the RSA key exchange or TLS
  1.0/1.1, and a few others) are listed in the script with their reasons.
- Fuzzing: `tls_server`, `tls_client`, `tls_record` in `fuzz/`; `fuzzing::tests` replays their
  corpora on stable.
