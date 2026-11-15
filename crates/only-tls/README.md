# only-tls

[中文](README.zh-CN.md)

TLS 1.3 and 1.2 for [`only`](https://github.com/lesismal/only), implemented in this crate from
the RFCs on [`only-crypto`](../only-crypto) and [`only-x509`](../only-x509): sans-io, safe Rust
(`#![forbid(unsafe_code)]`), no third-party dependencies. It replaced rustls and ring (DEV-PLAN
wave C) behind an unchanged API.

Wrap any acceptor in `Tls::server` (or `Tls::client` for `Engine::dial`) and its handlers see
plaintext; the handshake runs on the connection's I/O thread and never blocks. Configure with
`ServerConfig::builder(chain, key)` (SNI certificates, ALPN, client authentication, session cache
and tickets, `tls13_only`) and `ClientConfig::builder()` (roots, ALPN, client certificate, SNI,
resumption, `insecure_skip_verify` for tests); `tls_info` reads what was negotiated.

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
  cache), client certificates (CertificateRequest), middlebox compatibility mode; 0-RTT is
  rejected (and skipped as RFC 8446 4.2.10 says).
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

Not implemented: sending or accepting 0-RTT, record_size_limit, certificate compression, OCSP
stapling (status_request is ignored), RSA-PSS keys, P-521. Kernel TLS offload was evaluated and
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
  downgrade detection, tampering, unexpected and garbage records.
- Interop (`tools/interop/tls/run.sh`): OpenSSL `s_server` / `s_client` and Go `crypto/tls` in
  both directions over every suite, group, key type, client authentication, resumption, HRR,
  ALPN and KeyUpdate, plus curl against only-http (HTTP/1.1 and HTTP/2); gRPC over TLS with
  grpc-go (`tools/interop/grpc/run.sh`); rustls clients in the `only` crate's TLS tests.
- tlsfuzzer against the server (`tools/interop/tls/tlsfuzzer.sh`, Docker): the 33 scripts that
  apply (no CBC, RSA key exchange, FFDHE, external PSK ...), 985 probes, 5 known failures listed
  in the script with their reasons.
- Fuzzing: `tls_server`, `tls_client`, `tls_record` in `fuzz/`; `fuzzing::tests` replays their
  corpora on stable.
