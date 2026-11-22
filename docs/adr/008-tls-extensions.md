# ADR-008: TLS record_size_limit, certificate compression and OCSP stapling

English | [简体中文](008-tls-extensions.zh-CN.md)

Status: accepted (2026-11-16)

## Context

`akio-tls` runs its own TLS 1.2/1.3. Three extensions common in browsers and servers were
missing: record_size_limit (RFC 8449, constrained peers bound the records they receive),
certificate compression (RFC 8879, smaller TLS 1.3 handshakes) and OCSP stapling (RFC 6066
`status_request`; RFC 8446 section 4.4.2.1 in TLS 1.3). Each needs a configuration knob, and the
stapled response has to reach the application, so the public API grows.

## Decision

1. **Additive builder options, no new types.**
   - `ServerConfigBuilder::record_size_limit(u16)` and `ClientConfigBuilder::record_size_limit(u16)`:
     the value as RFC 8449 counts it, 64 to 16385 (TLS 1.3 includes the content type; TLS 1.2
     caps it at 16384), default 16385, out-of-range values fail `build`.
   - `ServerConfigBuilder::certificate_compression(bool)` and
     `ClientConfigBuilder::certificate_compression(bool)`: on by default on the server, off on
     the client.
   - `ServerConfigBuilder::ocsp_response(der)` for the default chain and
     `sni_ocsp_response(name, der)` for an `sni_cert` chain; `ClientConfigBuilder::ocsp_stapling(bool)`,
     default off.
   - `TlsInfo::ocsp_response: Option<Vec<u8>>` (the struct is `#[non_exhaustive]`).
2. **record_size_limit.** The client always sends its value (16385 by default: "I support it, no
   smaller limit"); the server answers with its own whenever the client sent one, and each side
   then cuts the protected records it writes to the peer's limit and refuses protected records
   over its own (`record_overflow`). Unprotected records are not limited. Early data goes under
   the limit of the connection that issued the ticket (kept with the client's ticket); the
   server does not hold early data to its new limit. Never sent or answered over QUIC. Answering
   by default is what makes the client's limit binding, which is the point of the extension;
   sending 16385 by default costs 6 bytes and changes nothing for a peer without a limit.
3. **Certificate compression: zlib only.** `akio-deflate` (in-house, already a workspace crate)
   provides zlib; there is no in-house brotli or zstd, so only zlib (algorithm 1) is offered and
   accepted. TLS 1.3 only, server and client certificates (offered in the ClientHello and the
   CertificateRequest). The server compresses each certificate chain once and reuses it; a
   compressed form that is not smaller is not sent. Received messages are decompressed into at
   most 128 KiB (the handshake message limit) and must match the announced length exactly
   (`bad_certificate`); an algorithm not offered is `illegal_parameter`. **On by default on the
   server**: compressing is paid once per chain, so a handshake costs nothing more, and clients
   that do not offer it see no change. **Off by default on the client**: each compressed chain
   received costs an inflate of about 1–2 µs (akio-deflate has a fixed cost of about 1 µs per
   stream), which the same-run handshake A/B measured as about 1% of an in-memory full
   handshake, for a saving of tens of bytes on a single self-signed certificate and a few
   hundred on a CA chain. Clients that care about bytes on the wire turn it on.
4. **OCSP stapling: carried, not validated.** The server staples the configured DER response
   when the client asks (TLS 1.3: leaf `CertificateEntry` extension; TLS 1.2: `status_request` in
   the ServerHello and a `CertificateStatus` message), never on resumption. The configured value
   is checked only for the outer shape of a successful `OCSPResponse`; refreshing it is the
   caller's job (build a new configuration). The client exposes the response and does **not**
   verify it: `akio-x509` has no OCSP (signature, responder, validity, certificate ID) yet, and a
   half check would suggest more protection than it gives. Off by default on the client, like
   OpenSSL, because nothing in the stack consumes it.
5. **`akio-tls` depends on `akio-deflate`.** Both are in-house and dependency-free, so the
   dependency policy (ADR-005, as amended by the in-house wave) is unchanged.

## Consequences

- ClientHellos grow by the record_size_limit extension (6 bytes; 7 more for compress_certificate
  when enabled); servers that do not know them ignore them (OpenSSL, Go, curl and tlsfuzzer
  runs).
- A peer advertising a small limit makes us write more, smaller records; kernel TLS offload
  (experimental) is refused then, since the kernel writes full records.
- OCSP validation, brotli/zstd, the client's `status_request` in TLS 1.3 CertificateRequests and
  `status_request_v2` are not done; adding them later is additive.
