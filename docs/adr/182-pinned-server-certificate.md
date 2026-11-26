# ADR-182: A pinned server certificate in akio-tls's client

English | [简体中文](182-pinned-server-certificate.zh-CN.md)

Status: accepted (2026-11-27). akit's A235.

## Context

fit's tunnel and LLM mesh check a hub's (or a listener's) self-signed certificate by its SHA-256 in
place of a chain and a name (`certpin.Pinned`: Go's `VerifyPeerCertificate` under
`InsecureSkipVerify`), during the handshake: a certificate that does not match fails it. akio-tls's
client verified the chain and the name against roots, or nothing at all (`insecure_skip_verify`,
which still checks the server's handshake signature with the leaf's key). akit therefore let the
handshake complete under `insecure_skip_verify`, polled `tls_info` from a timer until it had, and
compared the leaf with the pin before starting the link: sound, since the signature proves the key,
but a poll, and the handshake succeeded where it should have failed.

## Decision

1. **`ClientConfigBuilder::pin_sha256(Vec<[u8; 32]>)`**: the SHA-256 of the server's leaf
   certificate (its DER) must be one of the pins. The digest is compared with every pin in constant
   time (`akio_crypto::ct_eq`, no early exit over the list), so the time taken does not tell how
   close a certificate came to a pin, nor which pin matched.
2. **The pin replaces chain, name and date checks**, as Go's `VerifyPeerCertificate` with
   `InsecureSkipVerify` does: neither the roots nor the server name (still sent as SNI) nor the
   validity period is looked at, and OCSP and CRL policies are not applied. A mismatch fails the
   handshake with `bad_certificate`. It also overrides `insecure_skip_verify`: a configuration with
   both checks the pin.
3. **The leaf's key still signs the handshake.** The leaf is parsed as for `insecure_skip_verify`
   (its key usage must allow signing), and its key verifies CertificateVerify (TLS 1.3) or the
   ServerKeyExchange (TLS 1.2), so a server that has the certificate but not its key fails
   (`decrypt_error`).
4. **One place in the client state machine**, where the server's Certificate is taken for TLS 1.3
   and 1.2; QUIC's client runs the same machine, so `akio_quic::client_config_from` of a pinned
   configuration is pinned too. The HTTP, HTTP/2, WebSocket and gRPC clients take the same
   `ClientConfig`.
5. **An empty list is an error** at `build`, rather than a configuration that accepts nothing or
   everything.

## Consequences

- akit's tunnel TLS and QUIC links and the LLM mesh's `wss://` links give their pin to the client
  configuration and start the link at once; its `when_handshaken` poll goes.
- Cost: one SHA-256 of the leaf per full handshake of a pinned configuration; nothing otherwise.
  Resumed sessions are not checked again (their tickets come from a pinned handshake of the same
  configuration, whose session cache is its own).
- Tests: akio-tls `pinned_server_certificate` (TLS 1.3 and 1.2: no roots and any name, one of
  several pins, an expired certificate, a mismatch even with `insecure_skip_verify` and with roots
  that would accept it, an empty list refused) and `pinned_certificate_without_its_key_fails` (the
  pinned certificate spliced into another server's TLS 1.2 flight: the pin matches, the signature
  does not); akio `tests/tls.rs` over the engine and akio-quic `tests/echo.rs` over QUIC.
- Not done: TURN over DTLS (akio-webrtc's relay client) builds its DTLS verifier from the roots and
  ignores pins, so a pinned configuration there verifies against its roots (and fails without
  any).
