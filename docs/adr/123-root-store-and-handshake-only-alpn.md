# ADR-123: Root certificates outside a handshake, and ALPN protocols for the handshake only

English | [简体中文](123-root-store-and-handshake-only-alpn.zh-CN.md)

Status: accepted (2026-11-25)

## Context

akit (the gateway built on akio) asked for two things of akio-tls (`akit/docs/akio-api-requests.md`):

- **A57.** fit staples the OCSP response of a certificate from files only when its chain
  verifies against the system's roots, so that a certificate someone else gave (a tenant's
  Kubernetes Secret) does not have the gateway ask a responder it names. akit verifies chains
  with akio-x509's `Verifier`, which takes a `RootStore`; `RootCerts::system()` loads the
  system's roots (ADR-010, ADR-059) but kept its store private, usable by a handshake alone.
- **A58.** A listener that obtains certificates through TLS-ALPN-01 (RFC 8737) offers
  `acme-tls/1` in ALPN. A connection that negotiates it is for the handshake only: the CA reads
  the challenge's certificate and goes. fit closes it once the handshake is done; akio-http,
  which tells HTTP/2 by its preface and gives a service nothing of the TLS connection, served an
  HTTP/1 request sent on it.

## Decision

- **`RootCerts::store(&self) -> &akio_x509::RootStore`** and **`From<RootCerts> for
  RootStore`**: the roots for a `Verifier` of the caller's own, the system's included.
- **`ServerConfigBuilder::handshake_only_alpn(protocols)`**: a connection of `Tls::server` that
  negotiates one of these protocols is closed once its handshake completes. The transport
  checks the negotiated protocol after every `recv` (it is chosen with the ClientHello): the
  application bytes it decoded are dropped, so nothing reaches the handler (TLS 1.3 early data
  included), and once the handshake is done it appends a `close_notify` to its output and fails
  with `ErrorKind::ConnectionAborted`, which the engine sends before closing (the `Transport`
  contract). The handshake counts as completed. Default: none.

The ALPN choice is a TLS setting rather than an akio-http one (`Context::tls()` or an
`HttpConfig` field, the request's other suggestions): it closes a connection that sends nothing
after the handshake, as a CA's does, which a service only hears of when bytes arrive, and it
costs a request nothing (akio-http's `size_tests` budget stays as it was).

## Consequences

- akit's OCSP stapler verifies a certificate from files against `RootCerts::system()`'s store,
  on its own thread, as fit does; akit's listeners with TLS-ALPN-01 or on-demand TLS list
  `acme-tls/1` as handshake-only.
- Tests: `config_tests::roots_verify_a_chain_outside_a_handshake` (a chain verified against a
  store of one root, owned and borrowed, and not against the system's);
  `akio-http/tests/tls_handshake_only.rs` (a client negotiating `acme-tls/1` is closed after its
  handshake, whether it sends a request or nothing, and the request is never served; one
  negotiating `http/1.1` on the same listener is served), on epoll and io_uring.
