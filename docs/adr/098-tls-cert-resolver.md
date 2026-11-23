# ADR-098: Server certificates chosen per handshake by a resolver that may answer later

English | [简体中文](098-tls-cert-resolver.zh-CN.md)

Status: accepted (2026-11-23)

## Context

`ServerConfigBuilder` fixes the server's certificates when the configuration is built: a default
chain and the chains of `sni_cert`. akit (the gateway built on akio, akit
`docs/akio-api-requests.md` item A2) needs two more things, as fit gets them from Go's
`tls.Config.GetCertificate`:

1. **Certificates replaced while serving.** Automatic HTTPS renews certificates every 60 days or
   so; rebuilding the server configuration for that drops its session cache and ticket keys and
   has to be pushed to every listener.
2. **On-demand TLS.** A ClientHello for a name with no certificate yet triggers an ACME order;
   the handshake waits seconds for it. Rule 1 forbids waiting on the I/O thread.

ADR-062 already suspends a server handshake without holding the thread: the asynchronous
anti-replay store. The ClientHello is kept, nothing is sent, and when the answer lands (from any
thread) a waker posts a task to the connection's I/O thread (`TransportWaker`, TCP) or drives
the QUIC connection, which handles the same ClientHello again from the start with the answer.

## Decision

1. **A resolver on the server configuration.**

   ```rust
   pub trait CertResolver: Send + Sync {
       fn resolve(&self, hello: &ClientHelloInfo<'_>, done: CertDone);
   }
   impl ServerConfigBuilder { pub fn cert_resolver(self, r: Arc<dyn CertResolver>) -> Self; }
   impl ServerConfig { pub fn builder_with_resolver(r: Arc<dyn CertResolver>) -> ServerConfigBuilder; }
   ```

   `ClientHelloInfo` gives the SNI name (lowercase), the offered ALPN protocols, signature
   schemes and cipher suites, and the version being negotiated (and whether it is QUIC). `CertDone`
   is `Send`; it is answered once, from any thread, with:

   - `complete(CertifiedKey)`: serve this chain;
   - `use_default()`: what the configuration would serve without a resolver (the `sni_cert`
     chain for the name, else the default chain; `unrecognized_name` when the configuration
     was built with `builder_with_resolver` and has none);
   - `fail(CertAlert)`: abort with `handshake_failure`, `unrecognized_name`, `access_denied` or
     `internal_error`.

   Dropping it unanswered is `internal_error`. `CertDone::is_abandoned()` says the handshake is
   gone (closed, timed out), for a resolver that wants to skip work nobody waits for.
2. **`CertifiedKey`** is a chain and its key, checked to match once (`CertifiedKey::new`), with
   an optional stapled OCSP response; it is cheap to clone (shared), and keeps the compressed
   certificate messages it computed (RFC 8879) across the handshakes that use it.
3. **The synchronous fast path is an answer inside `resolve`.** A resolver that has the
   certificate in memory answers before returning: the handshake goes on in the same call,
   nothing suspends and nothing is woken. `CertStore` is such a resolver, ready-made: names
   (exact, or `*.example.com` for one label) to `CertifiedKey`, replaced at any time with
   `insert` / `remove` / `set_default` from any thread (a read lock and an `Arc` clone per full
   handshake). akit renews by `insert`ing the new key; on-demand issuance wraps a `CertStore`,
   answering hits inline and misses from its ACME task (the book's TLS chapter has the sketch).
4. **Suspension as in ADR-062.** The resolver is called for full handshakes only, once the
   ClientHello has been checked and the version, suite candidates and PSK are settled: a
   resumed handshake (TLS 1.3 PSK, TLS 1.2 ticket or session id) sends no certificate and does
   not call it; with a HelloRetryRequest it is called for the second ClientHello. If the answer is
   not in when `resolve` returns, the handshake keeps the ClientHello and returns having sent
   nothing; the answer wakes the connection, and the same ClientHello is handled again with
   the certificate given (the PSK lookup is not repeated: it found nothing). Bytes arriving
   meanwhile wait under ADR-062's bound. The same code serves `Tls::server` over the engine,
   the blocking test stream and QUIC (`QuicTls`, which akio-quic already wakes and resumes:
   it drives the connection from the answering thread, holding it by a weak reference).
5. **Timeout.** `ServerConfigBuilder::cert_resolver_timeout` (10 s by default, at least 1 ms):
   no answer in time fails the handshake with `internal_error`. It shares ADR-062's timer thread
   (generalised from anti-replay answers to any suspended answer). The handshake timeout (10 s,
   TCP) or QUIC's idle timeout still bounds the whole handshake: on-demand issuance raises both.
6. **A bound on waiting handshakes.** `ServerConfigBuilder::max_pending_cert_resolutions` (1024
   by default per configuration; at least 1). A handshake counts from the moment `resolve`
   returns unanswered until it is taken up again or dropped. At the bound the resolver is still
   called, so certificates it has in memory keep being served during a burst of issuance; a
   handshake it does not answer inside the call fails with `internal_error` instead of waiting,
   its `CertDone` abandoned.
7. **The static path does not change.** Without a resolver the certificate is picked as before
   (one `Option` check per full handshake). The A/B below measures it.

## Consequences

- `ServerConfig` without a default certificate exists (`builder_with_resolver`). The DTLS
  configuration of akio-turn, which takes the default chain, refuses such a configuration with
  an error.
- A resolver sees the ClientHello before any authentication: it must not do unbounded work per
  name (on-demand issuance needs an allow-list or rate limit, which is akit's job).
- Not done: choosing the certificate from the client's certificate_authorities or
  signature_algorithms_cert (the information is there, the matching is the resolver's), and
  certificates for client authentication chosen per handshake on the client side.

## Verification

Unit tests in akio-tls (`proto/resolver_tests.rs`): inline and later answers, from another thread,
TLS 1.2 and 1.3, HelloRetryRequest, resumption skipping the resolver, `use_default` with and without a
default, alerts, a dropped `CertDone`, the timeout, the pending bound, the connection dropped
while waiting, QUIC, `CertStore` (wildcards, replacement). Engine tests in akio
(`tests/tls.rs`): a resolver answering from another thread over the engine on every backend,
with a stock client (rustls), and the connection closed while waiting; in akio-quic
(`tests/zero_rtt.rs`), the same over QUIC. Static-certificate handshake A/B on the quiet host
(10 alternating rounds, medians): X25519 +0.5%, secp256r1 −0.1%, RSA-2048 +0.1%, within noise.
