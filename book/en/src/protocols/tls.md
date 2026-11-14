# TLS

`only::tls` (the `only-tls` crate) runs [rustls](https://docs.rs/rustls) sans-io as a
**transport layer** under the connection. Wrap any acceptor and its handlers see plaintext:
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

## Configuration

Configuration uses `only`'s own types; the TLS implementation underneath (rustls, with the
`ring` crypto provider compiled in) is not part of the API, so upgrading it is not a breaking
change. `Certificate::from_pem` / `from_der`, `PrivateKey::from_pem` / `from_der` /
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

`.build()` checks the certificates and key and returns the config or a `only::tls::Error`;
configs are cheap to clone. For settings these builders do not cover, the `unstable` cargo
feature re-exports `only::tls::rustls` and adds `ServerConfig::from_rustls` /
`ClientConfig::from_rustls` (and `as_rustls`); that feature is outside the semver promise.

## With other crates

- only-http: `Tls::server(cfg, serve(app))`. With `alpn_protocols = [h2, http/1.1]` the same
  listener serves HTTP/2 to clients that negotiate `h2`.
- only-ws client: `DialOptions::tls` for `wss://`.
- only-http clients: `Client::with_tls(cfg)`, `H2Client::dial(.., Some((cfg, name)), ..)`.
- QUIC and HTTP/3 use TLS 1.3 inside QUIC: see `only_quic::server_config` and
  `server_config_from(&tls_config)`.

## Not done

kTLS offload; TLS 1.3 early data over TCP; system root certificates (load them into
`RootCerts`).

## Writing your own transport

`only_core::Transport` is the trait TLS implements: `recv(cipher, plain, out)`, `seal(plain,
out)`, `shutdown(out)`, plus `name` and `handshaking`. Return one from `Acceptor::transport` to
layer any byte-stream transformation under a connection. All calls happen under the connection's
write lock, in wire order, and must not block.
