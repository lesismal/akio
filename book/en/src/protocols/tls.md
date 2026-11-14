# TLS

`flash::tls` (the `flash-tls` crate) runs [rustls](https://docs.rs/rustls) sans-io as a
**transport layer** under the connection. Wrap any acceptor and its handlers see plaintext:
`on_data` receives decrypted bytes, `Conn::send*` encrypts.

## Server

```rust,ignore
{{#include ../../../../crates/flash/examples/guide-tls.rs:server}}
```

## Client

```rust,ignore
{{#include ../../../../crates/flash/examples/guide-tls.rs:client}}
```

`Tls::client(config, server_name, acceptor)` verifies the server as `server_name` and sends it as
SNI. It returns an error for a name that is not a valid DNS name or IP address.

Run both with `cargo run -p flash --example guide-tls`.

## How it works

- The handshake runs on the connection's I/O thread, interleaved with other connections, and
  never blocks.
- Bytes you send before the handshake completes (for example from `on_open`) are held back and
  flushed as soon as it does.
- `close_after_send()` sends `close_notify` after the queued data.
- A failed handshake or a bad record closes the connection after flushing the alert; failures
  are counted separately for the handshake (`flash_tls_handshake_failures_total`) and afterwards
  (`flash_transport_errors_total`).
- Records are sealed in pieces of at most one TLS record, so large sends are fine.
- The connection table shows `transport: "tls"`.

## What it negotiated

`tls_info(&conn)` returns a `TlsInfo` with `handshaking`, `alpn`, `server_name` (SNI, server
side) and `version`, or `None` for a non-TLS connection.

## Configuration

Everything is configured through rustls's own `ServerConfig` / `ClientConfig`, re-exported as
`flash::tls::rustls`:

| Need | rustls setting |
|---|---|
| certificate chain and key | `with_single_cert(chain, key)` |
| several certificates by SNI | `with_cert_resolver(..)` (`ResolvesServerCert`) |
| ALPN (`h2`, `http/1.1`, custom) | `config.alpn_protocols` |
| session resumption | `config.ticketer`, `config.session_storage` |
| client certificates | `with_client_cert_verifier(..)` / `with_client_auth_cert(..)` |
| protocol versions | `builder_with_protocol_versions(..)` |

The `ring` crypto provider is compiled in. Loading PEM files is left to you (for example with
`rustls-pemfile` or `rustls::pki_types::pem`).

## With other crates

- flash-http: `Tls::server(cfg, serve(app))`. With `alpn_protocols = [h2, http/1.1]` the same
  listener serves HTTP/2 to clients that negotiate `h2`.
- flash-ws client: `DialOptions::tls` for `wss://`.
- flash-http clients: `Client::with_tls(cfg)`, `H2Client::connect(.., Some((cfg, name)), ..)`.
- QUIC and HTTP/3 use TLS 1.3 inside QUIC: see `flash_quic::server_config` and friends.

## Not done

kTLS offload; TLS 1.3 early data and client-certificate helpers beyond what rustls offers
directly.

## Writing your own transport

`flash_core::Transport` is the trait TLS implements: `recv(cipher, plain, out)`, `seal(plain,
out)`, `shutdown(out)`, plus `name` and `handshaking`. Return one from `Acceptor::transport` to
layer any byte-stream transformation under a connection. All calls happen under the connection's
write lock, in wire order, and must not block.
