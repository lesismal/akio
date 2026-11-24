# ADR-117: The HTTP/1 client's TLS server name, and a client certificate's key checked when built

English | [简体中文](117-client-tls-server-name-and-client-key-check.zh-CN.md)

Status: accepted (2026-11-24)

## Context

akit's iteration I54 brings fit's upstream TLS fields: `tls_server_name` (the name the upstream's
certificates are checked against, and sent in SNI, in place of each address's host),
`tls_ca_file` and a client certificate (`tls_cert_file`, `tls_key_file`). An `h2` upstream is
dialled by akio-http's `H2Client`, which already takes the TLS name apart from the host it
connects to; but a server that chooses HTTP/1.1 in ALPN, and the health probes of such an
address, go through akio-http's `Client`, and akit asked for two things (A108, A109), checked
against akio main `c5cf4353`:

- **A108.** `Client` dialled `https://` with `Tls::client(cfg, &key.host, ...)`: the name was
  always the URL's host. An upstream reached at `10.0.0.5:443` whose certificate names
  `app.internal` could not be verified, and the URL cannot carry the name instead, since the
  connection goes to the URL's host (`crates/akio-http/src/client.rs`, `Client::dial`).
- **A109.** `ClientConfigBuilder::build` parsed a client certificate's key but did not check it
  against the leaf, as `ServerConfigBuilder::build` does: a certificate and key that do not belong
  together built a configuration that failed every handshake that asked for the certificate,
  later and further from the cause. fit (Go's `tls.LoadX509KeyPair`) reports the mismatch when the
  files are loaded (`crates/akio-tls/src/config.rs`).

Constraints: no unsafe, additive API, nothing on the hot path.

## Decision

- **A108: `Client::with_tls_server_name(name)`.** Every `https://` connection the client makes
  sends `name` in SNI and verifies the server's certificate against it, in place of the URL's
  host. Connections are still pooled by the URL's host and port (the name is the client's, the
  same for all of them). An empty name restores the URL's host. TLS to an `https://` proxy keeps
  the proxy's own name.
- **A109: the client certificate's key is checked.** `ClientConfigBuilder::build` checks the
  client chain with the server side's `certified_key`: a non-empty chain whose leaf parses and
  carries the key's public key; otherwise `client certificate: private key does not match the
  certificate`.

Rejected:

- **A server name in `akio_tls::ClientConfig`**, overriding the name every connection is made
  with: `H2Client::connect` and `Tls::client` already take the name as an argument, and a second
  source of the same value would make which one wins a question every caller has to know.
- **Checking the key in akit** by building a throwaway `ServerConfig` from the client's chain: it
  works, but every user of a client certificate would have to know to do it.

## Consequences

- akit's I54 verifies an upstream by `tls_server_name` over HTTP/2 (`H2Client`) and HTTP/1.1
  (`Client`) alike, its probes included, and reports a client certificate whose key does not
  match when the config is compiled.
- Costs: `Settings` gains an `Option<String>`, read once per TLS dial. A client chain whose leaf
  akio-x509 cannot parse is now refused when built; before, it failed in the handshake.
- Tests: `akio-http/tests/client.rs` `https_with_a_tls_server_name` (verified under the name, not
  without it or under another, reused by host and port, an empty name restoring the URL's host),
  on epoll and io_uring; `akio-tls` `config_tests` `bad_keys_and_errors_are_reported` (a client
  key not the leaf's, an empty client chain).
