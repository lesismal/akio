# ADR-174: An HTTP server of HTTP/2 alone

English | [简体中文](174-http2-alone.zh-CN.md)

Status: accepted (2026-11-26). akit's A168.

## Context

akio-http's server takes HTTP/2 from a connection that starts with the client preface (prior
knowledge, or TLS with ALPN `h2`) or an `Upgrade: h2c` request, and HTTP/1 from anything else.
`HttpConfig::h2: None` turns HTTP/2 off, but nothing turned HTTP/1 off. fit's listener with
`protocols: [h2c]` serves HTTP/2 with prior knowledge and nothing else (fib's mux matches the
preface alone and closes the rest), as gRPC listeners and fit's benchmark config's h2c port do.

## Decision

1. **`HttpConfig::http1: bool`**, default `true`. With `false`, a connection whose first bytes
   leave the client preface gets a `GOAWAY` with `PROTOCOL_ERROR` (as a client that meant HTTP/2
   and got the preface wrong already did) and is closed, as soon as a byte differs; no HTTP/1
   request is read, so no `Upgrade: h2c` either. A preface split over reads still starts HTTP/2.
2. With `h2: None` too, nothing is served: every connection is closed at its first data.

## Consequences

- A listener can serve h2c alone, as fit's `[h2c]`, with the same answer for an HTTP/1 client.
- On TLS, a client that negotiated `http/1.1` gets the `GOAWAY` too; a TLS listener of HTTP/2
  alone should offer `h2` alone in ALPN.
