# WebSocket

`flash-ws` implements RFC 6455 with `permessage-deflate` (RFC 7692). The server side is reached
through a flash-http upgrade; the client dials `ws://` and `wss://` URLs. Both use the same
handler trait. Conformance: Autobahn|Testsuite server 298 OK + 3 informational (core) and 216/216
(permessage-deflate); client 514 OK + 3 informational of 517; run in CI by
`tools/autobahn/run.sh`.

## The handler

```rust,ignore
pub trait WsHandler: Send + 'static {
    fn on_open(&mut self, ws: &WsSender) {}
    fn on_message(&mut self, ws: &WsSender, msg: Message);   // Message::Text(String) | Binary(Vec<u8>)
    fn on_pong(&mut self, ws: &WsSender, payload: &[u8]) {}
    fn on_close(&mut self, code: Option<u16>, reason: &str) {}
}
```

Callbacks run on the connection's I/O thread, receive complete (reassembled, decompressed,
UTF-8-validated) messages and must not block. `on_close` runs exactly once with the peer's close
code, the code this side closed with after a protocol error, or 1006 when the transport dropped
without a close handshake.

`WsSender` is `Clone + Send + Sync`: keep clones to send from other threads (frames from
different threads never interleave):

| Method | Effect |
|---|---|
| `send_text`, `send_binary` | one message (compressed when negotiated and at least `compress_min_bytes`) |
| `send_text_fragmented`, `send_binary_fragmented` | split into frames of a given size |
| `send_prepared(&PreparedMessage)` | a message encoded once for many connections (sent uncompressed) |
| `ping`, `pong` | control frames |
| `close(code, reason)` | start the close handshake (`flash_ws::protocol::close::NORMAL`, ...) |
| `subprotocol()`, `is_open()` | negotiated subprotocol, state |

## Server

```rust,ignore
{{#include ../../../../crates/flash-ws/examples/guide-ws.rs:server}}
```

`ctx.upgrade_websocket(handler, &WsOptions)` validates the handshake (GET, HTTP/1.1,
`Upgrade`/`Connection` tokens, version 13, key, origin policy), answers `101 Switching
Protocols` and switches the connection; `on_open` runs right away. On a bad handshake it answers
400, 403 or 426 itself, returns `false`, and the connection stays HTTP. Do not pipeline requests
behind an upgrade request.

`WsOptions`:

- `config: WsConfig`: `max_message_bytes` (16 MiB, after decompression; larger closes with
  1009), `permessage_deflate` (true: accepted when the client offers it), `compress_min_bytes`
  (128).
- `protocols`: subprotocols the server speaks; the client's first choice among them is selected.
- `origin_allowed: Option<fn(&str) -> bool>`: requests with an `Origin` header are refused (403)
  unless it returns true. Requests without `Origin` (non-browser clients) are not affected.

Because the upgrade is an ordinary route, everything in front of it (middleware for
authentication, rate limiting, logging) applies to the handshake request.

## Client

```rust,ignore
{{#include ../../../../crates/flash-ws/examples/guide-ws.rs:client}}
```

```rust,ignore
{{#include ../../../../crates/flash-ws/examples/guide-ws.rs:dial}}
```

- `client::dial_blocking(&engine, url, &opts, handler)` blocks until the handshake completes and
  returns the `WsSender`; do not call it on an I/O thread of the same engine.
- `client::dial(&engine, url, &opts, handler, on_error)` is the non-blocking form: `on_open`
  runs on success, `on_error(WsClientError)` once on failure (`InvalidUrl`, `Io`, `Status`,
  `Handshake`, `Timeout`, `Closed`).
- `DialOptions`: `config` (limits; `permessage_deflate` decides whether it is offered), `pmd`
  (what the offer asks for), `protocols`, `origin`, `headers` (e.g. `Authorization`, cookies),
  `tls` (required for `wss://`; do not offer `h2` in its ALPN), `server_name`,
  `handshake_timeout` (10 s), `close_timeout` (3 s).
- Frames are masked with unpredictable keys; every resolved address is tried in turn; name
  resolution runs on the calling thread.

Run `cargo run -p flash-ws --example guide-ws` for a chat room with two clients, and see
`crates/flash-http/examples/ws-chat.rs` for a browser chat.

## Not done

Client: system root certificates (supply a rustls config), proxies, redirects, sending 1001 on
engine shutdown (connections currently end with 1006). Server: WebSocket over HTTP/2 or HTTP/3
(extended CONNECT).
