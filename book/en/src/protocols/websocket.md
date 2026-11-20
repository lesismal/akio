# WebSocket

`only-ws` implements RFC 6455 with `permessage-deflate` (RFC 7692). The server side is reached
through a only-http upgrade (HTTP/1.1, or an extended CONNECT on HTTP/3); the client dials `ws://` and `wss://` URLs. Both use the same
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
| `close(code, reason)` | start the close handshake (`only_ws::protocol::close::NORMAL`, ...) |
| `subprotocol()`, `is_open()` | negotiated subprotocol, state |

## Server

```rust,ignore
{{#include ../../../../crates/only-ws/examples/guide-ws.rs:server}}
```

`ctx.upgrade_websocket(handler, &WsOptions)` validates the handshake (GET, HTTP/1.1,
`Upgrade`/`Connection` tokens, version 13, key, origin policy), answers `101 Switching
Protocols` and switches the connection; `on_open` runs right away. On a bad handshake it answers
400, 403 or 426 itself, returns `false`, and the connection stays HTTP. Do not pipeline requests
behind an upgrade request. On HTTP/2 (RFC 8441) and HTTP/3 (RFC 9220) the same call accepts an
extended CONNECT and answers `200`; the request's stream then carries the WebSocket, next to
the connection's other requests. See [WebSocket over HTTP/2](#websocket-over-http2) and
[WebSocket over HTTP/3](quic-h3.md#websocket-over-http3).

`WsOptions`:

- `config: WsConfig`: `max_message_bytes` (16 MiB, after decompression; larger closes with
  1009; the compressed bytes of a message are bounded too, at the limit plus an eighth, so a
  peer cannot fragment a compressed message forever), `permessage_deflate` (true: accepted when the client offers it), `compress_min_bytes`
  (128).
- `protocols`: subprotocols the server speaks; the client's first choice among them is selected.
- `origin_allowed: Option<fn(&str) -> bool>`: requests with an `Origin` header are refused (403)
  unless it returns true. Requests without `Origin` (non-browser clients) are not affected.

Because the upgrade is an ordinary route, everything in front of it (middleware for
authentication, rate limiting, logging) applies to the handshake request.

## Client

```rust,ignore
{{#include ../../../../crates/only-ws/examples/guide-ws.rs:client}}
```

```rust,ignore
{{#include ../../../../crates/only-ws/examples/guide-ws.rs:dial}}
```

- `client::dial_blocking(&engine, url, &opts, handler)` blocks until the handshake completes and
  returns the `WsSender`; do not call it on an I/O thread of the same engine.
- `client::dial(&engine, url, &opts, handler, on_error)` is the non-blocking form: `on_open`
  runs on success, `on_error(WsClientError)` once on failure (`InvalidUrl`, `Io`, `Status`,
  `Handshake`, `Timeout`, `Closed`, `TooManyRedirects`).
- `DialOptions`: `config` (limits; `permessage_deflate` decides whether it is offered), `pmd`
  (what the offer asks for), `protocols`, `origin`, `headers` (e.g. `Authorization`, cookies),
  `tls` (`None`: the system's CAs; do not offer `h2` in its ALPN), `server_name`,
  `handshake_timeout` (10 s, redirects included), `close_timeout` (3 s), `proxy` (none;
  `only_ws::proxy::Proxy::from_env()` opts in to the environment) and `max_redirects` (0).
- Proxies: every connection a proxy applies to (`ws://` and `wss://`) goes through a
  `CONNECT host:port` tunnel, or a SOCKS tunnel for `socks5://` / `socks5h://` / `socks4://` /
  `socks4a://` proxies; a refusal is `WsClientError::Io` carrying a
  `only_ws::proxy::ProxyRefused`. Same `Proxy` type and rules as the
  [HTTP client](http-clients.md#proxies).
- Redirects (`max_redirects > 0`): 301, 302, 303, 307 and 308 with a `Location`; `http`/`https`
  locations become `ws`/`wss`; `wss://` never goes to `ws://`; another origin drops
  `Authorization`, `Cookie` and `Proxy-Authorization` from `headers`. Browsers do not follow
  WebSocket redirects, hence off by default.
- When the client's engine shuts down gracefully, open connections are closed with 1001 (going
  away) and the close handshake.
- Frames are masked with unpredictable keys; every resolved address is tried in turn; names are
  resolved off the calling thread (`only::dns`).

Run `cargo run -p only-ws --example guide-ws` for a chat room with two clients, and see
`crates/only-http/examples/ws-chat.rs` for a browser chat.

## WebSocket over HTTP/2

The HTTP/2 server advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`, so browsers that hold an h2
connection to the origin open their WebSockets on it. The route is the same `.get("/ws", ...)`:
`Router` answers an extended CONNECT for `websocket` with the path's GET route, and
`ctx.req().protocol` is `Some("websocket")`. `H2Config::enable_connect_protocol = false` turns
it off.

`H2Client::websocket(url, &H2WsOptions, handler, done)` (or `websocket_blocking`) opens one on an
`H2Client` connection (see [HTTP clients](http-clients.md#http2-h2clienth2client)); `done` gets
the `WsSender`, or `ClientError::Status` when the server refused. `H2WsOptions` has the fields of
`DialOptions` that apply (`config`, `pmd`, `protocols`, `origin`, `headers`, `close_timeout`),
`timeout` (10 s) and `max_queued_bytes` (8 MiB).

Each WebSocket is one stream: the stream's and the connection's windows pace it. Sends fail with
`Overloaded` once `H2Config::max_pending_bytes` (server) or `H2WsOptions::max_queued_bytes`
(client) are queued for a peer that does not open its window; `WsSender::queued_bytes` tells a
producer when to wait. A close frame ends our half of the stream, `RST_STREAM` or a lost
connection reach `on_close` as 1006, and graceful shutdown closes with 1001.

## Not done

Client: TLS to the proxy, cookies across redirects; `client::dial` stays HTTP/1.1 (WebSocket over
HTTP/2 needs an `H2Client`).
