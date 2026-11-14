# Protocol multiplexing

`only-mux` serves several protocols on one listening port, telling them apart by the first
bytes each client sends.

```rust,ignore
{{#include ../../../../crates/only-mux/examples/guide-mux.rs:mux}}
```

Rules, tried in the order the routes were added:

| `Rule` | Matches |
|---|---|
| `Tls` | a TLS ClientHello (`0x16 0x03 ..`) |
| `Http1` | an HTTP/1.x request line starting with a known method |
| `Http2` | the HTTP/2 connection preface (cleartext prior knowledge) |
| `Http` | either of the two above: what only-http serves |
| `Socks5`, `Socks4` | SOCKS version 5 / 4 and 4a |
| `Prefix(bytes)` | data starting with these bytes |
| `Custom(Arc<dyn Fn(&[u8]) -> Decision>)` | your test: `Yes`, `No` or `NeedMore` |

`fallback(acceptor)` takes connections that match nothing, or that decide nothing within
`max_sniff_bytes(n)` bytes (default 64); without a fallback they are closed. Serve the mux with
`Listener::serve_any(mux)` (a `Mux` converts into a type-erased `only::AnyAcceptor`). Configure it completely before serving it.

Once a rule matches, the connection belongs to that route's acceptor as if it had accepted it:
the sniffed bytes are replayed to its handler, `spawn_blocking` completions reach it, and
graceful shutdown calls *its* `on_shutdown`. A route can be a `Tls::server(..)` acceptor (TLS
then terminates after sniffing) or another `Mux` (`route_any`).

Protocols where the **server speaks first** (SMTP, MySQL, SSH banners...) cannot be detected this
way; give them their own port.
