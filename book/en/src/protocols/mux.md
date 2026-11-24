# Protocol multiplexing

`akio-mux` serves several protocols on one listening port, telling them apart by the first
bytes each client sends.

```rust,ignore
{{#include ../../../../crates/akio-mux/examples/guide-mux.rs:mux}}
```

Rules, tried in the order the routes were added (a match waits while an earlier route is still
undecided, so an SNI route placed before `Tls` sees the whole hello):

| `Rule` | Matches |
|---|---|
| `Tls` | a TLS ClientHello (`0x16 0x03 ..`) |
| `TlsSni(SniMatcher)` | a complete ClientHello whose server name matches (exact or `*.` one-label wildcard) |
| `TlsHello(Arc<dyn Fn(&ClientHello) -> bool>)` | a complete ClientHello your function accepts (server name, ALPN) |
| `Http1` | an HTTP/1.x request line starting with a known method |
| `Http2` | the HTTP/2 connection preface (cleartext prior knowledge) |
| `Http` | either of the two above: what akio-http serves |
| `Socks5`, `Socks4` | SOCKS version 5 / 4 and 4a |
| `Prefix(bytes)` | data starting with these bytes |
| `Custom(Arc<dyn Fn(&[u8]) -> Decision>)` | your test: `Yes`, `No` or `NeedMore` |

`fallback(acceptor)` takes connections that match nothing, or that decide nothing within
`max_sniff_bytes(n)` bytes (default 64); without a fallback they are closed. Serve the mux with
`Listener::serve_any(mux)` (a `Mux` converts into a type-erased `akio::AnyAcceptor`). Configure it completely before serving it.

`sniff_timeout(Some(d))` (default 5 s) bounds how long a client may take to send enough bytes
for a decision: a silent client, or one trickling a prefix several rules share, is closed at the
deadline (not handed to the fallback). `sniff_timeout(None)` waits forever.

Once a rule matches, the connection belongs to that route's acceptor as if it had accepted it:
the sniffed bytes are replayed to its handler, `spawn_blocking` completions reach it, and
graceful shutdown calls *its* `on_shutdown`. A route can be a `Tls::server(..)` acceptor (TLS
then terminates after sniffing) or another `Mux` (`route_any`).

## TLS passthrough by server name

`TlsSni` and `TlsHello` read the ClientHello without terminating TLS: the route gets the hello's
bytes untouched and can relay them to an upstream. The hello may arrive in several reads and
several TLS records; a mux with one of these routes sniffs up to `TLS_SNIFF_BYTES` (16 KiB + 5)
unless `max_sniff_bytes` says otherwise, still within `sniff_timeout`. A malformed hello or one
without a server name does not match `TlsSni`; put `Rule::Tls` after the SNI routes to catch the
rest. `akio_mux::tls::parse_client_hello` is the parser, for use elsewhere.

```rust,ignore
let mux = Mux::new()
    .route(Rule::TlsSni(SniMatcher::new(["api.example.com", "*.apps.example.com"])), relay_a)
    .route(Rule::TlsHello(Arc::new(|h: &ClientHello| h.offers_alpn(b"h2"))), relay_h2)
    .route(Rule::Tls, Tls::server(cfg, app))
    .fallback(other);
```

## PROXY protocol

Behind a load balancer, wrap the listener's acceptor in `akio_mux::proxy::ProxyProtocol`: it reads
a v1 or v2 header (TLVs, LOCAL, IPv4 / IPv6 / Unix) before the next acceptor runs, then hands the
connection on with the bytes after the header. A malformed header, one longer than
`max_header_bytes` (4096) or one not complete within `header_timeout` (5 s) closes the
connection. `allow_missing(true)` lets connections without a header through; `trusted(f)` reads
headers only from the load balancers' addresses.

```rust,ignore
let pp = ProxyProtocol::new_any(mux).trusted(|peer| peer.ip().is_loopback());
// in a handler:
let client = akio_mux::proxy::client_addr(&conn); // the header's source, else peer_addr
let tlvs = akio_mux::proxy::header(&conn).map(|h| h.tlvs.clone());
```

`Conn::peer_addr` stays the socket's peer. To send a header on an outgoing connection, build a
`ProxyHeader::proxy(source, destination)` and call `proxy::send_header(&conn, &h, Version::V2)`
first thing in the dialing handler's `on_open`.

Protocols where the **server speaks first** (SMTP, MySQL, SSH banners...) cannot be detected this
way; give them their own port.
