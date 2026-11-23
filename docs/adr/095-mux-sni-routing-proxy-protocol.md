# ADR-095: TLS routing by SNI without terminating it, and the PROXY protocol (akio-mux)

English | [简体中文](095-mux-sni-routing-proxy-protocol.zh-CN.md)

Status: accepted (2026-11-23)

## Context

akit (the gateway built on akio, the counterpart of fit) asked for two listener-side features
(`akit/docs/akio-api-requests.md`, A4 and A5):

- **A5, TLS passthrough.** A layer 4 route picks an upstream by the server name of the TLS
  ClientHello and relays the encrypted bytes, without terminating TLS. `akio-mux` had `Rule::Tls`,
  which matches any ClientHello by its first two bytes; nothing read the server name, and the
  default sniff limit (64 bytes) is far below a real ClientHello (300 bytes to 2 KiB, more with
  post-quantum key shares; clients may split it over several reads and several TLS records).
- **A4, PROXY protocol.** Behind a load balancer (HAProxy, AWS NLB, nginx `proxy_protocol`) the
  client address comes from a PROXY header (v1 text or v2 binary) sent before the first byte of
  the protocol; an upstream may want one written before akit's own bytes.

Both features read a bounded prefix of the connection before any protocol handler exists, then
hand the connection on. That is what `akio-mux` already does: it buffers the first bytes under a
byte limit and a deadline (one watchdog thread per process, ADR-009 rule 9), and replays them to
the acceptor it picks, which then owns the connection (`spawn_blocking` completions, graceful
shutdown). A parallel change (ADR-094) adds runtime listeners and an accept filter to the engine;
these features stay acceptor-level layers and touch neither the engine nor the backends.

## Decision

### 1. Both live in akio-mux

No new crate: the PROXY layer needs exactly the machinery of `Mux` (buffer, byte limit, sniff
deadline, replay, `chosen` acceptor for `on_shutdown`), and akio-mux has no dependency beyond
akio-core. Each layer is a `DynAcceptor`, so they compose by nesting:
`ProxyProtocol::new_any(Mux::new().route(Rule::TlsSni(..), passthrough))`.

### 2. A ClientHello parser in akio-mux (`akio_mux::tls`)

akio-tls has a `pub(crate)` ClientHello decoder, but exposing it would make akio-mux depend on the
whole TLS stack for 200 lines of parsing, and it decodes far more than routing needs. akio-mux
gets a small standalone parser, `tls::parse_client_hello(&[u8]) -> Result<ClientHello<'_>,
HelloError>`:

- It reassembles the handshake message from consecutive handshake records (content type 22,
  record version `0x03 xx`, record length 1..=2^14, the plaintext limit): a hello may span records, and records
  may hold any split of it. A non-handshake record before the hello is complete, a zero-length
  or oversized record, a handshake type other than ClientHello, or a message whose length goes
  past its own fields is `Invalid`.
- It walks the ClientHello (version, random, session id ≤ 32, cipher suites (even length ≥ 2),
  compression methods ≥ 1, extensions) and keeps, borrowed from the input: the server name
  (`server_name` extension, `host_name` type; the name must be ASCII letters, digits, `-`, `.`
  and `_`, 1..=255 bytes, no empty label), the ALPN protocol list and the legacy version.
  Duplicate extensions are `Invalid` (RFC 8446 4.2).
- The parse is prefix-consistent: a prefix of a hello is `Incomplete` or already `Invalid`,
  never `Ok`, and a longer input never turns `Invalid` into anything else. That is what
  `Rule::decide` needs. Bytes after the hello in its last record are ignored.
- `SniMatcher` and `ClientHello` are re-exported at the crate root.

### 3. New rules

`Rule` is `#[non_exhaustive]`, so these are additions:

- `Rule::TlsSni(SniMatcher)`: a complete ClientHello whose server name matches. `SniMatcher::new
  (["example.com", "*.example.org"])`: exact names and `*.` wildcards (one label, as in
  certificates: `*.example.org` matches `a.example.org`, not `example.org` nor `a.b.example.org`),
  compared without case and without a trailing dot, built into hash sets once (rule 11). A hello
  without a server name does not match.
- `Rule::TlsHello(Arc<dyn Fn(&ClientHello) -> bool>)`: any decision from the parsed hello (server
  name, ALPN, absent SNI).

Both answer `NeedMore` until the hello is complete, `No` for a malformed one. Each route parses
on its own; the cost is one walk of the record headers per read until the hello is complete, and
one full parse per route when it is.

### 4. Routes are tried strictly in order

`Mux` returned the first route answering `Yes`, even when an earlier route still answered
`NeedMore`. With `[TlsSni(..), Tls]` that sent every hello to `Tls` after two bytes. Now a `Yes`
waits while an earlier route is undecided, and wins once all earlier routes said `No`; at the
sniff limit the first `Yes` (else the fallback) takes the connection. This is what the docs
already promised ("routes are tried in order"); configurations whose earlier routes never
answer `NeedMore` when a later one matches are unaffected. The change adds one branch to the
decision, made once per connection.

### 5. The sniff limit grows when an SNI rule is routed

`max_sniff_bytes` defaulted to 64. A mux with a `TlsSni` or `TlsHello` route now defaults to
`TLS_SNIFF_BYTES` (16 KiB + 5, a full-size record) instead, unless `max_sniff_bytes` was set.
A hello that is still incomplete at the limit goes to the fallback (or is closed), as any
undecided connection. The sniff timeout is unchanged (5 s) and bounds trickling clients.
A mux without these rules keeps its limit.

### 6. PROXY protocol: `akio_mux::proxy`

- **Parser.** `ProxyHeader::parse(&[u8]) -> Result<(ProxyHeader, usize), ProxyError>`, both
  versions, prefix-consistent like the hello parser:
  - v1: `PROXY TCP4|TCP6|UNKNOWN ... \r\n`, at most 107 bytes; addresses must match the family,
    ports are decimal 0..=65535 without leading zeros, single spaces; `UNKNOWN` ignores the rest
    of the line.
  - v2: the 12-byte signature, version 2, command `LOCAL` or `PROXY`, family `UNSPEC` / `INET` /
    `INET6` / `UNIX` and protocol `UNSPEC` / `STREAM` / `DGRAM`; the length must cover the
    address block; the remainder must parse as TLVs exactly. A `CRC32C` TLV (0x03) is verified.
    A `LOCAL` header's addresses are ignored (the real ones apply), an `UNSPEC` family's too.
  - `ProxyHeader { version, command, transport, addresses, tlvs }`, `Addresses::{None, Inet {
    source, destination }, Unix { source, destination }}`; helpers `source()`, `destination()`,
    `tlv(kind)`, `authority()` (TLV 0x02).
- **Listener layer.** `ProxyProtocol::new(next)` / `new_any(next)`: a `DynAcceptor` that reads the
  header, then opens `next` with the bytes after the header replayed. Options: `header_timeout`
  (default 5 s, the same watchdog as the sniff deadline), `max_header_bytes` (default 4096;
  v1 is always capped at 107, v2 at 16 + 65535), `versions(v1, v2)` (both by default),
  `allow_missing(bool)` (off: a connection without a header is closed; on: it goes to `next`
  untouched, with no header attached), `trusted(Fn(SocketAddr) -> bool)` (peers for which the
  header is read; other peers go straight to `next` as if the layer were absent: a header from
  them is not believed). A malformed, oversized or late header closes the connection; a v2
  header announcing a length past the limit is refused as soon as its length is read.
- **Where the addresses go.** The parsed header is attached to the connection and read with
  `proxy::header(&conn) -> Option<&ProxyHeader>`, or `proxy::client_addr(&conn)` (the proxied
  source, else `peer_addr`). `Conn::peer_addr` keeps reporting the socket's peer: changing its
  meaning under every protocol would be surprising, and code that wants the client address
  asks for it.
- **Dial side.** `ProxyHeader::proxy(source, destination)` / `ProxyHeader::local()`, `with_tlv`,
  `encode_v1() -> Option<Vec<u8>>` (None for UNIX or TLVs, which v1 cannot carry),
  `encode_v2() -> Vec<u8>`, and `proxy::send_header(&conn, &header, Version)`: the first thing a
  dialing handler sends in `on_open` (bytes queued before the connect completes are sent after
  it).

### 7. One write-once attachment per connection in akio-core

`ConnInner` gains `attachment: OnceLock<Arc<dyn Any + Send + Sync>>` (24 bytes per connection),
with `ConnInner::attach(value) -> Result<(), Arc<..>>` (first writer wins) and
`Conn::attachment::<T>() -> Option<&T>`. Generic, so akio-core knows nothing of PROXY headers;
write-once, so readers take no lock (rule 12). It is set by the layer that owns the first bytes
of the connection, before the protocol handler runs. One slot only, because the PROXY layer is
the only writer today; a second layer that needs one stores a struct holding both. This is the
only akio-core change.

## Consequences

- akit gets passthrough by name (`Rule::TlsSni` / `Rule::TlsHello` to a relay acceptor) and the
  client address behind load balancers, without akio-mux depending on akio-tls.
- Tests cover hellos split across reads and across records, no SNI, malformed and oversized
  hellos, the sniff timeout, wildcard matching; PROXY v1/v2 valid, truncated, forged lengths,
  LOCAL, slowloris headers, untrusted peers; PROXY then an SNI rule on one connection. Fuzz
  targets `mux_tls_hello` and `proxy_header` check no panics, prefix consistency, and that
  encoding a parsed header parses back to it.
- akio-http still reports `peer_addr` as the remote address. Using `proxy::client_addr` there
  (and in access logs) is left to the application or a later change.

## Not done

- TLS 1.3 Encrypted Client Hello: the outer server name is what routing sees (the client-facing
  server), which is what passthrough with ECH needs anyway.
- QUIC (UDP) SNI routing and PROXY v2 over UDP: no UDP mux exists.
- The PP2 SSL sub-TLVs are kept as raw TLV bytes, not decoded.
