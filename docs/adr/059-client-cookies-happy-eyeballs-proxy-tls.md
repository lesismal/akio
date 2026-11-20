# ADR-059: Cookies, Happy Eyeballs, a DNS cache and TLS to proxies in the clients; SOCKS fragments and TLS

English | [简体中文](059-client-cookies-happy-eyeballs-proxy-tls.zh-CN.md)

Status: accepted (2026-11-20)

## Context

ADR-010 gave the HTTP/1, HTTP/2 and WebSocket clients redirects, timeouts, name resolution off the
calling thread, system roots and HTTP proxies, and listed what it left out: a cookie jar, TLS and
SOCKS proxies, PAC, Happy Eyeballs, a DNS cache, macOS trust settings and the Windows store.
ADR-019 then added SOCKS proxies (`socks5://`, `socks5h://`, `socks4://`, `socks4a://`, and
`ALL_PROXY`) and a SOCKS client, leaving out GSSAPI, sending fragmented UDP datagrams and TLS to
the proxy. This ADR closes the remaining items except PAC (it needs a JavaScript engine), the
Windows certificate store (Windows is not a target) and GSSAPI.

Constraints: no new third-party dependency (ADR-005); every table and queue has a safe bound
(ADR-009, `docs/rules.md`); no blocking on an I/O thread; additive public API.

## Decision

1. **Cookie jar** (`only_http::cookie`, `Client::with_cookies`). RFC 6265 storage and retrieval
   with the RFC 6265bis rules browsers follow: Domain (host-only without it; domain-match; a
   Domain that is a public suffix is refused unless it is the host itself), Path (default path,
   path-match), Secure (only set from and sent to `https://`; an `http://` response cannot
   overwrite or shadow a Secure cookie), `__Secure-` / `__Host-` prefixes, HttpOnly (stored and
   reported: the flag is about scripts), SameSite (`None` needs Secure; a request reached
   through a redirect chain that left the first request's site carries no `Strict` cookies, and
   `Lax` ones only with a safe method; cookies without SameSite are not restricted, since an
   HTTP client has no "Lax by default" navigation model), Max-Age over Expires, RFC 6265's
   lenient date parser, expiry capped at 400 days. Public suffixes: single labels and IP
   addresses always (an IP host takes host-only cookies only); a full list (the Public Suffix
   List) can be plugged in with `CookieJar::public_suffixes`, none is bundled (it would be a
   200 KB table to keep current). Limits (`CookieLimits`, RFC 6265 §6.1 minimums): 4096 bytes of
   name plus value, 50 cookies per domain, 3000 in all; least recently used go first, expired
   ones before anything. The client stores the `Set-Cookie` fields of every response, each hop
   of a redirect chain included, and sends one `Cookie` field per request (the request's own
   value first, then the jar's). Off unless a jar is attached.
2. **DNS cache** (`only::dns`). `getaddrinfo` does not return TTLs, so answers are kept for a
   fixed, configurable time (`CacheConfig::ttl`, 30 s), at most `max_entries` names (1024;
   expired ones evicted first, then the ones expiring soonest); failures are not cached unless
   `negative_ttl` is set. Process-wide like the resolver pool; `set_cache`, `cache_config`,
   `clear_cache`; `CacheConfig::disabled()` turns it off. Concurrent lookups of one name share one
   `getaddrinfo`. Cached answers and literals are given on the calling thread. The 30 s default
   bounds staleness; a deployment whose names move faster sets a smaller TTL.
3. **Happy Eyeballs v2** (`only::dns::HappyEyeballs`, RFC 8305). Addresses are interleaved by
   family starting with the family of the system's first choice (§4), a new attempt starts every
   250 ms (`attempt_delay`, clamped to 10 ms ..= 2 s) or at once when the previous one fails
   (§5), and the first connection up wins; the others are closed before any byte is sent. The
   race runs on one dedicated thread (`only-connect`, started on demand, gone after 10 s idle)
   that waits on non-blocking connects with `only_sys::Poller`; at most `MAX_RACES` (256) races
   at once, more are dialed one address after another by the engine as before; at most 16
   addresses per race; each attempt bounded by `connect_timeout` (10 s). The winning socket is
   handed to the engine with `Engine::adopt_tcp`, so the acceptor sees an ordinary dialed
   connection on an I/O thread; one address is dialed by the engine directly (unchanged path).
   Used by the HTTP/1 client (`ClientOptions::happy_eyeballs`), the WebSocket client
   (`DialOptions::happy_eyeballs`) and the new `H2Client::connect(engine, host, port, ...)`.
   Not done from RFC 8305: separate AAAA and A queries with the 50 ms resolution delay (§3):
   `getaddrinfo` returns both families together. `only::dns::black_hole` (hidden) makes the racer
   treat an address as a black hole, for tests on systems that answer a full accept queue
   (macOS); Linux tests use a real one.
4. **TLS to the proxy.** `https://` proxy URLs (port 443) in `Proxy` (and so in `from_env`):
   the proxy's certificate is checked for its host name with the client's TLS configuration (the
   system roots by default). `https://` targets run TLS inside TLS: the tunnel's `CONNECT` goes
   in the proxy's session, the target's session in the tunnel; `http://` targets go to the proxy
   in absolute form inside its session. Built as a layered transport (`only_ws::proxy::Layered`,
   hidden): an outer transport (TLS to the proxy) carries what the inner one (the tunnel, and
   the target's TLS inside it) puts on the wire; a failure of the outer one before the tunnel is
   open is reported as a tunnel failure. `Connect::over_tls` (hidden) adds it to any tunnel.
5. **SOCKS** (`only-socks`). `SocksClient::tls(cfg, server_name)`: TLS to the proxy on the
   engine methods (`dial`, `bind`, and the control connection of `udp_associate`; datagrams stay
   plain UDP as RFC 1928 has them); the blocking helpers return a `TcpStream` and refuse with
   `Unsupported`; a TLS failure before the tunnel opens goes to `on_error`. Sending fragments
   (RFC 1928 §7 `FRAG`): `UdpAssociation::send_fragmented` / `BlockingUdp::send_fragmented`
   split a datagram into pieces of at most `max` bytes (positions 1, 2, ..., the last with the
   high bit; whole when it fits; `InvalidInput` beyond 127 fragments), and the server's
   `Socks::udp_fragment_size(Some(n))` sends datagrams from remote hosts to the client in
   fragments of `n` bytes (raised to 516 so any datagram fits in 127; off by default since not
   every client reassembles). The client's UDP association now tries the proxy's next address
   when one cannot be reached, like `dial`.
6. **macOS trust settings** (`RootCerts::system`). `security trust-settings-export` writes the
   user, admin and system domains' settings as XML property lists without prompting (checked on
   the macOS development host, Darwin 27); they are read through a private temporary directory (it cannot write to a pipe)
   with a small bounded plist parser (16 levels, 8 MiB). A certificate's verdict comes from the
   first domain that has one (user, then admin, then system), from the first constraint that
   applies to TLS servers (no policy, `sslServer` or `basicX509`; not limited to an application
   or a host name): TrustRoot / TrustAsRoot keep it, Deny drops it, Unspecified looks further.
   The roots are then the system roots, the System keychain and the login keychain filtered by
   those verdicts; a certificate without one is a root only if it is a system root. This also
   drops the System keychain's certificates that nobody marked as trusted, which earlier
   versions took as roots (macOS does not). When no domain can be read, the earlier behaviour
   applies.
7. **API**, additive: `only::dns::{CacheConfig, set_cache, cache_config, clear_cache,
   HappyEyeballs, interleave, DEFAULT_CACHE_TTL, DEFAULT_CACHE_ENTRIES, ATTEMPT_DELAY,
   CONNECT_TIMEOUT, MAX_RACES, MAX_RACE_ADDRS}`; `only_http::cookie::{CookieJar, Cookie,
   CookieLimits, SameSite, MAX_AGE_CAP}`, `Client::{with_cookies, cookies}`,
   `ClientOptions::happy_eyeballs`, `H2Client::connect`; `only_ws::client::DialOptions::
   happy_eyeballs`; `only_socks::{SocksClient::tls, UdpAssociation::send_fragmented,
   BlockingUdp::send_fragmented, Socks::udp_fragment_size}`. `ClientOptions` and `DialOptions`
   are `#[non_exhaustive]`, so the new fields break no caller. Hidden: `ProxyServer::tls`,
   `Connect::over_tls`, `Layered`, `dns::black_hole`.

## Consequences

- Tests: cookie unit tests (dates, parsing, domain / path / Secure / prefix / SameSite rules,
  expiry, replacement, limits and eviction) and an integration test across redirect chains
  (cookies set mid-chain sent on the next hop, cross-site chains without Strict or, for POST,
  Lax cookies, host-only cookies of an IP not sent to another host, the request's own Cookie
  field kept first, Max-Age=0 deletes, nothing without a jar); `only::dns` cache (inline answers
  once cached, eviction and expiry); Happy Eyeballs on the engine (fallback from an IPv6 black
  hole after the attempt delay, a shorter delay, all addresses timing out, a refused address
  moving on at once, more races than the racer takes, resolve-then-race); `https://` proxies for
  the HTTP client (TLS in TLS for https, absolute form for http, keep-alive, proxy certificate
  checked by name) and the WebSocket client (ws and wss) through a TLS front of the local test
  proxy; SOCKS fragments both ways (the server's fragments seen raw, client fragments
  reassembled by the server, the echo reassembled by the client, blocking and on the engine) and
  `SocksClient::tls` against only-socks behind `Tls::server` (CONNECT, UDP ASSOCIATE, wrong
  certificate name, blocking refusal); trust-settings verdicts and domain precedence, and on
  macOS the real keychains.
- Fuzz targets `cookie_parse` (Set-Cookie and dates, the jar's storage rules and limits) and
  `tls_trust_plist` (the plist parser), with seed corpora replayed by the unit tests.
- Linux (gpu51, x86_64): only, only-http, only-ws, only-socks and only-tls pass on epoll and
  io_uring; the Happy Eyeballs test meets a real IPv6 black hole there (a full accept queue drops
  SYNs). macOS: the same crates pass (`only-ws`'s `large_and_fragmented_messages_and_limits` is
  slow in debug builds on main as well and needs `ONLY_TEST_TIMEOUT_SCALE` under load). Fuzzing on
  gpu51, 5 minutes each: `cookie_parse` 4.2 million runs, `tls_trust_plist` 6.3 million, no
  finding.
- Same-round A/B on gpu51 (`quiet.sh`, CPU 2-9, 7 alternating rounds,
  `examples/client-bench.rs`: 64 keep-alive request loops of the HTTP/1 client against a local
  server): 0.999x of main b22519ae (270.0k vs 270.2k requests/s, rounds 0.992-1.039x): no
  regression.
- Costs: a client without a jar tests one `Option` per request header; `resolve` takes a
  process-wide lock to look a name up (once per new connection, not per request); a race costs
  one hop through the racer thread and one poller registration per attempt; an `https://` proxy
  costs a second TLS session per connection.
- Not done: PAC, the Windows store, GSSAPI (as above); a cookie jar for `H2Client` and the
  WebSocket handshake (both can send a `Cookie` header taken from `CookieJar::header`); real DNS
  TTLs (would need an own DNS client); a bundled Public Suffix List.
