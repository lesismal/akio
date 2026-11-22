# ADR-054: TURN over DTLS, mDNS over IPv6 and SDES-SRTP

English | [简体中文](054-turn-dtls-mdns-ipv6-sdes.zh-CN.md)

Status: accepted (2026-11-20)

## Context

`crates/akio-webrtc/README.md` listed three gaps that keep coming up with non-browser
deployments:

- **TURN over DTLS** (RFC 7350, `turns:host?transport=udp`). `akio-turn` served TURN over
  UDP, TCP and TLS, and `Endpoint::gather_relay_via` allocated over the same three. Networks
  that let only UDP out but want the control channel encrypted, and coturn deployments that
  publish their DTLS listener, could not be used.
- **mDNS over IPv6 multicast.** `Endpoint::resolve_mdns` and `conceal_host_candidates` (ADR-044)
  used one IPv4 socket on `224.0.0.251:5353`. A name could resolve to an IPv6 address, but
  only through an IPv4 responder; an IPv6-only link, or a browser answering on `ff02::fb` only,
  was out of reach, and link-local IPv6 candidates had no interface to go out on.
- **SDES-SRTP** (RFC 4568 `a=crypto`). SIP gateways (Asterisk, FreeSWITCH and PBXs behind them)
  key SRTP with security descriptions in the SDP instead of DTLS-SRTP. `akio-srtp` already
  implements every suite they use (ADR-040), and `Profile::sdes_name` / `from_sdes_name` exist,
  but nothing negotiated them.

Constraints: `akio-srtp`, `akio-rtp` and `akio-ice` are being edited by other sessions and are
not touched here; browsers must keep seeing exactly what they see today; and the public API of
`akio-turn` and `akio-webrtc` (public tier) must not expose internal-tier types (`akio-dtls`,
`akio-srtp`).

## Decision

### 1. TURN over DTLS

**Server.** `TurnServer::dtls(&tls::ServerConfig) -> io::Result<TurnDtls>` is the acceptor of
a UDP listener whose clients talk DTLS. It takes the same `tls::ServerConfig` as the `turns:`
TCP listener (its default chain and key; client certificates only when the config asks for
them), so one certificate serves both. Per client 5-tuple:

- ClientHellos are answered statelessly by one `akio_dtls::HelloVerifier` per acceptor
  (HelloVerifyRequest for DTLS 1.2, HelloRetryRequest cookies for 1.3); a DTLS
  `Connection::server` (cookies off) is made only for a ClientHello with a valid cookie. DTLS
  1.3 is offered with fallback to 1.2 (1.3 only when the TLS config is TLS 1.3 only).
- Each application-data record is one STUN or ChannelData message with UDP semantics: no
  framing, no padding (RFC 7350 section 4). Responses and relayed data are sealed under the
  shard's lock (lock order shard → session, as for every other `TurnEnv` call).
- **An allocation lives as long as its DTLS association**: close_notify, a fatal alert, the
  listener's `udp_idle_timeout`, or a new handshake from the same 5-tuple (a ClientHello with
  a fresh random and a valid cookie on an established association: the client restarted)
  frees it. Without that, a client that lost its association would be refused with
  437 Allocation Mismatch until the old allocation expired.
- Retransmission and handshake timers run on the server's existing sweep thread (every 500 ms;
  DTLS starts at 1 s).
- DTLS clients get their own third of the shard table (UDP, stream, DTLS), so the same
  address on two transports names two clients, as UDP and TCP already did.
  `TurnServer::dtls_relay_of` reports a DTLS client's relay.

**Client.** `RelayServer::dtls(addr, server_name, tls::ClientConfig, user, pass)`, and
`turns:host[:port]?transport=udp` URLs (port 5349 by default; `tls_config` completes them as it
completes TLS ones). The allocation runs inside an `akio_dtls::Connection::client` over the
**endpoint's own UDP socket**, like a plain UDP allocation: datagrams from the server's address
are read off the socket before peer routing, decrypted, and fed to the sans-io TURN client;
its messages wait (bounded, retransmissions of a queued transaction not queued twice) until the
handshake completes. The DTLS timer joins the relay's timer on the shared WebRTC timer thread.
The server's certificate is verified against the TLS client configuration's roots for
`server_name` with `akio_x509::Verifier` (its client certificate is sent if it has one;
`insecure_skip_verify` verifies nothing). A failed handshake fails `gather_relay_via` at once;
an association lost later loses the allocation, which is made again with a new handshake
(ADR-032's backoff). The candidate is a UDP relayed one (as from a plain UDP allocation), and
the server's mapped address becomes a server-reflexive candidate. One datagram relay (UDP or
DTLS) per server address: both would read the same datagrams.

The `tls::ServerConfig` / `tls::ClientConfig` parts are read through their existing
doc-hidden `__parts()` (QUIC's bridge), so no internal-tier type reaches the public API.

### 2. mDNS over IPv6

- `resolve_mdns` binds a second socket, `[::]:5353` member of `ff02::fb`, next to the IPv4 one
  (the same fallback to an ephemeral port with QU queries when 5353 cannot be bound; a host
  without IPv6 runs IPv4 only, unchanged). The dual-stack socket drops IPv4-mapped sources (the
  IPv4 socket has them).
- **Per-interface join.** `ff02::fb` is link-scoped: a socket receives it only on the links it
  joined it on, and macOS refuses to send to it without an interface ("no route to host"). The
  interfaces are those with an IPv6 link-local address: on Linux from `/proc/net/if_inet6`,
  elsewhere by asking the kernel for a route to `ff02::fb%<i>` for the first 64 indexes (a UDP
  connect, nothing sent). The engine-served socket joins the group on each through a new
  additive `akio` API, `Engine::bind_udp_multicast_on(group, interfaces, acceptor)`
  (`UdpBinding` does not expose its socket, so this cannot be done from akio-webrtc; added
  with the coordinator's approval). `bind_udp_multicast(group, a)` is now
  `bind_udp_multicast_on(group, &[0], a)`, unchanged in behaviour; 0 is the default interface.
  Interfaces that refuse the join are skipped, and it fails only when none accepts it. **IPv6
  groups only take a list**: an IPv4 group is joined on the default interface, so it takes
  `&[0]` and anything else is refused with `InvalidInput` (IPv4 joins name an interface by
  address, not by index, and mDNS over IPv4 needs no more); an empty list is refused too.
  Tests in `crates/akio/tests/shared_ports.rs` (argument checks; an IPv6 group joined on every
  link-local interface receives a datagram sent to it on each link, from a source with that
  link's scope id).
- **Scope ids.** Queries go to `ff02::fb` on every joined interface (and on the scope ids of the
  endpoint's own link-local host candidates); an answer goes back to the group on the
  interface its query came from (or unicast to the querier when it asked so). SDP carries no
  scope id, so the endpoint hub keeps the interface of remote link-local addresses: learnt from
  the datagrams they send (the scope id is stripped before ICE sees the address) and from the
  mDNS answer that resolved them (the interface it arrived on), and put back on what is sent;
  when nothing was learnt, the endpoint's own socket's scope is used if it is bound to a
  link-local address (same link). Global IPv6 and IPv4 addresses never take that path.
- AAAA records were already parsed and answered (ADR-044); IPv6 host candidates are concealed
  like IPv4 ones. Either family's answers may carry A and AAAA records.

### 3. SDES-SRTP

`RtcConfig::enable_sdes_srtp(true)`, **off by default**:

- **Offers** made with it (the first offer of a session decides) are SDES offers: media
  sections `RTP/SAVPF`, no `a=fingerprint` / `a=setup`, and one `a=crypto` line per suite,
  strongest first (AEAD_AES_256_GCM, AEAD_AES_128_GCM, AES_256_CM_HMAC_SHA1_80,
  AES_CM_128_HMAC_SHA1_80, AES_CM_128_HMAC_SHA1_32), each with its own random key, the same
  lines in every section of the BUNDLE. Re-offers keep the keys.
- **A remote offer** is SDES when its first section in use is `RTP/SAVP` or `RTP/SAVPF` with
  `a=crypto` lines. It is answered (with SDES on) with the first line this side can use and a
  fresh key of this side's for that suite (kept across re-offers that keep the tag and suite),
  in the offer's protocol. Lines with an MKI, several keys, session parameters (`KDR=`,
  `UNENCRYPTED_SRTP`, ...), an unknown suite or a key of the wrong length are not taken (RFC
  4568 §6.1); a lifetime is accepted and not enforced. With SDES off, such an offer is refused
  with a clear error.
- **Keying.** Each side encrypts with its own key and decrypts with the other's: the two
  `akio-srtp` contexts are made from the SDP when the offer/answer completes, and only the one
  whose key changed is replaced on renegotiation (rollover counters and replay windows stay).
  The peer is connected once ICE has a pair; no DTLS handshake runs.
- **BUNDLE**: one SRTP context per direction serves the transport, so a remote description
  whose sections carry different keys is refused.
- **No data channels** in an SDES session (they need DTLS): adding one fails, and an offered
  application section is rejected.
- **DTLS-SRTP stays the default and browsers never see `a=crypto`**: offers are DTLS-SRTP
  unless SDES is enabled, and a DTLS-SRTP offer (`UDP/TLS/RTP/SAVPF`, with or without
  `a=crypto`) is answered with DTLS-SRTP even with SDES enabled. A renegotiation that switches
  between the two is refused.

## Consequences

- `akio-turn` depends on `akio-dtls` and `akio-x509` (both already in the graph through
  `akio` / `akio-tls`); `akio-webrtc` moves `akio-x509` from dev- to normal dependencies.
- New public API: `TurnServer::dtls`, `TurnServer::dtls_relay_of`, `TurnDtls` (and the hidden
  `TurnDtlsClient` handler), `RelayServer::dtls`, `RelayServer::transport() == "dtls"`,
  `RtcConfig::enable_sdes_srtp`, `Engine::bind_udp_multicast_on`. `turns:...?transport=udp`
  is no longer an error.
- An SDES session's keys are only as secret as the signalling channel; the docs say so, and it
  is off by default.
- IPv6 mDNS costs one more socket per resolving endpoint and, on non-Linux hosts, up to 64 UDP
  connect probes at `resolve_mdns`.

Tests: akio-turn `tests/dtls.rs` (DTLS 1.3 and 1.2 clients, relayed data both ways, close_notify
and deletion freeing the allocation, a wrong certificate refused, a restarted client replacing
its association, non-DTLS datagrams ignored); akio-webrtc `tests/relay_dtls.rs` (two
`Endpoint`s relayed through DTLS allocations with a data channel echo, credentials /
certificate / name failures, the `turns:?transport=udp` URL), `tests/sdes.rs` (media echo for
each of the five suites, renegotiation keeping the keys and an offer the other way, refusals,
a DTLS-SRTP offer answered with DTLS-SRTP), `tests/mdns.rs` (AAAA queries answered over
`ff02::fb`, a name only an IPv6 responder knows resolved and connected, concealed `::1`
endpoints, endpoints on a link-local address); unit tests of `a=crypto` parsing and the
offer/answer choice. Fuzzing: new target `turn_dtls` (a DTLS session in front of a TURN core,
with and without the cookie exchange); `webrtc_sdp` tries an SDES configuration and checks
that keys never appear without it or next to a fingerprint; `webrtc_turn_url` covers
`turns:?transport=udp`.

Interop (`tools/interop/webrtc/turn-dtls.sh`, Docker on gpu51, coturn 4.6): coturn's
`turnutils_uclient -S` over DTLS against akio-turn's DTLS listener; the akio_turn client inside
an akio-dtls connection against coturn's DTLS listener (DTLS 1.3 offered, 1.2 negotiated); two
`Endpoint`s relayed through coturn over DTLS (`turns:127.0.0.1:5349?transport=udp`) with a data
channel echo; the same through akio-turn.

Not done: SDES with MKIs or session parameters, SDES without ICE (plain `c=` / port media), and
data channels next to SDES; TURN over DTLS with connection IDs; ICE over link-local addresses
learnt any other way than mDNS or inbound traffic. A follow-up for `akio-ice`: export
`MULTICAST_V6` next to `MULTICAST_V4`, and let a resolved candidate carry a scope id.

Done since (2026-11-22, ADR-078): IPv6 mDNS goes out with hop limit 255 (new akio-sys
`set_multicast_hops_v6`), names are concealed on IPv6-only links (the IPv6 socket answers when
the IPv4 one has no shared port), and it is checked against Chrome 157, avahi 0.8 (IPv6 only,
`check-response-ttl=yes`) and mDNSResponder.
