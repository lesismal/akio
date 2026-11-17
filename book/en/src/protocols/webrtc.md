# WebRTC, STUN and TURN

Two crates:

- `only-webrtc` runs WebRTC peers on `only` UDP sockets, on an in-house sans-io stack with no
  third-party dependencies (DEV-PLAN wave D), one crate per layer, all `#![forbid(unsafe_code)]`
  on `only-crypto`: `only-ice` (ICE full agent and ICE-lite, checklists, nomination, role
  conflicts, peer-reflexive candidates, trickle, restarts, consent freshness), `only-dtls`
  (DTLS 1.2 and 1.3 with certificate fingerprint verification and DTLS-SRTP keys; see below),
  `only-srtp`
  (SRTP/SRTCP with AES-CM-HMAC-SHA1-80/32 and AEAD-AES-128/256-GCM, replay protection),
  `only-sctp` (SCTP over DTLS with congestion control, PR-SCTP, stream reset, DCEP data
  channels: reliable or not, ordered or not) and `only-rtp` (RTP/RTCP, Opus, G.711, G.722, VP8,
  VP9, H.264, H.265 and AV1 packetization, a frame assembler, NACK and RTX, PLI/FIR, REMB, TWCC
  and bandwidth estimation, sender/receiver reports). `only-webrtc` itself does SDP
  offer/answer (BUNDLE, rtcp-mux, codec and header-extension negotiation, renegotiation) and
  drives the peers with `only`'s I/O threads and one shared timer thread.
- `only-turn` has the STUN codec, a STUN server and a TURN server (RFC 8656 over UDP).

Interop is tested against pion (Go) in both offer directions, for data channels and media,
directly and through a `only` TURN relay, against fib's Go WebRTC (data channels, both
directions), and the TURN server against the pion/turn client and
coturn's `turnutils_uclient` (`tools/interop/webrtc/run.sh`, `COTURN=1` for coturn). Headless
Chrome is tested in both offer directions: data channels, and its fake camera and microphone
echoed back by an `RtcServer` and decoded by Chrome (`tools/interop/webrtc/browser.sh`).

## A server, a TURN server and a client on one engine

```rust,ignore
{{#include ../../../../crates/only-webrtc/examples/guide-webrtc.rs:engine}}
```

- `RtcServer::new(addrs)` is the acceptor of a **UDP listener**; all its peers share the port.
  `addrs` are the addresses remote peers reach the listener at (public IP and port): they go
  into every SDP as host candidates. It runs **ICE-lite** by default: the server only answers
  connectivity checks, which is right for anything publicly reachable (an SFU, a WHIP/WHEP
  endpoint). Datagrams are routed to peers by the ICE username of the first check, then by
  source address.
- Builder methods (call them before cloning): `config(|| rtc_config()...)` builds every peer's
  `RtcConfig` (codecs, RTP mode, BWE, statistics...), `ice_lite(false)` for a full agent,
  `close_on_disconnect(bool)` (default true: a peer whose consent expires is closed),
  `connect_timeout(Some(d))` (default 30 s: an accepted offer that never connects is dropped),
  `max_peers(n)` (default 1024, `DEFAULT_MAX_PEERS`: offers past it fail with
  `Error::TooManyPeers`; 0 removes the limit; on an `Endpoint` it may be set after binding).
- `TurnServer::new(TurnConfig::new(realm, auth, relay_ip))` serves TURN and STUN on another UDP
  listener. Relay sockets are bound at run time, so it needs the engine: `set_engine(&engine)`.

## Types

The API uses `only`'s own types: `ChannelId`, `ChannelConfig`, `Mid`, `Pt`, `Codec`,
`MediaKind`, `Direction`, `MediaTime` / `Frequency`, `MediaData`, `MediaAdded`, `RtpPacket`,
`KeyframeRequest`, `Candidate`, `IceConnectionState`, `RtcConfig`, `SdpChanges`, `Event`. The
protocol crates underneath are internal (their APIs may change in any release) and do not
appear in it. The `unstable` cargo feature is kept for APIs outside the semver promise and adds
nothing today (it used to expose str0m).

## Peers and handlers

```rust,ignore
{{#include ../../../../crates/only-webrtc/examples/guide-webrtc.rs:handler}}
```

`PeerHandler` has a default for every callback: `on_ice_state`, `on_connected`,
`on_channel_open` / `on_channel_data` / `on_channel_close`, `on_media_added`, `on_media_data`
(depacketized samples, the default frame mode), `on_rtp` (RTP mode), `on_keyframe_request`
(PLI/FIR from the remote), `on_event` (`Event::ChannelBufferedAmountLow`, and `Event::Other`
for statistics, bandwidth estimates, sender reports...), `on_close`. A peer's callbacks run one at a time, in order, on
the I/O thread that read the datagram, on the timer thread, or on the thread that called a
`Peer` method; they must not block.

`Peer` is cheap to clone and works from any thread:

| Method | What it does |
|---|---|
| `send(channel, data, binary)` | a data channel message (`Ok(false)`: buffer full) |
| `open_channel(cfg)` | a new channel; no renegotiation once one channel exists |
| `write_media(mid, pt, wallclock, rtp_time, data)` | one sample (packetized for you) |
| `payload_type(mid, codec)` | the negotiated payload type of a codec |
| `request_keyframe(mid, kind)` | PLI or FIR to the remote sender |
| `renegotiate(f)` / `accept_answer` / `accept_offer` | SDP changes after the first exchange |
| `add_remote_candidate(line)` | trickle ICE |
| `close()` | DTLS close notify, then `on_close` |

## A full ICE client: `Endpoint`

```rust,ignore
{{#include ../../../../crates/only-webrtc/examples/guide-webrtc.rs:client}}
```

```rust,ignore
{{#include ../../../../crates/only-webrtc/examples/guide-webrtc.rs:endpoint}}
```

`Endpoint::bind(&engine, addr)` binds a UDP socket with `Engine::bind_udp` (the engine needs
`udp_client_threads(n)` or a UDP listener). An unconnected socket is what an ICE agent needs: one
local port that sends checks to every remote candidate. The host candidate is `addr`, or the
address of the default-route interface when `addr` is unspecified. `gather_srflx(stun, timeout)`
asks a STUN server for the public address and adds it as a server-reflexive candidate (it
blocks: never call it from a callback). `create_offer(handler, |sdp| ...)` gets an
`SdpChanges` to add channels and media; `accept_offer` answers a remote offer. An `Endpoint` talks
to ICE-lite servers, to browsers and pion, and to other `Endpoint`s.

## TURN

`TurnConfig` fields (all public, `TurnConfig::new` sets the defaults):

| Field | Default | Meaning |
|---|---|---|
| `realm`, `auth` | – | long-term credentials: `static_auth(realm, users)` or `ephemeral_auth(secret)` (TURN REST API, `ephemeral_credentials` hands them out) |
| `relay_ip`, `public_ip` | –, none | relays bind on `relay_ip`; clients are told `public_ip` if set (1:1 NAT) |
| `default_lifetime`, `max_lifetime` | 600 s, 3600 s | allocation lifetimes |
| `permission_lifetime`, `channel_lifetime` | 300 s, 600 s | RFC 8656 values |
| `nonce_lifetime` | 600 s | nonces are stateless (an expiry and an HMAC of it with the client address) |
| `max_allocations`, `max_allocations_per_user` | 16384, 1024 | quotas (508, 486) |
| `max_permissions`, `max_channels` | 256, 256 | per allocation (508) |
| `peer_allowed`, `allow_private_peers` | none, false | the default refuses loopback, private, link-local, multicast and reserved peers (`denied_by_default`): a relay into the server's own network would be an SSRF hole |

Allocate, Refresh, CreatePermission, ChannelBind, Send and Data indications, ChannelData,
`EVEN-PORT` with `RESERVATION-TOKEN` and `REQUESTED-ADDRESS-FAMILY` are supported; requests are
authenticated with `MESSAGE-INTEGRITY` (`401`/`438` challenges), `FINGERPRINT` is checked and
echoed. Relayed traffic goes through the client's listener connection, so a client silent for
longer than `Config::udp_idle_timeout` (60 s) loses data from peers until it sends again: raise
that timeout on a TURN listener. `TurnCore` is the same server without I/O (`TurnEnv` does the
sending), for embedding or testing. `StunServer` alone answers Binding requests.

`TurnServer` splits allocations into shards by client address (about four per CPU, at least 8),
each with its own lock: datagrams of different allocations do not contend across I/O threads,
the expiry sweep takes one shard at a time, and the relay socket of an authenticated Allocate
is bound before any lock is taken. The quotas stay server-wide.

## The DTLS layer: DTLS 1.2 for WebRTC, DTLS 1.3 when asked

`only-dtls` is a sans-io connection (`Connection`: feed datagrams and timer expiries, send what
`poll_transmit` returns) that speaks DTLS 1.2 (RFC 6347) and DTLS 1.3 (RFC 9147). WebRTC uses
DTLS 1.2: `Config::webrtc` enables only it, because pion and the browsers' stacks negotiate
DTLS 1.2 and offering 1.3 would only make the ClientHello larger (ADR-021). Outside WebRTC,
`Config::with_versions(vec![Version::Dtls13, Version::Dtls12])` offers both and falls back to
DTLS 1.2 for a 1.2-only peer (with the RFC 8446 downgrade check).

- **DTLS 1.3**: unified record headers with encrypted record numbers, epochs with KeyUpdate
  (`Connection::update_keys`, also automatic before a key's usage limit), ACKs so that only
  the lost fragments of a flight are resent, stateless HelloRetryRequest cookies (also from
  `HelloVerifier::check` in front of the connections).
- **Connection IDs** (`Config::with_connection_id`): RFC 9146 `tls12_cid` records in DTLS 1.2,
  the CID in the unified header in DTLS 1.3. A listener routes datagrams with
  `only_dtls::connection_id(datagram, len)` instead of the address, so a peer whose NAT
  binding changes keeps its connection.
- **Resumption** (`Config::with_session_resumption`): DTLS 1.2 session IDs (bounded cache) and
  RFC 5077 tickets, DTLS 1.3 NewSessionTicket (`psk_dhe_ke`, always forward secret). The client
  gets `Event::NewSession(session)` and reconnects with `Connection::client_resume`; tickets
  are sealed with a `TicketKey` that servers can share, and the peer certificate is checked
  again by the verifier on resumption.
- **External PSKs** (`Config::with_psks`): the DTLS 1.2 PSK and ECDHE-PSK AEAD suites and
  DTLS 1.3 `psk_dhe_ke`; a PSK-only server needs no certificate.

Interop is checked against OpenSSL 3.5 / 4.1, wolfSSL 5.8 and pion/dtls
(`tools/interop/dtls/run.sh`).

## Not done yet

TURN over TCP/TLS and a TURN client in `only-webrtc` (relay candidates for an `Endpoint`); ICE
over TCP; resolving mDNS candidates (peers using them are still reached through peer-reflexive
candidates); simulcast sending and layer selection; FEC; RTCP XR; DTLS 1.3 for WebRTC by
default; DTLS 1.3 0-RTT and NewConnectionId.
