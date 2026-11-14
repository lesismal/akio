# WebRTC, STUN and TURN

Two crates:

- `only-webrtc` runs WebRTC peers on `only` UDP sockets. The protocol work is done by
  [str0m](https://github.com/algesten/str0m), a sans-io WebRTC state machine: ICE (full agent
  and ICE-lite, consent freshness), DTLS 1.2/1.3 with certificate fingerprint verification,
  SRTP/SRTCP (AES-CM-SHA1-80, AEAD-AES-128/256-GCM), SCTP data channels (DCEP; reliable or not,
  ordered or not), RTP/RTCP media (Opus, VP8, VP9, H.264, H.265, AV1 packetization; NACK and
  RTX, PLI/FIR, TWCC and bandwidth estimation, sender/receiver reports) and SDP offer/answer.
  `only` drives it with its I/O threads and one shared timer thread, and plugs in a pure-Rust
  crypto provider (RustCrypto plus the `dimpl` DTLS stack: no C toolchain, no OpenSSL).
- `only-turn` has the STUN codec, a STUN server and a TURN server (RFC 8656 over UDP).

Interop is tested against pion (Go) in both offer directions, for data channels and media,
directly and through a `only` TURN relay, against fib's Go WebRTC (data channels, both
directions), and the TURN server against the pion/turn client and
coturn's `turnutils_uclient` (`tools/interop/webrtc/run.sh`, `COTURN=1` for coturn).

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
  `connect_timeout(Some(d))` (default 30 s: an accepted offer that never connects is dropped).
- `TurnServer::new(TurnConfig::new(realm, auth, relay_ip))` serves TURN and STUN on another UDP
  listener. Relay sockets are bound at run time, so it needs the engine: `set_engine(&engine)`.

## Types

The API uses `only`'s own types: `ChannelId`, `ChannelConfig`, `Mid`, `Pt`, `Codec`,
`MediaKind`, `Direction`, `MediaTime` / `Frequency`, `MediaData`, `MediaAdded`, `RtpPacket`,
`KeyframeRequest`, `Candidate`, `IceConnectionState`, `RtcConfig`, `SdpChanges`, `Event`. str0m,
which does the work underneath, is not part of the API, so upgrading it is not a breaking
change. The `unstable` cargo feature (outside the semver promise) re-exports
`only_webrtc::str0m`, adds `Peer::with_rtc` (any str0m API on a peer), `RtcConfig::with_str0m`
and `OtherEvent::as_str0m`.

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
| `with_rtc(f)` | any str0m API, then the peer is driven (cargo feature `unstable` only) |
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

## Not done yet

TURN over TCP/TLS and a TURN client in `only-webrtc` (relay candidates for an `Endpoint`); ICE
over TCP; mDNS candidates. str0m's own limits apply (see its documentation).
