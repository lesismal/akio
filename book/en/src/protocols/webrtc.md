# WebRTC, STUN and TURN

Two crates:

- `only-webrtc` runs WebRTC peers on `only` UDP sockets, on an in-house sans-io stack with no
  third-party dependencies (DEV-PLAN wave D), one crate per layer, all `#![forbid(unsafe_code)]`
  on `only-crypto`: `only-ice` (ICE full agent and ICE-lite, checklists, nomination, role
  conflicts, peer-reflexive candidates, trickle, restarts, consent freshness), `only-dtls`
  (DTLS 1.2 with certificate fingerprint verification and DTLS-SRTP keys), `only-srtp`
  (SRTP/SRTCP with AES-CM-HMAC-SHA1-80/32 and AEAD-AES-128/256-GCM, replay protection),
  `only-sctp` (SCTP over DTLS with congestion control, PR-SCTP, stream reset, DCEP data
  channels: reliable or not, ordered or not) and `only-rtp` (RTP/RTCP, Opus, G.711, G.722, VP8,
  VP9, H.264, H.265 and AV1 packetization, a frame assembler, NACK and RTX, PLI/FIR, REMB, TWCC
  and bandwidth estimation, sender/receiver reports). `only-webrtc` itself does SDP
  offer/answer (BUNDLE, rtcp-mux, codec and header-extension negotiation, renegotiation) and
  drives the peers with `only`'s I/O threads and one shared timer thread.
- `only-turn` has the STUN codec, a STUN server, a TURN server (RFC 8656 over UDP, TCP and TLS)
  and a sans-io TURN client.

Interop is tested against pion (Go) in both offer directions, for data channels and media,
directly and through a `only` TURN relay, with an `Endpoint` offering only relayed candidates
(on `only`, pion/turn and coturn TURN servers) or only its passive ICE-TCP candidate, and with
simulcast sent to pion; against fib's Go WebRTC (data channels, both directions); the TURN
server against the pion/turn client and coturn's `turnutils_uclient` over UDP, TCP and TLS; the
TURN client against pion/turn, coturn and `only` over UDP, TCP and TLS
(`tools/interop/webrtc/run.sh`, `COTURN=1` for coturn, `linux.sh` for all of it in Linux
containers). Headless
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
| `write_simulcast(mid, rid, pt, wallclock, rtp_time, data)` | one sample of a simulcast encoding |
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

### Relayed candidates

`gather_relay(turn_server, username, password, timeout)` allocates a relayed address on a TURN
server over the endpoint's UDP socket and adds it as a relayed candidate (and the
server-reflexive address the server saw, when it is new); like `gather_srflx` it blocks. The
allocation is shared by every peer of the endpoint and kept alive (refreshes, permissions and
channels, on the WebRTC timer thread) until `Endpoint::close`, which deletes it. At most 4
allocations per endpoint; a refusal or the limit is `Error::Turn`, no answer `Error::Timeout`.

```rust,ignore
let ep = Endpoint::bind(&engine, "0.0.0.0:0".parse()?)?;
let relayed = ep.gather_relay("203.0.113.7:3478".parse()?, "alice", "secret", Duration::from_secs(5))?;
```

### ICE over TCP

`listen_tcp(&engine, addr)` adds a passive ICE-TCP candidate (RFC 6544) on its own TCP port: a
browser or pion behind a network that blocks UDP connects to it with an active candidate and runs
ICE, DTLS, SCTP and SRTP over the connection (RFC 4571 framing). The engine needs TCP I/O threads
(`client_threads(n)` or a TCP listener). A dedicated thread accepts, at most 256 connections at
once; a connection whose first frame is not a connectivity check for one of the endpoint's peers
within 10 seconds is closed, and so are a peer's connections when it closes. TCP candidates rank
below UDP ones, so a peer that can use UDP still does. An `Endpoint` has no active TCP
candidates: clients that only have TCP use TURN over TCP or TLS.

### Simulcast

`SdpChanges::add_simulcast_media(kind, dir, &["h", "m", "l"], stream_id, track_id)` adds a line
that sends one RTP stream per RID (RFC 8853, highest quality first, as browsers order them), and
`Peer::write_simulcast(mid, rid, pt, wallclock, rtp_time, data)` writes one encoding's samples:
the application encodes each layer at its own resolution and bitrate. The offer lists the RIDs
(`a=rid`, `a=simulcast:send`); the answer's `a=simulcast:recv` decides which are sent (only the
first without it). Every encoding has its own SSRC and RTX stream, its packets carry the MID and
RID header extensions, and a keyframe request names its RID (`KeyframeRequest::rid`). As an
answerer the stack also accepts simulcast from the remote (`MediaData::rid` tells the layers
apart); picking which layer to forward is the application's job.

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

### TURN over TCP and TLS

`turn.stream()` is the acceptor for TCP listeners, and wrapped in `only::tls::Tls` for TLS ones
(`turns:`, usually port 5349 or 443): the same allocations, quotas and credentials as the UDP
listener. Relays stay UDP; TCP relays (RFC 6062) are not offered (`442`).

```rust,ignore
let engine = Arc::new(
    Engine::builder()
        .listen(Listener::udp("0.0.0.0:3478".parse()?).serve(turn.clone()))
        .listen(Listener::tcp("0.0.0.0:3478".parse()?).serve(turn.stream()))
        .listen(Listener::tcp("0.0.0.0:5349".parse()?).serve(Tls::server(tls_cfg, turn.stream())))
        .build()?,
);
turn.set_engine(&engine);
```

| Field | Default | Meaning |
|---|---|---|
| `stream_allocate_timeout` | 30 s | a connection that has not allocated by then is closed |
| `max_stream_queue` | 256 KiB | relayed data for a connection with more queued is dropped (it keeps datagram semantics; responses always go) |

An allocation made over a connection ends with it. STUN and ChannelData are framed on the stream
by their own lengths (`only_turn::framing::FrameReader`), ChannelData padded to four bytes.

### The TURN client

`only_turn::client::Client` is a sans-io client of one allocation, over UDP or a TCP/TLS stream
(`ClientConfig::stream(true)`): it answers the 401 challenge with long-term credentials, renews
stale nonces, refreshes the allocation, binds a channel to each peer on first `send_to` (falling
back to permissions and Send indications), refreshes those bindings while a peer is in use, and
retransmits over UDP. The caller moves bytes: `poll_transmit` to the server, `handle_input`
with what comes back (it returns relayed data as `(peer, payload)`), `handle_timeout` at
`poll_timeout`. Bounds: 64 peers, 64 KiB waiting for bindings. `Endpoint::gather_relay` drives
one over UDP.

## Not done yet

TCP relays (RFC 6062); TURN over TCP/TLS from an `Endpoint` (the client supports it, the
endpoint allocates over UDP); active ICE-TCP candidates and ICE-TCP on `RtcServer`; resolving
mDNS candidates (peers using them are still reached through peer-reflexive candidates);
simulcast layer selection; FEC; RTCP XR; DTLS 1.3. ADR-017 has the details of what was added.
