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
  channels: reliable or not, ordered or not; I-DATA message interleaving when the peer offers
  it, so a large message does not hold up small ones on other channels, and channels sharing the
  association by weighted fair queueing on their priority, ADR-037) and `only-rtp` (RTP/RTCP, Opus, G.711, G.722, VP8,
  VP9, H.264, H.265 and AV1 packetization, a frame assembler, NACK and RTX, PLI/FIR, REMB, TWCC
  and bandwidth estimation, sender/receiver reports, RTCP XR, TMMBR / TMMBN, RFC 8888
  feedback and ULPFEC / FlexFEC / RED, which the peers negotiate when configured to; see "FEC and
  more RTCP" below). `only-webrtc` itself does SDP
  offer/answer (BUNDLE, rtcp-mux, codec and header-extension negotiation, renegotiation) and
  drives the peers with `only`'s I/O threads and one shared timer thread.
- `only-turn` has the STUN codec, a STUN server, a TURN server (RFC 8656 over UDP, TCP and TLS)
  and a sans-io TURN client.

Interop is tested against pion (Go) in both offer directions, for data channels and media,
directly and through a `only` TURN relay, with an `Endpoint` offering only relayed candidates
(on `only`, pion/turn and coturn TURN servers, allocated over UDP, TCP and TLS), only its passive
or only its active ICE-TCP candidate, pion reaching an `RtcServer` over ICE-TCP, and with
simulcast sent to pion; against fib's Go WebRTC (data channels, both directions); the TURN
server against the pion/turn client and coturn's `turnutils_uclient` over UDP, TCP and TLS; the
TURN client against pion/turn, coturn and `only` over UDP, TCP and TLS
(`tools/interop/webrtc/run.sh`, `COTURN=1` for coturn, `linux.sh` for all of it in Linux
containers). Headless
Chrome is tested in both offer directions: data channels, and its fake camera and microphone
echoed back by an `RtcServer` and decoded by Chrome; ICE-TCP only (Chrome to an `RtcServer`, an
`Endpoint` to Chrome); relay only (Chrome with `iceTransportPolicy: "relay"` through `only-turn`
over UDP, TCP and TLS, an `Endpoint` whose only candidates were allocated over TCP or TLS); and
simulcast: three VP8 layers from Chrome into an SFU, sent back as simulcast and as one selected
layer switched while Chrome decodes it (`tools/interop/webrtc/browser.sh`). pion negotiates
I-DATA with us; Chrome 157 uses DATA chunks unless its `WebRTC-DataChannelMessageInterleaving`
field trial is on (with it on, the same tests pass over I-DATA). The SCTP layer alone is also
checked against pion/sctp over UDP, with and without interleaving and loss
(`tools/interop/sctp/run.sh`).

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
| `request_layer_keyframe(mid, rid, kind)` | PLI or FIR to one received simulcast layer |
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

Networks that block UDP reach a TURN server over TCP, or TLS on port 443:
`gather_relay_via(&engine, &server, timeout)` takes a `RelayServer`, made with
`RelayServer::udp`, `tcp` or `tls(addr, server_name, tls_config, ..)`, or parsed from a URL as
browsers take it in `iceServers` (`turn:host[:port][?transport=udp|tcp]`,
`turns:host[:port]`; a `turns:` server then needs `tls_config`, since there are no default
roots). The engine dials the connection (it needs `client_threads(n)` or a TCP listener); the
allocation lives on it. A TCP- or TLS-allocated candidate ranks below a UDP-allocated one, and
gives no server-reflexive candidate. An allocation lost after it was made (the connection
closed, a refresh failed) is made again after 1 second, then doubling waits up to a minute:
the new relayed candidate replaces the old one for new peers and is added to the open ones,
which keep going if the other side is reachable from the relay (otherwise an ICE restart offers
it).

```rust,ignore
let turns = RelayServer::from_url("turns:turn.example.com:443", "alice", "secret")?
    .tls_config(tls_client_config);
let relayed = ep.gather_relay_via(&engine, &turns, Duration::from_secs(5))?;
```

`candidate_filter(f)` is the endpoint's `iceTransportPolicy`: new peers use, and signal, only
the local candidates `f` accepts, for example `|c| c.kind() == "relay"` (relay only) or
`|c| c.transport() == "tcp"` (ICE-TCP only).

### ICE over TCP

`listen_tcp(&engine, addr)` adds a passive ICE-TCP candidate (RFC 6544) on its own TCP port: a
browser or pion behind a network that blocks UDP connects to it with an active candidate and runs
ICE, DTLS, SCTP and SRTP over the connection (RFC 4571 framing). The engine needs TCP I/O threads
(`client_threads(n)` or a TCP listener). A dedicated thread accepts, at most 256 connections at
once; a connection whose first frame is not a connectivity check for one of the endpoint's peers
within 10 seconds is closed, and so are a peer's connections when it closes. TCP candidates rank
below UDP ones, so a peer that can use UDP still does.

`dial_tcp(&engine)` adds an active ICE-TCP candidate (the primary host address, port 9 as the
SDP writes it): to reach a server that only listens on TCP, the endpoint dials one connection per
candidate pair when the pair's first check goes out, and runs everything over it. A connection
that fails is dialed again by the next check; active and passive connections are bounded
together (256).

An `RtcServer` takes passive ICE-TCP too: `tcp_candidates(addrs)` puts passive TCP candidates in
its answers and offers, and `server.tcp()` is the acceptor for the engine's TCP listener at
those addresses, so browsers whose UDP is blocked connect to the server directly:

```rust,ignore
let server = RtcServer::new(vec![public_udp]).tcp_candidates(vec![public_tcp]);
let engine = Engine::builder()
    .listen(Listener::udp(udp_addr).serve(server.clone()))
    .listen(Listener::tcp(tcp_addr).serve(server.tcp()))
    .build()?;
```

The same rules hold (first check within 10 seconds, a peer's connections close with it); at most
twice `max_peers` connections.

### Simulcast

`SdpChanges::add_simulcast_media(kind, dir, &["h", "m", "l"], stream_id, track_id)` adds a line
that sends one RTP stream per RID (RFC 8853, highest quality first, as browsers order them), and
`Peer::write_simulcast(mid, rid, pt, wallclock, rtp_time, data)` writes one encoding's samples:
the application encodes each layer at its own resolution and bitrate. The offer lists the RIDs
(`a=rid`, `a=simulcast:send`); the answer's `a=simulcast:recv` decides which are sent (only the
first without it). Every encoding has its own SSRC and RTX stream, its packets carry the MID and
RID header extensions, and a keyframe request names its RID (`KeyframeRequest::rid`). As an
answerer the stack also accepts simulcast from the remote (`MediaData::rid` tells the layers
apart), as browsers publish it. An SFU forwarding one layer to a viewer picks it from
`MediaData::rid`, switches at a keyframe of the new layer, and asks the publisher for exactly
that one with `Peer::request_layer_keyframe(mid, rid, kind)` (the `sfu` mode of
`crates/only-webrtc/examples/webrtc-interop.rs` does this, rewriting RTP timestamps at a
switch). Chrome does not receive simulcast: its answer drops `a=simulcast`, and only the first
encoding is sent to it.

### FEC and more RTCP

Off by default (a default peer offers and answers exactly what it did before), each turned on in
the `RtcConfig` (ADR-039):

```rust,ignore
let cfg = only_webrtc::rtc_config()
    .enable_fec(Some(FecMechanism::FlexFec)) // or FecMechanism::Ulpfec (red + ulpfec)
    .set_fec_protection(0, 128)              // FEC per 256 media packets: bounds
    .enable_ccfb(true)                       // RFC 8888 feedback instead of transport-wide
    .enable_rtcp_xr(true)                    // XR receiver reference time / DLRR: receiver RTT
    .enable_tmmbr(true)                      // a=rtcp-fb ccm tmmbr
    .enable_bwe(None);
```

- **FEC** on video lines without simulcast. FlexFEC is libwebrtc's `flexfec-03`, a separate FEC
  stream signaled with `a=ssrc-group:FEC-FR` (Chrome needs the field trials
  `WebRTC-FlexFEC-03-Advertised/Enabled/WebRTC-FlexFEC-03/Enabled/`); ULPFEC travels in RED on
  the media stream, and browsers offer it by default. Received FEC repairs packets before the
  frame assembler and NACK (repaired packets are not NACKed, but receiver reports still count
  them as lost, as Chrome's do). Sent video is protected at three times the loss before repair
  (the reported loss, or the share of packets the receiver had retransmitted), within the bounds
  of `set_fec_protection`; a `min` above 0 protects from the start.
- **RFC 8888**: when both sides offer `ack ccfb`, received media is acknowledged with RFC 8888
  feedback instead of transport-wide feedback and the bandwidth estimator runs on it; Chrome
  needs `WebRTC-RFC8888CongestionControlFeedback/Enabled,offer:true/`.
- **RTCP XR** (`a=rtcp-xr:rcvr-rtt=all`): a line that only receives still learns its RTT (from
  the sender's DLRR), which paces its NACKs.
- **TMMBR**: `Peer::request_max_bitrate(mid, Some(bps))` asks the remote sender for at most
  `bps` (repeated with every report until `None`); Chrome follows it. Requests about our streams
  are answered with TMMBN and cap the bandwidth estimate, like REMB.

`tools/interop/webrtc/fec.sh` checks all of it against headless Chrome: with one RTP packet in
20 dropped each way and NACK removed, Chrome decodes 381–392 of 400 echoed frames with FEC and 8
without.

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

TCP relays (RFC 6062); TURN over DTLS; simultaneous-open ICE-TCP (`tcptype so`); resolving
mDNS candidates (peers using them are still reached through peer-reflexive candidates); FEC on
simulcast lines and for audio (Opus RED), libwebrtc's FEC mask tables; DTLS 1.3 for WebRTC by
default; DTLS 1.3 0-RTT and NewConnectionId. ADR-017, ADR-032 and ADR-039 have the details of
what was added.
