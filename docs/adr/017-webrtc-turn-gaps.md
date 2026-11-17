# ADR-017: TURN over TCP and TLS, a TURN client, ICE-TCP and simulcast sending

English | [简体中文](017-webrtc-turn-gaps.zh-CN.md)

Status: accepted (2026-11-17)

## Context

`docs/DEV-PLAN.md` left four WebRTC items open (M7 and wave D): TURN over TCP/TLS, a TURN client
so that `only-webrtc`'s `Endpoint` gathers relayed candidates, ICE over TCP, and simulcast
sending. Each of them is a reason a deployment cannot use `only` alone: networks that block UDP
reach a TURN server only over TCP or TLS on 443; a client behind a symmetric NAT needs a relay;
a server behind a UDP-hostile firewall needs ICE-TCP; an SFU feeding viewers of different
bandwidths needs simulcast from its publishers.

## Decision

### 1. TURN over TCP and TLS (`only-turn`)

- **`TurnServer::stream() -> TurnStream`**: the acceptor for TCP listeners, and for TLS ones
  through `only::tls::Tls` (`turns:`). It shares the server's state (allocations, quotas,
  nonce key, relays) with the UDP listener. Stream clients live in their own half of the
  shards, so the same address on UDP and on TCP names two clients and one cannot reach the
  other's allocation.
- **Framing (`only_turn::framing`)**: STUN messages and ChannelData back to back, each delimited
  by its own length; ChannelData padded to a multiple of four (RFC 8656 §12.5). `FrameReader`
  hands out messages that arrive whole without copying and holds at most one partial message
  (64 KiB); a first byte that is neither STUN nor ChannelData closes the connection.
  `TurnEnv::pads_channel_data` (a provided method, default `false`) tells `TurnCore` to pad
  ChannelData for a stream client.
- **Lifetime**: an allocation lives as long as its connection (RFC 8656 §3.1):
  `TurnCore::remove_client` frees it when the connection closes. A connection that has not
  allocated within `TurnConfig::stream_allocate_timeout` (30 s) is closed by the expiry sweep
  (rule 9).
- **Backpressure**: relays stay UDP; relayed data for a stream client (ChannelData, Data
  indications) is dropped while that connection has more than `TurnConfig::max_stream_queue`
  (256 KiB) queued, so a slow reader cannot pile up stale media; STUN responses always go.
  The other direction reads from the stream and sends datagrams, which never queue.
- **RFC 6062 TCP allocations: not implemented.** They relay to TCP peers (`CONNECT`,
  `CONNECTION-BIND`, one data connection per peer). WebRTC never asks for them (browsers and
  pion relay UDP over a TCP or TLS control connection, which is what this ADR adds), and they
  would add per-peer connection state, a second listener path and a connection-attempt
  lifecycle for no WebRTC use. `REQUESTED-TRANSPORT` TCP keeps getting `442`.

### 2. A TURN client (`only_turn::client`) and relayed candidates (`only-webrtc`)

- **`client::Client`** is a sans-io client of one allocation over UDP or a stream
  (`ClientConfig::stream`): the first Allocate unauthenticated, then long-term credentials from
  the 401 challenge, `438` renews the nonce, every success response to an authenticated request
  must carry a valid `MESSAGE-INTEGRITY`. Refresh a minute before the lifetime runs out;
  `send_to` installs a channel on first use (ChannelBind also installs the permission), falls back
  to a permission and Send indications when channels are off or refused, and refreshes each
  binding every 4 minutes while the peer is in use (permissions last 5); peers idle for 10
  minutes are forgotten. UDP requests are retransmitted (500 ms doubling, 7 sends, 39.5 s);
  over a stream a request is sent once and times out after 39.5 s. Bounds: `max_peers` (64),
  `max_pending` (64 KiB waiting for bindings, 16 datagrams per peer), channel numbers
  0x4000–0x4FFF. Events: `Allocated`, `Failed`, `PeerFailed`, `Closed`.
- **`Endpoint::gather_relay(server, username, password, timeout)`** allocates over the
  endpoint's own UDP socket (blocking, like `gather_srflx`) and adds the relayed candidate, and
  the server-reflexive address the server reported when it is new. One allocation serves every
  peer of the endpoint; at most 4 per endpoint (`Error::Turn` past that, or when the server
  refuses). Datagrams from the server are taken off the socket before peer routing and relayed
  data is delivered as if it had arrived on the relayed address; what a peer sends from the
  relayed address goes through the client. The client's timers run on the shared WebRTC timer
  thread. `Endpoint::close` deletes the allocations. Internally peer transmits now carry their
  source address (`Rtc` output), which is how a relayed or TCP pair is told from a UDP one.
- TURN over TCP/TLS **from `Endpoint`** is not wired in: the sans-io client supports it and is
  tested over both against `only`, pion/turn and coturn, but an `Endpoint` allocates over UDP.

### 3. ICE-TCP, passive candidates (`only-ice`, `only-webrtc`)

- `only-ice` candidates carry a transport: `TcpType::{Active, Passive, So}`, the `tcp ...
  tcptype` SDP syntax (an active candidate's port is 9), RFC 6544 local preferences (direction
  preference times 2^13 plus an IPv6-first other preference) and TCP type preferences below UDP's
  (host 90, as Chrome), and pairs only within a transport and between compatible types. A
  passive local candidate never starts checks: a check arriving over an accepted connection makes
  a peer-reflexive active remote candidate whose pair gets the triggered checks, nomination and
  consent. RFC 4571 framing in `only_ice::tcp`. `ParseError::Tcp` is gone (TCP lines parse);
  the crate is internal-tier.
- **`Endpoint::listen_tcp(&Arc<Engine>, addr)`** listens on a TCP port that differs from the UDP
  one and adds a passive host candidate. A dedicated thread accepts (blocking `accept`, never an
  I/O thread, rule 1) and adopts connections into the engine (`Engine::adopt_tcp`); at most 256
  at once. A connection's first frame must be a check naming one of the endpoint's peers within
  10 seconds, otherwise it is closed; then its frames go to that peer as datagrams from the
  connection's remote address, and what the peer sends from the candidate's address goes back
  framed, dropped past 1 MiB queued (datagram semantics: DTLS, SCTP and RTP recover). A closed
  peer closes its connections; `Endpoint::close` stops the listener.
- **Active and simultaneous-open local candidates are not implemented**: an `Endpoint` reached
  only over TCP is a server; clients behind UDP-blocking networks use TURN over TCP/TLS.

### 4. Simulcast sending (`only-webrtc`)

- **`SdpChanges::add_simulcast_media(kind, dir, rids, stream_id, track_id) -> Result<Mid,
  Error>`** (1 to 8 RIDs of letters, digits, `-` and `_`, at most 16 characters; a sending
  direction) and **`Peer::write_simulcast(mid, rid, pt, wallclock, rtp_time, data)`**. Each
  encoding is its own RTP stream with its own SSRC, RTX SSRC and packetizers; the application
  encodes each layer.
- SDP as browsers write it (RFC 8853): `a=rid:<id> send` and `a=simulcast:send a;b;c`, no
  `a=ssrc`. The answer's `a=simulcast:recv` decides which encodings are sent (paused `~` ones
  are not); without it only the first is sent. Samples for an encoding that is not sent are
  dropped; an unknown RID is `Error::UnknownMedia`.
- Packets carry the MID and RTP stream id extensions, retransmissions (RTX) the repaired
  stream id. Sender reports, report blocks, NACKs and PLI/FIR are per encoding;
  `KeyframeRequest::rid` names the encoding.
- As an answerer the stack also accepts a remote simulcast offer: the answer carries
  `a=rid:<id> recv` and `a=simulcast:recv`, received streams carry their RID
  (`MediaData::rid`), and unsignalled RTX is mapped to the stream of its repaired RID. Layer
  selection (forwarding one RID of several, as an SFU does) is left to the application.

## Consequences

- Public API (additive): `only_turn::{framing, client}` modules, `TurnServer::stream`,
  `TurnServer::stream_relay_of`, `TurnStream`, `TurnConfig::{stream_allocate_timeout,
  max_stream_queue}`, `TurnCore::remove_client`, `TurnEnv::pads_channel_data` (provided);
  `Endpoint::{gather_relay, listen_tcp}`, `Error::Turn` (the enum is `#[non_exhaustive]`),
  `SdpChanges::add_simulcast_media`, `Peer::write_simulcast`. Snapshots refreshed. The UDP
  datapath of `TurnServer` gains one branch per message sent to a client (the connection kind)
  and the shard table doubles (half for streams).
- New fuzz targets `turn_stream` (stream framing into the server, server messages into the
  client) and `ice_tcp` (RFC 4571 framing into an agent with a passive candidate); `webrtc_sdp`
  covers simulcast offers and answers and TCP candidates.
- Interop (`tools/interop/webrtc/run.sh`, `linux.sh`): pion/turn's client over UDP, TCP and TLS
  against `only-turn`; coturn's `turnutils_uclient` over UDP, TCP and TLS against `only-turn`;
  the `only_turn` client over UDP, TCP and TLS against pion/turn, coturn and `only-turn`; an
  `Endpoint` offering only relayed candidates (from `only-turn`, pion/turn and coturn) to pion;
  an `Endpoint` offering only its passive TCP candidate to pion with active TCP candidates only;
  simulcast h/m/l to pion, which receives three RID streams.
- Not done: RFC 6062, TURN over TCP/TLS from `Endpoint`, local active ICE-TCP candidates, ICE-TCP
  on `RtcServer`, layer selection, simulcast to Chrome in the browser test.
