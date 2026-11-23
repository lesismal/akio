# WebRTC, STUN and TURN

Two crates:

- `akio-webrtc` runs WebRTC peers on `akio` UDP sockets, on an in-house sans-io stack with no
  third-party dependencies (DEV-PLAN wave D), one crate per layer, all `#![forbid(unsafe_code)]`
  on `akio-crypto`: `akio-ice` (ICE full agent and ICE-lite, checklists, nomination, role
  conflicts, peer-reflexive candidates, trickle, restarts, consent freshness), `akio-dtls`
  (DTLS 1.3 falling back to 1.2, with certificate fingerprint verification and DTLS-SRTP keys; see below),
  `akio-srtp`
  (SRTP/SRTCP with AES-CM-HMAC-SHA1-80/32 and AEAD-AES-128/256-GCM, replay protection; the
  crate also has AES-192/256-CM, NULL, MKIs and re-keying, cryptex and RFC 6904 header
  extension encryption, which the peers do not negotiate in SDP yet),
  `akio-sctp` (SCTP over DTLS with congestion control, PR-SCTP, stream reset, DCEP data
  channels: reliable or not, ordered or not; I-DATA message interleaving when the peer offers
  it, so a large message does not hold up small ones on other channels, and channels sharing the
  association by weighted fair queueing on their priority, ADR-037; HEARTBEATs on idle
  associations, peer restarts and RFC 9653 zero checksums, ADR-042) and `akio-rtp` (RTP/RTCP, Opus, G.711, G.722, VP8,
  VP9, H.264, H.265 and AV1 packetization, a frame assembler, NACK and RTX, PLI/FIR, REMB, TWCC
  and bandwidth estimation, sender/receiver reports, RTCP XR, TMMBR / TMMBN, RFC 8888
  feedback and ULPFEC / FlexFEC / RED, which the peers negotiate when configured to; see "FEC and
  more RTCP" below). `akio-webrtc` itself does SDP
  offer/answer (BUNDLE, rtcp-mux, codec and header-extension negotiation, renegotiation) and
  drives the peers with `akio`'s I/O threads and one shared timer thread.
- `akio-turn` has the STUN codec, a STUN server, a TURN server (RFC 8656 over UDP, TCP and TLS)
  and a sans-io TURN client.

Interop is tested against pion (Go) in both offer directions, for data channels and media,
directly and through a `akio` TURN relay, with an `Endpoint` offering only relayed candidates
(on `akio`, pion/turn and coturn TURN servers, allocated over UDP, TCP and TLS), only its passive
or only its active ICE-TCP candidate, pion reaching an `RtcServer` over ICE-TCP, and with
simulcast sent to pion; against fib's Go WebRTC (data channels, both directions); the TURN
server against the pion/turn client and coturn's `turnutils_uclient` over UDP, TCP and TLS; the
TURN client against pion/turn, coturn and `akio` over UDP, TCP and TLS
(`tools/interop/webrtc/run.sh`, `COTURN=1` for coturn, `linux.sh` for all of it in Linux
containers). Headless
Chrome is tested in both offer directions: data channels, and its fake camera and microphone
echoed back by an `RtcServer` and decoded by Chrome; ICE-TCP only (Chrome to an `RtcServer`, an
`Endpoint` to Chrome); relay only (Chrome with `iceTransportPolicy: "relay"` through `akio-turn`
over UDP, TCP and TLS, an `Endpoint` whose only candidates were allocated over TCP or TLS); and
simulcast: three VP8 layers from Chrome into an SFU, sent back as simulcast and as one selected
layer switched while Chrome decodes it; an `Endpoint` with aggressive nomination; and an
`Endpoint` that hides its host address behind an mDNS name offering to a Chrome that does the
same (its default), each resolving the other's name, host to host, over IPv4 and over IPv6
(`tools/interop/webrtc/browser.sh`). pion negotiates
I-DATA with us; Chrome 157 uses DATA chunks unless its `WebRTC-DataChannelMessageInterleaving`
field trial is on (with it on, the same tests pass over I-DATA). The SCTP layer alone is also
checked against pion/sctp over UDP, with and without interleaving, loss and zero checksums
(`tools/interop/sctp/run.sh`). Headless Firefox (usrsctp) is tested in both offer directions
over WebDriver BiDi: data channel echoes, large messages, a long idle spell during which the
SCTP HEARTBEATs keep the association up, and a channel closed by Firefox and opened again
(`tools/interop/webrtc/firefox.sh`).

## A server, a TURN server and a client on one engine

```rust,ignore
{{#include ../../../../crates/akio-webrtc/examples/guide-webrtc.rs:engine}}
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

The API uses `akio`'s own types: `ChannelId`, `ChannelConfig`, `Mid`, `Pt`, `Codec`,
`MediaKind`, `Direction`, `MediaTime` / `Frequency`, `MediaData`, `MediaAdded`, `RtpPacket`,
`KeyframeRequest`, `Candidate`, `IceConnectionState`, `RtcConfig`, `SdpChanges`, `Event`. The
protocol crates underneath are internal (their APIs may change in any release) and do not
appear in it. The `unstable` cargo feature is kept for APIs outside the semver promise and adds
nothing today (it used to expose str0m).

## Peers and handlers

```rust,ignore
{{#include ../../../../crates/akio-webrtc/examples/guide-webrtc.rs:handler}}
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
{{#include ../../../../crates/akio-webrtc/examples/guide-webrtc.rs:client}}
```

```rust,ignore
{{#include ../../../../crates/akio-webrtc/examples/guide-webrtc.rs:endpoint}}
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

`RelayServer::dual_allocation(true)` makes it a dual allocation (ADR-083): one relayed
candidate per family, so an endpoint reaching the server over IPv4 can still be reached from
IPv6-only peers through the server's IPv6 relay. It is off by default (ADR-091): the allocation
serves every peer of the endpoint, so the second port stays taken on the server for the
endpoint's life, and it only helps against peers with IPv6 candidates and no IPv4 path.

```rust,ignore
let turns = RelayServer::from_url("turns:turn.example.com:443", "alice", "secret")?
    .tls_config(tls_client_config);
let relayed = ep.gather_relay_via(&engine, &turns, Duration::from_secs(5))?;
```

TURN over DTLS (RFC 7350) keeps UDP and encrypts the control channel:
`RelayServer::dtls(addr, server_name, tls_config, ..)` or `turns:host[:port]?transport=udp`
(then `tls_config`). The allocation runs inside a DTLS association (DTLS 1.3, falling back to
1.2 as coturn speaks it) on the endpoint's own UDP socket, the server's certificate checked
against the TLS configuration's roots for `server_name`; the candidate is a UDP relayed one, and
the server's mapped address becomes a server-reflexive candidate as with plain UDP. A lost
association loses the allocation, which is made again with a new handshake.

```rust,ignore
let dtls = RelayServer::from_url("turns:turn.example.com:5349?transport=udp", "alice", "secret")?
    .tls_config(tls_client_config);
let relayed = ep.gather_relay_via(&engine, &dtls, Duration::from_secs(5))?;
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

`listen_tcp_so(&engine, addr)` adds a simultaneous-open candidate (`tcptype so`), which pairs
with the remote's `so` candidates: both sides connect at once between the two advertised ports.
The port listens (`SO_REUSEPORT`) and the checks are dialed from it (`Engine::dial_from`), so
whichever connect arrives first, one connection results: crossing SYNs make a TCP simultaneous
open, otherwise the listener accepts the other side's and our checks go over that one. Browsers
and pion have no `so` candidates (libnice has); between two `Endpoint`s it works anywhere a
direct TCP connection does.

### mDNS candidates

Browsers do not show their host addresses: a page without camera or microphone permission gets
host candidates like `candidate:1 1 udp 2113937151 1f3c...-9a.local 54321 typ host`, and the
browser answers multicast DNS queries (RFC 6762) for that name on the local network. Without a
resolver such candidates are skipped, and an `Endpoint` reaches a browser on the same LAN only
when the browser's checks reach it first.

```rust,ignore
let ep = Endpoint::bind(&engine, "0.0.0.0:0".parse()?)?;
ep.resolve_mdns(&engine, Duration::from_secs(5))?; // resolve the browsers' .local names
ep.conceal_host_candidates()?;                      // and write ours as .local names too
```

`resolve_mdns` opens a socket on the mDNS port 5353, shared with the system's responder
(`Engine::bind_udp_multicast`, a member of `224.0.0.251`; when the port cannot be bound, an
ephemeral one asking for unicast answers), served by an engine I/O thread like the endpoint's
own. Each `.local` candidate, in a description or trickled through `add_remote_candidate`, is
queried at once and again after 1 and 2 seconds, then every 2 seconds until the timeout; the
answer gives the peer the candidate with the address. Answers, and the announcements browsers
send when they make a name, are cached for their TTL. `conceal_host_candidates` makes new peers
signal every host candidate under a random `<uuid>.local` name (one per address) and hide the
related address of the others (`0.0.0.0:0`); the socket answers queries for those names, so a
browser or another endpoint can resolve them.

IPv6 runs next to IPv4 (ADR-054): a second socket on `[::]:5353` joins `ff02::fb` on every
interface with a link-local address (`Engine::bind_udp_multicast_on`), queries go out on each of
them, and an answer goes back on the link its query came from. IPv6 host addresses are
concealed like IPv4 ones (AAAA records). SDP carries no scope id, so the endpoint remembers the
interface of a remote link-local address (from the answer that resolved it, or from its
traffic) and puts it back on what it sends. A host without IPv6 runs IPv4 only.
IPv6 answers leave with hop limit 255 as RFC 6762 asks (ADR-078; the engine's IPv6 multicast
bindings set it), and either family can answer: on an IPv6-only link, where `224.0.0.251` has
no route, `conceal_host_candidates` answers over `ff02::fb` alone. `tools/interop/webrtc/mdns6.sh`
checks this in an IPv6-only container against avahi, and `browser.sh` against Chrome with an
endpoint whose only host candidate is a concealed IPv6 address.

Concealed names are claimed as RFC 6762 asks (ADR-078's updates): after a random delay of up to
250 ms, three probes 250 ms apart,
then two announcements 1 s apart, all while the name is already in use and answered. If another
host answers the name with another address, or wins a simultaneous probe, the endpoint gives the
name up and new peers get a fresh one. Closing the endpoint withdraws its names (goodbyes with
TTL 0), and unicast answers leave with hop limit 255 like multicast ones. A link-local IPv6
address is claimed and answered on its own link only.

### Nomination

The controlling side (the offerer, or any side facing an ICE-lite remote) nominates one pair:
the best that works, once nothing better is still being checked. Two more modes are opt-in in
`RtcConfig`: `enable_ice_aggressive_nomination(true)` puts USE-CANDIDATE on every check (the
first pair that works is used at once, a better one replaces it), and
`enable_ice_renomination(true)` offers `a=ice-options:renomination`; when the remote does too,
checks of better pairs go on after nomination and a better pair that works later (a candidate
trickled late, say) is nominated again with a higher NOMINATION value. Whatever its own
configuration, a controlled peer follows the highest NOMINATION value it receives, or without
one the best nominated pair.

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
`crates/akio-webrtc/examples/webrtc-interop.rs` does this, rewriting RTP timestamps at a
switch). Chrome does not receive simulcast: its answer drops `a=simulcast`, and only the first
encoding is sent to it.

### FEC and more RTCP

Off by default (a default peer offers and answers exactly what it did before), each turned on in
the `RtcConfig` (ADR-039, ADR-048):

```rust,ignore
let cfg = akio_webrtc::rtc_config()
    .enable_fec(Some(FecMechanism::FlexFec)) // or Ulpfec (red + ulpfec), Red (red, no FEC)
    .set_fec_protection(0, 128)              // FEC per 256 media packets: bounds
    .set_fec_mask(FecMask::Random)           // libwebrtc's mask tables: Random or Bursty
    .enable_opus_red(Some(1))                // Opus RED, one redundant packet (at most 2)
    .enable_audio_red(Some(1))               // RED for PCMU, PCMA and G.722 (red/8000)
    .enable_ccfb(true)                       // RFC 8888 feedback instead of transport-wide
    .enable_rtcp_xr(true)                    // XR receiver reference time / DLRR: receiver RTT
    .enable_rtcp_xr_blocks(XrBlocks::ALL)    // XR loss / duplicate RLE, receipt times, VoIP metrics
    .set_ulpfec_level0(Some(120))            // ULPFEC levels: only toward peers that are this stack
    .enable_tmmbr(true)                      // a=rtcp-fb ccm tmmbr
    .enable_bwe(None);
```

- **FEC** on video lines. FlexFEC is libwebrtc's `flexfec-03`, a separate FEC
  stream signaled with `a=ssrc-group:FEC-FR` (Chrome needs the field trials
  `WebRTC-FlexFEC-03-Advertised/Enabled/WebRTC-FlexFEC-03/Enabled/`); ULPFEC travels in RED on
  the media stream, and browsers offer it by default. On a simulcast line each encoding has its
  own FEC at its own loss: ULPFEC in the encoding's RED stream (what Chrome sends), or a FlexFEC
  stream per encoding, which is not signaled (RID simulcast names no SSRCs) but carries the MID and
  the RID it repairs, so only peers that are this stack use it. Received FEC repairs packets
  before the frame assembler and NACK (repaired packets are not NACKed, but receiver reports
  still count them as lost, as Chrome's do); a packet FEC could only rebuild in part (ULPFEC
  levels) is handed to the depacketizer once a later frame arrives, and its frame comes with
  `contiguous: false`. Groups are protected as libwebrtc protects them (ADR-073): its mask tables
  for groups of up to 12 packets, and its protection policy, which takes the loss before repair
  (the reported loss, or the share of packets the receiver had retransmitted; the maximum of the
  last 10 s), the bits per frame and, when the receiver NACKs, the round-trip time: no FEC on
  delta frames below 20 ms of RTT, groups spanning more frames as the RTT grows, none for small
  frames below 200 ms. Key frames get more. `set_fec_protection` bounds the factors; a `min`
  above 0 protects from the start.
- **RED for other codecs** (`enable_audio_red`): `red/8000` for PCMU, PCMA and G.722, listed
  before each codec, with up to two earlier packets in each. `FecMechanism::Red` sends video in
  RED without FEC packets (and `red` without `ulpfec` from a peer is accepted either way).
- **Opus RED** (RFC 2198, `red/48000/2`): `enable_opus_red(Some(n))` lists RED *before* Opus,
  because libwebrtc sends RED only to a peer that lists it first (Chrome's own offers put it
  after Opus). Received RED is split: a redundant copy stands in for a lost packet (copies of
  packets that arrived are dropped); sent Opus carries the `n` previous packets (`Some(0)` sends
  plain Opus but still takes RED).
- **RFC 8888**: when both sides offer `ack ccfb`, received media is acknowledged with RFC 8888
  feedback instead of transport-wide feedback and the bandwidth estimator runs on it; Chrome
  needs `WebRTC-RFC8888CongestionControlFeedback/Enabled,offer:true/`. The reports carry the
  ECN codepoint each packet arrived with (the UDP backends read it); on the sending side a
  packet reported CE counts as lost for the estimator. This side marks its own RTP when asked
  (next section).
- **ECN-capable RTP** (ADR-077, `set_ecn_marking(EcnMarking::Ect1)` or `Ect0`): with RFC 8888
  in use and the estimator on, RTP leaves ECT(1) / ECT(0) once the path has shown the marks get
  through: one packet in four while unknown, every one after ten marked packets came back with
  their mark (RFC 6679 §7.2). A report showing a mark cleared or changed, or marked packets lost
  where unmarked ones are not, stops marking on that path (a new ICE pair or latched address
  starts over). RTCP, STUN, DTLS and SCTP are never marked. Chrome 157 receives ECT(1) (its
  `packetsReceivedWithEct1`) and validates the path; Chrome does not mark what it sends
  (`tools/interop/webrtc/ecn.sh`, which also shows a proxy that clears the codepoint ending it).
- **How CE is answered** (ADR-082): ECT(0) gets the classic response, where CE counts as loss.
  ECT(1) is L4S (RFC 9331), so its CE marks get a scalable response:
  - The fraction of CE marks per round trip is smoothed with gain 1/16.
  - A round with fresh marks cuts the rate by half that fraction, at most once per window.
  - A clean round adds to the rate slowly.
  - While marking ECT(1), pacing runs at 1.5 times the estimate with 1 ms bursts, because an
    L4S queue marks a frame sent in one burst at any rate.

  Through a simulated 6 Mbps L4S queue, ECT(1) reaches 4.9 Mbps with 1.3 ms of queueing, and
  ECT(0) only 1.36 Mbps. `akio_rtp::BandwidthEstimator::set_ecn_response` selects the response
  for other uses.
- **ECN without RFC 8888** (RFC 6679's own signalling, ADR-082): with marking on, the sections
  also offer `a=ecn-capable-rtp:rtp mode=setread; ect=N`, `nack ecn` and `a=rtcp-xr:ecn-sum`.
  - A remote that answers them reports per-source counters, in the RTCP ECN feedback message
    and the XR ECN summary. Those drive validation and the CE response, with transport-wide
    feedback driving the estimator.
  - Receiving works the same way when both sides opt in.
  - Browsers ignore the attributes.
- **How a path starts marking** (ADR-086). RFC 6679 has three initiation methods, offered in
  this order and answered with the first the offer lists:
  - `ice`, only with ICE and a full agent (`a=ice-options` then carries `rtp+ecn`): once ICE
    selects the pair, one ECN-marked STUN check goes out. The remote's answer says which
    codepoint arrived (the ECN-CHECK attribute). Nothing is marked before that: then every
    packet, or none if the mark did not arrive.
  - `rtp`: the probing above.
  - `leap`: every packet marked from the start, for paths known to carry ECN. It is offered
    (first) only with `set_ecn_initiation(EcnInitiation::LeapOfFaith)`, which also applies
    without RFC 6679.

  Each method still ends marking on a path that clears, re-marks or drops the marks. The
  remote's `ect=` picks the codepoint (and so the CE response): an RFC 6679 peer that wants
  ECT(0) gets ECT(0) even from an `Ect1` configuration.
- **Retrying** (ADR-086): a failed path tries again after 10 s, then 20, 40, ... up to 5
  minutes. After three fallbacks from full marking on the same path it stays unmarked.
  `tools/interop/webrtc/ecn6679.sh` runs the three methods, and a router that clears ECN and
  then stops, between two akio peers over a Linux NAT.
- **TURN and TCP paths** (ADR-082): over a UDP allocation the datagram to the TURN server
  carries the codepoint. RFC 8656 §12 asks the server to copy it, and validation finds out
  whether it does. A relay that clears it fails the path like any other middlebox. Paths over
  ICE-TCP or over TURN reached by TCP / TLS have no codepoint to carry, so ECN stays off there
  rather than failing. akio-turn's own relay copies the codepoint both ways over UDP and DTLS
  (ADR-083), so validation passes through it.
- **RTCP XR** (`a=rtcp-xr:rcvr-rtt=all`): a line that only receives still learns its RTT (from
  the sender's DLRR), which paces its NACKs.
- **XR blocks about received streams** (ADR-058, `pkt-loss-rle pkt-dup-rle pkt-rcpt-times
  voip-metrics`): a block goes out when both sides list its format, once a second per received
  stream, about the sequence numbers since the last report (thinned to fit a datagram); VoIP
  metrics on audio lines only, with the loss, burst and gap fields measured, the round-trip
  time, and the R factor, MOS-LQ and MOS-CQ of the E-model (ITU-T G.107; wideband codecs with
  G.107.1, fullband ones with G.107.2; ADR-085, ADR-087) from the loss, its burstiness, the round
  trip and the end system delay, with the received codec's G.113 planning values at its measured
  bitrate (`EModel::for_codec_rate`: PCMU, PCMA, G.722, G.729, G.723.1, AMR-WB, EVS, and Opus,
  which has no ITU-T value: rated fullband by bitrate with P.863-derived values) and its
  concealment in the receiver configuration. What only the application knows, since it decodes and plays the audio, it
  gives with `set_voip_quality`; the rest is sent unavailable (127). Received ones arrive as
  `XrReceipts` and `VoipMetrics` events (`metrics.quality()` decodes the latter), with totals in
  the statistics.

  ```rust,ignore
  use akio_rtp::{JitterBufferConfig, VoipQuality, pcm_level_dbm0};

  // After decoding: speech level over talkspurts, the jitter buffer as it stands.
  peer.set_voip_quality(mid, VoipQuality {
      signal_level: pcm_level_dbm0(&talkspurt),
      noise_level: pcm_level_dbm0(&silence),
      jitter_buffer: Some(JitterBufferConfig {
          adaptive: true,
          rate: 4,
          nominal: Duration::from_millis(60),
          maximum: Duration::from_millis(120),
          abs_max: Duration::from_millis(500),
      }),
      ..VoipQuality::default()
  }, None)?; // None: the received codec's E-model values
  ```
- **Audio jitter buffer** (ADR-087): `set_audio_jitter_buffer(Some(PlayoutDelay::default()))`
  holds each received audio stream in a jitter buffer.
  - Frames reach `on_media_data` in order, each at its playout instant (`d.playout_time`), so
    the application can play them as they come.
  - The delay adapts to the measured jitter (the 95th percentile, 0 to 500 ms by default,
    shorter at talkspurts) or is fixed (`PlayoutDelay::fixed`).
  - A missing frame is given up when a later one is due, which then comes with
    `contiguous = false`: the cue to conceal. A packet arriving after that is discarded.
  - The buffer's delay and discards fill the jitter buffer and discard fields of the VoIP
    metrics, unless `set_voip_quality` gives the application's own.
  - `Peer::jitter_buffer_stats(mid)` gives its counters.
  - Video and RTP mode are not affected. `akio_rtp::JitterBuffer` is the same buffer for use
    without a peer.

  ```rust,ignore
  use akio_rtp::PlayoutDelay;

  let cfg = rtc_config().set_audio_jitter_buffer(Some(PlayoutDelay::adaptive(
      Duration::from_millis(20), Duration::from_millis(300))));
  // In the handler: d.playout_time is Some(when) for audio; !d.contiguous after a gap.
  ```
- **ULPFEC levels** (RFC 5109 §5): with `set_ulpfec_level0(Some(l0))` the FEC packets of a frame
  protect the first `l0` bytes of each packet and one more level covers the rest once: a single
  loss is repaired whole for far fewer repair bytes. libwebrtc reads level 0 only (Chrome would
  rebuild long packets wrongly), so leave it off toward browsers.
- **TMMBR**: `Peer::request_max_bitrate(mid, Some(bps))` asks the remote sender for at most
  `bps` (repeated with every report until `None`); Chrome follows it. Requests about our streams
  are answered with TMMBN and cap the bandwidth estimate, like REMB.

`tools/interop/webrtc/fec.sh` checks all of it against headless Chrome: with one RTP packet in
20 dropped each way and NACK removed, Chrome decodes 381–397 of 400 echoed frames with FEC and 8-15
without; with 10 % loss each way Chrome conceals 2-3 % of its audio with Opus RED both ways and
20 % without; Chrome's three simulcast layers come with ULPFEC per layer, which repairs them.
`browser.sh` sends our simulcast line with ULPFEC per encoding to Chrome through 5 % loss and no
NACK: Chrome decodes every frame of it, and next to none without FEC.

### Header protection: cryptex and encrypted extensions

```rust,ignore
let cfg = akio_webrtc::rtc_config()
    .enable_cryptex(true)                     // a=cryptex (RFC 9335)
    .enable_encrypted_header_extensions(true); // RFC 6904 extmaps
```

RTP header extensions (MID, RID, audio level ...) and CSRCs are in the clear under plain SRTP.
With **cryptex** both sides signal `a=cryptex` (at session level, as Chrome writes it) and every
packet's extension block and CSRCs are encrypted; received cryptex is decrypted whenever this
side offered or accepted it. Chrome 157 offers it when the page sets
`RTCConfiguration.rtpHeaderEncryptionPolicy` (behind `--enable-experimental-web-platform-features`),
and with "require" refuses a peer without it. **RFC 6904** encrypts chosen extension values
instead: the offer adds `a=extmap:<id> urn:ietf:params:rtp-hdrext:encrypt <uri>` variants (audio
level, MID, RID, repaired RID, video orientation, playout delay, on free one-byte ids), and an
answer takes the encrypted variant of whatever is offered both ways. No browser offers RFC 6904,
so it is for peers like this one. MKIs with DTLS-SRTP travel in the handshake (RFC 5764
§4.1.3, ADR-082). With `set_dtls_srtp_mki_length(4)`, as the DTLS client this side offers a
4-byte MKI in `use_srtp`, and as the server it agrees to the client's. Every SRTP and SRTCP
packet then carries it. Browsers answer with an empty MKI, and SRTP runs without one.

### SDES-SRTP for SIP gateways

```rust,ignore
let ep = ep.config(|| akio_webrtc::rtc_config().enable_sdes_srtp(true));
```

SIP gateways often key SRTP with SDP security descriptions (RFC 4568) instead of DTLS-SRTP. With
`enable_sdes_srtp(true)` offers carry `RTP/SAVPF` sections with an `a=crypto` line per suite
(AEAD-AES-256/128-GCM, AES-256-CM and AES-128-CM with HMAC-SHA1-80, AES-128-CM with
HMAC-SHA1-32), each with a random key, and no fingerprint; an SDES offer (`RTP/SAVP` or
`RTP/SAVPF` with `a=crypto`) is answered with the first line this side can use and a key of its
own. Each side encrypts with its own key and decrypts with the other's; the peer connects once
ICE has a pair. The keys are only as secret as the signalling. Lines with MKIs (`|1:4`) and
several master keys are taken, and our answer's key then has an MKI of the same length;
`set_sdes_mki_length(4)` puts MKIs in our offers. Session parameters other than the window size
hint (`WSH=`) make a line unusable. DTLS-SRTP offers are still answered with DTLS-SRTP, so
browsers never see `a=crypto`.

Data channels can sit next to SDES media: the application section carries `a=fingerprint` and
`a=setup`, DTLS runs there for SCTP only, and the media keeps its SDP keys (ADR-072).

Many gateways do not do ICE at all. A remote SDP without `a=ice-ufrag` is taken as plain media:
RTP goes to its `c=` address and `m=` port, RTCP to `a=rtcp` (or the next port), and the answer
carries our host address and port the same way. `enable_ice(false)` makes our offers plain too:

```rust,ignore
let ep = ep.config(|| {
    akio_webrtc::rtc_config()
        .enable_sdes_srtp(true)
        .enable_ice(false)
        .set_rtcp_mux_policy(RtcpMuxPolicy::Off) // RTCP on the RTCP socket's port
});
```

Without ICE nothing checks the path: by default the remote must be reachable at the address it
wrote (ADR-072). A phone behind a NAT writes its private address and sends from the NAT's
mapping; latching (symmetric RTP, "comedia", ADR-077) follows it:

```rust,ignore
.set_latching(Latching::Once)                              // the first authenticated source
.set_latching(Latching::Rebind(Duration::from_secs(2)))    // and again after 2 s of silence
```

A datagram from an address the endpoint does not know is tried against the SRTP keys of the
peers that may still latch; one that authenticates (and is not a replay) is received and moves
the transport (RTP, and RTCP on its own port separately) to its source. Forged or replayed
packets move nothing.

With DTLS-SRTP the handshake latches first (ADR-082). When latching, this side answers an
`actpass` offer with `passive`, so the phone starts the handshake:

- Its ClientHello from the NAT's mapping first gets a stateless cookie exchange, which proves
  the address receives.
- The pair then moves there tentatively. It stays only if the handshake completes with the
  certificate the SDP's fingerprint names.
- A failed, closed or stalled (4 s) handshake moves the pair back, and the peer lives on.

RTCP's own handshake, without rtcp-mux, latches the same way on its own port (ADR-086).

When this side must be the DTLS client (the phone said `passive`), its ClientHello would go to
the private address. Instead, a datagram from an unknown source on the transport's port, such
as the phone's keepalive or a STUN request, starts the handshake toward that source
tentatively. The same fingerprint check decides (ADR-086). Phones built on this stack send such
keepalives with `set_plain_keepalive(Duration::from_secs(15))` (RFC 6263): a STUN Binding
Indication on every path. They also keep NAT bindings open through silence.

`tools/interop/webrtc/latch.sh` runs a SIP-style phone behind an iptables NAT in a network
namespace: with SDES and with DTLS-SRTP, including a NAT rebinding, RTCP on its own port, and
the gateway as the DTLS client.

### RTCP on its own port (no rtcp-mux)

```rust,ignore
let ep = Endpoint::bind(&engine, "0.0.0.0:5004".parse()?)?;
ep.bind_rtcp(&engine, "0.0.0.0:5005".parse()?)?; // ICE component 2
let ep = ep.config(|| akio_webrtc::rtc_config().set_rtcp_mux_policy(RtcpMuxPolicy::Negotiate));
```

Browsers and pion always multiplex RTP and RTCP (rtcp-mux, BUNDLE), and so does a default peer.
SIP endpoints and older RTP stacks may not: their offer has no `a=rtcp-mux` and they send RTCP
to a port of its own (RFC 5761, `a=rtcp`). An `Endpoint` with an RTCP socket answers them with
`a=rtcp` and runs ICE with two components (ADR-055): RTP on component 1, RTCP on component 2,
each with its selected pair. DTLS-SRTP runs one handshake per component (RFC 5764: SRTCP keyed
by component 2's), SDES-SRTP keys both from the SDP; the peer is connected once both
components are. Offers with `a=rtcp-mux` are answered with it as before. Our offers say what
`set_rtcp_mux_policy` asks: `Require` (default) rtcp-mux only, `Negotiate` rtcp-mux plus `a=rtcp`
and component-2 candidates (the answer decides), `Off` no rtcp-mux. There is no BUNDLE without
rtcp-mux (RFC 8843 §9.1), so a session with several sections needs one transport per section
(next section). Bind the RTCP socket before gathering: `gather_srflx` and `gather_relay` then
also gather component 2's server-reflexive and relayed candidates from it. An `RtcServer` gets a
second listener for component 2:

```rust,ignore
let server = RtcServer::new(vec![main]).rtcp_candidates(vec![rtcp]);
Engine::builder()
    .listen(Listener::udp(main).serve(server.clone()))
    .listen(Listener::udp(rtcp).serve(server.rtcp()))
```

### Without BUNDLE: a transport per section

```rust,ignore
let ep = ep.config(|| akio_webrtc::rtc_config().set_bundle_policy(BundlePolicy::Disabled));
ep.bind_transport_socket(&engine, "0.0.0.0:0".parse()?)?; // optional: one per extra section
```

By default the sections of a session share one transport (BUNDLE). A peer that does not bundle
gets one per section: an offer without `a=group:BUNDLE`, an answer that leaves ours out, or our
own offers with `BundlePolicy::Disabled` (which also refuse a remote's group). Each section then
has its own ICE agent (its own credentials and candidates in the SDP), DTLS association, SRTP
keys and, without rtcp-mux, RTCP component; media, RTCP and SCTP go out on their section's
transport, and `on_connected` fires once all of them are up. Chrome with
`bundlePolicy: "max-compat"` works this way in both directions (`tools/interop/webrtc/bundle.sh`).
The transports share the endpoint's socket unless `bind_transport_socket` gives them their own;
they are then told apart by the remote's addresses, which a peer that does not bundle always
has one of per section. Congestion control feedback (transport-cc, RFC 8888) is negotiated as
with BUNDLE and one estimator and pacer serve every transport (ADR-077): RFC 8888 runs per
transport; transport-wide sequence numbers follow the remote's numbering, one space over all
transports as libwebrtc numbers them (Chrome's, checked in `bundle.sh`), or one per transport
when the remote numbers that way; paced packets leave on their own transport. Trickled
candidates name their section with
`Peer::add_remote_candidate_in(mid, candidate)`.

### Data channel priorities

```rust,ignore
let ch = api.add_channel_with_config(&ChannelConfig::new("video-meta").with_priority(ChannelPriority::High));
let ep = ep.config(|| akio_webrtc::rtc_config().set_sctp_scheduler(ChannelScheduler::Priority));
```

A channel's priority goes to the peer in the DCEP open message (128, 256, 512 or 1024; a
remote channel's is `Peer::channel_priority`) and decides how the SCTP stream scheduler shares
the association among channels with data queued: by default weighted fair queueing (a channel
gets bytes in proportion to its priority value), or strict priority, round robin, round robin
per packet, fair capacity or first come first served. `Peer::set_channel_priority` changes this
side's weighting later (DCEP has no update message). Chrome 157 has no
`RTCDataChannel.priority` and sends 256.

### Bandwidth probing

With `enable_bwe` the estimator probes the path (ADR-050), as libwebrtc does: short clusters
(15 ms or more) of RTX copies of recently sent video, paced at a target rate, whose feedback
(transport-wide or RFC 8888) shows what the path delivers. It probes at 3 and 6 times the start
rate as soon as media flows and doubles while results keep up, every 5 s while the encoder sends
well below the estimate, after a large drop of the estimate, and from scratch when ICE moves to
another pair. A result only ever lifts the estimate; the delay and loss detectors still bring it
down. On a simulated 10 Mbps link a sender starting at 300 kbps reaches 90 % in 0.35 s instead of
44 s; `tools/interop/webrtc/bwe.sh` checks it with Chrome as the receiver (the estimate reaches
10 Mbps 0.2 s after the connection; it used to stay at its start).

The estimate's bounds are `set_bwe_bounds(min, max)` (30 kbps and 20 Mbps by default);
`Peer::set_bitrate_bounds` changes them on a running peer, and a raised maximum is probed at
once (ADR-073). akio-rtp's `BandwidthEstimator::set_network_state_estimate` also takes an
external link-capacity estimate, toward which it probes and above which it never does.

### Pacing

With the estimator on, sent media is paced (ADR-073), as libwebrtc paces it: video, FEC and
retransmissions leave through a queue drained at 2.5 times the estimate, and up to 40 ms worth
of bytes may leave at once, so an ordinary frame goes out whole while a keyframe is spread out
(at a 1 Mbps estimate a 60 kB keyframe takes about 150 ms). Retransmissions go first; audio is
never queued. Transport-wide sequence numbers and abs-send-time are written as packets leave,
so the estimator sees the real send times. `set_padding_rate(bps)` adds padding (RTX copies of
recent media) while there is nothing to send, to keep the estimate measured during quiet
periods; `enable_pacing(false)` turns pacing off. The queue holds at most 8192 packets (8 MB)
and drains faster when its oldest packet would wait 2 s: an application should follow the
`EgressBitrateEstimate` event, or it loses frames at the bound. `tools/interop/webrtc/pacing.sh`
shows it with Chrome: with the estimate capped at 300 kbps the largest burst of RTP towards
Chrome is 4 packets paced and 7 unpaced. While the path is marked ECT(1), the queue drains at
1.5 times the estimate with 1 ms bursts instead (ADR-082).

## TURN

`TurnConfig` fields (all public, `TurnConfig::new` sets the defaults):

| Field | Default | Meaning |
|---|---|---|
| `realm`, `auth` | – | long-term credentials: `static_auth(realm, users)` or `ephemeral_auth(secret)` (TURN REST API, `ephemeral_credentials` hands them out) |
| `relay_ip`, `public_ip` | –, none | relays bind on `relay_ip`; clients are told `public_ip` if set (1:1 NAT) |
| `additional_relay_ip`, `additional_public_ip` | none, none | relays of the other address family, for `REQUESTED-ADDRESS-FAMILY` of that family and dual allocations (next paragraphs) |
| `default_lifetime`, `max_lifetime` | 600 s, 3600 s | allocation lifetimes |
| `permission_lifetime`, `channel_lifetime` | 300 s, 600 s | RFC 8656 values |
| `nonce_lifetime` | 600 s | nonces are stateless (an expiry and an HMAC of it with the client address) |
| `max_allocations`, `max_allocations_per_user` | 16384, 1024 | quotas (508, 486) |
| `max_permissions`, `max_channels` | 256, 256 | per allocation (508) |
| `peer_allowed`, `allow_private_peers` | none, false | the default refuses loopback, private, link-local, multicast and reserved peers (`denied_by_default`): a relay into the server's own network would be an SSRF hole |
| `copy_dscp` | true | relayed datagrams keep the DSCP they came with (next paragraphs); false sends DSCP 0 |
| `relay_icmp` | true | ICMP errors of datagrams to peers go back to the client (Linux) |

Allocate, Refresh, CreatePermission, ChannelBind, Send and Data indications, ChannelData,
`EVEN-PORT` with `RESERVATION-TOKEN` and `REQUESTED-ADDRESS-FAMILY` are supported; requests are
authenticated with `MESSAGE-INTEGRITY` (`401`/`438` challenges), `FINGERPRINT` is checked and
echoed. Relayed traffic goes through the client's listener connection, so a client silent for
longer than `Config::udp_idle_timeout` (60 s) loses data from peers until it sends again: raise
that timeout on a TURN listener. `TurnCore` is the same server without I/O (`TurnEnv` does the
sending), for embedding or testing. `StunServer` alone answers Binding requests.

**Dual allocations** (RFC 8656 `ADDITIONAL-ADDRESS-FAMILY`, ADR-083). With
`additional_relay_ip` set to an address of the other family, a client can ask for an IPv4 and
an IPv6 relayed address in one Allocate. The success response carries two
`XOR-RELAYED-ADDRESS`, IPv4 first.

- Each address relays to peers of its own family, and has its own lifetime.
- A Refresh with `REQUESTED-ADDRESS-FAMILY` refreshes or deletes one of them, with its
  permissions and channels. Without it, a Refresh applies to both.
- A peer of a family the allocation lacks gets 443.
- A server that can only partly meet the request answers with the IPv4 address and an
  `ADDRESS-ERROR-CODE`: 440 with no IPv6 relay configured, 508 when no IPv6 port was free.
- The malformed combinations of RFC 8656 section 7.2 get 400.
- Without either attribute an allocation is IPv4 when the server relays IPv4.
- TCP allocations stay single-family: a dual request gets IPv4 plus `ADDRESS-ERROR-CODE` 440.

```rust,ignore
let cfg = TurnConfig::new("example.org", auth, "203.0.113.7".parse()?)
    .additional_relay_ip("2001:db8::7".parse()?);
```

**DSCP and ECN** (RFC 8656 section 14, ADR-083, ADR-091). Relayed data keeps the traffic
class byte it arrived with (the IPv4 TOS / IPv6 traffic class: DSCP and ECN codepoint), both
ways:

- ChannelData and Send indications from a UDP or DTLS client go to the peer with the client's
  byte.
- A peer's datagram goes to the client with the peer's byte.
- The byte is read from `IP_RECVTOS` / `IPV6_RECVTCLASS` and set with an `IP_TOS` /
  `IPV6_TCLASS` control message on Linux and macOS. Elsewhere datagrams go unmarked.
- `copy_dscp(false)` keeps the ECN codepoint only (DSCP 0, best effort): for a server that
  should not let clients and peers choose their class of service.
- Clients on TCP or TLS have no byte to give or get.
- An embedding `TurnCore` gets the byte with `handle_client_tos` / `handle_peer_tos` and
  `TurnEnv::send_to_peer_tos` / `send_to_client_tos`. The defaults of those pass the ECN bits
  on to the `_ecn` methods of ADR-083, whose defaults drop them.

**ICMP** (RFC 8656 section 11.5, ADR-091). When a datagram relayed to a peer draws an ICMP
destination unreachable, time exceeded or packet too big, the client gets a Data indication
with `XOR-PEER-ADDRESS` and an `ICMP` attribute (type, code, and the next-hop MTU for "packet
too big"), and no `DATA`, if it has a permission for that address.

- `TurnServer` binds its relay sockets with `Engine::bind_udp_icmp`, which sets `IP_RECVERR` /
  `IPV6_RECVERR` and reads the socket's error queue on its I/O thread. Linux only: elsewhere
  unconnected sockets never hear of ICMP.
- `TurnCore::handle_icmp(now, relay, peer, type, code, mtu, env)` is the entry point for an
  embedding; `TurnStats::icmp` counts what was relayed.
- ICMP is best effort: hosts rate-limit it and networks filter it.

`TurnServer` splits allocations into shards by client address (about four per CPU, at least 8),
each with its own lock: datagrams of different allocations do not contend across I/O threads,
the expiry sweep takes one shard at a time, and the relay socket of an authenticated Allocate
is bound before any lock is taken. The quotas stay server-wide.

### TURN over TCP and TLS

`turn.stream()` is the acceptor for TCP listeners, and wrapped in `akio::tls::Tls` for TLS ones
(`turns:`, usually port 5349 or 443): the same allocations, quotas and credentials as the UDP
listener. Relays are UDP, or TCP when the client asks for a TCP allocation (next section).

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
by their own lengths (`akio_turn::framing::FrameReader`), ChannelData padded to four bytes.

### TCP allocations (RFC 6062)

A TCP or TLS client may ask for `REQUESTED-TRANSPORT` TCP: its relayed address is then a
listening TCP socket, and it relays TCP connections instead of datagrams. Browsers never ask for
this; SIP and XMPP clients and applications tunnelling a TCP protocol through TURN do, and coturn
and pion/turn offer it too.

- **Connect**: the client names a peer; the server connects to it *from the relayed address*
  and answers with a `CONNECTION-ID` (or 447 when the peer cannot be reached, 446 when a
  connection with that peer address exists). The peer policy applies (403); no permission is
  needed.
- **Peers connecting** to the relayed address need a permission for their IP (CreatePermission,
  as for UDP); without one the connection is closed at once, with one the client gets a
  ConnectionAttempt indication with a `CONNECTION-ID`.
- **ConnectionBind**: the client opens a *new* connection to the server and binds it to the id
  (same credentials; the nonce of the control connection is accepted). From its success on,
  that connection and the peer's carry raw bytes both ways; closing either closes the other,
  and the allocation going (its control connection closing, a deletion, expiry) closes all of
  them. A connection nobody binds is closed after 30 s.

The server keeps the bytes of a bound connection off its allocation shards: each side writes
straight into the other, and when one side has more than `tcp_relay_buffer` queued, reading the
other pauses until it drains (`hold_reads` / `on_drain`), so a slow reader slows the peer down
instead of growing memory. Before the bind, a peer's bytes are held up to the same mark, then
reading it pauses. One thread per server polls the relayed addresses' listeners and hands
accepted connections to the engine; no I/O thread waits on `accept`.

| Field | Default | Meaning |
|---|---|---|
| `tcp_relays` | true | offer TCP allocations (false: 442) |
| `max_tcp_connections` | 64 | connections of one TCP allocation (Connect beyond: 508; peers beyond: closed) |
| `tcp_relay_buffer` | 64 KiB | held per direction: a peer's bytes before the bind, the queue at which the other side pauses |
| `tcp_connect_timeout` | 30 s | how long a Connect waits for the peer before 447 (RFC 6062: at least 30 s) |

A Connect's connection is opened by the same thread that accepts (a non-blocking connect from the
relayed address, then handed to the engine), so the engine's `Config::connect_timeout` does not
apply: `tcp_connect_timeout` alone decides, and the core keeps that deadline itself. Right after a
connection to a peer closes, a new Connect to the same peer address may fail (447) while the old
4-tuple sits in TIME_WAIT; RFC 6062 has clients wait 10 s before retrying anyway.

WebRTC does not use TCP allocations, and `Endpoint` does not gather relayed TCP candidates
(RFC 6544 §5.5). Browsers' TURN clients ask for UDP allocations only, even over TCP or TLS, so no
browser offers one. A browser could still reach a passive relayed TCP candidate of ours with its
active TCP candidate, but the TURN server accepts that connection only with a permission for
the address it comes from, and libwebrtc (Chrome, Edge, Safari) signals only active host TCP
candidates (port 9), no server-reflexive TCP one: behind a NAT, that address is unknown exactly
when TCP would matter.
A UDP allocation made over TCP or TLS (`RelayServer::tcp` / `tls`) already serves those networks.
ADR-076 has the reasoning.

### TURN over DTLS

`turn.dtls(&tls_cfg)?` is the acceptor for UDP listeners whose clients talk DTLS (RFC 7350,
`turns:host:5349?transport=udp`), with the same certificate as the TLS listener and the same
allocations, quotas and credentials. ClientHellos are answered with stateless cookies before
any state is kept; DTLS 1.3 is offered with a fallback to 1.2. Each record carries one STUN or
ChannelData message, unpadded. An allocation lives as long as its DTLS association: close_notify,
a fatal alert, `udp_idle_timeout` of silence or a new handshake from the same address frees it.
Clients that support connection IDs (RFC 9146, RFC 9147 §9) are asked for 8-byte ones: when a
client's address changes (a NAT rebinding), its records still name its association, and its path
moves to the new address once one of them authenticates there; the allocation stays.
`turn.dtls_with_connection_ids(&tls_cfg, None)` turns them off. coturn's `turnutils_uclient -S`
and coturn's own DTLS listener interoperate (`tools/interop/webrtc/turn-dtls.sh`).

```rust,ignore
Engine::builder()
    .listen(Listener::udp("0.0.0.0:5349".parse()?).serve(turn.dtls(&tls_cfg)?))
```

### The TURN client

`akio_turn::client::Client` is a sans-io client of one allocation, over UDP or a TCP/TLS stream
(`ClientConfig::stream(true)`): it answers the 401 challenge with long-term credentials, renews
stale nonces, refreshes the allocation, binds a channel to each peer on first `send_to` (falling
back to permissions and Send indications), refreshes those bindings while a peer is in use, and
retransmits over UDP. The caller moves bytes: `poll_transmit` to the server, `handle_input`
with what comes back (it returns relayed data as `(peer, payload)`), `handle_timeout` at
`poll_timeout`. Bounds: 64 peers, 64 KiB waiting for bindings. `Endpoint::gather_relay` drives
one over UDP.

`ClientConfig::dual_allocation(true)` asks for a dual allocation:

- `relayed_addrs()` gives both addresses, IPv4 first; `relayed_addr()` stays the first.
- `relayed_addr_for(peer)` gives the one that talks to `peer`.
- `address_error()` says why a family is missing.
- `send_to` works for peers of either family; refreshes keep both.
- `release_family(now, v6)` gives one of them back (a Refresh with lifetime 0 and that
  `REQUESTED-ADDRESS-FAMILY`): it leaves `relayed_addrs()` with its peers, and the other stays
  and is refreshed alone.

A Data indication with `ICMP` becomes `ClientEvent::Icmp { peer, icmp_type, code, mtu }` (a
datagram to `peer` was refused on the way; the port may be 0), for addresses the client has a
permission for.

For a TCP allocation, `ClientConfig::tcp_allocation(true)` (over TCP or TLS). `connect(peer)`
sends a Connect and is answered by `ClientEvent::Connected { peer, id }` or `ConnectFailed`;
`create_permission(peer)` installs a permission that stays refreshed, after which peers that
connect show up as `ClientEvent::ConnectionAttempt { peer, id }`. To use a connection, open a new
connection to the server and drive a `DataConnection` from `client.data_connection(now, id)` on
it: send what `poll_transmit` gives (the ConnectionBind), feed what is read to `handle_input`,
which returns how many bytes it took; once `state()` is `DataState::Bound`, the rest of that
read and everything after it are the peer's bytes, and what you write goes to the peer.

```rust,ignore
let mut ctl = Client::new(ClientConfig::new(server, "alice", "secret").tcp_allocation(true), now);
// ... drive ctl over a TCP connection until ClientEvent::Allocated ...
ctl.connect(now, peer);
// ... ClientEvent::Connected { id, .. } ...
let mut data_conn = TcpStream::connect(server)?;
let mut bind = ctl.data_connection(now, id).unwrap();
while let Some(m) = bind.poll_transmit() {
    data_conn.write_all(&m)?;
}
let n = data_conn.read(&mut buf)?;
let used = bind.handle_input(&buf[..n]);
if *bind.state() == DataState::Bound {
    peer_bytes(&buf[used..n]); // and data_conn is now a pipe to the peer
}
```

`TcpAllocation` does the same on an `akio` engine, without a blocking call: it dials the control
connection (TCP, or TLS with `ServerTransport::Tls`), runs the client's timers on one shared thread
and reports `AllocationEvent`s to a callback. `connect(peer, acceptor, on_error)` sends the Connect
and, once the server has connected, dials a data connection served by *your* acceptor: its
ConnectionBind is a transport layer under your handler (and over TLS's), like a TLS handshake, so
`on_open` runs as soon as the TCP connection is up, what the handler sends waits for the bind, and
`on_data` gets only the peer's bytes. `create_permission(peer)` and `accept(id, acceptor,
on_error)` take a peer's ConnectionAttempt the same way. Whatever keeps a data connection from
carrying the peer's bytes (the Connect refused, the dial or the bind failing) goes to `on_error`,
once. Dropping the last handle closes the control connection, which ends the allocation.

```rust,ignore
let alloc = TcpAllocation::open(&engine, ClientConfig::new(server, "alice", "secret"),
    ServerTransport::Tcp, |alloc, ev| match ev {
        AllocationEvent::Allocated { relayed, .. } => println!("relayed at {relayed}"),
        AllocationEvent::ConnectionAttempt { id, .. } => alloc.accept(id, MyAcceptor, |e| eprintln!("{e}")),
        _ => {}
    });
// once allocated: MyAcceptor's handler talks to the peer as to any connection
alloc.connect(peer, MyAcceptor, |e| eprintln!("connect: {e}"));
```

`tools/interop/webrtc/turn-tcp.sh` checks both clients against coturn (`turnutils_uclient -T`,
its server) and pion/turn (its TCP allocation client and server), over TCP and TLS.

## The DTLS layer: DTLS 1.3 with a DTLS 1.2 fallback

`akio-dtls` is a sans-io connection (`Connection`: feed datagrams and timer expiries, send what
`poll_transmit` returns) that speaks DTLS 1.2 (RFC 6347) and DTLS 1.3 (RFC 9147).
`Config::with_versions(vec![Version::Dtls13, Version::Dtls12])` offers both and falls back to
DTLS 1.2 for a 1.2-only peer (with the RFC 8446 downgrade check). `Config::webrtc` itself enables
only DTLS 1.2 (ADR-021); `akio-webrtc`'s peers add DTLS 1.3 (ADR-048, `RtcConfig::enable_dtls13`,
default on), which Chrome 157 negotiates in either DTLS role while pion stays on DTLS 1.2.

- **DTLS 1.3**: unified record headers with encrypted record numbers, epochs with KeyUpdate
  (`Connection::update_keys`, also automatic before a key's usage limit), ACKs so that only
  the lost fragments of a flight are resent, stateless HelloRetryRequest cookies (also from
  `HelloVerifier::check` in front of the connections).
- **Connection IDs** (`Config::with_connection_id`): RFC 9146 `tls12_cid` records in DTLS 1.2,
  the CID in the unified header in DTLS 1.3. A listener routes datagrams with
  `akio_dtls::connection_id(datagram, len)` instead of the address, so a peer whose NAT
  binding changes keeps its connection.
- **Resumption** (`Config::with_session_resumption`): DTLS 1.2 session IDs (bounded cache) and
  RFC 5077 tickets, DTLS 1.3 NewSessionTicket (`psk_dhe_ke`, always forward secret). The client
  gets `Event::NewSession(session)` and reconnects with `Connection::client_resume`; tickets
  are sealed with a `TicketKey` that servers can share, and the peer certificate is checked
  again by the verifier on resumption.
- **External PSKs** (`Config::with_psks`): the DTLS 1.2 PSK and ECDHE-PSK AEAD suites and
  DTLS 1.3 `psk_dhe_ke`; a PSK-only server needs no certificate.
- **CID updates** (DTLS 1.3, ADR-045): `Connection::new_connection_ids` and
  `request_connection_ids` exchange fresh CIDs (NewConnectionId / RequestConnectionId);
  `rotate_connection_id` switches to a spare one after an address change so the two paths
  cannot be linked; `Event::LocalConnectionIds` keeps a listener's routing table exact.
- **Post-handshake client authentication** (DTLS 1.3): a client offering it with
  `Config::with_post_handshake_auth` can be asked for its certificate at any time with
  `Connection::request_client_certificate`; the answer is `Event::ClientCertificate`.
- **Early data (0-RTT)** (DTLS 1.3, `Config::with_early_data`, off by default): a resuming
  client sends `Connection::send_early_data` before the handshake completes; the server gets
  `Event::EarlyData` once per ClientHello (ticket-age check and an `AntiReplayStore` of
  binders, shareable between servers). Early data can be replayed, so only idempotent
  requests belong in it.

Interop is checked against OpenSSL 3.5 / 4.1, wolfSSL 5.8 and pion/dtls
(`tools/interop/dtls/run.sh`).

## Not done yet

- DTLS re-keying within a session. A new handshake would be needed: DTLS 1.2 renegotiation,
  which Chrome and pion refuse, or a new association with a new `a=tls-id`, which also restarts
  the data channels. DTLS 1.3's KeyUpdate does not change SRTP's keys (ADR-086 §6).

ADR-017, ADR-032, ADR-039, ADR-044, ADR-045, ADR-048, ADR-054, ADR-058, ADR-072, ADR-073,
ADR-076, ADR-077, ADR-082, ADR-083, ADR-086 and ADR-091 have the details of what was added.
