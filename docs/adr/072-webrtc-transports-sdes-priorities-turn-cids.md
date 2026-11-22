# ADR-072: Transports without BUNDLE or ICE, SDES variants, data channel priorities and TURN DTLS connection IDs

English | [简体中文](072-webrtc-transports-sdes-priorities-turn-cids.zh-CN.md)

Status: accepted (2026-11-21)

## Context

Earlier work left gaps in akio-webrtc, akio-turn and akio-ice that the DEV-PLAN listed as not
done:

- **Data channel priorities and the SCTP stream scheduler** (ADR-037): akio-sctp implements
  RFC 8260 schedulers and RFC 8832 channel priorities, but akio-webrtc exposed neither, so
  every channel had DCEP priority 256 and the association used weighted fair queueing with no
  way to weigh channels.
- **One transport per session** (ADR-058): this stack ran one ICE agent, one DTLS association
  and one pair of SRTP contexts. A peer that does not bundle (SIP endpoints with audio and
  video, browsers with `bundlePolicy: "max-compat"` facing an answer that refuses BUNDLE)
  could not be served, so sessions without rtcp-mux were limited to one section and no data
  channels.
- **Component 2** (RTCP without rtcp-mux) had host and peer-reflexive candidates only, and
  `RtcServer` (ICE-lite on one listener) had no component 2.
- **SDES-SRTP** (ADR-054) needed ICE, refused lines with MKIs and refused data channels.
- **TURN over DTLS** (ADR-054) identified a client by its 5-tuple: a NAT rebinding lost the
  association and its allocation.
- **akio-ice** had no exported IPv6 mDNS group and no way to give a resolved link-local
  candidate its interface.

Constraints: browsers and pion must see what they saw before by default; another session was
changing akio-rtp and akio-webrtc's pacing / FEC / RED / feedback code at the same time, so the
changes to `rtc.rs` are hooks rather than rewrites; public-tier APIs must not expose
internal-tier types.

## Decision

### 1. Data channel priorities and the scheduler

`ChannelPriority` (`VeryLow`, `Low` default, `Medium`, `High`; DCEP 128 / 256 / 512 / 1024,
RFC 8831 §6.4 and the W3C mapping) in `ChannelConfig::priority` (`with_priority`), sent in the
DCEP open message; the priority of a channel the peer opened comes from its message (nearest
level; 0 counts as low). `Peer::channel_priority` and `Peer::set_channel_priority` (this side's
scheduler only: DCEP has no update). `ChannelScheduler` (FCFS, round robin, round robin per
packet, priority, fair capacity, weighted fair queueing by default) chosen with
`RtcConfig::set_sctp_scheduler`. Both map onto akio-sctp's types inside the crate.

### 2. Several transports without BUNDLE

- **When.** A session is not bundled when our first offer is made with
  `RtcConfig::set_bundle_policy(BundlePolicy::Disabled)`, when the first remote offer has no
  `a=group:BUNDLE` (or we disabled BUNDLE: our answer then refuses the group, RFC 9143 §7.3.3),
  or when the answer to our first offer leaves our group out. It is decided once; a later
  description that stops bundling an established bundled session is refused.
- **What.** Each section in use gets a transport: an ICE agent (role, options and candidates
  copied from the primary's), a DTLS association, SRTP contexts, SDES keys and an RTCP
  component (two components on media sections without rtcp-mux, one on the application
  section). The DTLS role, certificate and remote fingerprint are the session's. Our sections
  carry their transport's credentials and candidates, and no group. Credentials: the primary's
  ufrag followed by the transport's index, with a password of its own, so the endpoint hub
  finds the peer by the ufrag's first eight characters; when the answer refused our BUNDLE
  offer, the primary's own (our offer gave every section those).
- **How.** The per-transport fields of `Rtc` (`ice`, `dtls`, SRTP contexts, SDES state, RTCP
  component, the first DTLS source, mDNS candidates waiting) form a transport state, and
  `Rtc::with_tp` swaps transport `k`'s state in, runs the existing code, and swaps it back. The
  non-current transports are always those in the side table. Entry points redirect or fan out:
  datagrams by demultiplexing, timers to every transport, media to its line's transport, RTCP to
  the transport of the line whose SSRC sends it (the first packet's sender SSRC), SCTP to the
  application section's transport. ICE states are aggregated (W3C rules: any disconnected, else
  all new, else any new or checking, else all completed, else connected); `Connected` is
  reported once every transport has its keys.
- **Demultiplexing.** A connectivity check goes to the transport whose ufrag its USERNAME
  names; among transports sharing a ufrag, and for everything else, to the transport that owns
  the local address it arrived on (when transports have sockets of their own), else to the one
  whose selected pair, remote candidates or first DTLS datagram has its source. Transports on
  one socket are therefore told apart by the remote's addresses, which every peer that does not
  bundle provides (an ICE agent or a port per section).
- **Sockets per transport.** `Endpoint::bind_transport_socket` binds more sockets; the n-th
  transport after the first uses the n-th socket's host candidate, so two only endpoints can
  run without BUNDLE (one side needs them). Component 2 of every transport stays on the RTCP
  socket.
- **Limits.** Transport-wide congestion control needs one transport: transport-cc and RFC 8888
  feedback are not negotiated (and are removed after the fact) in a session that is not
  bundled, so neither bandwidth probing nor the estimator run there. Trickled candidates name
  their section with `Peer::add_remote_candidate_in(mid, ..)`.

### 3. Component 2: server-reflexive and relayed candidates, `RtcServer`

- `Endpoint::gather_srflx` also asks from the RTCP socket (when bound before) and adds a
  component-2 server-reflexive candidate; both answers are needed. `gather_relay(_via)` makes a
  second allocation from the RTCP socket (each relay knows whether it is component 2's: socket,
  base, candidate component); both must succeed; at most four allocations per component.
  Datagrams from a TURN server are matched to the relay of the socket they arrived on.
- `RtcServer::rtcp_candidates(addrs)` adds component-2 host candidates for a second UDP
  listener served by `RtcServer::rtcp()` (`RtcRtcp`): its connections are kept apart from the
  main listener's, and what component 2's candidates send leaves through them (a lock-free flag
  keeps servers without one on the old path).

### 4. SDES: without ICE, MKIs, next to data channels

- **Without ICE.** `RtcConfig::enable_ice(false)` makes our descriptions plain: no ICE
  attributes or candidates, the first host candidate's address in `c=` and its port in `m=`,
  `a=rtcp` with component 2's port and address without rtcp-mux. A remote description without
  `a=ice-ufrag` is taken that way whatever the setting. The ICE agent then gets fixed pairs
  (new `IceAgent::set_fixed_pair`): from our host candidate of the remote's family to the
  `c=` address and `m=` port, and on component 2 to `a=rtcp` (or the next port; the same one
  with rtcp-mux). The agent runs no checks, consent or timers and is `Completed` at once. The
  endpoint routes datagrams from those addresses to the peer before it sends anything (the
  hub learns them from `Rtc::take_plain_remotes`). The SDP layer now reads and writes `c=`
  lines (the unspecified address is "none"). Plain transports work with DTLS-SRTP too.
- **MKIs.** `a=crypto` key parameters with `|<value>:<length>` (1..=128 bytes, RFC 4568 §9.1),
  several master keys separated by `;` (they must all have MKIs of one length, distinct
  values), lifetimes (accepted, not enforced) and the `WSH=` window size hint are taken; other
  session parameters (`KDR=`, `UNENCRYPTED_*`, `FEC_*`) still make a line unusable. The SRTP
  contexts get every master key (`Context::new_with_mki` and `add_master_key`) and send with the
  first. Our answer's key has an MKI of the offer's length; `RtcConfig::set_sdes_mki_length`
  puts MKIs in our offers.
- **Data channels next to SDES.** The application section carries `a=fingerprint` and
  `a=setup` (the media sections keep `a=crypto` only); DTLS runs over the same transport (or the
  application section's own without BUNDLE) and carries SCTP only: its SRTP keys are ignored,
  media stays keyed by the SDP, and SCTP starts once the DTLS handshake completes (the peer is
  connected earlier, on its SDP keys and ICE pair).

### 5. Connection IDs on the TURN-over-DTLS listener

`TurnServer::dtls` asks clients for 8-byte connection IDs (RFC 9146 for DTLS 1.2, RFC 9147 §9
for 1.3; negotiated, so clients without them are unaffected);
`TurnServer::dtls_with_connection_ids` sets another length or none. The listener indexes the
live CIDs of its associations (bounded). A datagram from a 5-tuple without an association of
its own whose CID names one is fed to that association; once a record of it authenticates (an
application-data record came out), the client's path moves to that 5-tuple (RFC 9146 §6):
responses and relayed data go there, while the allocation keeps the address the association
started from as its identity, so nothing moves between shards. A forged or replayed record
moves nothing. Which connection holds the path is tracked in the session, so a datagram costs
no extra shard lock unless the path moves. akio-webrtc's DTLS relay client sends the server's
CID when asked.

### 6. akio-ice

`mdns::MULTICAST_V6` (`[ff02::fb]:5353`) and `mdns::multicast_v6_on(scope)` next to
`MULTICAST_V4`; `Candidate::with_scope_id(scope)` gives an IPv6 link-local candidate (address,
and base when it is the address) its interface; SDP never shows it. akio-webrtc keeps its
design (scope ids stripped before ICE, kept by the hub) and uses `multicast_v6_on`.

### API

Additive. akio-webrtc: `ChannelPriority`, `ChannelScheduler`, `ChannelConfig::{priority,
with_priority}`, `RtcConfig::{set_sctp_scheduler, set_bundle_policy, enable_ice,
set_sdes_mki_length}`, `BundlePolicy`, `Peer::{channel_priority, set_channel_priority,
add_remote_candidate_in}`, `Endpoint::bind_transport_socket`, `RtcServer::{rtcp_candidates,
rtcp}`, `RtcRtcp`. akio-turn: `TurnServer::dtls_with_connection_ids`. akio-ice:
`mdns::{MULTICAST_V6, multicast_v6_on}`, `Candidate::with_scope_id`,
`IceAgent::{set_fixed_pair, is_fixed}`. `ChannelConfig` is `#[non_exhaustive]`, so its new
field is not a break.

## Consequences

- Defaults are unchanged for browsers and pion: BUNDLE offered and accepted, ICE on, DCEP
  priority 256, weighted fair queueing. Two behaviours change: a remote offer without
  `a=group:BUNDLE` and several sections is now answered with a transport per section (it was
  answered with a BUNDLE group the offer never asked for, which did not work), and the TURN
  DTLS listener negotiates CIDs with clients that offer them.
- Tests: simulated network (`rtc/tests_transports.rs`): priorities reach the peer, the priority
  scheduler serves the high channel first, a raised priority takes effect, weighted fair
  queueing and round robin share as configured; three transports (audio, video, data) on their
  own address pairs with DTLS on each, RTP / RTCP on the media ones, checks within a transport
  and one `Connected`; an answer refusing BUNDLE splitting the offerer onto one socket; audio
  and video without BUNDLE or rtcp-mux (four components, RTCP on each component 2); SDES
  without ICE with RTCP on its own port (no STUN or DTLS, RTP and RTCP on their port pairs); a
  hand-written SIP offer with rtcp-mux and a 2-byte MKI; SDES with MKIs both ways; SDES media
  next to a data channel. Endpoints over loopback: without BUNDLE both ways (data channel,
  audio and video echo; `tests/bundle.rs`), SDES without ICE with MKIs and RTCP sockets, SDES
  with data channels (`tests/sdes.rs`), RTCP through relayed candidates on akio-turn (four
  allocations), component-2 server-reflexive candidates, an ICE-lite `RtcServer` with an RTCP
  listener (`tests/rtcp_mux.rs`). akio-turn (`tests/dtls.rs`): a client moving to a new socket
  mid-association keeps its allocation over DTLS 1.2 and 1.3, a forged record with the CID
  moves nothing, close_notify from the new address frees the allocation, no CID without them.
  akio-ice: fixed pairs (events, state, nothing running, moving a pair), scope ids, the IPv6
  group. Unit tests of `a=crypto` MKI parsing, `c=` lines, plain addresses, state aggregation.
- Interop: headless Chrome 157 (`tools/interop/webrtc/bundle.sh`): Chrome with
  `bundlePolicy: "max-compat"` offering audio, video and data channels to an `RtcServer` that
  refuses BUNDLE runs three transports (its statistics), with data and media echoed and
  decoded; the only `Endpoint` offering audio and a channel without BUNDLE gets Chrome's
  microphone over two transports. Chrome 157 has no `RTCDataChannel.priority` (it sends 256),
  and pion always bundles and sends 256, so priorities are checked between only peers only;
  pion's script (`run.sh`) and Chrome's (`browser.sh`) pass unchanged.
- Fuzzing: new target `webrtc_sdes` (an `a=crypto` value round-trips and keys a context);
  `webrtc_sdp` also tries SDES without ICE with MKIs and no BUNDLE with RTCP negotiation, and
  checks that keys never share a section with a fingerprint, that answers to offers without ICE
  carry none, that a disabled BUNDLE never appears, and that no section carries both
  `a=rtcp-mux` and `a=rtcp`; new seeds. On Linux arm64: `webrtc_sdes` 31 M runs in 15 minutes,
  clean; `webrtc_sdp` found two bugs, both fixed and kept as regression inputs (a disabled BUNDLE
  written as an empty group when every offered section was rejected; an application section
  taking the mid of a media line, which then ran on the data channel's transport); after the fixes
  170 k runs in 15 minutes, clean.
- Performance (same-run A/B against 57696b6b on gpu51, `quiet.sh`, CPUs 2-9, 7 alternating
  rounds, medians): RTP media between two loopback `Endpoint`s 92.1 vs 92.1 MB/s (1.000x), data
  channels 189.7 vs 189.7 MB/s (1.000x), TURN over DTLS through the listener and relay 230,804
  vs 231,015 datagrams per second (1.001x; 100-byte ChannelData, the CID path on): no
  regression.
- Costs: a session without BUNDLE runs an ICE agent, a DTLS handshake and consent checks per
  section; the swap is a handful of field moves per redirected call (none in a bundled session:
  every hook checks an empty table first). A TURN DTLS listener keeps one index entry per live
  CID.
- Not done: latching onto the address plain media really comes from (symmetric RTP behind
  NATs); a remote that sends from one address for several transports when we are on one socket
  too; transport-wide congestion control across transports; SDES session parameters other
  than `WSH`; usrsctp (Firefox) priorities.
