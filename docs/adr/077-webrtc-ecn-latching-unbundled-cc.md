# ADR-077: ECN-capable RTP, latching media without ICE, and congestion control across transports without BUNDLE

English | [简体中文](077-webrtc-ecn-latching-unbundled-cc.zh-CN.md)

Status: accepted (2026-11-22)

## Context

ADR-072 and ADR-073 left three items of only-webrtc's "not done" list open:

- **Sending ECN-capable packets.** RFC 8888 reports carry the ECN codepoint each packet arrived
  with and the estimator counts CE as loss (ADR-073), but this side never marked anything:
  `Rtc`'s output carried no codepoint, and an `Endpoint` sends through `UdpBinding::send_to`,
  which has no control messages. only-quic marks and validates ECN already (ADR-013 / ADR-035,
  `Conn::send_segments_ecn`, `IP_TOS` / `IPV6_TCLASS`), so the socket layer exists for
  connections, not for bound sockets.
- **Latching plain media.** A transport without ICE (ADR-072, `enable_ice(false)`, SIP style)
  sends to the `c=` address and `m=` port of the remote description and the endpoint routes only
  datagrams from there to the peer. A phone behind a NAT writes its private address, which is
  unreachable, and its packets arrive from the NAT's mapping, which nothing routes: no media
  either way. SIP gateways solve this with symmetric RTP / "comedia" latching (RFC 7362).
- **Transport-wide congestion control without BUNDLE.** ADR-072 removed transport-cc and RFC
  8888 from sessions that are not bundled, so a session with a transport per section ran no
  estimator, no probing and no pacing.

Constraints: defaults stay as they are for browsers and pion; nothing changes on the wire unless
configured, except that unbundled sessions negotiate congestion control feedback again; a
bundled session's hot path gains no work.

## Decision

### 1. ECN-capable RTP (`RtcConfig::set_ecn_marking`, `rtc/ecn.rs`)

- **Opt-in**: `EcnMarking::{Off (default), Ect0, Ect1}`. ECT(1) is what L4S (RFC 9331) and
  libwebrtc use; ECT(0) is classic ECN (RFC 3168, RFC 6679's default). A path marks only while
  RFC 8888 feedback is in use (negotiated by both sides: it reports the arrival codepoint, which
  validation needs; transport-wide feedback does not) and the bandwidth estimator runs (marked
  traffic must respond to CE, RFC 3168 §5, and the estimator is what responds).
- **What is marked**: RTP only — media, retransmissions, FEC, padding and probes. RTCP never
  (RFC 6679 §7.2 and §7.3.1 "SHALL NOT"), nor STUN, DTLS or SCTP: data channels have no ECN
  response in WebRTC's SCTP usage (RFC 8831 does not use SCTP's ECN; ADR-042), and marking
  without a responder is what RFC 3168 forbids.
- **Initiation** (RFC 6679 §7.2.1 with RFC 8888 as the feedback): one RTP packet in four is
  marked while it is unknown whether marks get through ("a small fraction"). Sent packets are
  remembered by SSRC and sequence number (the last 2048) with their codepoint, and every RFC
  8888 report entry is matched against them before the estimator sees the results. Ten marked
  packets reported received with their mark (or CE), and no more than a quarter as many lost,
  validate the path (the unicast "provisional success"): every RTP packet is marked from then on.
- **Failure** (RFC 6679 §7.4): a marked packet reported received without its mark (cleared to
  Not-ECT, or ECT(1) re-marked ECT(0)) ends marking on the path at once; so do marked packets
  that do not get through (ten lost, none received), or, with sixteen marked results, a marked
  loss rate above half and above three times the unmarked one plus 10 %. While capable, a
  window of 64 marked results more than half lost sends the path back to initiation, which
  compares marked and unmarked losses again (§7.4.1). A failed path stays unmarked (the RFC
  recommends disabling when full use failed); a new path (an ICE pair, a latched address)
  starts over. A receiver that cannot read the codepoint reports Not-ECT, which ends marking
  after the first marked packet it reports.
- **Per path**: each transport (ADR-072) has its own state, swapped in with the transport;
  RFC 8888 reports are split by the transport of each SSRC.
- **CE**: reaches the estimator as loss, as ADR-073 already did (`PacketResult::ecn`); the
  loss-based control's thresholds (hold between 2 and 10 %, decrease above) then act on the CE
  fraction. That is a classic response; a scalable (L4S) one is not implemented.
- **Sockets**: `Output::Transmit` carries the codepoint; the hub sends marked datagrams with the
  new `UdpBinding::send_to_ecn` (one `sendmsg` with an `IP_TOS` / `IPV6_TCLASS` control message;
  on Linux a new `only_sys::send_to_ecn`, macOS had one) and, on an `RtcServer`'s connections,
  with `Conn::send_segments_ecn`. Unmarked datagrams take the old calls. `ONLY_UDP_ECN=0`
  turns the codepoint off as for QUIC; TURN relays and ICE-TCP send none (their reports then
  show Not-ECT and the path fails over to unmarked).
- **Statistics**: `PeerStats` gains `ecn_marked_sent`, `ecn_failures` and `ecn_state`.

### 2. Latching media without ICE (`RtcConfig::set_latching`, `rtc/latch.rs`)

- **Opt-in**: `Latching::{Off (default), Once, Rebind(Duration)}`. `Once`: the source of the
  first authenticated packet becomes the remote for good (the SDP address included, if that is
  where it comes from). `Rebind(quiet)`: the first one, then another authenticated source once
  the latched one has sent nothing authenticated for `quiet` (a NAT rebinding, a phone changing
  networks); `Duration::ZERO` follows every authenticated packet from a new source.
- **SRTP authentication is the gate.** A datagram from an address no peer is known at is
  offered, as RTP or RTCP only, to the peers that may still latch (registered with the hub;
  `Once` peers leave the list once every component latched) on the local address it arrived on
  (at most 64 peers per datagram, starting where the last offer stopped). A peer tries it
  against each transport's SRTP / SRTCP keys; only a packet whose tag verifies and that SRTP's
  replay window accepts is taken (and received as usual). Forged packets therefore cost an HMAC
  per open peer and do nothing; copies of packets already received fail the replay check, so an
  off-path attacker cannot move the media (an on-path one could anyway). The pair of the ICE
  component the packet belongs to moves to its source (`IceAgent::set_fixed_pair`, which emits
  a selected-pair change: the estimator and ECN start over on the new path); without rtcp-mux
  RTCP latches on its own SRTCP. The endpoint routes the new source to the peer and forgets the
  previous latched address (never the description's).
- **Re-offers** that repeat a component's SDP address keep a latched pair; a new address starts
  the component's latching over.
- **Limits**: nothing latches before the SRTP keys exist: with DTLS-SRTP the handshake needs
  the SDP address (SDES, the SIP case, has its keys at once). Latching applies to transports
  without ICE only; with ICE, connectivity checks and peer-reflexive candidates already do this.
- **Statistics**: `PeerStats::latched` counts the moves.

### 3. Congestion control across transports without BUNDLE (`rtc/cc.rs`)

- **Negotiated again**: transport-cc and `ack ccfb` stay on every line of an unbundled session.
- **RFC 8888** reports per SSRC: each transport has its own receiver (its report goes out on
  it, about the streams it carries), the sender log is the session's, and reports that arrive on
  any transport are split by the transport of each SSRC (for ECN per path).
- **Transport-wide numbers** come in two conventions. The draft numbers packets per transport;
  libwebrtc numbers them per peer connection — one counter in its `PacketRouter` over every
  transport, one feedback generator — which Chrome 157 confirms (`tools/interop/webrtc/bundle.sh`:
  the server reads Chrome's numbering on three transports as one space). Mixing them breaks
  feedback both ways: a per-transport receiver reports the numbers that went to the other
  transports as lost, a per-connection receiver sees two spaces collide. So the session follows
  the remote's numbering, read from the packets it sends (`Spaces`): the same number arriving on
  two transports, or numbers more than 1024 apart, are another space each; a number whose
  predecessor arrived on another transport is one space. Until the remote shows separate spaces
  the session numbers in one space and acknowledges every transport with one receiver (what
  libwebrtc sends and expects, so a receive-only Chrome works too); once it does, every
  transport gets its own sender and receiver, swapped in with the transport's state, feedback per
  transport on it, and each transport's numbering continues from where the shared one stopped (a
  remote receiver must not see numbers go back). Per-transport numbering is therefore used with
  remotes that number per transport (the draft's model); between two of these stacks, and with
  browsers, the numbering is shared.
- **One estimator over several spaces** (`Merge`): per-transport results carry arrival times on
  separate clock anchors and come in per transport, out of send order. They are aligned (each
  transport's arrivals relative to its smallest one-way delay, so queueing delay is comparable
  across transports sharing a bottleneck), held until every transport with packets in flight has
  reported up to their send time (at most 300 ms), and handed to the estimator in send order,
  renumbered. RFC 8888 results share the remote's report clock and are only ordered. Shared
  numbering needs none of this.
- **One pacer**: a queued packet remembers its transport and leaves on it (`Queued::tp`);
  padding and probes go on the transport of the stream that carries them; retransmissions on
  their line's. Received RTP is parsed with the transport's own header extension map.
- **Statistics**: `PeerStats::twcc_spaces` ("unknown", "shared", "per-transport"; `None` with
  BUNDLE).

### API

Additive. only-webrtc: `EcnMarking`, `Latching`, `RtcConfig::{set_ecn_marking, set_latching}`.
only-core: `UdpBinding::send_to_ecn` (`#[doc(hidden)]`, outside the stability promise like
`Conn::send_segments_ecn`). only-sys: `send_to_ecn` on Linux (macOS had it).

## Consequences

- Defaults are unchanged for bundled sessions, browsers and pion. Sessions without BUNDLE now
  negotiate transport-cc / RFC 8888 and run the estimator, probing and pacing when it is on.
- Tests: simulated network (`rtc/tests_ecn.rs`): a path that keeps marks validates (a quarter
  of the first packets marked, then all; never RTCP, STUN or DTLS), paths that clear or re-mark
  them fail after a handful of probes and stop marking, CE marks reach the estimator without
  failing the path, nothing is marked without RFC 8888 or when off; a gateway latching onto a
  phone behind a modelled NAT (with and without rtcp-mux, RTCP latching on its own), no media
  without latching, forged and replayed packets moving nothing, a NAT rebinding followed or not
  as `Once` / `Rebind(500 ms)` / `Rebind(0)` say; unbundled sessions with shared and
  per-transport numbering (detected both ways) and RFC 8888 with ECN validated per transport;
  one estimate through an 800 kbps bottleneck with an encoder following it: bundled, unbundled
  shared and unbundled per-transport end within 0.6-1.4x of each other (656 / 657 / 697 kbps in
  one run). Unit tests of the ECN state machine, latching policies, the numbering detector and
  the merge; a Linux test of `only_sys::send_to_ecn` (IPv4 and IPv6, every codepoint). Endpoints
  over loopback (`tests/ecn_latch.rs`): marks through the kernel's sockets and the path
  validated, a phone whose answer names a dead port found by latching (and not without it), the
  estimate rising on the feedback of two transports without BUNDLE.
- Interop: headless Chrome 157 (`tools/interop/webrtc/ecn.sh`, RFC 8888 field trial): Chrome
  counts its received video packets with ECT(1) (`packetsReceivedWithEct1` 946 of 1015; the
  rest arrived before validation or are RTX of unmarked ones) and its RFC 8888 reports validate
  the path; through fec-server's UDP proxy, which clears the codepoint, the path fails after one
  marked packet and video goes on (199 of 199 frames decoded). Chrome sends nothing ECN-capable
  itself. `bundle.sh`: Chrome with `bundlePolicy: "max-compat"` (three transports) drives the
  server's estimator from 300 kbps to 19.9 Mbps, numbering shared. A SIP-style phone behind an
  iptables MASQUERADE NAT in a network namespace (`tools/interop/webrtc/latch.sh`, Docker):
  with latching off nothing comes back to the phone; with `Once` the gateway latches onto the
  NAT's mapping (one move) and 100 packets come back; after a rebinding (the phone's conntrack
  entry deleted, so the NAT picks another random port) `Once` stops echoing while `Rebind(1 s)`
  follows the new mapping (two moves) and 300 packets come back. pion always bundles and has no
  plain mode: `run.sh` passes unchanged, as does Chrome's `browser.sh`.
- Performance: same-run A/B against main 04a32fb5 on gpu51 (`quiet.sh`, CPUs 2-9, alternating, medians; new example `webrtc-bench`, default configurations): one-way VP8 RTP between two loopback `Endpoint`s 177.8 vs 178.0 MB/s (0.999x, 7 rounds); one data channel 154.8 vs 156.3 MB/s (0.990x, 7 rounds) and 155.9 vs 157.0 MB/s (0.993x, 11 rounds, branch first): about 1 % on data channels, at the edge of the spread (the ranges overlap); their path gained only a codepoint byte per output datagram and two flag checks per received one.
- Costs: with ECN on, a hash map entry per RTP packet sent (the last 2048) and a `sendmsg` with a
  control message per marked datagram; with latching on, an SRTP tag check per open peer for
  datagrams from unknown sources; without BUNDLE, per-transport feedback state and, with
  per-transport numbering, results held up to 300 ms for ordering.
- Not done: a scalable (L4S) response to CE (CE is loss); RFC 6679's own signalling
  (`a=ecn-capable-rtp`, the RTCP ECN feedback message, the XR ECN summary) and ECN with
  transport-wide feedback (no codepoint in it); retrying ECN on a path that failed; latching
  before DTLS-SRTP keys exist; marking through TURN relays and ICE-TCP; the estimator's
  behaviour with per-transport numbering when the sender overloads the link and ignores the
  estimate (a simulated 800 kbps link with 1 Mbps sent regardless ended at the 30 kbps floor
  where bundled ended at 63-187 kbps, all three modes chaotic there).
