# ADR-058: RTCP on its own ICE component, XR receipt blocks and ULPFEC levels in only-webrtc

English | [简体中文](058-webrtc-rtcp-components-xr-ulpfec-levels.zh-CN.md)

Status: accepted (2026-11-20)

## Context

Two sets of lower-layer features landed without being usable from a peer connection:

- **ICE components** (ADR-055): `only_ice::IceAgent` handles streams of several components,
  but only-webrtc always multiplexed RTP and RTCP on component 1 (rtcp-mux, BUNDLE). Peers that
  do not offer `a=rtcp-mux` (SIP endpoints, older RTP stacks: RFC 5761 lets them send RTCP on
  a port of its own, named with RFC 3605 `a=rtcp`) were answered with `a=rtcp-mux` anyway, and
  their RTCP never arrived.
- **only-rtp** (ADR-053): XR loss RLE, duplicate RLE and packet receipt times blocks from a
  `ReceiptLog`, complete VoIP metrics from `BurstLossModel::report`, ULPFEC protection levels
  (`FecEncoder::set_ulp_level0`), typed SDES items (`SdesItem`) and RFC 7022 CNAMEs
  (`random_cname`). The peers sent only XR receiver reference times / DLRR, ignored received
  SDES, and used a random 16-character CNAME of their own alphabet.

Constraints: browsers and pion must see exactly what they saw before (rtcp-mux, BUNDLE, no new
attributes by default); the public API (public tier) may not expose internal-tier types; only
only-webrtc changes (only-ice and only-rtp needed nothing).

## Decision

### 1. RTCP on ICE component 2

- **An RTCP socket.** `Endpoint::bind_rtcp(engine, addr)` binds a second UDP socket on the
  endpoint's hub; its host candidate (component 2, `Candidate::with_component(2)`, same
  foundation as component 1's) goes to new peers. `Endpoint::rtcp_addr` reports it. Datagrams
  from component-2 candidates leave through that socket (matched by the candidate base's
  address, or port and family when the socket is bound to the unspecified address); arriving
  ones are routed like any other (by source address, then by ICE username). Component 2 gets
  host and peer-reflexive candidates only: server-reflexive and relayed RTCP candidates would
  need a second STUN query and TURN allocation per endpoint and are not done. `RtcServer` (one
  listener port, ICE-lite) has no component 2.
- **Policy for our offers**: `RtcConfig::set_rtcp_mux_policy(RtcpMuxPolicy)`.
  `Require` (default) offers `a=rtcp-mux` alone, as before and as browsers do. `Negotiate`
  offers `a=rtcp-mux` and `a=rtcp:9 IN IP4 0.0.0.0` with the component-2 candidates (RFC 5761
  §5.1.1, the JSEP form), so the answer decides. `Off` leaves `a=rtcp-mux` out (the session
  has two components from the start); it needs an RTCP socket (`apply` fails otherwise).
- **Remote offers** are answered whatever the policy: with rtcp-mux when the first audio or
  video section in use has `a=rtcp-mux` (every browser, pion), with RTCP on component 2 when it
  does not and the endpoint has an RTCP socket, and, without one, with rtcp-mux as before (no
  change for existing deployments). An answer to a `Negotiate` offer that lacks `a=rtcp-mux`
  switches the offerer to two components.
- **One transport.** BUNDLE needs rtcp-mux (RFC 8843 §9.1), and this stack runs one ICE agent,
  one DTLS association per component and one pair of SRTP contexts: a session without
  rtcp-mux has one section in use and no data channels. Descriptions or changes with more are
  refused with a clear error (an offer without rtcp-mux of several sections, an answer to a
  `Negotiate` offer that drops rtcp-mux with several sections, `Off` with a channel, media
  added to such a session). Our descriptions then carry no `a=group:BUNDLE`.
- **The agent switches once.** Peers start with a one-component agent (the default stays
  byte-for-byte the same); at the first negotiation that decides on two components the agent
  is rebuilt with the same credentials, role, options and candidates plus component 2's —
  before the remote description's candidates are added, so nothing was checked yet. The count
  is kept by later descriptions (RFC 5761 §5.1.3: multiplexing is not switched by a
  re-offer); ICE restarts cover both components (ADR-055).
- **Keys.** DTLS-SRTP runs one handshake per component (RFC 5764 §4.1), both in the roles of
  `a=setup` with the same certificate and fingerprint: component 1's keys protect SRTP,
  component 2's SRTCP (sent and received on component 2's selected pair, `send_pair_of(2)`).
  A server-role handshake on component 2 starts with the first DTLS datagram there (answers go
  back to its source until ICE selects a pair). SDES-SRTP keys both components from the one
  `a=crypto` key per direction (RFC 4568: the master key serves SRTP and SRTCP of the stream).
  SRTCP protected with component 1's DTLS keys is not accepted on component 2.
- **Connected** means every key is in place and ICE selected a pair for every component: both
  handshakes for DTLS-SRTP, the SDP keys and both pairs for SDES. `PeerStats` gains
  `rtcp_mux`.

### 2. XR blocks about received streams

- `RtcConfig::enable_rtcp_xr_blocks(XrBlocks)` with `XrBlocks::{LOSS_RLE, DUPLICATE_RLE,
  RECEIPT_TIMES, VOIP_METRICS, ALL}` (combined with `|`) offers and accepts the RFC 3611 §5.1
  formats `pkt-loss-rle`, `pkt-dup-rle`, `pkt-rcpt-times`, `voip-metrics` in one `a=rtcp-xr`
  line per section (with `rcvr-rtt=all` when `enable_rtcp_xr` is on too). A line sends a block
  when both sides list its format (formats with parameters count, unknown ones are ignored);
  VoIP metrics are offered and sent on audio lines only. Default none: no `a=rtcp-xr` change.
- **Sending**: every received stream of such a line keeps a receipt log
  (`RecvStream::enable_receipt_log`, 4096 sequence numbers per interval). Once per RTCP
  interval (1 s) its blocks about the sequence numbers since the previous report go out in a
  compound of their own, an empty receiver report from the line's sender SSRC then the XR
  (RFC 3550 §6.1 needs the report first; separate compounds keep the reports of other streams
  under the MTU). RLE blocks are thinned (§4.1 T) to at most 1500 reported sequence numbers,
  receipt times to at most 96; the XR body stays under 900 bytes. VoIP metrics come from a
  `BurstLossModel` per stream fed with the interval's loss trace and
  `report(ssrc, 20 ms, &VoipQuality { round_trip, .. })`: the loss, discard, burst and gap
  fields are measured; the round-trip time is the stream's; the quality fields only the codec
  and the application know (levels, R factors, MOS, jitter buffer) are sent as unavailable.
  FEC-rebuilt packets count as lost, as in receiver reports.
- **Receiving**: loss RLE, duplicate RLE and receipt times blocks about a stream this side
  sends become an `XrReceipts` event (sequence numbers received, lost and duplicated, receipt
  times reported) per XR packet and stream, and running totals in `PeerStats`
  (`xr_received`, `xr_lost`, `xr_duplicated`); VoIP metrics become a `VoipMetrics` event.

### 3. ULPFEC levels

`RtcConfig::set_ulpfec_level0(Some(l0))` calls `FecEncoder::set_ulp_level0` on every ULPFEC
encoder (lines where `red` / `ulpfec` is negotiated, simulcast encodings included): the FEC
packets of a frame protect the first `l0` bytes of each packet, the last one adds a level 1
over the rest. Default `None`: whole-packet ULPFEC as before. Nothing in SDP says a receiver
reads levels, and libwebrtc reads level 0 alone (a lost packet longer than `l0` would be
rebuilt wrong in Chrome), so it is for peers that are this stack; the docs say so. The receive
side needed no change: the only-rtp decoder rebuilds packets from any number of levels.

### 4. CNAME and SDES items

- The CNAME of a peer connection is `random_cname` of 12 random bytes (RFC 7022 §4.2:
  short-term persistent, 96 random bits in base64), new per peer connection (it was 16
  random alphanumerics, already per connection).
- Received SDES chunks become typed `SdesItem`s per source; a `SourceDescription` event reports
  them when a source's items first arrive or change (at most 64 sources remembered).

The new events are variants of the crate-private `Other` behind `Event::Other` (their shape is
not promised, as for the existing statistics events).

### API

Additive: `Endpoint::{bind_rtcp, rtcp_addr}`, `RtcConfig::{set_rtcp_mux_policy,
enable_rtcp_xr_blocks, set_ulpfec_level0}`, `RtcpMuxPolicy` (`#[non_exhaustive]`),
`XrBlocks`. No only-ice or only-rtp change.

## Consequences

- Tests (`crates/only-webrtc/src/rtc/tests_mux.rs`, simulated network and time): two peers
  without rtcp-mux, DTLS-SRTP: no `a=rtcp-mux`, `a=rtcp`, no BUNDLE, a component-2 candidate
  of the same foundation and one less priority; two handshakes; audio both ways; RTP only
  between the component-1 ports, RTCP only between the component-2 ports, DTLS on both;
  sender reports and RTTs on both sides; an SRTCP packet under component 1's keys refused on
  component 2 and the same packet under component 2's accepted. The `Negotiate` policy against
  a muxing peer (one component, BUNDLE kept, re-offers without component 2) and against one
  that is not (two components). SDES-SRTP without rtcp-mux (RTCP on component 2, no DTLS
  datagram). The default policy, browser offers and offers without rtcp-mux to a peer without
  an RTCP socket answered as before; the refusals. XR negotiation (intersection, VoIP metrics
  on audio only, with `rcvr-rtt`); receipt blocks and VoIP metrics over a link losing 10 % of
  media (loss counted within bounds, loss rate and round trip in the VoIP block, totals in the
  statistics); nothing without negotiation. RFC 7022 CNAMEs and the typed SDES event. ULPFEC
  with `l0 = 120` under 8 % loss and no NACK: at least 180 of 200 three-packet frames whole
  (whole-packet ULPFEC within 10 frames of it) for less than 85 % of the bytes.
- Integration (`crates/only-webrtc/tests/rtcp_mux.rs`, two `Endpoint`s over loopback with
  RTCP sockets): Opus echoed over two components with DTLS-SRTP and with SDES-SRTP (sender
  reports, `rtcp_mux: false`, an RTT in the statistics); `Negotiate` and the default policy
  keep rtcp-mux; XR blocks negotiated end to end (receipt, VoIP metrics and SDES events); the
  component-2 checks leave from the RTCP socket. The existing only-webrtc tests pass unchanged.
- Interop: browsers and pion always mux; pion/webrtc only implements the `require` policy and
  pion/ice has one component (ADR-055), so there is no pion check without rtcp-mux. The
  two-component ICE layer is checked against libnice (ADR-055); the browser and pion scripts
  (`tools/interop/webrtc`) are unaffected since a default peer's SDP is unchanged.
- Fuzzing: `webrtc_sdp` also tries every input with a configuration that has component-2
  candidates, the `Negotiate` policy, every XR block and ULPFEC levels, and checks that an
  answer never carries `a=rtcp-mux` and `a=rtcp` together, carries no BUNDLE without
  rtcp-mux, and carries `a=rtcp` in its sections in use once the peer switched to two
  components; two seeds (an `Off` offer and its answer). 16 minutes on gpu51: 287 k runs, no
  finding in the code (an earlier run caught a too-strict check in the target: an offer whose
  only non-mux section is rejected leaves no section for `a=rtcp`; kept as a regression input).
- Costs: a session without rtcp-mux runs a second DTLS handshake and consent check; an
  endpoint with an RTCP socket holds one more socket. XR receipt blocks cost a receipt log of
  up to 4096 entries per received stream (8 bytes each) and a compound per stream and
  second.
- Not done: server-reflexive and relayed candidates of component 2; several transports (no
  BUNDLE) in one session, so sessions without rtcp-mux have one media section and no data
  channels; component 2 on `RtcServer`; the VoIP quality fields that need the codec (levels,
  R factor, MOS, jitter buffer); signalling that a receiver reads ULPFEC levels.
