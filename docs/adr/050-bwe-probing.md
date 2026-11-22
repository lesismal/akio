# ADR-050: Bandwidth probing in the akio-rtp estimator

English | [简体中文](050-bwe-probing.zh-CN.md)

Status: accepted (2026-11-19)

## Context

`akio_rtp::BandwidthEstimator` (ADR-036, the GCC-like send-side estimator fed by transport-wide or
RFC 8888 feedback) only grew by its AIMD rules: 8 % per second, additively near the rate of the
last decrease, and never above 1.5 times the acknowledged bitrate + 10 kbps. A WebRTC sender
starting at 300 kbps therefore needed 23 s to reach 90 % of a 2 Mbps link and 44 s for 10 Mbps,
and a sender that is application-limited (an encoder at its top layer, the SFU forwarding one
layer) never learned that more was available: against headless Chrome the echo server's estimate
stayed at its 1 Mbps start for the whole run. The crate README listed "probing in the estimator"
as not implemented.

libwebrtc solves this with probing: `ProbeController` decides when to probe and at which rates,
`BitrateProber` paces a *cluster* of packets at a target rate for at least 15 ms and 5 packets,
and `ProbeBitrateEstimator` turns the cluster's feedback into a measured rate that sets the
delay-based estimate. The packets are padding or RTX copies of recent media, tagged with the
cluster id in the pacer.

akio-webrtc has no pacer: `write_media` packetizes a frame and queues its packets for the
transport at once. Another session is editing akio-webrtc at the same time (DTLS 1.3, cryptex,
Opus RED), so the akio-webrtc change must stay small and inside the send path.

## Decision

1. **Probing lives in akio-rtp, sans-io, behind `BandwidthEstimator`** (a private `probe`
   module), on by default; `with_probing(false)` restores the previous estimator exactly (no
   probe is ever requested and nothing else changes).
   - *When* (libwebrtc's `ProbeController` defaults): on start, clusters at 3 and 6 times the
     start rate; while waiting for results, a result above 70 % of the last probe starts another
     at twice the estimate (stops after 1 s without one, or at the upper bound / REMB cap).
     While application-limited, a probe at twice the estimate every 5 s. After a large drop of
     the estimate (below 66 % of the previous one), a probe at up to 85 % of the rate before the
     drop when the delay detector is back to normal (under-use turned normal, or 500 ms after
     the drop), then every 3 s for 30 s while the estimate stays below that; such a probe aims
     at no more than twice the estimate and probes further while results keep up.
     `on_network_change(now)` (a new path) resets the delay and loss state to the start rate and
     probes from scratch.
   - *Application-limited* is measured from the feedback itself (no extra hook): the media sent
     in the last 500 ms (by the send times in the packet results, probes excluded) below 60 % of
     the estimate enters it, above 70 % leaves it. `application_limited()` reports it.
   - *Pacing*: `poll_probe(now)` returns `ProbePacket { cluster, size }` when a packet is due
     (call until `None`), `probe_timeout()` when the next one is; the caller reports what it
     really sent with `on_probe_sent(now, cluster, bytes)`, and packets are due when the bytes
     sent so far reach the cluster rate. A cluster lasts at least 15 ms and 5 packets; sizes aim
     at about 10 packets per cluster (200..1200 bytes) so that one lost packet moves the result
     less. Up to 4 clusters wait; one not started within 1 s is dropped.
   - *Measurement* (libwebrtc's `ProbeBitrateEstimator`): `TwccSender::on_sent_probe` and
     `CcfbSender::on_sent_probe` log a probe packet with its cluster, and `PacketResult` gains
     `probe: Option<u32>`. Once 80 % of a cluster's packets and bytes arrived, the send rate
     (without the last packet sent) and receive rate (without the first received) over at most a
     second give the result: their minimum, or 95 % of the receive rate when it is below 90 % of
     the send rate (saturated); a receive / send ratio above 2 is discarded. **Deviation**: the
     measurement also counts the media packets sent inside the cluster's send interval (from the
     same feedback). libwebrtc's pacer sends media inside a cluster, so its clusters carry media
     anyway; our probes go out next to unpaced media, which shares the bottleneck, and leaving it
     out made a saturated cluster report only the probe's share (7.2 instead of 9.5 Mbps on
     10 Mbps).
   - *Effect*: unless the detector says over-use, a result raises the delay-based rate to it
     (and clears the additive-increase region) and raises the loss-based rate to at least it,
     so moderate loss (2..10 %, where the loss-based rate holds) does not stop the ramp. Results
     never lower the estimate (libwebrtc's `SetEstimate` may); decreases stay with the delay and
     loss detectors. Results are capped at the bounds and the REMB / TMMBR cap.
   - **Deviation** from libwebrtc's drop probe: libwebrtc only probes after a drop while
     application-limited (or just after), once per 5 s and within 5 s of the drop. Ours does not
     require application-limited and keeps probing every 3 s for 30 s at no more than twice the
     estimate, because without a pacer to fill the gap the AIMD needs tens of seconds to recover
     from a transient drop (a capacity step 2 -> 10 Mbps: 3.6 s instead of never in a 30 s run).
2. **`SendStream::padding(now, size, rtx_pt, map, f)`** builds probe packets: an RTX copy of
   the newest packet in the history whose payload fits (else the newest), which the receiver
   takes as a duplicate; with an empty history or without RTX a padding-only packet (at most
   255 bytes of padding) on the RTX stream if there is one, else on the media stream with the
   next sequence number. Probe packets do not enter the history or the sent / resent counters.
   `None` before the stream sent anything.
3. **akio-webrtc: the minimal pacer hook** (new file `rtc/pacing.rs`, 11 lines in `rtc.rs`).
   With the estimator enabled (`RtcConfig::enable_bwe`), `send_probes` runs after each
   `write_media` and in `handle_timeout`, and `poll_output`'s timeout includes the probe timeout;
   probe packets go on the stream that sent the most media among the lines with congestion
   control feedback (transport-wide or RFC 8888), with fresh transport-wide sequence numbers and
   abs-send-time and the RID moved to the repaired-RID extension on RTX (as for NACK answers).
   Nothing is probed before media was sent; clusters that cannot be sent (no ICE pair, no such
   stream) are dropped with `cancel_probes`, so the probe timeout never stays in the past. A change of the ICE selected pair (not the first
   pair) calls `on_network_change`. No configuration: probing comes with `enable_bwe`.

## Consequences

- Simulated links (`crates/akio-rtp/src/tests_probe.rs`: an encoder following the estimate with
  ±20 % frame sizes, 20 ms each way, a 300 ms drop-tail FIFO, feedback every 100 ms; start
  300 kbps), probing on / off: 90 % of 0.5 Mbps after 0.15 s / 5.4 s, of 2 Mbps after 0.25 s /
  23.4 s, of 10 Mbps after 0.35 s / 44.3 s; peak estimate 1.12x / 1.03x / 1.01x the capacity
  (off: 1.08x / 1.01x / 0.30x); largest queueing delay 81 / 32 / 22 ms. A step 10 -> 2 -> 10 Mbps:
  down to 110 % of 2 Mbps in 0.6 s, back to 90 % of 10 Mbps 3.6 s after the step (off: never in
  30 s), peak 1.05x at 2 Mbps. 5 % random loss on 4 Mbps: 90 % after 0.35 s (off: never; the
  loss-based rate holds at the start). 6 Mbps of competing traffic on 10 Mbps: our share settles
  at 0.93 of the 4 Mbps left. An encoder capped at 1 Mbps on 10 Mbps: estimate 9.5 Mbps after
  30 s (off: 1.65 Mbps). The runs are deterministic (seeded, simulated time); a sweep of 40 seeds
  with 0..2 % loss is part of the tests.
- Chrome 157 as receiver (`tools/interop/webrtc/bwe.sh`: Chrome's VP8 echoed back by the
  fec-server with the estimator on, start 1 Mbps, 15 s): before, the estimate never left
  1 Mbps; now it reaches 10 Mbps 0.17-0.22 s after the connection (transport-wide and RFC 8888
  feedback) and the 20 Mbps bound later, and Chrome decodes every echoed frame (the RTX copies
  are taken as duplicates).
- The estimate now reaches the link early, so the delay detector's over-use cut (85 % of the
  acknowledged rate over 500 ms, which lags a fast ramp) can follow shortly after; the drop
  probing brings it back. Mean estimate over 5-30 s on 10 Mbps: 0.86 of the capacity (off: 0.13).
- Probes cost bandwidth: about 15 ms at up to twice the estimate per probe (78 kB in the first
  30 s on 10 Mbps).
- API, all additive except `PacketResult`'s new public field (akio-rtp is internal tier: struct
  literals of `PacketResult` outside the crate must add `probe: None`): `ProbePacket`,
  `BandwidthEstimator::{with_probing, poll_probe, probe_timeout, on_probe_sent,
  cancel_probes, on_network_change, application_limited}`, `TwccSender::on_sent_probe`,
  `CcfbSender::on_sent_probe`, `SendStream::padding`. akio-webrtc's public API is unchanged.
- Not done: probing when the configured maximum is raised, the network-state-estimate driven
  probing and the probe-uncertainty / rapid-recovery variants of libwebrtc; a real pacer in
  akio-webrtc (media still leaves in frame bursts); a configuration switch to turn probing off in
  akio-webrtc.
