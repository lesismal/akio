# ADR-082: Scalable (L4S) CE response, RFC 6679 signalling, ECN over relays, latching the DTLS handshake, and DTLS-SRTP MKIs

English | [简体中文](082-webrtc-l4s-rfc6679-dtls-latching-mki.zh-CN.md)

Status: accepted (2026-11-22)

## Context

ADR-077 made RTP ECN-capable and added latching for media without ICE. It left these open:

- **CE was loss.** A packet reported CE counted as a loss for the loss-based control. That
  is the classic response (RFC 3168), so it is also what ECT(1) traffic got. RFC 9331 §4.3
  says ECT(1) traffic must respond *scalably*. An L4S queue (RFC 9332) marks once packets
  wait about a millisecond, so a classic sender backs off far below the link rate.
- **ECN needed RFC 8888.** Validation and the CE signal came only from RFC 8888 reports.
  Endpoints that implement RFC 6679 itself had no way in: they use `a=ecn-capable-rtp`, the
  RTCP ECN feedback message and the XR ECN summary. That covers SIP stacks, and peers that
  use transport-wide feedback for congestion control.
- **TURN and ICE-TCP.** No codepoint was sent through relays. On a TCP path the receiver
  then reported Not-ECT, and the path "failed" after a few probes.
- **Latching needed SRTP keys.** With DTLS-SRTP and no ICE, the handshake needs the remote's
  address first. A phone behind a NAT can never be reached at the private address in its SDP.
- **No MKI with DTLS-SRTP.** SDES MKIs came in ADR-072. only-dtls and only-srtp already
  supported the `use_srtp` MKI (RFC 5764 §4.1.3), but nothing used it.

Constraints: nothing changes by default. Each new behaviour follows from an option that
already exists or from a new opt-in. A bundled session's hot path gains no work.

## Decision

### 1. Scalable response to CE (`only_rtp::EcnResponse`, `BandwidthEstimator`)

- `BandwidthEstimator::set_ecn_response(EcnResponse::{Classic (default), Scalable})`.
  `set_rtt` gives the response its round. `on_ecn_counts(now, ect, ce)` takes aggregate
  counts from feedback that has no per-packet results (section 2). `ce_fraction()` reports
  the smoothed fraction.
- **Scalable** (TCP Prague / DCTCP shape, for a rate):
  - CE is no longer a loss.
  - Per round (the RTT clamped to 25..500 ms, 100 ms until known), the fraction of
    ECN-capable results marked CE is smoothed with gain 1/16 (`alpha`).
  - A round with CE marks on packets sent *after the last cut* lowers a third rate to
    `(1 - alpha/2) x min(estimate, acknowledged rate)`. Like DCTCP, that happens at most
    once per window.
  - A round without CE adds an eighth of a 1200-byte packet per RTT per RTT. The virtual
    RTT is at least 25 ms, Prague's RTT independence. Growth stops at 1.5x the
    acknowledged rate + 10 kbps.
  - The estimate is the lowest of the delay-based, loss-based and scalable rates.
  - Fallback (RFC 9331 §4.3): CE that arrives while the delay detector reports over-use
    also counts as loss. A classic ECN queue marks only after its delay has grown.
  - Aggregate counters carry no send times. There, marks within an RTT + 100 ms of a cut
    count toward alpha but cannot cut again.
- **Increase gain.** Reno's one packet per RTT made the rate overshoot. A paced sender
  hears about it an RTT plus a feedback interval late, by which time a step-marking queue
  has marked whole rounds. The delay detector then saw the queue grow and cut the rate the
  slow way. In a simulated 2 Mbps L4S queue: gain 1 gave 89 % utilisation, 1/8 gave 93 % at
  0.4 ms of queue, and the classic response gave 82 %.
- **only-webrtc**: marking ECT(1) selects the scalable response; ECT(0) keeps the classic
  one. The RTT from RTCP reaches the estimator.
- **Pacing while marking ECT(1)**: 1.5x the estimate with a 1 ms burst allowance, instead
  of 2.5x and 40 ms. A frame sent as one burst queues several packets deep whatever the
  rate, and an L4S queue marks that. Simulated 6 Mbps step-marking queue, encoder at 90 %
  of the estimate:

  | Pacing | Received | Queue |
  | --- | --- | --- |
  | 2.5x / 40 ms | 3.9 Mbps | |
  | 1.5x / 5 ms | 2.6-3.4 Mbps | |
  | 1.5x / 1 ms | 4.9 Mbps | 1.3 ms |
  | No ECN | 4.7-5.1 Mbps | 7.3 ms |
  | ECT(0) classic | 1.36 Mbps | |

### 2. RFC 6679 signalling (`rtc/ecn_fb.rs`; only-rtp `EcnFeedback`, `EcnSummary`, `EcnReceiver`)

- **Wire formats** (only-rtp `ecn.rs`):
  - The RTCP ECN feedback message is RTPFB FMT 8. It carries the extended highest sequence
    number, the ECT(0) / ECT(1) / CE / not-ECT counters, lost and duplicates.
  - The XR ECN summary report is block type 13, with five words per source. Lengths that
    are not a multiple of five are discarded.
  - Both travel as `Rtcp::Unknown` / `XrBlock::Unknown` with conversions both ways. Adding
    enum variants would break exhaustive matches.
  - `EcnReceiver` keeps the per-source counters: duplicates over a 512-number window, lost
    as expected minus received, and the extended sequence number as RFC 3550 report blocks
    number it. It flags news: a source's first ECN-capable packet, or a CE mark.
- **SDP.** With ECN marking on:
  - Every audio and video section offers `a=ecn-capable-rtp:rtp mode=setread; ect=N`,
    `a=rtcp-fb:<pt> nack ecn` and `ecn-sum` in `a=rtcp-xr`.
  - An offer whose methods include "rtp" is answered the same way, with one method.
  - Only the "rtp" initiation method is implemented: no "ice" (STUN ECN-CHECK) and no
    "leap". Other offers get no attribute in the answer, so RFC 6679 is off in both
    directions (§6.1.1).
  - Both sides must opt in, since the answerer needs ECN marking configured. The remote's
    `ect=` preference is not followed: each side marks the codepoint it is configured with.
- **Receiving.**
  - Feedback messages go out when news arrives (at most every 20 ms) and with every regular
    report. Each goes from, and on the transport of, the line that receives the source.
  - Each section's compound report carries a summary of its sources when `ecn-sum` was
    negotiated.
  - With RFC 8888 in use, none of this is sent: its reports already carry every codepoint.
- **Sending.**
  - A remote that reads ECN (`setread` or `readonly`) and reports it, by feedback messages or
    summaries, enables marking without RFC 8888, while the estimator runs on transport-wide
    feedback.
  - The difference between two reports about a source is matched with the packets sent
    between their extended highest sequence numbers. The first report is a baseline.
  - The path fails when marks come back as the other ECT, or when marked packets arrive
    with none ECN-capable while the not-ECT count accounts for them.
  - Otherwise the counts go to the ADR-077 state machine as received or lost: initiation,
    capable, back to testing on heavy loss.
  - Summaries are matched with the report block about the same source in the same compound.
    The CE difference goes to the estimator (`on_ecn_counts`).

### 3. ECN over TURN, and off on TCP paths

- **TURN over UDP.** Relayed RTP reaches the server as ChannelData or a Send indication.
  That datagram is sent with the RTP packet's codepoint; STUN requests never carry one.
  RFC 8656 §12 asks the server to copy the codepoint onto the relayed datagram (its
  "preferred behaviour").
- **The other direction.** A datagram from a UDP allocation keeps the codepoint it arrived
  with: the server copied the peer's. Over DTLS to the server the outer datagram is the
  association's, so it is not used.
- **What can be checked.** Validation decides whether a relay copies. One that sets
  Not-ECT, as RFC 8656 allows, fails the path like any clearing middlebox, and media goes
  on unmarked.
- **only-turn's own server does not copy yet.** Its relay path is being worked on
  elsewhere (TCP allocations, ADR-076), so it is left as is. A path through it fails
  validation after a few probes.
- **TCP paths.** A local candidate that is ICE-TCP (RFC 6544), or an allocation over TCP or
  TLS, has no codepoint to give. ECN there is TCP's own business, and a TURN server reached
  over a stream has nothing to copy. Such a path never starts ECN: it stays *off*, not
  failed. The endpoint names relayed candidates over streams to the peer
  (`Rtc::set_no_ecn`). A later UDP path starts initiation as usual.

### 4. Latching the DTLS handshake (`rtc/latch.rs`)

- **When.** No ICE, latching configured, DTLS-SRTP with this side the DTLS *server*, the
  handshake not complete, and nothing heard from the description's address yet. An
  `actpass` offer is answered `passive` when latching, so the remote starts the handshake.
  An offer we make is `actpass` as before. A remote answering `passive` makes this side the
  client, and then nothing latches: our ClientHello goes to the unreachable SDP address.
- **Cookie exchange first.**
  - A DTLS datagram from an unknown source is checked with `only_dtls::HelloVerifier`
    (stateless). There is one verifier per process: the endpoint offers a datagram to one
    latching peer after another, so a cookie must verify at the next peer too.
  - A ClientHello without a valid cookie gets a HelloVerifyRequest, or a DTLS 1.3
    HelloRetryRequest. Nothing changes.
  - The endpoint routes the source to the peer that answered, so the second ClientHello
    reaches that peer. It goes through the same check, because the pair has not moved yet.
- **Tentative latch.** A ClientHello with a valid cookie proves that the source receives at
  its address. Component 1's pair moves there tentatively, a fresh server association runs
  with it, and the endpoint routes the source.
- **Confirmation.**
  - The remote's certificate must match the description's fingerprint. A completed
    handshake latches as the policy says: the move is counted, and the SDP address is
    released.
  - A handshake that fails (wrong certificate), is closed, or does not complete within 4 s
    moves the pair back without killing the peer. Another source can then try.
  - While one runs, other sources' ClientHellos are ignored, and their retransmissions get
    in later.
- **Security.** An off-path attacker cannot get a cookie for an address it does not
  receive at, and cannot finish a handshake without the remote's private key. One who reads
  the SDP can, from its own address, hold the tentative slot for 4 s at a time and delay the
  call. It cannot take over the media.
- **Limits.**
  - Component 2's own DTLS (RTCP without rtcp-mux) does not latch this way. It latches on
    its SRTCP once the keys exist, as before.
  - Several latching peers on the same local address get handshakes in the order the
    endpoint offers datagrams. A peer whose certificate check fails gives the next attempt
    to the next peer. Separate local addresses per call (`bind_transport_socket`) avoid
    this.

### 5. SRTP MKIs with DTLS-SRTP (`RtcConfig::set_dtls_srtp_mki_length`)

- 0 (default) for none, otherwise 1..=128 bytes.
- **As the DTLS client:** offers an MKI of that length in `use_srtp`. Its value counts the
  session's handshakes, so a later handshake's keys can be told apart.
- **As the server:** agrees to whatever the client offers (`with_srtp_accept_mki`).
- When agreed, the SRTP and SRTCP contexts carry it both ways, component 2's included. A
  peer that does not agree answers with an empty MKI, and SRTP runs without one.
- Nothing re-keys mid-session today: a DTLS re-handshake is not started. The MKI matters
  for gateways that require one, and for a later re-keying.

### API

Additive.

- only-rtp: `EcnResponse`, `BandwidthEstimator::{set_ecn_response, ecn_response, set_rtt,
  ce_fraction, on_ecn_counts}`, `EcnCounters`, `EcnDelta`, `EcnFeedback`, `EcnSummary`,
  `EcnReceiver`, `ECN_FEEDBACK_FMT`, `ECN_SUMMARY_BT`.
- only-webrtc: `RtcConfig::set_dtls_srtp_mki_length`.
- No change to only-turn, only-dtls or only-srtp.

## Consequences

- **Defaults** are unchanged. With ECN marking on, offers carry the RFC 6679 attributes.
  Chrome ignores them, and so do remotes that do not know them.
- **Tests:**
  - only-rtp: the estimator through a simulated L4S queue (scalable vs classic vs no ECN,
    2 and 10 Mbps, where the CE fraction falls as the rate grows); the counter path;
    feedback and summary round trips; receiver counting with wrap, loss, duplicates and
    late arrivals.
  - only-webrtc simulated network: ECT(1) through a 6 Mbps step-marking queue at 82 % of
    the link with a 1.3 ms queue, against 1.36 Mbps for ECT(0); RFC 6679 negotiation,
    validation, clearing / re-marking detection and CE to the estimator without RFC 8888;
    no RFC 6679 when the answerer does not mark; TCP paths off, not failed; the DTLS
    handshake latching onto a phone behind a NAT both offer directions (cookie exchange
    first), not without the option, a foreign certificate tried and refused before the
    phone latches; DTLS-SRTP MKIs agreed, with and without rtcp-mux, and not when either
    side is off.
  - Endpoints over loopback: a DTLS phone whose answer names a dead port, found by
    latching.
- **Fuzzing:** the `rtp_rtcp` target converts ECN feedback and summaries both ways and feeds
  an `EcnReceiver`. `webrtc_sdp` seeds include RFC 6679 offers and answers. On gpu51, 5 minutes per target: 1.03M runs
  (`rtp_rtcp`) and 46.4k runs (`webrtc_sdp`), no finding.
- **Interop:** see the CHANGELOG / DEV-PLAN entry of 2026-11-22. Chrome 157 with `ecn.sh`;
  `latch.sh` with a DTLS-SRTP phone behind the NAT.
- **Performance:** a same-run A/B against main 7e4db2d9 on gpu51 (`webrtc-bench`, default
  configurations, 7 rounds, medians) gives media 0.999x and data channels 0.997x, with the
  ranges overlapping (docs/BENCHMARKS.md).
- **Costs:**
  - With ECN on: per received RTP packet, an RFC 6679 counter update when negotiated; per
    report, a walk over the sequence numbers between two reports.
  - With ECT(1): smoother pacing, so frames leave over about their own duration instead of
    at once.
  - With DTLS latching: an HMAC per ClientHello from an unknown source.
- **Not done:**
  - RFC 6679's "ice" and "leap" initiation, and following the remote's `ect=` preference.
  - ECN feedback for RTP over ICE-TCP (there is none to give).
  - Copying the codepoint in only-turn's own relay.
  - Retrying ECN on a path that failed.
  - Latching component 2's DTLS.
  - Latching when this side must be the DTLS client.
  - DTLS re-keying, so the MKI value changes only between sessions' handshakes.
