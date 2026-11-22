# ADR-086: RFC 6679 "ice" and "leap" ECN initiation, the remote's `ect=`, retrying ECN, latching RTCP's DTLS and the DTLS client

English | [简体中文](086-webrtc-ecn-initiation-retry-dtls-latching.zh-CN.md)

Status: accepted (2026-11-22)

## Context

ADR-082 left these WebRTC items open:

- **Initiation.** RFC 6679 §7.2 defines three ways to start ECN on a path. Only "rtp" was
  implemented: a quarter of the packets marked until feedback confirms them. "ice" (an
  ECN-marked STUN check) and "leap" (mark everything at once) were not.
- **`ect=`.** The remote's preferred codepoint was ignored. Each side marked the codepoint it
  was configured with.
- **A failed path stayed unmarked** until the path itself changed.
- **RTCP's own DTLS** (component 2, without rtcp-mux) did not latch before keys existed.
- **The DTLS client role.** When this side must start the handshake (the remote said
  `passive`), its ClientHello goes to the private address in the remote's SDP, and nothing
  latched.
- **DTLS re-keying** was not available.

Constraints, as in ADR-082: nothing changes by default, and the default send and receive paths
gain no work.

## Decision

### 1. Initiation methods (akio-ice `ecn.rs`; akio-webrtc `rtc/ecn.rs`, `rtc/ecn_fb.rs`)

- **SDP.**
  - With ECN marking on and ICE with a full agent, sections offer
    `a=ecn-capable-rtp:ice,rtp mode=setread; ect=N`. Without ICE, or as a lite agent, they offer
    `rtp` only. `a=ice-options` then carries `rtp+ecn` (§6.4).
  - The new `RtcConfig::set_ecn_initiation(EcnInitiation::LeapOfFaith)` puts `leap` first.
    Without it, `leap` is never offered.
  - An offer is answered with the first method, in our order of preference, that it lists:
    `leap` when configured, then `ice` (only where we can run checks), then `rtp`, then `leap`.
    A remote that offers only `leap` is therefore answered with it either way.
- **"rtp"** is ADR-077's probing, unchanged.
- **"leap"** (§7.2.3): initiation marks every RTP packet from the first one, and judges them the
  same way as probing does:
  - a cleared or re-marked codepoint fails the path;
  - so do marked packets that keep getting lost;
  - ten marks received with nothing lost make it capable.

  Without RFC 6679 (Chrome, RFC 8888 only), `LeapOfFaith` also applies.
- **"ice"** (§7.2.2):
  - Once ICE has selected the pair, `IceAgent::check_ecn` sends an extra Binding request on it.
    The request is marked with the codepoint and carries ECN-CHECK (0x802D) with V = 0.
  - The responder (`IceAgent::handle_receive_ecn`, given the datagram's codepoint) answers with
    ECN-CHECK V = 1 and the codepoint it read. Through plain `handle_receive` the attribute is
    ignored, as by an agent that cannot read ECN.
  - Transmissions: 5 in all, 500 ms apart. This is the "parallel mode" interval Ta x k with
    k = 10, since media flows meanwhile; the RFC recommends at least 4 retransmissions. The
    check is given up 500 ms after the last one.
  - A V = 0 answer asks for the next transmission at once.
  - `IceEvent::EcnChecked { local, remote, ecn }` reports the codepoint seen. It is `None` when
    no answer came, or the answer had no attribute.
  - `IceAgent::poll_transmit_ecn` returns datagrams with their codepoint. Only these checks
    carry one. akio-webrtc sends ICE's datagrams through it.
  - The path (`Phase::Verifying`) marks nothing until the result comes:
    - our codepoint or CE: capable, every packet marked;
    - anything else: failed.

    Failure detection from feedback runs as for the other methods.
  - Where no check can run (fixed pairs, a lite agent), the path probes instead.

### 2. The remote's `ect=`

- `ect=` is a receiver's preference (§6.1). It is "0" when absent, and "it will be the sender's
  choice to honour" it.
- Toward a remote that negotiated RFC 6679, the path marks what the first negotiated section
  asks for: `ect=0` gives ECT(0), `ect=1` gives ECT(1), and `random` leaves ours.
- The estimator's CE response follows the codepoint actually marked (RFC 9331 §4.3): scalable
  for ECT(1), classic for ECT(0). A renegotiation that changes the codepoint restarts
  initiation.
- Our own answer's `ect=` still states our configured preference.
- **Consequence:** a peer configured with `EcnMarking::Ect1` marks ECT(0) toward an RFC 6679
  remote that writes no `ect=`. Remotes without RFC 6679 (browsers) are unaffected.

### 3. Retrying a failed path (RFC 6679 §7.4.1, option 1)

- A failed path starts initiation again after 10 s, then 20, 40, ... up to 300 s. It retries by
  probing, or with a new STUN check under "ice".
- Reaching full marking resets the wait to 10 s.
- After three fallbacks from full marking on the same path (marks confirmed, then lost or
  cleared), the path is not tried again: §7.4.1 recommends giving up then.
- A new path starts afresh.
- The retry is checked when an RTP packet is about to be marked, so it adds no timer.

### 4. Latching RTCP's own DTLS handshake (`rtc/latch.rs`)

- The tentative handshake of ADR-082 §4 now exists per ICE component.
- Component 2 (RTCP on its own port) handles a ClientHello from an unknown source on its local
  address the same way: a stateless cookie exchange first, then a tentative pair to that
  source. It latches when the handshake completes with the description's fingerprint.
- Failure, a close, or 4 s without completing moves the pair back.
- Component 2 no longer has to wait for SRTCP keys.

### 5. Latching as the DTLS client

- **When.** No ICE, latching configured, DTLS-SRTP with this side the client, the component's
  handshake not complete, and nothing heard from the description's address.
- **Trigger.** A datagram from an unknown source on the component's local address: a STUN
  message (an RFC 6263 keepalive, a Binding request), or RTP before keys exist.
- **What it does.**
  - The component's pair moves to that source tentatively.
  - A fresh client handshake starts toward it, and its server must prove the description's
    fingerprint.
  - Failure, a close or 4 s moves the pair back. The handshake then starts over toward the
    description's address.
  - The endpoint now also offers STUN from unknown sources (no ICE agent claimed it) to
    latching peers.
- **Security.**
  - Only the right certificate latches.
  - One attempt runs at a time per component, so a spoofed trigger makes this side send at most
    the handshake's few ClientHello transmissions to the spoofed address per 4 s.
- **Keepalives.** A NATed DTLS server sends nothing a NAT would let through until it hears from
  the client. So the new `RtcConfig::set_plain_keepalive(every)` sends RFC 6263 keepalives
  without ICE: a STUN Binding Indication (28 bytes) on every component's path, as soon as the
  path exists and then every `every`. It also keeps NAT bindings open through silence. Default
  off.

### 6. DTLS re-keying: not done, and why

- **DTLS 1.2.** Re-keying DTLS-SRTP takes a new handshake, and in DTLS 1.2 that is
  renegotiation. Chrome (BoringSSL) and pion refuse renegotiation, and akio-dtls does not
  implement it (it has a history of attacks, RFC 5746). No peer exists to interop with.
- **DTLS 1.3.** KeyUpdate changes the record keys, but not the SRTP keys exported from the
  handshake.
- **A new association.** The standard alternative is a new association signalled by a changed
  `a=tls-id` (RFC 8842). It also restarts SCTP (the data channels), and browsers do it only
  with an ICE restart.
- **Need.** SRTP's own limit (2^48 packets per key) makes re-keying unnecessary within a
  session.
- **What stays.** The MKI of ADR-082 still counts handshakes, so a future new association can
  be told apart.

### API

Additive.

- akio-ice: `IceAgent::{check_ecn, ecn_checking, handle_receive_ecn, poll_transmit_ecn}`,
  `IceEvent::EcnChecked`, `ECN_CHECK_SENDS`, `ECN_CHECK_INTERVAL`, `ECN_CHECK_GIVE_UP`.
- akio-webrtc: `EcnInitiation`, `RtcConfig::{set_ecn_initiation, set_plain_keepalive}`.
- The `ecn_state` statistic can also read "verifying".

### Fix on the way

DTLS-SRTP without ICE and without BUNDLE (one transport per section) never read the remote
fingerprint, so no handshake started. It does now. Plain DTLS with RTCP on its own port is
exactly that case.

## Consequences

- **Defaults** are unchanged.
  - With ECN marking on and ICE, offers say `ice,rtp` and `a=ice-options:... rtp+ecn`. Browsers
    ignore both: Chrome 157 with `ecn.sh` still validates the path over RFC 8888.
  - Remotes with RFC 6679 now get their `ect=` honoured.
- **Tests** (simulated network):
  - "ice" verifies a path with one marked STUN check, before any RTP is marked, and fails a
    clearing path without marking RTP.
  - "leap" marks every packet with RFC 8888, with RFC 6679 over ICE, and with RFC 6679 without
    ICE, and still fails on a clearing path.
  - "rtp" without ICE.
  - The remote's `ect=0` makes an `Ect1` peer mark ECT(0) with the classic response.
  - A failed path retries and recovers once the clearing goes away (RFC 8888, RFC 6679 with and
    without ICE).
  - RTCP's own handshake latches both offer directions, with a cookie exchange, and RTCP flows
    both ways on component 2.
  - The DTLS client latches onto a keepalive, with and without rtcp-mux, and not without
    keepalives.
  - The DTLS client refuses an attacker's server (foreign certificate) and latches onto the
    phone after.
  - Keepalive timing.
  - Unit tests of the ECN-CHECK layout, the echo, retransmissions and giving up; of the path
    state machine (leap, verifying, backoff, fallbacks); and of the negotiation (method choice,
    `ect=`).
- **Fuzzing:** see the CHANGELOG / DEV-PLAN entry. `ice_stun` feeds every datagram through
  `handle_receive_ecn` and runs checks, and its seeds include ECN-CHECK requests and responses.
  `webrtc_sdp` seeds cover `leap` / `ice` / `ect=random` / `setonly` lists and `setup:passive`
  offers, and a configuration with leap and keepalives.
- **Interop:** see the CHANGELOG / DEV-PLAN entry.
  - `latch.sh`: RTCP's own handshake and the client role, behind an iptables NAT.
  - New `ecn6679.sh`: rtp / leap / ice between two akio peers over a real Linux NAT, and a
    router rule clearing ECN, then removed (failure, retry, recovery). No browser or SIP stack
    we can run implements RFC 6679's "ice" or "leap", so these run only between akio peers.
- **Performance:** a same-run `webrtc-bench` A/B against main da0637aa on gpu51 gives media
  0.999x and data channels 0.997x, with the ranges overlapping (docs/BENCHMARKS.md).
- **Not done:**
  - DTLS re-keying (section 6).
  - Copying the codepoint in akio-turn's relay: another session does that.
