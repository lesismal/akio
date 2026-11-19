# only-ice

[中文](README.zh-CN.md)

Sans-io ICE (RFC 8445) for [`only`](https://github.com/lesismal/only): full and lite agents,
consent freshness (RFC 7675), trickle (RFC 8838), ICE restarts, regular, aggressive and
renomination, for one component over UDP and TCP (RTP/RTCP muxed, BUNDLE), with an mDNS codec for
the `.local` candidates browsers send, on [`only-turn`](../only-turn)'s STUN codec and
[`only-crypto`](../only-crypto), in safe Rust (`#![forbid(unsafe_code)]`) with no other
dependencies. It is the ICE layer of the in-house WebRTC stack, replacing str0m's. An internal
crate (docs/api-stability.md): its API follows that stack and may change in any release.

## Driving an agent

An `IceAgent` has no sockets, threads or clocks. The caller gathers candidates, does the
signaling, passes in every datagram and the current time and sends what comes out:

```rust,ignore
use std::time::Instant;
use only_ice::{Candidate, Credentials, IceAgent, IceConfig, IceEvent};

let mut agent = IceAgent::new(IceConfig::new(false, /* controlling */ true), Instant::now());
agent.add_local_candidate(Candidate::host(socket.local_addr()?));
// SDP: a=ice-ufrag / a=ice-pwd from agent.local_credentials(), a=candidate from to_sdp().
agent.set_remote_credentials(Credentials::new(remote_ufrag, remote_pwd));
agent.add_remote_candidate(Candidate::parse(line)?); // trickle: any time
loop {
    while let Some(t) = agent.poll_transmit() { /* send t.contents from t.source to t.destination */ }
    while let Some(e) = agent.poll_event() {
        match e {
            IceEvent::StateChanged(s) => { /* New, Checking, Connected, Completed, ... */ }
            IceEvent::SelectedPair { local, remote } => { /* where DTLS/SRTP goes */ }
            _ => {}
        }
    }
    // wait for a datagram until agent.poll_timeout(), then:
    // if !agent.handle_receive(now, from, local_addr, &datagram) { /* DTLS, SRTP, ... */ }
    // or agent.handle_timeout(now)
}
```

- `send_pair()` is where application data goes: the selected pair, else (before nomination)
  the best valid pair; for a lite agent the pair of the last USE-CANDIDATE check.
- `restart(new_credentials, keep_local_candidates)` and `set_remote_credentials` with new
  values restart ICE; the old selected pair keeps working until the new generation nominates.
- `set_remote_lite(true)` for an `a=ice-lite` remote; `end_of_remote_candidates()` lets the
  agent reach `Failed`; `close()` stops it.
- `Candidate::parse` reports mDNS (`*.local`) and FQDN candidates as distinct `ParseError`
  variants (`is_unsupported()`); `Candidate::parse_resolved(line, |name| ...)` hands the name to
  a resolver and takes the address it returns (the name stays in `hostname()`). The `mdns`
  module builds the one-shot queries and reads the answers (RFC 6762; one question per message,
  as Chromium's responder wants), and answers queries for names of our own:
  `Candidate::with_hostname(name)` writes such a name instead of the IP (with
  `with_related(Some(0.0.0.0:0))` hiding the related address). The sockets are the caller's
  (only-webrtc's `Endpoint::resolve_mdns`).
- Nomination: regular by default; `IceConfig::aggressive_nomination` (USE-CANDIDATE on every
  check, the best pair that works wins) and `IceConfig::renomination` with
  `set_remote_renomination(true)` (draft-thatcher-ice-renomination: a better pair found after
  nomination is nominated again with a higher NOMINATION value). A controlled agent follows the
  highest NOMINATION value, or without one the highest-priority nominated pair.
- TCP candidates (RFC 6544): `TcpType`, `Candidate::host_tcp`, `tcp ... tcptype` in SDP, RFC 6544
  priorities below UDP's, pairing within a transport and between compatible types (active with
  passive, `so` with `so`). Active and `so` local candidates send checks like UDP ones (the caller
  opens the connection when the first goes out); a passive local candidate only answers: a check
  arriving over an accepted connection makes the pair. The caller frames the connections with
  `tcp::FrameReader` / `tcp::frame` (RFC 4571).

## Protocol coverage

- Candidates: RFC 8445 §5.1 priorities and foundations, SDP grammar of RFC 8839 §5.1 with the
  `generation`, `ufrag`, `network-id`, `network-cost` extensions.
- Checklist: pairs per IP family, pair priorities, pruning by base, Frozen/Waiting/
  InProgress/Succeeded/Failed with per-foundation unfreezing, at most 100 pairs; pacing one
  check per `Ta` (50 ms), triggered-check queue; retransmission from 250 ms doubling to 1.6 s,
  7 sends (the pair fails about 8 s after the first).
- Checks: USERNAME, PRIORITY, ICE-CONTROLLING/ICE-CONTROLLED with a random tie-breaker,
  USE-CANDIDATE, MESSAGE-INTEGRITY, FINGERPRINT; 400/401 answers, role conflicts (487) on
  both sides; peer-reflexive candidates; symmetric responses only; requests before the remote
  credentials are answered and their triggered checks wait.
- Nomination: regular nomination (best valid pair once no better pair is pending or 500 ms
  after the first valid pair; at once with a lite remote); aggressive nomination (RFC 5245
  §8.1.1.2) and renomination (draft-thatcher-ice-renomination-01, NOMINATION attribute 0xC001),
  both of which keep checking better pairs after a selection and move to one that works;
  controlled agents follow USE-CANDIDATE (the highest NOMINATION value, else the
  highest-priority nominated pair); lite agents select the pair of the last USE-CANDIDATE check.
- mDNS (`mdns`, RFC 6762): one-shot queries for `A` / `AAAA`, responses (multicast, unicast
  with QU, legacy unicast), compression pointers (backwards only, at most 16 per name), random
  UUID names.
- Consent freshness: checks every 5 s ±20 % on the selected pair (retransmitted 4 times),
  `Disconnected` after 30 s without responses (lite: without valid checks), recovery when
  they resume. `Failed` once every pair failed after end-of-candidates or 30 s.

Not implemented: several components (WebRTC always muxes RTP and RTCP: rtcp-mux, BUNDLE),
gathering (STUN/TURN clients are the caller's), sockets of any kind (the mDNS resolver and
responder, the TCP connections: only-webrtc's `Endpoint` has them), renominating when the
remote does not support renomination (an ICE restart does that).

## Testing

- Simulated network (`tests/sim.rs`): full↔full in both roles, full↔lite both ways, host,
  srflx and peer-reflexive candidates through a simulated port-restricted NAT, unreachable
  candidates, IPv4/IPv6 mixes, 24 seeds with 25 % loss, 10 % duplication and 300 ms of
  reordering, trickle, checks before remote credentials, role conflicts, consent loss after
  ~30 s and recovery, ICE restarts from either side (with and without new candidates, and
  onto a new path), `Failed` after end-of-candidates or the timeout, responses from the wrong
  address, forged integrity, malformed requests (400/401), RFC 5769 test vectors.
- Interop (`tests/pion.rs`, ignored): pion/ice v4.4.8 over loopback UDP in four setups
  (pion controlled, pion controlling, pion lite, only-ice lite), data exchanged both ways on
  the selected pair; needs `ONLY_ICE_PION_PEER` pointing at a small pion peer program.
- Nomination (`tests/sim.rs`): a better pair trickled after nomination is ignored with regular
  nomination and taken by both sides with aggressive nomination and with renomination (also
  over 10 % loss); aggressive nomination ends on the best pair; a controlled agent follows the
  highest NOMINATION value and ignores an older one.
- Fuzzing: targets `ice_stun` (datagrams into controlling, controlled and lite agents, also with
  aggressive nomination and renomination, and `Candidate::parse`), `ice_tcp` (framed
  connections) and `ice_mdns` (mDNS messages, candidate lines with names) in `fuzz/`;
  `fuzzing::tests` replays their corpora on stable.
