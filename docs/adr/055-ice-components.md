# ADR-055: Several components per ICE stream in only-ice

English | [简体中文](055-ice-components.zh-CN.md)

Status: accepted (2026-11-20)

## Context

`only_ice::IceAgent` (the ICE layer of the in-house WebRTC stack, ADR-044 for its latest
additions) handled one component: candidates of any component other than 1 were dropped, and
the selection, nomination, consent freshness and lite-agent state were single values. WebRTC
always muxes RTP and RTCP (rtcp-mux, BUNDLE), so that was enough for only-webrtc, but RFC 8445
streams may have several components, and the classic case, RTP on one port and RTCP on the next
(SIP endpoints, older RTP stacks, `a=rtcp` without `a=rtcp-mux`), needs two. The crate README
listed "several components" as not implemented.

RFC 8445 keeps one checklist per data stream holding the pairs of every component (§6.1.2), with
one pacing timer (§6.1.4.2). Foundations do not depend on the component (§5.1.1.3), so the RTP
and RTCP candidates of one socket pair share them; the initial states put, for each foundation,
the pair of the lowest component in Waiting and the others in Frozen (§6.1.2.6), and a check that
succeeds unfreezes the pairs of its foundation in every component (§7.2.5.3.3), so RTCP is
checked on a path once RTP works on it. Nomination and selection are per component (§8.1), the
checklist completes once every component has a nominated pair (§8.1.2), consent freshness runs
on each selected pair (RFC 7675 §5), and the PRIORITY of a check is computed with the
component's id (§7.1.1). The role (and its tie-breaker) belongs to the agent, not the component.

The single-component API is used by only-webrtc, which another session is changing at the same
time; it had to stay source-compatible and behave exactly as before.

## Decision

1. **Components are a property of the stream**: `IceConfig::components` (default 1, clamped to
   1..=256). Local candidates get theirs with `Candidate::with_component(n)`, which rewrites the
   low byte of the priority (`256 - n`, RFC 8445 §5.1.2.1) and keeps the foundation; remote
   candidates carry it in their SDP line as before. Candidates of components the stream does not
   have are still ignored (`add_local_candidate` returns `false`), so a default agent ignores
   component 2 as it always did. A candidate only pairs with one of its own component.
2. **One checklist, per-component state.** The pairs of every component stay in one list with
   one triggered queue and one `Ta` pacing; each pair records its component. What was a single
   value moves to a per-component record: the selected pair, the pair being nominated, the first
   valid / improved times that time regular nomination, the controlled side's highest
   NOMINATION value, consent (next check, last response, lost flag, transactions) and the lite
   agent's last valid check. The controlling side keeps one NOMINATION counter (values only have
   to grow per component).
3. **Frozen and Waiting as in RFC 8445 §6.1.2.6, with trickle.** Candidates arrive in any order,
   so the initial states are kept as an invariant instead of being computed once: a new pair is
   Frozen behind a pair of its foundation of a lower component that has not failed, or of its own
   component that is Waiting or being checked; a new pair of a lower component freezes again the
   Waiting, not yet checked, not triggered pairs of higher components of its foundation. A
   success unfreezes the foundation's pairs in every component (the existing rule, now across
   components). When no pair is Waiting the highest-priority Frozen one is checked (as before), so
   a foundation whose RTP pairs all failed still gets its RTCP pairs checked.
4. **Nomination, selection and consent per component.** The controlling agent runs regular
   nomination (best valid pair once no better pair of that component is pending, or
   `nomination_delay` after its first valid pair), aggressive nomination and renomination per
   component; a selection stops the other checks of its component only. The controlled agent
   accepts nominations per component. A lite agent finds the component of a check from the local
   candidate at its destination (component 1 when it has none there, as before). Consent checks
   run on every selected pair with their own timers and transactions; a consent response counts
   for the component whose transaction it answers.
5. **The agent state is over the components**: `Connected` once every component has a selected
   pair (of any generation), `Completed` once every one has a selected pair of the current
   generation and no check is left, `Disconnected` when consent expired on any component, `Failed`
   when, after end-of-candidates or `failed_timeout`, a component without a selected pair has no
   triggered check and every pair of it failed (also when it never had one). With one component
   these are the previous rules.
6. **ICE restarts cover the stream**: `restart` and new remote credentials rebuild the checklist
   for every component; each component keeps its selected pair (and consent on the old
   credentials) until the new generation nominates one of its own.
7. **API, additive**: `IceConfig::components`, `Candidate::with_component`,
   `IceAgent::{components, selected_pair_of, send_pair_of}` and
   `IceEvent::ComponentSelectedPair { component, local, remote }` (`IceEvent` is
   `#[non_exhaustive]`). `IceEvent::SelectedPair`, `selected_pair()` and `send_pair()` stay
   component 1's, so callers that match `SelectedPair { local, remote }` (only-webrtc) compile
   and behave unchanged. `Transmit` gets no component field: its `source` is the local socket,
   which is what the caller needs. The ICE state docs now speak of every component. The one
   source-level break: struct literals of `IceConfig` outside the crate must add
   `components: 1` (only-ice is internal tier; the workspace builds its configs with
   `IceConfig::new`, which sets it).

## Consequences

- Simulated network (`tests/sim.rs`): two-component streams connect in every nomination mode
  and both roles in under a second, `Connected` only after both selections, and stay `Completed`
  for 120 s with data on both components; 12 seeds of 25 % loss, 10 % duplication and 300 ms of
  reordering over IPv4 and IPv6 (some with a lite remote) all complete with one selection per
  component; role conflicts resolve; peer-reflexive pairs are found per component through a NAT;
  the check order shows the Frozen rule (both RTP pairs before the IPv6 RTCP pair that outranks
  the IPv4 RTP pair, whatever order the candidates trickle in; checked by turning the rule off);
  an unreachable RTCP port gives `Failed` (end-of-candidates: after 6-10 s, otherwise after the
  30 s timeout) although RTP is selected; consent lost on RTCP only gives `Disconnected` after
  23-31 s and `Completed` again once it comes back; ICE restarts from either side re-select both
  components. The 46 earlier tests (28 simulator, 18 unit) pass unchanged.
- Interop (`tests/libnice.rs`, `tools/interop/ice/run.sh`): libnice 0.1.21 (Debian 12) with one
  stream of two components over loopback UDP in five setups (libnice controlling with aggressive
  and with regular nomination, libnice controlled, libnice lite, only-ice lite): both sides
  select the same pair for each component, libnice reports both components `ready`, and data
  goes both ways on both. pion/ice has one component only, so `tests/pion.rs` is unchanged.
- Fuzzing: `ice_stun` also drives agents of two components (full controlling, controlled with
  aggressive nomination and renomination, lite) with datagrams on both components' addresses; one
  seed with a component-2 candidate line.
- Costs: each component carries its own consent timer and checks (one every 5 s ±20 % per
  selected pair); the checklist limit of 100 pairs is shared by the components.
- Not done: wiring streams without rtcp-mux into only-webrtc (offering or accepting `a=rtcp`
  without `a=rtcp-mux`, a second socket per m-line, RTCP on component 2): only-webrtc keeps
  component 1 and is unchanged. Nominating the pairs of all components on one foundation when
  several work equally well (each component picks its best pair on its own; with the shared
  foundations and the Frozen order they usually end up on the same path).
