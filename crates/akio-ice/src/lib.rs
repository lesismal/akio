#![forbid(unsafe_code)]
#![warn(clippy::unwrap_used)]
//! Sans-io ICE (RFC 8445) for the `akio` WebRTC stack: streams of one component (RTP/RTCP
//! muxed, BUNDLE) or several ([`IceConfig::components`]: RTP and RTCP on their own ports) over
//! UDP and TCP (RFC 6544), full and lite agents, regular and aggressive nomination and
//! renomination, and an mDNS codec ([`mdns`]) for browsers' `.local` candidates.
//!
//! An [`IceAgent`] owns no sockets, threads or clocks. The caller gathers local candidates
//! (host addresses of its sockets, server-reflexive and relayed ones from its STUN/TURN
//! clients), exchanges credentials and candidates with the remote over signaling, passes in
//! every received datagram and the current time, sends what [`IceAgent::poll_transmit`]
//! returns and sends application data (DTLS, SRTP) on [`IceAgent::send_pair`].
//!
//! ```
//! use std::time::{Duration, Instant};
//! use akio_ice::{Candidate, IceAgent, IceConfig, IceState};
//!
//! let now = Instant::now();
//! let mut a = IceAgent::new(IceConfig::new(false, true), now);
//! let mut b = IceAgent::new(IceConfig::new(false, false), now);
//! let (aa, ba) = ("10.0.0.1:5000".parse().unwrap(), "10.0.0.2:6000".parse().unwrap());
//! a.add_local_candidate(Candidate::host(aa));
//! b.add_local_candidate(Candidate::host(ba));
//! // Signaling: credentials and candidates (Candidate::to_sdp / Candidate::parse).
//! a.set_remote_credentials(b.local_credentials().clone());
//! b.set_remote_credentials(a.local_credentials().clone());
//! a.add_remote_candidate(Candidate::parse(&b.local_candidates()[0].to_sdp()).unwrap());
//! b.add_remote_candidate(Candidate::parse(&a.local_candidates()[0].to_sdp()).unwrap());
//!
//! // A perfect in-memory network.
//! let mut t = now;
//! for _ in 0..100 {
//!     while let Some(x) = a.poll_transmit() {
//!         assert!(b.handle_receive(t, x.source, x.destination, &x.contents));
//!     }
//!     while let Some(x) = b.poll_transmit() {
//!         assert!(a.handle_receive(t, x.source, x.destination, &x.contents));
//!     }
//!     t += Duration::from_millis(10);
//!     a.handle_timeout(t);
//!     b.handle_timeout(t);
//! }
//! assert_eq!(a.state(), IceState::Completed);
//! assert_eq!(a.selected_pair(), Some((aa, ba)));
//! assert_eq!(b.send_pair(), Some((ba, aa)));
//! ```
//!
//! # Implemented
//!
//! - Candidates (RFC 8445 §5.1): priorities (type preferences host 126, prflx 110, srflx 100,
//!   relay 0; local preference IPv6 > IPv4 > IPv6 link-local; component 1, or another with
//!   [`Candidate::with_component`]), foundations from type, base IP and transport (shared by
//!   the components), the SDP `candidate` attribute (RFC 8839 §5.1, with the `generation`,
//!   `ufrag`, `network-id`, `network-cost` extensions). mDNS (`*.local`) and other FQDN
//!   candidates parse to distinct [`ParseError`] variants; [`Candidate::parse_resolved`] takes
//!   a resolver for them, [`Candidate::with_hostname`] writes such a name for a local one.
//! - TCP candidates (RFC 6544): `tcp` transport with `tcptype` (active, passive, so), TCP
//!   type and local preferences below UDP's (§4.2), pairs only within a transport and between
//!   compatible types (§6.2: active with passive, `so` with `so`). Local active and `so`
//!   candidates send checks (the caller opens the connection). A local passive candidate
//!   ([`Candidate::host_tcp`]) never starts checks: a check arriving over an accepted connection makes a peer-reflexive remote
//!   (active) candidate whose pair gets the triggered checks, nomination and consent. The
//!   caller frames STUN and data on the connection (RFC 4571) and passes the connection's
//!   remote address and the candidate's address as for UDP.
//! - Checklist (§6.1): one per stream, for every component: pairs of the same component and
//!   IP family, pair priority formula, redundant pairs (same base and remote) pruned to the
//!   highest priority, Frozen/Waiting/InProgress/Succeeded/Failed with the §6.1.2.6 initial
//!   states (of each foundation, the pair of the lowest component is Waiting, the others
//!   Frozen) and per-foundation unfreezing across components (§7.2.5.3.3), at most 100 pairs.
//! - Components (§2, [`IceConfig::components`]): nomination, selection and consent freshness
//!   per component; the agent is [`IceState::Connected`] once every component has a selected
//!   pair, [`IceState::Disconnected`] when consent expires on any of them and
//!   [`IceState::Failed`] when a component without a selected pair has no pair left. Component
//!   1's selection is [`IceEvent::SelectedPair`], [`IceAgent::selected_pair`] and
//!   [`IceAgent::send_pair`]; the others' [`IceEvent::ComponentSelectedPair`],
//!   [`IceAgent::selected_pair_of`] and [`IceAgent::send_pair_of`]. A received datagram
//!   belongs to the component of the local candidate it arrived on.
//! - Checks (§7): one new check every `Ta` (triggered queue first), retransmissions from
//!   [`IceConfig::check_rto`] doubling to [`IceConfig::check_rto_max`], the pair fails after
//!   [`IceConfig::check_max_sends`] sends (about 8 s by default); USERNAME, PRIORITY,
//!   ICE-CONTROLLING/ICE-CONTROLLED with a random 64-bit tie-breaker, USE-CANDIDATE,
//!   MESSAGE-INTEGRITY and FINGERPRINT; responses must come from where the request went;
//!   requests are answered with XOR-MAPPED-ADDRESS (400 for missing attributes, 401 for a bad
//!   USERNAME or integrity), role conflicts per §7.3.1.1 (487) and §7.2.5.1; peer-reflexive
//!   remote and local candidates; requests arriving before the remote credentials are
//!   answered and their triggered checks wait for the credentials.
//! - Nomination (§8): regular nomination by a controlling full agent (the best valid pair
//!   once no higher-priority pair is pending, or [`IceConfig::nomination_delay`] after the
//!   first valid pair; immediately when the remote is lite); a controlled agent selects a pair
//!   with USE-CANDIDATE once its own check on it succeeded; a lite agent selects the pair of
//!   the last valid USE-CANDIDATE check. After nomination no new ordinary checks start, except
//!   with [`IceConfig::aggressive_nomination`] (USE-CANDIDATE on every check, RFC 5245
//!   §8.1.1.2) or renomination ([`IceConfig::renomination`] and
//!   [`IceAgent::set_remote_renomination`], draft-thatcher-ice-renomination: NOMINATION
//!   attribute 0xC001): checks of better pairs go on and a better pair that works is selected
//!   (renominated). A controlled agent selects the nominated pair with the highest NOMINATION
//!   value, or without one the highest-priority nominated pair.
//! - mDNS ([`mdns`], RFC 6762): one-shot queries, answers, queries for our own names; the
//!   caller has the socket.
//! - Consent freshness (RFC 7675) on the selected pair with randomized intervals (each check
//!   retransmitted up to 4 times from 500 ms);
//!   [`IceState::Disconnected`] after [`IceConfig::consent_timeout`] without responses (a lite
//!   agent: without valid checks), back when they resume.
//! - Trickle (RFC 8838): candidates may be added at any time;
//!   [`IceAgent::end_of_remote_candidates`] lets the agent reach [`IceState::Failed`].
//! - ICE restarts (§9) from either side, for every component, each keeping its old selected
//!   pair (and answering requests on the old credentials) until the new generation nominates
//!   one.
//!
//! # Not implemented
//!
//! Gathering (the caller's STUN/TURN clients do it), sockets (mDNS, TCP connections), cancelling an in-progress check when a triggered
//! check is due on its pair (§7.3.1.4: the retransmissions continue instead), re-nominating a
//! better pair after nomination without renomination support on both sides. A success response whose mapped address is new adds a peer-reflexive local
//! candidate, but the valid pair is the checked one (both share the same base).
//!
//! This is an implementation crate of `akio` (docs/api-stability.md, Internal tier): its API
//! follows the needs of the WebRTC stack and may change in any release.

mod agent;
mod candidate;
mod ecn;
pub mod mdns;
pub mod tcp;

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

pub use crate::agent::{IceAgent, IceConfig, IceEvent, IceState, Transmit};
pub use crate::candidate::{Candidate, CandidateKind, Credentials, ParseError, TcpType};
pub use crate::ecn::{ECN_CHECK_GIVE_UP, ECN_CHECK_INTERVAL, ECN_CHECK_SENDS};
