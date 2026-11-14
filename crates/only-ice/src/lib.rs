#![forbid(unsafe_code)]
#![warn(clippy::unwrap_used)]
//! Sans-io ICE (RFC 8445) for the `only` WebRTC stack: one component (RTP/RTCP muxed,
//! BUNDLE) over UDP, full and lite agents.
//!
//! An [`IceAgent`] owns no sockets, threads or clocks. The caller gathers local candidates
//! (host addresses of its sockets, server-reflexive and relayed ones from its STUN/TURN
//! clients), exchanges credentials and candidates with the remote over signaling, passes in
//! every received datagram and the current time, sends what [`IceAgent::poll_transmit`]
//! returns and sends application data (DTLS, SRTP) on [`IceAgent::send_pair`].
//!
//! ```
//! use std::time::{Duration, Instant};
//! use only_ice::{Candidate, IceAgent, IceConfig, IceState};
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
//!   relay 0; local preference IPv6 > IPv4 > IPv6 link-local; component 1), foundations from
//!   type and base IP, the SDP `candidate` attribute (RFC 8839 §5.1, with the `generation`,
//!   `ufrag`, `network-id`, `network-cost` extensions). TCP, mDNS (`*.local`) and other FQDN
//!   candidates parse to distinct [`ParseError`] variants so callers can skip them.
//! - Checklist (§6.1): pairs of the same IP family, pair priority formula, redundant pairs
//!   (same base and remote) pruned to the highest priority, Frozen/Waiting/InProgress/
//!   Succeeded/Failed with per-foundation unfreezing, at most 100 pairs.
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
//!   the last valid USE-CANDIDATE check. After nomination no new ordinary checks start.
//! - Consent freshness (RFC 7675) on the selected pair with randomized intervals (each check
//!   retransmitted up to 4 times from 500 ms);
//!   [`IceState::Disconnected`] after [`IceConfig::consent_timeout`] without responses (a lite
//!   agent: without valid checks), back when they resume.
//! - Trickle (RFC 8838): candidates may be added at any time;
//!   [`IceAgent::end_of_remote_candidates`] lets the agent reach [`IceState::Failed`].
//! - ICE restarts (§9) from either side, keeping the old selected pair (and answering
//!   requests on the old credentials) until the new generation nominates.
//!
//! # Not implemented
//!
//! Several components, TCP candidates (RFC 6544), aggressive nomination (requests carrying
//! USE-CANDIDATE are honoured, but this agent never sends them outside regular nomination),
//! renomination, gathering (the caller's STUN/TURN clients do it), mDNS resolution, cancelling
//! an in-progress check when a triggered check is due on its pair (§7.3.1.4: the
//! retransmissions continue instead), re-nominating a better pair that appears after
//! nomination. A success response whose mapped address is new adds a peer-reflexive local
//! candidate, but the valid pair is the checked one (both share the same base).
//!
//! This is an implementation crate of `only` (docs/api-stability.md, Internal tier): its API
//! follows the needs of the WebRTC stack and may change in any release.

mod agent;
mod candidate;

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

pub use crate::agent::{IceAgent, IceConfig, IceEvent, IceState, Transmit};
pub use crate::candidate::{Candidate, CandidateKind, Credentials, ParseError};
