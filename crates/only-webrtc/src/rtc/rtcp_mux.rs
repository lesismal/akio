//! RTCP on ICE component 2, for peers without rtcp-mux (RFC 5761 §5.1.3, RFC 8445 §4.1.1.1,
//! ADR-058): SIP endpoints and older RTP stacks send RTCP on a port of its own.
//!
//! - The agent starts with one component; a session switches to two at its first
//!   negotiation (an offer or answer without `a=rtcp-mux`, or our [`RtcpMuxPolicy::Off`]
//!   offer). The agent is rebuilt then with the same credentials and candidates (nothing was
//!   checked yet: the remote credentials arrive with that description). Later descriptions
//!   keep the count (RFC 5761 §5.1.3: multiplexing is not turned on or off by a re-offer).
//! - Component 2's local candidates come from the endpoint's RTCP socket
//!   ([`Endpoint::bind_rtcp`](crate::Endpoint::bind_rtcp)); datagrams arriving on their
//!   addresses are component 2's.
//! - DTLS-SRTP runs one handshake per component (RFC 5764 §4.1): SRTP with the keys of
//!   component 1's, SRTCP with those of component 2's, in the same roles and with the same
//!   certificate and fingerprint. SDES-SRTP keys both from the one `a=crypto` key (RFC 4568
//!   §6.1: the master key serves SRTP and SRTCP of the media stream).
//! - Without BUNDLE (RFC 8843 §9.1 needs rtcp-mux) the session has one media section and no
//!   data channels: this stack runs one transport.

use super::*;

/// The local side of component 2.
#[derive(Default)]
pub(super) struct RtcpComponent {
    /// Local candidates of component 2 (signaled; at most [`MAX_RTCP_CANDIDATES`]).
    cands: Vec<IceCandidate>,
    /// Component 2's DTLS association (DTLS-SRTP).
    pub(super) dtls: Option<Connection>,
    /// Its handshake completed.
    pub(super) dtls_up: bool,
    /// (local, remote) of the first DTLS datagram on component 2: where answers go before
    /// ICE selected a pair.
    pub(super) first: Option<(SocketAddr, SocketAddr)>,
    /// SRTCP keys of component 2's handshake.
    pub(super) srtcp_tx: Option<Srtp>,
    pub(super) srtcp_rx: Option<Srtp>,
}

impl std::fmt::Debug for RtcpComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtcpComponent")
            .field("candidates", &self.cands.len())
            .field("dtls_up", &self.dtls_up)
            .finish_non_exhaustive()
    }
}

/// Most component-2 candidates kept.
const MAX_RTCP_CANDIDATES: usize = 16;

impl RtcpComponent {
    pub(super) fn add_candidate(&mut self, c: &IceCandidate) {
        if self.cands.len() < MAX_RTCP_CANDIDATES
            && !self
                .cands
                .iter()
                .any(|x| x.addr() == c.addr() && x.base() == c.base())
        {
            self.cands.push(c.clone());
        }
    }

    pub(super) fn has_candidates(&self) -> bool {
        !self.cands.is_empty()
    }

    pub(super) fn candidates(&self) -> &[IceCandidate] {
        &self.cands
    }

    /// Whether `a` is a local address of component 2 (a candidate's base).
    pub(super) fn is_local(&self, a: SocketAddr) -> bool {
        self.cands.iter().any(|c| c.base() == a || c.addr() == a)
    }
}

/// Whether a description multiplexes RTCP: its first audio or video section in use has
/// `a=rtcp-mux` (or it has none: data channels have no RTCP).
pub(super) fn muxed(sdp: &Sdp) -> bool {
    sdp.media
        .iter()
        .find(|m| m.port != 0 && (m.kind == "audio" || m.kind == "video"))
        .is_none_or(|m| m.has("rtcp-mux"))
}

/// The sections of a description in use (port not 0).
pub(super) fn sections_in_use(sdp: &Sdp) -> usize {
    sdp.media.iter().filter(|m| m.port != 0).count()
}

impl Rtc {
    /// RTCP runs on component 2.
    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn two_components(&self) -> bool {
        self.ice.components() == 2
    }

    /// Our first offer signals component 2 next to `a=rtcp-mux` ([`RtcpMuxPolicy::Negotiate`]
    /// or `Off`, with an RTCP socket).
    pub(super) fn offers_rtcp_component(&self) -> bool {
        !self.negotiated
            && self.cfg.rtcp_mux != RtcpMuxPolicy::Require
            && self.rtcp.has_candidates()
    }

    /// Whether our description of a media section carries `a=rtcp-mux` and `a=rtcp`.
    pub(super) fn rtcp_mux_attrs(&self, offer: bool) -> (bool, bool) {
        if self.ice.components() == 2 {
            (false, true)
        } else if offer && self.offers_rtcp_component() {
            (true, true)
        } else {
            (true, false)
        }
    }

    /// The sections in use once `ops` are applied (the application section counts once).
    pub(super) fn sections_after(&self, ops: &[Change]) -> usize {
        let mut n = self.media.iter().filter(|l| !l.stopped).count();
        let mut channels = self.app_mid.is_some();
        for o in ops {
            match o {
                Change::AddMedia { .. } => n += 1,
                Change::StopMedia(mid) => {
                    if self.media.iter().any(|l| l.mid == *mid && !l.stopped) {
                        n = n.saturating_sub(1);
                    }
                }
                Change::AddChannel(..) => channels = true,
                _ => {}
            }
        }
        n + usize::from(channels)
    }

    /// Switches the ICE agent to two components (RTP and RTCP), keeping its credentials, role
    /// and candidates and adding component 2's.
    pub(super) fn use_rtcp_component(&mut self, now: Instant) {
        if self.ice.components() == 2 {
            return;
        }
        let mut cfg = IceConfig::new(self.lite, self.ice.controlling());
        self.ice.local_credentials().clone_into(&mut cfg.local);
        cfg.aggressive_nomination = self.cfg.ice_aggressive;
        cfg.renomination = self.cfg.ice_renomination;
        cfg.components = 2;
        let mut ice = IceAgent::new(cfg, now);
        for c in self.ice.local_candidates() {
            if c.kind() != only_ice::CandidateKind::PeerReflexive {
                ice.add_local_candidate(c.clone());
            }
        }
        for c in &self.rtcp.cands {
            ice.add_local_candidate(c.clone());
        }
        if let Some(r) = self.ice.remote_credentials() {
            ice.set_remote_credentials(r.clone());
        }
        for c in self.ice.remote_candidates() {
            ice.add_remote_candidate(c.clone());
        }
        self.ice = ice;
    }

    /// A DTLS datagram on component 2.
    pub(super) fn rtcp_dtls_input(
        &mut self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
        data: &[u8],
    ) {
        if self.rtcp.first.is_none() {
            self.rtcp.first = Some((destination, source));
        }
        if self.rtcp.dtls.is_none() {
            self.rtcp.dtls = self.new_dtls(now, Some(source));
        }
        if let Some(d) = self.rtcp.dtls.as_mut() {
            if let Err(e) = d.handle_datagram(now, data) {
                only_log::debug!(target: "only_webrtc", "dtls (rtcp): {e}");
                // A handshake latched onto tentatively fails without harm (ADR-086).
                if !self.latch_dtls_failed(2) {
                    self.die();
                }
            }
        }
    }

    /// Component 2's DTLS datagrams out, its events in. Whether anything happened.
    pub(super) fn flush_rtcp_dtls(&mut self, now: Instant) -> bool {
        let path = self.ice.send_pair_of(2).or(self.rtcp.first);
        let Some(d) = self.rtcp.dtls.as_mut() else {
            return false;
        };
        while let Some(t) = d.poll_transmit() {
            if let Some((src, dest)) = path {
                self.transmits.push_back((src, dest, t, 0));
            }
        }
        let mut evs = Vec::new();
        while let Some(e) = d.poll_event() {
            evs.push(e);
        }
        let mut progress = false;
        for e in evs {
            progress = true;
            match e {
                DtlsEvent::Connected(info) => {
                    let role = self.dtls_role.unwrap_or(Role::Client);
                    if let Some(keys) = info.srtp_keys {
                        if let Some(p) = Profile::from_id(keys.profile.id()) {
                            let (lk, ls) = keys.local(role);
                            let (rk, rs) = keys.remote(role);
                            let mki = info.srtp_mki.as_deref();
                            self.rtcp.srtcp_tx = dtls_srtp(p, mki, lk, ls);
                            self.rtcp.srtcp_rx =
                                dtls_srtp(p, mki, rk, rs).map(|c| c.with_replay_window(512));
                        }
                    }
                    only_log::debug!(target: "only_webrtc", "dtls (rtcp): connected with {}", info.version);
                    self.latch_dtls_done(now, 2);
                    self.rtcp.dtls_up = true;
                    self.check_connected(now);
                }
                DtlsEvent::Closed => {
                    if !self.latch_dtls_failed(2) {
                        self.die();
                    }
                    break;
                }
                _ => {}
            }
        }
        progress
    }

    /// Marks the peer connected once every key is in place: DTLS-SRTP's handshakes (both
    /// components' without rtcp-mux), or SDES keys and an ICE pair for every component.
    /// Whether it just became connected.
    pub(super) fn check_connected(&mut self, now: Instant) -> bool {
        if self.dtls_connected {
            // SDES media is connected by its SDP keys; data channels next to it wait for
            // DTLS, which may complete later.
            if self.sdes.active && self.dtls_up && self.sctp.is_none() {
                self.start_sctp(now);
                self.open_pending_channels(now);
            }
            return false;
        }
        let two = self.ice.components() == 2;
        let ready = if self.sdes.active {
            self.srtp_tx.is_some()
                && self.ice.send_pair().is_some()
                && (!two || self.ice.send_pair_of(2).is_some())
        } else {
            self.dtls_up && (!two || self.rtcp.dtls_up)
        };
        if !ready {
            return false;
        }
        self.dtls_connected = true;
        // With several transports (no BUNDLE), once the last one is connected.
        if self.tp_others_connected() {
            self.events.push_back(RtcEvent::Connected);
        }
        self.next_rtcp = Some(now + Duration::from_millis(200));
        self.start_sctp(now);
        self.open_pending_channels(now);
        true
    }
}
