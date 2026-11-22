//! Several transports in one session (no BUNDLE, RFC 9143 §7.3.3 and RFC 8829 §4.1.1) and
//! transports without ICE (plain `c=` / `m=` port, as SIP endpoints write them), ADR-072.
//!
//! - **One transport per section** when the session is not bundled: our offers with
//!   [`BundlePolicy::Disabled`], a remote offer without `a=group:BUNDLE`, or an answer that
//!   leaves our BUNDLE group out. Each section in use then has its own ICE agent (its own
//!   credentials: the primary's ufrag followed by a digit, so the endpoint hub still finds the
//!   peer by it; or, when the answer refused our BUNDLE offer, the primary's own, which the
//!   offer gave every section), DTLS association, SRTP contexts, SDES keys and RTCP
//!   component. The DTLS role, certificate and remote fingerprint are the session's.
//! - **The state of a transport is swapped in.** The fields of [`Tp`] live on [`Rtc`] for the
//!   *current* transport (the primary, 0, outside any call); the others wait in
//!   [`Extra::tps`]. [`Rtc::with_tp`] swaps transport `k` in, runs the existing code (which
//!   only knows `self.ice`, `self.dtls`, `self.srtp_tx`, ...), and swaps it back, so ICE,
//!   DTLS-SRTP, SDES, RTCP on component 2 and the media paths serve every transport without
//!   being written twice. While transport `k` is current, the primary's state sits in
//!   `tps[k - 1]`: the transports that are *not* current are always exactly `tps`.
//! - **Demultiplexing.** Our transports share the endpoint's sockets, so a datagram's
//!   transport comes from its source: a connectivity check by the ufrag in its USERNAME
//!   (then by source among transports that share one), anything else by the transport whose
//!   selected pair, remote candidates or first DTLS datagram has that source. The remote must
//!   therefore reach each transport from an address of its own, as every peer that does not
//!   bundle does (it runs an ICE agent, or has a port, per section).
//! - **Sending.** Media goes out on its line's transport; RTCP on the transport of the line
//!   whose SSRC sends it (the first packet's sender SSRC); SCTP on the application section's.
//!   Congestion control feedback (transport-cc, RFC 8888) runs per transport into one
//!   estimator and pacer (ADR-077, [`super::cc`]); paced packets go out on their own
//!   transport.
//! - **Without ICE** a transport's agent gets fixed pairs ([`IceAgent::set_fixed_pair`]):
//!   from our first host candidate of the remote's family to the `c=` address and `m=` port,
//!   and on component 2 to `a=rtcp` (or the next port) when RTCP is not multiplexed.

use super::*;
use crate::types::BundlePolicy;

/// The state of one transport (see the module docs): swapped with [`Rtc`]'s fields.
pub(super) struct Tp {
    ice: Option<IceAgent>,
    dtls: Option<Connection>,
    dtls_connected: bool,
    dtls_up: bool,
    sdes: sdes::Sdes,
    pub(super) srtp_tx: Option<Srtp>,
    pub(super) srtp_rx: Option<Srtp>,
    srtp_enc_ids: Vec<u8>,
    remote_addr: Option<SocketAddr>,
    remote_local: Option<SocketAddr>,
    pub(super) rtcp: rtcp_mux::RtcpComponent,
    dtls_version: Option<DtlsVersion>,
    probe_pair: Option<(SocketAddr, SocketAddr)>,
    mdns_wanted: Vec<(String, String)>,
    /// ECN marking of the transport's path and latching of its remote (ADR-077).
    pub(super) ecn: ecn::EcnPath,
    pub(super) latch: latch::Latch,
    /// RFC 8888: the transport's receiver (its report goes out on it).
    ccfb_rx: CcfbReceiver,
    /// Transport-wide CC of the transport when the remote numbers per transport (else the
    /// session's are used; see [`super::cc`]).
    twcc_tx: TwccSender,
    twcc_rx: TwccReceiver,
    twcc_media_ssrc: u32,
}

impl Default for Tp {
    fn default() -> Tp {
        Tp {
            ice: None,
            dtls: None,
            dtls_connected: false,
            dtls_up: false,
            sdes: sdes::Sdes::default(),
            srtp_tx: None,
            srtp_rx: None,
            srtp_enc_ids: Vec::new(),
            remote_addr: None,
            remote_local: None,
            rtcp: rtcp_mux::RtcpComponent::default(),
            dtls_version: None,
            probe_pair: None,
            mdns_wanted: Vec::new(),
            ecn: ecn::EcnPath::default(),
            latch: latch::Latch::default(),
            ccfb_rx: CcfbReceiver::new(),
            twcc_tx: TwccSender::new(),
            twcc_rx: TwccReceiver::new(),
            twcc_media_ssrc: 0,
        }
    }
}

impl Tp {
    /// What DTLS latching looks at (ADR-082): SDES on, handshake done, the remote's address.
    pub(super) fn dtls_view(&self) -> (bool, bool, Option<SocketAddr>) {
        (self.sdes.active, self.dtls_up, self.remote_addr)
    }

    pub(super) fn agent(&self) -> &IceAgent {
        self.ice.as_ref().expect("a transport has an agent")
    }

    /// The next transport-wide number of the transport's own sender (tests).
    #[cfg(test)]
    pub(super) fn twcc_tx_next(&mut self) -> u16 {
        self.twcc_tx.next_seq()
    }

    /// Starts the transport's own transport-wide numbering at `next` (a switch to per-transport
    /// numbering, [`super::cc`]).
    pub(super) fn skip_twcc(&mut self, next: u16) {
        for _ in 0..next {
            self.twcc_tx.next_seq();
        }
    }

    /// The transport has SRTP keys and a path for RTP.
    pub(super) fn ready(&self) -> bool {
        self.srtp_tx.is_some() && self.agent().send_pair().is_some()
    }
}

/// The transports beyond the primary and how the session uses them.
#[derive(Default)]
pub(super) struct Extra {
    /// The other transports (section mid, state).
    pub(super) tps: Vec<(Mid, Tp)>,
    /// The current transport (0: the primary).
    pub(super) cur: usize,
    /// The section the primary transport serves when the session is not bundled.
    primary: Option<Mid>,
    /// The session is not bundled (decided once, at the first negotiation).
    pub(super) split: bool,
    /// The transports have no ICE: the remote's and our descriptions carry plain addresses.
    pub(super) plain: bool,
    /// Plain remote addresses not reported to the endpoint yet ([`Rtc::take_plain_remotes`]).
    pub(super) new_remotes: Vec<SocketAddr>,
    /// The descriptions' plain remote addresses, and addresses latched away from that the
    /// endpoint should forget ([`Rtc::take_gone_remotes`]).
    pub(super) sdp_remotes: Vec<SocketAddr>,
    pub(super) gone_remotes: Vec<SocketAddr>,
    /// Congestion control across the transports (ADR-077).
    pub(super) cc: cc::UnbundledCc,
    /// Local candidates of the transports made later, by creation index (1..): such a
    /// transport takes these instead of the primary's (a socket per transport,
    /// [`Endpoint::bind_transport_socket`](crate::Endpoint::bind_transport_socket)).
    own_cands: Vec<(usize, IceCandidate)>,
}

impl std::fmt::Debug for Extra {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Extra")
            .field("transports", &(self.tps.len() + 1))
            .field("split", &self.split)
            .field("plain", &self.plain)
            .finish_non_exhaustive()
    }
}

/// The aggregate of transport states (W3C `RTCIceConnectionState`).
fn aggregate(states: impl Iterator<Item = IceConnectionState>) -> IceConnectionState {
    use IceConnectionState as S;
    let all: Vec<S> = states.collect();
    if all.contains(&S::Disconnected) {
        S::Disconnected
    } else if all.iter().all(|s| *s == S::New) {
        S::New
    } else if all.iter().any(|s| matches!(s, S::New | S::Checking)) {
        S::Checking
    } else if all.iter().all(|s| *s == S::Completed) {
        S::Completed
    } else {
        S::Connected
    }
}

/// The sender SSRC of an RTCP packet we send.
fn rtcp_sender(p: &Rtcp) -> Option<u32> {
    match p {
        Rtcp::SenderReport { ssrc, .. }
        | Rtcp::ReceiverReport { ssrc, .. }
        | Rtcp::ExtendedReport { ssrc, .. } => Some(*ssrc),
        Rtcp::Nack { sender_ssrc, .. }
        | Rtcp::Pli { sender_ssrc, .. }
        | Rtcp::Fir { sender_ssrc, .. }
        | Rtcp::Remb { sender_ssrc, .. }
        | Rtcp::Tmmbr { sender_ssrc, .. }
        | Rtcp::Tmmbn { sender_ssrc, .. } => Some(*sender_ssrc),
        _ => None,
    }
}

/// The address and port of a section without ICE: its `c=` (else the session's) and `m=`
/// port, and RTCP's (`a=rtcp`, else the next port; the same one with `a=rtcp-mux`).
pub(super) fn plain_addrs(sdp: &Sdp, i: usize) -> Option<(SocketAddr, SocketAddr)> {
    let m = sdp.media.get(i)?;
    let ip = sdp.media_conn.get(i).copied().flatten().or(sdp.conn)?;
    if ip.is_unspecified() || m.port == 0 {
        return None;
    }
    let rtp = SocketAddr::new(ip, m.port);
    let rtcp = if m.has("rtcp-mux") {
        rtp
    } else if let Some(v) = m.get("rtcp") {
        // RFC 3605: `port [IN IP4|IP6 address]`.
        let mut f = v.split_ascii_whitespace();
        let port: u16 = f.next()?.parse().ok()?;
        let ip = match (f.next(), f.next(), f.next()) {
            (Some("IN"), Some("IP4" | "IP6"), Some(a)) => a.parse().ok()?,
            _ => ip,
        };
        SocketAddr::new(ip, port)
    } else {
        SocketAddr::new(ip, m.port.checked_add(1)?)
    };
    Some((rtp, rtcp))
}

/// Whether a remote description does ICE: an `a=ice-ufrag` somewhere.
pub(super) fn has_ice(sdp: &Sdp) -> bool {
    sdp.has("ice-ufrag") || sdp.media.iter().any(|m| m.has("ice-ufrag"))
}

/// Whether a remote description bundles: an `a=group:BUNDLE` with at least one mid.
pub(super) fn bundles(sdp: &Sdp) -> bool {
    sdp.attrs.iter().any(|a| {
        a.key == "group"
            && a.value
                .as_deref()
                .is_some_and(|v| v.split_ascii_whitespace().next() == Some("BUNDLE"))
    })
}

impl Rtc {
    /// Swaps the fields of the current transport with `t`.
    fn swap_tp(&mut self, t: &mut Tp) {
        let ice = t.ice.as_mut().expect("a transport has an agent");
        std::mem::swap(&mut self.ice, ice);
        std::mem::swap(&mut self.dtls, &mut t.dtls);
        std::mem::swap(&mut self.dtls_connected, &mut t.dtls_connected);
        std::mem::swap(&mut self.dtls_up, &mut t.dtls_up);
        std::mem::swap(&mut self.sdes, &mut t.sdes);
        std::mem::swap(&mut self.srtp_tx, &mut t.srtp_tx);
        std::mem::swap(&mut self.srtp_rx, &mut t.srtp_rx);
        std::mem::swap(&mut self.srtp_enc_ids, &mut t.srtp_enc_ids);
        std::mem::swap(&mut self.remote_addr, &mut t.remote_addr);
        std::mem::swap(&mut self.remote_local, &mut t.remote_local);
        std::mem::swap(&mut self.rtcp, &mut t.rtcp);
        std::mem::swap(&mut self.dtls_version, &mut t.dtls_version);
        std::mem::swap(&mut self.probe_pair, &mut t.probe_pair);
        std::mem::swap(&mut self.mdns_wanted, &mut t.mdns_wanted);
        std::mem::swap(&mut self.ecn, &mut t.ecn);
        std::mem::swap(&mut self.latch, &mut t.latch);
        std::mem::swap(&mut self.ccfb_rx, &mut t.ccfb_rx);
        if self.xt.cc.per_transport() {
            std::mem::swap(&mut self.twcc_tx, &mut t.twcc_tx);
            std::mem::swap(&mut self.twcc_rx, &mut t.twcc_rx);
            std::mem::swap(&mut self.twcc_media_ssrc, &mut t.twcc_media_ssrc);
        }
    }

    /// Toggles transport `k` (1..) with the primary: in when the primary is current, out when
    /// `k` is.
    fn toggle(&mut self, k: usize) {
        let mut t = std::mem::take(&mut self.xt.tps[k - 1].1);
        self.swap_tp(&mut t);
        self.xt.tps[k - 1].1 = t;
    }

    /// Runs `f` with transport `k` current (0: the primary).
    pub(super) fn with_tp<R>(&mut self, k: usize, f: impl FnOnce(&mut Rtc) -> R) -> R {
        let prev = self.xt.cur;
        if prev == k || k > self.xt.tps.len() {
            return f(self);
        }
        if prev != 0 {
            self.toggle(prev);
        }
        if k != 0 {
            self.toggle(k);
        }
        self.xt.cur = k;
        let r = f(self);
        if k != 0 {
            self.toggle(k);
        }
        if prev != 0 {
            self.toggle(prev);
        }
        self.xt.cur = prev;
        r
    }

    /// The session has transports beyond the primary, and the primary is current (a call
    /// from outside): the entry points fan out or redirect then.
    pub(super) fn tp_entry(&self) -> bool {
        !self.xt.tps.is_empty() && self.xt.cur == 0
    }

    /// Gives the `k`-th transport made later (1..) local candidate `c`, instead of the
    /// primary's (a socket per transport).
    pub(crate) fn add_transport_candidate(&mut self, k: usize, c: IceCandidate) {
        self.xt.own_cands.push((k, c));
    }

    /// Adds a remote candidate line for section `mid`: to its transport's agent.
    pub(crate) fn add_remote_candidate_in(
        &mut self,
        mid: Mid,
        line: &str,
    ) -> Result<(), only_ice::ParseError> {
        let k = self.tp_of_mid(mid);
        self.with_tp(k, |s| s.add_remote_candidate_line(line))
    }

    /// Sum of `f` over the transports beyond the current one's slot (statistics).
    pub(super) fn xt_sum(&self, f: impl Fn(&Tp) -> u64) -> u64 {
        self.xt.tps.iter().map(|(_, t)| f(t)).sum()
    }

    /// The header extension map of received RTP: the current transport's line's when the
    /// session is not bundled (each section may number extensions its own way), else the
    /// session's.
    pub(super) fn rx_ext(&self) -> &ExtensionMap {
        if self.xt.split && !self.xt.tps.is_empty() {
            let k = self.xt.cur;
            if let Some(l) = self
                .media
                .iter()
                .enumerate()
                .find(|(i, l)| !l.stopped && self.tp_of_line(*i) == k)
                .map(|(_, l)| l)
            {
                return &l.ext;
            }
        }
        &self.ext
    }

    /// Where transport `k`'s state is while another is current: `None` when `k` is the
    /// current one (its state is on `self`).
    pub(super) fn tp_state(&self, k: usize) -> Option<&Tp> {
        let cur = self.xt.cur;
        if k == cur {
            None
        } else if k == 0 {
            self.xt.tps.get(cur - 1).map(|(_, t)| t)
        } else {
            self.xt.tps.get(k - 1).map(|(_, t)| t)
        }
    }

    /// The session is not bundled.
    pub(super) fn unbundled(&self) -> bool {
        self.xt.split
    }

    /// The transport of section `mid`.
    pub(super) fn tp_of_mid(&self, mid: Mid) -> usize {
        self.xt
            .tps
            .iter()
            .position(|(m, _)| *m == mid)
            .map_or(0, |i| i + 1)
    }

    /// The transport of media line `line`.
    pub(super) fn tp_of_line(&self, line: usize) -> usize {
        self.media.get(line).map_or(0, |l| self.tp_of_mid(l.mid))
    }

    /// When the call should run on another transport than the current one: the transport of
    /// `mid`.
    pub(super) fn tp_redirect(&self, mid: Mid) -> Option<usize> {
        if self.xt.tps.is_empty() {
            return None;
        }
        let k = self.tp_of_mid(mid);
        (k != self.xt.cur).then_some(k)
    }

    /// The application section's transport, when it is not the current one.
    pub(super) fn tp_redirect_app(&self) -> Option<usize> {
        self.app_mid.and_then(|m| self.tp_redirect(m))
    }

    /// The transport an RTCP compound goes out on, when not the current one: that of the
    /// line whose SSRC sends it.
    pub(super) fn tp_redirect_rtcp(&self, pkts: &[Rtcp]) -> Option<usize> {
        if self.xt.tps.is_empty() {
            return None;
        }
        let ssrc = pkts.iter().find_map(rtcp_sender)?;
        let line = self
            .media
            .iter()
            .position(|l| l.sends_ssrc(ssrc) || l.send.ssrc() == ssrc)?;
        let k = self.tp_of_line(line);
        (k != self.xt.cur).then_some(k)
    }

    /// The transport a datagram from `source` to our `destination` belongs to (called with
    /// the primary current).
    pub(super) fn tp_demux(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        data: &[u8],
    ) -> usize {
        let n = self.xt.tps.len() + 1;
        let ice = |k: usize| {
            if k == 0 {
                &self.ice
            } else {
                self.xt.tps[k - 1].1.agent()
            }
        };
        let first = |k: usize| {
            if k == 0 {
                self.remote_addr
            } else {
                self.xt.tps[k - 1].1.remote_addr
            }
        };
        let from = |k: usize| {
            let a = ice(k);
            a.selected_pair().is_some_and(|p| p.1 == source)
                || a.selected_pair_of(2).is_some_and(|p| p.1 == source)
                || first(k) == Some(source)
                || a.remote_candidates().iter().any(|c| c.addr() == source)
        };
        let rtcp = |k: usize| {
            if k == 0 {
                &self.rtcp
            } else {
                &self.xt.tps[k - 1].1.rtcp
            }
        };
        let to = |k: usize| {
            ice(k)
                .local_candidates()
                .iter()
                .any(|c| c.base() == destination || c.addr() == destination)
                || rtcp(k).is_local(destination)
        };
        let mut candidates: Vec<usize> = (0..n).collect();
        if data.first().is_some_and(|b| *b < 4) {
            if let Ok(m) = only_turn::stun::Message::parse(data) {
                if let Some(u) = m.get_str(only_turn::stun::attr::USERNAME) {
                    let ours = u.split(':').next().unwrap_or("");
                    let named: Vec<usize> = (0..n)
                        .filter(|k| ice(*k).local_credentials().ufrag == ours)
                        .collect();
                    if named.len() == 1 {
                        return named[0];
                    }
                    if !named.is_empty() {
                        candidates = named;
                    }
                }
            }
        }
        // Transports on sockets of their own are told apart by the local address, those
        // sharing ours by the remote's.
        let local: Vec<usize> = candidates.iter().copied().filter(|k| to(*k)).collect();
        if local.len() == 1 {
            return local[0];
        }
        if !local.is_empty() {
            candidates = local;
        }
        candidates
            .iter()
            .copied()
            .find(|k| from(*k))
            .unwrap_or(candidates[0])
    }

    /// The ICE state to report when the current transport's agent changed to `s`: the
    /// aggregate over every transport.
    pub(super) fn tp_ice_state(&self, s: IceConnectionState) -> IceConnectionState {
        if self.xt.tps.is_empty() {
            return s;
        }
        aggregate(
            std::iter::once(s).chain(
                self.xt
                    .tps
                    .iter()
                    .map(|(_, t)| IceConnectionState::from_ice(t.agent().state())),
            ),
        )
    }

    /// Whether every transport other than the current one is connected (keys in place).
    pub(super) fn tp_others_connected(&self) -> bool {
        self.xt.tps.iter().all(|(_, t)| t.dtls_connected)
    }

    /// Whether every transport beyond the primary has its keys and paths (with the primary
    /// current).
    pub(super) fn tp_all_connected(&self) -> bool {
        self.xt.tps.iter().all(|(_, t)| {
            let a = t.agent();
            t.dtls_connected
                && a.send_pair().is_some()
                && (a.components() == 1 || a.send_pair_of(2).is_some())
        })
    }

    /// Whether a transport beyond the primary has SRTP keys (media timers run then).
    pub(super) fn tp_any_srtp(&self) -> bool {
        self.xt.tps.iter().any(|(_, t)| t.srtp_tx.is_some())
    }

    /// The earliest timer of the transports beyond the primary.
    pub(super) fn tp_timeout(&self) -> Option<Instant> {
        self.xt
            .tps
            .iter()
            .flat_map(|(_, t)| {
                [
                    t.agent().poll_timeout(),
                    t.dtls.as_ref().and_then(Connection::poll_timeout),
                    t.rtcp.dtls.as_ref().and_then(Connection::poll_timeout),
                ]
            })
            .flatten()
            .min()
    }

    /// The ICE and DTLS timers of the current transport.
    pub(super) fn tp_handle_timeout(&mut self, now: Instant) {
        self.ice.handle_timeout(now);
        self.latch_expire(now);
        let mut failed = [false; 2];
        for (i, d) in [self.dtls.as_mut(), self.rtcp.dtls.as_mut()]
            .into_iter()
            .enumerate()
        {
            let Some(d) = d else { continue };
            if d.poll_timeout().is_some_and(|t| t <= now) {
                if let Err(e) = d.handle_timeout(now) {
                    only_log::debug!(target: "only_webrtc", "dtls: {e}");
                    failed[i] = true;
                }
            }
        }
        // A handshake latched onto tentatively fails without harm (ADR-082).
        if (failed[0] && !self.latch_dtls_failed(1)) || (failed[1] && !self.latch_dtls_failed(2)) {
            self.alive = false;
        }
        self.pump(now);
    }

    /// Runs `f` on every transport beyond the primary (with the primary current).
    pub(super) fn tp_each(&mut self, mut f: impl FnMut(&mut Rtc)) {
        for k in 1..=self.xt.tps.len() {
            self.with_tp(k, &mut f);
        }
    }

    /// Closes the current transport's DTLS associations and agent.
    pub(super) fn tp_close(&mut self, now: Instant) {
        if let Some(d) = self.dtls.as_mut() {
            d.close();
        }
        self.flush_dtls(now);
        if let Some(d) = self.rtcp.dtls.as_mut() {
            d.close();
        }
        self.flush_rtcp_dtls(now);
        self.ice.close();
    }

    // ---- making transports ----

    /// A new transport for section `mid`: an agent like the primary's (role, options,
    /// candidates; `components` of them), with `creds`.
    fn new_tp(&self, k: usize, creds: Credentials, components: u16, now: Instant) -> Tp {
        let mut cfg = IceConfig::new(self.lite, self.ice.controlling());
        cfg.local = creds;
        cfg.aggressive_nomination = self.cfg.ice_aggressive;
        cfg.renomination = self.cfg.ice_renomination;
        cfg.components = components;
        let mut ice = IceAgent::new(cfg, now);
        let own: Vec<IceCandidate> = self
            .xt
            .own_cands
            .iter()
            .filter(|(i, _)| *i == k)
            .map(|(_, c)| c.clone())
            .collect();
        let (c1, c2): (Vec<IceCandidate>, Vec<IceCandidate>) = if own.is_empty() {
            (
                self.ice
                    .local_candidates()
                    .iter()
                    .filter(|c| c.component() == 1)
                    .cloned()
                    .collect(),
                self.rtcp.candidates().to_vec(),
            )
        } else {
            own.into_iter().partition(|c| c.component() == 1)
        };
        for c in c1 {
            if c.kind() != only_ice::CandidateKind::PeerReflexive {
                ice.add_local_candidate(c);
            }
        }
        let mut rtcp = rtcp_mux::RtcpComponent::default();
        for c in c2 {
            rtcp.add_candidate(&c);
            if components == 2 {
                ice.add_local_candidate(c);
            }
        }
        Tp {
            ice: Some(ice),
            rtcp,
            ..Tp::default()
        }
    }

    /// The credentials of transport `k` (1..): the primary's ufrag followed by `k` and a
    /// password of its own (the endpoint hub finds the peer by the ufrag's first eight
    /// characters), or the primary's own (`shared`: our offer gave every section those).
    fn tp_creds(&self, k: usize, shared: bool) -> Credentials {
        let p = self.ice.local_credentials();
        if shared {
            return p.clone();
        }
        Credentials::new(format!("{}{k}", p.ufrag), Credentials::random().pwd)
    }

    /// Makes the session unbundled with a transport per section of `mids` (in use, in
    /// order); the first media section (else the first) keeps the primary. `shared`: the
    /// transports keep the primary's credentials. Sections that already have one keep it;
    /// transports of sections no longer listed are closed. Called with the primary current.
    pub(super) fn split_transports(&mut self, now: Instant, mids: &[Mid], shared: bool) {
        self.xt.split = true;
        if mids.is_empty() {
            return;
        }
        let is_media = |m: &Mid| self.media.iter().any(|l| l.mid == *m && !l.stopped);
        let primary = *self
            .xt
            .primary
            .as_ref()
            .filter(|p| mids.contains(p))
            .or_else(|| mids.iter().find(|m| is_media(m)))
            .unwrap_or(&mids[0]);
        self.xt.primary = Some(primary);
        // Transports of sections that went away.
        let gone: Vec<usize> = (1..=self.xt.tps.len())
            .filter(|k| !mids.contains(&self.xt.tps[k - 1].0))
            .collect();
        for k in gone.into_iter().rev() {
            self.with_tp(k, |s| s.tp_close(now));
            self.xt.tps.remove(k - 1);
        }
        for m in mids {
            if *m == primary || self.xt.tps.iter().any(|(x, _)| x == m) {
                continue;
            }
            let comps = if Some(*m) == self.app_mid {
                1
            } else {
                self.ice.components()
            };
            let k = self.xt.tps.len() + 1;
            let mut t = self.new_tp(k, self.tp_creds(k, shared), comps, now);
            // The application section runs DTLS even next to SDES media.
            t.sdes.active = self.sdes.active && Some(*m) != self.app_mid;
            t.sdes.proto.clone_from(&self.sdes.proto);
            self.xt.tps.push((*m, t));
        }
    }

    /// Our offer makes the session unbundled ([`BundlePolicy::Disabled`]): a transport for
    /// every section in use, with credentials of its own.
    pub(super) fn split_for_offer(&mut self, now: Instant) {
        if self.cfg.bundle != BundlePolicy::Disabled && !self.xt.split {
            return;
        }
        let mids = self.mids_in_use();
        self.split_transports(now, &mids, false);
    }

    /// The sections in use in our order (media not stopped, then the application section
    /// where its mid sorts).
    fn mids_in_use(&self) -> Vec<Mid> {
        let mut order: Vec<Mid> = self
            .media
            .iter()
            .filter(|l| !l.stopped)
            .map(|l| l.mid)
            .collect();
        if let Some(a) = self.app_mid {
            let pos = order
                .iter()
                .position(|m| mid_order(m) > mid_order(&a))
                .unwrap_or(order.len());
            order.insert(pos, a);
        }
        order
    }

    /// The sections in use of a remote description, by mid.
    pub(super) fn remote_mids(sdp: &Sdp) -> Vec<Mid> {
        sdp.media
            .iter()
            .enumerate()
            .filter(|(_, m)| m.port != 0 || (m.port == 0 && m.has("bundle-only")))
            .map(|(i, m)| {
                m.get("mid")
                    .map_or_else(|| Mid::new(&i.to_string()), Mid::new)
            })
            .collect()
    }

    /// ICE restart (`keep`: our candidates stay) of the transports beyond the primary, after
    /// the primary's.
    pub(super) fn restart_extra(&mut self, keep: bool) {
        let n = self.xt.tps.len();
        for k in 1..=n {
            let creds = self.tp_creds(k, false);
            self.with_tp(k, |s| s.ice.restart(creds, keep));
        }
    }

    // ---- remote descriptions ----

    /// The remote description's ICE credentials, candidates and options for each transport
    /// (section by section), or its plain addresses.
    pub(super) fn apply_split_transport(
        &mut self,
        sdp: &Sdp,
        is_offer: bool,
    ) -> Result<(), RtcErr> {
        for (i, m) in sdp.media.iter().enumerate() {
            if m.port == 0 {
                continue;
            }
            let mid = m
                .get("mid")
                .map_or_else(|| Mid::new(&i.to_string()), Mid::new);
            let k = self.tp_of_mid(mid);
            if k == 0 && Some(mid) != self.xt.primary {
                continue;
            }
            let one = Sdp {
                attrs: sdp.attrs.clone(),
                media: vec![m.clone()],
                conn: sdp.conn,
                media_conn: vec![sdp.media_conn.get(i).copied().flatten()],
                ..Sdp::default()
            };
            self.with_tp(k, |s| s.apply_one_transport(&one, is_offer))?;
        }
        Ok(())
    }

    /// The transport part of a one-section description for the current transport: its SDES
    /// keys, then its ICE credentials and candidates, or its plain addresses.
    fn apply_one_transport(&mut self, sdp: &Sdp, is_offer: bool) -> Result<(), RtcErr> {
        if self.sdes.active {
            if is_offer {
                self.sdes.accept_offer(sdp).map_err(err)?;
            } else {
                self.sdes.accept_answer(sdp).map_err(err)?;
            }
        }
        if self.xt.plain {
            if !self.sdes.active {
                // DTLS-SRTP without ICE still needs the fingerprint (ADR-086: it was not read
                // without BUNDLE, so no handshake started).
                self.apply_fingerprint(sdp)?;
            }
            return self.apply_plain(sdp);
        }
        self.apply_remote_transport(sdp, is_offer)
    }

    /// Without ICE and with BUNDLE (one transport): the plain addresses of the first section
    /// in use.
    pub(super) fn apply_plain_bundled(&mut self, sdp: &Sdp) -> Result<(), RtcErr> {
        let i = sdp
            .media
            .iter()
            .position(|m| m.port != 0)
            .ok_or_else(|| err("no section in use"))?;
        if !self.sdes.active {
            // DTLS-SRTP without ICE still needs the fingerprint.
            self.apply_fingerprint(sdp)?;
        }
        let one = Sdp {
            attrs: sdp.attrs.clone(),
            media: vec![sdp.media[i].clone()],
            conn: sdp.conn,
            media_conn: vec![sdp.media_conn.get(i).copied().flatten()],
            ..Sdp::default()
        };
        self.apply_plain(&one)
    }

    /// The remote DTLS fingerprint of a description (any section, else the session).
    fn apply_fingerprint(&mut self, sdp: &Sdp) -> Result<(), RtcErr> {
        let fp = sdp
            .media
            .iter()
            .find_map(|m| m.get("fingerprint"))
            .or_else(|| sdp.get("fingerprint"))
            .ok_or_else(|| err("no a=fingerprint"))?;
        let fp = Fingerprint::parse(fp).map_err(|e| err(format!("fingerprint: {e}")))?;
        if self.remote_fp.as_ref().is_some_and(|f| *f != fp) && self.dtls.is_some() {
            return Err(err("the remote DTLS fingerprint changed"));
        }
        self.remote_fp = Some(fp);
        Ok(())
    }

    /// The credentials a restart of the current transport takes: random for the primary,
    /// derived from the primary's ufrag for the others.
    pub(super) fn restart_creds(&self) -> Credentials {
        let k = self.xt.cur;
        if k == 0 {
            return Credentials::random();
        }
        let p = self.xt.tps[k - 1].1.agent().local_credentials();
        Credentials::new(format!("{}{k}", p.ufrag), Credentials::random().pwd)
    }

    /// Without ICE: fixed pairs to the section's addresses (section 0 of `sdp`).
    pub(super) fn apply_plain(&mut self, sdp: &Sdp) -> Result<(), RtcErr> {
        let (rtp, rtcp) = plain_addrs(sdp, 0)
            .ok_or_else(|| err("no c= address and port for media without ICE"))?;
        let local = |comp: u16, v6: bool| {
            let cands: Vec<IceCandidate> = if comp == 1 {
                self.ice.local_candidates().to_vec()
            } else {
                self.rtcp.candidates().to_vec()
            };
            cands
                .iter()
                .filter(|c| {
                    c.kind() == only_ice::CandidateKind::Host
                        && c.tcp_type().is_none()
                        && c.component() == comp
                })
                .find(|c| c.addr().is_ipv6() == v6)
                .map(IceCandidate::addr)
        };
        let l1 = local(1, rtp.is_ipv6())
            .ok_or_else(|| err("no host candidate for media without ICE"))?;
        let mut news = vec![rtp];
        if self.ice.components() == 2 {
            let l2 = local(2, rtcp.is_ipv6())
                .ok_or_else(|| err("no component-2 host candidate for RTCP without ICE"))?;
            // A description repeating the address keeps a latched pair.
            if !self.latch_keep(2, rtcp) {
                self.ice.set_fixed_pair(2, l2, rtcp);
            }
            news.push(rtcp);
        }
        if !self.latch_keep(1, rtp) {
            self.ice.set_fixed_pair(1, l1, rtp);
        }
        for a in &news {
            if !self.xt.sdp_remotes.contains(a) && self.xt.sdp_remotes.len() < 16 {
                self.xt.sdp_remotes.push(*a);
            }
        }
        for a in news {
            if !self.xt.new_remotes.contains(&a) && self.xt.new_remotes.len() < 16 {
                self.xt.new_remotes.push(a);
            }
        }
        Ok(())
    }

    /// Plain remote addresses learnt since the last call: the endpoint routes their
    /// datagrams to this peer before it sends anything there.
    pub(crate) fn take_plain_remotes(&mut self) -> Vec<SocketAddr> {
        std::mem::take(&mut self.xt.new_remotes)
    }

    // ---- our descriptions ----

    /// The local address and port a section without ICE is written with: the first host
    /// candidate of the current transport (component 1, and component 2's for `a=rtcp`).
    pub(super) fn plain_local(&self) -> (Option<SocketAddr>, Option<SocketAddr>) {
        let host =
            |c: &&IceCandidate| c.kind() == only_ice::CandidateKind::Host && c.tcp_type().is_none();
        let peer = self.ice.send_pair().map(|p| p.0);
        let c1 = peer.or_else(|| {
            self.ice
                .local_candidates()
                .iter()
                .filter(host)
                .find(|c| c.component() == 1)
                .map(IceCandidate::addr)
        });
        let c2 = self.ice.send_pair_of(2).map(|p| p.0).or_else(|| {
            self.rtcp
                .candidates()
                .iter()
                .filter(host)
                .map(IceCandidate::addr)
                .next()
        });
        (c1, c2)
    }

    /// Writes the plain addresses into a section built for the current transport (without
    /// ICE): the `m=` port and `a=rtcp`; returns the `c=` address (`None` with ICE).
    pub(super) fn plain_fixup_media(&self, m: &mut Media) -> Option<std::net::IpAddr> {
        if !self.xt.plain || m.port == 0 {
            return None;
        }
        let (c1, c2) = self.plain_local();
        let c1 = c1?;
        m.port = c1.port();
        if let Some(c2) = c2 {
            for a in m.attrs.iter_mut().filter(|a| a.key == "rtcp") {
                let fam = if c2.is_ipv4() { "IP4" } else { "IP6" };
                a.value = Some(format!("{} IN {fam} {}", c2.port(), c2.ip()));
            }
        }
        Some(c1.ip())
    }

    /// The token [`Rtc::take_mdns`] hands out for the remote ufrag of transport `k`, and back.
    pub(super) fn mdns_token(k: usize, ufrag: &str) -> String {
        if k == 0 {
            ufrag.to_owned()
        } else {
            format!("{k}#{ufrag}")
        }
    }

    pub(super) fn mdns_untoken(token: &str) -> (usize, &str) {
        match token.split_once('#') {
            Some((k, u)) => (k.parse().unwrap_or(0), u),
            None => (0, token),
        }
    }

    /// The first transport beyond the primary with mDNS candidates waiting.
    pub(super) fn tp_with_mdns(&self) -> Option<usize> {
        self.xt
            .tps
            .iter()
            .position(|(_, t)| !t.mdns_wanted.is_empty())
            .map(|i| i + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_states() {
        use IceConnectionState as S;
        let agg = |v: &[S]| aggregate(v.iter().copied());
        assert_eq!(agg(&[S::New, S::New]), S::New);
        assert_eq!(agg(&[S::New, S::Connected]), S::Checking);
        assert_eq!(agg(&[S::Checking, S::Completed]), S::Checking);
        assert_eq!(agg(&[S::Connected, S::Completed]), S::Connected);
        assert_eq!(agg(&[S::Completed, S::Completed]), S::Completed);
        assert_eq!(agg(&[S::Completed, S::Disconnected]), S::Disconnected);
    }

    #[test]
    fn plain_addresses() {
        let sdp = |s: &str| Sdp::parse(s).unwrap();
        let base = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n";
        let s = sdp(&format!("{base}m=audio 4000 RTP/SAVP 0\r\n"));
        assert_eq!(
            plain_addrs(&s, 0),
            Some((
                "192.0.2.1:4000".parse().unwrap(),
                "192.0.2.1:4001".parse().unwrap()
            ))
        );
        let s = sdp(&format!(
            "{base}m=audio 4000 RTP/SAVP 0\r\nc=IN IP4 192.0.2.7\r\na=rtcp:5005 IN IP4 192.0.2.9\r\n"
        ));
        assert_eq!(
            plain_addrs(&s, 0),
            Some((
                "192.0.2.7:4000".parse().unwrap(),
                "192.0.2.9:5005".parse().unwrap()
            ))
        );
        let s = sdp(&format!("{base}m=audio 4000 RTP/SAVP 0\r\na=rtcp:4002\r\n"));
        assert_eq!(
            plain_addrs(&s, 0).unwrap().1,
            "192.0.2.1:4002".parse().unwrap()
        );
        let s = sdp(&format!("{base}m=audio 4000 RTP/SAVP 0\r\na=rtcp-mux\r\n"));
        assert_eq!(
            plain_addrs(&s, 0).unwrap().1,
            "192.0.2.1:4000".parse().unwrap()
        );
        let s = sdp(
            "v=0\r\no=- 1 1 IN IP6 ::1\r\ns=-\r\nt=0 0\r\nm=audio 4000 RTP/SAVP 0\r\nc=IN IP6 2001:db8::5\r\n",
        );
        assert_eq!(
            plain_addrs(&s, 0).unwrap().0,
            "[2001:db8::5]:4000".parse().unwrap()
        );
        // No address, an unspecified one, a rejected section, a bad a=rtcp.
        assert_eq!(
            plain_addrs(&sdp("v=0\r\nm=audio 4000 RTP/SAVP 0\r\n"), 0),
            None
        );
        let s = sdp("v=0\r\nc=IN IP4 0.0.0.0\r\nm=audio 4000 RTP/SAVP 0\r\n");
        assert_eq!(plain_addrs(&s, 0), None);
        assert_eq!(
            plain_addrs(&sdp(&format!("{base}m=audio 0 RTP/SAVP 0\r\n")), 0),
            None
        );
        let s = sdp(&format!("{base}m=audio 4000 RTP/SAVP 0\r\na=rtcp:x\r\n"));
        assert_eq!(plain_addrs(&s, 0), None);
        assert!(!has_ice(&s) && !bundles(&s));
    }
}
