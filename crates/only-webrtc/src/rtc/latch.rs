//! Latching plain (no-ICE) media onto the address it really comes from (ADR-077): symmetric
//! RTP / "comedia", as SIP gateways serve phones behind NATs (RFC 7362).
//!
//! A remote without ICE writes the address it believes it has in `c=` / `m=`; behind a NAT
//! that is a private address, and its packets arrive from the NAT's public mapping. With
//! [`RtcConfig::set_latching`](crate::RtcConfig::set_latching), a transport without ICE moves
//! its fixed pair (per ICE component: RTP, and RTCP when it has its own port) to the source
//! of an RTP or RTCP packet that **authenticated** under the transport's SRTP / SRTCP keys,
//! and the endpoint routes that source to the peer:
//!
//! - [`Latching::Once`]: the first authenticated packet's source (the SDP address included)
//!   is the remote for good;
//! - [`Latching::Rebind`]`(quiet)`: the first one, then another authenticated source once the
//!   latched one has sent nothing authenticated for `quiet` (a NAT rebinding, a phone moving
//!   networks); `Duration::ZERO` follows every authenticated packet from a new source.
//!
//! The SRTP tag is the gate: a packet from an unknown source reaches the peer only to be
//! authenticated (nothing else is done with it otherwise), and SRTP's replay protection
//! refuses copies of packets already received, so an off-path attacker cannot move the media.
//!
//! **Before DTLS-SRTP keys exist** (ADR-082) the handshake latches: while this side is the
//! DTLS server (the remote `a=setup:active`; an `actpass` offer is answered `passive` when
//! latching) and nothing came from the description's address, a ClientHello from an unknown
//! source is answered with a stateless cookie exchange (HelloVerifyRequest, or a DTLS 1.3
//! HelloRetryRequest, [`only_dtls::HelloVerifier`]) and changes nothing. A ClientHello with
//! a valid cookie proves the source receives at its address: the component's pair moves
//! there *tentatively* and the handshake runs with it. The remote's certificate must match
//! the description's fingerprint: a handshake that completes latches for good (as the policy
//! says); one that fails, is closed, or has not completed within [`DTLS_TENTATIVE`] moves the
//! pair back and lets another source try. Others' ClientHellos wait meanwhile.

use super::*;
use crate::types::Latching;

/// The latching state of one ICE component of a transport.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct LatchComp {
    /// An authenticated packet's source was taken (or confirmed) as the remote.
    latched: bool,
    /// When the latched source last sent an authenticated packet.
    heard: Option<Instant>,
}

/// How long a handshake latched onto tentatively has to complete.
pub(super) const DTLS_TENTATIVE: Duration = Duration::from_secs(4);

/// A DTLS handshake running with an unknown source (see the module docs).
#[derive(Debug, Clone, Copy)]
pub(super) struct Tentative {
    pub(super) source: SocketAddr,
    since: Instant,
    /// The pair's remote before (the description's address).
    sdp: SocketAddr,
}

/// The latching state of a transport (components 1 and 2).
#[derive(Debug, Default)]
pub(super) struct Latch {
    comps: [LatchComp; 2],
    /// A handshake with an unknown source (ADR-082).
    pub(super) tentative: Option<Tentative>,
    /// The description's address of each component.
    sdp: [Option<SocketAddr>; 2],
    /// Times the remote moved (statistics).
    pub(super) moves: u64,
}

impl Latch {
    /// Whether component `comp` may move to another source at `now` under `policy`.
    fn may_move(&self, comp: u16, policy: Latching, now: Instant) -> bool {
        let Some(c) = self.comps.get(usize::from(comp.max(1)) - 1) else {
            return false;
        };
        match policy {
            Latching::Once => !c.latched,
            Latching::Rebind(quiet) => {
                !c.latched
                    || c.heard
                        .is_none_or(|h| now.saturating_duration_since(h) >= quiet)
            }
            _ => false,
        }
    }

    /// Whether a component could still move later (else the endpoint need not offer the
    /// peer datagrams from unknown sources).
    fn open(&self, policy: Latching, comps: u16) -> bool {
        match policy {
            Latching::Once => self.comps[..usize::from(comps.clamp(1, 2))]
                .iter()
                .any(|c| !c.latched),
            Latching::Rebind(_) => true,
            _ => false,
        }
    }
}

impl Rtc {
    /// Whether the session latches: no ICE, and latching configured.
    pub(super) fn latching(&self) -> bool {
        self.xt.plain && self.cfg.latching != Latching::Off
    }

    /// An RTP or RTCP packet of component `comp` authenticated: when it came from another
    /// source than the component's remote (the datagram being received,
    /// [`Rtc::latch_rx`]), the pair moves there if the policy allows.
    pub(super) fn latch_auth(&mut self, now: Instant, comp: u16) {
        let Some((src, _)) = self.latch_rx.take() else {
            return;
        };
        self.latch_took = true;
        let Some((local, remote)) = self.ice.send_pair_of(comp) else {
            return;
        };
        let i = usize::from(comp.clamp(1, 2)) - 1;
        if src == remote {
            let c = &mut self.latch.comps[i];
            c.latched = true;
            c.heard = Some(now);
            return;
        }
        if !self.latch.may_move(comp, self.cfg.latching, now) {
            return;
        }
        only_log::debug!(target: "only_webrtc", "latching component {comp}: {remote} -> {src}");
        let c = &mut self.latch.comps[i];
        c.latched = true;
        c.heard = Some(now);
        self.latch.moves += 1;
        // With rtcp-mux RTCP goes where RTP does (one component); without, component 2
        // latches on its own SRTCP.
        self.ice.set_fixed_pair(comp, local, src);
        if !self.xt.new_remotes.contains(&src) && self.xt.new_remotes.len() < 16 {
            self.xt.new_remotes.push(src);
        }
        if !self.xt.sdp_remotes.contains(&remote) && self.xt.gone_remotes.len() < 16 {
            self.xt.gone_remotes.push(remote);
        }
    }

    /// A description gives component `comp` the address `sdp`: `true` keeps the pair (it
    /// latched elsewhere and the description repeats the address it had), else the latch of
    /// the component starts over.
    pub(super) fn latch_keep(&mut self, comp: u16, sdp: SocketAddr) -> bool {
        let i = usize::from(comp.clamp(1, 2)) - 1;
        let keep = self.latching()
            && self.latch.sdp[i] == Some(sdp)
            && self.latch.comps[i].latched
            && self.ice.send_pair_of(comp).is_some();
        if !keep {
            self.latch.sdp[i] = Some(sdp);
            self.latch.comps[i] = LatchComp::default();
        }
        keep
    }

    /// Whether the peer takes datagrams from unknown sources on local address
    /// `destination` at `now` to try them for latching: some transport has its keys, uses
    /// that local address, and has a component that may move now.
    pub(crate) fn latch_open(&self, now: Instant, destination: SocketAddr) -> bool {
        if !self.latching() || !self.alive {
            return false;
        }
        if self.dtls_latch_open(now, destination)
            || self
                .xt
                .tps
                .iter()
                .any(|(_, t)| t.dtls_latch_open(&self.cfg, self.dtls_role, now, destination))
        {
            return true;
        }
        let policy = self.cfg.latching;
        let one = |ice: &IceAgent, latch: &Latch, keys: bool| {
            keys && (1..=ice.components()).any(|c| {
                ice.send_pair_of(c).is_some_and(|p| p.0 == destination)
                    && latch.may_move(c, policy, now)
            })
        };
        one(
            &self.ice,
            &self.latch,
            self.srtp_rx.is_some() || self.rtcp.srtcp_rx.is_some(),
        ) || self.xt.tps.iter().any(|(_, t)| {
            one(
                t.agent(),
                &t.latch,
                t.srtp_rx.is_some() || t.rtcp.srtcp_rx.is_some(),
            )
        })
    }

    /// Whether a component of some transport may still move (the endpoint offers the peer
    /// datagrams from unknown sources while this holds).
    pub(crate) fn latch_wanted(&self) -> bool {
        if !self.latching() || !self.alive {
            return false;
        }
        let policy = self.cfg.latching;
        self.latch.open(policy, self.ice.components())
            || self
                .xt
                .tps
                .iter()
                .any(|(_, t)| t.latch.open(policy, t.agent().components()))
    }

    /// A datagram from `source`, an address no transport knows, that arrived on
    /// `destination`: tried as RTP / RTCP of each transport; `true` if it authenticated
    /// (it was then received, and the transport latched onto `source` if the policy allows).
    pub(crate) fn latch_receive(
        &mut self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
        data: &[u8],
    ) -> bool {
        let dtls = matches!(data.first(), Some(20..=63));
        if !(dtls || matches!(data.first(), Some(128..=191))) || !self.latch_open(now, destination)
        {
            self.rx_ecn = 0;
            return false;
        }
        self.latch_took = false;
        for k in 0..=self.xt.tps.len() {
            self.with_tp(k, |s| s.latch_one(now, source, destination, data));
            if self.latch_took {
                break;
            }
        }
        let took = std::mem::take(&mut self.latch_took);
        self.rx_ecn = 0;
        if took {
            self.pump(now);
        }
        took
    }

    /// [`latch_receive`](Self::latch_receive) on the current transport.
    fn latch_one(
        &mut self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
        data: &[u8],
    ) {
        let comp1 = self.ice.send_pair_of(1).is_some_and(|p| p.0 == destination);
        let rtcp_comp = self.ice.components() == 2 && self.rtcp.is_local(destination);
        if !comp1 && !rtcp_comp {
            return;
        }
        if matches!(data.first(), Some(20..=63)) {
            if comp1 {
                self.latch_dtls(now, source, destination, data);
            }
            return;
        }
        self.latch_rx = Some((source, destination));
        if only_rtp::is_rtcp(data) {
            self.handle_rtcp(now, data, rtcp_comp);
        } else if !rtcp_comp {
            self.handle_rtp(now, data);
        }
        self.latch_rx = None;
        if self.latch_took {
            self.stats.bytes_received += data.len() as u64;
            self.stats.packets_received += 1;
        }
    }

    /// Whether the current transport latches a DTLS handshake onto a ClientHello arriving on
    /// `destination` at `now` (see the module docs).
    fn dtls_latch_open(&self, now: Instant, destination: SocketAddr) -> bool {
        dtls_open(
            &self.cfg,
            &self.ice,
            &self.latch,
            (self.sdes.active, self.dtls_role, self.dtls_up),
            self.remote_addr,
            now,
            destination,
        )
    }

    /// Whether a DTLS datagram from `source` on `destination` goes to DTLS latching: the
    /// handshake may latch and `source` is not the pair's remote.
    pub(super) fn dtls_latching(
        &self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> bool {
        self.latching()
            && self.ice.send_pair_of(1).is_some_and(|p| p.1 != source)
            && self.dtls_latch_open(now, destination)
    }

    /// A DTLS datagram from the unknown `source` on the current transport (component 1).
    pub(super) fn latch_dtls(
        &mut self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
        data: &[u8],
    ) {
        if !self.dtls_latch_open(now, destination) {
            return;
        }
        self.latch_expire(now);
        if self.latch.tentative.is_some() {
            return; // another source's handshake runs
        }
        let Some((local, sdp)) = self.ice.send_pair_of(1) else {
            return;
        };
        let Some(hv) = hello_verifier(now) else {
            return;
        };
        let peer = source.to_string();
        match hv.check(now, peer.as_bytes(), data) {
            only_dtls::HelloCheck::Respond(m) => {
                // Stateless: nothing changes until the source answers from where it is.
                self.latch_took = true;
                self.transmits.push_back((destination, source, m, 0));
            }
            only_dtls::HelloCheck::Accept => {
                only_log::debug!(target: "only_webrtc", "latching the DTLS handshake: {sdp} -> {source} (tentative)");
                self.latch_took = true;
                self.latch.tentative = Some(Tentative {
                    source,
                    since: now,
                    sdp,
                });
                self.ice.set_fixed_pair(1, local, source);
                self.remote_addr = Some(source);
                self.remote_local = Some(destination);
                self.dtls = self.new_dtls(now, Some(source));
                if !self.xt.new_remotes.contains(&source) && self.xt.new_remotes.len() < 16 {
                    self.xt.new_remotes.push(source);
                }
                self.handle_dtls(now, Some(data));
            }
            _ => {}
        }
    }

    /// The tentative handshake completed (its certificate matched): the latch holds.
    pub(super) fn latch_dtls_done(&mut self, now: Instant) {
        let Some(t) = self.latch.tentative.take() else {
            return;
        };
        only_log::debug!(target: "only_webrtc", "latched the DTLS handshake onto {}", t.source);
        let c = &mut self.latch.comps[0];
        c.latched = true;
        c.heard = Some(now);
        self.latch.moves += 1;
        if !self.xt.sdp_remotes.contains(&t.sdp) && self.xt.gone_remotes.len() < 16 {
            self.xt.gone_remotes.push(t.sdp);
        }
    }

    /// The tentative handshake failed or was closed: back to the description's address, the
    /// association dropped; `true` if there was one (the peer lives on).
    pub(super) fn latch_dtls_failed(&mut self) -> bool {
        let Some(t) = self.latch.tentative.take() else {
            return false;
        };
        only_log::debug!(target: "only_webrtc", "DTLS handshake with {} failed: not latched", t.source);
        if let Some((local, _)) = self.ice.send_pair_of(1) {
            self.ice.set_fixed_pair(1, local, t.sdp);
        }
        self.dtls = None;
        self.remote_addr = None;
        self.remote_local = None;
        if self.xt.gone_remotes.len() < 16 {
            self.xt.gone_remotes.push(t.source);
        }
        self.xt.new_remotes.retain(|a| *a != t.source);
        true
    }

    /// Gives up on a tentative handshake that did not complete in time.
    pub(super) fn latch_expire(&mut self, now: Instant) {
        if self
            .latch
            .tentative
            .is_some_and(|t| now.saturating_duration_since(t.since) >= DTLS_TENTATIVE)
        {
            self.latch_dtls_failed();
        }
    }

    /// Remote addresses the transports latched away from (not the descriptions' own): the
    /// endpoint stops routing them to this peer.
    pub(crate) fn take_gone_remotes(&mut self) -> Vec<SocketAddr> {
        std::mem::take(&mut self.xt.gone_remotes)
    }

    /// Times a transport's remote moved.
    pub(super) fn latch_moves(&self) -> u64 {
        self.latch.moves + self.xt.tps.iter().map(|(_, t)| t.latch.moves).sum::<u64>()
    }
}

/// The cookie verifier of DTLS latching, one per process: the endpoint offers a datagram to
/// one latching peer after another, so a cookie one made must verify at the next.
fn hello_verifier(now: Instant) -> Option<&'static only_dtls::HelloVerifier> {
    static V: std::sync::OnceLock<Option<only_dtls::HelloVerifier>> = std::sync::OnceLock::new();
    V.get_or_init(|| only_dtls::HelloVerifier::new(now).ok())
        .as_ref()
}

/// Whether DTLS may latch on a transport: latching, DTLS-SRTP with this side the server
/// before the handshake completed, nothing from the description's address yet (or the
/// tentative source's), and component 1 on `destination` able to move.
fn dtls_open(
    cfg: &ConfigInner,
    ice: &IceAgent,
    latch: &Latch,
    (sdes, role, up): (bool, Option<Role>, bool),
    remote: Option<SocketAddr>,
    now: Instant,
    destination: SocketAddr,
) -> bool {
    !sdes
        && role == Some(Role::Server)
        && !up
        && (remote.is_none() || remote == latch.tentative.map(|t| t.source))
        && ice.send_pair_of(1).is_some_and(|p| p.0 == destination)
        && latch.may_move(1, cfg.latching, now)
}

impl transports::Tp {
    /// [`Rtc::dtls_latch_open`] of a transport that is not current.
    pub(super) fn dtls_latch_open(
        &self,
        cfg: &ConfigInner,
        role: Option<Role>,
        now: Instant,
        destination: SocketAddr,
    ) -> bool {
        let (sdes, up, remote) = self.dtls_view();
        dtls_open(
            cfg,
            self.agent(),
            &self.latch,
            (sdes, role, up),
            remote,
            now,
            destination,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn policies() {
        let now = Instant::now();
        let mut l = Latch::default();
        assert!(!l.may_move(1, Latching::Off, now));
        assert!(l.may_move(1, Latching::Once, now));
        assert!(l.open(Latching::Once, 2));
        l.comps[0] = LatchComp {
            latched: true,
            heard: Some(now),
        };
        assert!(!l.may_move(1, Latching::Once, now));
        // Component 2 has not latched yet.
        assert!(l.may_move(2, Latching::Once, now));
        assert!(l.open(Latching::Once, 2));
        assert!(!l.open(Latching::Once, 1));
        let q = Duration::from_secs(2);
        assert!(!l.may_move(1, Latching::Rebind(q), now + Duration::from_secs(1)));
        assert!(l.may_move(1, Latching::Rebind(q), now + q));
        assert!(l.may_move(1, Latching::Rebind(Duration::ZERO), now));
        assert!(l.open(Latching::Rebind(q), 1));
    }
}
