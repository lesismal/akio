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
//! HelloRetryRequest, [`akio_dtls::HelloVerifier`]) and changes nothing. A ClientHello with
//! a valid cookie proves the source receives at its address: the component's pair moves
//! there *tentatively* and the handshake runs with it. The remote's certificate must match
//! the description's fingerprint: a handshake that completes latches for good (as the policy
//! says); one that fails, is closed, or has not completed within [`DTLS_TENTATIVE`] moves the
//! pair back and lets another source try. Others' ClientHellos wait meanwhile.
//!
//! ADR-086 extends this to the other cases:
//!
//! - **RTCP's own handshake** (component 2, without rtcp-mux, RFC 5764 §4.1) latches the same
//!   way, from the NAT's mapping of the remote's RTCP port, with its own cookie exchange and
//!   tentative pair.
//! - **This side the DTLS client** (the remote answered or offered `passive`): the remote, a
//!   server, sends nothing a NAT would let through until it hears from us, and our
//!   ClientHello goes to the private address. A datagram from an unknown source on the
//!   component's local address (an RFC 6263 keepalive: a STUN Binding Indication or request,
//!   or RTP before any keys) makes the component's pair move there tentatively, and a fresh
//!   client handshake starts toward it. The server must prove the description's fingerprint,
//!   as above; failure, a close or [`DTLS_TENTATIVE`] moves the pair back and the handshake
//!   starts over toward the description's address. One attempt at a time per component, so
//!   spoofed triggers make this side send a few ClientHellos per [`DTLS_TENTATIVE`] at most.
//!   [`RtcConfig::set_plain_keepalive`](crate::RtcConfig::set_plain_keepalive) sends such
//!   keepalives.

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
    /// A handshake with an unknown source, per component (ADR-082, ADR-086).
    pub(super) tentative: [Option<Tentative>; 2],
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
        akio_log::debug!(target: "akio_webrtc", "latching component {comp}: {remote} -> {src}");
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
    /// that local address, and has a component that may move now; or a DTLS handshake of a
    /// component on it may latch.
    pub(crate) fn latch_open(&self, now: Instant, destination: SocketAddr) -> bool {
        if !self.latching() || !self.alive {
            return false;
        }
        if (1..=2).any(|c| self.dtls_latch_open(now, c, destination))
            || self.xt.tps.iter().any(|(_, t)| {
                (1..=2).any(|c| t.dtls_latch_open(&self.cfg, self.dtls_role, now, c, destination))
            })
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
    /// `destination`: tried as RTP / RTCP of each transport, or for DTLS latching; `true` if
    /// it was taken (it authenticated, and the transport latched onto `source` if the policy
    /// allows; or a handshake answered it or started toward it).
    pub(crate) fn latch_receive(
        &mut self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
        data: &[u8],
    ) -> bool {
        if !matches!(data.first(), Some(0..=3 | 20..=63 | 128..=191))
            || !self.latch_open(now, destination)
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
        let comp = if rtcp_comp { 2 } else { 1 };
        match data.first() {
            Some(20..=63) => {
                if self.dtls_role == Some(Role::Server) {
                    self.latch_dtls(now, comp, source, destination, data);
                }
                return;
            }
            Some(0..=3 | 128..=191)
                if self.dtls_role == Some(Role::Client)
                    && self.dtls_latch_open(now, comp, destination) =>
            {
                // The DTLS client hears from a source it does not know (ADR-086).
                self.latch_dtls_client(now, comp, source, destination);
                return;
            }
            Some(0..=3) => return,
            _ => {}
        }
        self.latch_rx = Some((source, destination));
        if akio_rtp::is_rtcp(data) {
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

    /// Component `comp`'s DTLS state: handshake done, and the remote address heard from.
    fn comp_dtls(&self, comp: u16) -> (bool, Option<SocketAddr>) {
        if comp == 2 {
            (self.rtcp.dtls_up, self.rtcp.first.map(|f| f.1))
        } else {
            (self.dtls_up, self.remote_addr)
        }
    }

    /// Whether the current transport's component `comp` latches its DTLS handshake from
    /// `destination` at `now` (see the module docs).
    fn dtls_latch_open(&self, now: Instant, comp: u16, destination: SocketAddr) -> bool {
        let (up, heard) = self.comp_dtls(comp);
        dtls_open(
            &self.cfg,
            &self.ice,
            &self.latch,
            comp,
            (self.sdes.active, self.dtls_role, up),
            heard,
            now,
            destination,
        )
    }

    /// Whether a DTLS datagram from `source` on `destination` goes to DTLS latching of
    /// component `comp`: this side is the server, the handshake may latch and `source` is
    /// not the pair's remote.
    pub(super) fn dtls_latching(
        &self,
        now: Instant,
        comp: u16,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> bool {
        self.latching()
            && self.dtls_role == Some(Role::Server)
            && self.ice.send_pair_of(comp).is_some_and(|p| p.1 != source)
            && self.dtls_latch_open(now, comp, destination)
    }

    /// A DTLS datagram from the unknown `source` on the current transport's component
    /// `comp`, while this side is the DTLS server.
    pub(super) fn latch_dtls(
        &mut self,
        now: Instant,
        comp: u16,
        source: SocketAddr,
        destination: SocketAddr,
        data: &[u8],
    ) {
        if !self.dtls_latch_open(now, comp, destination) {
            return;
        }
        self.latch_expire(now);
        let i = usize::from(comp.clamp(1, 2)) - 1;
        if self.latch.tentative[i].is_some() {
            return; // another source's handshake runs
        }
        let Some((local, sdp)) = self.ice.send_pair_of(comp) else {
            return;
        };
        let Some(hv) = hello_verifier(now) else {
            return;
        };
        let peer = source.to_string();
        match hv.check(now, peer.as_bytes(), data) {
            akio_dtls::HelloCheck::Respond(m) => {
                // Stateless: nothing changes until the source answers from where it is.
                self.latch_took = true;
                self.transmits.push_back((destination, source, m, 0));
            }
            akio_dtls::HelloCheck::Accept => {
                akio_log::debug!(target: "akio_webrtc", "latching component {comp}'s DTLS handshake: {sdp} -> {source} (tentative)");
                self.latch_tentative(now, comp, local, sdp, source, destination);
                if comp == 2 {
                    self.rtcp.dtls = self.new_dtls(now, Some(source));
                    self.rtcp_dtls_input(now, source, destination, data);
                } else {
                    self.dtls = self.new_dtls(now, Some(source));
                    self.handle_dtls(now, Some(data));
                }
            }
            _ => {}
        }
    }

    /// While this side is the DTLS client (ADR-086): a datagram (a STUN keepalive or binding
    /// request, RTP before keys) from the unknown `source` on component `comp`. A fresh
    /// handshake starts toward it tentatively; its server must prove the description's
    /// fingerprint.
    fn latch_dtls_client(
        &mut self,
        now: Instant,
        comp: u16,
        source: SocketAddr,
        destination: SocketAddr,
    ) {
        self.latch_expire(now);
        let i = usize::from(comp.clamp(1, 2)) - 1;
        if self.latch.tentative[i].is_some() {
            return; // one at a time
        }
        let Some((local, sdp)) = self.ice.send_pair_of(comp) else {
            return;
        };
        if local != destination || sdp == source {
            return;
        }
        akio_log::debug!(target: "akio_webrtc", "latching component {comp}'s DTLS handshake as the client: {sdp} -> {source} (tentative)");
        self.latch_tentative(now, comp, local, sdp, source, destination);
        if comp == 2 {
            self.rtcp.dtls = self.new_dtls(now, None);
        } else {
            self.dtls = self.new_dtls(now, None);
        }
    }

    /// Moves component `comp`'s pair to `source` tentatively.
    fn latch_tentative(
        &mut self,
        now: Instant,
        comp: u16,
        local: SocketAddr,
        sdp: SocketAddr,
        source: SocketAddr,
        destination: SocketAddr,
    ) {
        let i = usize::from(comp.clamp(1, 2)) - 1;
        self.latch_took = true;
        self.latch.tentative[i] = Some(Tentative {
            source,
            since: now,
            sdp,
        });
        self.ice.set_fixed_pair(comp, local, source);
        if comp == 2 {
            self.rtcp.first = Some((destination, source));
        } else {
            self.remote_addr = Some(source);
            self.remote_local = Some(destination);
        }
        if !self.xt.new_remotes.contains(&source) && self.xt.new_remotes.len() < 16 {
            self.xt.new_remotes.push(source);
        }
    }

    /// Component `comp`'s tentative handshake completed (its certificate matched): the latch
    /// holds.
    pub(super) fn latch_dtls_done(&mut self, now: Instant, comp: u16) {
        let i = usize::from(comp.clamp(1, 2)) - 1;
        let Some(t) = self.latch.tentative[i].take() else {
            return;
        };
        akio_log::debug!(target: "akio_webrtc", "latched component {comp}'s DTLS handshake onto {}", t.source);
        let c = &mut self.latch.comps[i];
        c.latched = true;
        c.heard = Some(now);
        self.latch.moves += 1;
        if !self.xt.sdp_remotes.contains(&t.sdp) && self.xt.gone_remotes.len() < 16 {
            self.xt.gone_remotes.push(t.sdp);
        }
    }

    /// Component `comp`'s tentative handshake failed or was closed: back to the description's
    /// address, the association dropped (a client's starts over toward that address); `true`
    /// if there was one (the peer lives on).
    pub(super) fn latch_dtls_failed(&mut self, comp: u16) -> bool {
        let i = usize::from(comp.clamp(1, 2)) - 1;
        let Some(t) = self.latch.tentative[i].take() else {
            return false;
        };
        akio_log::debug!(target: "akio_webrtc", "component {comp}'s DTLS handshake with {} failed: not latched", t.source);
        if let Some((local, _)) = self.ice.send_pair_of(comp) {
            self.ice.set_fixed_pair(comp, local, t.sdp);
        }
        if comp == 2 {
            self.rtcp.dtls = None;
            self.rtcp.first = None;
        } else {
            self.dtls = None;
            self.remote_addr = None;
            self.remote_local = None;
        }
        if self.xt.gone_remotes.len() < 16 {
            self.xt.gone_remotes.push(t.source);
        }
        self.xt.new_remotes.retain(|a| *a != t.source);
        true
    }

    /// Gives up on tentative handshakes that did not complete in time.
    pub(super) fn latch_expire(&mut self, now: Instant) {
        for comp in 1..=2 {
            let i = usize::from(comp) - 1;
            if self.latch.tentative[i]
                .is_some_and(|t| now.saturating_duration_since(t.since) >= DTLS_TENTATIVE)
            {
                self.latch_dtls_failed(comp);
            }
        }
    }

    /// RFC 6263 keepalives (ADR-086, [`RtcConfig::set_plain_keepalive`](crate::RtcConfig::set_plain_keepalive)):
    /// without ICE, a STUN Binding Indication on every component's path of every transport
    /// once its pair exists, then every configured interval. It keeps NAT bindings open
    /// through silence, and lets a latching remote that must start the DTLS handshake find
    /// this side behind a NAT.
    pub(super) fn keepalive(&mut self, now: Instant) {
        let every = self.cfg.keepalive;
        if every.is_zero()
            || !self.xt.plain
            || !self.alive
            || self.keepalive_next.is_some_and(|t| t > now)
        {
            return;
        }
        let mut tid = [0u8; 12];
        fill_random(&mut tid);
        let ka = akio_turn::stun::MessageBuilder::new(
            akio_turn::stun::Method::BINDING,
            akio_turn::stun::Class::Indication,
            tid,
        )
        .fingerprint()
        .build();
        let mut sent = false;
        for k in 0..=self.xt.tps.len() {
            self.with_tp(k, |s| {
                for c in 1..=s.ice.components() {
                    if let Some((l, r)) = s.ice.send_pair_of(c) {
                        s.transmits.push_back((l, r, ka.clone(), 0));
                        sent = true;
                    }
                }
            });
        }
        if sent {
            self.keepalive_next = Some(now + every);
        }
    }

    /// When the next keepalive is due (`None`: none configured, or no path yet).
    pub(super) fn keepalive_timeout(&self, now: Instant) -> Option<Instant> {
        (!self.cfg.keepalive.is_zero()
            && self.xt.plain
            && self.alive
            && self.ice.send_pair().is_some())
        .then(|| self.keepalive_next.unwrap_or(now))
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
fn hello_verifier(now: Instant) -> Option<&'static akio_dtls::HelloVerifier> {
    static V: std::sync::OnceLock<Option<akio_dtls::HelloVerifier>> = std::sync::OnceLock::new();
    V.get_or_init(|| akio_dtls::HelloVerifier::new(now).ok())
        .as_ref()
}

/// Whether DTLS may latch on component `comp` of a transport: latching, DTLS-SRTP before
/// the component's handshake completed (`up`; either role, ADR-086), nothing from the
/// description's address yet (`heard`, or only the tentative source), and the component on
/// `destination` able to move.
#[allow(clippy::too_many_arguments)]
fn dtls_open(
    cfg: &ConfigInner,
    ice: &IceAgent,
    latch: &Latch,
    comp: u16,
    (sdes, role, up): (bool, Option<Role>, bool),
    heard: Option<SocketAddr>,
    now: Instant,
    destination: SocketAddr,
) -> bool {
    let i = usize::from(comp.clamp(1, 2)) - 1;
    !sdes
        && role.is_some()
        && !up
        && comp <= ice.components()
        && (heard.is_none() || heard == latch.tentative[i].map(|t| t.source))
        && ice.send_pair_of(comp).is_some_and(|p| p.0 == destination)
        && latch.may_move(comp, cfg.latching, now)
}

impl transports::Tp {
    /// [`Rtc::dtls_latch_open`] of a transport that is not current.
    pub(super) fn dtls_latch_open(
        &self,
        cfg: &ConfigInner,
        role: Option<Role>,
        now: Instant,
        comp: u16,
        destination: SocketAddr,
    ) -> bool {
        let (sdes, up1, remote) = self.dtls_view();
        let (up, heard) = if comp == 2 {
            (self.rtcp.dtls_up, self.rtcp.first.map(|f| f.1))
        } else {
            (up1, remote)
        };
        dtls_open(
            cfg,
            self.agent(),
            &self.latch,
            comp,
            (sdes, role, up),
            heard,
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
