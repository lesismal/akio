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
//! Before the keys exist nothing latches (DTLS-SRTP without ICE needs the remote at its SDP
//! address for the handshake).

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

/// The latching state of a transport (components 1 and 2).
#[derive(Debug, Default)]
pub(super) struct Latch {
    comps: [LatchComp; 2],
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
        if !matches!(data.first(), Some(128..=191)) || !self.latch_open(now, destination) {
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
