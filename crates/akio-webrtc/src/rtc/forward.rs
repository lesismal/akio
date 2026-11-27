//! What an SFU needs of a peer (ADR-187): a cap on what the remote sends told as REMB, and
//! ICE consent failure after a timeout of its own.

use super::*;

/// The SFU state of one peer.
#[derive(Debug, Default)]
pub(super) struct PeerFwd {
    /// The cap told the remote senders as REMB (bits per second).
    remb_cap: Option<u64>,
    /// When ICE reports `Failed` (consent lost since `Disconnected`).
    pub(super) fail_at: Option<Instant>,
}

impl Rtc {
    /// Caps what the remote sends at `cap` bits per second, told as REMB once a second with
    /// the reports and once now (`None`: no more REMBs).
    pub(crate) fn set_receive_bitrate_cap(&mut self, cap: Option<u64>) {
        self.fwd.remb_cap = cap;
        if let Some(remb) = self.remb() {
            let ssrc = self.remb_sender();
            self.send_rtcp(&[
                Rtcp::ReceiverReport {
                    ssrc,
                    reports: Vec::new(),
                },
                remb,
            ]);
        }
    }

    fn remb_sender(&self) -> u32 {
        self.media.first().map_or(1, |l| l.send.ssrc())
    }

    /// The REMB of the cap about every media stream received (signalled ones before any
    /// arrived), or `None` without a cap or a stream.
    fn remb(&self) -> Option<Rtcp> {
        let cap = self.fwd.remb_cap?;
        let mut ssrcs: Vec<u32> = self
            .recv
            .keys()
            .copied()
            .filter(|s| self.routes.get(s).is_none_or(|r| r.repairs.is_none()))
            .collect();
        if ssrcs.is_empty() {
            for l in self.media.iter().filter(|l| !l.stopped) {
                ssrcs.extend(
                    l.remote_ssrcs
                        .iter()
                        .filter(|s| !l.remote_rtx.contains_key(s) && !l.remote_fec.contains_key(s)),
                );
            }
        }
        if ssrcs.is_empty() {
            return None;
        }
        ssrcs.sort_unstable();
        ssrcs.dedup();
        ssrcs.truncate(255);
        Some(Rtcp::Remb {
            sender_ssrc: self.remb_sender(),
            bitrate: cap,
            ssrcs,
        })
    }

    /// The periodic REMB joins the first compound of the reports.
    pub(super) fn add_remb(&self, compounds: &mut Vec<Vec<Rtcp>>) {
        let Some(remb) = self.remb() else { return };
        match compounds.first_mut() {
            Some(c) => c.push(remb),
            None => compounds.push(vec![
                Rtcp::ReceiverReport {
                    ssrc: self.remb_sender(),
                    reports: Vec::new(),
                },
                remb,
            ]),
        }
    }

    /// The ICE state became `s`: consent lost starts the wait for `Failed`, consent back
    /// ends it.
    pub(super) fn consent_state(&mut self, now: Instant, s: IceConnectionState) {
        match s {
            IceConnectionState::Disconnected => {
                if let Some((d, f)) = self.cfg.ice_timeouts {
                    if let Some(more) = f.checked_sub(d).filter(|m| !m.is_zero()) {
                        self.fwd.fail_at = Some(now + more);
                    }
                }
            }
            IceConnectionState::Failed => {}
            _ => self.fwd.fail_at = None,
        }
    }

    /// Reports `Failed` once consent stayed lost for the failed timeout.
    pub(super) fn consent_failed(&mut self, now: Instant) {
        if self.fwd.fail_at.is_some_and(|t| t <= now) {
            self.fwd.fail_at = None;
            self.ice_state = IceConnectionState::Failed;
            self.events
                .push_back(RtcEvent::IceState(IceConnectionState::Failed));
        }
    }

    /// Whether loss of consent is followed by `Failed` (then the peer closes at `Failed`, not
    /// at `Disconnected`).
    pub(crate) fn fails_after_disconnect(&self) -> bool {
        self.cfg.ice_timeouts.is_some_and(|(d, f)| f > d)
    }
}
