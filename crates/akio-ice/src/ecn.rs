//! RFC 6679 §7.2.2: the "ice" initiation of ECN for RTP, the STUN ECN-CHECK attribute.
//!
//! - **Requester** ([`IceAgent::check_ecn`]): once a pair is selected, an extra Binding
//!   request on component 1's selected pair, sent with an ECT codepoint and carrying ECN-CHECK
//!   with V = 0. It is sent [`ECN_CHECK_SENDS`] times (the RFC recommends at least four
//!   retransmissions, since checks get lost for other reasons too) every
//!   [`ECN_CHECK_INTERVAL`] (the "parallel mode" interval Ta x k with k = 10: media flows
//!   meanwhile, unmarked), and given up [`ECN_CHECK_GIVE_UP`] after the last. A response with
//!   V = 1 ends it with the codepoint the request arrived with; V = 0 (the responder could
//!   not read it this time) asks for the next transmission at once; a response without the
//!   attribute (a responder that does not know it) or an error ends it unverified.
//!   [`IceEvent::EcnChecked`] reports the result.
//! - **Responder** ([`IceAgent::handle_receive_ecn`]): a request carrying ECN-CHECK is
//!   answered as usual, plus ECN-CHECK with V = 1 and the codepoint the request arrived with.
//!   Through [`IceAgent::handle_receive`], which does not know the codepoint, the attribute
//!   is ignored (comprehension-optional), as by an agent that cannot read ECN.

use std::time::{Duration, Instant};

use akio_turn::stun::{Class, Message, MessageBuilder};

use crate::{IceAgent, IceEvent, Transmit};

/// The ECN-CHECK attribute (RFC 6679 §10.6), comprehension-optional.
pub(crate) const ATTR_ECN_CHECK: u16 = 0x802D;
/// Transmissions of one ECN check.
pub const ECN_CHECK_SENDS: u32 = 5;
/// Between transmissions of an ECN check.
pub const ECN_CHECK_INTERVAL: Duration = Duration::from_millis(500);
/// An ECN check is given up this long after its last transmission.
pub const ECN_CHECK_GIVE_UP: Duration = Duration::from_millis(500);

/// An ECN check in flight.
#[derive(Debug)]
pub(crate) struct EcnCheck {
    tid: [u8; 12],
    key: String,
    local: std::net::SocketAddr,
    remote: std::net::SocketAddr,
    packet: Vec<u8>,
    ecn: u8,
    sends: u32,
    next: Instant,
}

/// The ECN-CHECK value: ECF in bits 2..1, V in bit 0.
fn value(ecf: u8, valid: bool) -> [u8; 4] {
    [0, 0, 0, ((ecf & 3) << 1) | u8::from(valid)]
}

/// ECN-CHECK of `m`: `Some(Some(ecf))` valid, `Some(None)` present but not valid, `None`
/// absent (or malformed).
fn parse(m: &Message<'_>) -> Option<Option<u8>> {
    let v = <[u8; 4]>::try_from(m.get(ATTR_ECN_CHECK)?).ok()?;
    Some((v[3] & 1 == 1).then_some((v[3] >> 1) & 3))
}

impl IceAgent {
    /// [`handle_receive`](Self::handle_receive) of a datagram that arrived with ECN codepoint
    /// `ecn` (the low two bits of the IP TOS / traffic class): a connectivity check carrying
    /// ECN-CHECK (RFC 6679 §7.2.2) is answered with that codepoint echoed.
    pub fn handle_receive_ecn(
        &mut self,
        now: Instant,
        source: std::net::SocketAddr,
        destination: std::net::SocketAddr,
        data: &[u8],
        ecn: u8,
    ) -> bool {
        self.rx_ecn = Some(ecn & 3);
        let r = self.handle_receive(now, source, destination, data);
        self.rx_ecn = None;
        r
    }

    /// Adds ECN-CHECK to the success response `b` to request `m` when `m` carries it and the
    /// datagram's codepoint is known.
    pub(crate) fn ecn_echo(&self, m: &Message<'_>, b: MessageBuilder) -> MessageBuilder {
        match (self.rx_ecn, m.get(ATTR_ECN_CHECK)) {
            (Some(ecn), Some(_)) => b.attr(ATTR_ECN_CHECK, &value(ecn, true)),
            _ => b,
        }
    }

    /// Starts verifying that component 1's selected pair carries ECN codepoint `ecn` (1 for
    /// ECT(1), 2 for ECT(0)), RFC 6679 §7.2.2; the result comes as [`IceEvent::EcnChecked`].
    /// `false` (nothing started) without a selected pair, remote credentials, or for a lite
    /// agent or fixed pairs (no checks are sent); a check still running is replaced.
    pub fn check_ecn(&mut self, now: Instant, ecn: u8) -> bool {
        if self.closed || self.fixed || self.config.lite || !matches!(ecn, 1 | 2) {
            return false;
        }
        let Some(sel) = self.comps.first().and_then(|c| c.selected.clone()) else {
            return false;
        };
        let Some(remote) = sel.remote_creds.as_ref() else {
            return false;
        };
        let (tid, packet, _) = self.build_request_with(
            remote,
            &sel.local_ufrag,
            sel.local_pref,
            1,
            Some(&value(0, false)),
        );
        if let Some(old) = self.ecn_check.take() {
            self.retire(old.tid);
        }
        self.ecn_check = Some(EcnCheck {
            tid,
            key: remote.pwd.clone(),
            local: sel.local,
            remote: sel.remote,
            packet,
            ecn,
            sends: 0,
            next: now,
        });
        self.ecn_tick(now);
        true
    }

    /// Whether an ECN check runs.
    pub fn ecn_checking(&self) -> bool {
        self.ecn_check.is_some()
    }

    /// Retransmits or gives up the ECN check.
    pub(crate) fn ecn_tick(&mut self, now: Instant) {
        let Some(c) = self.ecn_check.as_mut() else {
            return;
        };
        if c.next > now {
            return;
        }
        if c.sends >= ECN_CHECK_SENDS {
            self.ecn_done(None);
            return;
        }
        c.sends += 1;
        c.next = now
            + if c.sends >= ECN_CHECK_SENDS {
                ECN_CHECK_GIVE_UP
            } else {
                ECN_CHECK_INTERVAL
            };
        let t = Transmit {
            source: c.local,
            destination: c.remote,
            contents: c.packet.clone(),
        };
        self.ecn_transmits.push_back((t, c.ecn));
    }

    /// When the ECN check wants [`handle_timeout`](Self::handle_timeout).
    pub(crate) fn ecn_timeout(&self) -> Option<Instant> {
        self.ecn_check.as_ref().map(|c| c.next)
    }

    /// A response that may be the ECN check's: `true` if it was.
    pub(crate) fn ecn_response(&mut self, now: Instant, m: &Message<'_>) -> bool {
        let tid = m.transaction_id();
        let Some(c) = self.ecn_check.as_mut().filter(|c| c.tid == tid) else {
            return false;
        };
        if !m.check_integrity(c.key.as_bytes()) {
            return true;
        }
        if m.class() != Class::Success {
            self.ecn_done(None);
            return true;
        }
        match parse(m) {
            Some(Some(ecf)) => self.ecn_done(Some(ecf)),
            Some(None) if c.sends < ECN_CHECK_SENDS => {
                // The responder could not read this one's codepoint: the next one now.
                c.next = now;
                self.ecn_tick(now);
            }
            _ => self.ecn_done(None),
        }
        true
    }

    fn ecn_done(&mut self, ecn: Option<u8>) {
        if let Some(c) = self.ecn_check.take() {
            self.retire(c.tid);
            self.events.push_back(IceEvent::EcnChecked {
                local: c.local,
                remote: c.remote,
                ecn,
            });
        }
    }

    /// The next datagram to send and its ECN codepoint (0: Not-ECT): what
    /// [`poll_transmit`](Self::poll_transmit) returns, then ECN checks (RFC 6679 §7.2.2),
    /// which go out marked. A caller that marks datagrams uses this instead.
    pub fn poll_transmit_ecn(&mut self) -> Option<(Transmit, u8)> {
        self.transmits
            .pop_front()
            .map(|t| (t, 0))
            .or_else(|| self.ecn_transmits.pop_front())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Candidate, IceConfig};

    fn pair() -> (IceAgent, IceAgent, Instant) {
        let now = Instant::now();
        let mut a = IceAgent::new(IceConfig::new(false, true), now);
        let mut b = IceAgent::new(IceConfig::new(false, false), now);
        a.add_local_candidate(Candidate::host("10.0.0.1:5000".parse().unwrap()));
        b.add_local_candidate(Candidate::host("10.0.0.2:6000".parse().unwrap()));
        a.set_remote_credentials(b.local_credentials().clone());
        b.set_remote_credentials(a.local_credentials().clone());
        a.add_remote_candidate(Candidate::parse(&b.local_candidates()[0].to_sdp()).unwrap());
        b.add_remote_candidate(Candidate::parse(&a.local_candidates()[0].to_sdp()).unwrap());
        (a, b, now)
    }

    /// Runs the two agents; `path(ecn)` is what the network does to a codepoint (`None`:
    /// drops the datagram); `b_reads`: B learns codepoints. Returns A's ECN results.
    fn run(
        a: &mut IceAgent,
        b: &mut IceAgent,
        mut t: Instant,
        steps: u32,
        path: impl Fn(u8) -> Option<u8>,
        b_reads: bool,
    ) -> (Vec<Option<u8>>, Instant) {
        let mut out = Vec::new();
        for _ in 0..steps {
            while let Some((x, ecn)) = a.poll_transmit_ecn() {
                let Some(e) = path(ecn) else { continue };
                if b_reads {
                    b.handle_receive_ecn(t, x.source, x.destination, &x.contents, e);
                } else {
                    b.handle_receive(t, x.source, x.destination, &x.contents);
                }
            }
            while let Some((x, ecn)) = b.poll_transmit_ecn() {
                assert_eq!(ecn, 0);
                a.handle_receive_ecn(t, x.source, x.destination, &x.contents, 0);
            }
            while let Some(e) = a.poll_event() {
                if let IceEvent::EcnChecked { ecn, .. } = e {
                    out.push(ecn);
                }
            }
            t += Duration::from_millis(10);
            a.handle_timeout(t);
            b.handle_timeout(t);
        }
        (out, t)
    }

    #[test]
    fn ecn_check_echoes_the_codepoint() {
        let (mut a, mut b, now) = pair();
        assert!(!a.check_ecn(now, 1), "no selected pair yet");
        let (r, t) = run(&mut a, &mut b, now, 200, Some, true);
        assert!(r.is_empty() && a.selected_pair().is_some());
        assert!(a.check_ecn(t, 1));
        let (r, t) = run(&mut a, &mut b, t, 50, Some, true);
        assert_eq!(r, vec![Some(1)]);
        assert!(!a.ecn_checking());
        // Bleached on the way: the echo says so.
        assert!(a.check_ecn(t, 2));
        let (r, t) = run(&mut a, &mut b, t, 50, |_| Some(0), true);
        assert_eq!(r, vec![Some(0)]);
        // A responder that does not read ECN: no attribute, unverified.
        assert!(a.check_ecn(t, 2));
        let (r, _) = run(&mut a, &mut b, t, 50, Some, false);
        assert_eq!(r, vec![None]);
    }

    #[test]
    fn ecn_check_retransmits_then_gives_up() {
        let (mut a, mut b, now) = pair();
        let (_, t) = run(&mut a, &mut b, now, 200, Some, true);
        assert!(a.check_ecn(t, 1));
        // Marked datagrams dropped: five sends, then given up.
        let mut sends = 0;
        let mut t = t;
        let mut result = None;
        for _ in 0..400 {
            while let Some((_, ecn)) = a.poll_transmit_ecn() {
                if ecn != 0 {
                    sends += 1;
                }
            }
            while let Some(e) = a.poll_event() {
                if let IceEvent::EcnChecked { ecn, .. } = e {
                    result = Some(ecn);
                }
            }
            t += Duration::from_millis(10);
            a.handle_timeout(t);
        }
        assert_eq!((sends, result), (ECN_CHECK_SENDS, Some(None)));
        // A lost first transmission does not matter.
        assert!(a.check_ecn(t, 1));
        let first = std::cell::Cell::new(true);
        let (r, _) = run(
            &mut a,
            &mut b,
            t,
            200,
            |e| {
                if e != 0 && first.replace(false) {
                    None
                } else {
                    Some(e)
                }
            },
            true,
        );
        assert_eq!(r, vec![Some(1)]);
    }

    #[test]
    fn attribute_layout() {
        assert_eq!(value(1, true), [0, 0, 0, 0b011]);
        assert_eq!(value(2, true), [0, 0, 0, 0b101]);
        assert_eq!(value(3, false), [0, 0, 0, 0b110]);
    }
}
