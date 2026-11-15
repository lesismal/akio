//! Explicit Congestion Notification (RFC 9000 section 13.4, RFC 9002 section 7.1): counting
//! the codepoints of received packets for ACK_ECN frames, marking sent packets ECT(0) while the
//! path is being validated or known to pass ECN, validating the peer's counts, and falling back
//! to unmarked packets when the path (or the peer) does not handle ECN.

/// The ECN codepoints of the IP header (RFC 3168).
pub(crate) mod cp {
    pub const NOT_ECT: u8 = 0;
    pub const ECT1: u8 = 1;
    pub const ECT0: u8 = 2;
    pub const CE: u8 = 3;
}

/// Packets marked to test a new path before marking waits for the result (RFC 9000 13.4.2:
/// "a testing period" of about ten packets).
const TESTING_PACKETS: u64 = 10;

/// Where validation of the current path stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Marking the first packets on the path.
    Testing,
    /// The testing packets are out; not marking until an acknowledgment validates them.
    Unknown,
    /// Validated: every packet is marked.
    Capable,
    /// Validation failed (or marks cannot be sent): never marking on this path again.
    Failed,
}

/// The ECN state of a connection's current path.
#[derive(Clone, Debug)]
pub(crate) struct Ecn {
    pub phase: Phase,
    /// Packets marked during the testing period.
    testing_sent: u64,
    /// Of those, declared lost.
    testing_lost: u64,
    /// Marked packets sent per packet number space.
    marked_sent: [u64; 3],
    /// The peer's ECT(0), ECT(1) and CE counts per space, as last validated.
    peer: [[u64; 3]; 3],
    /// ECT(0), ECT(1) and CE counts of the packets received per space (for ACK_ECN).
    pub rx: [[u64; 3]; 3],
}

/// What an ACK frame's ECN counts mean.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AckEcn {
    /// Nothing to act on.
    None,
    /// This many new CE marks: a congestion event (RFC 9002 section 7.1).
    Congestion(u64),
}

impl Ecn {
    /// The state of a connection that marks packets when `enabled`.
    pub fn new(enabled: bool) -> Ecn {
        Ecn {
            phase: if enabled {
                Phase::Testing
            } else {
                Phase::Failed
            },
            testing_sent: 0,
            testing_lost: 0,
            marked_sent: [0; 3],
            peer: [[0; 3]; 3],
            rx: [[0; 3]; 3],
        }
    }

    /// A new path: validation starts over (unless ECN is off). The counts go on: they are per
    /// packet number space, not per path.
    pub fn new_path(&mut self, enabled: bool) {
        let (rx, peer, marked) = (self.rx, self.peer, self.marked_sent);
        *self = Ecn::new(enabled);
        (self.rx, self.peer, self.marked_sent) = (rx, peer, marked);
    }

    /// Whether the next datagram is sent ECT(0).
    pub fn marking(&self) -> bool {
        match self.phase {
            Phase::Testing => self.testing_sent < TESTING_PACKETS,
            Phase::Capable => true,
            Phase::Unknown | Phase::Failed => false,
        }
    }

    /// A marked packet went out in space `space`.
    pub fn on_marked_sent(&mut self, space: usize) {
        self.marked_sent[space] += 1;
        if self.phase == Phase::Testing {
            self.testing_sent += 1;
            if self.testing_sent >= TESTING_PACKETS {
                self.phase = Phase::Unknown;
            }
        }
    }

    /// A probe timeout: the testing period ends early, so a path that drops marked packets
    /// (the handshake's first packets included) costs one PTO rather than ten.
    pub fn on_pto(&mut self) {
        if self.phase == Phase::Testing {
            self.phase = Phase::Unknown;
        }
    }

    /// A marked packet was declared lost. All the testing packets lost: the path may drop
    /// ECN-marked packets (RFC 9000 13.4.2), so stop marking.
    pub fn on_marked_lost(&mut self) {
        if matches!(self.phase, Phase::Testing | Phase::Unknown) {
            self.testing_lost += 1;
            // Only once the whole testing period is out.
            if self.phase == Phase::Unknown && self.testing_lost >= self.testing_sent {
                self.phase = Phase::Failed;
            }
        }
    }

    /// A packet arrived in space `space` with IP codepoint `codepoint`. Returns whether it was
    /// CE-marked (which is acknowledged at once).
    pub fn on_received(&mut self, space: usize, codepoint: u8) -> bool {
        let i = match codepoint & 3 {
            cp::ECT0 => 0,
            cp::ECT1 => 1,
            cp::CE => 2,
            _ => return false,
        };
        self.rx[space][i] += 1;
        i == 2
    }

    /// The counts to report in an ACK frame of space `space`, once any ECN-capable packet
    /// arrived in it.
    pub fn report(&self, space: usize) -> Option<[u64; 3]> {
        let c = self.rx[space];
        (c != [0; 3]).then_some(c)
    }

    /// Validates an ACK frame of space `space` that raised the largest acknowledged packet
    /// number and newly acknowledged `newly_marked` packets sent ECT(0) (RFC 9000 13.4.2.1).
    pub fn on_ack(&mut self, space: usize, newly_marked: u64, counts: Option<[u64; 3]>) -> AckEcn {
        if self.phase == Phase::Failed {
            return AckEcn::None;
        }
        let Some(c) = counts else {
            if newly_marked > 0 {
                // Marked packets acknowledged without counts: the path or the peer bleaches.
                self.phase = Phase::Failed;
            }
            return AckEcn::None;
        };
        let p = self.peer[space];
        if c[0] < p[0] || c[1] < p[1] || c[2] < p[2] {
            self.phase = Phase::Failed;
            return AckEcn::None;
        }
        let (d_ect0, d_ect1, d_ce) = (c[0] - p[0], c[1] - p[1], c[2] - p[2]);
        // Every newly acknowledged ECT(0) packet must show up as ECT(0) or CE; nothing was sent
        // ECT(1), and no more ECT(0) than was sent can be reported.
        if d_ect0 + d_ce < newly_marked || d_ect1 > 0 || c[0] > self.marked_sent[space] {
            self.phase = Phase::Failed;
            return AckEcn::None;
        }
        self.peer[space] = c;
        if newly_marked > 0 && matches!(self.phase, Phase::Testing | Phase::Unknown) {
            self.phase = Phase::Capable;
        }
        if d_ce > 0 {
            AckEcn::Congestion(d_ce)
        } else {
            AckEcn::None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_and_fallback() {
        // Testing: ten marked packets, then a wait for the verdict.
        let mut e = Ecn::new(true);
        for _ in 0..10 {
            assert!(e.marking());
            e.on_marked_sent(2);
        }
        assert!(!e.marking());
        assert_eq!(e.phase, Phase::Unknown);
        // Counts that cover what was acknowledged validate the path.
        assert_eq!(e.on_ack(2, 4, Some([4, 0, 0])), AckEcn::None);
        assert_eq!(e.phase, Phase::Capable);
        assert!(e.marking());
        // CE marks are congestion.
        e.on_marked_sent(2);
        e.on_marked_sent(2);
        assert_eq!(e.on_ack(2, 2, Some([5, 0, 1])), AckEcn::Congestion(1));
        // A count going backwards fails validation.
        assert_eq!(e.on_ack(2, 1, Some([4, 0, 1])), AckEcn::None);
        assert_eq!(e.phase, Phase::Failed);
        assert!(!e.marking());

        // Marked packets acknowledged without counts: bleached.
        let mut e = Ecn::new(true);
        e.on_marked_sent(0);
        e.on_ack(0, 1, None);
        assert_eq!(e.phase, Phase::Failed);
        // Fewer ECT(0) + CE than acknowledged marked packets: remarked or bleached.
        let mut e = Ecn::new(true);
        e.on_marked_sent(2);
        e.on_marked_sent(2);
        e.on_ack(2, 2, Some([1, 0, 0]));
        assert_eq!(e.phase, Phase::Failed);
        // ECT(1) was never sent.
        let mut e = Ecn::new(true);
        e.on_marked_sent(2);
        e.on_ack(2, 1, Some([1, 1, 0]));
        assert_eq!(e.phase, Phase::Failed);
        // More reported than sent.
        let mut e = Ecn::new(true);
        e.on_marked_sent(2);
        e.on_ack(2, 1, Some([3, 0, 0]));
        assert_eq!(e.phase, Phase::Failed);
        // Every testing packet lost: the path drops marked packets.
        let mut e = Ecn::new(true);
        for _ in 0..10 {
            e.on_marked_sent(2);
        }
        for _ in 0..10 {
            e.on_marked_lost();
        }
        assert_eq!(e.phase, Phase::Failed);
        // Some lost but others acknowledged: fine.
        let mut e = Ecn::new(true);
        for _ in 0..10 {
            e.on_marked_sent(2);
        }
        e.on_marked_lost();
        e.on_ack(2, 1, Some([1, 0, 0]));
        assert_eq!(e.phase, Phase::Capable);
        // Off: never marks; a new path keeps the receive counts.
        let mut e = Ecn::new(false);
        assert!(!e.marking());
        assert!(e.on_received(2, cp::CE));
        assert!(!e.on_received(2, cp::ECT0));
        assert!(!e.on_received(2, cp::NOT_ECT));
        assert_eq!(e.report(2), Some([1, 0, 1]));
        assert_eq!(e.report(1), None);
        e.new_path(true);
        assert_eq!(e.phase, Phase::Testing);
        assert_eq!(e.report(2), Some([1, 0, 1]));
    }
}
