//! One TCP connection (RFC 9293): the state machine, send and receive buffers, retransmission
//! (RFC 6298 timer, fast retransmit / recovery with SACK, RFC 2018 / RFC 6675, or NewReno,
//! RFC 6582, without it), congestion control (`cc`), window scaling and timestamps with PAWS
//! (RFC 7323), delayed ACKs, zero-window probing, keepalive and TIME-WAIT; optionally ECN
//! (RFC 3168: ECT(0) on new data, ECE / CWR) and pacing (a rate of `gain * cwnd / srtt`,
//! timer driven). Connections run over IPv4 or IPv6 (the MSS accounts for the larger header).
//!
//! A `Tcb` never touches the network itself: segments go out through [`SegOut`], and what the
//! application should learn is left in [`Notes`] for the interface to turn into events.

use std::{
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    time::{Duration, Instant},
};

use super::{
    buf::{Assembler, Ring},
    cc::{Cc, CcKind, MAX_RTO, Rtt},
    wire::{ACK, CWR, ECE, ECN_CE, ECN_MASK, FIN, MAX_SACK, PSH, RST, SYN, Tcp, TcpOpts, TcpOut},
};

// ---- sequence arithmetic --------------------------------------------------------------------

pub(crate) fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
pub(crate) fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}
pub(crate) fn seq_gt(a: u32, b: u32) -> bool {
    seq_lt(b, a)
}
pub(crate) fn seq_ge(a: u32, b: u32) -> bool {
    seq_le(b, a)
}
fn seq_max(a: u32, b: u32) -> u32 {
    if seq_gt(a, b) { a } else { b }
}
fn seq_min(a: u32, b: u32) -> u32 {
    if seq_lt(a, b) { a } else { b }
}

// ---- tunables -------------------------------------------------------------------------------

/// Delayed-ACK timeout (Linux's minimum; RFC 9293 allows up to 500 ms).
pub(crate) const DELACK: Duration = Duration::from_millis(40);
/// Segments acknowledged immediately at the start of a connection (Linux "quickack").
const QUICKACKS: u8 = 16;
/// Retransmissions of a SYN or SYN-ACK before giving up.
const SYN_RETRIES: u32 = 6;
/// Retransmissions of data before the connection is aborted (about 15 minutes with backoff).
const DATA_RETRIES: u32 = 15;
/// Orphaned connections (closed by the application) in FIN-WAIT-2 wait this long for the
/// peer's FIN (Linux `tcp_fin_timeout`).
const FIN_WAIT2_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest an orphaned connection may take to finish its closing exchange (then it is dropped).
const ORPHAN_LINGER: Duration = Duration::from_secs(120);
/// Keepalive probes before the connection is declared dead.
const KEEPALIVE_PROBES: u32 = 9;
/// Default peer MSS when it sends none (RFC 9293 3.7.1).
const DEFAULT_MSS: u32 = 536;
/// Timestamps older than this are not checked by PAWS (RFC 7323 5.5: 24 days).
const PAWS_IDLE: Duration = Duration::from_secs(24 * 24 * 3600);
/// IPv6 header less IPv4 header: an IPv6 connection's MSS is this much smaller.
const V6_EXTRA: u16 = 20;
/// Pacing gain in slow start and in congestion avoidance (Linux `tcp_pacing_ss_ratio` /
/// `tcp_pacing_ca_ratio`), percent.
const PACE_SS: u64 = 200;
const PACE_CA: u64 = 120;
/// A paced connection may run this far ahead of its rate (and at least two segments'
/// time): the loop's timer granularity, so pacing does not idle the link between wake-ups.
const PACE_SLACK: Duration = Duration::from_micros(100);

/// Connection-wide settings, from the interface configuration.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Params {
    /// Our MSS over IPv4: IP MTU - 40 (IPv6 connections use 20 less).
    pub(crate) mss: u16,
    pub(crate) rx_buf: usize,
    pub(crate) tx_buf: usize,
    pub(crate) cc: CcKind,
    pub(crate) keepalive: Option<Duration>,
    pub(crate) time_wait: Duration,
    /// Offer / accept window scaling, timestamps, SACK.
    pub(crate) wscale: bool,
    pub(crate) timestamps: bool,
    pub(crate) sack: bool,
    /// Negotiate ECN (RFC 3168).
    pub(crate) ecn: bool,
    /// Pace transmissions.
    pub(crate) pacing: bool,
}

impl Params {
    /// Window shift needed for our receive buffer (RFC 7323 2.3: at most 14).
    fn our_wscale(&self) -> u8 {
        let mut s = 0u8;
        while s < 14 && (self.rx_buf >> s) > 0xffff {
            s += 1;
        }
        s
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

/// Why a connection ended abnormally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TcpError {
    Refused,
    Reset,
    TimedOut,
    /// ICMP destination unreachable (host / network / protocol / port) during the handshake.
    Unreachable,
}

/// An ICMP / ICMPv6 error about one of the connection's segments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IcmpError {
    /// Destination unreachable (hard during the handshake, soft afterwards).
    Unreachable,
    /// Fragmentation needed / packet too big, with the next-hop MTU.
    TooBig(u32),
}

/// What happened to a connection since the interface last looked (bit set).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Notes(u8);

impl Notes {
    pub(crate) const READABLE: u8 = 1;
    pub(crate) const WRITABLE: u8 = 2;
    pub(crate) const ESTABLISHED: u8 = 4;
    pub(crate) const CLOSED: u8 = 8;

    pub(crate) fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }
    pub(crate) fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Where a connection's segments go: the interface wraps them in IP and Ethernet.
pub(crate) trait SegOut {
    /// Sends one segment between `ep`; `payload` is the concatenation of the two slices.
    fn segment(&mut self, ep: &Endpoints, hdr: &TcpOut, payload: (&[u8], &[u8]));
}

/// The clock a connection runs on.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Clock {
    pub(crate) now: Instant,
    /// Timestamp clock (TSval), milliseconds.
    pub(crate) ts: u32,
}

/// The negotiated part of a SYN, also recovered from a SYN cookie.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SynOpts {
    pub(crate) mss: Option<u16>,
    pub(crate) wscale: Option<u8>,
    pub(crate) sack: bool,
    /// The peer's TSval (timestamps were offered).
    pub(crate) ts: Option<u32>,
}

impl SynOpts {
    pub(crate) fn of(o: &TcpOpts) -> SynOpts {
        SynOpts {
            mss: o.mss,
            wscale: o.wscale,
            sack: o.sack_perm,
            ts: o.ts.map(|t| t.0),
        }
    }
}

/// A connection's (local, remote) addresses: IPv4 inline (16 bytes), IPv6 boxed, so the common
/// case keeps the connection as small as it was before IPv6 and segments go out through a
/// monomorphic IPv4 path.
#[derive(Debug)]
pub(crate) enum Endpoints {
    V4(SocketAddrV4, SocketAddrV4),
    V6(Box<(SocketAddrV6, SocketAddrV6)>),
}

impl Endpoints {
    #[inline]
    pub(crate) fn new(local: SocketAddr, remote: SocketAddr) -> Endpoints {
        match (local, remote) {
            (SocketAddr::V4(l), SocketAddr::V4(r)) => Endpoints::V4(l, r),
            (l, r) => {
                let v6 = |a: SocketAddr| match a {
                    SocketAddr::V6(a) => a,
                    SocketAddr::V4(a) => SocketAddrV6::new(a.ip().to_ipv6_mapped(), a.port(), 0, 0),
                };
                Endpoints::V6(Box::new((v6(l), v6(r))))
            }
        }
    }
}

/// Pacing state of a connection.
#[derive(Debug)]
struct Pace {
    /// Earliest time the next paced segment may go.
    next: Instant,
    /// Output held back by pacing: run it then.
    at: Option<Instant>,
}

/// A TCP connection.
#[derive(Debug)]
pub(crate) struct Tcb {
    pub(crate) state: State,
    addrs: Endpoints,
    /// Port of the listener that accepted it (passive open).
    pub(crate) listener: Option<u16>,
    p: Params,

    // send side
    iss: u32,
    snd_una: u32,
    /// Highest sequence number sent + 1 (new data starts here).
    snd_max: u32,
    snd_wnd: u32,
    snd_wl1: u32,
    snd_wl2: u32,
    snd_wscale: u8,
    /// Peer's MSS (bytes of payload per segment, before our options).
    peer_mss: u32,
    tx: Ring,
    /// Sequence number of `tx`'s first byte.
    tx_seq: u32,
    /// The application closed its sending side: a FIN follows the data.
    fin_queued: bool,
    /// The SYN (or SYN-ACK) must be (re)sent.
    syn_pending: bool,

    // receive side
    irs: u32,
    rcv_nxt: u32,
    rx: Ring,
    ooo: Assembler,
    /// Sequence number of an out-of-order FIN.
    ooo_fin: Option<u32>,
    rcv_wscale: u8,
    /// Right edge of the window last advertised.
    rcv_adv: u32,
    fin_received: bool,

    // options
    ts_ok: bool,
    ts_recent: u32,
    ts_recent_at: Instant,
    sack_ok: bool,
    wscale_ok: bool,
    /// ECN negotiated (RFC 3168 6.1.1).
    ecn_ok: bool,
    /// Receiver: a CE mark arrived; ECE on every ACK until the sender's CWR.
    ece_pending: bool,
    /// Sender: reduced the window for an ECE; CWR on the next new data segment.
    cwr_pending: bool,
    /// Sender: no further ECE reduction until `snd_una` passes this (once per window).
    ecn_recover: u32,

    // loss recovery
    /// Sacked ranges above `snd_una`, sorted, disjoint.
    sacked: Vec<(u32, u32)>,
    sacked_bytes: u32,
    dupacks: u32,
    /// In fast recovery until `snd_una` passes `recover`.
    in_recovery: bool,
    /// After an RTO: retransmitting everything up to `recover`.
    in_rto_recovery: bool,
    recover: u32,
    /// Next byte to retransmit (cursor), and the end of the range presumed lost.
    rxt_next: u32,
    lost_end: u32,
    /// Retransmit at the cursor once regardless of cwnd (fast retransmit).
    rxt_now: bool,
    pub(crate) cc: Cc,
    pub(crate) rtt: Rtt,
    /// Karn's algorithm without timestamps: the segment being timed and when it was sent.
    rtt_seq: Option<(u32, Instant)>,
    retries: u32,
    last_send: Instant,

    // acknowledgment
    ack_now: bool,
    unacked_segs: u8,
    quickacks: u8,

    /// Pacing state, when pacing is on (boxed: most connections do not pace, and the
    /// connection's hot fields stay in fewer cache lines).
    pace: Option<Box<Pace>>,

    // timers
    rto_at: Option<Instant>,
    delack_at: Option<Instant>,
    persist_at: Option<Instant>,
    persist_backoff: u32,
    keepalive_at: Option<Instant>,
    keepalive_probes: u32,
    /// TIME-WAIT expiry, or the FIN-WAIT-2 timeout of an orphan.
    close_at: Option<Instant>,
    /// Earliest heap entry scheduled for this connection (see `timer`).
    pub(crate) scheduled: Option<Instant>,

    // application
    /// The application released the connection (closed or aborted it): no more notes; the
    /// stack frees it once the closing exchange is over.
    pub(crate) orphan: bool,
    pub(crate) error: Option<TcpError>,
    notes: Notes,
    /// The application wanted to send more than fit: tell it when space frees up.
    want_write: bool,
}

impl Tcb {
    #[inline]
    fn new(mut p: Params, local: SocketAddr, remote: SocketAddr, iss: u32, clock: Clock) -> Tcb {
        if remote.is_ipv6() {
            p.mss = p.mss.saturating_sub(V6_EXTRA).max(64);
        }
        let mss = u32::from(p.mss);
        Tcb {
            state: State::Closed,
            addrs: Endpoints::new(local, remote),
            listener: None,
            p,
            iss,
            snd_una: iss,
            snd_max: iss,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            snd_wscale: 0,
            peer_mss: DEFAULT_MSS,
            tx: Ring::new(p.tx_buf),
            tx_seq: iss.wrapping_add(1),
            fin_queued: false,
            syn_pending: true,
            irs: 0,
            rcv_nxt: 0,
            rx: Ring::new(p.rx_buf),
            ooo: Assembler::default(),
            ooo_fin: None,
            rcv_wscale: 0,
            rcv_adv: 0,
            fin_received: false,
            ts_ok: false,
            ts_recent: 0,
            ts_recent_at: clock.now,
            sack_ok: false,
            wscale_ok: false,
            ecn_ok: false,
            ece_pending: false,
            cwr_pending: false,
            ecn_recover: iss,
            sacked: Vec::new(),
            sacked_bytes: 0,
            dupacks: 0,
            in_recovery: false,
            in_rto_recovery: false,
            recover: iss,
            rxt_next: iss,
            lost_end: iss,
            rxt_now: false,
            cc: Cc::new(p.cc, mss),
            rtt: Rtt::default(),
            rtt_seq: None,
            retries: 0,
            last_send: clock.now,
            ack_now: false,
            unacked_segs: 0,
            quickacks: QUICKACKS,
            pace: p.pacing.then(|| {
                Box::new(Pace {
                    next: clock.now,
                    at: None,
                })
            }),
            rto_at: None,
            delack_at: None,
            persist_at: None,
            persist_backoff: 0,
            keepalive_at: None,
            keepalive_probes: 0,
            close_at: None,
            scheduled: None,
            orphan: false,
            error: None,
            notes: Notes::default(),
            want_write: false,
        }
    }

    /// Active open: the SYN goes out with the next `output`.
    pub(crate) fn connect(
        p: Params,
        local: SocketAddr,
        remote: SocketAddr,
        iss: u32,
        clock: Clock,
    ) -> Tcb {
        let mut t = Tcb::new(p, local, remote, iss, clock);
        t.state = State::SynSent;
        t.rcv_wscale = if p.wscale { p.our_wscale() } else { 0 };
        t
    }

    /// Passive open from a SYN: the SYN-ACK goes out with the next `output`.
    pub(crate) fn accept(
        p: Params,
        local: SocketAddr,
        remote: SocketAddr,
        iss: u32,
        syn: &Tcp<'_>,
        clock: Clock,
    ) -> Tcb {
        let mut t = Tcb::new(p, local, remote, iss, clock);
        t.state = State::SynReceived;
        t.irs = syn.seq;
        t.rcv_nxt = syn.seq.wrapping_add(1);
        t.apply_syn_opts(SynOpts::of(&syn.opts), clock);
        // RFC 3168 6.1.1: an ECN-setup SYN carries ECE and CWR.
        t.ecn_ok = p.ecn && syn.flags & (ECE | CWR) == ECE | CWR;
        // The SYN's window is never scaled.
        t.snd_wnd = u32::from(syn.window);
        t.snd_wl1 = syn.seq;
        t.snd_wl2 = iss;
        t
    }

    /// A connection rebuilt from a valid SYN-cookie ACK: established right away.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_cookie(
        p: Params,
        local: SocketAddr,
        remote: SocketAddr,
        iss: u32,
        irs: u32,
        opts: SynOpts,
        ack: &Tcp<'_>,
        clock: Clock,
    ) -> Tcb {
        let mut t = Tcb::new(p, local, remote, iss, clock);
        t.irs = irs;
        t.rcv_nxt = irs.wrapping_add(1);
        t.apply_syn_opts(opts, clock);
        t.syn_pending = false;
        t.snd_una = iss.wrapping_add(1);
        t.snd_max = t.snd_una;
        t.recover = t.snd_una;
        t.rxt_next = t.snd_una;
        t.lost_end = t.snd_una;
        t.snd_wnd = u32::from(ack.window) << t.snd_wscale;
        t.snd_wl1 = ack.seq;
        t.snd_wl2 = ack.ack;
        t.rcv_adv = t.rcv_nxt.wrapping_add(t.rcv_window());
        t.state = State::Established;
        t.notes.0 |= Notes::ESTABLISHED;
        t.arm_keepalive(clock.now);
        t
    }

    fn apply_syn_opts(&mut self, o: SynOpts, clock: Clock) {
        if let Some(m) = o.mss {
            self.peer_mss = u32::from(m).max(64);
        }
        if self.p.wscale {
            if let Some(ws) = o.wscale {
                self.wscale_ok = true;
                self.snd_wscale = ws.min(14);
                self.rcv_wscale = self.p.our_wscale();
            } else {
                self.wscale_ok = false;
                self.snd_wscale = 0;
                self.rcv_wscale = 0;
            }
        }
        self.sack_ok = self.p.sack && o.sack;
        if self.p.timestamps {
            if let Some(v) = o.ts {
                self.ts_ok = true;
                self.ts_recent = v;
                self.ts_recent_at = clock.now;
            } else {
                self.ts_ok = false;
            }
        }
        self.cc = Cc::new(self.p.cc, self.mss());
    }

    // ---- accessors ------------------------------------------------------------------------

    #[inline]
    pub(crate) fn local(&self) -> SocketAddr {
        match &self.addrs {
            Endpoints::V4(l, _) => SocketAddr::V4(*l),
            Endpoints::V6(b) => SocketAddr::V6(b.0),
        }
    }

    #[inline]
    pub(crate) fn remote(&self) -> SocketAddr {
        match &self.addrs {
            Endpoints::V4(_, r) => SocketAddr::V4(*r),
            Endpoints::V6(b) => SocketAddr::V6(b.1),
        }
    }

    /// Payload bytes per full segment (MSS minus the timestamp option, RFC 6691).
    pub(crate) fn mss(&self) -> u32 {
        let m = self.peer_mss.min(u32::from(self.p.mss));
        if self.ts_ok { m - 12 } else { m }.max(64)
    }

    pub(crate) fn take_notes(&mut self) -> Notes {
        std::mem::take(&mut self.notes)
    }

    /// Bytes readable by the application.
    pub(crate) fn readable(&self) -> usize {
        self.rx.len()
    }

    /// The peer sent FIN and every byte before it has been read.
    pub(crate) fn eof(&self) -> bool {
        self.fin_received && self.rx.is_empty()
    }

    /// The application may still queue data.
    pub(crate) fn may_send(&self) -> bool {
        !self.fin_queued
            && matches!(
                self.state,
                State::SynSent | State::SynReceived | State::Established | State::CloseWait
            )
    }

    /// Finished: free it.
    pub(crate) fn is_dead(&self) -> bool {
        self.state == State::Closed
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> (u32, u32, bool, bool, bool) {
        (
            self.cc.cwnd,
            self.cc.ssthresh,
            self.sack_ok,
            self.ts_ok,
            self.wscale_ok,
        )
    }

    #[cfg(test)]
    pub(crate) fn snd_wnd(&self) -> u32 {
        self.snd_wnd
    }

    // ---- application calls ----------------------------------------------------------------

    /// Queues data; returns the bytes taken.
    pub(crate) fn send(&mut self, data: &[u8]) -> usize {
        if !self.may_send() {
            return 0;
        }
        let n = self.tx.push(data);
        if n < data.len() {
            self.want_write = true;
        }
        n
    }

    /// Reads in-order data; may schedule a window update.
    pub(crate) fn recv(&mut self, out: &mut [u8]) -> usize {
        let before = self.advertisable();
        let n = self.rx.read(out);
        if n > 0 {
            let after = self.advertisable();
            let edge = self.adv_edge();
            // Window update when the usable window grew substantially (RFC 9293 3.8.6.2.2).
            let mss = self.mss();
            if after > before
                && after.saturating_sub(edge) >= (2 * mss).min(self.rx.cap() as u32 / 2)
                && matches!(
                    self.state,
                    State::Established | State::FinWait1 | State::FinWait2
                )
            {
                self.ack_now = true;
            }
        }
        n
    }

    /// Orderly close of the sending side: FIN after the queued data. `orphan`: the application
    /// is done with the connection.
    pub(crate) fn close(&mut self, orphan: bool, clock: Clock) {
        self.orphan |= orphan;
        match self.state {
            State::SynSent => {
                self.state = State::Closed;
            }
            State::SynReceived | State::Established => {
                self.fin_queued = true;
                if self.state == State::Established {
                    self.state = State::FinWait1;
                }
            }
            State::CloseWait => {
                self.fin_queued = true;
                self.state = State::LastAck;
            }
            _ => {}
        }
        if self.orphan && self.state != State::TimeWait {
            let linger = if self.state == State::FinWait2 {
                FIN_WAIT2_TIMEOUT
            } else {
                ORPHAN_LINGER
            };
            self.close_at = Some(clock.now + linger);
        }
    }

    /// Abort: RST (in a synchronized state) and gone.
    pub(crate) fn abort(&mut self, out: &mut dyn SegOut) {
        self.orphan = true;
        if matches!(
            self.state,
            State::SynReceived
                | State::Established
                | State::FinWait1
                | State::FinWait2
                | State::CloseWait
        ) {
            let hdr = TcpOut {
                src_port: self.local().port(),
                dst_port: self.remote().port(),
                seq: self.snd_max,
                ack: self.rcv_nxt,
                flags: RST | ACK,
                window: 0,
                opts: TcpOpts::default(),
                ect: false,
            };
            out.segment(&self.addrs, &hdr, (&[], &[]));
        }
        self.state = State::Closed;
    }

    // ---- segment arrival (RFC 9293 3.10.7) ------------------------------------------------

    /// Processes a segment for this connection. Only RSTs go out here: the caller runs
    /// `output` afterwards (once per receive burst, which coalesces ACKs).
    pub(crate) fn on_segment(&mut self, seg: &Tcp<'_>, clock: Clock, out: &mut dyn SegOut) {
        match self.state {
            State::Closed => {}
            State::SynSent => self.on_syn_sent(seg, clock, out),
            _ => self.on_synchronized(seg, clock, out),
        }
    }

    fn reset_to(&self, seg: &Tcp<'_>, out: &mut dyn SegOut) {
        if seg.flags & RST != 0 {
            return;
        }
        let hdr = if seg.flags & ACK != 0 {
            TcpOut {
                src_port: self.local().port(),
                dst_port: self.remote().port(),
                seq: seg.ack,
                flags: RST,
                ..TcpOut::default()
            }
        } else {
            TcpOut {
                src_port: self.local().port(),
                dst_port: self.remote().port(),
                seq: 0,
                ack: seg.seq.wrapping_add(seg.seg_len()),
                flags: RST | ACK,
                ..TcpOut::default()
            }
        };
        out.segment(&self.addrs, &hdr, (&[], &[]));
    }

    fn on_syn_sent(&mut self, seg: &Tcp<'_>, clock: Clock, out: &mut dyn SegOut) {
        let f = seg.flags;
        if f & ACK != 0 && (seq_le(seg.ack, self.iss) || seq_gt(seg.ack, self.snd_max)) {
            self.reset_to(seg, out);
            return;
        }
        if f & RST != 0 {
            if f & ACK != 0 {
                self.fail(TcpError::Refused);
            }
            return;
        }
        if f & SYN == 0 {
            return;
        }
        self.irs = seg.seq;
        self.rcv_nxt = seg.seq.wrapping_add(1);
        self.apply_syn_opts(SynOpts::of(&seg.opts), clock);
        if f & ACK != 0 {
            // RFC 3168 6.1.1: an ECN-setup SYN-ACK carries ECE but not CWR.
            self.ecn_ok = self.p.ecn && f & (ECE | CWR) == ECE;
            self.snd_una = seg.ack;
            self.syn_pending = false;
            self.on_rtt_ack(seg, clock);
            self.snd_wnd = u32::from(seg.window); // SYN windows are not scaled
            self.snd_wl1 = seg.seq;
            self.snd_wl2 = seg.ack;
            self.rto_at = None;
            self.retries = 0;
            self.state = State::Established;
            self.notes.0 |= Notes::ESTABLISHED;
            self.ack_now = true;
            self.arm_keepalive(clock.now);
            // Data on the SYN-ACK (rare): accept it.
            if !seg.payload.is_empty() {
                self.on_data(seg.seq.wrapping_add(1), seg.payload, clock);
            }
            if self.fin_queued {
                self.state = State::FinWait1;
            }
        } else {
            // Simultaneous open.
            self.state = State::SynReceived;
            self.snd_wnd = u32::from(seg.window);
            self.snd_wl1 = seg.seq;
            self.syn_pending = true;
            self.snd_max = self.iss;
        }
    }

    /// RFC 9293 3.10.7.4: segment acceptability against the receive window.
    fn acceptable(&self, seg: &Tcp<'_>) -> bool {
        let len = seg.seg_len();
        let wnd = (self.rx.free() as u32).max(self.adv_edge());
        let s = seg.seq;
        let nxt = self.rcv_nxt;
        let end = nxt.wrapping_add(wnd);
        match (len, wnd) {
            (0, 0) => s == nxt,
            (0, _) => seq_le(nxt, s) && seq_lt(s, end),
            (_, 0) => false,
            _ => {
                let last = s.wrapping_add(len - 1);
                (seq_le(nxt, s) && seq_lt(s, end)) || (seq_le(nxt, last) && seq_lt(last, end))
            }
        }
    }

    fn on_synchronized(&mut self, seg: &Tcp<'_>, clock: Clock, out: &mut dyn SegOut) {
        let f = seg.flags;
        // TIME-WAIT: a retransmitted FIN is acknowledged again and restarts the timer.
        if self.state == State::TimeWait {
            if f & RST != 0 {
                return; // RFC 1337: ignore RSTs in TIME-WAIT
            }
            if f & FIN != 0 {
                self.close_at = Some(clock.now + self.p.time_wait);
            }
            self.ack_now = true;
            return;
        }
        // PAWS (RFC 7323 5.3).
        if self.ts_ok && f & RST == 0 {
            if let Some((val, _)) = seg.opts.ts {
                if seq_lt(val, self.ts_recent)
                    && clock.now.saturating_duration_since(self.ts_recent_at) < PAWS_IDLE
                {
                    self.ack_now = true;
                    return;
                }
            }
        }
        if !self.acceptable(seg) {
            if f & RST == 0 {
                self.ack_now = true;
            }
            return;
        }
        // RST (RFC 5961 3.2: only an exact match resets; otherwise a challenge ACK).
        if f & RST != 0 {
            if seg.seq != self.rcv_nxt {
                self.ack_now = true;
                return;
            }
            if self.state == State::SynReceived && self.listener.is_some() {
                // Back to LISTEN: for us, simply forget the embryonic connection.
                self.orphan = true;
                self.state = State::Closed;
                return;
            }
            self.fail(TcpError::Reset);
            return;
        }
        // SYN in a synchronized state: challenge ACK (RFC 5961 4.2).
        if f & SYN != 0 {
            if self.state == State::SynReceived && seg.seq == self.irs {
                // Retransmitted SYN: resend the SYN-ACK.
                self.syn_pending = true;
                self.snd_max = self.iss;
                return;
            }
            self.ack_now = true;
            return;
        }
        if f & ACK == 0 {
            return;
        }
        // Timestamp recording (RFC 7323 4.3): the segment covers rcv_nxt (last ACK sent).
        if self.ts_ok {
            if let Some((val, _)) = seg.opts.ts {
                if seq_le(seg.seq, self.rcv_nxt) && seq_ge(val, self.ts_recent) {
                    self.ts_recent = val;
                    self.ts_recent_at = clock.now;
                }
            }
        }
        if self.state == State::SynReceived {
            if seq_lt(self.snd_una, seg.ack) && seq_le(seg.ack, self.snd_max) {
                self.state = State::Established;
                self.syn_pending = false;
                self.snd_wnd = u32::from(seg.window) << self.snd_wscale;
                self.snd_wl1 = seg.seq;
                self.snd_wl2 = seg.ack;
                self.notes.0 |= Notes::ESTABLISHED;
                self.arm_keepalive(clock.now);
                if self.fin_queued {
                    self.state = State::FinWait1;
                }
            } else {
                self.reset_to(seg, out);
                return;
            }
        }
        if self.keepalive_at.is_some() {
            self.keepalive_probes = 0;
            self.arm_keepalive(clock.now);
        }
        if !self.on_ack(seg, clock) {
            return;
        }
        if self.state == State::Closed {
            return;
        }
        if self.ecn_ok {
            // RFC 3168 6.1.3: ECE until a CWR arrives; a CE mark (re)starts it.
            if f & CWR != 0 {
                self.ece_pending = false;
            }
            if seg.ecn & ECN_MASK == ECN_CE && !seg.payload.is_empty() {
                if !self.ece_pending {
                    self.ack_now = true; // tell the sender at once
                }
                self.ece_pending = true;
            }
        }
        // Data and FIN.
        if matches!(
            self.state,
            State::Established | State::FinWait1 | State::FinWait2
        ) {
            if !seg.payload.is_empty() {
                self.on_data(seg.seq, seg.payload, clock);
            }
            if f & FIN != 0 {
                let fin_seq = seg.seq.wrapping_add(seg.payload.len() as u32);
                self.on_fin(fin_seq, clock);
            }
        } else if f & FIN != 0 || !seg.payload.is_empty() {
            // Past the peer's FIN: retransmissions; acknowledge again.
            self.ack_now = true;
        }
    }

    /// ACK processing. Returns `false` if the segment must be dropped.
    fn on_ack(&mut self, seg: &Tcp<'_>, clock: Clock) -> bool {
        let ack = seg.ack;
        if seq_gt(ack, self.snd_max) {
            self.ack_now = true;
            return false;
        }
        let old_wnd = self.snd_wnd;
        // Window update (RFC 9293 3.10.7.4, fifth check).
        if seq_le(self.snd_una, ack)
            && (seq_lt(self.snd_wl1, seg.seq)
                || (self.snd_wl1 == seg.seq && seq_le(self.snd_wl2, ack)))
        {
            self.snd_wnd = u32::from(seg.window) << self.snd_wscale;
            self.snd_wl1 = seg.seq;
            self.snd_wl2 = ack;
            if self.snd_wnd > 0 {
                self.persist_at = None;
                self.persist_backoff = 0;
            }
        }
        if self.sack_ok && seg.opts.sack_n > 0 {
            self.update_sacks(seg.opts.sacks());
        }
        if self.ecn_ok && seg.flags & ECE != 0 {
            self.on_ece(ack);
        }
        if seq_lt(ack, self.snd_una) {
            return true; // old duplicate: ignore its ACK
        }
        let acked = ack.wrapping_sub(self.snd_una);
        if acked == 0 {
            // Duplicate ACK (RFC 5681 2): no data, no window change, outstanding data.
            let flight = self.snd_max.wrapping_sub(self.snd_una);
            if seg.payload.is_empty()
                && seg.flags & (SYN | FIN) == 0
                && self.snd_wnd == old_wnd
                && flight > 0
            {
                self.dupacks += 1;
                self.maybe_enter_recovery();
            } else if self.sack_ok && seg.opts.sack_n > 0 {
                self.maybe_enter_recovery();
            }
            return true;
        }
        // New data acknowledged.
        self.on_rtt_ack(seg, clock);
        self.retries = 0;
        let fin_seq = self.tx_seq.wrapping_add(self.tx.len() as u32);
        let data_acked = seq_min(ack, fin_seq).wrapping_sub(self.tx_seq);
        if seq_gt(seq_min(ack, fin_seq), self.tx_seq) {
            self.tx.consume(data_acked as usize);
            self.tx_seq = self.tx_seq.wrapping_add(data_acked);
            if self.want_write {
                self.want_write = false;
                self.notes.0 |= Notes::WRITABLE;
            }
        }
        let fin_acked = self.fin_queued && seq_gt(ack, fin_seq);
        self.snd_una = ack;
        self.drop_sacked_below(ack);
        // Loss recovery and congestion control.
        let mss = self.mss();
        let flight = self.snd_max.wrapping_sub(self.snd_una);
        if self.in_recovery {
            if seq_ge(ack, self.recover) {
                self.in_recovery = false;
                self.cc.on_recovered(flight, mss);
            } else {
                // Partial ACK: the next hole is lost too (RFC 6582 / RFC 6675).
                self.rxt_next = seq_max(self.rxt_next, ack);
                if !self.sack_ok {
                    self.rxt_next = ack;
                    self.lost_end = ack.wrapping_add(mss);
                    self.rxt_now = true;
                    self.dupacks = 0;
                }
            }
        } else if self.in_rto_recovery {
            self.rxt_next = seq_max(self.rxt_next, ack);
            if seq_ge(ack, self.recover) {
                self.in_rto_recovery = false;
            }
            self.cc.on_ack(acked, mss, clock.now, &self.rtt);
        } else {
            self.cc.on_ack(acked, mss, clock.now, &self.rtt);
        }
        if !self.in_recovery {
            self.dupacks = 0;
        }
        // Retransmission timer (RFC 6298 5.2 / 5.3).
        if self.snd_una == self.snd_max {
            self.rto_at = None;
        } else {
            self.rto_at = Some(clock.now + self.rtt.rto());
        }
        if fin_acked {
            match self.state {
                State::FinWait1 => {
                    self.state = State::FinWait2;
                    if self.orphan {
                        self.close_at = Some(clock.now + FIN_WAIT2_TIMEOUT);
                    }
                }
                State::Closing => self.enter_time_wait(clock),
                State::LastAck => {
                    self.state = State::Closed;
                    return false;
                }
                _ => {}
            }
        }
        true
    }

    /// ECN-Echo (RFC 3168 6.1.2): reduce the window as for a loss, at most once per window of
    /// data, without retransmitting; CWR goes out with the next new data.
    fn on_ece(&mut self, ack: u32) {
        if self.in_recovery
            || self.in_rto_recovery
            || seq_lt(seq_max(ack, self.snd_una), self.ecn_recover)
        {
            return; // already reduced for this window
        }
        let flight = self.snd_max.wrapping_sub(self.snd_una);
        self.cc.on_loss(flight, self.mss());
        self.ecn_recover = self.snd_max;
        self.cwr_pending = true;
    }

    fn on_rtt_ack(&mut self, seg: &Tcp<'_>, clock: Clock) {
        if self.ts_ok {
            if let Some((_, ecr)) = seg.opts.ts {
                if ecr != 0 {
                    let ms = clock.ts.wrapping_sub(ecr);
                    if ms < 60_000 {
                        self.rtt.sample(Duration::from_millis(u64::from(ms.max(1))));
                    }
                }
                return;
            }
        }
        if let Some((s, at)) = self.rtt_seq {
            if seq_gt(seg.ack, s) {
                self.rtt.sample(clock.now.saturating_duration_since(at));
                self.rtt_seq = None;
            }
        }
    }

    fn update_sacks(&mut self, blocks: &[(u32, u32)]) {
        for &(l, r) in blocks {
            // Valid blocks lie within (snd_una, snd_max] (D-SACKs below snd_una are ignored).
            if !(seq_lt(self.snd_una, r) && seq_lt(l, r) && seq_le(r, self.snd_max)) {
                continue;
            }
            let l = seq_max(l, self.snd_una);
            self.add_sacked(l, r);
        }
        if self.in_recovery {
            if let Some(h) = self.high_sack() {
                self.lost_end = seq_max(self.lost_end, h);
            }
        }
    }

    fn add_sacked(&mut self, l: u32, r: u32) {
        let base = self.snd_una;
        let off = |s: u32| s.wrapping_sub(base);
        let (lo, ro) = (off(l), off(r));
        let i = self.sacked.partition_point(|&(_, e)| off(e) < lo);
        let mut j = i;
        while j < self.sacked.len() && off(self.sacked[j].0) <= ro {
            j += 1;
        }
        if i == j {
            if self.sacked.len() >= 64 {
                return;
            }
            self.sacked.insert(i, (l, r));
        } else {
            let s = if off(self.sacked[i].0) < lo {
                self.sacked[i].0
            } else {
                l
            };
            let e = if off(self.sacked[j - 1].1) > ro {
                self.sacked[j - 1].1
            } else {
                r
            };
            self.sacked.drain(i + 1..j);
            self.sacked[i] = (s, e);
        }
        self.sacked_bytes = self.sacked.iter().map(|&(a, b)| b.wrapping_sub(a)).sum();
    }

    fn drop_sacked_below(&mut self, una: u32) {
        if self.sacked.is_empty() {
            return;
        }
        self.sacked.retain_mut(|r| {
            if seq_le(r.1, una) {
                return false;
            }
            if seq_lt(r.0, una) {
                r.0 = una;
            }
            true
        });
        self.sacked_bytes = self.sacked.iter().map(|&(a, b)| b.wrapping_sub(a)).sum();
    }

    fn high_sack(&self) -> Option<u32> {
        self.sacked.last().map(|r| r.1)
    }

    /// Sacked bytes within `[a, b)`.
    fn sacked_between(&self, a: u32, b: u32) -> u32 {
        let mut n = 0;
        for &(l, r) in &self.sacked {
            let l = seq_max(l, a);
            let r = seq_min(r, b);
            if seq_lt(l, r) {
                n += r.wrapping_sub(l);
            }
        }
        n
    }

    /// RFC 6675 `IsLost(snd_una)` or three duplicate ACKs: fast retransmit.
    fn maybe_enter_recovery(&mut self) {
        if self.in_recovery {
            return;
        }
        let mss = self.mss();
        let lost = self.dupacks >= 3 || (self.sack_ok && self.sacked_bytes >= 3 * mss);
        if !lost {
            return;
        }
        // RFC 6582: duplicate ACKs for data sent before a retransmission timeout start no new
        // recovery.
        if self.in_rto_recovery && seq_lt(self.snd_una, self.recover) {
            return;
        }
        let flight = self.snd_max.wrapping_sub(self.snd_una);
        self.cc.on_loss(flight, mss);
        self.in_recovery = true;
        self.recover = self.snd_max;
        self.rxt_next = self.snd_una;
        self.lost_end = if self.sack_ok {
            seq_max(
                self.high_sack().unwrap_or(self.snd_una),
                self.snd_una.wrapping_add(mss),
            )
        } else {
            self.snd_una.wrapping_add(mss)
        };
        self.rxt_now = true;
        self.rtt_seq = None;
    }

    /// Bytes in the network (RFC 6675 `pipe`, with NewReno's dupack credit without SACK).
    fn pipe(&self) -> u32 {
        let flight = self.snd_max.wrapping_sub(self.snd_una);
        if !self.in_recovery && !self.in_rto_recovery {
            return flight.saturating_sub(self.sacked_bytes);
        }
        let sacked = if self.sack_ok {
            self.sacked_bytes
        } else {
            (self.dupacks * self.mss()).min(flight.saturating_sub(self.mss()))
        };
        let unrexmitted_lost = if seq_lt(self.rxt_next, self.lost_end) {
            self.lost_end.wrapping_sub(self.rxt_next)
                - self.sacked_between(self.rxt_next, self.lost_end)
        } else {
            0
        };
        flight
            .saturating_sub(sacked)
            .saturating_sub(unrexmitted_lost)
    }

    fn on_data(&mut self, seq: u32, data: &[u8], clock: Clock) {
        let _ = clock;
        // Trim what was already received and what lies beyond the buffer.
        let mut seq = seq;
        let mut data = data;
        if seq_lt(seq, self.rcv_nxt) {
            let skip = self.rcv_nxt.wrapping_sub(seq) as usize;
            if skip >= data.len() {
                self.ack_now = true; // a pure retransmission (or a keepalive probe)
                return;
            }
            data = &data[skip..];
            seq = self.rcv_nxt;
        }
        let off = seq.wrapping_sub(self.rcv_nxt) as usize;
        let room = self.rx.free();
        if off >= room {
            self.ack_now = true;
            return;
        }
        let data = &data[..data.len().min(room - off)];
        let readable_before = self.rx.len();
        if off == 0 {
            self.rx.write_at(self.rx.len(), data);
            let extra = self.ooo.advance(data.len() as u32) as usize;
            let n = data.len() + extra;
            self.rx.commit(n);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(n as u32);
            if extra > 0 {
                self.ack_now = true; // filled a hole
            }
            self.unacked_segs = self.unacked_segs.saturating_add(1);
            if self.unacked_segs >= 2 || self.quickacks > 0 {
                self.quickacks = self.quickacks.saturating_sub(1);
                self.ack_now = true;
            } else if self.delack_at.is_none() {
                self.delack_at = Some(clock.now + DELACK);
            }
            if let Some(fs) = self.ooo_fin {
                if fs == self.rcv_nxt {
                    self.ooo_fin = None;
                    self.on_fin(fs, clock);
                }
            }
        } else {
            // Out of order: buffer ahead of the readable data, acknowledge at once (SACK).
            if self.ooo.add(off as u32, (off + data.len()) as u32) {
                self.rx.write_at(self.rx.len() + off, data);
            }
            self.ack_now = true;
        }
        if self.rx.len() > readable_before {
            self.notes.0 |= Notes::READABLE;
        }
    }

    fn on_fin(&mut self, fin_seq: u32, clock: Clock) {
        if self.fin_received {
            self.ack_now = true;
            return;
        }
        if fin_seq != self.rcv_nxt {
            if seq_gt(fin_seq, self.rcv_nxt) {
                self.ooo_fin = Some(fin_seq);
            }
            self.ack_now = true;
            return;
        }
        self.fin_received = true;
        self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        self.ack_now = true;
        self.notes.0 |= Notes::READABLE;
        match self.state {
            State::Established => self.state = State::CloseWait,
            State::FinWait1 => {
                let fin_seq_ours = self.tx_seq.wrapping_add(self.tx.len() as u32);
                if self.fin_queued && seq_gt(self.snd_una, fin_seq_ours) {
                    self.enter_time_wait(clock);
                } else {
                    self.state = State::Closing;
                }
            }
            State::FinWait2 => self.enter_time_wait(clock),
            _ => {}
        }
    }

    fn enter_time_wait(&mut self, clock: Clock) {
        self.state = State::TimeWait;
        self.rto_at = None;
        self.persist_at = None;
        self.keepalive_at = None;
        self.delack_at = None;
        self.close_at = Some(clock.now + self.p.time_wait);
        // Nothing more to send or receive: give the buffers back.
        if self.rx.is_empty() {
            self.rx = Ring::new(0);
        }
        self.tx = Ring::new(0);
        self.tx_seq = self.snd_max;
        self.sacked = Vec::new();
        self.ooo.clear();
    }

    fn fail(&mut self, e: TcpError) {
        self.error = Some(e);
        self.state = State::Closed;
        self.notes.0 |= Notes::CLOSED;
    }

    /// ICMP / ICMPv6 error for this connection (RFC 1122 4.2.3.9 / RFC 5927 / RFC 4443):
    /// destination unreachable is fatal during the handshake, ignored afterwards (soft error).
    /// Fragmentation needed / packet too big lowers the MSS (path MTU discovery, RFC 1191 /
    /// RFC 8201).
    pub(crate) fn on_icmp_error(&mut self, err: IcmpError, seq: u32) {
        if !(seq_le(self.snd_una, seq) && seq_lt(seq, self.snd_max.wrapping_add(1))) {
            return; // RFC 5927 4.1: must quote a segment in flight
        }
        if let IcmpError::TooBig(mtu) = err {
            let (hdr, min) = if self.remote().is_ipv6() {
                (60, 1280)
            } else {
                (40, 576)
            };
            if (min..=u32::from(self.p.mss) + hdr).contains(&mtu) {
                self.peer_mss = self.peer_mss.min(mtu - hdr);
                self.rxt_next = self.snd_una;
                self.lost_end = self.snd_max;
                self.rxt_now = true;
            }
            return;
        }
        if matches!(self.state, State::SynSent | State::SynReceived) {
            self.fail(TcpError::Unreachable);
        }
    }

    // ---- timers ---------------------------------------------------------------------------

    /// The earliest timer of this connection.
    pub(crate) fn next_timer(&self) -> Option<Instant> {
        fn min(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
            match (a, b) {
                (Some(x), Some(y)) => Some(x.min(y)),
                (x, None) => x,
                (None, y) => y,
            }
        }
        let t = min(
            min(self.rto_at, self.delack_at),
            min(min(self.persist_at, self.keepalive_at), self.close_at),
        );
        match &self.pace {
            None => t,
            Some(p) => min(t, p.at),
        }
    }

    fn arm_keepalive(&mut self, now: Instant) {
        if let Some(k) = self.p.keepalive {
            self.keepalive_at = Some(now + k);
        }
    }

    /// Runs the timers due at `clock.now`, then sends what they call for.
    pub(crate) fn on_timer(&mut self, clock: Clock, out: &mut dyn SegOut) {
        let now = clock.now;
        if self.close_at.is_some_and(|t| now >= t) {
            self.close_at = None;
            if self.orphan || matches!(self.state, State::TimeWait | State::FinWait2) {
                self.state = State::Closed;
                return;
            }
        }
        if self.delack_at.is_some_and(|t| now >= t) {
            self.delack_at = None;
            self.ack_now = true;
        }
        if let Some(p) = self
            .pace
            .as_mut()
            .filter(|p| p.at.is_some_and(|t| now >= t))
        {
            p.at = None; // `output` below sends what pacing held back
        }
        if self.rto_at.is_some_and(|t| now >= t) {
            self.rto_at = None;
            if !self.on_rto() {
                return;
            }
        }
        if self.persist_at.is_some_and(|t| now >= t) {
            self.persist_at = None;
            self.send_probe(clock, out, true);
            self.persist_backoff = (self.persist_backoff + 1).min(10);
        }
        if self.keepalive_at.is_some_and(|t| now >= t) {
            self.keepalive_at = None;
            if self.state == State::Established && self.snd_una == self.snd_max {
                if self.keepalive_probes >= KEEPALIVE_PROBES {
                    self.fail(TcpError::TimedOut);
                    return;
                }
                self.keepalive_probes += 1;
                self.send_probe(clock, out, false);
                let k = self.p.keepalive.unwrap_or(Duration::from_secs(75));
                self.keepalive_at = Some(now + k.min(Duration::from_secs(75)));
            } else {
                self.arm_keepalive(now);
            }
        }
        if self.state != State::Closed {
            self.output(clock, out);
        }
    }

    /// Retransmission timeout. Returns `false` if the connection was given up.
    fn on_rto(&mut self) -> bool {
        self.retries += 1;
        let limit = if matches!(self.state, State::SynSent | State::SynReceived) {
            SYN_RETRIES
        } else {
            DATA_RETRIES
        };
        if self.retries > limit {
            self.fail(TcpError::TimedOut);
            return false;
        }
        let mss = self.mss();
        if self.syn_pending || matches!(self.state, State::SynSent | State::SynReceived) {
            self.syn_pending = true;
            self.snd_max = self.iss;
        } else {
            let flight = self.snd_max.wrapping_sub(self.snd_una);
            if self.retries == 1 {
                self.cc.on_rto(flight, mss);
            } else {
                self.cc.cwnd = mss;
            }
            self.in_recovery = false;
            self.in_rto_recovery = true;
            self.recover = self.snd_max;
            self.rxt_next = self.snd_una;
            self.lost_end = self.snd_max;
            self.dupacks = 0;
            self.rxt_now = true;
        }
        self.rtt_seq = None;
        // The backed-off timer is armed when the retransmission goes out.
        true
    }

    fn backed_off_rto(&self) -> Duration {
        let shift = self.retries.min(10);
        (self.rtt.rto() * (1u32 << shift)).min(MAX_RTO)
    }

    /// A zero-window probe (`window`) or keepalive probe: one old byte (keepalive) or the next
    /// byte beyond the window (probe).
    fn send_probe(&mut self, clock: Clock, out: &mut dyn SegOut, window: bool) {
        if window {
            let avail = self.tx_seq.wrapping_add(self.tx.len() as u32);
            if seq_lt(self.snd_max, avail) && self.snd_max == self.snd_una {
                let off = self.snd_max.wrapping_sub(self.tx_seq) as usize;
                let seq = self.snd_max;
                self.emit(seq, off, 1, false, false, clock, out);
                self.snd_max = self.snd_max.wrapping_add(1);
                if self.rto_at.is_none() {
                    self.rto_at = Some(clock.now + self.backed_off_rto());
                }
            } else if self.tx_pending() > 0 {
                self.ack_now = true;
            }
            if self.snd_wnd == 0 && self.tx_pending() > 0 {
                self.arm_persist(clock.now);
            }
        } else {
            let hdr = self.header(self.snd_una.wrapping_sub(1), ACK, clock, false);
            out.segment(&self.addrs, &hdr, (&[], &[]));
        }
    }

    fn arm_persist(&mut self, now: Instant) {
        if self.persist_at.is_none() {
            let d = (self.rtt.rto() * (1u32 << self.persist_backoff.min(6))).min(MAX_RTO);
            self.persist_at = Some(now + d);
        }
    }

    /// Unsent bytes (data not yet sent once).
    fn tx_pending(&self) -> u32 {
        let end = self.tx_seq.wrapping_add(self.tx.len() as u32);
        if seq_lt(self.snd_max, end) {
            end.wrapping_sub(self.snd_max)
        } else {
            0
        }
    }

    // ---- output ---------------------------------------------------------------------------

    /// Our receive window (bytes), with receiver-side silly window avoidance (RFC 9293
    /// 3.8.6.2.2) and never shrinking the right edge already advertised.
    fn rcv_window(&self) -> u32 {
        let free = self.rx.free() as u32;
        let mss = self.mss();
        let w = if free < mss.min(self.rx.cap() as u32 / 2) {
            0
        } else {
            free
        };
        w.max(self.adv_edge())
    }

    /// What is left of the window last advertised.
    fn adv_edge(&self) -> u32 {
        if seq_gt(self.rcv_adv, self.rcv_nxt) {
            self.rcv_adv.wrapping_sub(self.rcv_nxt)
        } else {
            0
        }
    }

    /// The window the next ACK would carry, unscaled bytes (for update decisions).
    fn advertisable(&self) -> u32 {
        let free = self.rx.free() as u32;
        let mss = self.mss();
        if free < mss.min(self.rx.cap() as u32 / 2) {
            0
        } else {
            free
        }
    }

    fn header(&mut self, seq: u32, flags: u8, clock: Clock, sacks: bool) -> TcpOut {
        let syn = flags & SYN != 0;
        let mut opts = TcpOpts::default();
        let window = if syn {
            opts.mss = Some(self.p.mss);
            let offer = self.state == State::SynSent || self.wscale_ok;
            if self.p.wscale && offer {
                opts.wscale = Some(self.rcv_wscale);
            }
            let sack = self.p.sack && (self.state == State::SynSent || self.sack_ok);
            opts.sack_perm = sack;
            if self.p.timestamps && (self.state == State::SynSent || self.ts_ok) {
                opts.ts = Some((clock.ts, if self.ts_ok { self.ts_recent } else { 0 }));
            }
            let w = (self.rx.free() as u32).min(0xffff);
            self.rcv_adv = self.rcv_nxt.wrapping_add(w);
            w as u16
        } else {
            if self.ts_ok {
                opts.ts = Some((clock.ts, self.ts_recent));
            }
            let w = self.rcv_window();
            let scaled = (w >> self.rcv_wscale).min(0xffff);
            self.rcv_adv = self.rcv_nxt.wrapping_add(scaled << self.rcv_wscale);
            scaled as u16
        };
        if sacks && self.sack_ok && !self.ooo.is_empty() && !syn {
            let max = if self.ts_ok { 3 } else { MAX_SACK };
            let mut n = 0;
            let base = self.rcv_nxt;
            let last = self.ooo.last();
            if let Some((s, e)) = last {
                opts.sack[0] = (base.wrapping_add(s), base.wrapping_add(e));
                n = 1;
            }
            for &(s, e) in self.ooo.ranges() {
                if n >= max {
                    break;
                }
                if last.is_some_and(|(ls, le)| s <= ls && le <= e) {
                    continue;
                }
                opts.sack[n] = (base.wrapping_add(s), base.wrapping_add(e));
                n += 1;
            }
            opts.sack_n = n;
        }
        let mut flags = flags;
        if syn {
            if self.p.ecn && self.state == State::SynSent {
                flags |= ECE | CWR;
            } else if self.ecn_ok && self.state == State::SynReceived {
                flags |= ECE;
            }
        } else if self.ece_pending {
            // (Set only once ECN was negotiated; RSTs are not built here.)
            flags |= ECE;
        }
        if flags & ACK != 0 || !syn {
            self.ack_now = false;
            self.unacked_segs = 0;
            self.delack_at = None;
        }
        TcpOut {
            src_port: self.local().port(),
            dst_port: self.remote().port(),
            seq,
            ack: if flags & ACK != 0 { self.rcv_nxt } else { 0 },
            flags,
            window,
            opts,
            ect: false,
        }
    }

    /// Bytes of SACK option the next segment carries.
    fn sack_opt_len(&self) -> usize {
        if !self.sack_ok || self.ooo.is_empty() {
            return 0;
        }
        let max = if self.ts_ok { 3 } else { MAX_SACK };
        4 + 8 * self.ooo.ranges().len().min(max)
    }

    /// Sends `len` bytes of `tx` starting `off` bytes past `tx_seq` at sequence `seq` (plus
    /// FIN when `fin`). `fresh`: new data (not a retransmission or a probe), which is what
    /// ECN marks ECN-capable (RFC 3168 6.1.5) and carries CWR.
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    fn emit(
        &mut self,
        seq: u32,
        off: usize,
        len: usize,
        fin: bool,
        fresh: bool,
        clock: Clock,
        out: &mut dyn SegOut,
    ) {
        let mut flags = ACK;
        if fin {
            flags |= FIN;
        }
        if len > 0 && off + len == self.tx.len() {
            flags |= PSH;
        }
        if fresh && len > 0 && self.ecn_ok && std::mem::take(&mut self.cwr_pending) {
            flags |= CWR;
        }
        let mut hdr = self.header(seq, flags, clock, true);
        hdr.ect = fresh && len > 0 && self.ecn_ok;
        let payload = self.tx.slices(off, len);
        out.segment(&self.addrs, &hdr, payload);
        self.last_send = clock.now;
        if self.pace.is_some() {
            self.pace_sent(len, clock.now);
        }
    }

    /// The pacing rate, bytes per second: `gain * cwnd / srtt` (none before an RTT sample).
    fn pace_rate(&self) -> Option<u64> {
        let srtt = self.rtt.srtt()?.as_nanos().max(1) as u64;
        let gain = if self.cc.in_slow_start() {
            PACE_SS
        } else {
            PACE_CA
        };
        let rate = u64::from(self.cc.cwnd) * gain * 10_000_000 / srtt;
        Some(rate.max(1))
    }

    /// Time one `bytes`-byte segment takes at the pacing rate.
    fn pace_gap(&self, bytes: usize) -> Option<Duration> {
        let rate = self.pace_rate()?;
        let wire = (bytes + 54) as u64; // headers: what the link carries
        Some(Duration::from_nanos(
            wire.saturating_mul(1_000_000_000) / rate,
        ))
    }

    #[inline(never)]
    fn pace_sent(&mut self, len: usize, now: Instant) {
        if let (Some(gap), Some(p)) = (self.pace_gap(len), self.pace.as_deref()) {
            let next = p.next.max(now) + gap;
            if let Some(p) = self.pace.as_mut() {
                p.next = next;
            }
        }
    }

    /// Pacing lets a segment go now; otherwise arms the pacing timer.
    #[inline]
    fn pace_ok(&mut self, now: Instant) -> bool {
        match &self.pace {
            None => true,
            Some(p) => {
                let next = p.next;
                self.pace_wait(next, now)
            }
        }
    }

    /// The paced case of `pace_ok` (out of line: unpaced connections only test `pace`).
    #[inline(never)]
    fn pace_wait(&mut self, next: Instant, now: Instant) -> bool {
        let slack = self
            .pace_gap(self.mss() as usize)
            .map_or(PACE_SLACK, |g| (g * 2).max(PACE_SLACK));
        if next <= now + slack {
            return true;
        }
        if let Some(p) = self.pace.as_mut() {
            p.at = Some(next.checked_sub(slack).unwrap_or(now));
        }
        false
    }

    /// Sends what the connection's state calls for: SYN / SYN-ACK, retransmissions, new data
    /// within the congestion and receive windows, FIN, a pending ACK.
    pub(crate) fn output(&mut self, clock: Clock, out: &mut dyn SegOut) {
        if matches!(self.state, State::Closed) {
            return;
        }
        if self.syn_pending {
            if matches!(self.state, State::SynSent | State::SynReceived) && self.snd_max == self.iss
            {
                let flags = if self.state == State::SynSent {
                    SYN
                } else {
                    SYN | ACK
                };
                let hdr = self.header(self.iss, flags, clock, false);
                out.segment(&self.addrs, &hdr, (&[], &[]));
                self.snd_max = self.iss.wrapping_add(1);
                if self.retries == 0 && self.rtt_seq.is_none() {
                    self.rtt_seq = Some((self.iss, clock.now));
                }
                self.rto_at = Some(clock.now + self.backed_off_rto());
            }
            if self.ack_now && self.state == State::SynReceived && self.snd_max != self.iss {
                self.ack_now = false;
            }
            return;
        }
        if self.state == State::TimeWait {
            if self.ack_now {
                let hdr = self.header(self.snd_max, ACK, clock, false);
                out.segment(&self.addrs, &hdr, (&[], &[]));
            }
            return;
        }
        // Restart after idle (RFC 5681 4.1).
        if self.snd_una == self.snd_max
            && clock.now.saturating_duration_since(self.last_send) > self.rtt.rto()
            && self.tx_pending() > 0
        {
            self.cc.on_idle(self.mss());
        }
        // Payload per segment: the MSS less the SACK option the segment will carry (RFC 6691).
        let mss = (self.mss() as usize)
            .saturating_sub(self.sack_opt_len())
            .max(64);
        let data_end = self.tx_seq.wrapping_add(self.tx.len() as u32);
        let fin_can = self.fin_queued
            && matches!(
                self.state,
                State::FinWait1 | State::LastAck | State::Closing
            );
        let mut sent_any = false;
        // 1. Retransmissions.
        for _ in 0..256 {
            if !(self.in_recovery || self.in_rto_recovery || self.rxt_now) {
                break;
            }
            let pipe = self.pipe();
            if !self.rxt_now && pipe >= self.cc.cwnd {
                break;
            }
            let Some((seq, len, fin)) = self.next_rexmit(data_end, mss, fin_can) else {
                self.rxt_now = false;
                break;
            };
            if !self.pace_ok(clock.now) {
                break;
            }
            self.rxt_now = false;
            let off = seq.wrapping_sub(self.tx_seq) as usize;
            self.emit(seq, off, len, fin, false, clock, out);
            sent_any = true;
            self.rxt_next = seq.wrapping_add(len as u32 + u32::from(fin));
            if self.rto_at.is_none() || self.retries > 0 {
                self.rto_at = Some(clock.now + self.backed_off_rto());
            }
        }
        // 2. New data (and FIN) within min(cwnd, receive window).
        loop {
            let pending = self.tx_pending() as usize;
            let fin_unsent = fin_can && seq_le(self.snd_max, data_end);
            if pending == 0 && !fin_unsent {
                break;
            }
            let in_flight = if self.in_recovery || self.in_rto_recovery {
                self.pipe()
            } else {
                self.snd_max
                    .wrapping_sub(self.snd_una)
                    .saturating_sub(self.sacked_bytes)
            };
            let cwnd_room = self.cc.cwnd.saturating_sub(in_flight) as usize;
            let wnd_end = self.snd_una.wrapping_add(self.snd_wnd);
            let wnd_room = if seq_lt(self.snd_max, wnd_end) {
                wnd_end.wrapping_sub(self.snd_max) as usize
            } else {
                0
            };
            let len = pending.min(mss).min(cwnd_room).min(wnd_room);
            if pending > 0 && len == 0 {
                if wnd_room == 0 && self.snd_una == self.snd_max {
                    self.arm_persist(clock.now);
                }
                break;
            }
            // Sender-side SWS avoidance: do not send a runt into a window that is merely small
            // while data is outstanding (Nagle stays off: a short final segment goes out when
            // that is all there is).
            if len < pending.min(mss) && len < mss / 2 && self.snd_una != self.snd_max {
                break;
            }
            if !self.pace_ok(clock.now) {
                break;
            }
            let fin = fin_unsent && len == pending;
            let seq = self.snd_max;
            let off = seq.wrapping_sub(self.tx_seq) as usize;
            self.emit(seq, off, len, fin, true, clock, out);
            sent_any = true;
            if self.rtt_seq.is_none() && !self.ts_ok && len > 0 && self.retries == 0 {
                self.rtt_seq = Some((seq, clock.now));
            }
            self.snd_max = seq.wrapping_add(len as u32 + u32::from(fin));
            if !(self.in_recovery || self.in_rto_recovery) {
                self.rxt_next = self.snd_max;
                self.lost_end = self.snd_max;
            }
            if self.rto_at.is_none() {
                self.rto_at = Some(clock.now + self.backed_off_rto());
            }
            if fin {
                break;
            }
        }
        // 3. A bare ACK if one is due and nothing carried it.
        if self.ack_now && !sent_any {
            let hdr = self.header(self.snd_max, ACK, clock, true);
            out.segment(&self.addrs, &hdr, (&[], &[]));
        }
    }

    /// The next retransmission: the first unsacked byte at or after the cursor and before the
    /// end of the presumed-lost range. Returns (seq, data length, FIN).
    fn next_rexmit(&self, data_end: u32, mss: usize, fin_can: bool) -> Option<(u32, usize, bool)> {
        let mut seq = seq_max(self.rxt_next, self.snd_una);
        let limit = seq_min(self.lost_end, self.snd_max);
        // Skip sacked ranges.
        for &(l, r) in &self.sacked {
            if seq_le(l, seq) && seq_lt(seq, r) {
                seq = r;
            }
        }
        if !seq_lt(seq, limit) {
            return None;
        }
        // Up to the next sacked range, the end of the lost range and one MSS.
        let mut end = seq_min(limit, seq.wrapping_add(mss as u32));
        for &(l, _) in &self.sacked {
            if seq_lt(seq, l) && seq_lt(l, end) {
                end = l;
            }
        }
        let data_stop = seq_min(end, data_end);
        let len = if seq_lt(seq, data_stop) {
            data_stop.wrapping_sub(seq) as usize
        } else {
            0
        };
        let fin =
            fin_can && seq.wrapping_add(len as u32) == data_end && seq_lt(data_end, self.snd_max);
        if len == 0 && !fin {
            return None;
        }
        Some((seq, len, fin))
    }
}
