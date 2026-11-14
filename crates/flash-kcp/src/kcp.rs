//! KCP itself, without I/O: the segments and the ARQ of github.com/skywind3000/kcp (and of
//! kcp-go), flushed when something is due rather than on a fixed interval.

/// Size of a segment header: conv(4) cmd(1) frg(1) wnd(2) ts(4) sn(4) una(4) len(4).
pub const OVERHEAD: usize = 24;

const CMD_PUSH: u8 = 81;
const CMD_ACK: u8 = 82;
const CMD_WASK: u8 = 83;
const CMD_WINS: u8 = 84;
const ASK_SEND: u32 = 1;
const ASK_TELL: u32 = 2;
const RTO_NODELAY: u32 = 30;
const RTO_MIN: u32 = 100;
const RTO_DEFAULT: u32 = 200;
const RTO_MAX: u32 = 60_000;
/// Default send/receive windows, in segments.
pub const DEFAULT_WINDOW: u32 = 128;
/// Default MTU (KCP header included, framing excluded).
pub const DEFAULT_MTU: u32 = 1400;
const DEFAULT_INTERVAL: u32 = 100;
const DEFAULT_DEAD_LINK: u32 = 20;
const THRESH_INIT: u32 = 2;
const THRESH_MIN: u32 = 2;
const PROBE_INIT: u32 = 500;
const PROBE_LIMIT: u32 = 120_000;
const MAX_FRAGMENTS: usize = 256;

/// KCP errors.
#[derive(Debug, PartialEq, Eq)]
pub enum KcpError {
    /// A segment of another conversation.
    Conv,
    /// A malformed segment.
    Malformed,
    /// A message needing more than 255 fragments.
    TooBig,
    /// An empty message.
    Empty,
    /// The session is closed.
    Closed,
    /// The session's write queue is full.
    Full,
}

impl std::fmt::Display for KcpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            KcpError::Conv => "kcp: segment of another conversation",
            KcpError::Malformed => "kcp: malformed segment",
            KcpError::TooBig => "kcp: message too big",
            KcpError::Empty => "kcp: empty message",
            KcpError::Closed => "kcp: session closed",
            KcpError::Full => "kcp: write queue full",
        })
    }
}

impl std::error::Error for KcpError {}

#[derive(Clone, Default)]
struct Segment {
    frg: u8,
    ts: u32,
    sn: u32,
    resendts: u32,
    rto: u32,
    fastack: u32,
    xmit: u32,
    acked: bool,
    data: Vec<u8>,
}

fn diff(later: u32, earlier: u32) -> i32 {
    later.wrapping_sub(earlier) as i32
}

/// One conversation.
pub struct Kcp {
    conv: u32,
    mtu: u32,
    mss: u32,
    dead: bool,
    snd_una: u32,
    snd_nxt: u32,
    rcv_nxt: u32,
    ssthresh: u32,
    rx_rttvar: i32,
    rx_srtt: i32,
    rx_rto: u32,
    rx_minrto: u32,
    snd_wnd: u32,
    rcv_wnd: u32,
    rmt_wnd: u32,
    cwnd: u32,
    incr: u32,
    probe: u32,
    interval: u32,
    nodelay: i32,
    ts_probe: u32,
    probe_wait: u32,
    dead_link: u32,
    fastresend: i32,
    fastlimit: i32,
    nocwnd: bool,
    stream: bool,
    snd_queue: std::collections::VecDeque<Segment>,
    rcv_queue: std::collections::VecDeque<Segment>,
    snd_buf: std::collections::VecDeque<Segment>,
    rcv_buf: std::collections::VecDeque<Segment>,
    acklist: Vec<(u32, u32)>,
    buffer: Vec<u8>,
    /// Segments sent, retransmitted, fast-retransmitted; loss events.
    pub stats: [u64; 4],
}

impl std::fmt::Debug for Kcp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kcp").finish_non_exhaustive()
    }
}

impl Kcp {
    /// Conversation `conv`.
    pub fn new(conv: u32) -> Kcp {
        Kcp {
            conv,
            mtu: DEFAULT_MTU,
            mss: DEFAULT_MTU - OVERHEAD as u32,
            dead: false,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            ssthresh: THRESH_INIT,
            rx_rttvar: 0,
            rx_srtt: 0,
            rx_rto: RTO_DEFAULT,
            rx_minrto: RTO_MIN,
            snd_wnd: DEFAULT_WINDOW,
            rcv_wnd: DEFAULT_WINDOW,
            rmt_wnd: DEFAULT_WINDOW,
            cwnd: 1,
            incr: DEFAULT_MTU - OVERHEAD as u32,
            probe: 0,
            interval: DEFAULT_INTERVAL,
            nodelay: 0,
            ts_probe: 0,
            probe_wait: 0,
            dead_link: DEFAULT_DEAD_LINK,
            fastresend: 0,
            fastlimit: 5,
            nocwnd: false,
            stream: false,
            snd_queue: Default::default(),
            rcv_queue: Default::default(),
            snd_buf: Default::default(),
            rcv_buf: Default::default(),
            acklist: Vec::new(),
            buffer: Vec::with_capacity(DEFAULT_MTU as usize),
            stats: [0; 4],
        }
    }

    /// The conversation id.
    pub fn conv(&self) -> u32 {
        self.conv
    }

    /// Largest packet output (KCP header included); `false` if out of range.
    pub fn set_mtu(&mut self, mtu: usize) -> bool {
        if mtu <= OVERHEAD || mtu > 1 << 16 {
            return false;
        }
        self.mtu = mtu as u32;
        self.mss = self.mtu - OVERHEAD as u32;
        self.incr = self.incr.max(self.mss);
        true
    }

    /// The reference implementation's speed knobs (kcptun "fast3" is `(1, 10, 2, true)`).
    pub fn nodelay(&mut self, nodelay: i32, interval: i32, resend: i32, nc: bool) {
        if nodelay >= 0 {
            self.nodelay = nodelay;
            self.rx_minrto = if nodelay != 0 { RTO_NODELAY } else { RTO_MIN };
        }
        if interval > 0 {
            self.interval = interval.clamp(10, 5000) as u32;
        }
        if resend >= 0 {
            self.fastresend = resend;
        }
        self.nocwnd = nc;
    }

    /// Send and receive windows in segments (`<= 0` keeps one).
    pub fn set_window(&mut self, send: i32, recv: i32) {
        if send > 0 {
            self.snd_wnd = send as u32;
        }
        if recv > 0 {
            self.rcv_wnd = recv as u32;
        }
    }

    /// Stream mode: no message boundaries.
    pub fn set_stream(&mut self, on: bool) {
        self.stream = on;
    }

    /// Transmissions after which a segment declares the link dead.
    pub fn set_dead_link(&mut self, n: u32) {
        if n > 0 {
            self.dead_link = n;
        }
    }

    /// Whether a segment hit the dead-link limit.
    pub fn is_dead(&self) -> bool {
        self.dead
    }

    /// Segments queued or in flight.
    pub fn wait_send(&self) -> usize {
        self.snd_buf.len() + self.snd_queue.len()
    }

    /// Size of the next complete message, if there is one.
    pub fn peek_size(&self) -> Option<usize> {
        let first = self.rcv_queue.front()?;
        if first.frg == 0 {
            return Some(first.data.len());
        }
        if self.rcv_queue.len() < first.frg as usize + 1 {
            return None;
        }
        let mut n = 0;
        for s in &self.rcv_queue {
            n += s.data.len();
            if s.frg == 0 {
                break;
            }
        }
        Some(n)
    }

    /// The next complete message.
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        let size = self.peek_size()?;
        let reopen = self.rcv_queue.len() as u32 >= self.rcv_wnd;
        let mut out = Vec::with_capacity(size);
        while let Some(s) = self.rcv_queue.pop_front() {
            out.extend_from_slice(&s.data);
            if s.frg == 0 {
                break;
            }
        }
        self.move_recv();
        if reopen && (self.rcv_queue.len() as u32) < self.rcv_wnd {
            self.probe |= ASK_TELL;
        }
        Some(out)
    }

    fn move_recv(&mut self) {
        while let Some(s) = self.rcv_buf.front() {
            if s.sn != self.rcv_nxt || self.rcv_queue.len() as u32 >= self.rcv_wnd {
                break;
            }
            let s = self.rcv_buf.pop_front().expect("front");
            self.rcv_queue.push_back(s);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        }
    }

    /// Queues a message (split into segments of MSS bytes).
    pub fn send(&mut self, mut b: &[u8]) -> Result<(), KcpError> {
        if b.is_empty() {
            return Err(KcpError::Empty);
        }
        let mss = self.mss as usize;
        if self.stream {
            if let Some(last) = self.snd_queue.back_mut() {
                let room = mss.saturating_sub(last.data.len());
                if room > 0 {
                    let take = room.min(b.len());
                    last.data.extend_from_slice(&b[..take]);
                    last.frg = 0;
                    b = &b[take..];
                }
            }
            if b.is_empty() {
                return Ok(());
            }
        }
        let count = b.len().div_ceil(mss);
        if !self.stream && count >= MAX_FRAGMENTS {
            return Err(KcpError::TooBig);
        }
        for i in 0..count {
            let size = b.len().min(mss);
            self.snd_queue.push_back(Segment {
                frg: if self.stream {
                    0
                } else {
                    (count - i - 1) as u8
                },
                data: b[..size].to_vec(),
                ..Segment::default()
            });
            b = &b[size..];
        }
        Ok(())
    }

    fn update_ack(&mut self, rtt: i32) {
        // The RTT comes from a timestamp the peer echoes, so it can be anything up to
        // `i32::MAX`: compute in i64 (the results stay within i32, being weighted averages).
        if self.rx_srtt == 0 {
            self.rx_srtt = rtt;
            self.rx_rttvar = rtt / 2;
        } else {
            let (rtt, srtt, var) = (
                i64::from(rtt),
                i64::from(self.rx_srtt),
                i64::from(self.rx_rttvar),
            );
            let delta = (rtt - srtt).abs();
            self.rx_rttvar = ((3 * var + delta) / 4) as i32;
            self.rx_srtt = ((7 * srtt + rtt) / 8).max(1) as i32;
        }
        let var4 = 4 * u64::from(self.rx_rttvar.unsigned_abs());
        let rto = u64::from(self.rx_srtt.unsigned_abs()) + u64::from(self.interval).max(var4);
        self.rx_rto = rto.clamp(u64::from(self.rx_minrto), u64::from(RTO_MAX)) as u32;
    }

    fn shrink_buf(&mut self) {
        while self.snd_buf.front().is_some_and(|s| s.acked) {
            self.snd_buf.pop_front();
        }
        self.snd_una = self.snd_buf.front().map_or(self.snd_nxt, |s| s.sn);
    }

    fn parse_ack(&mut self, sn: u32) {
        if diff(sn, self.snd_una) < 0 || diff(sn, self.snd_nxt) >= 0 {
            return;
        }
        let Some(first) = self.snd_buf.front() else {
            return;
        };
        let i = sn.wrapping_sub(first.sn) as usize;
        if let Some(s) = self.snd_buf.get_mut(i) {
            if s.sn == sn {
                s.acked = true;
                s.data = Vec::new();
            }
        }
    }

    fn parse_una(&mut self, una: u32) {
        while self.snd_buf.front().is_some_and(|s| diff(una, s.sn) > 0) {
            self.snd_buf.pop_front();
        }
    }

    fn parse_fastack(&mut self, sn: u32, ts: u32) {
        if diff(sn, self.snd_una) < 0 || diff(sn, self.snd_nxt) >= 0 {
            return;
        }
        for s in &mut self.snd_buf {
            if diff(sn, s.sn) < 0 {
                break;
            }
            if sn != s.sn && !s.acked && diff(ts, s.ts) >= 0 {
                s.fastack += 1;
            }
        }
    }

    fn parse_data(&mut self, seg: Segment) {
        let sn = seg.sn;
        if diff(sn, self.rcv_nxt.wrapping_add(self.rcv_wnd)) >= 0 || diff(sn, self.rcv_nxt) < 0 {
            return;
        }
        let mut i = self.rcv_buf.len();
        while i > 0 {
            let prev = self.rcv_buf[i - 1].sn;
            if prev == sn {
                return;
            }
            if diff(sn, prev) > 0 {
                break;
            }
            i -= 1;
        }
        self.rcv_buf.insert(i, seg);
        self.move_recv();
    }

    /// Reads a packet of the peer's at time `now` (ms, wrapping).
    pub fn input(&mut self, mut p: &[u8], now: u32) -> Result<(), KcpError> {
        let prev_una = self.snd_una;
        let mut ack: Option<(u32, u32)> = None;
        if p.len() < OVERHEAD {
            return Err(KcpError::Malformed);
        }
        let u32le = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        while p.len() >= OVERHEAD {
            if u32le(p) != self.conv {
                return Err(KcpError::Conv);
            }
            let cmd = p[4];
            let frg = p[5];
            let wnd = u16::from_le_bytes([p[6], p[7]]);
            let ts = u32le(&p[8..]);
            let sn = u32le(&p[12..]);
            let una = u32le(&p[16..]);
            let len = u32le(&p[20..]) as usize;
            p = &p[OVERHEAD..];
            if len > p.len() || !(CMD_PUSH..=CMD_WINS).contains(&cmd) {
                return Err(KcpError::Malformed);
            }
            self.rmt_wnd = u32::from(wnd);
            self.parse_una(una);
            self.shrink_buf();
            match cmd {
                CMD_ACK => {
                    let rtt = diff(now, ts);
                    if rtt >= 0 {
                        self.update_ack(rtt);
                    }
                    self.parse_ack(sn);
                    self.shrink_buf();
                    ack = match ack {
                        None => Some((sn, ts)),
                        Some((m, t)) if diff(sn, m) > 0 && diff(ts, t) > 0 => Some((sn, ts)),
                        a => a,
                    };
                }
                CMD_PUSH => {
                    if diff(sn, self.rcv_nxt.wrapping_add(self.rcv_wnd)) < 0 {
                        self.acklist.push((sn, ts));
                        if diff(sn, self.rcv_nxt) >= 0 {
                            self.parse_data(Segment {
                                frg,
                                ts,
                                sn,
                                data: p[..len].to_vec(),
                                ..Segment::default()
                            });
                        }
                    }
                }
                CMD_WASK => self.probe |= ASK_TELL,
                _ => {}
            }
            p = &p[len..];
        }
        if let Some((sn, ts)) = ack {
            self.parse_fastack(sn, ts);
        }
        if diff(self.snd_una, prev_una) > 0 && self.cwnd < self.rmt_wnd {
            let mss = self.mss;
            if self.cwnd < self.ssthresh {
                self.cwnd += 1;
                self.incr += mss;
            } else {
                self.incr = self.incr.max(mss);
                self.incr += mss * mss / self.incr + mss / 16;
                if (self.cwnd + 1) * mss <= self.incr {
                    self.cwnd = self.incr.div_ceil(mss);
                }
            }
            if self.cwnd > self.rmt_wnd {
                self.cwnd = self.rmt_wnd;
                self.incr = self.rmt_wnd * mss;
            }
        }
        Ok(())
    }

    fn wnd_unused(&self) -> u16 {
        let n = self.rcv_queue.len() as u32;
        if n < self.rcv_wnd {
            (self.rcv_wnd - n).min(0xffff) as u16
        } else {
            0
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn header(&mut self, cmd: u8, frg: u8, wnd: u16, ts: u32, sn: u32, una: u32, len: usize) {
        let b = &mut self.buffer;
        b.extend_from_slice(&self.conv.to_le_bytes());
        b.push(cmd);
        b.push(frg);
        b.extend_from_slice(&wnd.to_le_bytes());
        b.extend_from_slice(&ts.to_le_bytes());
        b.extend_from_slice(&sn.to_le_bytes());
        b.extend_from_slice(&una.to_le_bytes());
        b.extend_from_slice(&(len as u32).to_le_bytes());
    }

    fn room(&mut self, size: usize, out: &mut dyn FnMut(&[u8])) {
        if self.buffer.len() + size > self.mtu as usize && !self.buffer.is_empty() {
            out(&self.buffer);
            self.buffer.clear();
        }
    }

    fn cwnd_now(&self) -> u32 {
        let c = self.snd_wnd.min(self.rmt_wnd);
        if self.nocwnd { c } else { self.cwnd.min(c) }
    }

    /// Sends what is due at `now` through `out` (one packet per call).
    pub fn flush(&mut self, now: u32, out: &mut dyn FnMut(&[u8])) {
        let wnd = self.wnd_unused();
        let una = self.rcv_nxt;
        for (sn, ts) in std::mem::take(&mut self.acklist) {
            self.room(OVERHEAD, out);
            self.header(CMD_ACK, 0, wnd, ts, sn, una, 0);
        }
        if self.rmt_wnd == 0 {
            if self.probe_wait == 0 {
                self.probe_wait = PROBE_INIT;
                self.ts_probe = now.wrapping_add(self.probe_wait);
            } else if diff(now, self.ts_probe) >= 0 {
                self.probe_wait =
                    (self.probe_wait.max(PROBE_INIT) + self.probe_wait / 2).min(PROBE_LIMIT);
                self.ts_probe = now.wrapping_add(self.probe_wait);
                self.probe |= ASK_SEND;
            }
        } else {
            self.ts_probe = 0;
            self.probe_wait = 0;
        }
        if self.probe & ASK_SEND != 0 {
            self.room(OVERHEAD, out);
            self.header(CMD_WASK, 0, wnd, now, 0, una, 0);
        }
        if self.probe & ASK_TELL != 0 {
            self.room(OVERHEAD, out);
            self.header(CMD_WINS, 0, wnd, now, 0, una, 0);
        }
        self.probe = 0;
        let cwnd = self.cwnd_now();
        while !self.snd_queue.is_empty() && diff(self.snd_nxt, self.snd_una.wrapping_add(cwnd)) < 0
        {
            let mut s = self.snd_queue.pop_front().expect("non-empty");
            s.sn = self.snd_nxt;
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            self.snd_buf.push_back(s);
        }
        let resent = if self.fastresend > 0 {
            self.fastresend as u32
        } else {
            u32::MAX
        };
        let rtomin = if self.nodelay == 0 {
            self.rx_rto >> 3
        } else {
            0
        };
        let (mut change, mut lost) = (false, false);
        for i in 0..self.snd_buf.len() {
            let rx_rto = self.rx_rto;
            let (nodelay, fastlimit) = (self.nodelay, self.fastlimit);
            let s = &mut self.snd_buf[i];
            if s.acked {
                continue;
            }
            let send = if s.xmit == 0 {
                s.rto = rx_rto;
                s.resendts = now.wrapping_add(s.rto + rtomin);
                true
            } else if diff(now, s.resendts) >= 0 {
                if nodelay == 0 {
                    s.rto += s.rto.max(rx_rto);
                } else {
                    let step = if nodelay >= 2 { rx_rto } else { s.rto };
                    s.rto += step / 2;
                }
                s.resendts = now.wrapping_add(s.rto);
                lost = true;
                self.stats[1] += 1;
                true
            } else if s.fastack >= resent && (fastlimit <= 0 || s.xmit <= fastlimit as u32) {
                s.fastack = 0;
                s.resendts = now.wrapping_add(s.rto);
                change = true;
                self.stats[1] += 1;
                self.stats[2] += 1;
                true
            } else {
                false
            };
            if !send {
                continue;
            }
            s.xmit += 1;
            s.ts = now;
            let (frg, sn, xmit) = (s.frg, s.sn, s.xmit);
            let data = std::mem::take(&mut s.data);
            self.stats[0] += 1;
            self.room(OVERHEAD + data.len(), out);
            self.header(CMD_PUSH, frg, wnd, now, sn, una, data.len());
            self.buffer.extend_from_slice(&data);
            self.snd_buf[i].data = data;
            if xmit >= self.dead_link {
                self.dead = true;
            }
        }
        if !self.buffer.is_empty() {
            out(&self.buffer);
            self.buffer.clear();
        }
        if change {
            let inflight = self.snd_nxt.wrapping_sub(self.snd_una);
            self.ssthresh = (inflight / 2).max(THRESH_MIN);
            self.cwnd = self.ssthresh + resent.min(1 << 16);
            self.incr = self.cwnd * self.mss;
        }
        if lost {
            self.stats[3] += 1;
            self.ssthresh = (cwnd / 2).max(THRESH_MIN);
            self.cwnd = 1;
            self.incr = self.mss;
        }
        if self.cwnd < 1 {
            self.cwnd = 1;
            self.incr = self.mss;
        }
    }

    /// When `flush` next has something to send (`now` or earlier means now), `None` if idle.
    pub fn next_flush(&self, now: u32) -> Option<u32> {
        if !self.acklist.is_empty() || self.probe != 0 {
            return Some(now);
        }
        if !self.snd_queue.is_empty()
            && diff(self.snd_nxt, self.snd_una.wrapping_add(self.cwnd_now())) < 0
        {
            return Some(now);
        }
        let resent = if self.fastresend > 0 {
            self.fastresend as u32
        } else {
            u32::MAX
        };
        let mut at: Option<u32> = None;
        let mut earlier = |t: u32| {
            if at.is_none_or(|a| diff(t, a) < 0) {
                at = Some(t);
            }
        };
        for s in &self.snd_buf {
            if s.acked {
                continue;
            }
            if s.xmit == 0
                || (s.fastack >= resent && (self.fastlimit <= 0 || s.xmit <= self.fastlimit as u32))
            {
                return Some(now);
            }
            earlier(s.resendts);
        }
        if self.rmt_wnd == 0 && (!self.snd_queue.is_empty() || !self.snd_buf.is_empty()) {
            if self.probe_wait == 0 {
                return Some(now);
            }
            earlier(self.ts_probe);
        }
        at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression (found by fuzzing): acks echoing timestamps far in the past gave RTTs near
    /// `i32::MAX`, and the smoothing arithmetic overflowed (a panic in debug builds).
    #[test]
    fn huge_rtts_do_not_overflow() {
        let mut k = Kcp::new(1);
        k.send(b"x").unwrap();
        k.flush(0, &mut |_| {});
        for now in [i32::MAX as u32, u32::MAX / 2 + 7, 3_000_000_000, 1] {
            let mut ack = Vec::new();
            ack.extend(1u32.to_le_bytes());
            ack.extend([CMD_ACK, 0, 128, 0]);
            ack.extend(0u32.to_le_bytes()); // ts
            ack.extend(0u32.to_le_bytes()); // sn
            ack.extend(0u32.to_le_bytes()); // una
            ack.extend(0u32.to_le_bytes()); // len
            k.input(&ack, now).unwrap();
            assert!((RTO_MIN..=RTO_MAX).contains(&k.rx_rto));
        }
    }

    /// Two KCPs connected by a lossy pipe deliver everything in order.
    #[test]
    fn delivers_over_a_lossy_link() {
        let (mut a, mut b) = (Kcp::new(7), Kcp::new(7));
        a.nodelay(1, 10, 2, true);
        b.nodelay(1, 10, 2, true);
        let msgs: Vec<Vec<u8>> = (0..300)
            .map(|i| vec![(i % 251) as u8; 1 + i * 37 % 5000])
            .collect();
        for m in &msgs {
            a.send(m).unwrap();
        }
        let mut seed = 12345u32;
        let mut lossy = |p: &[u8], q: &mut Vec<Vec<u8>>| {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            if (seed >> 16) % 10 != 0 {
                q.push(p.to_vec()); // 10% loss
            }
        };
        let mut got = Vec::new();
        let mut now = 0u32;
        for _ in 0..20_000 {
            now += 5;
            let mut ab = Vec::new();
            let mut ba = Vec::new();
            a.flush(now, &mut |p| lossy(p, &mut ab));
            for p in ab {
                b.input(&p, now).unwrap();
            }
            b.flush(now, &mut |p| lossy(p, &mut ba));
            for p in ba {
                a.input(&p, now).unwrap();
            }
            while let Some(m) = b.recv() {
                got.push(m);
            }
            if got.len() == msgs.len() {
                break;
            }
        }
        assert_eq!(got.len(), msgs.len());
        assert!(got == msgs);
        assert!(a.stats[1] > 0, "loss caused retransmissions");
        assert_eq!(a.wait_send(), 0);
    }

    #[test]
    fn stream_mode_and_errors() {
        let mut a = Kcp::new(1);
        assert_eq!(a.send(&[]), Err(KcpError::Empty));
        assert_eq!(a.send(&vec![0; 1376 * 256]), Err(KcpError::TooBig));
        a.set_stream(true);
        a.send(b"ab").unwrap();
        a.send(b"cd").unwrap();
        assert_eq!(a.snd_queue.len(), 1, "stream mode coalesces");
        let mut b = Kcp::new(2);
        assert_eq!(b.input(&[0; 24], 0), Err(KcpError::Conv));
        assert_eq!(b.input(&[1, 2], 0), Err(KcpError::Malformed));
    }
}
