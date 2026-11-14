//! uTP (BEP 29): a reliable byte stream over UDP with LEDBAT congestion control, wire
//! compatible with libutp (Transmission, libtorrent, anacrolix/torrent).
//!
//! [`Header`] is the packet codec. [`Connection`] is one connection without I/O: it takes the
//! packets read ([`Connection::on_packet`]), the bytes to send ([`Connection::write`]) and the
//! clock ([`Connection::on_tick`]), and returns packets to transmit and [`Event`]s. The
//! [`UdpPort`](crate::port::UdpPort) runs connections on a `only` UDP listener.
//!
//! The protocol follows libutp's: version 1 headers, SYN, DATA, STATE, FIN and RESET, its
//! connection-ID rule, 16-bit sequence numbers with wraparound, selective acknowledgements both
//! ways, fast retransmission on three duplicate acknowledgements or a SACK three packets past a
//! hole, retransmission timeouts from the smoothed RTT with backoff (500 ms minimum), LEDBAT
//! (100 ms target, a slow start until the first loss or delay), keepalives every 29 s and FIN.

use std::collections::{BTreeMap, VecDeque};
use std::io;

/// Packet type DATA.
pub const ST_DATA: u8 = 0;
/// Packet type FIN.
pub const ST_FIN: u8 = 1;
/// Packet type STATE (an acknowledgement).
pub const ST_STATE: u8 = 2;
/// Packet type RESET.
pub const ST_RESET: u8 = 3;
/// Packet type SYN.
pub const ST_SYN: u8 = 4;
/// Header size without extensions.
pub const HEADER_SIZE: usize = 20;
/// Payload bytes per DATA packet.
pub const PAYLOAD_SIZE: usize = 1380;

const VERSION: u8 = 1;
const EXT_SACK: u8 = 1;
const MIN_RTO_US: u64 = 500_000;
const INITIAL_RTO_US: u64 = 1_000_000;
const MAX_RTO_US: u64 = 30_000_000;
const CONNECT_TIMEOUTS: u32 = 2;
const DATA_TIMEOUTS: u32 = 7;
const TARGET_DELAY_US: f64 = 100_000.0;
const MAX_CWND_INCREASE: f64 = 3000.0;
const MIN_WINDOW: f64 = (2 * PAYLOAD_SIZE) as f64;
const MAX_WINDOW: f64 = (8 << 20) as f64;
const RECV_WINDOW: usize = 1 << 20;
const REORDER_MAX: u16 = 1024;
const MAX_OUT_PACKETS: usize = 4096;
const KEEPALIVE_US: u64 = 29_000_000;
const IDLE_TIMEOUT_US: u64 = 90_000_000;

/// Whether `b` looks like a uTP packet (version 1, a known type, a whole header): what a
/// port shared with the DHT (`d...`) and UDP tracker replies (`\0...`) sorts datagrams by.
pub fn is_utp(b: &[u8]) -> bool {
    b.len() >= HEADER_SIZE && b[0] & 0x0F == VERSION && b[0] >> 4 <= ST_SYN
}

fn seq_less(a: u16, b: u16) -> bool {
    (a.wrapping_sub(b) as i16) < 0
}

fn seq_le(a: u16, b: u16) -> bool {
    a == b || seq_less(a, b)
}

/// A parsed packet: header, selective-ACK mask (if any), payload.
pub type Parsed<'a> = (Header, Option<&'a [u8]>, &'a [u8]);

/// A packet header (big-endian on the wire).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Header {
    /// Packet type (`ST_*`).
    pub typ: u8,
    /// First extension.
    pub ext: u8,
    /// Connection ID.
    pub conn_id: u16,
    /// Sender's clock, microseconds.
    pub ts: u32,
    /// Sender's last measured one-way delay of our packets, microseconds.
    pub ts_diff: u32,
    /// Sender's advertised receive window, bytes.
    pub wnd: u32,
    /// Sequence number.
    pub seq: u16,
    /// Last sequence number received in order.
    pub ack: u16,
}

impl Header {
    /// Parses a packet: its header, its selective-ACK mask if any, and its payload.
    pub fn parse(b: &[u8]) -> Option<Parsed<'_>> {
        if !is_utp(b) {
            return None;
        }
        let u32_at = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        let h = Header {
            typ: b[0] >> 4,
            ext: b[1],
            conn_id: u16::from_be_bytes([b[2], b[3]]),
            ts: u32_at(4),
            ts_diff: u32_at(8),
            wnd: u32_at(12),
            seq: u16::from_be_bytes([b[16], b[17]]),
            ack: u16::from_be_bytes([b[18], b[19]]),
        };
        let mut p = &b[HEADER_SIZE..];
        let mut sack = None;
        let mut ext = h.ext;
        while ext != 0 {
            if p.len() < 2 || p.len() - 2 < usize::from(p[1]) {
                return None;
            }
            let (next, n) = (p[0], usize::from(p[1]));
            if ext == EXT_SACK && sack.is_none() {
                sack = Some(&p[2..2 + n]);
            }
            ext = next;
            p = &p[2 + n..];
        }
        Some((h, sack, p))
    }

    /// Writes the 20-byte header into `out`.
    pub fn encode_to(&self, out: &mut Vec<u8>) {
        out.push((self.typ << 4) | VERSION);
        out.push(self.ext);
        out.extend_from_slice(&self.conn_id.to_be_bytes());
        out.extend_from_slice(&self.ts.to_be_bytes());
        out.extend_from_slice(&self.ts_diff.to_be_bytes());
        out.extend_from_slice(&self.wnd.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.ack.to_be_bytes());
    }
}

/// A RESET answering `h` from a peer we have no connection for.
pub fn reset_for(h: &Header, now_us: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(HEADER_SIZE);
    Header {
        typ: ST_RESET,
        conn_id: h.conn_id,
        ts: now_us as u32,
        seq: crate::rand_u32() as u16,
        ack: h.seq,
        ..Header::default()
    }
    .encode_to(&mut b);
    b
}

/// What a connection reports.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// The handshake completed (dialing side).
    Connected,
    /// Bytes received in order.
    Data(Vec<u8>),
    /// The peer finished sending (FIN, after all its data).
    Eof,
    /// The connection is gone; `None` after an orderly close.
    Closed(Option<io::ErrorKind>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    SynSent,
    Connected,
    Closed,
}

#[derive(Debug)]
struct Out {
    seq: u16,
    typ: u8,
    payload: Vec<u8>,
    sent_at: u64,
    transmissions: u32,
    acked: bool,
    need_resend: bool,
}

/// One uTP connection without I/O.
#[derive(Debug)]
pub struct Connection {
    state: State,
    recv_id: u16,
    send_id: u16,
    seq_nr: u16,
    ack_nr: u16,
    out: VecDeque<Out>,
    pending: VecDeque<u8>,
    in_flight: usize,
    cwnd: f64,
    ssthresh: f64,
    peer_wnd: usize,
    srtt: u64,
    rttvar: u64,
    rto: u64,
    rto_at: Option<u64>,
    timeouts: u32,
    reorder: BTreeMap<u16, (u8, Vec<u8>)>,
    reorder_bytes: usize,
    reply_micro: u32,
    delay_min: [u32; 2],
    delay_bucket_at: u64,
    dup_acks: u32,
    loss_seq: u16,
    eof_seq: Option<u16>,
    eof_delivered: bool,
    fin_sent: bool,
    fin_acked: bool,
    closing: bool,
    last_heard: u64,
    last_sent: u64,
    unacked_recv: u32,
    ack_due: bool,
    stats: Stats,
}

/// Counters of a connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Stats {
    /// Packets sent, retransmissions included.
    pub packets_sent: u64,
    /// Packets received.
    pub packets_received: u64,
    /// Retransmissions.
    pub retransmits: u64,
    /// Retransmission timeouts.
    pub timeouts: u64,
}

impl Connection {
    fn blank(recv_id: u16, send_id: u16, now: u64) -> Connection {
        let seq = crate::rand_u32() as u16;
        Connection {
            state: State::SynSent,
            recv_id,
            send_id,
            seq_nr: seq,
            ack_nr: 0,
            out: VecDeque::new(),
            pending: VecDeque::new(),
            in_flight: 0,
            cwnd: (10 * PAYLOAD_SIZE) as f64,
            ssthresh: MAX_WINDOW,
            peer_wnd: RECV_WINDOW,
            srtt: 0,
            rttvar: 0,
            rto: INITIAL_RTO_US,
            rto_at: None,
            timeouts: 0,
            reorder: BTreeMap::new(),
            reorder_bytes: 0,
            reply_micro: 0,
            delay_min: [u32::MAX; 2],
            delay_bucket_at: now,
            dup_acks: 0,
            loss_seq: seq,
            eof_seq: None,
            eof_delivered: false,
            fin_sent: false,
            fin_acked: false,
            closing: false,
            last_heard: now,
            last_sent: now,
            unacked_recv: 0,
            ack_due: false,
            stats: Stats::default(),
        }
    }

    /// Starts a connection receiving with `recv_id`; `send` gets the SYN.
    pub fn connect(recv_id: u16, now: u64, send: &mut Vec<Vec<u8>>) -> Connection {
        let mut c = Connection::blank(recv_id, recv_id.wrapping_add(1), now);
        let seq = c.seq_nr;
        c.seq_nr = c.seq_nr.wrapping_add(1);
        c.out.push_back(Out {
            seq,
            typ: ST_SYN,
            payload: Vec::new(),
            sent_at: 0,
            transmissions: 0,
            acked: false,
            need_resend: true,
        });
        c.try_send(now, send);
        c
    }

    /// Accepts the connection a SYN starts; `send` gets the acknowledgement.
    pub fn accept(syn: &Header, now: u64, send: &mut Vec<Vec<u8>>) -> Connection {
        let mut c = Connection::blank(syn.conn_id.wrapping_add(1), syn.conn_id, now);
        c.state = State::Connected;
        c.ack_nr = syn.seq;
        c.peer_wnd = syn.wnd as usize;
        if syn.ts != 0 {
            c.reply_micro = (now as u32).wrapping_sub(syn.ts);
        }
        c.send_state(now, send);
        c
    }

    /// The ID this side receives with (the key of incoming packets).
    pub fn recv_id(&self) -> u16 {
        self.recv_id
    }

    /// The ID this side sends with.
    pub fn send_id(&self) -> u16 {
        self.send_id
    }

    /// Whether the handshake is done.
    pub fn is_connected(&self) -> bool {
        self.state == State::Connected
    }

    /// Whether the connection is gone.
    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    /// Bytes accepted by [`write`](Self::write) and not yet acknowledged.
    pub fn buffered(&self) -> usize {
        self.pending.len()
            + self
                .out
                .iter()
                .filter(|o| !o.acked)
                .map(|o| o.payload.len())
                .sum::<usize>()
    }

    /// Smoothed round-trip time, microseconds (0 before the first sample).
    pub fn rtt_us(&self) -> u64 {
        self.srtt
    }

    /// Counters.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Queues bytes to send and sends what the window allows.
    pub fn write(&mut self, data: &[u8], now: u64, send: &mut Vec<Vec<u8>>) -> io::Result<()> {
        if self.state == State::Closed || self.closing {
            return Err(io::ErrorKind::NotConnected.into());
        }
        self.pending.extend(data);
        if self.state == State::Connected {
            self.try_send(now, send);
        }
        Ok(())
    }

    /// Closes once everything queued is acknowledged (sends FIN).
    pub fn close(&mut self, now: u64, send: &mut Vec<Vec<u8>>) {
        if self.state == State::Closed {
            return;
        }
        if self.state == State::SynSent {
            self.state = State::Closed;
            return;
        }
        self.closing = true;
        self.try_send(now, send);
    }

    /// Drops the connection at once, telling the peer with a RESET.
    pub fn abort(&mut self, now: u64, send: &mut Vec<Vec<u8>>) {
        if self.state == State::Closed {
            return;
        }
        let mut b = Vec::with_capacity(HEADER_SIZE);
        self.header(ST_RESET, self.seq_nr, now).encode_to(&mut b);
        send.push(b);
        self.state = State::Closed;
    }

    fn header(&self, typ: u8, seq: u16, now: u64) -> Header {
        Header {
            typ,
            ext: 0,
            conn_id: if typ == ST_SYN {
                self.recv_id
            } else {
                self.send_id
            },
            ts: now as u32,
            ts_diff: self.reply_micro,
            wnd: RECV_WINDOW.saturating_sub(self.reorder_bytes) as u32,
            seq,
            ack: self.ack_nr,
        }
    }

    fn send_state(&mut self, now: u64, send: &mut Vec<Vec<u8>>) {
        let mut h = self.header(ST_STATE, self.seq_nr, now);
        let mut b = Vec::with_capacity(HEADER_SIZE + 6);
        // A selective ACK of the 32 packets past the first one missing.
        let mask = if self.reorder.is_empty() {
            None
        } else {
            let mut m = [0u8; 4];
            for &s in self.reorder.keys() {
                let i = s.wrapping_sub(self.ack_nr).wrapping_sub(2);
                if i < 32 {
                    m[usize::from(i / 8)] |= 1 << (i % 8);
                }
            }
            Some(m)
        };
        if mask.is_some() {
            h.ext = EXT_SACK;
        }
        h.encode_to(&mut b);
        if let Some(m) = mask {
            b.extend_from_slice(&[0, 4]);
            b.extend_from_slice(&m);
        }
        send.push(b);
        self.stats.packets_sent += 1;
        self.ack_due = false;
        self.unacked_recv = 0;
        self.last_sent = now;
    }

    fn transmit(&mut self, i: usize, now: u64, send: &mut Vec<Vec<u8>>) {
        let (typ, seq) = (self.out[i].typ, self.out[i].seq);
        let h = self.header(typ, seq, now);
        let o = &mut self.out[i];
        let mut b = Vec::with_capacity(HEADER_SIZE + o.payload.len());
        h.encode_to(&mut b);
        b.extend_from_slice(&o.payload);
        if o.transmissions > 0 {
            self.stats.retransmits += 1;
        }
        o.transmissions += 1;
        o.sent_at = now;
        o.need_resend = false;
        self.in_flight += o.payload.len();
        send.push(b);
        self.stats.packets_sent += 1;
        self.ack_due = false;
        self.unacked_recv = 0;
        self.last_sent = now;
        if self.rto_at.is_none() {
            self.rto_at = Some(now + self.rto);
        }
    }

    fn window(&self) -> usize {
        (self.cwnd as usize).min(self.peer_wnd.max(PAYLOAD_SIZE))
    }

    fn try_send(&mut self, now: u64, send: &mut Vec<Vec<u8>>) {
        if self.state == State::Closed {
            return;
        }
        // Retransmissions first, oldest first.
        for i in 0..self.out.len() {
            if self.out[i].need_resend && !self.out[i].acked {
                if self.in_flight > 0 && self.in_flight + self.out[i].payload.len() > self.window()
                {
                    return;
                }
                self.transmit(i, now, send);
            }
        }
        if self.state != State::Connected {
            return;
        }
        while !self.pending.is_empty() && self.out.len() < MAX_OUT_PACKETS {
            let n = self.pending.len().min(PAYLOAD_SIZE);
            if self.in_flight > 0 && self.in_flight + n > self.window() {
                return;
            }
            let payload: Vec<u8> = self.pending.drain(..n).collect();
            let seq = self.seq_nr;
            self.seq_nr = self.seq_nr.wrapping_add(1);
            self.out.push_back(Out {
                seq,
                typ: ST_DATA,
                payload,
                sent_at: 0,
                transmissions: 0,
                acked: false,
                need_resend: false,
            });
            let i = self.out.len() - 1;
            self.transmit(i, now, send);
        }
        if self.closing && self.pending.is_empty() && !self.fin_sent {
            self.fin_sent = true;
            let seq = self.seq_nr;
            self.seq_nr = self.seq_nr.wrapping_add(1);
            self.out.push_back(Out {
                seq,
                typ: ST_FIN,
                payload: Vec::new(),
                sent_at: 0,
                transmissions: 0,
                acked: false,
                need_resend: false,
            });
            let i = self.out.len() - 1;
            self.transmit(i, now, send);
        }
    }

    fn rtt_sample(&mut self, sample: u64) {
        if self.srtt == 0 {
            self.srtt = sample.max(1);
            self.rttvar = sample / 2;
        } else {
            let d = self.srtt.abs_diff(sample);
            self.rttvar = (3 * self.rttvar + d) / 4;
            self.srtt = (7 * self.srtt + sample) / 8;
        }
        self.rto = (self.srtt + 4 * self.rttvar).clamp(MIN_RTO_US, MAX_RTO_US);
    }

    fn on_loss(&mut self, seq: u16) {
        // At most one window cut per window of data.
        if seq_less(seq, self.loss_seq) {
            return;
        }
        self.loss_seq = self.seq_nr;
        self.cwnd = (self.cwnd / 2.0).max(MIN_WINDOW);
        self.ssthresh = self.cwnd;
    }

    fn ack_packet(&mut self, i: usize, now: u64, sample: bool) -> usize {
        let o = &mut self.out[i];
        if o.acked {
            return 0;
        }
        o.acked = true;
        let n = o.payload.len();
        let counted = o.transmissions > 0 && !o.need_resend;
        let rtt = (sample && o.transmissions == 1).then(|| now.saturating_sub(o.sent_at));
        let fin = o.typ == ST_FIN;
        if counted {
            self.in_flight = self.in_flight.saturating_sub(n);
        }
        if let Some(s) = rtt {
            self.rtt_sample(s);
        }
        if fin {
            self.fin_acked = true;
        }
        n
    }

    fn delay_base(&mut self, d: u32, now: u64) -> u32 {
        if now.saturating_sub(self.delay_bucket_at) > 60_000_000 {
            self.delay_min = [self.delay_min[1], u32::MAX];
            self.delay_bucket_at = now;
        }
        self.delay_min[1] = self.delay_min[1].min(d);
        self.delay_min[0].min(self.delay_min[1])
    }

    fn take_acks(&mut self, h: &Header, sack: Option<&[u8]>, now: u64) {
        let Some(front) = self.out.front().map(|o| o.seq) else {
            return;
        };
        let mut acked = 0usize;
        let mut progressed = false;
        // Cumulative.
        while let Some(o) = self.out.front() {
            if !seq_le(o.seq, h.ack) {
                break;
            }
            acked += self.ack_packet(0, now, true);
            self.out.pop_front();
            progressed = true;
        }
        // Selective: bit i acknowledges ack + 2 + i.
        let mut highest_sacked: Option<u16> = None;
        if let Some(mask) = sack {
            for (byte_i, &byte) in mask.iter().enumerate() {
                for bit in 0..8 {
                    if byte & (1 << bit) == 0 {
                        continue;
                    }
                    let seq = h
                        .ack
                        .wrapping_add(2)
                        .wrapping_add((byte_i * 8 + bit) as u16);
                    let base = self.out.front().map_or(seq, |o| o.seq);
                    let idx = usize::from(seq.wrapping_sub(base));
                    if idx < self.out.len() && self.out[idx].seq == seq {
                        acked += self.ack_packet(idx, now, false);
                        highest_sacked = Some(seq);
                    }
                }
            }
        }
        // Duplicate acknowledgements and SACK holes: fast retransmit of the oldest.
        if progressed {
            self.dup_acks = 0;
            self.timeouts = 0;
            let outstanding = self.out.iter().any(|o| !o.acked && o.transmissions > 0);
            self.rto_at = outstanding.then_some(now + self.rto);
        } else if h.typ == ST_STATE && h.ack == front.wrapping_sub(1) && !self.out.is_empty() {
            self.dup_acks += 1;
        }
        let sack_hole = highest_sacked.is_some_and(|hs| {
            self.out
                .front()
                .is_some_and(|o| !o.acked && hs.wrapping_sub(o.seq) >= 3)
        });
        let srtt = self.srtt.max(1_000);
        if (self.dup_acks == 3 || sack_hole)
            && self.out.front().is_some_and(|o| {
                !o.acked
                    && o.transmissions > 0
                    && !o.need_resend
                    && now.saturating_sub(o.sent_at) >= srtt
            })
        {
            self.dup_acks = 0;
            let seq = self.out[0].seq;
            self.on_loss(seq);
            let n = self.out[0].payload.len();
            self.in_flight = self.in_flight.saturating_sub(n);
            self.out[0].need_resend = true;
        }
        // Drop acknowledged packets at the front.
        while self.out.front().is_some_and(|o| o.acked) {
            self.out.pop_front();
        }
        if acked > 0 {
            let off_target = if h.ts_diff != 0 && h.ts_diff != i32::MAX as u32 {
                let base = self.delay_base(h.ts_diff, now);
                let our_delay = f64::from(h.ts_diff.wrapping_sub(base));
                ((TARGET_DELAY_US - our_delay) / TARGET_DELAY_US).clamp(-1.0, 1.0)
            } else {
                1.0
            };
            if self.cwnd < self.ssthresh && off_target > 0.5 {
                self.cwnd += acked as f64;
            } else {
                self.cwnd += MAX_CWND_INCREASE * off_target * acked as f64 / self.cwnd;
            }
            self.cwnd = self.cwnd.clamp(MIN_WINDOW, MAX_WINDOW);
        }
    }

    /// Takes a packet addressed to this connection; `send` gets what it causes, `events` what
    /// the application hears.
    pub fn on_packet(
        &mut self,
        h: &Header,
        sack: Option<&[u8]>,
        payload: &[u8],
        now: u64,
        send: &mut Vec<Vec<u8>>,
        events: &mut Vec<Event>,
    ) {
        if self.state == State::Closed {
            return;
        }
        self.stats.packets_received += 1;
        if h.typ == ST_RESET {
            self.state = State::Closed;
            events.push(Event::Closed(Some(io::ErrorKind::ConnectionReset)));
            return;
        }
        if h.typ == ST_SYN {
            // A SYN again: our acknowledgement was lost.
            self.send_state(now, send);
            return;
        }
        // An acknowledgement of something never sent: spoofed or confused.
        if seq_less(self.seq_nr.wrapping_sub(1), h.ack) {
            return;
        }
        self.last_heard = now;
        if h.ts != 0 {
            self.reply_micro = (now as u32).wrapping_sub(h.ts);
        }
        self.peer_wnd = h.wnd as usize;
        if self.state == State::SynSent {
            self.state = State::Connected;
            self.ack_nr = h.seq.wrapping_sub(1);
            events.push(Event::Connected);
        }
        self.take_acks(h, sack, now);

        if h.typ == ST_DATA || h.typ == ST_FIN {
            let rel = h.seq.wrapping_sub(self.ack_nr).wrapping_sub(1);
            if rel == 0 {
                self.deliver(h.typ, payload.to_vec(), events);
                while let Some((typ, data)) = self.reorder.remove(&self.ack_nr.wrapping_add(1)) {
                    self.reorder_bytes -= data.len();
                    self.deliver(typ, data, events);
                }
                self.unacked_recv += 1;
                if self.unacked_recv >= 2 || self.eof_delivered || !self.reorder.is_empty() {
                    self.send_state(now, send);
                } else {
                    self.ack_due = true;
                }
            } else if rel < REORDER_MAX {
                if !self.reorder.contains_key(&h.seq)
                    && self.reorder_bytes + payload.len() <= RECV_WINDOW
                    && !self.eof_seq.is_some_and(|e| seq_less(e, h.seq))
                {
                    self.reorder_bytes += payload.len();
                    self.reorder.insert(h.seq, (h.typ, payload.to_vec()));
                }
                self.send_state(now, send);
            } else {
                // Old: our acknowledgement was lost.
                self.send_state(now, send);
            }
        }
        if self.eof_delivered && self.fin_acked {
            self.state = State::Closed;
            events.push(Event::Closed(None));
            return;
        }
        self.try_send(now, send);
    }

    fn deliver(&mut self, typ: u8, data: Vec<u8>, events: &mut Vec<Event>) {
        self.ack_nr = self.ack_nr.wrapping_add(1);
        if typ == ST_FIN {
            self.eof_seq = Some(self.ack_nr);
            if !self.eof_delivered {
                self.eof_delivered = true;
                events.push(Event::Eof);
            }
            return;
        }
        if !data.is_empty() && !self.eof_delivered {
            events.push(Event::Data(data));
        }
    }

    /// Drives timers: retransmissions, delayed acknowledgements, keepalives, timeouts. Call
    /// every few milliseconds.
    pub fn on_tick(&mut self, now: u64, send: &mut Vec<Vec<u8>>, events: &mut Vec<Event>) {
        if self.state == State::Closed {
            return;
        }
        if let Some(at) = self.rto_at {
            if now >= at {
                self.timeouts += 1;
                self.stats.timeouts += 1;
                let limit = if self.state == State::SynSent {
                    CONNECT_TIMEOUTS
                } else {
                    DATA_TIMEOUTS
                };
                if self.timeouts > limit {
                    self.state = State::Closed;
                    events.push(Event::Closed(Some(io::ErrorKind::TimedOut)));
                    return;
                }
                self.rto = (self.rto * 2).min(MAX_RTO_US);
                self.ssthresh = (self.cwnd / 2.0).max(MIN_WINDOW);
                self.cwnd = MIN_WINDOW;
                self.loss_seq = self.seq_nr;
                for o in &mut self.out {
                    if o.transmissions > 0 && !o.acked {
                        o.need_resend = true;
                    }
                }
                self.in_flight = 0;
                self.rto_at = None;
                self.try_send(now, send);
                if self.rto_at.is_none() && self.out.iter().any(|o| !o.acked) {
                    self.rto_at = Some(now + self.rto);
                }
            }
        }
        if self.state == State::Connected {
            if self.ack_due {
                self.send_state(now, send);
            }
            if now.saturating_sub(self.last_sent) > KEEPALIVE_US {
                self.send_state(now, send);
            }
            if now.saturating_sub(self.last_heard) > IDLE_TIMEOUT_US {
                self.state = State::Closed;
                events.push(Event::Closed(Some(io::ErrorKind::TimedOut)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two connections wired back to back through a lossy, reordering "network".
    struct Pair {
        a: Connection,
        b: Connection,
        now: u64,
        to_a: Vec<Vec<u8>>,
        to_b: Vec<Vec<u8>>,
        got_a: Vec<u8>,
        got_b: Vec<u8>,
        ev_a: Vec<Event>,
        ev_b: Vec<Event>,
        n: u64,
    }

    fn feed(
        c: &mut Connection,
        pkts: Vec<Vec<u8>>,
        now: u64,
        out: &mut Vec<Vec<u8>>,
        got: &mut Vec<u8>,
        evs: &mut Vec<Event>,
    ) {
        for p in pkts {
            let (h, sack, payload) = Header::parse(&p).unwrap();
            let mut ev = Vec::new();
            c.on_packet(&h, sack, payload, now, out, &mut ev);
            for e in ev {
                match e {
                    Event::Data(d) => got.extend(d),
                    e => evs.push(e),
                }
            }
        }
    }

    impl Pair {
        fn new() -> Pair {
            let mut to_b = Vec::new();
            let a = Connection::connect(100, 0, &mut to_b);
            let syn = Header::parse(&to_b[0]).unwrap().0;
            assert_eq!((syn.typ, syn.conn_id), (ST_SYN, 100));
            let mut to_a = Vec::new();
            let b = Connection::accept(&syn, 0, &mut to_a);
            assert_eq!((b.recv_id(), b.send_id()), (101, 100));
            Pair {
                a,
                b,
                now: 0,
                to_a,
                to_b: Vec::new(),
                got_a: Vec::new(),
                got_b: Vec::new(),
                ev_a: Vec::new(),
                ev_b: Vec::new(),
                n: 0,
            }
        }

        /// One round: deliver everything in flight (dropping every `drop`-th packet, reversing
        /// order when asked), then tick both sides.
        fn step(&mut self, drop: u64, reverse: bool) {
            self.now += 2_000;
            let filter = |v: Vec<Vec<u8>>, n: &mut u64| -> Vec<Vec<u8>> {
                let mut out: Vec<Vec<u8>> = v
                    .into_iter()
                    .filter(|_| {
                        *n += 1;
                        drop == 0 || *n % drop != 0
                    })
                    .collect();
                if reverse {
                    out.reverse();
                }
                out
            };
            let ta = filter(std::mem::take(&mut self.to_a), &mut self.n);
            let tb = filter(std::mem::take(&mut self.to_b), &mut self.n);
            feed(
                &mut self.a,
                ta,
                self.now,
                &mut self.to_b,
                &mut self.got_a,
                &mut self.ev_a,
            );
            feed(
                &mut self.b,
                tb,
                self.now,
                &mut self.to_a,
                &mut self.got_b,
                &mut self.ev_b,
            );
            let mut ev = Vec::new();
            self.a.on_tick(self.now, &mut self.to_b, &mut ev);
            self.ev_a.extend(ev);
            let mut ev = Vec::new();
            self.b.on_tick(self.now, &mut self.to_a, &mut ev);
            self.ev_b.extend(ev);
        }
    }

    fn data(n: usize, seed: u8) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    #[test]
    fn transfer_both_ways_and_close() {
        let mut p = Pair::new();
        p.step(0, false);
        assert_eq!(p.ev_a, vec![Event::Connected]);
        let (da, db) = (data(300_000, 1), data(200_000, 2));
        p.a.write(&da, p.now, &mut p.to_b).unwrap();
        p.b.write(&db, p.now, &mut p.to_a).unwrap();
        for _ in 0..2000 {
            p.step(0, false);
            if p.got_b.len() == da.len() && p.got_a.len() == db.len() {
                break;
            }
        }
        assert!(p.got_b == da && p.got_a == db);
        p.a.close(p.now, &mut p.to_b);
        for _ in 0..50 {
            p.step(0, false);
        }
        assert!(p.ev_b.contains(&Event::Eof));
        p.b.close(p.now, &mut p.to_a);
        for _ in 0..50 {
            p.step(0, false);
        }
        assert!(
            p.a.is_closed() && p.b.is_closed(),
            "{:?} {:?}",
            p.ev_a,
            p.ev_b
        );
        assert!(p.ev_a.contains(&Event::Closed(None)));
    }

    #[test]
    fn lossy_and_reordered() {
        for (drop, reverse) in [(7, false), (3, true), (0, true)] {
            let mut p = Pair::new();
            let da = data(150_000, 9);
            p.step(0, false);
            p.a.write(&da, p.now, &mut p.to_b).unwrap();
            for _ in 0..200_000 {
                p.step(drop, reverse);
                if p.got_b.len() == da.len() {
                    break;
                }
            }
            assert_eq!(p.got_b.len(), da.len(), "drop {drop} reverse {reverse}");
            assert!(p.got_b == da);
            assert!(drop == 0 || p.a.stats().retransmits > 0);
        }
    }

    #[test]
    fn connect_timeout_and_reset() {
        let mut send = Vec::new();
        let mut c = Connection::connect(5, 0, &mut send);
        let mut ev = Vec::new();
        let mut now = 0;
        while ev.is_empty() {
            now += 100_000;
            c.on_tick(now, &mut send, &mut ev);
        }
        assert_eq!(ev, vec![Event::Closed(Some(io::ErrorKind::TimedOut))]);
        assert!(send.len() >= 3, "SYN resent");
        let mut p = Pair::new();
        p.step(0, false);
        let rst = reset_for(
            &Header {
                conn_id: 101,
                seq: 1,
                ..Header::default()
            },
            0,
        );
        let (h, s, pl) = Header::parse(&rst).unwrap();
        let mut ev = Vec::new();
        p.b.on_packet(&h, s, pl, p.now, &mut Vec::new(), &mut ev);
        assert_eq!(
            ev,
            vec![Event::Closed(Some(io::ErrorKind::ConnectionReset))]
        );
    }

    #[test]
    fn header_codec() {
        let h = Header {
            typ: ST_STATE,
            ext: 0,
            conn_id: 7,
            ts: 1,
            ts_diff: 2,
            wnd: 3,
            seq: 4,
            ack: 5,
        };
        let mut b = Vec::new();
        h.encode_to(&mut b);
        assert_eq!(Header::parse(&b).unwrap().0, h);
        let mut with_sack = b.clone();
        with_sack[1] = EXT_SACK;
        with_sack.extend_from_slice(&[0, 4, 1, 0, 0, 0, 0xAA]);
        let (_, s, p) = Header::parse(&with_sack).unwrap();
        assert_eq!(s, Some(&[1u8, 0, 0, 0][..]));
        assert_eq!(p, &[0xAA]);
        with_sack.truncate(23);
        assert!(Header::parse(&with_sack).is_none());
        assert!(!is_utp(b"d1:ad"));
        assert!(!is_utp(&[0u8; 20]));
    }
}
