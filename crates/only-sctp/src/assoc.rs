//! The association state machine: handshake (RFC 9260 §5) with the I-DATA negotiation (RFC
//! 8260 §2.2), shutdown and abort (§9), chunk dispatch, stream reset (RFC 6525) and the data
//! channel layer (RFC 8831 / 8832).

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use only_crypto::hash::Sha256;
use only_crypto::mac::Hmac;

use crate::dcep::{self, Open};
use crate::packet::{
    self, CT_ABORT, CT_COOKIE_ACK, CT_COOKIE_ECHO, CT_DATA, CT_ERROR, CT_FORWARD_TSN, CT_HEARTBEAT,
    CT_HEARTBEAT_ACK, CT_IDATA, CT_IFORWARD_TSN, CT_INIT, CT_INIT_ACK, CT_RECONFIG, CT_SACK,
    CT_SHUTDOWN, CT_SHUTDOWN_ACK, CT_SHUTDOWN_COMPLETE, Data, FLAG_T, ForwardTsn, Header, IData,
    IForwardTsn, Init, PacketWriter, RawChunk, ReconfigParam, Sack,
};
use crate::recv::{Message, Receiver};
use crate::send::{Policy, Sender, Timing, le32, lt32};
use crate::{ChannelInfo, ChannelOptions, Config, Error, Event, Reliability};

/// Payload protocol identifiers (RFC 8831 §8).
pub(crate) const PPID_DCEP: u32 = 50;
pub(crate) const PPID_STRING: u32 = 51;
pub(crate) const PPID_BINARY_PARTIAL: u32 = 52;
pub(crate) const PPID_BINARY: u32 = 53;
pub(crate) const PPID_STRING_PARTIAL: u32 = 54;
pub(crate) const PPID_STRING_EMPTY: u32 = 56;
pub(crate) const PPID_BINARY_EMPTY: u32 = 57;

const COOKIE_DATA_LEN: usize = 21;
const COOKIE_MAC_LEN: usize = 16;
const STREAMS: u16 = u16::MAX;
/// Peer RE-CONFIG requests remembered for retransmissions.
const PEER_REQUESTS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// No association yet (we may answer INITs statelessly).
    Closed,
    CookieWait,
    CookieEchoed,
    Established,
    ShutdownPending,
    ShutdownSent,
    ShutdownReceived,
    ShutdownAckSent,
    /// Terminal.
    Done,
}

impl State {
    fn connected(self) -> bool {
        matches!(
            self,
            State::Established
                | State::ShutdownPending
                | State::ShutdownSent
                | State::ShutdownReceived
                | State::ShutdownAckSent
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutReset {
    None,
    Queued,
    InFlight,
    Done,
}

#[derive(Debug)]
struct Channel {
    label: String,
    protocol: String,
    ordered: bool,
    reliability: Reliability,
    negotiated: bool,
    priority: u16,
    /// The peer acknowledged our OPEN (or opened it, or it is negotiated).
    acked: bool,
    /// `ChannelOpen` was emitted.
    announced: bool,
    closing: bool,
    out_reset: OutReset,
    in_reset: bool,
    /// Deprecated PPID 52 / 54 partial message being collected.
    partial: Vec<u8>,
}

/// What we learned from the peer's INIT / INIT ACK (or from our own cookie).
#[derive(Clone, Copy, Debug)]
struct Peer {
    tag: u32,
    initial_tsn: u32,
    a_rwnd: u32,
    forward_tsn: bool,
    /// The peer offered I-DATA (RFC 8260).
    i_data: bool,
}

#[derive(Debug)]
struct OutRequest {
    req_seq: u32,
    streams: Vec<u16>,
    last_tsn: u32,
}

#[derive(Debug)]
struct PeerRequest {
    req_seq: u32,
    result: u32,
    /// An Outgoing SSN Reset that is "in progress": (sender's last TSN, streams).
    pending: Option<(u32, Vec<u16>)>,
}

/// A sans-io SCTP association carrying WebRTC data channels. See the crate docs.
#[derive(Debug)]
pub struct Association {
    cfg: Config,
    state: State,
    my_tag: u32,
    my_initial_tsn: u32,
    cookie_secret: [u8; 32],
    peer: Option<Peer>,
    /// Encoded control chunks, each with the verification tag of its packet.
    ctrl: VecDeque<(u32, Vec<u8>)>,
    events: VecDeque<Event>,
    /// Retransmittable handshake chunk (INIT or COOKIE ECHO) and its tag.
    t1_chunk: Option<(u32, Vec<u8>)>,
    t1: Option<Instant>,
    t1_count: u32,
    t1_rto: Duration,
    t2: Option<Instant>,
    t2_count: u32,
    tx: Sender,
    rx: Receiver,
    channels: BTreeMap<u16, Channel>,
    // RE-CONFIG (RFC 6525).
    next_req_seq: u32,
    out_request: Option<OutRequest>,
    reconfig_send: bool,
    reconfig_timer: Option<Instant>,
    peer_req_expected: u32,
    peer_reqs: VecDeque<PeerRequest>,
    low_buf: Vec<u16>,
    delivered: Vec<Message>,
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    if only_crypto::rand::fill_random(&mut b).is_err() {
        // The OS RNG failed: fall back on std's randomly keyed SipHash.
        use std::hash::{BuildHasher, Hasher};
        let s = std::collections::hash_map::RandomState::new();
        for (i, c) in b.chunks_mut(8).enumerate() {
            let mut h = s.build_hasher();
            h.write_usize(i);
            let v = h.finish().to_le_bytes();
            c.copy_from_slice(&v[..c.len()]);
        }
    }
    b
}

impl Association {
    /// A new association in the CLOSED state. It answers an incoming INIT; call
    /// [`connect`](Self::connect) to start the handshake actively.
    #[must_use]
    pub fn new(config: Config, now: Instant) -> Association {
        Association::with_random(config, now, random_bytes())
    }

    /// [`new`](Self::new) with the given bytes instead of fresh randomness for the
    /// verification tag, the initial TSN and the cookie key: for reproducible tests only.
    #[doc(hidden)]
    #[must_use]
    pub fn with_random(config: Config, now: Instant, r: [u8; 40]) -> Association {
        let _ = now;
        let my_tag = u32::from_be_bytes([r[0], r[1], r[2], r[3]]).max(1);
        let my_initial_tsn = u32::from_be_bytes([r[4], r[5], r[6], r[7]]);
        let mut cookie_secret = [0u8; 32];
        cookie_secret.copy_from_slice(&r[8..40]);
        Association::with_ids(config, my_tag, my_initial_tsn, cookie_secret)
    }

    pub(crate) fn with_ids(
        mut config: Config,
        my_tag: u32,
        my_initial_tsn: u32,
        cookie_secret: [u8; 32],
    ) -> Association {
        config.mtu = config.mtu.clamp(128, 65535);
        let timing = Timing {
            rto_initial: config.rto_initial,
            rto_min: config.rto_min,
            rto_max: config.rto_max.max(config.rto_min),
        };
        Association {
            tx: Sender::new(config.mtu, timing, my_initial_tsn, config.scheduler),
            rx: Receiver::new(0, 0, 0, config.mtu, false),
            state: State::Closed,
            my_tag,
            my_initial_tsn,
            cookie_secret,
            peer: None,
            ctrl: VecDeque::new(),
            events: VecDeque::new(),
            t1_chunk: None,
            t1: None,
            t1_count: 0,
            t1_rto: config.rto_initial,
            t2: None,
            t2_count: 0,
            channels: BTreeMap::new(),
            next_req_seq: my_initial_tsn,
            out_request: None,
            reconfig_send: false,
            reconfig_timer: None,
            peer_req_expected: 0,
            peer_reqs: VecDeque::new(),
            low_buf: Vec::new(),
            delivered: Vec::new(),
            cfg: config,
        }
    }

    fn header(&self, vtag: u32) -> Header {
        Header {
            src_port: self.cfg.local_port,
            dst_port: self.cfg.remote_port,
            vtag,
        }
    }

    fn peer_tag(&self) -> u32 {
        self.peer.map_or(0, |p| p.tag)
    }

    fn our_init(&self) -> Init {
        Init {
            initiate_tag: self.my_tag,
            a_rwnd: self.cfg.receive_window,
            outbound_streams: STREAMS,
            inbound_streams: STREAMS,
            initial_tsn: self.my_initial_tsn,
            cookie: None,
            forward_tsn: true,
            reconfig: true,
            i_data: self.cfg.message_interleaving,
        }
    }

    /// Starts the handshake: sends INIT (RFC 9260 §5.1). Does nothing unless CLOSED.
    pub fn connect(&mut self, now: Instant) {
        if self.state != State::Closed {
            return;
        }
        let chunk = self.our_init().encode(false);
        self.ctrl.push_back((0, chunk.clone()));
        self.t1_chunk = Some((0, chunk));
        self.state = State::CookieWait;
        self.t1_count = 0;
        self.t1_rto = self.cfg.rto_initial;
        self.t1 = Some(now + self.t1_rto);
    }

    /// Whether the association is up (from [`Event::Connected`] until it closes).
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.state.connected()
    }

    /// Whether the association has shut down, aborted or failed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state == State::Done
    }

    /// The next event, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// When [`handle_timeout`](Self::handle_timeout) should be called next.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        if self.state == State::Done {
            return None;
        }
        [
            self.t1,
            self.t2,
            self.tx.t3,
            self.rx.sack_deadline,
            self.reconfig_timer,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Processes expired timers.
    pub fn handle_timeout(&mut self, now: Instant) {
        if self.state == State::Done {
            return;
        }
        if self.t1.is_some_and(|t| t <= now) {
            self.t1_count += 1;
            if self.t1_count > self.cfg.max_init_retransmissions {
                self.close_now();
                return;
            }
            self.t1_rto = (self.t1_rto * 2).min(self.cfg.rto_max);
            self.t1 = Some(now + self.t1_rto);
            if let Some(c) = self.t1_chunk.clone() {
                self.ctrl.push_back(c);
            }
        }
        if self.t2.is_some_and(|t| t <= now) {
            self.t2_count += 1;
            if self.t2_count > self.cfg.max_retransmissions {
                self.abort();
                return;
            }
            self.tx.rto = (self.tx.rto * 2).min(self.cfg.rto_max);
            self.t2 = Some(now + self.tx.rto);
            let c = match self.state {
                State::ShutdownSent => Some(packet::shutdown(self.rx.cum_tsn())),
                State::ShutdownAckSent => Some(packet::chunk(CT_SHUTDOWN_ACK, 0, &[])),
                _ => None,
            };
            if let Some(c) = c {
                self.ctrl.push_back((self.peer_tag(), c));
            }
        }
        if self.tx.t3.is_some_and(|t| t <= now) {
            let mut low = std::mem::take(&mut self.low_buf);
            let ok = self.tx.on_t3(now, self.cfg.max_retransmissions, &mut low);
            self.emit_low(&mut low);
            self.low_buf = low;
            if !ok {
                self.abort();
                return;
            }
        }
        if self.rx.sack_deadline.is_some_and(|t| t <= now) {
            self.rx.on_sack_timer();
        }
        if self.reconfig_timer.is_some_and(|t| t <= now) {
            self.reconfig_timer = None;
            if self.out_request.is_some() {
                self.tx.error_count += 1;
                if self.tx.error_count > self.cfg.max_retransmissions {
                    self.abort();
                    return;
                }
                self.reconfig_send = true;
            }
        }
        self.after(now);
    }

    // ----- handshake -----

    fn make_cookie(&self, init: &Init) -> Vec<u8> {
        let mut c = Vec::with_capacity(COOKIE_DATA_LEN + COOKIE_MAC_LEN);
        c.extend_from_slice(&init.initiate_tag.to_be_bytes());
        c.extend_from_slice(&init.initial_tsn.to_be_bytes());
        c.extend_from_slice(&init.a_rwnd.to_be_bytes());
        c.extend_from_slice(&init.outbound_streams.to_be_bytes());
        c.extend_from_slice(&init.inbound_streams.to_be_bytes());
        c.push(u8::from(init.forward_tsn) | (u8::from(init.i_data) << 1));
        c.extend_from_slice(&self.my_tag.to_be_bytes());
        let mac = Hmac::<Sha256>::mac(&self.cookie_secret, &c);
        c.extend_from_slice(&mac[..COOKIE_MAC_LEN]);
        c
    }

    fn check_cookie(&self, c: &[u8]) -> Option<Peer> {
        if c.len() != COOKIE_DATA_LEN + COOKIE_MAC_LEN {
            return None;
        }
        let (data, mac) = c.split_at(COOKIE_DATA_LEN);
        if !Hmac::<Sha256>::new(&self.cookie_secret)
            .chain(data)
            .verify(mac)
        {
            return None;
        }
        let u32_at =
            |i: usize| u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        if u32_at(17) != self.my_tag {
            return None;
        }
        Some(Peer {
            tag: u32_at(0),
            initial_tsn: u32_at(4),
            a_rwnd: u32_at(8),
            forward_tsn: data[16] & 1 != 0,
            i_data: data[16] & 2 != 0,
        })
    }

    fn on_init(&mut self, init: &Init) {
        if init.initiate_tag == 0 || init.outbound_streams == 0 || init.inbound_streams == 0 {
            return;
        }
        match self.state {
            State::Closed | State::CookieWait | State::CookieEchoed => {
                // RFC 9260 §5.2.1: the same tag as our own INIT, so that an INIT collision
                // converges on one association.
                let mut ack = self.our_init();
                ack.cookie = Some(self.make_cookie(init));
                self.ctrl.push_back((init.initiate_tag, ack.encode(true)));
            }
            State::ShutdownAckSent => {
                self.ctrl
                    .push_back((self.peer_tag(), packet::chunk(CT_SHUTDOWN_ACK, 0, &[])));
            }
            // A retransmitted INIT of the current handshake; peer restarts (§5.2.2) are not
            // supported (one association per DTLS connection).
            _ => {}
        }
    }

    fn on_init_ack(&mut self, now: Instant, init: &Init) {
        if self.state != State::CookieWait || init.initiate_tag == 0 {
            return;
        }
        let Some(cookie) = &init.cookie else {
            return;
        };
        self.peer = Some(Peer {
            tag: init.initiate_tag,
            initial_tsn: init.initial_tsn,
            a_rwnd: init.a_rwnd,
            forward_tsn: init.forward_tsn,
            i_data: init.i_data,
        });
        let echo = packet::chunk(CT_COOKIE_ECHO, 0, cookie);
        self.ctrl.push_back((init.initiate_tag, echo.clone()));
        self.t1_chunk = Some((init.initiate_tag, echo));
        self.state = State::CookieEchoed;
        self.t1_count = 0;
        self.t1_rto = self.cfg.rto_initial;
        self.t1 = Some(now + self.t1_rto);
    }

    fn on_cookie_echo(&mut self, cookie: &[u8]) {
        let Some(p) = self.check_cookie(cookie) else {
            return;
        };
        match self.state {
            State::Closed | State::CookieWait | State::CookieEchoed => {
                self.peer = Some(p);
                self.ctrl
                    .push_back((p.tag, packet::chunk(CT_COOKIE_ACK, 0, &[])));
                self.establish();
            }
            s if s.connected() && p.tag == self.peer_tag() => {
                // Duplicate COOKIE ECHO (§5.2.4 case D).
                self.ctrl
                    .push_back((p.tag, packet::chunk(CT_COOKIE_ACK, 0, &[])));
            }
            _ => {}
        }
    }

    fn establish(&mut self) {
        let Some(p) = self.peer else {
            return;
        };
        self.state = State::Established;
        self.t1 = None;
        self.t1_chunk = None;
        // RFC 8260 §2.2: I-DATA only when both sides offered it.
        let idata = self.cfg.message_interleaving && p.i_data;
        self.tx.start(p.a_rwnd, p.forward_tsn, idata);
        self.rx = Receiver::new(
            p.initial_tsn,
            self.cfg.receive_window,
            self.cfg.max_receive_message_size,
            self.cfg.mtu,
            idata,
        );
        self.peer_req_expected = p.initial_tsn;
        self.events.push_back(Event::Connected);
        for (&stream, ch) in &mut self.channels {
            if !ch.announced && !ch.closing {
                ch.announced = true;
                self.events.push_back(Event::ChannelOpen {
                    stream,
                    label: ch.label.clone(),
                    protocol: ch.protocol.clone(),
                });
            }
        }
    }

    /// Enters the terminal state: `ChannelClose` for every announced channel, then `Closed`.
    fn close_now(&mut self) {
        if self.state == State::Done {
            return;
        }
        self.state = State::Done;
        self.t1 = None;
        self.t2 = None;
        self.tx.t3 = None;
        self.rx.sack_deadline = None;
        self.reconfig_timer = None;
        for (&stream, ch) in &self.channels {
            if ch.announced {
                self.events.push_back(Event::ChannelClose { stream });
            }
        }
        self.channels.clear();
        self.events.push_back(Event::Closed);
    }

    /// Sends ABORT (if the peer is known) and closes immediately.
    pub fn abort(&mut self) {
        if self.state == State::Done {
            return;
        }
        if self.peer.is_some() {
            let cause = packet::cause(packet::CAUSE_USER_ABORT, &[]);
            self.ctrl
                .push_back((self.peer_tag(), packet::chunk(CT_ABORT, 0, &cause)));
        }
        self.close_now();
    }

    fn abort_with(&mut self, cause_code: u16) {
        if self.peer.is_some() {
            let cause = packet::cause(cause_code, &[]);
            self.ctrl
                .push_back((self.peer_tag(), packet::chunk(CT_ABORT, 0, &cause)));
        }
        self.close_now();
    }

    /// Starts a graceful shutdown (RFC 9260 §9.2): queued data is delivered first, then
    /// SHUTDOWN / SHUTDOWN ACK / SHUTDOWN COMPLETE. Before the association is up this is an
    /// abort.
    pub fn shutdown(&mut self, now: Instant) {
        match self.state {
            State::Established => {
                self.state = State::ShutdownPending;
                self.after(now);
            }
            State::Closed | State::CookieWait | State::CookieEchoed => self.abort(),
            _ => {}
        }
    }

    fn check_shutdown(&mut self, now: Instant) {
        if !self.tx.all_acked() {
            return;
        }
        let chunk = match self.state {
            State::ShutdownPending => {
                self.state = State::ShutdownSent;
                packet::shutdown(self.rx.cum_tsn())
            }
            State::ShutdownReceived => {
                self.state = State::ShutdownAckSent;
                packet::chunk(CT_SHUTDOWN_ACK, 0, &[])
            }
            _ => return,
        };
        self.ctrl.push_back((self.peer_tag(), chunk));
        self.t2_count = 0;
        self.t2 = Some(now + self.tx.rto);
    }

    // ----- input -----

    /// Processes one received SCTP packet (one DTLS application-data record). Packets with
    /// a bad checksum or verification tag, and malformed chunks, are ignored.
    pub fn handle_packet(&mut self, now: Instant, packet: &[u8]) {
        if self.state == State::Done {
            return;
        }
        let Some((h, chunks)) = packet::parse_packet(packet) else {
            return;
        };
        let Some(first) = chunks.first() else {
            return;
        };
        if first.typ == CT_INIT {
            // RFC 9260 §6.10: INIT is alone, with tag 0.
            if h.vtag == 0 && chunks.len() == 1 {
                if let Some(init) = Init::parse(first.value) {
                    self.on_init(&init);
                }
            }
            self.after(now);
            return;
        }
        let tag_ok = h.vtag == self.my_tag;
        let peer_tag = self.peer_tag();
        let mut had_data = false;
        let mut reports: Vec<u8> = Vec::new();
        for c in &chunks {
            let ok = match c.typ {
                CT_ABORT | CT_SHUTDOWN_COMPLETE => {
                    if c.flags & FLAG_T != 0 {
                        peer_tag != 0 && h.vtag == peer_tag
                    } else {
                        tag_ok
                    }
                }
                _ => tag_ok,
            };
            if !ok || self.state == State::Done {
                break;
            }
            if !self.on_chunk(now, c, &mut had_data, &mut reports) {
                break;
            }
        }
        if !reports.is_empty() && self.peer.is_some() {
            self.ctrl
                .push_back((self.peer_tag(), packet::chunk(CT_ERROR, 0, &reports)));
        }
        if had_data && self.state != State::Done {
            self.rx.packet_done(now);
        }
        self.flush_delivered();
        self.after(now);
    }

    /// Handles one chunk; `false` stops processing the rest of the packet.
    fn on_chunk(
        &mut self,
        now: Instant,
        c: &RawChunk<'_>,
        had_data: &mut bool,
        reports: &mut Vec<u8>,
    ) -> bool {
        let connected = self.state.connected();
        match c.typ {
            CT_DATA | CT_IDATA => {
                if !matches!(
                    self.state,
                    State::Established | State::ShutdownPending | State::ShutdownSent
                ) {
                    return true;
                }
                if (c.typ == CT_IDATA) != self.tx.idata {
                    // RFC 8260 §2.2.3: DATA when I-DATA was negotiated, or the other way
                    // round, is a protocol violation.
                    self.flush_delivered();
                    self.abort_with(packet::CAUSE_PROTOCOL_VIOLATION);
                    return false;
                }
                let mut out = std::mem::take(&mut self.delivered);
                let r = if c.typ == CT_IDATA {
                    IData::parse(c.flags, c.value).map(|d| self.rx.on_idata(&d, &mut out))
                } else {
                    Data::parse(c.flags, c.value).map(|d| self.rx.on_data(&d, &mut out))
                };
                self.delivered = out;
                let Some(r) = r else {
                    return true;
                };
                *had_data = true;
                if r.is_err() {
                    self.flush_delivered();
                    self.abort_with(packet::CAUSE_PROTOCOL_VIOLATION);
                    return false;
                }
            }
            CT_INIT_ACK => {
                if let Some(init) = Init::parse(c.value) {
                    self.on_init_ack(now, &init);
                }
            }
            CT_COOKIE_ECHO => self.on_cookie_echo(c.value),
            CT_COOKIE_ACK => {
                if self.state == State::CookieEchoed {
                    self.establish();
                }
            }
            CT_SACK if connected => {
                if let Some(s) = Sack::parse(c.value) {
                    let mut low = std::mem::take(&mut self.low_buf);
                    self.tx.on_sack(now, &s, &mut low);
                    self.emit_low(&mut low);
                    self.low_buf = low;
                }
            }
            CT_HEARTBEAT => {
                if let Some(ack) = packet::heartbeat_ack(c.value) {
                    // An info too large for our MTU goes unanswered.
                    if self.peer.is_some() && packet::pad4(ack.len()) + 12 <= self.cfg.mtu {
                        self.ctrl.push_back((self.peer_tag(), ack));
                    }
                }
            }
            CT_HEARTBEAT_ACK | CT_ERROR => {}
            CT_ABORT => {
                self.close_now();
                return false;
            }
            CT_SHUTDOWN if connected => {
                if let Some(cum) = packet::parse_shutdown(c.value) {
                    let mut low = std::mem::take(&mut self.low_buf);
                    self.tx.on_cum_ack(now, cum, &mut low);
                    self.emit_low(&mut low);
                    self.low_buf = low;
                }
                match self.state {
                    State::Established | State::ShutdownPending => {
                        self.state = State::ShutdownReceived;
                    }
                    State::ShutdownSent => {
                        // Both sides shut down at once (§9.2).
                        self.state = State::ShutdownAckSent;
                        self.ctrl
                            .push_back((self.peer_tag(), packet::chunk(CT_SHUTDOWN_ACK, 0, &[])));
                        self.t2_count = 0;
                        self.t2 = Some(now + self.tx.rto);
                    }
                    _ => {}
                }
            }
            CT_SHUTDOWN_ACK => {
                if matches!(self.state, State::ShutdownSent | State::ShutdownAckSent) {
                    self.ctrl
                        .push_back((self.peer_tag(), packet::chunk(CT_SHUTDOWN_COMPLETE, 0, &[])));
                    self.close_now();
                    return false;
                }
            }
            CT_SHUTDOWN_COMPLETE => {
                if self.state == State::ShutdownAckSent {
                    self.close_now();
                    return false;
                }
            }
            CT_IFORWARD_TSN if connected && self.tx.idata => {
                if let Some(f) = IForwardTsn::parse(c.value) {
                    let mut out = std::mem::take(&mut self.delivered);
                    self.rx.on_iforward_tsn(f.new_cum_tsn, &f.streams, &mut out);
                    self.delivered = out;
                    for &(s, _, _) in &f.streams {
                        if let Some(ch) = self.channels.get_mut(&s) {
                            ch.partial.clear();
                        }
                    }
                }
            }
            CT_FORWARD_TSN if connected && !self.tx.idata => {
                if let Some(f) = ForwardTsn::parse(c.value) {
                    let mut out = std::mem::take(&mut self.delivered);
                    self.rx.on_forward_tsn(f.new_cum_tsn, &f.streams, &mut out);
                    self.delivered = out;
                    for &(s, _) in &f.streams {
                        if let Some(ch) = self.channels.get_mut(&s) {
                            ch.partial.clear();
                        }
                    }
                }
            }
            CT_RECONFIG if connected => {
                for p in ReconfigParam::parse_all(c.value) {
                    self.on_reconfig_param(now, p);
                }
            }
            // Out of state, or the forward kind that does not match the data chunks in use
            // (RFC 8260 §2.3.1): ignored.
            CT_SACK | CT_SHUTDOWN | CT_FORWARD_TSN | CT_IFORWARD_TSN | CT_RECONFIG => {}
            t => {
                // RFC 9260 §3.2: the two high bits say whether to go on and whether to report.
                if t & 0x40 != 0 {
                    let mut raw = packet::chunk(t, c.flags, c.value);
                    raw.truncate(256);
                    let cause = packet::cause(packet::CAUSE_UNRECOGNIZED_CHUNK, &raw);
                    // The ERROR chunk must fit in one packet.
                    if reports.len() + cause.len() + 16 <= self.cfg.mtu {
                        reports.extend_from_slice(&cause);
                    }
                }
                return t & 0x80 != 0;
            }
        }
        true
    }

    fn emit_low(&mut self, low: &mut Vec<u16>) {
        for s in low.drain(..) {
            if self.channels.contains_key(&s) {
                self.events
                    .push_back(Event::BufferedAmountLow { stream: s });
            }
        }
    }

    // ----- data channels -----

    fn flush_delivered(&mut self) {
        let msgs = std::mem::take(&mut self.delivered);
        for m in msgs {
            self.on_message(m);
        }
    }

    fn on_message(&mut self, m: Message) {
        let stream = m.stream;
        if m.ppid == PPID_DCEP {
            self.on_dcep(stream, &m.data);
            return;
        }
        let max = self.cfg.max_receive_message_size;
        let Some(ch) = self.channels.get_mut(&stream) else {
            return;
        };
        ch.acked = true; // data implies the peer has the channel (RFC 8832 §6)
        let (data, binary) = match m.ppid {
            PPID_STRING | PPID_BINARY => {
                let binary = m.ppid == PPID_BINARY;
                if ch.partial.is_empty() {
                    (m.data, binary)
                } else {
                    let mut d = std::mem::take(&mut ch.partial);
                    if d.len() + m.data.len() > max {
                        return;
                    }
                    d.extend_from_slice(&m.data);
                    (d, binary)
                }
            }
            PPID_STRING_PARTIAL | PPID_BINARY_PARTIAL => {
                if ch.partial.len() + m.data.len() <= max {
                    ch.partial.extend_from_slice(&m.data);
                } else {
                    ch.partial.clear();
                }
                return;
            }
            PPID_STRING_EMPTY => (Vec::new(), false),
            PPID_BINARY_EMPTY => (Vec::new(), true),
            _ => return,
        };
        self.events.push_back(Event::ChannelData {
            stream,
            data,
            binary,
        });
    }

    fn on_dcep(&mut self, stream: u16, msg: &[u8]) {
        match msg.first() {
            Some(&dcep::MSG_OPEN) => {
                if self.channels.contains_key(&stream) {
                    return;
                }
                let Some(open) = Open::parse(msg) else {
                    return;
                };
                self.channels.insert(
                    stream,
                    Channel {
                        label: open.label.clone(),
                        protocol: open.protocol.clone(),
                        ordered: open.ordered,
                        reliability: open.reliability,
                        negotiated: false,
                        priority: open.priority,
                        acked: true,
                        announced: true,
                        closing: false,
                        out_reset: OutReset::None,
                        in_reset: false,
                        partial: Vec::new(),
                    },
                );
                self.tx.set_priority(stream, open.priority);
                self.tx.enqueue(
                    stream,
                    PPID_DCEP,
                    &[dcep::MSG_ACK],
                    false,
                    Policy::Reliable,
                    false,
                );
                self.events.push_back(Event::ChannelOpen {
                    stream,
                    label: open.label,
                    protocol: open.protocol,
                });
            }
            Some(&dcep::MSG_ACK) => {
                if let Some(ch) = self.channels.get_mut(&stream) {
                    ch.acked = true;
                }
            }
            _ => {}
        }
    }

    fn accepting(&self) -> bool {
        matches!(
            self.state,
            State::Closed | State::CookieWait | State::CookieEchoed | State::Established
        )
    }

    /// Opens a data channel and returns its stream id. Without `opts.negotiated` the id is
    /// the lowest free one of our parity (even for the DTLS client, odd for the server, RFC
    /// 8832 §6) and a DATA_CHANNEL_OPEN is queued; it goes out once the association is up.
    /// [`Event::ChannelOpen`] follows once the association is established (at once if it
    /// already is).
    pub fn open_channel(&mut self, now: Instant, opts: ChannelOptions) -> Result<u16, Error> {
        if !self.accepting() {
            return Err(Error::AssociationClosed);
        }
        if opts.label.len() > usize::from(u16::MAX) || opts.protocol.len() > usize::from(u16::MAX) {
            return Err(Error::LabelTooLong);
        }
        let stream = match opts.negotiated {
            Some(id) => {
                if self.channels.contains_key(&id) || id == u16::MAX {
                    return Err(Error::StreamInUse(id));
                }
                id
            }
            None => {
                let mut id = u16::from(!self.cfg.dtls_client);
                loop {
                    if !self.channels.contains_key(&id) {
                        break id;
                    }
                    id = match id.checked_add(2) {
                        Some(n) if n < u16::MAX => n,
                        _ => return Err(Error::NoStreamAvailable),
                    };
                }
            }
        };
        let negotiated = opts.negotiated.is_some();
        // A previous channel on this id may still have state; start clean.
        self.tx.forget_stream(stream);
        self.rx.reset_stream(stream);
        self.tx.set_priority(stream, opts.priority);
        if !negotiated {
            let open = Open {
                ordered: opts.ordered,
                reliability: opts.reliability,
                priority: opts.priority,
                label: opts.label.clone(),
                protocol: opts.protocol.clone(),
            };
            self.tx.enqueue(
                stream,
                PPID_DCEP,
                &open.encode(),
                false,
                Policy::Reliable,
                false,
            );
        }
        let established = self.state == State::Established;
        if established {
            self.events.push_back(Event::ChannelOpen {
                stream,
                label: opts.label.clone(),
                protocol: opts.protocol.clone(),
            });
        }
        self.channels.insert(
            stream,
            Channel {
                label: opts.label,
                protocol: opts.protocol,
                ordered: opts.ordered,
                reliability: opts.reliability,
                negotiated,
                priority: opts.priority,
                acked: negotiated,
                announced: established,
                closing: false,
                out_reset: OutReset::None,
                in_reset: false,
                partial: Vec::new(),
            },
        );
        let _ = now;
        Ok(stream)
    }

    /// Queues one message on a channel. `Ok(false)` means the channel's buffered amount
    /// already exceeds `max_buffered_amount` and nothing was queued. Empty messages are sent
    /// as one zero byte with PPID 56 / 57 (RFC 8831 §6.6).
    pub fn send(
        &mut self,
        now: Instant,
        stream: u16,
        data: &[u8],
        binary: bool,
    ) -> Result<bool, Error> {
        if !self.accepting() {
            return Err(Error::AssociationClosed);
        }
        let ch = self
            .channels
            .get(&stream)
            .ok_or(Error::UnknownChannel(stream))?;
        if ch.closing {
            return Err(Error::ChannelClosed(stream));
        }
        if data.len() > self.cfg.max_message_size {
            return Err(Error::MessageTooLarge {
                size: data.len(),
                max: self.cfg.max_message_size,
            });
        }
        if self.tx.buffered_amount(stream) > self.cfg.max_buffered_amount {
            return Ok(false);
        }
        // Until the peer ACKs our OPEN, messages go ordered (RFC 8832 §6).
        let unordered = !ch.ordered && ch.acked;
        let policy = match ch.reliability {
            Reliability::Reliable => Policy::Reliable,
            Reliability::MaxRetransmits(n) => Policy::MaxRetransmits(n),
            Reliability::MaxLifetime(ms) => {
                Policy::Deadline(now + Duration::from_millis(u64::from(ms)))
            }
        };
        let (ppid, payload): (u32, &[u8]) = match (data.is_empty(), binary) {
            (true, true) => (PPID_BINARY_EMPTY, &[0]),
            (true, false) => (PPID_STRING_EMPTY, &[0]),
            (false, true) => (PPID_BINARY, data),
            (false, false) => (PPID_STRING, data),
        };
        self.tx
            .enqueue(stream, ppid, payload, unordered, policy, true);
        Ok(true)
    }

    /// Bytes of user messages queued or in flight on `stream` and not yet acknowledged.
    #[must_use]
    pub fn buffered_amount(&self, stream: u16) -> usize {
        self.tx.buffered_amount(stream)
    }

    /// Sets the threshold for [`Event::BufferedAmountLow`] (default 0): the event fires when
    /// the buffered amount drops to or below it after having been above it.
    pub fn set_buffered_amount_low_threshold(&mut self, stream: u16, bytes: usize) {
        self.tx.set_threshold(stream, bytes);
    }

    /// Changes a channel's priority for the [`Scheduler`](crate::Scheduler) (our sending side
    /// only: the peer was told the priority at open time). Takes effect for the next chunk.
    pub fn set_channel_priority(&mut self, stream: u16, priority: u16) -> Result<(), Error> {
        let ch = self
            .channels
            .get_mut(&stream)
            .ok_or(Error::UnknownChannel(stream))?;
        ch.priority = priority;
        self.tx.set_priority(stream, priority);
        Ok(())
    }

    /// Whether I-DATA (RFC 8260 message interleaving) is in use: both sides offered it.
    /// `false` until the association is established.
    #[must_use]
    pub fn message_interleaving(&self) -> bool {
        self.tx.idata
    }

    /// The channel on `stream`, if open (or closing).
    #[must_use]
    pub fn channel(&self, stream: u16) -> Option<ChannelInfo> {
        self.channels.get(&stream).map(|c| ChannelInfo {
            label: c.label.clone(),
            protocol: c.protocol.clone(),
            ordered: c.ordered,
            reliability: c.reliability,
            negotiated: c.negotiated,
            priority: c.priority,
        })
    }

    /// Closes a channel (RFC 8831 §6.7): once its queued data has TSNs, the outgoing stream
    /// is reset; the peer resets its side too and [`Event::ChannelClose`] fires once both
    /// directions are reset. Before the association is up the channel is just dropped.
    pub fn close_channel(&mut self, now: Instant, stream: u16) {
        let Some(ch) = self.channels.get_mut(&stream) else {
            return;
        };
        if ch.closing {
            return;
        }
        ch.closing = true;
        if self.state.connected() {
            ch.out_reset = OutReset::Queued;
            self.after(now);
        } else {
            let announced = ch.announced;
            self.channels.remove(&stream);
            self.tx.drop_pending_stream(stream);
            if announced {
                self.events.push_back(Event::ChannelClose { stream });
            }
        }
    }

    // ----- RE-CONFIG (RFC 6525) -----

    fn on_reconfig_param(&mut self, now: Instant, p: ReconfigParam) {
        match p {
            ReconfigParam::OutgoingReset {
                req_seq,
                last_tsn,
                streams,
                ..
            } => {
                let result = self.on_peer_request(req_seq, Some((last_tsn, streams)), true);
                self.respond(req_seq, result);
            }
            ReconfigParam::OtherRequest { typ, req_seq } => {
                // Add-streams requests: we accept any stream id anyway. Incoming and SSN/TSN
                // resets are refused.
                let ok = matches!(typ, packet::PARAM_ADD_OUTGOING | packet::PARAM_ADD_INCOMING);
                let result = self.on_peer_request(req_seq, None, ok);
                self.respond(req_seq, result);
            }
            ReconfigParam::Response { resp_seq, result } => {
                let Some(req) = &self.out_request else {
                    return;
                };
                if req.req_seq != resp_seq {
                    return;
                }
                if result == packet::RESULT_IN_PROGRESS {
                    // §5.2.7: retry later without counting an error.
                    self.reconfig_timer = Some(now + self.tx.rto);
                    return;
                }
                let Some(req) = self.out_request.take() else {
                    return;
                };
                self.reconfig_timer = None;
                self.tx.error_count = 0;
                // Performed, nothing to do, or refused: either way this direction is over.
                for s in req.streams {
                    self.tx.reset_ssn(s);
                    if let Some(ch) = self.channels.get_mut(&s) {
                        ch.out_reset = OutReset::Done;
                    }
                    self.maybe_finish_close(s);
                }
            }
        }
    }

    /// A request from the peer. Requests are remembered by sequence number (the last
    /// [`PEER_REQUESTS`]), so retransmissions get the same answer and, since pion keeps
    /// several requests in flight, requests are taken in any order rather than only the
    /// expected next one (RFC 6525 §5.2.1 would answer "bad sequence number").
    fn on_peer_request(&mut self, req_seq: u32, reset: Option<(u32, Vec<u16>)>, ok: bool) -> u32 {
        if let Some(i) = self.peer_reqs.iter().position(|r| r.req_seq == req_seq) {
            self.check_pending_incoming();
            return self.peer_reqs[i].result;
        }
        let window = PEER_REQUESTS as u32;
        if !le32(self.peer_req_expected.wrapping_sub(window), req_seq)
            || !lt32(req_seq, self.peer_req_expected.wrapping_add(window))
        {
            return packet::RESULT_BAD_SEQUENCE;
        }
        if le32(self.peer_req_expected, req_seq) {
            self.peer_req_expected = req_seq.wrapping_add(1);
        }
        let (result, pending) = match reset {
            None if ok => (packet::RESULT_PERFORMED, None),
            None => (packet::RESULT_DENIED, None),
            Some((last_tsn, streams)) => {
                if le32(last_tsn, self.rx.cum_tsn()) {
                    self.reset_incoming(&streams);
                    (packet::RESULT_PERFORMED, None)
                } else {
                    (packet::RESULT_IN_PROGRESS, Some((last_tsn, streams)))
                }
            }
        };
        if self.peer_reqs.len() == PEER_REQUESTS {
            self.peer_reqs.pop_front();
        }
        self.peer_reqs.push_back(PeerRequest {
            req_seq,
            result,
            pending,
        });
        result
    }

    /// Performs deferred incoming resets once the cumulative TSN reached them.
    fn check_pending_incoming(&mut self) {
        let cum = self.rx.cum_tsn();
        let mut ready = Vec::new();
        for r in &mut self.peer_reqs {
            if r.pending.as_ref().is_some_and(|(t, _)| le32(*t, cum)) {
                if let Some((_, streams)) = r.pending.take() {
                    r.result = packet::RESULT_PERFORMED;
                    ready.extend(streams);
                }
            }
        }
        if !ready.is_empty() {
            self.reset_incoming(&ready);
        }
    }

    fn respond(&mut self, resp_seq: u32, result: u32) {
        let chunk = ReconfigParam::encode_chunk(&[ReconfigParam::Response { resp_seq, result }]);
        self.ctrl.push_back((self.peer_tag(), chunk));
    }

    /// The peer reset its outgoing streams: reset our incoming side, and our outgoing side
    /// too (RFC 8831 §6.7).
    fn reset_incoming(&mut self, streams: &[u16]) {
        // An empty list means every stream (RFC 6525 §4.1).
        let all: Vec<u16>;
        let streams = if streams.is_empty() {
            self.rx.reset_all_streams();
            all = self.channels.keys().copied().collect();
            &all[..]
        } else {
            streams
        };
        for &s in streams {
            self.rx.reset_stream(s);
            if let Some(ch) = self.channels.get_mut(&s) {
                ch.in_reset = true;
                ch.partial.clear();
                if !ch.closing {
                    ch.closing = true;
                    ch.out_reset = OutReset::Queued;
                }
            }
            self.maybe_finish_close(s);
        }
    }

    fn maybe_finish_close(&mut self, stream: u16) {
        let done = self
            .channels
            .get(&stream)
            .is_some_and(|c| c.in_reset && c.out_reset == OutReset::Done);
        if done {
            if let Some(ch) = self.channels.remove(&stream) {
                self.tx.forget_stream(stream);
                if ch.announced {
                    self.events.push_back(Event::ChannelClose { stream });
                }
            }
        }
    }

    /// Starts an Outgoing SSN Reset Request for closing channels whose data all has TSNs.
    fn maybe_send_reset(&mut self, now: Instant) {
        if self.out_request.is_some() || !self.state.connected() {
            return;
        }
        let max = (self.cfg.mtu.saturating_sub(12 + 4 + 16)) / 2;
        let mut streams = Vec::new();
        for (&s, ch) in &self.channels {
            if ch.out_reset == OutReset::Queued && self.tx.pending_on(s) == 0 {
                streams.push(s);
                if streams.len() >= max {
                    break;
                }
            }
        }
        if streams.is_empty() {
            return;
        }
        for s in &streams {
            if let Some(ch) = self.channels.get_mut(s) {
                ch.out_reset = OutReset::InFlight;
            }
        }
        self.out_request = Some(OutRequest {
            req_seq: self.next_req_seq,
            streams,
            last_tsn: self.tx.last_assigned_tsn(),
        });
        self.next_req_seq = self.next_req_seq.wrapping_add(1);
        self.reconfig_send = true;
        let _ = now;
    }

    fn reconfig_request_chunk(&self) -> Option<Vec<u8>> {
        let r = self.out_request.as_ref()?;
        Some(ReconfigParam::encode_chunk(&[
            ReconfigParam::OutgoingReset {
                req_seq: r.req_seq,
                resp_seq: self.peer_req_expected.wrapping_sub(1),
                last_tsn: r.last_tsn,
                streams: r.streams.clone(),
            },
        ]))
    }

    /// Bookkeeping after any input.
    fn after(&mut self, now: Instant) {
        if self.state == State::Done {
            return;
        }
        self.check_pending_incoming();
        self.maybe_send_reset(now);
        self.check_shutdown(now);
    }

    // ----- output -----

    /// The next packet to send (at most `mtu` bytes), bundling control chunks, SACK,
    /// FORWARD TSN, RE-CONFIG and DATA. Call until it returns `None`.
    pub fn poll_transmit(&mut self, now: Instant) -> Option<Vec<u8>> {
        let peer_tag = self.peer_tag();
        let data_ok = self.state.connected() && peer_tag != 0;
        if let Some((vtag, _)) = self.ctrl.front() {
            let vtag = *vtag;
            if vtag == 0 || !data_ok || vtag != peer_tag {
                let mut w = PacketWriter::new(self.header(vtag), self.cfg.mtu);
                while let Some((v, c)) = self.ctrl.front() {
                    if *v != vtag
                        || (!w.is_empty() && (vtag == 0 || packet::pad4(c.len()) > w.remaining()))
                    {
                        break;
                    }
                    if let Some((_, c)) = self.ctrl.pop_front() {
                        w.push_raw(&c);
                    }
                    if vtag == 0 {
                        break;
                    }
                }
                return Some(w.finish());
            }
        }
        if !data_ok {
            return None;
        }
        let mut w = PacketWriter::new(self.header(peer_tag), self.cfg.mtu);
        while let Some((v, c)) = self.ctrl.front() {
            if *v != peer_tag || (!w.is_empty() && packet::pad4(c.len()) > w.remaining()) {
                break;
            }
            if let Some((_, c)) = self.ctrl.pop_front() {
                w.push_raw(&c);
            }
        }
        let allow_new = matches!(
            self.state,
            State::Established | State::ShutdownPending | State::ShutdownReceived
        );
        let sending =
            !w.is_empty() || self.tx.fwd_tsn_needed || self.reconfig_send || self.tx.has_sendable();
        if self.rx.sack_due() || (self.rx.sack_pending() && sending) {
            let room = w.remaining().saturating_sub(4);
            let sack = self.rx.make_sack(room);
            w.push_raw(&sack.encode());
        }
        if self.tx.fwd_tsn_needed {
            let enc = if self.tx.idata {
                let max_entries = self.cfg.mtu.saturating_sub(12 + 8) / 8;
                self.tx.iforward_tsn(max_entries).map(|f| f.encode())
            } else {
                let max_streams = self.cfg.mtu.saturating_sub(12 + 8) / 4;
                self.tx.forward_tsn(max_streams).map(|f| f.encode())
            };
            if let Some(enc) = enc {
                if packet::pad4(enc.len()) <= w.remaining() {
                    w.push_raw(&enc);
                    self.tx.fwd_tsn_needed = false;
                }
            } else {
                self.tx.fwd_tsn_needed = false;
            }
        }
        if self.reconfig_send {
            if let Some(c) = self.reconfig_request_chunk() {
                if packet::pad4(c.len()) <= w.remaining() {
                    w.push_raw(&c);
                    self.reconfig_send = false;
                    self.reconfig_timer = Some(now + self.tx.rto);
                }
            } else {
                self.reconfig_send = false;
            }
        }
        let mut low = std::mem::take(&mut self.low_buf);
        self.tx.fill(now, &mut w, allow_new, &mut low);
        self.emit_low(&mut low);
        self.low_buf = low;
        self.maybe_send_reset(now);
        if w.is_empty() {
            return None;
        }
        Some(w.finish())
    }
}
