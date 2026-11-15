//! The receive side of a connection: unprotecting packets, frames, acknowledgments, loss
//! detection and probe timeouts (RFC 9002), key updates, migration, Retry.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::super::bbr::RateSample;
use super::super::cid::{ConnectionId, LOCAL_CID_LEN};
use super::super::coding::Reader;
use super::super::crypto::{TAG_LEN, initial_keys};
use super::super::frame::{self, Frame, TransportError, code};
use super::super::packet::{
    HeaderError, PacketType, VERSION_1, decode_pn, parse_header, unprotect_header,
};
use super::super::recovery::{GRANULARITY, PACKET_THRESHOLD, PERSISTENT_CONGESTION_THRESHOLD, Rtt};
use super::*;
use crate::bytes::pool;
use crate::types::ConnectionError;

/// The owned parts of a packet header.
struct Pkt {
    ty: PacketType,
    dcid: ConnectionId,
    scid: ConnectionId,
    token: Vec<u8>,
    pn_offset: usize,
    len: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyUse {
    Current,
    Prev,
    Next,
}

enum Outcome {
    Processed,
    /// Could not be decrypted (yet).
    Undecryptable,
}

impl Connection {
    /// Handles a received UDP datagram (possibly several coalesced packets).
    #[cfg_attr(not(any(test, feature = "fuzzing")), allow(dead_code))]
    pub fn handle_datagram(&mut self, now: Instant, from: SocketAddr, data: Vec<u8>) {
        self.handle_shared(now, from, Arc::new(data));
    }

    /// [`Connection::handle_datagram`] on a buffer from [`crate::bytes::pool`] (or any buffer
    /// not shared yet), which goes back to the pool afterwards.
    pub fn handle_shared(&mut self, now: Instant, from: SocketAddr, data: Arc<Vec<u8>>) {
        self.handle_shared_ecn(now, from, 0, data);
    }

    /// [`Connection::handle_shared`] for a datagram that arrived with ECN codepoint `ecn`.
    pub fn handle_shared_ecn(
        &mut self,
        now: Instant,
        from: SocketAddr,
        ecn: u8,
        data: Arc<Vec<u8>>,
    ) {
        if matches!(self.state, State::Drained) {
            return;
        }
        self.stats.udp_rx.datagrams += 1;
        self.stats.udp_rx.bytes += data.len() as u64;
        self.stats.udp_rx.ios += 1;
        if from == self.path.remote {
            self.path.recv_bytes += data.len() as u64;
        }
        self.rx_ecn = ecn;
        self.datagram(now, from, data, true);
        let mut rounds = 0;
        while self.replay && rounds < 4 {
            rounds += 1;
            self.replay = false;
            for (f, e, d) in std::mem::take(&mut self.buffered) {
                self.rx_ecn = e;
                self.datagram(now, f, d, false);
            }
        }
    }

    fn datagram(&mut self, now: Instant, from: SocketAddr, data: Arc<Vec<u8>>, fresh: bool) {
        let total = data.len();
        let mut off = 0;
        let mut first_dcid: Option<ConnectionId> = None;
        let mut any = false;
        let mut data = Some(data);
        while off < total {
            let buf = data.as_ref().map_or(&[][..], |d| &d[off..]);
            let h = match parse_header(buf, LOCAL_CID_LEN) {
                Ok(h) => Pkt {
                    ty: h.ty,
                    dcid: h.dcid,
                    scid: h.scid,
                    token: if matches!(h.ty, PacketType::Retry | PacketType::VersionNegotiation) {
                        h.token.to_vec()
                    } else {
                        Vec::new()
                    },
                    pn_offset: h.pn_offset,
                    len: h.len,
                },
                Err(HeaderError::Invalid | HeaderError::UnsupportedVersion { .. }) => break,
            };
            // Coalesced packets must all be for this connection ID (RFC 9000 section 12.2).
            match first_dcid {
                None => first_dcid = Some(h.dcid),
                Some(d) if d != h.dcid => break,
                _ => {}
            }
            let mut pkt = if off == 0 && h.len == total {
                data.take().unwrap_or_default()
            } else {
                pool::copy(&buf[..h.len])
            };
            off += h.len;
            let outcome = self.packet(now, from, &mut pkt, &h, total);
            pool::recycle(pkt);
            if let Outcome::Processed = outcome {
                any = true;
            }
            if matches!(self.state, State::Drained) {
                return;
            }
        }
        // A datagram moved whole into one packet was checked for a stateless reset there.
        if let Some(d) = data {
            if !any && fresh && self.is_stateless_reset(&d) {
                self.drain_now(ConnectionError::Reset);
            }
            pool::recycle(d);
        }
    }

    fn space_of(ty: PacketType) -> Option<SpaceId> {
        match ty {
            PacketType::Initial => Some(SpaceId::Initial),
            PacketType::Handshake => Some(SpaceId::Handshake),
            PacketType::Short => Some(SpaceId::Data),
            _ => None,
        }
    }

    fn packet(
        &mut self,
        now: Instant,
        from: SocketAddr,
        pkt: &mut Arc<Vec<u8>>,
        h: &Pkt,
        dgram_len: usize,
    ) -> Outcome {
        match h.ty {
            PacketType::VersionNegotiation => {
                self.on_version_negotiation(&h.token);
                return Outcome::Processed;
            }
            PacketType::Retry => {
                self.on_retry(now, &pkt[..], h);
                return Outcome::Processed;
            }
            PacketType::ZeroRtt => return Outcome::Undecryptable,
            _ => {}
        }
        let Some(sid) = Connection::space_of(h.ty) else {
            return Outcome::Undecryptable;
        };
        if self.spaces[sid as usize].discarded {
            return Outcome::Undecryptable;
        }
        if matches!(self.state, State::Draining { .. }) {
            return Outcome::Processed;
        }
        let have_keys = match sid {
            SpaceId::Data => self.one_rtt.is_some(),
            s => self.spaces[s as usize].keys.is_some(),
        };
        if !have_keys {
            if self.buffered.len() < MAX_BUFFERED_PACKETS && !self.is_closed() {
                self.buffered.push((from, self.rx_ecn, pkt.clone()));
            }
            return Outcome::Undecryptable;
        }
        // Header protection.
        let unprot = {
            let hk = match sid {
                SpaceId::Data => self.one_rtt.as_ref().map(|k| &k.remote_hp),
                s => self.spaces[s as usize]
                    .keys
                    .as_ref()
                    .map(|k| &k.remote.header),
            };
            let Some(hk) = hk else {
                return Outcome::Undecryptable;
            };
            // Unshared (fresh from the pool), so this does not copy.
            unprotect_header(hk, &mut Arc::make_mut(pkt)[..h.len], h.pn_offset)
        };
        let Some((pn_len, tpn)) = unprot else {
            return Outcome::Undecryptable;
        };
        let pn = decode_pn(self.spaces[sid as usize].largest_rx, tpn, pn_len);
        let first = pkt[0];
        let header_len = h.pn_offset + pn_len;
        if h.len < header_len + TAG_LEN {
            return Outcome::Undecryptable;
        }
        // Decrypt with the right key (and phase, for 1-RTT).
        let mut used = KeyUse::Current;
        let ok = {
            let (head, rest) = Arc::make_mut(pkt).split_at_mut(header_len);
            let body = &mut rest[..h.len - header_len];
            let (ct, tag) = body.split_at_mut(body.len() - TAG_LEN);
            match sid {
                SpaceId::Data => {
                    let k = self.one_rtt.as_ref().expect("checked above");
                    let phase = first & 0x04 != 0;
                    if phase == k.phase {
                        k.remote.open(pn, head, ct, tag)
                    } else if let (Some((prev, _)), true) = (
                        &k.prev_remote,
                        self.phase_first_rx.is_none_or(|start| pn < start),
                    ) {
                        // A late packet of the previous phase.
                        used = KeyUse::Prev;
                        prev.open(pn, head, ct, tag)
                    } else {
                        used = KeyUse::Next;
                        k.next_remote.open(pn, head, ct, tag)
                    }
                }
                s => self.spaces[s as usize]
                    .keys
                    .as_ref()
                    .is_some_and(|k| k.remote.packet.open(pn, head, ct, tag)),
            }
        };
        if !ok {
            if h.ty == PacketType::Short && h.len == dgram_len && self.is_stateless_reset(&pkt[..])
            {
                self.drain_now(ConnectionError::Reset);
                return Outcome::Processed;
            }
            return Outcome::Undecryptable;
        }
        let reserved = if h.ty.is_long() {
            first & 0x0c
        } else {
            first & 0x18
        };
        if reserved != 0 {
            self.close_transport(
                now,
                TransportError::new(code::PROTOCOL_VIOLATION, "reserved header bits set"),
            );
            return Outcome::Processed;
        }
        if sid == SpaceId::Data {
            match used {
                KeyUse::Next => {
                    // The peer updated its keys: follow (RFC 9001 section 6.2).
                    if !self.confirmed && self.side == Side::Server && !self.tls_done {
                        self.close_transport(
                            now,
                            TransportError::new(
                                code::KEY_UPDATE_ERROR,
                                "key update before the handshake completed",
                            ),
                        );
                        return Outcome::Processed;
                    }
                    let keep = now + self.pto() * 3;
                    if let Some(k) = self.one_rtt.as_mut() {
                        k.update(keep);
                    }
                    self.phase_first_rx = Some(pn);
                    self.phase_first_sent = self.spaces[2].next_pn;
                    self.phase_acked = false;
                }
                KeyUse::Current => {
                    if self.phase_first_rx.is_none_or(|s| pn < s) {
                        self.phase_first_rx = Some(pn);
                    }
                }
                KeyUse::Prev => {}
            }
        }
        // Duplicates.
        {
            let sp = &mut self.spaces[sid as usize];
            if pn < sp.seen_floor || !sp.seen.insert_one(pn) {
                return Outcome::Processed;
            }
            if sp.seen.len() > 512 {
                if let Some(r) = sp.seen.first() {
                    sp.seen_floor = r.end;
                }
                sp.seen.keep_highest(512);
            }
        }
        let ce = self.ecn.on_received(sid as usize, self.rx_ecn);
        self.last_rx = now;
        self.eliciting_since_rx = false;
        self.reset_idle(now);
        if self.side == Side::Server && sid == SpaceId::Handshake {
            // The client got our Initial: its address is validated and Initial keys go.
            self.path.validated = true;
            self.discard_space(now, SpaceId::Initial);
        }
        if self.side == Side::Client && !self.got_server_packet {
            self.got_server_packet = true;
            if let Some(r) = self.remote_cids.get_mut(&0) {
                r.cid = h.scid;
            }
            self.peer_initial_scid = Some(h.scid);
        }
        let payload = Bytes::from_shared(pkt.clone()).slice(header_len..h.len - TAG_LEN);
        if payload.is_empty() {
            self.close_transport(
                now,
                TransportError::new(code::PROTOCOL_VIOLATION, "packet without frames"),
            );
            return Outcome::Processed;
        }
        let migrating = sid == SpaceId::Data && from != self.path.remote;
        let refused = match self.side {
            // A client hears from its server's address only, and from the path it probes.
            Side::Client => !self.probing_from(from),
            Side::Server => !self.cfg.migration || !self.confirmed,
        };
        if migrating && refused {
            // No migration: ignore packets from elsewhere.
            return Outcome::Processed;
        }
        let mut eliciting = false;
        let mut non_probing = false;
        let mut r = Reader::new(&payload);
        while !r.is_empty() {
            let f = match frame::parse(&mut r) {
                Ok(f) => f,
                Err(e) => {
                    self.close_transport(now, e);
                    return Outcome::Processed;
                }
            };
            if sid != SpaceId::Data && !f.allowed_in_handshake() {
                self.close_transport(
                    now,
                    TransportError::new(
                        code::PROTOCOL_VIOLATION,
                        "frame not allowed in this packet type",
                    ),
                );
                return Outcome::Processed;
            }
            eliciting |= f.ack_eliciting();
            non_probing |= !f.probing();
            if let Err(e) = self.on_frame(now, sid, from, &payload, f) {
                self.close_transport(now, e);
                return Outcome::Processed;
            }
            if self.is_closed() {
                return Outcome::Processed;
            }
        }
        // Acknowledgment bookkeeping.
        let sp = &mut self.spaces[sid as usize];
        sp.rx.insert_one(pn);
        sp.rx.keep_highest(MAX_ACK_RANGES * 4);
        let out_of_order = sp.largest_rx.is_some_and(|l| pn != l + 1);
        let is_largest = sp.largest_rx.is_none_or(|l| pn > l);
        if is_largest {
            sp.largest_rx = Some(pn);
            sp.largest_rx_time = Some(now);
        }
        if eliciting {
            sp.rx_new = true;
            sp.eliciting_since_ack += 1;
            // CE-marked packets are acknowledged at once (RFC 9000 section 13.2.1).
            if sid != SpaceId::Data || sp.eliciting_since_ack >= 2 || out_of_order || ce {
                sp.ack_now = true;
            } else if sp.ack_deadline.is_none() {
                sp.ack_deadline = Some(now + LOCAL_MAX_ACK_DELAY);
            }
        }
        if migrating && non_probing && is_largest && self.side == Side::Server {
            self.follow_peer(now, from, dgram_len);
        }
        Outcome::Processed
    }

    fn on_version_negotiation(&mut self, list: &[u8]) {
        if self.side != Side::Client || self.got_server_packet || !self.is_handshaking() {
            return;
        }
        let mut r = Reader::new(list);
        while let Some(v) = r.u32() {
            if v == VERSION_1 {
                // A VN listing our version is bogus (RFC 9000 section 6.2): ignore it.
                return;
            }
        }
        self.drain_now(ConnectionError::VersionMismatch);
    }

    fn on_retry(&mut self, _now: Instant, pkt: &[u8], h: &Pkt) {
        if self.side != Side::Client || self.got_server_packet || self.retry_scid.is_some() {
            return;
        }
        let (body, tag) = pkt.split_at(pkt.len() - TAG_LEN);
        let want = super::super::crypto::retry_tag(&self.orig_dcid, body);
        if !only_crypto::ct_eq(&want, tag) || h.token.is_empty() || h.scid == self.orig_dcid {
            return;
        }
        self.retry_scid = Some(h.scid);
        self.retry_token = h.token.clone();
        if let Some(r) = self.remote_cids.get_mut(&0) {
            r.cid = h.scid;
        }
        self.spaces[0].keys = Some(initial_keys(&h.scid, true));
        // The server kept nothing: everything sent in Initial packets goes again.
        let sent: Vec<Sent> = self.spaces[0].sent.drain().collect();
        for p in sent {
            if p.in_flight {
                self.bytes_in_flight = self.bytes_in_flight.saturating_sub(u64::from(p.size));
            }
            for f in p.frames {
                if let SentFrame::Crypto { off, len } = f {
                    self.spaces[0].crypto_send.on_lost(off..off + len, false);
                }
            }
        }
        self.spaces[0].eliciting_in_flight = 0;
        self.spaces[0].loss_time = None;
        self.pto_count = 0;
    }

    fn on_frame(
        &mut self,
        now: Instant,
        sid: SpaceId,
        from: SocketAddr,
        payload: &Bytes,
        f: Frame<'_>,
    ) -> Result<(), TransportError> {
        match f {
            Frame::Padding | Frame::Ping => {}
            Frame::Ack { ranges, delay, ecn } => self.on_ack(now, sid, &ranges, delay, ecn)?,
            Frame::Crypto { offset, data } => {
                let sp = &mut self.spaces[sid as usize];
                sp.crypto_recv.insert(offset, payload.slice(data), false)?;
                if sp.crypto_recv.buffered() > MAX_CRYPTO_BUFFER {
                    return Err(TransportError::new(
                        code::CRYPTO_BUFFER_EXCEEDED,
                        "too much out-of-order CRYPTO data",
                    ));
                }
                while let Some(chunk) = self.spaces[sid as usize].crypto_recv.pop() {
                    if let Err(e) = self.tls.read_handshake(sid.level(), &chunk) {
                        return Err(TransportError::new(
                            code::CRYPTO_ERROR + u64::from(e.alert.code()),
                            e.to_string(),
                        ));
                    }
                }
                self.drain_tls(now);
            }
            Frame::NewToken(t) => {
                if self.side == Side::Server {
                    return Err(TransportError::new(
                        code::PROTOCOL_VIOLATION,
                        "NEW_TOKEN from a client",
                    ));
                }
                self.ep_events
                    .push_back(EndpointEvent::NewToken(t.to_vec()));
            }
            Frame::Stream {
                id,
                offset,
                data,
                fin,
            } => {
                self.on_stream_frame(id, offset, payload.slice(data), fin)?;
            }
            Frame::ResetStream {
                id,
                code,
                final_size,
            } => self.on_reset_stream(id, code, final_size)?,
            Frame::StopSending { id, code } => self.on_stop_sending(id, code)?,
            Frame::MaxData(m) => {
                if m > self.tx_max_data {
                    self.tx_max_data = m;
                    self.requeue_all_streams();
                }
            }
            Frame::MaxStreamData { id, max } => self.on_max_stream_data(id, max)?,
            Frame::MaxStreams { bidi, max } => self.on_max_streams(bidi, max)?,
            Frame::DataBlocked(_)
            | Frame::StreamDataBlocked { .. }
            | Frame::StreamsBlocked { .. } => {
                if let Frame::StreamDataBlocked { id, .. } = f {
                    self.check_stream_id(id, false)?;
                }
            }
            Frame::NewConnectionId {
                seq,
                retire_prior_to,
                cid,
                token,
            } => {
                self.on_new_cid(seq, retire_prior_to, cid, token)?;
                // A migration may have waited for a connection ID.
                self.try_start_probe(now);
            }
            Frame::RetireConnectionId(seq) => self.on_retire_cid(seq)?,
            Frame::PathChallenge(d) => {
                if self.pending.path_responses.len() < 4 {
                    self.pending.path_responses.push_back((from, d));
                }
            }
            Frame::PathResponse(d) => {
                if self.on_probe_response(now, d) {
                    // The client moved to the probed path.
                } else if self.path.challenge == Some(d) {
                    self.path.validated = true;
                    self.path.challenge = None;
                    self.path.challenge_deadline = None;
                    self.prev_path = None;
                }
            }
            Frame::ConnectionClose {
                app,
                code,
                frame: _,
                reason,
            } => {
                let reason = reason.to_vec();
                let e = if app {
                    ConnectionError::ApplicationClosed { code, reason }
                } else {
                    ConnectionError::ConnectionClosed { code, reason }
                };
                self.enter_draining(now, e);
            }
            Frame::HandshakeDone => {
                if self.side == Side::Server {
                    return Err(TransportError::new(
                        code::PROTOCOL_VIOLATION,
                        "HANDSHAKE_DONE from a client",
                    ));
                }
                self.confirm(now);
            }
            Frame::Datagram(r) => {
                if self.cfg.transport.datagram_receive_buffer_size.is_none() {
                    return Err(TransportError::new(
                        code::PROTOCOL_VIOLATION,
                        "DATAGRAM frames not accepted",
                    ));
                }
                self.events.push_back(Event::Datagram(payload.slice(r)));
            }
        }
        Ok(())
    }

    // ---- connection IDs ----

    fn on_new_cid(
        &mut self,
        seq: u64,
        rpt: u64,
        cid: ConnectionId,
        token: ResetToken,
    ) -> Result<(), TransportError> {
        if self.remote_cid().is_empty() {
            return Err(TransportError::new(
                code::PROTOCOL_VIOLATION,
                "NEW_CONNECTION_ID with zero-length IDs",
            ));
        }
        if let Some(old) = self.remote_cids.get(&seq) {
            if old.cid != cid {
                return Err(TransportError::new(
                    code::PROTOCOL_VIOLATION,
                    "connection id sequence reused",
                ));
            }
            return Ok(());
        }
        if seq < self.remote_retire_prior_to {
            // Already retired by an earlier frame.
            self.pending.retire_cids.push(seq);
            return Ok(());
        }
        self.remote_cids.insert(
            seq,
            RemoteCid {
                cid,
                token: Some(token),
            },
        );
        if rpt > self.remote_retire_prior_to {
            self.remote_retire_prior_to = rpt;
            let old: Vec<u64> = self.remote_cids.range(..rpt).map(|(s, _)| *s).collect();
            for s in old {
                self.remote_cids.remove(&s);
                self.pending.retire_cids.push(s);
            }
            if self.remote_seq < rpt {
                if let Some((&s, _)) = self.remote_cids.iter().next() {
                    self.remote_seq = s;
                }
            }
        }
        if self.remote_cids.len() as u64 > LOCAL_CID_LIMIT {
            return Err(TransportError::new(
                code::CONNECTION_ID_LIMIT_ERROR,
                "too many connection ids",
            ));
        }
        Ok(())
    }

    fn on_retire_cid(&mut self, seq: u64) -> Result<(), TransportError> {
        if seq >= self.next_local_seq {
            return Err(TransportError::new(
                code::PROTOCOL_VIOLATION,
                "retiring an unissued connection id",
            ));
        }
        if let Some(cid) = self.local_cids.remove(&seq) {
            self.ep_events.push_back(EndpointEvent::RetireCid(cid));
            if self.confirmed {
                self.issue_cids();
            }
        }
        Ok(())
    }

    // ---- migration ----

    /// The client's address changed (server): validate it and follow.
    fn follow_peer(&mut self, now: Instant, from: SocketAddr, dgram_len: usize) {
        let same_ip = from.ip() == self.path.remote.ip();
        let mut p = Path::new(from, false);
        p.recv_bytes = dgram_len as u64;
        let mut d = [0u8; 8];
        self.rng.fill(&mut d);
        p.challenge = Some(d);
        p.challenge_sent = Some(now);
        p.challenge_deadline = Some(now + self.rtt.pto_base() * 2);
        self.pending.path_challenge = true;
        self.prev_path = Some(std::mem::replace(&mut self.path, p));
        if !same_ip {
            self.cc.reset();
            self.rtt = Rtt::new(self.cfg.transport.initial_rtt);
        }
        self.ecn.new_path(self.cfg.ecn());
        // A fresh connection ID for the new path, if the peer gave us one (RFC 9000 9.5).
        if let Some((&s, _)) = self.remote_cids.range(self.remote_seq + 1..).next() {
            let old = self.remote_seq;
            self.remote_seq = s;
            self.remote_cids.remove(&old);
            self.pending.retire_cids.push(old);
        }
    }

    // ---- acknowledgments and loss detection ----

    fn on_ack(
        &mut self,
        now: Instant,
        sid: SpaceId,
        ranges: &[std::ops::Range<u64>],
        delay: u64,
        ecn: Option<[u64; 3]>,
    ) -> Result<(), TransportError> {
        let Some(largest) = ranges.first().map(|r| r.end - 1) else {
            return Ok(());
        };
        if largest >= self.spaces[sid as usize].next_pn {
            return Err(TransportError::new(
                code::PROTOCOL_VIOLATION,
                "ACK of an unsent packet",
            ));
        }
        let mut newly: Vec<(u64, Sent)> = Vec::new();
        let raised;
        {
            let sp = &mut self.spaces[sid as usize];
            for r in ranges {
                sp.sent.remove_range(r.clone(), &mut newly);
            }
            if newly.is_empty() {
                return Ok(());
            }
            raised = sp.largest_acked.is_none_or(|l| largest > l);
            if raised {
                sp.largest_acked = Some(largest);
            }
        }
        // ECN validation, on ACK frames that raise the largest acknowledged only (older ones
        // carry older counts, RFC 9000 section 13.4.2.1).
        if raised {
            let marked = newly.iter().filter(|(_, p)| p.ecn).count() as u64;
            let largest_sent = newly
                .iter()
                .find(|(pn, _)| *pn == largest)
                .map(|(_, p)| p.time);
            if let ecn::AckEcn::Congestion(ce) = self.ecn.on_ack(sid as usize, marked, ecn) {
                self.cc.on_lost(ce * u64::from(self.mtu));
                if let Some(t) = largest_sent {
                    let before = self.cc.events;
                    self.cc.on_congestion(now, t);
                    if self.cc.events > before {
                        self.stats.ecn_ce_events += 1;
                    }
                }
            }
        }
        // An RTT sample from the largest acknowledged, if newly acknowledged.
        let mut rtt_sample = None;
        if let Some((_, p)) = newly.iter().find(|(pn, _)| *pn == largest) {
            if newly.iter().any(|(_, p)| p.ack_eliciting) {
                let latest = now.saturating_duration_since(p.time);
                let mut ack_delay = if sid == SpaceId::Data {
                    Duration::from_micros(
                        delay.saturating_mul(1 << self.peer.ack_delay_exponent.min(20)),
                    )
                } else {
                    Duration::ZERO
                };
                if self.confirmed {
                    ack_delay = ack_delay.min(Duration::from_millis(self.peer.max_ack_delay));
                }
                self.rtt.update(latest, ack_delay);
                rtt_sample = Some(latest);
                self.first_rtt_sample.get_or_insert(now);
                self.spaces[sid as usize].largest_acked_time = Some(p.time);
            }
        }
        let app_limited = self.app_limited;
        // The delivery-rate sample of this acknowledgment: from the newest packet it covers.
        let mut rs = RateSample {
            total_delivered: 0,
            prior_delivered: 0,
            delivered: 0,
            interval: Duration::ZERO,
            acked: 0,
            app_limited: false,
            rtt: rtt_sample,
        };
        let mut newest: Option<(Instant, Instant, Instant)> = None;
        for (pn, mut p) in newly {
            if p.in_flight && !p.mtu_probe {
                let d = &mut self.dlv;
                d.delivered += u64::from(p.size);
                d.delivered_time = now;
                rs.acked += u64::from(p.size);
                if newest.is_none() || p.delivered >= rs.prior_delivered {
                    rs.prior_delivered = p.delivered;
                    rs.app_limited = p.app_limited;
                    newest = Some((p.time, p.first_sent, p.delivered_time));
                    d.first_sent = p.time;
                }
            }
            if p.in_flight {
                self.bytes_in_flight = self.bytes_in_flight.saturating_sub(u64::from(p.size));
                if p.ack_eliciting {
                    let sp = &mut self.spaces[sid as usize];
                    sp.eliciting_in_flight = sp.eliciting_in_flight.saturating_sub(1);
                }
            }
            if p.mtu_probe {
                self.on_mtu_probe_acked(p.size);
            } else if p.in_flight {
                self.cc
                    .on_ack(now, p.time, u64::from(p.size), &self.rtt, app_limited);
            }
            if sid == SpaceId::Data && pn >= self.phase_first_sent {
                self.phase_acked = true;
            }
            let mut frames = std::mem::take(&mut p.frames);
            for f in frames.drain(..) {
                self.on_frame_acked(sid, f);
            }
            self.recycle_frames(frames);
        }
        if let Some((sent, first_sent, delivered_time)) = newest {
            let d = &mut self.dlv;
            if d.app_limited_until != 0 && d.delivered > d.app_limited_until {
                d.app_limited_until = 0;
            }
            rs.total_delivered = d.delivered;
            rs.delivered = d.delivered - rs.prior_delivered;
            let send_elapsed = sent.saturating_duration_since(first_sent);
            let ack_elapsed = now.saturating_duration_since(delivered_time);
            rs.interval = send_elapsed.max(ack_elapsed);
        }
        self.detect_lost(now, sid);
        if newest.is_some() {
            self.cc.on_ack_event(now, &rs, self.bytes_in_flight);
        }
        self.pto_count = 0;
        Ok(())
    }

    /// Keeps an emptied frame list for a later packet (a few dozen at most).
    fn recycle_frames(&mut self, frames: Vec<SentFrame>) {
        if self.spare_frames.len() < 64 && frames.capacity() > 0 {
            self.spare_frames.push(frames);
        }
    }

    fn on_frame_acked(&mut self, sid: SpaceId, f: SentFrame) {
        match f {
            SentFrame::Stream { id, off, len, fin } => self.on_stream_acked(id, off, len, fin),
            SentFrame::Crypto { off, len } => {
                self.spaces[sid as usize]
                    .crypto_send
                    .on_ack(off..off + len, false);
            }
            SentFrame::Ack(largest) => {
                let sp = &mut self.spaces[sid as usize];
                sp.rx.remove_below(largest + 1);
                if sp.rx.is_empty() {
                    sp.rx_new = false;
                }
            }
            SentFrame::ResetStream(id) => self.on_reset_acked(id),
            _ => {}
        }
    }

    fn on_frame_lost(&mut self, sid: SpaceId, f: SentFrame) {
        match f {
            SentFrame::Stream { id, off, len, fin } => self.on_stream_lost(id, off, len, fin),
            SentFrame::Crypto { off, len } => {
                self.spaces[sid as usize]
                    .crypto_send
                    .on_lost(off..off + len, false);
            }
            SentFrame::Ack(_) | SentFrame::PathChallenge => {}
            SentFrame::ResetStream(id) => {
                if self.streams.get(&id).is_some_and(|s| {
                    s.send
                        .as_ref()
                        .is_some_and(|x| x.reset.is_some_and(|r| !r.2))
                }) {
                    self.pending.reset_stream.insert(id);
                }
            }
            SentFrame::StopSending(id) => {
                if self
                    .streams
                    .get(&id)
                    .is_some_and(|s| s.recv.as_ref().is_some_and(|r| !r.done))
                {
                    self.pending.stop_sending.insert(id);
                }
            }
            SentFrame::MaxData => self.pending.max_data = true,
            SentFrame::MaxStreamData(id) => {
                if self
                    .streams
                    .get(&id)
                    .is_some_and(|s| s.recv.as_ref().is_some_and(|r| !r.done))
                {
                    self.pending.max_stream_data.insert(id);
                }
            }
            SentFrame::MaxStreams(bidi) => {
                if bidi {
                    self.pending.max_streams_bidi = true;
                } else {
                    self.pending.max_streams_uni = true;
                }
            }
            SentFrame::DataBlocked | SentFrame::StreamDataBlocked | SentFrame::StreamsBlocked => {}
            SentFrame::NewCid(seq) => {
                if self.local_cids.contains_key(&seq) {
                    self.pending.new_cids.push(seq);
                }
            }
            SentFrame::RetireCid(seq) => self.pending.retire_cids.push(seq),
            SentFrame::HandshakeDone => self.pending.handshake_done = true,
            SentFrame::NewToken(t) => self.pending.new_token = Some(t),
        }
    }

    pub(super) fn detect_lost(&mut self, now: Instant, sid: SpaceId) {
        let loss_delay = self.rtt.loss_delay();
        let sp = &mut self.spaces[sid as usize];
        let Some(largest) = sp.largest_acked else {
            return;
        };
        let lost_send_time = now.checked_sub(loss_delay);
        sp.loss_time = None;
        let mut lost: Vec<u64> = Vec::new();
        for (pn, p) in sp.sent.up_to(largest) {
            if lost_send_time.is_some_and(|t| p.time <= t) || largest >= pn + PACKET_THRESHOLD {
                lost.push(pn);
            } else {
                let t = p.time + loss_delay;
                sp.loss_time = Some(sp.loss_time.map_or(t, |l| l.min(t)));
            }
        }
        if lost.is_empty() {
            return;
        }
        let mut latest_lost: Option<Instant> = None;
        let mut run: Vec<(u64, Instant)> = Vec::new();
        let mut persistent = false;
        let pc = (self.rtt.smoothed
            + (self.rtt.var * 4).max(GRANULARITY)
            + Duration::from_millis(self.peer.max_ack_delay))
            * PERSISTENT_CONGESTION_THRESHOLD;
        let mut packets = Vec::with_capacity(lost.len());
        for pn in lost {
            if let Some(p) = self.spaces[sid as usize].sent.remove(pn) {
                packets.push((pn, p));
            }
        }
        for (pn, mut p) in packets {
            if p.in_flight {
                self.bytes_in_flight = self.bytes_in_flight.saturating_sub(u64::from(p.size));
                if p.ack_eliciting {
                    let sp = &mut self.spaces[sid as usize];
                    sp.eliciting_in_flight = sp.eliciting_in_flight.saturating_sub(1);
                }
            }
            if p.ecn {
                self.ecn.on_marked_lost();
            }
            if p.mtu_probe {
                self.on_mtu_probe_lost(p.size);
            } else {
                if p.in_flight {
                    // Lost ACK-only packets are not counted: nothing is resent for them.
                    self.stats.lost_packets += 1;
                    self.stats.lost_bytes += u64::from(p.size);
                    self.cc.on_lost(u64::from(p.size));
                    latest_lost = Some(latest_lost.map_or(p.time, |l| l.max(p.time)));
                }
                if p.ack_eliciting && self.first_rtt_sample.is_some_and(|f| p.time >= f) {
                    if run.last().is_some_and(|&(last, _)| last + 1 != pn) {
                        run.clear();
                    }
                    run.push((pn, p.time));
                    if let (Some(a), Some(b)) = (run.first(), run.last()) {
                        if b.1.saturating_duration_since(a.1) > pc {
                            persistent = true;
                        }
                    }
                }
            }
            let mut frames = std::mem::take(&mut p.frames);
            for f in frames.drain(..) {
                self.on_frame_lost(sid, f);
            }
            self.recycle_frames(frames);
        }
        if let Some(t) = latest_lost {
            self.cc.on_congestion(now, t);
            if persistent {
                self.cc.on_persistent_congestion();
            }
        }
    }

    /// The loss detection timer: (when, which space).
    pub(super) fn loss_timer(&self) -> Option<(Instant, SpaceId)> {
        let mut best: Option<(Instant, SpaceId)> = None;
        for id in SpaceId::ALL {
            if let Some(t) = self.spaces[id as usize].loss_time {
                if best.is_none_or(|b| t < b.0) {
                    best = Some((t, id));
                }
            }
        }
        if best.is_some() {
            return best;
        }
        if self.side == Side::Server && !self.path.validated && self.path.budget() == 0 {
            // Blocked by the amplification limit: nothing could be sent anyway.
            return None;
        }
        let backoff = 1u32 << self.pto_count.min(10);
        let base = self.rtt.pto_base();
        let any = self.spaces.iter().any(|s| s.eliciting_in_flight > 0);
        if !any {
            // The client keeps probing until the server validated its address
            // (RFC 9002 section 6.2.2.1), so the handshake cannot deadlock.
            let unvalidated = self.side == Side::Client
                && !self.confirmed
                && self.spaces[1].largest_acked.is_none();
            if unvalidated && !self.is_closed() {
                let anchor = self
                    .last_eliciting_sent_any
                    .unwrap_or(self.last_rx)
                    .max(self.last_rx);
                let id = if self.spaces[1].keys.is_some() {
                    SpaceId::Handshake
                } else {
                    SpaceId::Initial
                };
                return Some((anchor + base * backoff, id));
            }
            return None;
        }
        for id in SpaceId::ALL {
            let sp = &self.spaces[id as usize];
            if sp.eliciting_in_flight == 0 || sp.discarded {
                continue;
            }
            let mut d = base * backoff;
            if id == SpaceId::Data {
                if !self.confirmed {
                    continue;
                }
                d += Duration::from_millis(self.peer.max_ack_delay) * backoff;
            }
            if let Some(last) = sp.last_eliciting_sent {
                let t = last + d;
                if best.is_none_or(|b| t < b.0) {
                    best = Some((t, id));
                }
            }
        }
        best
    }

    pub(super) fn on_loss_timer(&mut self, now: Instant, sid: SpaceId) {
        if self.spaces[sid as usize]
            .loss_time
            .is_some_and(|t| t <= now)
        {
            self.detect_lost(now, sid);
            return;
        }
        self.pto_count += 1;
        self.ecn.on_pto();
        let any = self.spaces.iter().any(|s| s.eliciting_in_flight > 0);
        if !any {
            let sp = &mut self.spaces[sid as usize];
            sp.probes = 1;
            // Anti-deadlock probes carry the handshake data again.
            self.requeue_for_probe(sid, true);
            return;
        }
        self.spaces[sid as usize].probes = 2;
        self.requeue_for_probe(sid, sid != SpaceId::Data);
    }

    /// Queues the data of in-flight packets again so a probe carries it (they stay in flight).
    fn requeue_for_probe(&mut self, sid: SpaceId, all: bool) {
        let frames: Vec<SentFrame> = {
            let sp = &self.spaces[sid as usize];
            let take = if all { usize::MAX } else { 2 };
            sp.sent
                .values()
                .filter(|p| p.ack_eliciting)
                .take(take)
                .flat_map(|p| p.frames.iter().cloned())
                .collect()
        };
        for f in frames {
            match f {
                SentFrame::Stream { .. } | SentFrame::Crypto { .. } => self.on_frame_lost(sid, f),
                _ => {}
            }
        }
        if sid == SpaceId::Handshake || sid == SpaceId::Initial {
            // The peer may have lost all of it: resend unacknowledged CRYPTO data from the start.
            let sp = &mut self.spaces[sid as usize];
            let end = sp.crypto_send.sent();
            sp.crypto_send.on_lost(0..end, false);
        }
    }

    fn on_mtu_probe_acked(&mut self, size: u16) {
        self.mtu_in_flight = None;
        if size > self.mtu {
            self.mtu = size;
            self.cc.set_mtu(size);
            self.stats.current_mtu = size;
        }
        self.mtu_probe = if self.mtu_upper.saturating_sub(self.mtu) >= 20 {
            Some((self.next_probe_size(), 0))
        } else {
            None
        };
    }

    fn on_mtu_probe_lost(&mut self, size: u16) {
        self.mtu_in_flight = None;
        let Some((s, tries)) = self.mtu_probe else {
            return;
        };
        if s != size {
            return;
        }
        if tries + 1 < 3 {
            self.mtu_probe = Some((s, tries + 1));
            return;
        }
        self.mtu_upper = size - 1;
        self.mtu_probe = if self.mtu_upper.saturating_sub(self.mtu) >= 20 {
            Some((self.next_probe_size(), 0))
        } else {
            None
        };
    }

    pub(super) fn next_probe_size(&self) -> u16 {
        // Try the upper bound first (the common case: a 1500-byte Ethernet path), then bisect.
        if self.mtu_probe.is_none() && self.mtu_upper == MTU_PROBE_MAX.max(self.mtu) {
            return self.mtu_upper;
        }
        self.mtu + (self.mtu_upper - self.mtu).div_ceil(2)
    }
}
