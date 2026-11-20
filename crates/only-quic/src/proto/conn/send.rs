//! The send side of a connection: building and protecting packets, coalescing them into
//! datagrams and batching full-size datagrams for GSO, congestion control, pacing, the
//! anti-amplification limit, padding rules, path MTU probes and CONNECTION_CLOSE.

use std::net::SocketAddr;
use std::time::Instant;

use super::super::coding::varint_len;
use super::super::crypto::TAG_LEN;
use super::super::frame::{self, ty};
use super::super::packet::{MIN_INITIAL_SIZE, PacketBuilder, PacketType, pn_len};
use super::*;

/// Room an ACK frame needs at most (bounded number of ranges).
fn ack_room(sp: &Space) -> usize {
    frame::ack_size(&sp.rx, u64::from(u32::MAX), MAX_ACK_RANGES)
}

impl Connection {
    /// The next datagram(s) to send, up to `max_datagrams` full-size ones for one GSO call.
    pub fn poll_transmit(&mut self, now: Instant, max_datagrams: usize) -> Option<Transmit> {
        self.resume_tls(now);
        match &self.state {
            State::Drained | State::Draining { .. } => return None,
            State::Closing { resend, .. } => {
                if !*resend {
                    return None;
                }
                return self.write_close();
            }
            _ => {}
        }
        // PATH_RESPONSE to an address other than the current path goes out alone.
        if let Some(i) = self
            .pending
            .path_responses
            .iter()
            .position(|(a, _)| *a != self.path.remote)
        {
            if let Some((to, data)) = self.pending.path_responses.remove(i) {
                if let Some(t) = self.write_path_response(now, to, data) {
                    return Some(t);
                }
            }
        }
        if let Some(t) = self.write_probe(now) {
            return Some(t);
        }
        if let Some(t) = self.write_mtu_probe(now) {
            return Some(t);
        }
        let max = max_datagrams.max(1);
        // One ECN marking for the whole batch (the I/O sends it with one codepoint).
        self.tx_ecn = self.ecn.marking();
        let mut buf = Vec::with_capacity(usize::from(self.mtu) * max);
        let mut seg = 0usize;
        let mut n = 0usize;
        while n < max {
            let start = buf.len();
            let limit = if n == 0 { usize::from(self.mtu) } else { seg };
            let Some(long) = self.write_datagram(now, &mut buf, limit) else {
                break;
            };
            let len = buf.len() - start;
            n += 1;
            if n == 1 {
                seg = len;
            }
            // Batch only full-size, short-header datagrams.
            if long || len < limit || len < seg {
                break;
            }
        }
        if n == 0 {
            return None;
        }
        self.stats.udp_tx.datagrams += n as u64;
        self.stats.udp_tx.bytes += buf.len() as u64;
        self.stats.udp_tx.ios += 1;
        Some(Transmit {
            dest: self.path.remote,
            segment_size: (n > 1).then_some(seg),
            data: buf,
            ecn: if self.tx_ecn {
                ecn::cp::ECT0
            } else {
                ecn::cp::NOT_ECT
            },
            probe: false,
        })
    }

    /// The application data space sends 0-RTT packets (client, before the 1-RTT keys).
    fn zero_rtt_mode(&self) -> bool {
        self.one_rtt.is_none() && self.zero_rtt.is_some() && self.side == Side::Client
    }

    fn space_ready(&self, sid: SpaceId) -> bool {
        match sid {
            SpaceId::Data => self.one_rtt.is_some() || self.zero_rtt_mode(),
            s => !self.spaces[s as usize].discarded && self.spaces[s as usize].keys.is_some(),
        }
    }

    /// Whether `sid` has something to send (an estimate: a packet may still come out empty).
    fn space_wants(&self, sid: SpaceId, now: Instant, blocked: bool) -> bool {
        if !self.space_ready(sid) {
            return false;
        }
        let sp = &self.spaces[sid as usize];
        if sp.ack_due(now) && !sp.rx.is_empty() {
            return true;
        }
        self.space_has_data(sid, blocked)
    }

    /// Whether something other than an acknowledgment waits to be sent (ignoring congestion
    /// control and pacing, which may still hold it back). The I/O layer acknowledges once per
    /// receive batch, but sends data as soon as there is some.
    pub fn wants_transmit(&self) -> bool {
        match &self.state {
            State::Drained | State::Draining { .. } => false,
            State::Closing { resend, .. } => *resend,
            // (An MTU probe waits for the end of the batch.)
            _ => SpaceId::ALL
                .into_iter()
                .any(|s| self.space_ready(s) && self.space_has_data(s, false)),
        }
    }

    /// [`Connection::space_wants`] without the acknowledgment.
    fn space_has_data(&self, sid: SpaceId, blocked: bool) -> bool {
        let sp = &self.spaces[sid as usize];
        if blocked && sp.probes == 0 {
            return false;
        }
        if sp.probes > 0 || sp.crypto_send.wants_send(u64::MAX) {
            return true;
        }
        if sid != SpaceId::Data {
            return false;
        }
        if self.zero_rtt_mode() {
            // Stream data only.
            return !self.send_queue.is_empty();
        }
        let p = &self.pending;
        p.ping
            || p.max_data
            || p.handshake_done
            || p.max_streams_bidi
            || p.max_streams_uni
            || p.data_blocked
            || p.streams_blocked_bidi
            || p.streams_blocked_uni
            || p.path_challenge
            || p.new_token.is_some()
            || !p.max_stream_data.is_empty()
            || !p.reset_stream.is_empty()
            || !p.stop_sending.is_empty()
            || !p.new_cids.is_empty()
            || !p.retire_cids.is_empty()
            || !p.stream_data_blocked.is_empty()
            || !p.path_responses.is_empty()
            || !self.dgram_queue.is_empty()
            || !self.send_queue.is_empty()
    }

    /// Writes one datagram (coalescing packets of several spaces) into `buf`; returns whether
    /// it holds long-header packets, or `None` if there was nothing to send.
    fn write_datagram(&mut self, now: Instant, buf: &mut Vec<u8>, limit: usize) -> Option<bool> {
        let start = buf.len();
        let budget = self.path.budget();
        let limit = (limit as u64).min(budget) as usize;
        if limit < 48 {
            return None;
        }
        let probing = self.spaces.iter().any(|s| s.probes > 0);
        let cwnd_blocked = !probing && self.bytes_in_flight + u64::from(self.mtu) > self.cc.window;
        if cwnd_blocked {
            self.app_limited = false;
        }
        let mut blocked = cwnd_blocked;
        if !blocked && !probing {
            if self.pacing_until.is_some_and(|p| now < p) {
                blocked = true;
            } else if let Some(at) = self.pacer.delay(
                now,
                limit as u64,
                u64::from(self.mtu),
                self.cc.window,
                self.rtt.smoothed,
                self.cc.pacing_rate(),
            ) {
                self.pacing_until = Some(at);
                blocked = true;
            }
        }
        let mut wants = [SpaceId::Data; 3];
        let mut nwants = 0;
        for s in SpaceId::ALL {
            if self.space_wants(s, now, blocked) {
                wants[nwants] = s;
                nwants += 1;
            }
        }
        let wants = &wants[..nwants];
        if wants.is_empty() {
            if !blocked {
                self.app_limited = true;
                // Rate samples are application-limited until what is in flight now is
                // delivered.
                self.dlv.app_limited_until = (self.dlv.delivered + self.bytes_in_flight).max(1);
            }
            return None;
        }
        // Client datagrams with Initial packets, and server datagrams with ack-eliciting
        // Initial packets, are padded to 1200 bytes (RFC 9000 section 14.1).
        let mut pad = self.side == Side::Client && wants.contains(&SpaceId::Initial);
        let mut long = false;
        let mut wrote_hs = false;
        for (i, &sid) in wants.iter().enumerate() {
            let last = i + 1 == wants.len();
            if self.side == Side::Server && sid == SpaceId::Initial {
                let sp = &self.spaces[0];
                pad |= sp.probes > 0 || (!blocked && sp.crypto_send.wants_send(u64::MAX));
            }
            let pad_end = (pad && last).then(|| start + MIN_INITIAL_SIZE.min(limit));
            let zero = sid == SpaceId::Data && self.zero_rtt_mode();
            if let Some(w) = self.write_packet(now, sid, buf, start, limit, blocked, pad_end) {
                long |= sid != SpaceId::Data || zero;
                wrote_hs |= sid == SpaceId::Handshake;
                let _ = w;
            }
        }
        let len = buf.len() - start;
        if len == 0 {
            return None;
        }
        if pad && len < MIN_INITIAL_SIZE.min(limit) {
            // A predicted later packet came out empty: pad the datagram itself (receivers drop
            // what does not parse as a packet).
            buf.resize(start + MIN_INITIAL_SIZE.min(limit), 0);
        }
        self.path.sent_bytes += (buf.len() - start) as u64;
        if wrote_hs && self.side == Side::Client {
            // A client discards Initial keys once it sends a Handshake packet.
            self.discard_space(now, SpaceId::Initial);
        }
        Some(long)
    }

    /// Writes one packet of space `sid`; `None` if it had nothing to carry.
    #[allow(clippy::too_many_arguments)]
    fn write_packet(
        &mut self,
        now: Instant,
        sid: SpaceId,
        buf: &mut Vec<u8>,
        dgram_start: usize,
        limit: usize,
        blocked: bool,
        pad_end: Option<usize>,
    ) -> Option<bool> {
        let pkt_start = buf.len();
        let dcid = self.remote_cid();
        let scid = self.local_cid();
        let zero = sid == SpaceId::Data && self.zero_rtt_mode();
        let (pn, pnl) = {
            let sp = &self.spaces[sid as usize];
            (sp.next_pn, pn_len(sp.next_pn, sp.largest_acked))
        };
        let b = match sid {
            SpaceId::Initial => {
                let token = if self.side == Side::Client {
                    self.retry_token.clone()
                } else {
                    Vec::new()
                };
                PacketBuilder::long(
                    buf,
                    self.version,
                    PacketType::Initial,
                    &dcid,
                    &scid,
                    &token,
                    pn,
                    pnl,
                )
            }
            SpaceId::Handshake => PacketBuilder::long(
                buf,
                self.version,
                PacketType::Handshake,
                &dcid,
                &scid,
                &[],
                pn,
                pnl,
            ),
            // 0-RTT stays in the first version after a compatible switch (RFC 9369 4.1).
            SpaceId::Data if zero => PacketBuilder::long(
                buf,
                self.orig_version.unwrap_or(self.version),
                PacketType::ZeroRtt,
                &dcid,
                &scid,
                &[],
                pn,
                pnl,
            ),
            SpaceId::Data => {
                let phase = self.one_rtt.as_ref().is_some_and(|k| k.phase);
                PacketBuilder::short(buf, &dcid, phase, pn, pnl)
            }
        };
        let max_end = (dgram_start + limit).saturating_sub(TAG_LEN);
        if buf.len() + 8 > max_end {
            buf.truncate(pkt_start);
            return None;
        }
        let mut frames = self.spare_frames.pop().unwrap_or_default();
        let mut eliciting = false;
        let mut path_frame = false;
        let mut fill = false;
        // ACK first.
        {
            let counts = self.ecn.report(sid as usize);
            let sp = &mut self.spaces[sid as usize];
            if !zero && sp.rx_new && !sp.rx.is_empty() && buf.len() + ack_room(sp) <= max_end {
                let delay = if sid == SpaceId::Data {
                    let d = sp
                        .largest_rx_time
                        .map_or(0, |t| now.saturating_duration_since(t).as_micros() as u64);
                    d >> LOCAL_ACK_DELAY_EXPONENT
                } else {
                    0
                };
                frame::put_ack_ecn(buf, &sp.rx, delay, MAX_ACK_RANGES, counts);
                if let Some(l) = sp.rx.max() {
                    frames.push(SentFrame::Ack(l));
                }
                sp.rx_new = false;
                sp.ack_now = false;
                sp.ack_deadline = None;
                sp.eliciting_since_ack = 0;
            }
        }
        let allow = !blocked || self.spaces[sid as usize].probes > 0;
        if allow && zero {
            // 0-RTT: stream data (RFC 9000 section 12.4 allows more; nothing else is needed).
            let before = frames.len();
            self.write_streams(buf, max_end, &mut frames, &mut eliciting);
            fill = frames.len() > before && max_end.saturating_sub(buf.len()) < 32;
            if self.spaces[sid as usize].probes > 0 && !eliciting && buf.len() < max_end {
                buf.push(ty::PING as u8);
                eliciting = true;
            }
        } else if allow {
            if sid == SpaceId::Data {
                path_frame = self.write_control(buf, max_end, &mut frames, &mut eliciting);
            }
            self.write_crypto(sid, buf, max_end, &mut frames, &mut eliciting);
            if sid == SpaceId::Data {
                self.write_datagrams(buf, max_end, &mut eliciting);
                let before = frames.len();
                self.write_streams(buf, max_end, &mut frames, &mut eliciting);
                // A packet that ran out of room for stream data is padded to the full size, so
                // the datagram can lead a GSO batch of equal-size segments.
                fill = frames.len() > before && max_end.saturating_sub(buf.len()) < 32;
            }
            let ping =
                self.spaces[sid as usize].probes > 0 || (sid == SpaceId::Data && self.pending.ping);
            if ping && !eliciting && buf.len() < max_end {
                buf.push(ty::PING as u8);
                eliciting = true;
            }
            if sid == SpaceId::Data && eliciting {
                self.pending.ping = false;
            }
        }
        let header_end = b.pn_offset + b.pn_len;
        if buf.len() == header_end {
            buf.truncate(pkt_start);
            return None;
        }
        // Padding: enough for the header protection sample, the datagram minimum, and
        // 1200 bytes around path validation frames (RFC 9000 section 8.2.1).
        let mut min_end = header_end + b.min_payload();
        if let Some(e) = pad_end {
            min_end = min_end.max(e.saturating_sub(TAG_LEN));
        }
        if path_frame {
            min_end =
                min_end.max((dgram_start + MIN_INITIAL_SIZE.min(limit)).saturating_sub(TAG_LEN));
        }
        if fill {
            min_end = max_end;
        }
        let padded = buf.len() < min_end.min(max_end);
        if padded {
            buf.resize(min_end.min(max_end).max(header_end + b.min_payload()), 0);
        }
        // Seal.
        match sid {
            SpaceId::Data if zero => {
                let k = self.zero_rtt.as_ref()?;
                b.finish(buf, &k.packet, &k.header);
                self.zero_rtt_last_pn = Some(pn);
            }
            SpaceId::Data => {
                let k = self.one_rtt.as_ref()?;
                b.finish(buf, &k.local, &k.local_hp);
                if !self.tls_done {
                    // 0.5-RTT (server answering 0-RTT).
                    self.zero_rtt_last_pn = Some(pn);
                }
            }
            s => {
                let k = self.spaces[s as usize].keys.as_ref()?;
                b.finish(buf, &k.local.packet, &k.local.header);
            }
        }
        let size = (buf.len() - pkt_start) as u16;
        let in_flight = eliciting || padded;
        if self.tx_ecn {
            self.ecn.on_marked_sent(sid as usize);
        }
        // Delivery-rate state, for a controller that samples it (BBR).
        let (delivered, delivered_age, first_sent_age, app_limited) =
            if self.cc.wants_rate_samples() {
                if in_flight && self.bytes_in_flight == 0 {
                    // A new flight: its rate intervals start now.
                    self.dlv.first_sent = now;
                    self.dlv.delivered_time = now;
                }
                let d = self.dlv;
                (
                    d.delivered,
                    age_us(now, d.delivered_time),
                    age_us(now, d.first_sent),
                    d.app_limited_until != 0,
                )
            } else {
                (0, 0, 0, false)
            };
        let sp = &mut self.spaces[sid as usize];
        sp.next_pn += 1;
        if eliciting {
            sp.last_eliciting_sent = Some(now);
            sp.eliciting_in_flight += 1;
            if sp.probes > 0 {
                sp.probes -= 1;
            }
        }
        sp.sent.insert(
            pn,
            Sent {
                time: now,
                size,
                ack_eliciting: eliciting,
                in_flight,
                mtu_probe: false,
                ecn: self.tx_ecn,
                delivered,
                delivered_age,
                first_sent_age,
                app_limited,
                frames,
            },
        );
        if in_flight {
            self.bytes_in_flight += u64::from(size);
            self.pacer.on_sent(u64::from(size));
        }
        if eliciting {
            self.last_eliciting_sent_any = Some(now);
            if !self.eliciting_since_rx {
                self.eliciting_since_rx = true;
                self.reset_idle(now);
            }
        }
        self.stats.sent_packets += 1;
        if sid == SpaceId::Data
            && self.confirmed
            && self.phase_acked
            && pn.saturating_sub(self.phase_first_sent) >= self.cfg.key_update_interval
        {
            self.start_key_update(now);
        }
        Some(eliciting)
    }

    /// Starts a 1-RTT key update (RFC 9001 section 6.1).
    pub(super) fn start_key_update(&mut self, now: Instant) -> bool {
        if !self.confirmed || !self.phase_acked {
            return false;
        }
        let keep = now + self.pto() * 3;
        let Some(k) = self.one_rtt.as_mut() else {
            return false;
        };
        k.update(keep);
        self.phase_first_sent = self.spaces[2].next_pn;
        self.phase_acked = false;
        self.phase_first_rx = None;
        true
    }

    fn write_crypto(
        &mut self,
        sid: SpaceId,
        buf: &mut Vec<u8>,
        max_end: usize,
        frames: &mut Vec<SentFrame>,
        eliciting: &mut bool,
    ) {
        let sp = &mut self.spaces[sid as usize];
        loop {
            let room = max_end.saturating_sub(buf.len());
            let hdr = frame::crypto_header_size(sp.crypto_send.end(), room);
            if room <= hdr + 1 {
                return;
            }
            let Some((r, _)) = sp.crypto_send.next(room - hdr, u64::MAX) else {
                return;
            };
            let len = (r.end - r.start) as usize;
            frame::put_crypto_header(buf, r.start, len);
            sp.crypto_send.copy(r.clone(), buf);
            frames.push(SentFrame::Crypto {
                off: r.start,
                len: r.end - r.start,
            });
            *eliciting = true;
        }
    }

    fn write_datagrams(&mut self, buf: &mut Vec<u8>, max_end: usize, eliciting: &mut bool) {
        while let Some(d) = self.dgram_queue.front() {
            let need = 1 + varint_len(d.len() as u64) + d.len();
            if buf.len() + need > max_end {
                return;
            }
            let d = self.dgram_queue.pop_front().unwrap_or_default();
            self.dgram_queued_bytes -= d.len();
            frame::put_datagram(buf, &d);
            *eliciting = true;
        }
    }

    fn write_streams(
        &mut self,
        buf: &mut Vec<u8>,
        max_end: usize,
        frames: &mut Vec<SentFrame>,
        eliciting: &mut bool,
    ) {
        let mut tries = self.send_queue.len();
        while tries > 0 {
            tries -= 1;
            let room = max_end.saturating_sub(buf.len());
            let Some(&raw) = self.send_queue.front() else {
                return;
            };
            if room <= 1 + varint_len(raw) + 3 {
                return;
            }
            self.send_queue.pop_front();
            self.dequeued(raw);
            // New data is bounded by the peer's MAX_DATA and by our send window.
            let window = self
                .cfg
                .transport
                .send_window
                .saturating_sub(self.stream_unacked);
            let credit = self.tx_max_data.saturating_sub(self.tx_data).min(window);
            let Some(snd) = self.streams.get_mut(&raw).and_then(|s| s.send.as_mut()) else {
                continue;
            };
            if snd.reset.is_some() {
                continue;
            }
            // The frame header: type, id, offset (at most the next new offset), 2-byte length.
            let est = 1 + varint_len(raw) + varint_len(snd.buf.sent()) + 2;
            if room <= est {
                self.enqueue(raw);
                return;
            }
            let max_off = snd.max_data.min(snd.buf.sent() + credit);
            let before = snd.buf.sent();
            let Some((r, fin)) = snd.buf.next(room - est, max_off) else {
                // Blocked by flow control: tell the peer once per limit.
                if snd.buf.blocked_at(snd.max_data) {
                    self.pending.stream_data_blocked.insert(raw);
                } else if snd.buf.unsent() > 0 && self.tx_data >= self.tx_max_data {
                    self.pending.data_blocked = true;
                } else if snd.buf.unsent() > 0 && window == 0 {
                    self.window_blocked = true;
                }
                continue;
            };
            let len = (r.end - r.start) as usize;
            frame::put_stream_header(buf, raw, r.start, len, fin);
            snd.buf.copy(r.clone(), buf);
            let new = snd.buf.sent() - before;
            let again = snd
                .buf
                .wants_send(snd.max_data.min(snd.buf.sent() + credit - new));
            if !again && snd.buf.unsent() > 0 && new >= window {
                // The send window ran out: acknowledgments queue the stream again.
                self.window_blocked = true;
            }
            self.tx_data += new;
            self.stream_unacked += new;
            frames.push(SentFrame::Stream {
                id: raw,
                off: r.start,
                len: r.end - r.start,
                fin,
            });
            *eliciting = true;
            if again {
                self.enqueue(raw);
            }
        }
    }

    /// Control frames of 1-RTT packets; returns whether a path validation frame was written.
    fn write_control(
        &mut self,
        buf: &mut Vec<u8>,
        max_end: usize,
        frames: &mut Vec<SentFrame>,
        eliciting: &mut bool,
    ) -> bool {
        let room = |buf: &Vec<u8>, n: usize| buf.len() + n <= max_end;
        let mut path = false;
        // PATH_RESPONSE on the current path.
        while let Some(&(to, d)) = self.pending.path_responses.front() {
            if to != self.path.remote || !room(buf, 9) {
                break;
            }
            self.pending.path_responses.pop_front();
            buf.push(ty::PATH_RESPONSE as u8);
            buf.extend_from_slice(&d);
            *eliciting = true;
            path = true;
        }
        if self.pending.path_challenge && room(buf, 9) {
            if let Some(d) = self.path.challenge {
                self.pending.path_challenge = false;
                buf.push(ty::PATH_CHALLENGE as u8);
                buf.extend_from_slice(&d);
                frames.push(SentFrame::PathChallenge);
                *eliciting = true;
                path = true;
            } else {
                self.pending.path_challenge = false;
            }
        }
        if self.pending.handshake_done && room(buf, 1) {
            self.pending.handshake_done = false;
            buf.push(ty::HANDSHAKE_DONE as u8);
            frames.push(SentFrame::HandshakeDone);
            *eliciting = true;
        }
        while let Some(&seq) = self.pending.retire_cids.first() {
            if !room(buf, 1 + varint_len(seq)) {
                break;
            }
            self.pending.retire_cids.remove(0);
            frame::put_simple(buf, ty::RETIRE_CONNECTION_ID, &[seq]);
            frames.push(SentFrame::RetireCid(seq));
            *eliciting = true;
        }
        while let Some(&seq) = self.pending.new_cids.first() {
            if !room(buf, 1 + 8 + 8 + 1 + 20 + 16) {
                break;
            }
            self.pending.new_cids.remove(0);
            let Some(cid) = self.local_cids.get(&seq).copied() else {
                continue;
            };
            let token = self.reset_token_for(&cid);
            frame::put_new_cid(buf, seq, 0, &cid, &token);
            frames.push(SentFrame::NewCid(seq));
            *eliciting = true;
        }
        if self.pending.max_data && room(buf, 9) {
            self.pending.max_data = false;
            frame::put_simple(buf, ty::MAX_DATA, &[self.rx_max_data]);
            frames.push(SentFrame::MaxData);
            *eliciting = true;
        }
        for (flag, bidi) in [
            (self.pending.max_streams_bidi, true),
            (self.pending.max_streams_uni, false),
        ] {
            if flag && room(buf, 9) {
                let d = usize::from(!bidi);
                let t = if bidi {
                    ty::MAX_STREAMS_BIDI
                } else {
                    ty::MAX_STREAMS_UNI
                };
                frame::put_simple(buf, t, &[self.local_max_streams[d]]);
                self.local_advertised[d] = self.local_max_streams[d];
                frames.push(SentFrame::MaxStreams(bidi));
                *eliciting = true;
                if bidi {
                    self.pending.max_streams_bidi = false;
                } else {
                    self.pending.max_streams_uni = false;
                }
            }
        }
        let ids: Vec<u64> = self.pending.max_stream_data.iter().copied().collect();
        for id in ids {
            if !room(buf, 17) {
                break;
            }
            self.pending.max_stream_data.remove(&id);
            let Some(r) = self.streams.get(&id).and_then(|s| s.recv.as_ref()) else {
                continue;
            };
            if r.done {
                continue;
            }
            frame::put_simple(buf, ty::MAX_STREAM_DATA, &[id, r.max_data]);
            frames.push(SentFrame::MaxStreamData(id));
            *eliciting = true;
        }
        let ids: Vec<u64> = self.pending.reset_stream.iter().copied().collect();
        for id in ids {
            if !room(buf, 25) {
                break;
            }
            self.pending.reset_stream.remove(&id);
            let Some((code, size, _)) = self
                .streams
                .get(&id)
                .and_then(|s| s.send.as_ref())
                .and_then(|s| s.reset)
            else {
                continue;
            };
            frame::put_simple(buf, ty::RESET_STREAM, &[id, code, size]);
            frames.push(SentFrame::ResetStream(id));
            *eliciting = true;
        }
        let ids: Vec<u64> = self.pending.stop_sending.iter().copied().collect();
        for id in ids {
            if !room(buf, 17) {
                break;
            }
            self.pending.stop_sending.remove(&id);
            let Some(code) = self
                .streams
                .get(&id)
                .and_then(|s| s.recv.as_ref())
                .and_then(|r| r.stop_sent)
            else {
                continue;
            };
            frame::put_simple(buf, ty::STOP_SENDING, &[id, code]);
            frames.push(SentFrame::StopSending(id));
            *eliciting = true;
        }
        if let Some(t) = self.pending.new_token.take() {
            if room(buf, 1 + 2 + t.len()) {
                frame::put_simple(buf, ty::NEW_TOKEN, &[t.len() as u64]);
                buf.extend_from_slice(&t);
                frames.push(SentFrame::NewToken(t));
                *eliciting = true;
            } else {
                self.pending.new_token = Some(t);
            }
        }
        if self.pending.data_blocked && room(buf, 9) {
            self.pending.data_blocked = false;
            frame::put_simple(buf, ty::DATA_BLOCKED, &[self.tx_max_data]);
            frames.push(SentFrame::DataBlocked);
            *eliciting = true;
        }
        let ids: Vec<u64> = self.pending.stream_data_blocked.iter().copied().collect();
        for id in ids {
            if !room(buf, 17) {
                break;
            }
            self.pending.stream_data_blocked.remove(&id);
            let Some(s) = self.streams.get(&id).and_then(|s| s.send.as_ref()) else {
                continue;
            };
            frame::put_simple(buf, ty::STREAM_DATA_BLOCKED, &[id, s.max_data]);
            frames.push(SentFrame::StreamDataBlocked);
            *eliciting = true;
        }
        for (flag, bidi) in [
            (self.pending.streams_blocked_bidi, true),
            (self.pending.streams_blocked_uni, false),
        ] {
            if flag && room(buf, 9) {
                let d = usize::from(!bidi);
                let t = if bidi {
                    ty::STREAMS_BLOCKED_BIDI
                } else {
                    ty::STREAMS_BLOCKED_UNI
                };
                frame::put_simple(buf, t, &[self.peer_max_streams[d]]);
                frames.push(SentFrame::StreamsBlocked);
                *eliciting = true;
                if bidi {
                    self.pending.streams_blocked_bidi = false;
                } else {
                    self.pending.streams_blocked_uni = false;
                }
            }
        }
        path
    }

    /// A PATH_RESPONSE to an address other than the current path.
    fn write_path_response(
        &mut self,
        now: Instant,
        to: SocketAddr,
        data: [u8; 8],
    ) -> Option<Transmit> {
        // Not the connection ID of the current path: one per destination (RFC 9000 9.5).
        let dcid = self.path_cid(to);
        let k = self.one_rtt.as_ref()?;
        let sp = &self.spaces[2];
        let pn = sp.next_pn;
        let pnl = pn_len(pn, sp.largest_acked);
        let mut buf = Vec::with_capacity(MIN_INITIAL_SIZE);
        let b = PacketBuilder::short(&mut buf, &dcid, k.phase, pn, pnl);
        buf.push(ty::PATH_RESPONSE as u8);
        buf.extend_from_slice(&data);
        buf.resize(MIN_INITIAL_SIZE - TAG_LEN, 0);
        b.finish(&mut buf, &k.local, &k.local_hp);
        let size = buf.len() as u16;
        let sp = &mut self.spaces[2];
        sp.next_pn += 1;
        sp.sent.insert(
            pn,
            Sent {
                time: now,
                size,
                ack_eliciting: true,
                in_flight: false,
                mtu_probe: false,
                ecn: false,
                delivered: self.dlv.delivered,
                delivered_age: age_us(now, self.dlv.delivered_time),
                first_sent_age: age_us(now, self.dlv.first_sent),
                app_limited: true,
                frames: Vec::new(),
            },
        );
        self.stats.sent_packets += 1;
        self.stats.udp_tx.datagrams += 1;
        self.stats.udp_tx.bytes += buf.len() as u64;
        self.stats.udp_tx.ios += 1;
        Some(Transmit {
            dest: to,
            segment_size: None,
            data: buf,
            ecn: 0,
            probe: false,
        })
    }

    /// A path MTU probe: a PING padded to the size being tried.
    fn write_mtu_probe(&mut self, now: Instant) -> Option<Transmit> {
        let (size, _) = self.mtu_probe?;
        if !self.confirmed || self.mtu_in_flight.is_some() || !self.path.validated {
            return None;
        }
        if self.bytes_in_flight + u64::from(size) > self.cc.window {
            return None;
        }
        let k = self.one_rtt.as_ref()?;
        let sp = &self.spaces[2];
        let pn = sp.next_pn;
        let pnl = pn_len(pn, sp.largest_acked);
        let mut buf = Vec::with_capacity(usize::from(size));
        let b = PacketBuilder::short(&mut buf, &self.remote_cid(), k.phase, pn, pnl);
        buf.push(ty::PING as u8);
        buf.resize(usize::from(size) - TAG_LEN, 0);
        b.finish(&mut buf, &k.local, &k.local_hp);
        let sp = &mut self.spaces[2];
        sp.next_pn += 1;
        sp.last_eliciting_sent = Some(now);
        sp.eliciting_in_flight += 1;
        sp.sent.insert(
            pn,
            Sent {
                time: now,
                size,
                ack_eliciting: true,
                in_flight: true,
                mtu_probe: true,
                ecn: false,
                delivered: self.dlv.delivered,
                delivered_age: age_us(now, self.dlv.delivered_time),
                first_sent_age: age_us(now, self.dlv.first_sent),
                app_limited: true,
                frames: Vec::new(),
            },
        );
        self.bytes_in_flight += u64::from(size);
        self.mtu_in_flight = Some(pn);
        self.stats.sent_packets += 1;
        self.stats.udp_tx.datagrams += 1;
        self.stats.udp_tx.bytes += buf.len() as u64;
        self.stats.udp_tx.ios += 1;
        Some(Transmit {
            dest: self.path.remote,
            segment_size: None,
            data: buf,
            ecn: 0,
            probe: false,
        })
    }

    /// CONNECTION_CLOSE in every space we have keys for (the peer may lack the higher ones
    /// before the handshake is confirmed, RFC 9000 section 10.2.3).
    fn write_close(&mut self) -> Option<Transmit> {
        let State::Closing { close, resend, .. } = &mut self.state else {
            return None;
        };
        *resend = false;
        let close = close.clone();
        self.close_sent_count += 1;
        let mut buf = Vec::with_capacity(MIN_INITIAL_SIZE);
        let dcid = self.remote_cid();
        let scid = self.local_cid();
        let mut spaces: Vec<SpaceId> = Vec::new();
        if self.one_rtt.is_some() && (self.confirmed || self.tls_done) {
            spaces.push(SpaceId::Data);
        }
        if !self.confirmed {
            for s in [SpaceId::Handshake, SpaceId::Initial] {
                if self.space_ready(s) {
                    spaces.push(s);
                }
            }
            if spaces.is_empty() && self.one_rtt.is_some() {
                spaces.push(SpaceId::Data);
            }
        }
        spaces.sort();
        let budget = self.path.budget().min(usize::from(self.mtu) as u64) as usize;
        for sid in spaces {
            let (pn, pnl) = {
                let sp = &self.spaces[sid as usize];
                (sp.next_pn, pn_len(sp.next_pn, sp.largest_acked))
            };
            let pkt_start = buf.len();
            let b = match sid {
                SpaceId::Initial => {
                    let tok = if self.side == Side::Client {
                        self.retry_token.clone()
                    } else {
                        Vec::new()
                    };
                    PacketBuilder::long(
                        &mut buf,
                        self.version,
                        PacketType::Initial,
                        &dcid,
                        &scid,
                        &tok,
                        pn,
                        pnl,
                    )
                }
                SpaceId::Handshake => PacketBuilder::long(
                    &mut buf,
                    self.version,
                    PacketType::Handshake,
                    &dcid,
                    &scid,
                    &[],
                    pn,
                    pnl,
                ),
                SpaceId::Data => {
                    let phase = self.one_rtt.as_ref().is_some_and(|k| k.phase);
                    PacketBuilder::short(&mut buf, &dcid, phase, pn, pnl)
                }
            };
            match (&close, sid) {
                (CloseKind::App { code, reason }, SpaceId::Data) => {
                    frame::put_close(&mut buf, true, *code, 0, reason);
                }
                (CloseKind::App { .. }, _) => {
                    frame::put_close(&mut buf, false, code::APPLICATION_ERROR, 0, b"");
                }
                (
                    CloseKind::Transport {
                        code,
                        frame,
                        reason,
                    },
                    _,
                ) => {
                    let r = &reason[..reason.len().min(256)];
                    frame::put_close(&mut buf, false, *code, *frame, r);
                }
            }
            let mut min_end = b.pn_offset + b.pn_len + b.min_payload();
            if self.side == Side::Client && sid == SpaceId::Initial {
                min_end = min_end.max(MIN_INITIAL_SIZE - TAG_LEN);
            }
            if buf.len() < min_end {
                buf.resize(min_end, 0);
            }
            match sid {
                SpaceId::Data => {
                    let k = self.one_rtt.as_ref()?;
                    b.finish(&mut buf, &k.local, &k.local_hp);
                }
                s => {
                    let k = self.spaces[s as usize].keys.as_ref()?;
                    b.finish(&mut buf, &k.local.packet, &k.local.header);
                }
            }
            if buf.len() > budget {
                buf.truncate(pkt_start);
                break;
            }
            self.spaces[sid as usize].next_pn += 1;
        }
        if buf.is_empty() {
            return None;
        }
        self.path.sent_bytes += buf.len() as u64;
        self.stats.udp_tx.datagrams += 1;
        self.stats.udp_tx.bytes += buf.len() as u64;
        self.stats.udp_tx.ios += 1;
        Some(Transmit {
            dest: self.path.remote,
            segment_size: None,
            data: buf,
            ecn: 0,
            probe: false,
        })
    }

    /// A 1-RTT packet with `payload` as its frames, protected with this side's keys: lets the
    /// fuzzer reach the frame handlers of the peer.
    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn forge_1rtt(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        self.one_rtt.as_ref()?;
        let sp = &mut self.spaces[2];
        let pn = sp.next_pn;
        sp.next_pn += 1;
        let pnl = pn_len(pn, sp.largest_acked);
        let dcid = self.remote_cid();
        let k = self.one_rtt.as_ref()?;
        let mut buf = Vec::with_capacity(payload.len() + 64);
        let b = PacketBuilder::short(&mut buf, &dcid, k.phase, pn, pnl);
        buf.extend_from_slice(payload);
        let min = b.pn_offset + b.pn_len + b.min_payload();
        if buf.len() < min {
            buf.resize(min, 0);
        }
        b.finish(&mut buf, &k.local, &k.local_hp);
        Some(buf)
    }

    // ---- datagrams ----

    /// The largest DATAGRAM payload that fits a packet now.
    pub fn max_datagram_size(&self) -> Option<usize> {
        if self.peer.max_datagram_frame_size == 0 || !self.params_done {
            return None;
        }
        let packet = usize::from(self.mtu) - 1 - self.remote_cid().len() - 4 - TAG_LEN - 1 - 2;
        Some(packet.min(self.peer.max_datagram_frame_size.saturating_sub(3) as usize))
    }

    /// Queues an unreliable datagram (RFC 9221).
    pub fn send_datagram(&mut self, data: Bytes) -> Result<(), crate::Error> {
        if self.is_closed() {
            return Err(crate::Error::Closed);
        }
        let Some(max) = self.max_datagram_size() else {
            return Err(crate::Error::Datagram(
                "datagrams not supported by peer".into(),
            ));
        };
        if data.len() > max {
            return Err(crate::Error::Datagram(format!(
                "datagram too large ({} > {max})",
                data.len()
            )));
        }
        let cap = self.cfg.transport.datagram_send_buffer_size;
        while self.dgram_queued_bytes + data.len() > cap {
            match self.dgram_queue.pop_front() {
                Some(d) => self.dgram_queued_bytes -= d.len(),
                None => break,
            }
        }
        self.dgram_queued_bytes += data.len();
        self.dgram_queue.push_back(data);
        Ok(())
    }
}
