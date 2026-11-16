//! Streams of a connection: opening, writing, finishing, resetting and stopping them; the
//! frames that drive them; stream and connection flow control (RFC 9000 sections 2-4).

use super::super::frame::{TransportError, code};
use super::super::stream::{RecvBuf, SendBuf};
use super::*;
use crate::Error;

/// A stream's send side.
#[derive(Debug, Default)]
pub(crate) struct SendSide {
    pub buf: SendBuf,
    /// The peer's limit on our offsets.
    pub max_data: u64,
    /// RESET_STREAM: code, final size, acknowledged.
    pub reset: Option<(u64, u64, bool)>,
    /// STOP_SENDING code from the peer.
    pub stopped: Option<u64>,
}

/// A stream's receive side.
#[derive(Debug, Default)]
pub(crate) struct RecvSide {
    pub buf: RecvBuf,
    /// The limit we advertised.
    pub max_data: u64,
    pub reset: Option<u64>,
    /// We sent STOP_SENDING: data is dropped.
    pub stop_sent: Option<u64>,
    pub fin_delivered: bool,
    /// Nothing more for the application: FIN or reset delivered.
    pub done: bool,
}

#[derive(Debug, Default)]
pub(crate) struct StreamState {
    pub send: Option<SendSide>,
    pub recv: Option<RecvSide>,
    pub(super) queued: bool,
    /// Data of the stream arrived in 0-RTT packets (server): possibly replayed.
    pub early: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Need {
    Send,
    Recv,
}

fn di(dir: Dir) -> usize {
    match dir {
        Dir::Bi => 0,
        Dir::Uni => 1,
    }
}

impl Connection {
    fn new_stream(&self, id: StreamId) -> StreamState {
        let local = id.initiator() == self.side;
        let window = self
            .cfg
            .transport
            .stream_receive_window
            .min(super::super::coding::VARINT_MAX);
        let send = (id.dir() == Dir::Bi || local).then(|| SendSide {
            max_data: initial_send_window(&self.peer, self.side, id),
            ..SendSide::default()
        });
        let recv = (id.dir() == Dir::Bi || !local).then(|| RecvSide {
            max_data: window,
            ..RecvSide::default()
        });
        StreamState {
            send,
            recv,
            queued: false,
            early: false,
        }
    }

    /// Whether data of stream `id` arrived in 0-RTT packets (server): it may be a replay.
    pub fn is_early(&self, id: StreamId) -> bool {
        self.streams.get(&u64::from(id)).is_some_and(|s| s.early)
    }

    /// Opens a stream of `dir`; `None` while the peer's limit is reached.
    pub fn open(&mut self, dir: Dir) -> Option<StreamId> {
        if self.is_closed() {
            return None;
        }
        let d = di(dir);
        let idx = self.next_local[d];
        if idx >= self.peer_max_streams[d] {
            if !self.streams_blocked[d] && self.tls_done {
                if dir == Dir::Bi {
                    self.pending.streams_blocked_bidi = true;
                } else {
                    self.pending.streams_blocked_uni = true;
                }
            }
            self.streams_blocked[d] = true;
            return None;
        }
        self.next_local[d] += 1;
        let id = StreamId::new(self.side, dir, idx);
        let s = self.new_stream(id);
        self.streams.insert(u64::from(id), s);
        Some(id)
    }

    fn send_side(&mut self, id: StreamId) -> Result<&mut SendSide, Error> {
        if self.is_closed() {
            return Err(Error::Closed);
        }
        if id.dir() == Dir::Uni && id.initiator() != self.side {
            return Err(Error::UnknownStream);
        }
        let s = self
            .streams
            .get_mut(&u64::from(id))
            .ok_or(Error::UnknownStream)?;
        let snd = s.send.as_mut().ok_or(Error::UnknownStream)?;
        if let Some(c) = snd.stopped {
            return Err(Error::Stopped(c));
        }
        if snd.reset.is_some() || snd.buf.fin {
            return Err(Error::UnknownStream);
        }
        Ok(snd)
    }

    /// Queues bytes on a stream.
    pub fn write(&mut self, id: StreamId, data: Bytes) -> Result<(), Error> {
        let snd = self.send_side(id)?;
        snd.buf.write(data);
        self.enqueue(u64::from(id));
        Ok(())
    }

    /// Ends a stream after its queued bytes.
    pub fn finish(&mut self, id: StreamId) -> Result<(), Error> {
        let snd = self.send_side(id)?;
        snd.buf.fin = true;
        self.enqueue(u64::from(id));
        Ok(())
    }

    /// Abandons sending (RESET_STREAM).
    pub fn reset(&mut self, id: StreamId, code: u64) -> Result<(), Error> {
        if self.is_closed() {
            return Err(Error::Closed);
        }
        if id.dir() == Dir::Uni && id.initiator() != self.side {
            return Err(Error::UnknownStream);
        }
        let raw = u64::from(id);
        let snd = self
            .streams
            .get_mut(&raw)
            .and_then(|s| s.send.as_mut())
            .ok_or(Error::UnknownStream)?;
        if snd.reset.is_some() {
            return Ok(());
        }
        let final_size = snd.buf.sent();
        snd.reset = Some((code, final_size, false));
        let dropped = snd.buf.clear();
        self.stream_unacked = self.stream_unacked.saturating_sub(dropped);
        self.pending.reset_stream.insert(raw);
        Ok(())
    }

    /// Asks the peer to stop sending (STOP_SENDING).
    pub fn stop(&mut self, id: StreamId, code: u64) -> Result<(), Error> {
        if self.is_closed() {
            return Err(Error::Closed);
        }
        if id.dir() == Dir::Uni && id.initiator() == self.side {
            return Err(Error::UnknownStream);
        }
        let raw = u64::from(id);
        let r = self
            .streams
            .get_mut(&raw)
            .and_then(|s| s.recv.as_mut())
            .ok_or(Error::UnknownStream)?;
        if r.done || r.stop_sent.is_some() {
            return Ok(());
        }
        r.stop_sent = Some(code);
        self.pending.stop_sending.insert(raw);
        Ok(())
    }

    /// Bytes written on a stream but not sent yet.
    pub fn queued_bytes(&self, id: StreamId) -> usize {
        self.streams
            .get(&u64::from(id))
            .and_then(|s| s.send.as_ref())
            .map_or(0, |s| s.buf.unsent() as usize)
    }

    /// The code of a STOP_SENDING the peer sent for this stream, if any.
    pub(crate) fn enqueue(&mut self, raw: u64) {
        if let Some(s) = self.streams.get_mut(&raw) {
            if !s.queued {
                s.queued = true;
                self.send_queue.push_back(raw);
            }
        }
    }

    pub(super) fn dequeued(&mut self, raw: u64) {
        if let Some(s) = self.streams.get_mut(&raw) {
            s.queued = false;
        }
    }

    pub(super) fn requeue_all_streams(&mut self) {
        let ids: Vec<u64> = self
            .streams
            .iter()
            .filter(|(_, s)| {
                s.send
                    .as_ref()
                    .is_some_and(|x| x.buf.unsent() > 0 || x.buf.has_lost())
            })
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            self.enqueue(id);
        }
    }

    /// Validates a stream id in a received frame, opening peer streams implicitly; `None` if the
    /// stream is already closed.
    fn stream_for(
        &mut self,
        raw: u64,
        need: Need,
    ) -> Result<Option<&mut StreamState>, TransportError> {
        let id = StreamId::from_raw(raw);
        let local = id.initiator() == self.side;
        let d = di(id.dir());
        if id.dir() == Dir::Uni {
            let ok = match need {
                Need::Recv => !local,
                Need::Send => local,
            };
            if !ok {
                return Err(TransportError::new(
                    code::STREAM_STATE_ERROR,
                    "frame for the wrong direction of a stream",
                ));
            }
        }
        if local {
            if id.index() >= self.next_local[d] {
                return Err(TransportError::new(
                    code::STREAM_STATE_ERROR,
                    "frame for a stream not opened yet",
                ));
            }
        } else {
            if id.index() >= self.local_max_streams[d] {
                return Err(TransportError::new(
                    code::STREAM_LIMIT_ERROR,
                    "stream limit exceeded",
                ));
            }
            while self.peer_opened[d] <= id.index() {
                let nid = StreamId::new(id.initiator(), id.dir(), self.peer_opened[d]);
                self.peer_opened[d] += 1;
                let s = self.new_stream(nid);
                self.streams.insert(u64::from(nid), s);
                self.events.push_back(Event::StreamOpened(nid));
            }
        }
        Ok(self.streams.get_mut(&raw))
    }

    pub(super) fn check_stream_id(&mut self, raw: u64, send: bool) -> Result<(), TransportError> {
        self.stream_for(raw, if send { Need::Send } else { Need::Recv })
            .map(|_| ())
    }

    pub(super) fn on_stream_frame(
        &mut self,
        raw: u64,
        offset: u64,
        data: Bytes,
        fin: bool,
    ) -> Result<(), TransportError> {
        let early = self.rx_early;
        let Some(s) = self.stream_for(raw, Need::Recv)? else {
            return Ok(());
        };
        s.early |= early;
        let Some(r) = s.recv.as_mut() else {
            return Ok(());
        };
        if r.done {
            return Ok(());
        }
        let end = offset + data.len() as u64;
        if end > r.max_data {
            return Err(TransportError::new(
                code::FLOW_CONTROL_ERROR,
                "stream flow control exceeded",
            ));
        }
        let before = r.buf.max_seen;
        r.buf.insert(offset, data, fin)?;
        let grown = r.buf.max_seen - before;
        self.rx_data += grown;
        if self.rx_data > self.rx_max_data {
            return Err(TransportError::new(
                code::FLOW_CONTROL_ERROR,
                "connection flow control exceeded",
            ));
        }
        self.deliver_stream(raw);
        Ok(())
    }

    /// Hands in-order data of a stream to the application and extends the windows.
    fn deliver_stream(&mut self, raw: u64) {
        let id = StreamId::from_raw(raw);
        let window = self.cfg.transport.stream_receive_window;
        let Some(r) = self.streams.get_mut(&raw).and_then(|s| s.recv.as_mut()) else {
            return;
        };
        // Chunks go straight into the event queue (two temporary vectors per delivery showed up
        // in HTTP/3 profiles); the last one gets the FIN once the stream is known to be done.
        let mut delivered = 0u64;
        let mut n = 0;
        while let Some(c) = r.buf.pop() {
            delivered += c.len() as u64;
            if r.stop_sent.is_none() {
                self.events.push_back(Event::StreamData(id, c, false));
                n += 1;
            }
        }
        let finished = r.buf.finished();
        if finished && n > 0 {
            if let Some(Event::StreamData(_, _, fin)) = self.events.back_mut() {
                *fin = true;
            }
        }
        if finished && !r.fin_delivered {
            r.fin_delivered = true;
            if n == 0 && r.stop_sent.is_none() {
                self.events
                    .push_back(Event::StreamData(id, Bytes::new(), true));
            }
        }
        let read = r.buf.read_offset();
        if !finished && r.buf.final_size.is_none() && r.max_data - read < window / 2 {
            r.max_data = read + window;
            self.pending.max_stream_data.insert(raw);
        }
        if finished {
            r.done = true;
        }
        self.credit_conn(delivered);
        if finished {
            self.maybe_free(raw);
        }
    }

    /// `n` bytes were consumed: extend the connection window when half of it is used.
    fn credit_conn(&mut self, n: u64) {
        self.rx_delivered += n;
        if let Some(w) = self.cfg.transport.receive_window {
            if self.rx_max_data - self.rx_delivered.min(self.rx_max_data) < w / 2 {
                self.rx_max_data = self.rx_delivered + w;
                self.pending.max_data = true;
            }
        }
    }

    pub(super) fn on_reset_stream(
        &mut self,
        raw: u64,
        code: u64,
        final_size: u64,
    ) -> Result<(), TransportError> {
        let Some(s) = self.stream_for(raw, Need::Recv)? else {
            return Ok(());
        };
        let Some(r) = s.recv.as_mut() else {
            return Ok(());
        };
        if r.reset.is_some() {
            return Ok(());
        }
        if r.buf.final_size.is_some_and(|f| f != final_size) || final_size < r.buf.max_seen {
            return Err(TransportError::new(
                code::FINAL_SIZE_ERROR,
                "RESET_STREAM final size changed",
            ));
        }
        if final_size > r.max_data {
            return Err(TransportError::new(
                code::FLOW_CONTROL_ERROR,
                "RESET_STREAM beyond the window",
            ));
        }
        let grown = final_size - r.buf.max_seen;
        r.buf.max_seen = final_size;
        let unread = final_size - r.buf.read_offset();
        let was_done = r.done;
        r.reset = Some(code);
        r.done = true;
        self.rx_data += grown;
        if self.rx_data > self.rx_max_data {
            return Err(TransportError::new(
                code::FLOW_CONTROL_ERROR,
                "connection flow control exceeded",
            ));
        }
        if !was_done {
            self.events
                .push_back(Event::StreamReset(StreamId::from_raw(raw), code));
        }
        self.pending.max_stream_data.remove(&raw);
        self.credit_conn(unread);
        self.maybe_free(raw);
        Ok(())
    }

    pub(super) fn on_stop_sending(&mut self, raw: u64, code: u64) -> Result<(), TransportError> {
        let Some(s) = self.stream_for(raw, Need::Send)? else {
            return Ok(());
        };
        let Some(snd) = s.send.as_mut() else {
            return Ok(());
        };
        if snd.stopped.is_some() || snd.reset.is_some() {
            return Ok(());
        }
        snd.stopped = Some(code);
        let reset = !snd.buf.all_acked();
        if reset {
            // Answer with RESET_STREAM (RFC 9000 section 3.5).
            let final_size = snd.buf.sent();
            snd.reset = Some((code, final_size, false));
            let dropped = snd.buf.clear();
            self.stream_unacked = self.stream_unacked.saturating_sub(dropped);
            self.pending.reset_stream.insert(raw);
        }
        self.events
            .push_back(Event::StreamStopped(StreamId::from_raw(raw), code));
        Ok(())
    }

    pub(super) fn on_max_stream_data(&mut self, raw: u64, max: u64) -> Result<(), TransportError> {
        let Some(s) = self.stream_for(raw, Need::Send)? else {
            return Ok(());
        };
        let Some(snd) = s.send.as_mut() else {
            return Ok(());
        };
        if max > snd.max_data {
            snd.max_data = max;
            self.enqueue(raw);
        }
        Ok(())
    }

    pub(super) fn on_max_streams(&mut self, bidi: bool, max: u64) -> Result<(), TransportError> {
        if max > 1 << 60 {
            return Err(TransportError::new(
                code::FRAME_ENCODING_ERROR,
                "MAX_STREAMS above 2^60",
            ));
        }
        let d = usize::from(!bidi);
        if max > self.peer_max_streams[d] {
            self.peer_max_streams[d] = max;
            if self.streams_blocked[d] {
                self.streams_blocked[d] = false;
                self.events.push_back(Event::StreamsAvailable(if bidi {
                    Dir::Bi
                } else {
                    Dir::Uni
                }));
            }
        }
        Ok(())
    }

    pub(super) fn on_stream_acked(&mut self, raw: u64, off: u64, len: u64, fin: bool) {
        let Some(snd) = self.streams.get_mut(&raw).and_then(|s| s.send.as_mut()) else {
            return;
        };
        if snd.reset.is_some() {
            return;
        }
        let moved = snd.buf.on_ack(off..off + len, fin);
        self.stream_unacked = self.stream_unacked.saturating_sub(moved);
        if self.window_blocked && self.stream_unacked < self.cfg.transport.send_window {
            self.window_blocked = false;
            self.requeue_all_streams();
        }
        let Some(snd) = self.streams.get_mut(&raw).and_then(|s| s.send.as_mut()) else {
            return;
        };
        if snd.buf.all_acked() {
            self.maybe_free(raw);
        }
    }

    pub(super) fn on_stream_lost(&mut self, raw: u64, off: u64, len: u64, fin: bool) {
        let Some(snd) = self.streams.get_mut(&raw).and_then(|s| s.send.as_mut()) else {
            return;
        };
        if snd.reset.is_some() {
            return;
        }
        snd.buf.on_lost(off..off + len, fin);
        self.enqueue(raw);
    }

    pub(super) fn on_reset_acked(&mut self, raw: u64) {
        if let Some(snd) = self.streams.get_mut(&raw).and_then(|s| s.send.as_mut()) {
            if let Some(r) = snd.reset.as_mut() {
                r.2 = true;
            }
        }
        self.maybe_free(raw);
    }

    /// Forgets a stream whose both sides are over; a peer stream gives the peer a new one.
    fn maybe_free(&mut self, raw: u64) {
        let Some(s) = self.streams.get(&raw) else {
            return;
        };
        let send_done = s
            .send
            .as_ref()
            .is_none_or(|x| x.buf.all_acked() || x.reset.is_some_and(|r| r.2));
        let recv_done = s.recv.as_ref().is_none_or(|x| x.done);
        if !(send_done && recv_done) {
            return;
        }
        self.streams.remove(&raw);
        let id = StreamId::from_raw(raw);
        if id.initiator() != self.side {
            let d = di(id.dir());
            self.local_closed[d] += 1;
            self.local_max_streams[d] += 1;
            // More credit in batches of an eighth of the limit, or at once when the peer is
            // about to run out.
            let t = &self.cfg.transport;
            let limit = u64::from(if d == 0 {
                t.max_concurrent_bidi_streams
            } else {
                t.max_concurrent_uni_streams
            });
            let step = (limit / 8).max(1);
            let unused = self.local_advertised[d].saturating_sub(self.peer_opened[d]);
            if self.local_max_streams[d] - self.local_advertised[d] >= step || unused < step {
                if d == 0 {
                    self.pending.max_streams_bidi = true;
                } else {
                    self.pending.max_streams_uni = true;
                }
            }
        }
    }
}
