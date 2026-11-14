//! The RTMP chunk stream, sans-IO: [`ChunkReader`] reassembles messages from the four chunk
//! header formats (with extended timestamps, chunk size changes and aborts) and
//! [`write_message`] splits a message into chunks.

use std::{collections::HashMap, fmt};

/// Message type: Set Chunk Size.
pub const SET_CHUNK_SIZE: u8 = 1;
/// Message type: Abort.
pub const ABORT: u8 = 2;
/// Message type: Acknowledgement.
pub const ACK: u8 = 3;
/// Message type: User Control.
pub const USER_CONTROL: u8 = 4;
/// Message type: Window Acknowledgement Size.
pub const WINDOW_ACK_SIZE: u8 = 5;
/// Message type: Set Peer Bandwidth.
pub const SET_PEER_BANDWIDTH: u8 = 6;
/// Message type: audio.
pub const AUDIO: u8 = 8;
/// Message type: video.
pub const VIDEO: u8 = 9;
/// Message type: AMF3 data.
pub const DATA_AMF3: u8 = 15;
/// Message type: AMF3 command.
pub const COMMAND_AMF3: u8 = 17;
/// Message type: AMF0 data (onMetaData, @setDataFrame).
pub const DATA_AMF0: u8 = 18;
/// Message type: AMF0 command.
pub const COMMAND_AMF0: u8 = 20;
/// Message type: aggregate.
pub const AGGREGATE: u8 = 22;

/// The largest chunk size either side may set.
pub const MAX_CHUNK_SIZE: u32 = 0x7fff_ffff;

/// One RTMP message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Message {
    /// The chunk stream it came on (or goes on).
    pub csid: u32,
    /// The message type.
    pub msg_type: u8,
    /// The message stream id.
    pub stream_id: u32,
    /// The absolute timestamp in milliseconds.
    pub timestamp: u32,
    /// The payload.
    pub payload: Vec<u8>,
}

impl Message {
    /// A message of `msg_type` on chunk stream `csid`.
    pub fn new(
        csid: u32,
        msg_type: u8,
        stream_id: u32,
        timestamp: u32,
        payload: Vec<u8>,
    ) -> Message {
        Message {
            csid,
            msg_type,
            stream_id,
            timestamp,
            payload,
        }
    }
}

/// A chunk stream the peer got wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChunkError {
    /// A message over the reader's size limit.
    TooLarge,
    /// A continuation chunk (format 1-3) on a chunk stream never started with format 0.
    NoHeader,
    /// Too many chunk streams at once.
    TooManyStreams,
    /// An invalid chunk size.
    ChunkSize,
}

impl fmt::Display for ChunkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChunkError::TooLarge => f.write_str("RTMP message too large"),
            ChunkError::NoHeader => f.write_str("RTMP chunk without a previous header"),
            ChunkError::TooManyStreams => f.write_str("too many RTMP chunk streams"),
            ChunkError::ChunkSize => f.write_str("invalid RTMP chunk size"),
        }
    }
}

impl std::error::Error for ChunkError {}

#[derive(Debug, Default, Clone)]
struct Stream {
    timestamp: u32,
    delta: u32,
    length: usize,
    msg_type: u8,
    stream_id: u32,
    extended: bool,
    has_header: bool,
    payload: Vec<u8>,
    /// The message in progress started (its first chunk was read).
    started: bool,
}

/// Reassembles messages from chunks. Set Chunk Size and Abort are applied here (and passed on
/// too); everything else is only passed on.
#[derive(Debug)]
pub struct ChunkReader {
    buf: Vec<u8>,
    chunk_size: usize,
    streams: HashMap<u32, Stream>,
    max_message: usize,
    received: u64,
}

impl Default for ChunkReader {
    fn default() -> Self {
        ChunkReader::new()
    }
}

const MAX_STREAMS: usize = 256;

impl ChunkReader {
    /// A reader with chunk size 128 and a 16 MiB message limit.
    pub fn new() -> ChunkReader {
        ChunkReader {
            buf: Vec::new(),
            chunk_size: 128,
            streams: HashMap::new(),
            max_message: 16 << 20,
            received: 0,
        }
    }

    /// Bytes fed so far (for acknowledgements).
    pub fn received(&self) -> u64 {
        self.received
    }

    /// The peer's current chunk size.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Feeds bytes; returns the messages completed.
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<Message>, ChunkError> {
        self.received += data.len() as u64;
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        let mut p = 0;
        loop {
            match self.chunk(p, &mut out)? {
                Some(np) => p = np,
                None => break,
            }
        }
        self.buf.drain(..p);
        Ok(out)
    }

    /// Parses one chunk at `p`; `None` when the buffer does not hold all of it yet.
    fn chunk(&mut self, mut p: usize, out: &mut Vec<Message>) -> Result<Option<usize>, ChunkError> {
        let b = &self.buf;
        let Some(&b0) = b.get(p) else { return Ok(None) };
        let fmt = b0 >> 6;
        let mut csid = u32::from(b0 & 0x3f);
        p += 1;
        match csid {
            0 => {
                let Some(&x) = b.get(p) else { return Ok(None) };
                csid = 64 + u32::from(x);
                p += 1;
            }
            1 => {
                let Some(x) = b.get(p..p + 2) else {
                    return Ok(None);
                };
                csid = 64 + u32::from(x[0]) + 256 * u32::from(x[1]);
                p += 2;
            }
            _ => {}
        }
        let hlen = [11, 7, 3, 0][usize::from(fmt)];
        let Some(h) = b.get(p..p + hlen) else {
            return Ok(None);
        };
        let h = h.to_vec();
        p += hlen;
        if !self.streams.contains_key(&csid) && self.streams.len() >= MAX_STREAMS {
            return Err(ChunkError::TooManyStreams);
        }
        let mut st = self.streams.get(&csid).cloned().unwrap_or_default();
        if fmt != 0 && !st.has_header {
            return Err(ChunkError::NoHeader);
        }
        let u24 = |x: &[u8]| (u32::from(x[0]) << 16) | (u32::from(x[1]) << 8) | u32::from(x[2]);
        let mut continuing = st.started && !st.payload.is_empty();
        if fmt != 3 && continuing {
            // A new header in the middle of a message: the peer abandoned it.
            st.payload.clear();
            continuing = false;
        }
        let mut ts_field = 0;
        if fmt <= 2 {
            ts_field = u24(&h[0..3]);
            st.extended = ts_field == 0xff_ffff;
        }
        if fmt <= 1 {
            st.length = u24(&h[3..6]) as usize;
            st.msg_type = h[6];
            if st.length > self.max_message {
                return Err(ChunkError::TooLarge);
            }
        }
        if fmt == 0 {
            st.stream_id = u32::from_le_bytes([h[7], h[8], h[9], h[10]]);
        }
        let mut ext = None;
        if st.extended {
            let Some(x) = self.buf.get(p..p + 4) else {
                return Ok(None);
            };
            let v = u32::from_be_bytes([x[0], x[1], x[2], x[3]]);
            if fmt == 3 && continuing {
                // Continuation chunks repeat the extended timestamp; some peers leave it out.
                if v == st.timestamp || v == st.delta {
                    p += 4;
                }
            } else {
                ext = Some(v);
                p += 4;
            }
        }
        if !continuing {
            let field = ext.unwrap_or(ts_field);
            match fmt {
                0 => {
                    st.timestamp = field;
                    st.delta = 0;
                }
                1 | 2 => {
                    st.delta = field;
                    st.timestamp = st.timestamp.wrapping_add(field);
                }
                _ => st.timestamp = st.timestamp.wrapping_add(st.delta),
            }
        }
        st.has_header = true;
        let need = st.length - st.payload.len();
        let n = need.min(self.chunk_size);
        let Some(data) = self.buf.get(p..p + n) else {
            return Ok(None);
        };
        st.payload.extend_from_slice(data);
        st.started = true;
        p += n;
        if st.payload.len() == st.length {
            let payload = std::mem::take(&mut st.payload);
            st.started = false;
            let m = Message {
                csid,
                msg_type: st.msg_type,
                stream_id: st.stream_id,
                timestamp: st.timestamp,
                payload,
            };
            self.streams.insert(csid, st);
            self.control(&m)?;
            out.push(m);
        } else {
            self.streams.insert(csid, st);
        }
        Ok(Some(p))
    }

    fn control(&mut self, m: &Message) -> Result<(), ChunkError> {
        match m.msg_type {
            SET_CHUNK_SIZE if m.stream_id == 0 || m.csid == 2 => {
                let Some(x) = m.payload.get(..4) else {
                    return Err(ChunkError::ChunkSize);
                };
                let v = u32::from_be_bytes([x[0], x[1], x[2], x[3]]) & MAX_CHUNK_SIZE;
                if v == 0 {
                    return Err(ChunkError::ChunkSize);
                }
                self.chunk_size = v as usize;
            }
            ABORT => {
                if let Some(x) = m.payload.get(..4) {
                    let id = u32::from_be_bytes([x[0], x[1], x[2], x[3]]);
                    if let Some(s) = self.streams.get_mut(&id) {
                        s.payload.clear();
                        s.started = false;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn basic_header(out: &mut Vec<u8>, fmt: u8, csid: u32) {
    match csid {
        2..=63 => out.push((fmt << 6) | csid as u8),
        64..=319 => {
            out.push(fmt << 6);
            out.push((csid - 64) as u8);
        }
        _ => {
            let c = csid.clamp(320, 65599) - 64;
            out.push((fmt << 6) | 1);
            out.push(c as u8);
            out.push((c >> 8) as u8);
        }
    }
}

/// Appends `m` as chunks of `chunk_size` bytes: a format 0 chunk, then format 3 chunks (with
/// the extended timestamp repeated when the timestamp needs one).
pub fn write_message(out: &mut Vec<u8>, m: &Message, chunk_size: usize) {
    let chunk_size = chunk_size.max(1);
    let ext = m.timestamp >= 0xff_ffff;
    let ts = if ext { 0xff_ffff } else { m.timestamp };
    basic_header(out, 0, m.csid);
    out.extend_from_slice(&ts.to_be_bytes()[1..]);
    out.extend_from_slice(&(m.payload.len() as u32).to_be_bytes()[1..]);
    out.push(m.msg_type);
    out.extend_from_slice(&m.stream_id.to_le_bytes());
    if ext {
        out.extend_from_slice(&m.timestamp.to_be_bytes());
    }
    let mut chunks = m.payload.chunks(chunk_size);
    if let Some(first) = chunks.next() {
        out.extend_from_slice(first);
    }
    for c in chunks {
        basic_header(out, 3, m.csid);
        if ext {
            out.extend_from_slice(&m.timestamp.to_be_bytes());
        }
        out.extend_from_slice(c);
    }
}

/// A protocol control message with a 4-byte big-endian value (Set Chunk Size, Ack, Window
/// Acknowledgement Size).
pub fn control_u32(msg_type: u8, v: u32) -> Message {
    Message::new(2, msg_type, 0, 0, v.to_be_bytes().to_vec())
}

/// Set Peer Bandwidth with limit type dynamic (2).
pub fn peer_bandwidth(v: u32) -> Message {
    let mut p = v.to_be_bytes().to_vec();
    p.push(2);
    Message::new(2, SET_PEER_BANDWIDTH, 0, 0, p)
}

/// A User Control message: `event` with a 4-byte value (StreamBegin = 0, StreamEOF = 1,
/// PingRequest = 6, PingResponse = 7).
pub fn user_control(event: u16, v: u32) -> Message {
    let mut p = event.to_be_bytes().to_vec();
    p.extend_from_slice(&v.to_be_bytes());
    Message::new(2, USER_CONTROL, 0, 0, p)
}

/// Splits an aggregate message's payload into its sub-messages (FLV tags with back pointers),
/// their timestamps rebased on the aggregate's.
pub fn split_aggregate(m: &Message) -> Vec<Message> {
    let mut out = Vec::new();
    let b = &m.payload;
    let mut p = 0;
    let mut first_ts = None;
    while b.len() >= p + 11 {
        let typ = b[p];
        let n =
            (usize::from(b[p + 1]) << 16) | (usize::from(b[p + 2]) << 8) | usize::from(b[p + 3]);
        let ts = (u32::from(b[p + 7]) << 24)
            | (u32::from(b[p + 4]) << 16)
            | (u32::from(b[p + 5]) << 8)
            | u32::from(b[p + 6]);
        let Some(body) = b.get(p + 11..p + 11 + n) else {
            break;
        };
        let base = *first_ts.get_or_insert(ts);
        out.push(Message::new(
            m.csid,
            typ,
            m.stream_id,
            m.timestamp.wrapping_add(ts.wrapping_sub(base)),
            body.to_vec(),
        ));
        p += 11 + n + 4;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_with_small_chunks_and_extended_timestamps() {
        let msgs = vec![
            Message::new(3, COMMAND_AMF0, 0, 0, vec![1; 300]),
            Message::new(6, VIDEO, 1, 40, vec![2; 1000]),
            Message::new(4, AUDIO, 1, 0x0100_0000, vec![3; 260]),
            Message::new(400, VIDEO, 1, 0x0100_0040, vec![4; 5]),
            Message::new(70, AUDIO, 1, 7, vec![]),
        ];
        let mut wire = Vec::new();
        for m in &msgs {
            write_message(&mut wire, m, 128);
        }
        for step in [1usize, 7, 128, wire.len()] {
            let mut r = ChunkReader::new();
            let mut got = Vec::new();
            for c in wire.chunks(step) {
                got.extend(r.feed(c).unwrap());
            }
            assert_eq!(got, msgs, "step {step}");
        }
    }

    #[test]
    fn compressed_headers_and_chunk_size_change() {
        let mut wire = Vec::new();
        write_message(&mut wire, &control_u32(SET_CHUNK_SIZE, 4096), 128);
        // fmt 0 at ts 100, then fmt 1 (+20, new length), fmt 2 (+20), fmt 3 (+20 again).
        wire.extend_from_slice(&[0x04, 0, 0, 100, 0, 0, 2, AUDIO, 1, 0, 0, 0, 0xaa, 0xbb]);
        wire.extend_from_slice(&[0x44, 0, 0, 20, 0, 0, 1, AUDIO, 0xcc]);
        wire.extend_from_slice(&[0x84, 0, 0, 20, 0xdd]);
        wire.extend_from_slice(&[0xc4, 0xee]);
        let mut big = Vec::new();
        write_message(&mut big, &Message::new(6, VIDEO, 1, 0, vec![9; 3000]), 4096);
        wire.extend_from_slice(&big);
        let mut r = ChunkReader::new();
        let got = r.feed(&wire).unwrap();
        assert_eq!(r.chunk_size(), 4096);
        let ts: Vec<u32> = got.iter().map(|m| m.timestamp).collect();
        assert_eq!(ts, vec![0, 100, 120, 140, 160, 0]);
        assert_eq!(got[2].payload, vec![0xcc]);
        assert_eq!(got[5].payload.len(), 3000);
        assert_eq!(r.received(), wire.len() as u64);
    }

    #[test]
    fn errors_and_aggregate() {
        assert_eq!(
            ChunkReader::new()
                .feed(&[0x43, 0, 0, 0, 0, 0, 1, 8])
                .unwrap_err(),
            ChunkError::NoHeader
        );
        let huge = [0x03, 0, 0, 0, 0xff, 0xff, 0xff, 8, 0, 0, 0, 0];
        let mut r = ChunkReader::new();
        r.max_message = 1000;
        assert_eq!(r.feed(&huge).unwrap_err(), ChunkError::TooLarge);
        let mut agg = Vec::new();
        crate::flv::write_tag(&mut agg, 9, 1000, &[1, 2]);
        crate::flv::write_tag(&mut agg, 8, 1040, &[3]);
        let subs = split_aggregate(&Message::new(4, AGGREGATE, 1, 5000, agg));
        assert_eq!(subs.len(), 2);
        assert_eq!((subs[0].msg_type, subs[0].timestamp), (9, 5000));
        assert_eq!(
            (subs[1].msg_type, subs[1].timestamp, subs[1].payload.clone()),
            (8, 5040, vec![3])
        );
    }
}
