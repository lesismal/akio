//! The WebSocket connection driver and the application-facing types.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use only_buf::SharedBuf;
use only_core::{ConnInner, Error, Result};

/// A transport other than a TCP connection that carries a WebSocket connection's bytes (an
/// HTTP/3 request stream for RFC 9220). Used by only-h3; `#[doc(hidden)]`, outside the semver
/// promise.
#[doc(hidden)]
pub trait WsLink: Send + Sync + 'static {
    /// Queues bytes (whole frames) for the peer; `Err` when the transport is gone.
    fn send(&self, data: Vec<u8>) -> Result<()>;
    /// Ends the transport once what is queued is out (the server side after a close frame).
    fn close_after_send(&self);
    /// Ends the transport now (the client after its close timeout, or the peer went away).
    fn close(&self);
    /// Whether the transport can still send.
    fn is_open(&self) -> bool;
    /// Bytes queued but not yet sent.
    fn queued_bytes(&self) -> usize;
}

/// Where a session's frames go: a TCP (or TLS) connection, or another transport.
#[derive(Clone)]
enum Link {
    Tcp(Arc<ConnInner>),
    Ext(Arc<dyn WsLink>),
}

enum WeakLink {
    Tcp(std::sync::Weak<ConnInner>),
    Ext(std::sync::Weak<dyn WsLink>),
}

impl Link {
    fn send(&self, data: &[u8]) -> Result<()> {
        match self {
            Link::Tcp(c) => c.send(data),
            Link::Ext(l) => l.send(data.to_vec()),
        }
    }

    fn send_owned(&self, data: Vec<u8>) -> Result<()> {
        match self {
            Link::Tcp(c) => c.send_owned(data),
            Link::Ext(l) => l.send(data),
        }
    }

    fn send_shared(&self, data: SharedBuf) -> Result<()> {
        match self {
            Link::Tcp(c) => c.send_shared(data),
            Link::Ext(l) => l.send(data[..].to_vec()),
        }
    }

    fn close_after_send(&self) {
        match self {
            Link::Tcp(c) => c.close_after_send(),
            Link::Ext(l) => l.close_after_send(),
        }
    }

    fn is_open(&self) -> bool {
        match self {
            Link::Tcp(c) => c.is_open(),
            Link::Ext(l) => l.is_open(),
        }
    }

    fn queued_bytes(&self) -> usize {
        match self {
            Link::Tcp(c) => c.queued_bytes(),
            Link::Ext(l) => l.queued_bytes(),
        }
    }

    fn downgrade(&self) -> WeakLink {
        match self {
            Link::Tcp(c) => WeakLink::Tcp(Arc::downgrade(c)),
            Link::Ext(l) => WeakLink::Ext(Arc::downgrade(l)),
        }
    }
}

impl WeakLink {
    fn close(&self) {
        match self {
            WeakLink::Tcp(w) => {
                if let Some(c) = w.upgrade() {
                    c.close();
                }
            }
            WeakLink::Ext(w) => {
                if let Some(l) = w.upgrade() {
                    l.close();
                }
            }
        }
    }
}

use crate::{
    deflate::{Deflater, Inflater, PmdParams},
    protocol::{
        Decoder, Event, Opcode, Role, close_payload, encode_frame, encode_frame_masked,
        frame_header,
    },
};

/// A complete WebSocket message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// UTF-8 text.
    Text(String),
    /// Binary data.
    Binary(Vec<u8>),
}

/// Application callbacks for one WebSocket connection. They run on the connection's I/O thread
/// and must not block; keep a clone of the [`WsSender`] to answer from other threads.
pub trait WsHandler: Send + 'static {
    /// The handshake finished; the connection is ready.
    fn on_open(&mut self, _ws: &WsSender) {}

    /// A complete message arrived.
    fn on_message(&mut self, ws: &WsSender, msg: Message);

    /// A pong arrived (answering a [`WsSender::ping`]).
    fn on_pong(&mut self, _ws: &WsSender, _payload: &[u8]) {}

    /// The connection ended, exactly once. `code` is the peer's close status, the status this
    /// side closed with after a protocol error, or 1006 when the transport dropped without a
    /// close handshake.
    fn on_close(&mut self, _code: Option<u16>, _reason: &str) {}
}

/// Options for a WebSocket connection.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct WsConfig {
    /// Largest message accepted, after decompression; larger ones close with 1009.
    pub max_message_bytes: usize,
    /// Offer `permessage-deflate` when the client does.
    pub permessage_deflate: bool,
    /// Messages shorter than this are sent uncompressed even when compression is negotiated.
    pub compress_min_bytes: usize,
}

impl Default for WsConfig {
    fn default() -> Self {
        WsConfig {
            max_message_bytes: 16 << 20,
            permessage_deflate: true,
            compress_min_bytes: 128,
        }
    }
}

struct Tx {
    deflater: Option<Deflater>,
    compress_min: usize,
    closed: bool,
    /// Client side: frames are masked with keys from this generator.
    mask: Option<MaskGen>,
    /// Client side: after the close handshake, how long to wait for the server to close the TCP
    /// connection before closing it from this side.
    close_timeout: Duration,
    /// The subprotocol agreed in the handshake (client side).
    protocol: Option<String>,
}

/// Frames up to this size go through a reused per-thread scratch buffer and are sent with one
/// copy into the connection's (pooled) queue, so a message costs no allocation; larger ones are
/// encoded into a buffer of their own that the connection queues without copying it again.
const SCRATCH_MAX: usize = 64 << 10;

thread_local! {
    /// Frame encoding and compression output buffers, per thread rather than per connection so
    /// idle connections hold nothing. Taken out while in use: a re-entrant send (from a drain
    /// callback) just starts from an empty buffer.
    static BUFS: std::cell::Cell<(Vec<u8>, Vec<u8>)> = const { std::cell::Cell::new((Vec::new(), Vec::new())) };
}

/// Runs `f` with the thread's (scratch, compression) buffers and puts them back, dropping any
/// that grew past [`SCRATCH_MAX`].
fn with_bufs<R>(f: impl FnOnce(&mut Vec<u8>, &mut Vec<u8>) -> R) -> R {
    let (mut a, mut b) = BUFS.with(|c| c.take());
    let r = f(&mut a, &mut b);
    if a.capacity() > 2 * SCRATCH_MAX {
        a = Vec::new();
    }
    if b.capacity() > 2 * SCRATCH_MAX {
        b = Vec::new();
    }
    BUFS.with(|c| c.set((a, b)));
    r
}

/// Appends one frame to `out`, masked when `mask` hands out keys (client side).
fn put_frame(
    mask: Option<&mut MaskGen>,
    op: Opcode,
    fin: bool,
    rsv1: bool,
    payload: &[u8],
    out: &mut Vec<u8>,
) {
    match mask {
        Some(m) => encode_frame_masked(op, fin, rsv1, payload, m.next_key(), out),
        None => {
            let (h, n) = frame_header(op, fin, rsv1, payload.len(), None);
            out.extend_from_slice(&h[..n]);
            out.extend_from_slice(payload);
        }
    }
}

impl Tx {
    /// Encodes the frames of one message (`frame` payload bytes each, 0: one frame; `body`
    /// already compressed when `rsv1`) and sends them on `conn`.
    fn send_frames(
        &mut self,
        conn: &Link,
        op: Opcode,
        rsv1: bool,
        body: &[u8],
        frame: usize,
        scratch: &mut Vec<u8>,
    ) -> Result<()> {
        let mask = &mut self.mask;
        let frame = if frame == 0 { body.len().max(1) } else { frame };
        let frames = body.len().div_ceil(frame).max(1);
        let total = body.len() + 14 * frames;
        let mut own;
        let out: &mut Vec<u8> = if total <= SCRATCH_MAX {
            scratch.clear();
            scratch
        } else {
            own = Vec::with_capacity(total);
            &mut own
        };
        if body.is_empty() {
            put_frame(mask.as_mut(), op, true, rsv1, body, out);
        } else {
            for (i, piece) in body.chunks(frame).enumerate() {
                let first = i == 0;
                put_frame(
                    mask.as_mut(),
                    if first { op } else { Opcode::Continue },
                    i + 1 == frames,
                    rsv1 && first,
                    piece,
                    out,
                );
            }
        }
        if total <= SCRATCH_MAX {
            conn.send(out)
        } else {
            conn.send_owned(std::mem::take(out))
        }
    }

    /// Sends one control frame (payload already at most 125 bytes) from a stack buffer.
    fn send_control(&mut self, conn: &Link, op: Opcode, payload: &[u8]) -> Result<()> {
        let payload = &payload[..payload.len().min(125)];
        let key = self.mask.as_mut().map(MaskGen::next_key);
        let (h, n) = frame_header(op, true, false, payload.len(), key);
        let mut buf = [0u8; 14 + 125];
        buf[..n].copy_from_slice(&h[..n]);
        buf[n..n + payload.len()].copy_from_slice(payload);
        if let Some(k) = key {
            crate::protocol::unmask(&mut buf[n..n + payload.len()], k, 0);
        }
        conn.send(&buf[..n + payload.len()])
    }
}

/// Masking keys: a SplitMix64 stream seeded from the operating system's random source, one per
/// connection (RFC 6455 section 10.3 asks for unpredictable keys; they only protect against
/// cache poisoning by a peer that could predict them).
struct MaskGen(u64);

impl MaskGen {
    fn new() -> MaskGen {
        let mut seed = [0u8; 8];
        if only_crypto::rand::fill_random(&mut seed).is_err() {
            // Practically unreachable; still never hand out a constant stream.
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos() as u64);
            seed = t.to_le_bytes();
        }
        MaskGen(u64::from_le_bytes(seed))
    }

    fn next_key(&mut self) -> [u8; 4] {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        (z as u32).to_ne_bytes()
    }
}

/// Sends on a WebSocket connection. Cheap to clone, usable from any thread; frames from different
/// threads never interleave.
#[derive(Clone)]
pub struct WsSender {
    conn: Link,
    tx: Arc<Mutex<Tx>>,
}

impl std::fmt::Debug for WsSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsSender").finish_non_exhaustive()
    }
}

/// A message encoded once, to be sent to many connections ([`WsSender::send_prepared`]). It is
/// sent uncompressed, which every peer accepts.
#[derive(Debug, Clone)]
pub struct PreparedMessage {
    frame: SharedBuf,
}

impl PreparedMessage {
    /// A text message.
    pub fn text(text: &str) -> PreparedMessage {
        PreparedMessage::new(Opcode::Text, text.as_bytes())
    }

    /// A binary message.
    pub fn binary(data: &[u8]) -> PreparedMessage {
        PreparedMessage::new(Opcode::Binary, data)
    }

    fn new(op: Opcode, payload: &[u8]) -> PreparedMessage {
        let mut out = Vec::with_capacity(payload.len() + 10);
        encode_frame(op, true, false, payload, &mut out);
        PreparedMessage {
            frame: SharedBuf::from(out),
        }
    }
}

impl WsSender {
    fn new(conn: Link, deflater: Option<Deflater>, compress_min: usize) -> WsSender {
        WsSender {
            conn,
            tx: Arc::new(Mutex::new(Tx {
                deflater,
                compress_min,
                closed: false,
                mask: None,
                close_timeout: Duration::ZERO,
                protocol: None,
            })),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Tx> {
        self.tx.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Sends one message, split into frames of at most `frame` payload bytes (0: one frame).
    fn send_data(&self, op: Opcode, payload: &[u8], frame: usize) -> Result<()> {
        // The lock is held across the send so compressed frames, whose compressor state depends
        // on order, reach the wire in the order they were compressed.
        let mut tx = self.lock();
        if tx.closed {
            return Err(Error::Closed);
        }
        let tx = &mut *tx;
        with_bufs(|scratch, zout| {
            let compressed = match tx.deflater.as_mut() {
                Some(d) if payload.len() >= tx.compress_min => {
                    d.deflate_into(payload, zout);
                    true
                }
                _ => false,
            };
            let body: &[u8] = if compressed { zout } else { payload };
            tx.send_frames(&self.conn, op, compressed, body, frame, scratch)
        })
    }

    /// Sends a text message.
    pub fn send_text(&self, text: &str) -> Result<()> {
        self.send_data(Opcode::Text, text.as_bytes(), 0)
    }

    /// Sends a binary message.
    pub fn send_binary(&self, data: &[u8]) -> Result<()> {
        self.send_data(Opcode::Binary, data, 0)
    }

    /// Sends a text message as a sequence of frames of at most `frame_bytes` payload each
    /// (after compression, when negotiated). The frames leave together; this is about the wire
    /// format (for peers or intermediaries with frame size limits), not streaming.
    pub fn send_text_fragmented(&self, text: &str, frame_bytes: usize) -> Result<()> {
        self.send_data(Opcode::Text, text.as_bytes(), frame_bytes.max(1))
    }

    /// Binary counterpart of [`send_text_fragmented`](Self::send_text_fragmented).
    pub fn send_binary_fragmented(&self, data: &[u8], frame_bytes: usize) -> Result<()> {
        self.send_data(Opcode::Binary, data, frame_bytes.max(1))
    }

    /// Sends a message prepared once for many connections.
    pub fn send_prepared(&self, m: &PreparedMessage) -> Result<()> {
        let mut tx = self.lock();
        if tx.closed {
            return Err(Error::Closed);
        }
        if tx.mask.is_some() {
            // A client must mask every frame with a fresh key: re-encode the payload.
            let f = &m.frame[..];
            let at = match f[1] & 0x7f {
                126 => 4,
                127 => 10,
                _ => 2,
            };
            let op = if f[0] & 0x0f == Opcode::Text as u8 {
                Opcode::Text
            } else {
                Opcode::Binary
            };
            return with_bufs(|scratch, _| {
                tx.send_frames(&self.conn, op, false, &f[at..], 0, scratch)
            });
        }
        // Held across the send for ordering against compressed frames, like `send_data`.
        self.conn.send_shared(m.frame.clone())
    }

    fn control(&self, op: Opcode, payload: &[u8]) -> Result<()> {
        let mut tx = self.lock();
        if tx.closed {
            return Err(Error::Closed);
        }
        tx.send_control(&self.conn, op, payload)
    }

    /// Sends a ping; the answer arrives in [`WsHandler::on_pong`].
    pub fn ping(&self, payload: &[u8]) -> Result<()> {
        self.control(Opcode::Ping, payload)
    }

    /// Sends an unsolicited pong.
    pub fn pong(&self, payload: &[u8]) -> Result<()> {
        self.control(Opcode::Pong, payload)
    }

    /// Starts the close handshake with `code` and `reason`; later sends fail. A server closes
    /// the connection once the frame is written. A client waits for the server's close frame
    /// (reported to [`WsHandler::on_close`]) and for the server to end the TCP connection, as
    /// RFC 6455 section 7.1.1 asks, up to the dial options' `close_timeout`.
    pub fn close(&self, code: u16, reason: &str) {
        self.close_with(Some(code), reason, false);
    }

    /// Sends a close frame unless one was sent. `drop_tcp`: close the transport once it is
    /// written even on the client side (failing the connection after a protocol error).
    fn close_with(&self, code: Option<u16>, reason: &str, drop_tcp: bool) {
        let mut tx = self.lock();
        if tx.closed {
            if drop_tcp {
                self.conn.close_after_send();
            }
            return;
        }
        tx.closed = true;
        let payload = match code {
            Some(c) => close_payload(c, reason),
            None => Vec::new(),
        };
        let _ = tx.send_control(&self.conn, Opcode::Close, &payload);
        if tx.mask.is_none() || drop_tcp {
            self.conn.close_after_send();
        } else {
            let weak = self.conn.downgrade();
            crate::timer::after(tx.close_timeout, move || weak.close());
        }
    }

    /// The subprotocol the server selected (client side; `None` on the server side, where the
    /// application chose it).
    pub fn subprotocol(&self) -> Option<String> {
        self.lock().protocol.clone()
    }

    /// Whether the connection can still send.
    pub fn is_open(&self) -> bool {
        !self.lock().closed && self.conn.is_open()
    }

    /// Bytes sent but not yet written to the socket, for pacing a producer (a sender that
    /// streams to a slow peer drops or waits while this is high).
    pub fn queued_bytes(&self) -> usize {
        self.conn.queued_bytes()
    }
}

/// Drives one WebSocket connection: feed it the bytes read, it calls the handler. Used by
/// only-http's upgrade glue; `#[doc(hidden)]`, outside the semver promise.
#[doc(hidden)]
pub struct WsSession {
    decoder: Decoder,
    handler: Box<dyn WsHandler>,
    sender: WsSender,
    events: Vec<Event>,
    ended: bool,
}

impl std::fmt::Debug for WsSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsSession").finish_non_exhaustive()
    }
}

impl WsSession {
    /// Starts a session on `conn` after a successful handshake that agreed `pmd`.
    pub fn new(
        conn: Arc<ConnInner>,
        cfg: &WsConfig,
        pmd: Option<PmdParams>,
        handler: Box<dyn WsHandler>,
    ) -> WsSession {
        WsSession::server(Link::Tcp(conn), cfg, pmd, handler)
    }

    /// The server side of a connection carried by `link` (WebSocket over HTTP/3).
    pub fn with_link(
        link: Arc<dyn WsLink>,
        cfg: &WsConfig,
        pmd: Option<PmdParams>,
        handler: Box<dyn WsHandler>,
    ) -> WsSession {
        WsSession::server(Link::Ext(link), cfg, pmd, handler)
    }

    fn server(
        conn: Link,
        cfg: &WsConfig,
        pmd: Option<PmdParams>,
        handler: Box<dyn WsHandler>,
    ) -> WsSession {
        let inflater = pmd.map(|p| Inflater::new(p.client_no_context_takeover));
        let deflater =
            pmd.map(|p| Deflater::new(p.server_no_context_takeover, p.server_max_window_bits));
        WsSession {
            decoder: Decoder::new(Role::Server, cfg.max_message_bytes, inflater),
            handler,
            sender: WsSender::new(conn, deflater, cfg.compress_min_bytes),
            events: Vec::new(),
            ended: false,
        }
    }

    /// The client side of a connection whose handshake agreed `pmd` and `protocol`.
    pub(crate) fn client(
        conn: Arc<ConnInner>,
        cfg: &WsConfig,
        pmd: Option<PmdParams>,
        handler: Box<dyn WsHandler>,
        protocol: Option<String>,
        close_timeout: Duration,
    ) -> WsSession {
        WsSession::client_on(Link::Tcp(conn), cfg, pmd, handler, protocol, close_timeout)
    }

    /// The client side of a connection carried by `link` (WebSocket over HTTP/3) whose
    /// handshake agreed `pmd` and `protocol`.
    pub fn client_with_link(
        link: Arc<dyn WsLink>,
        cfg: &WsConfig,
        pmd: Option<PmdParams>,
        handler: Box<dyn WsHandler>,
        protocol: Option<String>,
        close_timeout: Duration,
    ) -> WsSession {
        WsSession::client_on(Link::Ext(link), cfg, pmd, handler, protocol, close_timeout)
    }

    fn client_on(
        conn: Link,
        cfg: &WsConfig,
        pmd: Option<PmdParams>,
        handler: Box<dyn WsHandler>,
        protocol: Option<String>,
        close_timeout: Duration,
    ) -> WsSession {
        let inflater = pmd.map(|p| Inflater::new(p.server_no_context_takeover));
        let deflater =
            pmd.map(|p| Deflater::new(p.client_no_context_takeover, p.client_max_window_bits));
        let sender = WsSender::new(conn, deflater, cfg.compress_min_bytes);
        {
            let mut tx = sender.lock();
            tx.mask = Some(MaskGen::new());
            tx.close_timeout = close_timeout;
            tx.protocol = protocol;
        }
        WsSession {
            decoder: Decoder::new(Role::Client, cfg.max_message_bytes, inflater),
            handler,
            sender,
            events: Vec::new(),
            ended: false,
        }
    }

    /// The session's sender.
    pub fn sender(&self) -> &WsSender {
        &self.sender
    }

    /// Whether the session has ended (close handshake done or failed).
    pub fn ended(&self) -> bool {
        self.ended
    }

    /// Starts the close handshake with 1001 (going away), as an engine shutdown does.
    pub(crate) fn going_away(&self) {
        self.sender
            .close(crate::protocol::close::GOING_AWAY, "going away");
    }

    /// Calls `on_open`. Do this before feeding data.
    pub fn open(&mut self) {
        self.handler.on_open(&self.sender);
    }

    /// Processes bytes read from the connection.
    pub fn on_data(&mut self, data: &[u8]) {
        if self.ended {
            return;
        }
        let mut events = std::mem::take(&mut self.events);
        events.clear();
        let res = self.decoder.decode(data, &mut events);
        for ev in events.drain(..) {
            if self.ended {
                break;
            }
            match ev {
                Event::Text(t) => self.handler.on_message(&self.sender, Message::Text(t)),
                Event::Binary(b) => self.handler.on_message(&self.sender, Message::Binary(b)),
                Event::Ping(p) => {
                    let _ = self.sender.pong(&p);
                    self.decoder.recycle_control(p);
                }
                Event::Pong(p) => {
                    self.handler.on_pong(&self.sender, &p);
                    self.decoder.recycle_control(p);
                }
                Event::Close { code, reason } => {
                    // Echo the status (or an empty close), then end. A server closes the
                    // transport; a client waits for the server to do so.
                    self.sender.close_with(code, "", false);
                    self.end(code, &reason);
                }
            }
        }
        self.events = events;
        if let Err(e) = res {
            if !self.ended {
                self.sender.close_with(Some(e.code), e.reason, true);
                self.end(Some(e.code), e.reason);
            }
        }
    }

    /// The transport closed. Calls `on_close` with 1006 unless the close handshake already ended
    /// the session.
    pub fn on_transport_closed(&mut self) {
        if let Link::Ext(l) = &self.sender.conn {
            // The peer ended its side: end ours too (a TCP connection is already gone).
            l.close();
        }
        if !self.ended {
            self.sender.lock().closed = true;
            self.end(Some(1006), "connection closed without a close handshake");
        }
    }

    fn end(&mut self, code: Option<u16>, reason: &str) {
        self.ended = true;
        self.handler.on_close(code, reason);
    }
}

/// `Sec-WebSocket-Accept` for a client's `Sec-WebSocket-Key`.
pub fn accept_key(key: &str) -> String {
    let mut h = only_crypto::hash::Sha1::new();
    h.update(key.trim().as_bytes());
    h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    only_crypto::base64::STANDARD.encode(h.finalize())
}

/// Whether `key` is a valid `Sec-WebSocket-Key` (base64 of 16 bytes).
pub fn valid_key(key: &str) -> bool {
    only_crypto::base64::STANDARD
        .decode(key.trim())
        .is_ok_and(|v| v.len() == 16)
}

/// The first of the client's offered subprotocols (`Sec-WebSocket-Protocol` values) that the
/// server supports.
pub fn select_subprotocol<'a>(
    offered: impl IntoIterator<Item = &'a str>,
    supported: &[String],
) -> Option<String> {
    for value in offered {
        for p in value.split(',').map(str::trim) {
            if supported.iter().any(|s| s == p) {
                return Some(p.to_owned());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_accept_key_example() {
        // RFC 6455 section 1.3.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        assert!(valid_key("dGhlIHNhbXBsZSBub25jZQ=="));
        assert!(!valid_key("short"));
        assert!(!valid_key(""));
    }

    #[test]
    fn subprotocol_selection_follows_client_preference() {
        let sup = vec!["chat".to_string(), "v2.json".to_string()];
        assert_eq!(
            select_subprotocol(["mqtt, v2.json , chat"], &sup),
            Some("v2.json".to_string())
        );
        assert_eq!(select_subprotocol(["mqtt"], &sup), None);
        assert_eq!(select_subprotocol(std::iter::empty(), &sup), None);
    }
}
