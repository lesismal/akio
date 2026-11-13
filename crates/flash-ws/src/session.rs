//! The WebSocket connection driver and the application-facing types.

use std::sync::{Arc, Mutex};

use flash_buf::SharedBuf;
use flash_core::{ConnInner, Error, Result};

use crate::{
    deflate::{Deflater, Inflater, PmdParams},
    protocol::{Decoder, Event, Opcode, Role, close, close_payload, encode_frame},
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
}

/// Sends on a WebSocket connection. Cheap to clone, usable from any thread; frames from different
/// threads never interleave.
#[derive(Clone)]
pub struct WsSender {
    conn: Arc<ConnInner>,
    tx: Arc<Mutex<Tx>>,
}

/// A message encoded once, to be sent to many connections ([`WsSender::send_prepared`]). It is
/// sent uncompressed, which every peer accepts.
#[derive(Clone)]
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
    pub(crate) fn new(
        conn: Arc<ConnInner>,
        pmd: Option<PmdParams>,
        compress_min: usize,
    ) -> WsSender {
        WsSender {
            conn,
            tx: Arc::new(Mutex::new(Tx {
                deflater: pmd
                    .map(|p| Deflater::new(p.server_no_context_takeover, p.server_max_window_bits)),
                compress_min,
                closed: false,
            })),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Tx> {
        self.tx.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn send_data(&self, op: Opcode, payload: &[u8]) -> Result<()> {
        // The lock is held across the send so compressed frames, whose compressor state depends
        // on order, reach the wire in the order they were compressed.
        let mut tx = self.lock();
        if tx.closed {
            return Err(Error::Closed);
        }
        let compress_min = tx.compress_min;
        let mut out;
        match tx.deflater.as_mut() {
            Some(d) if payload.len() >= compress_min => {
                let c = d.deflate(payload);
                out = Vec::with_capacity(c.len() + 10);
                encode_frame(op, true, true, &c, &mut out);
            }
            _ => {
                out = Vec::with_capacity(payload.len() + 10);
                encode_frame(op, true, false, payload, &mut out);
            }
        }
        self.conn.send_owned(out)
    }

    /// Sends a text message.
    pub fn send_text(&self, text: &str) -> Result<()> {
        self.send_data(Opcode::Text, text.as_bytes())
    }

    /// Sends a binary message.
    pub fn send_binary(&self, data: &[u8]) -> Result<()> {
        self.send_data(Opcode::Binary, data)
    }

    /// Sends a message prepared once for many connections.
    pub fn send_prepared(&self, m: &PreparedMessage) -> Result<()> {
        let tx = self.lock();
        if tx.closed {
            return Err(Error::Closed);
        }
        // Held across the send for ordering against compressed frames, like `send_data`.
        self.conn.send_shared(m.frame.clone())
    }

    fn control(&self, op: Opcode, payload: &[u8]) -> Result<()> {
        let tx = self.lock();
        if tx.closed {
            return Err(Error::Closed);
        }
        let mut out = Vec::with_capacity(payload.len() + 2);
        encode_frame(
            op,
            true,
            false,
            &payload[..payload.len().min(125)],
            &mut out,
        );
        self.conn.send_owned(out)
    }

    /// Sends a ping; the answer arrives in [`WsHandler::on_pong`].
    pub fn ping(&self, payload: &[u8]) -> Result<()> {
        self.control(Opcode::Ping, payload)
    }

    /// Sends an unsolicited pong.
    pub fn pong(&self, payload: &[u8]) -> Result<()> {
        self.control(Opcode::Pong, payload)
    }

    /// Sends a close frame and closes the connection once it is written. Later sends fail.
    pub fn close(&self, code: u16, reason: &str) {
        self.close_with(Some(code), reason);
    }

    fn close_with(&self, code: Option<u16>, reason: &str) {
        let mut tx = self.lock();
        if tx.closed {
            return;
        }
        tx.closed = true;
        let payload = match code {
            Some(c) => close_payload(c, reason),
            None => Vec::new(),
        };
        let mut out = Vec::with_capacity(payload.len() + 2);
        encode_frame(Opcode::Close, true, false, &payload, &mut out);
        let _ = self.conn.send_owned(out);
        self.conn.close_after_send();
    }

    /// Whether the connection can still send.
    pub fn is_open(&self) -> bool {
        !self.lock().closed && self.conn.is_open()
    }
}

/// Drives one WebSocket connection: feed it the bytes read, it calls the handler.
pub struct WsSession {
    decoder: Decoder,
    handler: Box<dyn WsHandler>,
    sender: WsSender,
    events: Vec<Event>,
    ended: bool,
}

impl WsSession {
    /// Starts a session on `conn` after a successful handshake that agreed `pmd`.
    pub fn new(
        conn: Arc<ConnInner>,
        cfg: &WsConfig,
        pmd: Option<PmdParams>,
        handler: Box<dyn WsHandler>,
    ) -> WsSession {
        let inflater = pmd.map(|p| Inflater::new(p.client_no_context_takeover));
        WsSession {
            decoder: Decoder::new(Role::Server, cfg.max_message_bytes, inflater),
            handler,
            sender: WsSender::new(conn, pmd, cfg.compress_min_bytes),
            events: Vec::new(),
            ended: false,
        }
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
                }
                Event::Pong(p) => self.handler.on_pong(&self.sender, &p),
                Event::Close { code, reason } => {
                    // Echo the status (or an empty close), then end.
                    self.sender.close_with(code, "");
                    self.end(code, &reason);
                }
            }
        }
        self.events = events;
        if let Err(e) = res {
            if !self.ended {
                self.sender.close(e.code, e.reason);
                self.end(Some(e.code), e.reason);
            }
        }
    }

    /// The transport closed. Calls `on_close` with 1006 unless the close handshake already ended
    /// the session.
    pub fn on_transport_closed(&mut self) {
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
    use base64::Engine;
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(key.trim().as_bytes());
    h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

/// Whether `key` is a valid `Sec-WebSocket-Key` (base64 of 16 bytes).
pub fn valid_key(key: &str) -> bool {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
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

/// Status 1011 helper for servers that hit an internal error.
pub const INTERNAL_ERROR: u16 = close::INTERNAL;

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
