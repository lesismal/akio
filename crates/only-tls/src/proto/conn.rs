//! A TLS connection over a byte stream: the record layer driving a handshake state machine,
//! sans-io (bytes in, bytes out).

use std::sync::Arc;

use super::alert::{Alert, Fatal, fatal};
use super::client::Client;
use super::common::{Action, ClientSettings, ServerSettings};
use super::msgs::{TLS12, TLS13};
use super::record::{
    CT_ALERT, CT_APPLICATION_DATA, CT_CHANGE_CIPHER_SPEC, CT_HANDSHAKE, RecordLayer,
};
use super::server::Server;
use super::suites::Suite;

/// Largest handshake message accepted (certificate chains are the big ones).
pub(crate) const MAX_HANDSHAKE: usize = 1 << 17;
/// Consecutive warning alerts tolerated (TLS 1.2).
const MAX_WARNINGS: u32 = 4;
/// Rejected 0-RTT bytes the server skips.
const EARLY_DATA_SKIP: usize = 1 << 16;
/// TLS 1.3 records written under one key before a KeyUpdate (well under the AES-GCM limit of
/// RFC 8446 section 5.5).
const KEY_UPDATE_AFTER: u64 = 1 << 23;

/// The handshake state machine of either side.
pub(crate) enum Machine {
    Client(Box<Client>),
    Server(Box<Server>),
}

impl Machine {
    pub(crate) fn handle(&mut self, msg: &[u8], out: &mut Vec<Action>) -> Result<(), Fatal> {
        match self {
            Machine::Client(c) => c.handle(msg, out),
            Machine::Server(s) => s.handle(msg, out),
        }
    }

    fn change_cipher_spec(&mut self, out: &mut Vec<Action>) -> Result<(), Fatal> {
        match self {
            Machine::Client(c) => c.change_cipher_spec(out),
            Machine::Server(s) => s.change_cipher_spec(out),
        }
    }

    fn initiate_key_update(&mut self, out: &mut Vec<Action>) -> Result<(), Fatal> {
        match self {
            Machine::Client(c) => c.initiate_key_update(out),
            Machine::Server(s) => s.initiate_key_update(out),
        }
    }

    pub(crate) fn handshaking(&self) -> bool {
        match self {
            Machine::Client(c) => c.handshaking(),
            Machine::Server(s) => s.handshaking(),
        }
    }

    pub(crate) fn version(&self) -> u16 {
        match self {
            Machine::Client(c) => c.version,
            Machine::Server(s) => s.version,
        }
    }

    pub(crate) fn suite(&self) -> Option<&'static Suite> {
        match self {
            Machine::Client(c) => c.suite,
            Machine::Server(s) => s.suite,
        }
    }

    pub(crate) fn alpn(&self) -> Option<&[u8]> {
        match self {
            Machine::Client(c) => c.alpn.as_deref(),
            Machine::Server(s) => s.alpn.as_deref(),
        }
    }

    pub(crate) fn server_name(&self) -> Option<&str> {
        match self {
            Machine::Client(_) => None,
            Machine::Server(s) => s.sni.as_deref(),
        }
    }

    pub(crate) fn peer_chain(&self) -> &[Vec<u8>] {
        match self {
            Machine::Client(c) => &c.peer_chain,
            Machine::Server(s) => &s.peer_chain,
        }
    }

    pub(crate) fn resumed(&self) -> bool {
        match self {
            Machine::Client(c) => c.resumed,
            Machine::Server(s) => s.resumed,
        }
    }

    pub(crate) fn peer_quic(&self) -> Option<&[u8]> {
        match self {
            Machine::Client(c) => c.peer_quic.as_deref(),
            Machine::Server(s) => s.peer_quic.as_deref(),
        }
    }
}

/// A TLS connection: feed it what the peer sent, give it what the application sends, and it
/// produces the bytes for the wire.
pub struct Connection {
    m: Machine,
    rec: RecordLayer,
    rx: Vec<u8>,
    hs: Vec<u8>,
    pending: Vec<u8>,
    out_pending: Vec<u8>,
    actions: Vec<Action>,
    hs_out: Vec<u8>,
    received_close: bool,
    sent_close: bool,
    error: Option<Fatal>,
    warnings: u32,
    compat_ccs: bool,
    key_update_after: u64,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("handshaking", &self.handshaking())
            .field("version", &self.m.version())
            .finish_non_exhaustive()
    }
}

impl Connection {
    pub(crate) fn client(cfg: Arc<ClientSettings>, name: &str) -> Result<Connection, Fatal> {
        let mut c = Client::new(cfg, name, None)?;
        let mut actions = Vec::new();
        c.start(&mut actions)?;
        let mut conn = Connection::new(Machine::Client(Box::new(c)));
        let mut out = Vec::new();
        conn.apply(&mut actions, &mut out)?;
        conn.out_pending = out;
        Ok(conn)
    }

    pub(crate) fn server(cfg: Arc<ServerSettings>) -> Connection {
        let mut c = Connection::new(Machine::Server(Box::new(Server::new(cfg, None))));
        c.rec.first_write = false;
        c
    }

    fn new(m: Machine) -> Connection {
        Connection {
            m,
            rec: RecordLayer::new(),
            rx: Vec::new(),
            hs: Vec::new(),
            pending: Vec::new(),
            out_pending: Vec::new(),
            actions: Vec::new(),
            hs_out: Vec::new(),
            received_close: false,
            sent_close: false,
            error: None,
            warnings: 0,
            compat_ccs: false,
            key_update_after: KEY_UPDATE_AFTER,
        }
    }

    /// Still negotiating (also after a failure during the handshake: it counts as a failed
    /// handshake).
    pub fn handshaking(&self) -> bool {
        self.m.handshaking()
    }

    /// The peer sent close_notify.
    pub fn received_close_notify(&self) -> bool {
        self.received_close
    }

    /// `"TLSv1_3"`, `"TLSv1_2"` once negotiated.
    pub fn version_name(&self) -> Option<&'static str> {
        match self.m.version() {
            TLS13 => Some("TLSv1_3"),
            TLS12 => Some("TLSv1_2"),
            _ => None,
        }
    }

    /// The negotiated cipher suite.
    pub fn suite(&self) -> Option<&'static Suite> {
        self.m.suite()
    }

    /// The negotiated ALPN protocol.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.m.alpn()
    }

    /// The SNI name the client asked for (server side).
    pub fn server_name(&self) -> Option<&str> {
        self.m.server_name()
    }

    /// The peer's certificate chain (DER, leaf first).
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        self.m.peer_chain()
    }

    /// The session was resumed.
    pub fn resumed(&self) -> bool {
        self.m.resumed()
    }

    #[cfg(test)]
    pub(crate) fn test_record_layer(&mut self) -> &mut RecordLayer {
        &mut self.rec
    }

    #[doc(hidden)]
    pub fn set_key_update_after(&mut self, records: u64) {
        self.key_update_after = records;
    }

    /// Consumes bytes from the peer: decrypted application data goes to `plain`, bytes for the
    /// peer to `out`. On error, `out` holds the alert to send.
    pub fn recv(
        &mut self,
        input: &[u8],
        plain: &mut Vec<u8>,
        out: &mut Vec<u8>,
    ) -> Result<(), Fatal> {
        out.append(&mut self.out_pending);
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        if self.received_close {
            return Ok(());
        }
        self.rx.extend_from_slice(input);
        if let Err(e) = self.process(plain, out) {
            self.fail(&e, out);
            return Err(e);
        }
        if !self.m.handshaking() && !self.pending.is_empty() {
            let p = std::mem::take(&mut self.pending);
            self.seal(&p, out)?;
        }
        Ok(())
    }

    /// Encrypts application data (held back until the handshake completes).
    pub fn seal(&mut self, plain: &[u8], out: &mut Vec<u8>) -> Result<(), Fatal> {
        out.append(&mut self.out_pending);
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        if self.sent_close {
            return fatal(Alert::InternalError, "write after close_notify");
        }
        if self.m.handshaking() {
            self.pending.extend_from_slice(plain);
            return Ok(());
        }
        if self.m.version() == TLS13 && self.rec.write_seq() >= self.key_update_after {
            let mut acts = std::mem::take(&mut self.actions);
            let r = self
                .m
                .initiate_key_update(&mut acts)
                .and_then(|()| self.apply(&mut acts, out).map(|_| ()));
            self.actions = acts;
            if let Err(e) = r {
                self.fail(&e, out);
                return Err(e);
            }
        }
        if let Err(e) = self.rec.seal(CT_APPLICATION_DATA, plain, out) {
            self.fail(&e, out);
            return Err(e);
        }
        Ok(())
    }

    /// Sends close_notify.
    pub fn close(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.out_pending);
        if self.sent_close || self.error.is_some() {
            return;
        }
        self.sent_close = true;
        let _ = self.rec.seal(CT_ALERT, &[1, 0], out);
    }

    fn fail(&mut self, e: &Fatal, out: &mut Vec<u8>) {
        if self.error.is_some() {
            return;
        }
        if !e.from_peer {
            out.append(&mut self.hs_out);
            let _ = self.rec.seal(CT_ALERT, &[2, e.alert.code()], out);
        }
        self.error = Some(e.clone());
    }

    fn process(&mut self, plain: &mut Vec<u8>, out: &mut Vec<u8>) -> Result<(), Fatal> {
        let mut pos = 0;
        let r = self.process_records(&mut pos, plain, out);
        self.rx.drain(..pos);
        r
    }

    fn process_records(
        &mut self,
        pos: &mut usize,
        plain: &mut Vec<u8>,
        out: &mut Vec<u8>,
    ) -> Result<(), Fatal> {
        while let Some(n) = RecordLayer::frame(&self.rx[*pos..])? {
            let at = *pos;
            let o = self.rec.open(&mut self.rx[at..at + n])?;
            *pos += n;
            if o.skipped {
                continue;
            }
            let (a, b) = (at + o.start, at + o.end);
            match o.typ {
                CT_HANDSHAKE => {
                    if a == b {
                        return fatal(Alert::UnexpectedMessage, "empty handshake record");
                    }
                    self.warnings = 0;
                    self.hs.extend_from_slice(&self.rx[a..b]);
                    self.process_handshake(out)?;
                }
                CT_APPLICATION_DATA => {
                    if !self.hs.is_empty() {
                        return fatal(Alert::UnexpectedMessage, "data inside a handshake message");
                    }
                    if self.m.handshaking() {
                        return fatal(Alert::UnexpectedMessage, "data before the handshake");
                    }
                    self.warnings = 0;
                    plain.extend_from_slice(&self.rx[a..b]);
                }
                CT_ALERT => {
                    if !self.hs.is_empty() {
                        return fatal(Alert::UnexpectedMessage, "alert inside a handshake message");
                    }
                    if a == b {
                        return fatal(Alert::UnexpectedMessage, "empty alert record");
                    }
                    if b - a != 2 {
                        return fatal(Alert::DecodeError, "bad alert");
                    }
                    let (level, desc) = (self.rx[a], Alert::from_code(self.rx[a + 1]));
                    if desc == Alert::CloseNotify {
                        self.received_close = true;
                        return Ok(());
                    }
                    let tls13 = self.m.version() == TLS13 || self.rec.read_is_tls13();
                    if desc == Alert::UserCanceled || (level == 1 && !tls13) {
                        self.warnings += 1;
                        if self.warnings > MAX_WARNINGS {
                            return fatal(Alert::UnexpectedMessage, "too many warning alerts");
                        }
                        continue;
                    }
                    return Err(Fatal::peer(desc));
                }
                CT_CHANGE_CIPHER_SPEC => {
                    if self.rx[a..b] != [1] {
                        return fatal(Alert::UnexpectedMessage, "bad ChangeCipherSpec");
                    }
                    if !self.hs.is_empty() {
                        return fatal(Alert::UnexpectedMessage, "CCS inside a handshake message");
                    }
                    match self.m.version() {
                        TLS12 => {
                            let mut acts = std::mem::take(&mut self.actions);
                            let r = self
                                .m
                                .change_cipher_spec(&mut acts)
                                .and_then(|()| self.apply(&mut acts, out));
                            self.actions = acts;
                            r?;
                        }
                        // Middlebox compatibility (RFC 8446 appendix D.4).
                        // One per handshake.
                        TLS13 if self.m.handshaking() && !self.compat_ccs => {
                            self.compat_ccs = true;
                        }
                        _ => return fatal(Alert::UnexpectedMessage, "unexpected ChangeCipherSpec"),
                    }
                }
                _ => return fatal(Alert::UnexpectedMessage, "unknown content type"),
            }
        }
        Ok(())
    }

    fn process_handshake(&mut self, out: &mut Vec<u8>) -> Result<(), Fatal> {
        loop {
            if self.hs.len() < 4 {
                return Ok(());
            }
            let len = (usize::from(self.hs[1]) << 16)
                | (usize::from(self.hs[2]) << 8)
                | usize::from(self.hs[3]);
            if len > MAX_HANDSHAKE {
                return fatal(Alert::DecodeError, "handshake message too long");
            }
            if self.hs.len() < 4 + len {
                return Ok(());
            }
            let msg: Vec<u8> = self.hs.drain(..4 + len).collect();
            let mut acts = std::mem::take(&mut self.actions);
            let r = self
                .m
                .handle(&msg, &mut acts)
                .and_then(|()| self.apply(&mut acts, out));
            self.actions = acts;
            let read_changed = r?;
            if read_changed && !self.hs.is_empty() {
                return fatal(
                    Alert::UnexpectedMessage,
                    "handshake data across a key change",
                );
            }
        }
    }

    /// Applies the actions of one step; returns whether the read keys changed.
    fn apply(&mut self, acts: &mut Vec<Action>, out: &mut Vec<u8>) -> Result<bool, Fatal> {
        let mut read_changed = false;
        for a in acts.drain(..) {
            match a {
                Action::Msg(_, m) => self.hs_out.extend_from_slice(&m),
                Action::Ccs => {
                    self.flush_hs(out)?;
                    self.rec.seal(CT_CHANGE_CIPHER_SPEC, &[1], out)?;
                }
                Action::ReadKeys(_, k) => {
                    self.rec.set_read(&k);
                    read_changed = true;
                }
                Action::WriteKeys(_, k) => {
                    self.flush_hs(out)?;
                    self.rec.set_write(&k);
                }
                Action::Warning(alert) => {
                    self.flush_hs(out)?;
                    self.rec.seal(CT_ALERT, &[1, alert.code()], out)?;
                }
                Action::RejectEarlyData => self.rec.skip_early = EARLY_DATA_SKIP,
                Action::Done => {}
            }
        }
        self.flush_hs(out)?;
        Ok(read_changed)
    }

    fn flush_hs(&mut self, out: &mut Vec<u8>) -> Result<(), Fatal> {
        if self.hs_out.is_empty() {
            return Ok(());
        }
        let r = self.rec.seal(CT_HANDSHAKE, &self.hs_out, out);
        self.hs_out.clear();
        r
    }
}
