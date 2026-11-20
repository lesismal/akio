//! A TLS connection over a byte stream: the record layer driving a handshake state machine,
//! sans-io (bytes in, bytes out).

use std::sync::Arc;

use super::alert::{Alert, Fatal, fatal};
use super::client::Client;
#[cfg(feature = "ktls")]
use super::common::Keys;
use super::common::{Action, ClientSettings, EarlyData, Level, ServerSettings};
use super::msgs::{TLS12, TLS13};
use super::record::{
    CT_ALERT, CT_APPLICATION_DATA, CT_CHANGE_CIPHER_SPEC, CT_HANDSHAKE, HEADER_LEN, RecordLayer,
};
use super::server::Server;
use super::suites::Suite;
use crate::replay::Waker;

#[cfg(feature = "ktls")]
mod ktls;
#[cfg(feature = "ktls")]
pub use ktls::{DirKeys, Offload, OffloadEvent};

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

    pub(crate) fn early(&self) -> EarlyData {
        match self {
            Machine::Client(c) => c.early,
            Machine::Server(s) => s.early,
        }
    }

    pub(crate) fn cert_compressed(&self) -> Option<u16> {
        match self {
            Machine::Client(c) => c.cert_compressed,
            Machine::Server(s) => s.cert_compressed,
        }
    }

    pub(crate) fn ocsp(&self) -> Option<&[u8]> {
        match self {
            Machine::Client(c) => c.ocsp.as_deref(),
            Machine::Server(s) => s.peer_ocsp.as_deref(),
        }
    }

    fn is_client(&self) -> bool {
        matches!(self, Machine::Client(_))
    }

    /// A server waiting for an asynchronous anti-replay answer.
    pub(crate) fn suspended(&self) -> bool {
        matches!(self, Machine::Server(s) if s.suspended())
    }

    pub(crate) fn resume(&mut self, out: &mut Vec<Action>) -> Result<bool, Fatal> {
        match self {
            Machine::Client(_) => Ok(false),
            Machine::Server(s) => s.resume(out),
        }
    }

    pub(crate) fn set_replay_waker(&self, w: Waker) -> bool {
        match self {
            Machine::Client(_) => false,
            Machine::Server(s) => s.set_replay_waker(w),
        }
    }

    /// Rejected early data a server skips: what its tickets allow, at least 64 KiB.
    fn early_skip(&self) -> usize {
        match self {
            Machine::Client(_) => 0,
            Machine::Server(s) => EARLY_DATA_SKIP.max(s.max_early_data() as usize),
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
    /// Early data: bytes the ticket still allows (client) or still accepted (server).
    early_budget: usize,
    /// The client writes under the early keys (until the server's first message).
    early_writing: bool,
    /// The server reads under the early keys (until EndOfEarlyData).
    early_reading: bool,
    /// A copy of what the client sent early, sent again if the server rejects it.
    early_sent: Vec<u8>,
    /// Bytes sent (client) or received (server) as early data.
    early_len: u64,
    /// The record_size_limit we advertised once negotiated (0: none), enforced on what is read
    /// under every key but the early ones.
    read_limit: u16,
    /// Kernel TLS: keep the raw traffic keys (`read_keys` / `write_keys`) for an offload.
    #[cfg(feature = "ktls")]
    keep_keys: bool,
    #[cfg(feature = "ktls")]
    read_keys: Option<Keys>,
    #[cfg(feature = "ktls")]
    write_keys: Option<Keys>,
    /// The record layer moved into the kernel (`commit_offload`, `commit_rx_offload`): the
    /// receive direction too.
    #[cfg(feature = "ktls")]
    offloaded: bool,
    /// The send direction is in the kernel (`commit_tx_offload`): records to send become
    /// `kernel_ev` events instead of bytes.
    #[cfg(feature = "ktls")]
    tx_kernel: bool,
    #[cfg(feature = "ktls")]
    kernel_ev: Vec<OffloadEvent>,
    /// Records the kernel sent under the current send keys (approximate, see
    /// `kernel_records_sent`).
    #[cfg(feature = "ktls")]
    kernel_records: u64,
    /// Called when a suspended handshake can go on (an asynchronous anti-replay answer came).
    waker: Option<Waker>,
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
        let early = cfg.early_data;
        let mut c = Client::new(cfg, name, None, early, 0)?;
        let mut actions = Vec::new();
        c.start(&mut actions)?;
        let mut conn = Connection::new(Machine::Client(Box::new(c)));
        let mut out = Vec::new();
        conn.apply(&mut actions, &mut out)?;
        conn.out_pending = out;
        Ok(conn)
    }

    pub(crate) fn server(cfg: Arc<ServerSettings>) -> Connection {
        let mut c = Connection::new(Machine::Server(Box::new(Server::new(cfg, None, None))));
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
            early_budget: 0,
            early_writing: false,
            early_reading: false,
            early_sent: Vec::new(),
            early_len: 0,
            read_limit: 0,
            #[cfg(feature = "ktls")]
            keep_keys: false,
            #[cfg(feature = "ktls")]
            read_keys: None,
            #[cfg(feature = "ktls")]
            write_keys: None,
            #[cfg(feature = "ktls")]
            offloaded: false,
            #[cfg(feature = "ktls")]
            tx_kernel: false,
            #[cfg(feature = "ktls")]
            kernel_ev: Vec::new(),
            #[cfg(feature = "ktls")]
            kernel_records: 0,
            waker: None,
        }
    }

    /// Sets what to call when a suspended handshake can go on: the server's handshake waits
    /// for an asynchronous anti-replay store (ADR-062); calling [`recv`](Self::recv) (with no
    /// input) then takes it up again.
    pub(crate) fn set_waker(&mut self, w: Waker) {
        self.waker = Some(w);
    }

    /// The handshake is suspended, waiting for an asynchronous anti-replay answer.
    pub fn suspended(&self) -> bool {
        self.m.suspended()
    }

    /// While [`suspended`](Self::suspended): blocks until the answer is here (blocking
    /// drivers; then call [`recv`](Self::recv)).
    pub fn wait_resumable(&self) {
        if let Machine::Server(s) = &self.m {
            s.wait_replay();
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

    /// What happened to early data (0-RTT): offered, accepted, rejected.
    pub fn early_data(&self) -> EarlyData {
        self.m.early()
    }

    /// The OCSP response the peer stapled to its certificate, DER: the server's (client side,
    /// when asked for with `ocsp_stapling`; validated only under an `ocsp_policy`), or the
    /// client's (server side, TLS 1.3, when asked for with `client_ocsp_policy`, which
    /// validated it).
    pub fn ocsp_response(&self) -> Option<&[u8]> {
        self.m.ocsp()
    }

    /// The peer's certificate came compressed (RFC 8879).
    pub fn peer_certificate_compressed(&self) -> bool {
        self.m.cert_compressed().is_some()
    }

    /// The algorithm the peer's certificate came compressed with (RFC 8879), if it did.
    pub fn peer_certificate_compression(&self) -> Option<crate::CertCompression> {
        self.m
            .cert_compressed()
            .and_then(crate::CertCompression::from_id)
    }

    /// The record_size_limit values in force (RFC 8449): `(read, write)`, what we advertised
    /// and what the peer did; 0 when not negotiated.
    pub fn record_size_limits(&self) -> (u16, u16) {
        (self.read_limit, self.rec.write_limit)
    }

    /// Bytes of application data sent (client) or received (server) as early data: the first
    /// this many bytes of the stream. A client's count stays when the server rejects them
    /// (they are sent again after the handshake).
    pub fn early_data_len(&self) -> u64 {
        self.early_len
    }

    #[cfg(test)]
    pub(crate) fn test_record_layer(&mut self) -> &mut RecordLayer {
        &mut self.rec
    }

    /// Tests: lets a client send more early data than its ticket allows.
    #[cfg(test)]
    pub(crate) fn test_early_budget(&mut self, bytes: usize) {
        self.early_budget = bytes;
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
        if let Err(e) = self.recv_records(input, plain, out) {
            self.fail(&e, out);
            return Err(e);
        }
        if !self.early_sent.is_empty() && self.m.early() == EarlyData::Accepted {
            self.early_sent = Vec::new();
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
            // Early data (client): as much as the ticket allows, in order (nothing queued yet).
            let n = if self.early_writing && self.pending.is_empty() {
                plain.len().min(self.early_budget)
            } else {
                0
            };
            if n > 0 {
                if let Err(e) = self.rec.seal(CT_APPLICATION_DATA, &plain[..n], out) {
                    self.fail(&e, out);
                    return Err(e);
                }
                self.early_sent.extend_from_slice(&plain[..n]);
                self.early_budget -= n;
                self.early_len += n as u64;
            }
            self.pending.extend_from_slice(&plain[n..]);
            return Ok(());
        }
        if self.m.version() == TLS13
            && !self.kernel_tx()
            && self.rec.write_seq() >= self.key_update_after
        {
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
        if let Err(e) = self.emit(CT_APPLICATION_DATA, plain, out) {
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
        let _ = self.emit(CT_ALERT, &[1, 0], out);
    }

    fn fail(&mut self, e: &Fatal, out: &mut Vec<u8>) {
        if self.error.is_some() {
            return;
        }
        if !e.from_peer {
            if self.kernel_tx() {
                self.hs_out.clear();
            } else {
                out.append(&mut self.hs_out);
            }
            let _ = self.emit(CT_ALERT, &[2, e.alert.code()], out);
        }
        self.error = Some(e.clone());
    }

    /// Whether the send direction is in the kernel (kernel TLS).
    #[inline]
    fn kernel_tx(&self) -> bool {
        #[cfg(feature = "ktls")]
        {
            self.tx_kernel
        }
        #[cfg(not(feature = "ktls"))]
        {
            false
        }
    }

    /// Protects one record for the peer: through the record layer into `out`, or, with the
    /// send direction in the kernel, as an event for it (`take_kernel_events`).
    fn emit(&mut self, typ: u8, data: &[u8], out: &mut Vec<u8>) -> Result<(), Fatal> {
        #[cfg(feature = "ktls")]
        if self.tx_kernel {
            self.kernel_ev.push(OffloadEvent::Send(typ, data.to_vec()));
            return Ok(());
        }
        self.rec.seal(typ, data, out)
    }

    /// Takes in `input` after the handshake: completes a record left over from an earlier call,
    /// then opens whole records straight from `input` into `plain` (one copy instead of two:
    /// none into a receive buffer, none out of it) and keeps only a partial tail.
    fn recv_records(
        &mut self,
        mut input: &[u8],
        plain: &mut Vec<u8>,
        out: &mut Vec<u8>,
    ) -> Result<(), Fatal> {
        if !self.rx.is_empty() && !self.m.handshaking() {
            if self.rx.len() < HEADER_LEN {
                let take = (HEADER_LEN - self.rx.len()).min(input.len());
                self.rx.extend_from_slice(&input[..take]);
                input = &input[take..];
            }
            if self.rx.len() >= HEADER_LEN {
                let total = RecordLayer::record_len(&self.rx)?;
                let take = total.saturating_sub(self.rx.len()).min(input.len());
                self.rx.extend_from_slice(&input[..take]);
                input = &input[take..];
            }
            self.process(plain, out)?;
            if self.received_close {
                return Ok(());
            }
        }
        if !self.rx.is_empty() || self.m.handshaking() {
            self.rx.extend_from_slice(input);
            return self.process(plain, out);
        }
        let mut pos = 0;
        while let Some(n) = RecordLayer::frame(&input[pos..])? {
            let rec = &input[pos..pos + n];
            pos += n;
            let o = self.rec.open_into(rec, plain)?;
            if o.skipped {
                continue;
            }
            if o.typ == CT_APPLICATION_DATA {
                if let Err(e) = self.app_data_ok() {
                    plain.truncate(o.start);
                    return Err(e);
                }
                continue;
            }
            // Post-handshake messages and alerts are rare: move them out of `plain`.
            let content = plain.split_off(o.start);
            if !self.on_record(o.typ, &content, plain, out)? {
                return Ok(());
            }
            if self.m.handshaking() {
                break;
            }
        }
        self.rx.extend_from_slice(&input[pos..]);
        if self.m.handshaking() {
            return self.process(plain, out);
        }
        Ok(())
    }

    fn process(&mut self, plain: &mut Vec<u8>, out: &mut Vec<u8>) -> Result<(), Fatal> {
        if self.m.suspended() {
            if !self.resume_now(out)? {
                // What arrives meanwhile (early data under keys not decided yet) waits,
                // bounded.
                if self.rx.len() > 2 * self.m.early_skip() + MAX_HANDSHAKE {
                    return fatal(
                        Alert::UnexpectedMessage,
                        "too much data while the anti-replay check is pending",
                    );
                }
                return Ok(());
            }
            self.process_handshake(out)?;
        }
        // Records are opened in place in `rx`, taken out of `self` meanwhile so their contents
        // can be handed to `on_record`.
        let mut rx = std::mem::take(&mut self.rx);
        let mut pos = 0;
        let r = self.process_records(&mut rx, &mut pos, plain, out);
        rx.drain(..pos);
        self.rx = rx;
        r
    }

    fn process_records(
        &mut self,
        rx: &mut [u8],
        pos: &mut usize,
        plain: &mut Vec<u8>,
        out: &mut Vec<u8>,
    ) -> Result<(), Fatal> {
        while let Some(n) = RecordLayer::frame(&rx[*pos..])? {
            let at = *pos;
            let o = self.rec.open(&mut rx[at..at + n])?;
            *pos += n;
            if o.skipped {
                continue;
            }
            if !self.on_record(o.typ, &rx[at + o.start..at + o.end], plain, out)? {
                return Ok(());
            }
            if self.m.suspended() {
                // The rest is read once the ClientHello is taken up again.
                return Ok(());
            }
        }
        Ok(())
    }

    /// A suspended handshake: takes the ClientHello up again if the anti-replay answer is
    /// here (`true`), else registers the waker (`false`).
    fn resume_now(&mut self, out: &mut Vec<u8>) -> Result<bool, Fatal> {
        loop {
            let mut acts = std::mem::take(&mut self.actions);
            let r = match self.m.resume(&mut acts) {
                Ok(true) => self.apply(&mut acts, out).map(Some),
                Ok(false) => Ok(None),
                Err(e) => Err(e),
            };
            self.actions = acts;
            match r? {
                Some(read_changed) => {
                    if read_changed && !self.hs.is_empty() {
                        return fatal(
                            Alert::UnexpectedMessage,
                            "handshake data across a key change",
                        );
                    }
                    return Ok(true);
                }
                None => match &self.waker {
                    // Answered between the two looks: go on now.
                    Some(w) if !self.m.set_replay_waker(w.clone()) => {}
                    _ => return Ok(false),
                },
            }
        }
    }

    /// Application data may arrive now.
    fn app_data_ok(&mut self) -> Result<(), Fatal> {
        if !self.hs.is_empty() {
            return fatal(Alert::UnexpectedMessage, "data inside a handshake message");
        }
        if self.m.handshaking() {
            return fatal(Alert::UnexpectedMessage, "data before the handshake");
        }
        self.warnings = 0;
        Ok(())
    }

    /// Handles the content of one opened record; `false` once close_notify arrived (the rest
    /// is ignored).
    fn on_record(
        &mut self,
        typ: u8,
        content: &[u8],
        plain: &mut Vec<u8>,
        out: &mut Vec<u8>,
    ) -> Result<bool, Fatal> {
        match typ {
            CT_HANDSHAKE => {
                if content.is_empty() {
                    return fatal(Alert::UnexpectedMessage, "empty handshake record");
                }
                self.warnings = 0;
                self.hs.extend_from_slice(content);
                self.process_handshake(out)?;
            }
            CT_APPLICATION_DATA if self.early_reading => {
                if !self.hs.is_empty() {
                    return fatal(Alert::UnexpectedMessage, "data inside a handshake message");
                }
                // max_early_data_size (RFC 8446 section 4.2.10).
                if content.len() > self.early_budget {
                    return fatal(Alert::UnexpectedMessage, "too much early data");
                }
                self.early_budget -= content.len();
                self.early_len += content.len() as u64;
                plain.extend_from_slice(content);
            }
            CT_APPLICATION_DATA => {
                self.app_data_ok()?;
                plain.extend_from_slice(content);
            }
            CT_ALERT => {
                if !self.hs.is_empty() {
                    return fatal(Alert::UnexpectedMessage, "alert inside a handshake message");
                }
                if content.is_empty() {
                    return fatal(Alert::UnexpectedMessage, "empty alert record");
                }
                if content.len() != 2 {
                    return fatal(Alert::DecodeError, "bad alert");
                }
                let (level, desc) = (content[0], Alert::from_code(content[1]));
                if desc == Alert::CloseNotify {
                    self.received_close = true;
                    return Ok(false);
                }
                let tls13 = self.m.version() == TLS13 || self.rec.read_is_tls13();
                if desc == Alert::UserCanceled || (level == 1 && !tls13) {
                    self.warnings += 1;
                    if self.warnings > MAX_WARNINGS {
                        return fatal(Alert::UnexpectedMessage, "too many warning alerts");
                    }
                    return Ok(true);
                }
                return Err(Fatal::peer(desc));
            }
            CT_CHANGE_CIPHER_SPEC => {
                if content != [1] {
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
        Ok(true)
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
            // The server answered: no more early data (client).
            self.early_writing = false;
            let mut acts = std::mem::take(&mut self.actions);
            let r = self
                .m
                .handle(&msg, &mut acts)
                .and_then(|()| self.apply(&mut acts, out));
            self.actions = acts;
            let read_changed = r?;
            if self.m.suspended() {
                if !self.resume_now(out)? {
                    return Ok(());
                }
                continue;
            }
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
                Action::ReadKeys(l, k) => {
                    self.early_reading = l == Level::EarlyData;
                    // Early data was protected under the limits of an earlier connection.
                    self.rec.read_limit = if self.early_reading {
                        0
                    } else {
                        self.read_limit
                    };
                    self.rec.set_read(&k);
                    #[cfg(feature = "ktls")]
                    if self.keep_keys {
                        self.read_keys = Some(k);
                    }
                    read_changed = true;
                }
                Action::WriteKeys(l, k) => {
                    self.flush_hs(out)?;
                    self.early_writing = l == Level::EarlyData;
                    #[cfg(feature = "ktls")]
                    if self.tx_kernel {
                        // A key update answering the peer's: the kernel installs the new keys
                        // after the KeyUpdate just queued.
                        self.kernel_records = 0;
                        self.kernel_ev
                            .push(OffloadEvent::TxKeys(DirKeys::new(&k, 0)));
                        continue;
                    }
                    self.rec.set_write(&k);
                    #[cfg(feature = "ktls")]
                    if self.keep_keys {
                        self.write_keys = Some(k);
                    }
                }
                Action::Warning(alert) => {
                    self.flush_hs(out)?;
                    self.emit(CT_ALERT, &[1, alert.code()], out)?;
                }
                Action::RejectEarlyData if self.m.is_client() => {
                    // Back to plaintext (a ClientHello may follow) until the next keys; what
                    // went early goes again after the handshake, ahead of anything queued.
                    self.flush_hs(out)?;
                    self.rec.clear_write();
                    self.early_writing = false;
                    let mut again = std::mem::take(&mut self.early_sent);
                    again.append(&mut self.pending);
                    self.pending = again;
                }
                Action::RejectEarlyData => self.rec.skip_early = self.m.early_skip(),
                Action::EarlyOffered(max) | Action::EarlyAccepted(max) => {
                    self.early_budget = max as usize;
                }
                Action::RecordLimit { read, write } => {
                    // What is already queued went under the old limit.
                    self.flush_hs(out)?;
                    self.read_limit = read;
                    if !self.early_reading {
                        self.rec.read_limit = read;
                    }
                    self.rec.write_limit = write;
                }
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
        let hs = std::mem::take(&mut self.hs_out);
        let r = self.emit(CT_HANDSHAKE, &hs, out);
        self.hs_out = hs;
        self.hs_out.clear();
        r
    }
}
