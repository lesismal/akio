//! The DTLS 1.3 connection state machine (RFC 9147), sans-io.
//!
//! - Records: DTLSPlaintext in epoch 0, DTLSCiphertext with the unified header after it
//!   (16-bit sequence numbers, explicit length, the connection ID when negotiated) and record
//!   number encryption; epochs 2 (handshake) and 3+ (application, one per KeyUpdate) with a
//!   replay window each.
//! - Reliability (§7): every handshake record sent is remembered with the fragments it
//!   carried; ACKs mark fragments received and only the unacknowledged ones are retransmitted
//!   (exponential backoff). The receiver ACKs on gaps, after a quarter of the retransmission
//!   timeout when a flight stays incomplete, on the peer's final flight and on repeats.
//! - Handshake: ECDHE (X25519, P-256, P-384) with certificates (mutual by default), stateless
//!   HelloRetryRequest cookies, `psk_dhe_ke` with external PSKs or tickets, `use_srtp`,
//!   connection IDs, NewSessionTicket and KeyUpdate after the handshake.
//! - A peer that only speaks DTLS 1.2 makes the connection hand over to the DTLS 1.2 machine
//!   (`into_handoff`); the wrapper in `connection.rs` does that.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use only_crypto::pkey::PublicKey;
use only_x509::Certificate;

use crate::config::{Config, Fingerprint, FingerprintAlgorithm, SrtpKeys, SrtpProfile, Version};
use crate::conn::{
    Conn12, Event, Handoff, HandshakeInfo, Role, new_cid, srtp_mki_answer, srtp_mki_echo,
};
use crate::cookie::{self, HelloVerifier, HrrCookie};
use crate::crypto::{
    self, CipherSuite, KeyShare, NamedGroup, PrfHash, Protection13, SIGNATURE_SCHEMES,
    SIGNATURE_SCHEMES_13,
};
use crate::handshake::{self as hs, ClientHello, Extensions, Partial, PskOffer, ServerHello};
use crate::ks13::{self, Schedule};
use crate::record::{
    self, CT_ACK, CT_ALERT, CT_APPLICATION_DATA, CT_HANDSHAKE, DTLS12, DTLS13, Header,
    MAX_PLAINTEXT, ReplayWindow, Unified, Wire,
};
use crate::session::{Session, SessionState};
use crate::{AlertDescription, Error};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Handshake,
    Connected,
    Closed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    // client
    ServerHello,
    EncryptedExtensions,
    CertificateOrRequest,
    ServerCertificate,
    ServerCertificateVerify,
    ServerFinished,
    // server
    ClientHello,
    ClientCertificate,
    ClientCertificateVerify,
    ClientFinished,
    // both
    Done,
}

/// What a flight is for: handshake flights are answered by the peer's next flight (or ACKed
/// when final); post-handshake ones only by ACKs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlightKind {
    Handshake,
    KeyUpdate,
    Ticket,
}

/// A handshake message of an outgoing flight and which of its bytes the peer acknowledged.
#[derive(Debug, Clone)]
struct OutMsg {
    epoch: u64,
    msg_type: u8,
    seq: u16,
    body: Vec<u8>,
    /// Acknowledged byte ranges (merged).
    acked: Vec<(usize, usize)>,
}

impl OutMsg {
    fn ack(&mut self, s: usize, e: usize) {
        self.acked.push((s, e));
        self.acked.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(self.acked.len());
        for &(s, e) in &self.acked {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        self.acked = merged;
    }

    fn is_acked(&self) -> bool {
        // An empty message is acknowledged with the record that carried it (an empty range).
        self.acked
            .first()
            .is_some_and(|&(s, e)| s == 0 && e >= self.body.len())
    }

    /// The byte ranges still unacknowledged.
    fn missing(&self) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut at = 0;
        for &(s, e) in &self.acked {
            if s > at {
                out.push((at, s));
            }
            at = at.max(e);
        }
        if at < self.body.len() || (self.body.is_empty() && self.acked.is_empty()) {
            out.push((at, self.body.len()));
        }
        out
    }
}

/// An (epoch, sequence number) record number (RFC 9147 §4).
type RecordNumber = (u64, u64);
/// A fragment of a flight's message: (message index, offset, length).
type Fragment = (usize, usize, usize);

#[derive(Debug, Clone)]
struct Flight {
    kind: FlightKind,
    msgs: Vec<OutMsg>,
    /// Records sent: record number -> (message index, offset, length) of the fragments.
    sent: Vec<(RecordNumber, Vec<Fragment>)>,
    retransmits: u32,
}

impl Flight {
    fn is_acked(&self) -> bool {
        self.msgs.iter().all(OutMsg::is_acked)
    }
}

/// Read keys of one epoch with its replay window.
#[derive(Debug)]
struct ReadEpoch {
    epoch: u64,
    keys: Protection13,
    window: ReplayWindow,
}

/// Write keys of one epoch with its next sequence number.
#[derive(Debug)]
struct WriteEpoch {
    epoch: u64,
    keys: Protection13,
    seq: u64,
}

/// The PSK the client offers.
#[derive(Debug, Clone)]
struct OfferedPsk {
    identity: Vec<u8>,
    key: Vec<u8>,
    external: bool,
    hash: PrfHash,
    /// The resumed session (tickets).
    session: Option<SessionState>,
}

/// Records of epochs we have no keys for yet, and early application data, are buffered up to
/// these counts.
const MAX_EARLY_RECORDS: usize = 32;
const MAX_EARLY_APP: usize = 16;
/// Handshake messages accepted ahead of the next expected one.
const REASSEMBLY_WINDOW: u16 = 16;
/// Record numbers kept for ACKs, and sent records remembered per flight.
const MAX_ACK_RECORDS: usize = 32;
const MAX_SENT_RECORDS: usize = 256;
/// A post-handshake flight (NewSessionTicket, KeyUpdate) is given up after this many
/// retransmissions.
const MAX_POST_RETRANSMITS: u32 = 8;
/// Records sent in one epoch before an automatic KeyUpdate (RFC 9147 §4.5.3 bounds AES-GCM
/// to 2^24.5 records per key with a large margin).
const KEY_UPDATE_AFTER: u64 = 1 << 23;
/// Unified header length with a 16-bit sequence number and a length, without the CID.
const UNIFIED_HEADER: usize = 5;

fn random32() -> Result<[u8; 32], Error> {
    let mut r = [0u8; 32];
    only_crypto::rand::fill_random(&mut r)
        .map_err(|_| Error::Crypto(only_crypto::Error::Random))?;
    Ok(r)
}

fn unexpected(reason: &'static str) -> Error {
    Error::protocol(AlertDescription::UnexpectedMessage, reason)
}

fn handshake_failure(reason: &'static str) -> Error {
    Error::protocol(AlertDescription::HandshakeFailure, reason)
}

fn illegal(reason: &'static str) -> Error {
    Error::protocol(AlertDescription::IllegalParameter, reason)
}

/// The DTLS 1.3 suites of a configuration.
fn suites13(config: &Config) -> Vec<CipherSuite> {
    config
        .cipher_suites
        .iter()
        .copied()
        .filter(|s| s.is_tls13())
        .collect()
}

/// A DTLS 1.3 connection.
#[derive(Debug)]
pub(crate) struct Conn13 {
    config: Arc<Config>,
    role: Role,
    state: State,
    expect: Expect,
    peer_addr: Vec<u8>,
    hello_verifier: Option<HelloVerifier>,
    // negotiation
    suite: Option<CipherSuite>,
    /// TLS 1.3-style transcript (RFC 9147 §5.2).
    transcript: Vec<u8>,
    client_random: [u8; 32],
    /// Client: the ClientHello sent last and its message sequence number.
    client_hello: Option<(ClientHello, u16)>,
    key_shares: Vec<KeyShare>,
    hrr: bool,
    offer12: bool,
    offered_psk: Option<OfferedPsk>,
    /// The PSK in use: key, external, identity (external only), session (tickets).
    psk: Option<(Vec<u8>, bool, Option<Vec<u8>>)>,
    resumed: bool,
    schedule: Option<Schedule>,
    client_hs: Vec<u8>,
    server_hs: Vec<u8>,
    client_ap: Vec<u8>,
    server_ap: Vec<u8>,
    exporter: Vec<u8>,
    resumption: Vec<u8>,
    peer_chain: Vec<Vec<u8>>,
    peer_key: Option<PublicKey>,
    /// Client: the CertificateRequest's context and schemes.
    cert_request: Option<(Vec<u8>, Vec<u16>)>,
    /// Server: we asked for a client certificate; the client sent a non-empty one.
    cert_requested: bool,
    client_sent_cert: bool,
    /// Server: the client's signature_algorithms; whether it allows tickets (psk_dhe_ke).
    peer_schemes: Vec<u16>,
    peer_psk_dhe: bool,
    srtp_profile: Option<SrtpProfile>,
    srtp_mki: Option<Vec<u8>>,
    local_cid: Option<Vec<u8>>,
    peer_cid: Option<Vec<u8>>,
    // handshake messages
    send_seq: u16,
    recv_seq: u16,
    partials: BTreeMap<u16, (u64, Partial)>,
    flight: Option<Flight>,
    retransmit_at: Option<Instant>,
    rto: Duration,
    deadline: Instant,
    /// Record numbers of handshake records received since our last flight.
    ack_records: Vec<(u64, u64)>,
    ack_at: Option<Instant>,
    ack_now: bool,
    /// A gap in the peer's flight: ACK at the next timer (coalescing the datagrams that
    /// arrive together).
    ack_gap: bool,
    /// A KeyUpdate to send once the current flight is acknowledged (request the peer's).
    key_update_wanted: Option<bool>,
    tickets_sent: u8,
    // record layer
    epoch0_seq: u64,
    last_record_seq: u64,
    write_hs: Option<WriteEpoch>,
    write_app: Option<WriteEpoch>,
    read: Vec<ReadEpoch>,
    early_records: Vec<Vec<u8>>,
    early_app: Vec<Vec<u8>>,
    transmits: VecDeque<Vec<u8>>,
    events: VecDeque<Event>,
    info: Option<HandshakeInfo>,
    sent_close: bool,
    /// The peer speaks only DTLS 1.2: hand over (`take_handoff`).
    downgrade: bool,
    /// The latest time we were given (for flights started from API calls without one).
    now: Instant,
}

impl Conn13 {
    /// A client (resuming `resume` when it is a DTLS 1.3 session).
    pub(crate) fn client(
        config: Arc<Config>,
        now: Instant,
        resume: Option<Session>,
    ) -> Result<Conn13, Error> {
        let mut c = Conn13::new(config, Role::Client, now, &[])?;
        c.start_client(now, resume)?;
        Ok(c)
    }

    pub(crate) fn new(
        config: Arc<Config>,
        role: Role,
        now: Instant,
        peer: &[u8],
    ) -> Result<Conn13, Error> {
        if suites13(&config).is_empty() {
            return Err(Error::Config("no DTLS 1.3 cipher suites"));
        }
        if role == Role::Server && config.identity.is_none() && config.psks.is_empty() {
            return Err(Error::Config("a server needs an identity"));
        }
        let offer12 = config.versions.contains(&Version::Dtls12);
        if offer12 {
            crate::conn::check_config12(&config, role)?;
        }
        let hello_verifier = if role == Role::Server && config.hello_verify {
            Some(HelloVerifier::new(now)?)
        } else {
            None
        };
        let local_cid = new_cid(&config)?;
        Ok(Conn13 {
            role,
            state: State::Handshake,
            expect: match role {
                Role::Client => Expect::ServerHello,
                Role::Server => Expect::ClientHello,
            },
            peer_addr: peer.to_vec(),
            hello_verifier,
            suite: None,
            transcript: Vec::new(),
            client_random: random32()?,
            client_hello: None,
            key_shares: Vec::new(),
            hrr: false,
            offer12,
            offered_psk: None,
            psk: None,
            resumed: false,
            schedule: None,
            client_hs: Vec::new(),
            server_hs: Vec::new(),
            client_ap: Vec::new(),
            server_ap: Vec::new(),
            exporter: Vec::new(),
            resumption: Vec::new(),
            peer_chain: Vec::new(),
            peer_key: None,
            cert_request: None,
            cert_requested: false,
            client_sent_cert: false,
            peer_schemes: Vec::new(),
            peer_psk_dhe: false,
            srtp_profile: None,
            srtp_mki: None,
            local_cid,
            peer_cid: None,
            send_seq: 0,
            recv_seq: 0,
            partials: BTreeMap::new(),
            flight: None,
            retransmit_at: None,
            rto: config.initial_retransmit,
            deadline: now + config.handshake_timeout,
            ack_records: Vec::new(),
            ack_at: None,
            ack_now: false,
            ack_gap: false,
            key_update_wanted: None,
            tickets_sent: 0,
            epoch0_seq: 0,
            last_record_seq: 0,
            write_hs: None,
            write_app: None,
            read: Vec::new(),
            early_records: Vec::new(),
            early_app: Vec::new(),
            transmits: VecDeque::new(),
            events: VecDeque::new(),
            info: None,
            sent_close: false,
            downgrade: false,
            now,
            config,
        })
    }

    /// Whether the peer turned out to speak only DTLS 1.2.
    pub(crate) fn wants_downgrade(&self) -> bool {
        self.downgrade
    }

    /// What the DTLS 1.2 machine needs to continue the handshake (this connection is spent).
    pub(crate) fn take_handoff(&mut self) -> Handoff {
        self.state = State::Failed;
        let partials = std::mem::take(&mut self.partials)
            .into_iter()
            .filter(|(_, (e, _))| *e == 0)
            .map(|(k, (_, p))| (k, (0u16, p)))
            .collect();
        let client_hello = self.client_hello.take().map(|(mut ch, seq)| {
            // DTLS 1.2 servers ignore the DTLS 1.3 extensions; they stay so that the
            // HelloVerifyRequest retry is the same offer.
            ch.cookie.clear();
            (ch, seq)
        });
        Handoff {
            config: self.config.clone(),
            role: self.role,
            peer_addr: std::mem::take(&mut self.peer_addr),
            deadline: self.deadline,
            partials,
            recv_seq: self.recv_seq,
            send_seq: self.send_seq,
            epoch0_seq: self.epoch0_seq,
            last_record_seq: self.last_record_seq,
            client_hello,
            retransmit_at: self.retransmit_at,
            rto: self.rto,
            local_cid: self.local_cid.take(),
        }
    }

    pub(crate) fn role(&self) -> Role {
        self.role
    }

    pub(crate) fn is_connected(&self) -> bool {
        self.state == State::Connected
    }

    pub(crate) fn is_closed(&self) -> bool {
        matches!(self.state, State::Closed | State::Failed)
    }

    pub(crate) fn handshake_info(&self) -> Option<&HandshakeInfo> {
        self.info.as_ref()
    }

    pub(crate) fn local_cid(&self) -> Option<&[u8]> {
        self.local_cid.as_deref()
    }

    pub(crate) fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        self.transmits.pop_front()
    }

    pub(crate) fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub(crate) fn poll_timeout(&self) -> Option<Instant> {
        if self.is_closed() {
            return None;
        }
        let deadline = (self.state == State::Handshake).then_some(self.deadline);
        [deadline, self.retransmit_at, self.ack_at]
            .into_iter()
            .flatten()
            .min()
    }

    pub(crate) fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        if self.is_closed() {
            return Ok(());
        }
        self.now = self.now.max(now);
        if self.state == State::Handshake && now >= self.deadline {
            self.fail(&Error::Timeout);
            return Err(Error::Timeout);
        }
        if self.ack_at.is_some_and(|t| now >= t) {
            self.send_ack();
        }
        if let Some(t) = self.retransmit_at {
            if now >= t {
                let give_up = self.flight.as_ref().is_some_and(|f| {
                    f.retransmits >= MAX_POST_RETRANSMITS
                        && (f.kind != FlightKind::Handshake || self.state == State::Connected)
                });
                if give_up {
                    self.flight = None;
                    self.retransmit_at = None;
                } else {
                    self.transmit_flight();
                    if let Some(f) = &mut self.flight {
                        f.retransmits += 1;
                    }
                    self.rto = (self.rto * 2).min(self.config.max_retransmit);
                    self.retransmit_at = Some(now + self.rto);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn handle_datagram(&mut self, now: Instant, datagram: &[u8]) -> Result<(), Error> {
        if self.is_closed() {
            return Err(Error::Closed);
        }
        self.now = self.now.max(now);
        let cid_len = self.local_cid.as_ref().map_or(0, Vec::len);
        let mut retransmit = false;
        for w in record::split_cid(datagram, cid_len) {
            let keys_before = self.read.len();
            let r = match w {
                Wire::Plain {
                    h,
                    cid: None,
                    fragment,
                } => self.handle_plaintext(now, h, fragment, &mut retransmit),
                Wire::Plain { .. } => Ok(()),
                Wire::Unified(u) => self.handle_unified(now, &u, &mut retransmit),
            };
            if let Err(e) = r {
                self.fail(&e);
                return Err(e);
            }
            if self.downgrade || self.is_closed() {
                return Ok(());
            }
            if self.read.len() > keys_before && !self.early_records.is_empty() {
                for rec in std::mem::take(&mut self.early_records) {
                    for w in record::split_cid(&rec, cid_len) {
                        if let Wire::Unified(u) = w {
                            if let Err(e) = self.handle_unified(now, &u, &mut retransmit) {
                                self.fail(&e);
                                return Err(e);
                            }
                        }
                    }
                }
            }
        }
        if retransmit
            && self
                .flight
                .as_ref()
                .is_some_and(|f| f.kind == FlightKind::Handshake)
        {
            self.transmit_flight();
        }
        if self.ack_now {
            self.send_ack();
        } else if std::mem::take(&mut self.ack_gap) {
            self.ack_at = Some(self.ack_at.map_or(now, |t| t.min(now)));
        } else if !self.ack_records.is_empty()
            && self.ack_at.is_none()
            && self.state == State::Handshake
            && !self.partials.is_empty()
        {
            // Part of a flight arrived: ACK what we have if the rest does not follow soon.
            self.ack_at = Some(now + self.rto / 4);
        }
        Ok(())
    }

    pub(crate) fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        match self.state {
            State::Connected => {}
            State::Handshake => return Err(Error::NotConnected),
            _ => return Err(Error::Closed),
        }
        if data.len() > MAX_PLAINTEXT {
            return Err(Error::TooLarge);
        }
        let epoch = self.write_app.as_ref().map_or(3, |w| w.epoch);
        if let Some((r, _)) = self.seal(epoch, CT_APPLICATION_DATA, data) {
            self.transmits.push_back(r);
        }
        if self
            .write_app
            .as_ref()
            .is_some_and(|w| w.seq >= KEY_UPDATE_AFTER)
            && self.key_update_wanted.is_none()
        {
            self.update_keys(false)?;
        }
        Ok(())
    }

    /// Sends a KeyUpdate (after the current post-handshake flight, if any); the new keys are
    /// used once the peer acknowledged it (RFC 9147 §8).
    pub(crate) fn update_keys(&mut self, request_peer: bool) -> Result<(), Error> {
        match self.state {
            State::Connected => {}
            State::Handshake => return Err(Error::NotConnected),
            _ => return Err(Error::Closed),
        }
        if self.flight.is_some() {
            self.key_update_wanted = Some(request_peer || self.key_update_wanted == Some(true));
            return Ok(());
        }
        self.send_key_update(request_peer);
        Ok(())
    }

    fn send_key_update(&mut self, request_peer: bool) {
        self.key_update_wanted = None;
        let Some(epoch) = self.write_app.as_ref().map(|w| w.epoch) else {
            return;
        };
        let m = self.out_msg(epoch, hs::KEY_UPDATE, vec![u8::from(request_peer)], false);
        self.start_flight(self.now, FlightKind::KeyUpdate, vec![m]);
    }

    pub(crate) fn export_keying_material(
        &self,
        label: &str,
        context: Option<&[u8]>,
        len: usize,
    ) -> Result<Vec<u8>, Error> {
        if self.state != State::Connected {
            return Err(Error::Exporter("handshake not complete"));
        }
        self.export(label, context, len)
    }

    fn export(&self, label: &str, context: Option<&[u8]>, len: usize) -> Result<Vec<u8>, Error> {
        let suite = self.suite.ok_or(Error::Exporter("no cipher suite"))?;
        let h = suite.prf_hash();
        if len > 255 * h.len() {
            return Err(Error::Exporter("too long"));
        }
        Ok(ks13::export(
            h,
            &self.exporter,
            label.as_bytes(),
            context.unwrap_or_default(),
            len,
        ))
    }

    pub(crate) fn close(&mut self) {
        if matches!(self.state, State::Handshake | State::Connected) {
            self.send_alert(1, AlertDescription::CloseNotify);
            self.sent_close = true;
            self.state = State::Closed;
            self.retransmit_at = None;
            self.ack_at = None;
        }
    }

    // ---- record layer ----

    /// The epoch we currently send non-handshake records in.
    fn current_epoch(&self) -> u64 {
        if let Some(w) = &self.write_app {
            w.epoch
        } else if self.write_hs.is_some() {
            2
        } else {
            0
        }
    }

    /// A record of `content_type` in `epoch`, and its record number.
    fn seal(
        &mut self,
        epoch: u64,
        content_type: u8,
        payload: &[u8],
    ) -> Option<(Vec<u8>, (u64, u64))> {
        if epoch == 0 {
            let seq = self.epoch0_seq;
            self.epoch0_seq = (seq + 1).min(record::MAX_SEQ);
            let h = Header {
                content_type,
                version: DTLS12,
                epoch: 0,
                seq,
            };
            let mut out = Vec::with_capacity(record::HEADER_LEN + payload.len());
            h.encode(payload.len(), &mut out);
            out.extend_from_slice(payload);
            return Some((out, (0, seq)));
        }
        let cid = self.peer_cid.clone().filter(|c| !c.is_empty());
        let w = if epoch == 2 {
            self.write_hs.as_mut()?
        } else {
            self.write_app.as_mut().filter(|w| w.epoch == epoch)?
        };
        let seq = w.seq;
        w.seq += 1;
        let mut inner = Vec::with_capacity(payload.len() + 1);
        inner.extend_from_slice(payload);
        inner.push(content_type);
        let ct_len = inner.len() + 16;
        let mut header = Vec::with_capacity(UNIFIED_HEADER + cid.as_ref().map_or(0, Vec::len));
        header.push(0x20 | if cid.is_some() { 0x10 } else { 0 } | 0x08 | 0x04 | (epoch & 3) as u8);
        if let Some(c) = &cid {
            header.extend_from_slice(c);
        }
        let seq_at = header.len();
        header.extend_from_slice(&(seq as u16).to_be_bytes());
        header.extend_from_slice(&(ct_len as u16).to_be_bytes());
        let ct = w.keys.seal(seq, &header, &inner);
        let mut sample = [0u8; 16];
        sample.copy_from_slice(&ct[..16]);
        let mask = w.keys.mask(&sample);
        header[seq_at] ^= mask[0];
        header[seq_at + 1] ^= mask[1];
        header.extend_from_slice(&ct);
        Some((header, (epoch, seq)))
    }

    fn send_alert(&mut self, level: u8, desc: AlertDescription) {
        let epoch = self.current_epoch();
        if let Some((r, _)) = self.seal(epoch, CT_ALERT, &[level, desc.to_u8()]) {
            self.transmits.push_back(r);
        }
    }

    fn fail(&mut self, e: &Error) {
        if self.is_closed() {
            return;
        }
        if let Some(a) = e.alert() {
            self.send_alert(2, a);
        }
        self.state = State::Failed;
        self.retransmit_at = None;
        self.ack_at = None;
    }

    fn handle_plaintext(
        &mut self,
        now: Instant,
        h: Header,
        fragment: &[u8],
        retransmit: &mut bool,
    ) -> Result<(), Error> {
        if h.epoch != 0 {
            // A DTLS 1.2 encrypted record, or garbage.
            return Ok(());
        }
        self.last_record_seq = h.seq;
        match h.content_type {
            CT_HANDSHAKE => self.handle_handshake(now, 0, (0, h.seq), fragment, retransmit),
            // Unauthenticated alerts are only believed before any keys exist.
            CT_ALERT if self.read.is_empty() && self.state == State::Handshake => {
                self.handle_alert(fragment)
            }
            _ => Ok(()),
        }
    }

    fn handle_unified(
        &mut self,
        now: Instant,
        u: &Unified<'_>,
        retransmit: &mut bool,
    ) -> Result<(), Error> {
        if let Some(c) = u.cid {
            if Some(c) != self.local_cid.as_deref() {
                return Ok(());
            }
        }
        if u.ciphertext.len() < 16 {
            return Ok(());
        }
        let Some(idx) = self
            .read
            .iter()
            .enumerate()
            .filter(|(_, r)| (r.epoch & 3) as u8 == u.epoch_bits)
            .max_by_key(|(_, r)| r.epoch)
            .map(|(i, _)| i)
        else {
            if self.state == State::Handshake && self.early_records.len() < MAX_EARLY_RECORDS {
                let mut rec = u.header.to_vec();
                rec.extend_from_slice(u.ciphertext);
                self.early_records.push(rec);
            }
            return Ok(());
        };
        let r = &mut self.read[idx];
        let mut sample = [0u8; 16];
        sample.copy_from_slice(&u.ciphertext[..16]);
        let mask = r.keys.mask(&sample);
        let mut header = u.header.to_vec();
        let mut low = 0u64;
        for i in 0..u.seq_len {
            header[u.seq_at + i] ^= mask[i];
            low = low << 8 | u64::from(header[u.seq_at + i]);
        }
        let expected = r.window.next_expected();
        let seq = record::reconstruct_seq(expected, low, 8 * u.seq_len as u32);
        if !r.window.check(seq) {
            return Ok(());
        }
        let Some(mut inner) = r.keys.open(seq, &header, u.ciphertext) else {
            return Ok(());
        };
        r.window.accept(seq);
        let epoch = r.epoch;
        while inner.last() == Some(&0) {
            inner.pop();
        }
        let Some(content_type) = inner.pop() else {
            return Err(Error::protocol(
                AlertDescription::UnexpectedMessage,
                "record without a content type",
            ));
        };
        if inner.len() > MAX_PLAINTEXT {
            return Err(Error::protocol(
                AlertDescription::RecordOverflow,
                "record too large",
            ));
        }
        match content_type {
            CT_HANDSHAKE => self.handle_handshake(now, epoch, (epoch, seq), &inner, retransmit),
            CT_ACK => self.handle_ack(now, &inner),
            CT_ALERT => self.handle_alert(&inner),
            CT_APPLICATION_DATA if epoch >= 3 => {
                match self.state {
                    State::Connected => self.events.push_back(Event::ApplicationData(inner)),
                    State::Handshake if self.early_app.len() < MAX_EARLY_APP => {
                        self.early_app.push(inner);
                    }
                    _ => {}
                }
                Ok(())
            }
            _ => Err(unexpected("unexpected record type")),
        }
    }

    fn handle_alert(&mut self, p: &[u8]) -> Result<(), Error> {
        let [_level, desc] = p else {
            return Err(Error::decode("bad alert"));
        };
        let desc = AlertDescription::from_u8(*desc);
        match desc {
            AlertDescription::CloseNotify => {
                if !self.sent_close {
                    self.send_alert(1, AlertDescription::CloseNotify);
                    self.sent_close = true;
                }
                self.state = State::Closed;
                self.retransmit_at = None;
                self.ack_at = None;
                self.events.push_back(Event::Closed);
                Ok(())
            }
            AlertDescription::UserCanceled => Ok(()),
            // RFC 8446 §6: every other alert is fatal in (D)TLS 1.3.
            d => Err(Error::PeerAlert(d)),
        }
    }

    // ---- ACKs and flights ----

    fn handle_ack(&mut self, now: Instant, body: &[u8]) -> Result<(), Error> {
        let records = hs::parse_ack(body)?;
        let Some(f) = &mut self.flight else {
            return Ok(());
        };
        for rn in &records {
            if let Some(pos) = f.sent.iter().position(|(n, _)| n == rn) {
                let (_, frags) = f.sent.swap_remove(pos);
                for (m, off, len) in frags {
                    if let Some(msg) = f.msgs.get_mut(m) {
                        msg.ack(off, off + len);
                    }
                }
            }
        }
        if f.is_acked() {
            self.flight_done(now);
        }
        Ok(())
    }

    /// The current flight was acknowledged (by an ACK or the peer's next flight).
    fn flight_done(&mut self, now: Instant) {
        let Some(f) = self.flight.take() else {
            return;
        };
        self.retransmit_at = None;
        self.rto = self.config.initial_retransmit;
        if f.kind == FlightKind::KeyUpdate {
            // RFC 9147 §8: switch to the next epoch once the KeyUpdate is acknowledged.
            if let (Some(suite), Some(w)) = (self.suite, &self.write_app) {
                let next = w.epoch + 1;
                let secret = match self.role {
                    Role::Client => &mut self.client_ap,
                    Role::Server => &mut self.server_ap,
                };
                *secret = ks13::next_secret(suite.prf_hash(), secret);
                if let Ok(keys) = ks13::protection(suite, secret) {
                    self.write_app = Some(WriteEpoch {
                        epoch: next,
                        keys,
                        seq: 0,
                    });
                }
            }
        }
        if self.state == State::Connected {
            if let Some(req) = self.key_update_wanted {
                self.send_key_update(req);
            } else if self.role == Role::Server {
                let _ = self.maybe_send_ticket(now);
            }
        }
    }

    /// A message of ours: numbered and, for handshake messages, added to the transcript.
    fn out_msg(&mut self, epoch: u64, msg_type: u8, body: Vec<u8>, transcript: bool) -> OutMsg {
        let seq = self.send_seq;
        self.send_seq = self.send_seq.wrapping_add(1);
        if transcript {
            self.transcript
                .extend_from_slice(&hs::transcript13(msg_type, &body));
        }
        OutMsg {
            epoch,
            msg_type,
            seq,
            body,
            acked: Vec::new(),
        }
    }

    /// Makes `msgs` the current flight (it acknowledges the peer's), sends it and arms the
    /// retransmission timer.
    fn start_flight(&mut self, now: Instant, kind: FlightKind, msgs: Vec<OutMsg>) {
        self.flight = Some(Flight {
            kind,
            msgs,
            sent: Vec::new(),
            retransmits: 0,
        });
        if kind == FlightKind::Handshake {
            self.ack_records.clear();
            self.ack_at = None;
            self.ack_now = false;
        }
        self.transmit_flight();
        self.rto = self.config.initial_retransmit;
        self.retransmit_at = Some(now + self.rto);
    }

    /// Sends the unacknowledged fragments of the current flight, fragmented to the MTU, packed
    /// into datagrams; remembers which record carried what.
    fn transmit_flight(&mut self) {
        let Some(mut f) = self.flight.take() else {
            return;
        };
        let mtu = self.config.mtu;
        let overhead = self.suite.map_or(17, CipherSuite::overhead);
        let cid = self
            .peer_cid
            .as_ref()
            .map_or(0, |c| if c.is_empty() { 0 } else { c.len() });
        let mut datagram: Vec<u8> = Vec::new();
        for i in 0..f.msgs.len() {
            let (epoch, ty, seq, total) = {
                let m = &f.msgs[i];
                (m.epoch, m.msg_type, m.seq, m.body.len())
            };
            let room = mtu
                - hs::HEADER_LEN
                - if epoch == 0 {
                    record::HEADER_LEN
                } else {
                    UNIFIED_HEADER + cid + overhead
                };
            for (s, e) in f.msgs[i].missing() {
                let mut off = s;
                loop {
                    let n = (e - off).min(room);
                    let frag =
                        hs::encode_fragment(ty, seq, total, off, &f.msgs[i].body[off..off + n]);
                    let Some((rec, rn)) = self.seal(epoch, CT_HANDSHAKE, &frag) else {
                        break;
                    };
                    if f.sent.len() >= MAX_SENT_RECORDS {
                        f.sent.remove(0);
                    }
                    f.sent.push((rn, vec![(i, off, n)]));
                    if !datagram.is_empty() && datagram.len() + rec.len() > mtu {
                        self.transmits.push_back(std::mem::take(&mut datagram));
                    }
                    datagram.extend_from_slice(&rec);
                    off += n;
                    if off >= e {
                        break;
                    }
                }
            }
        }
        if !datagram.is_empty() {
            self.transmits.push_back(datagram);
        }
        self.flight = Some(f);
    }

    /// Sends an ACK of the handshake records received (needs epoch 2 or later keys).
    fn send_ack(&mut self) {
        self.ack_now = false;
        self.ack_gap = false;
        self.ack_at = None;
        if self.ack_records.is_empty() {
            return;
        }
        // The epoch of the newest record acknowledged, if we can still send in it (RFC 9147
        // §7 allows any epoch at least that; OpenSSL 4.1 clients only accept an ACK of their
        // final flight in the handshake epoch), else the current one.
        let newest = self.ack_records.iter().map(|r| r.0).max().unwrap_or(0);
        let epoch = if newest == 2 && self.write_hs.is_some() {
            2
        } else {
            self.current_epoch()
        };
        if epoch == 0 {
            return;
        }
        let max = ((self.config.mtu.saturating_sub(64)) / 16).clamp(1, MAX_ACK_RECORDS);
        let skip = self.ack_records.len().saturating_sub(max);
        let mut list: Vec<(u64, u64)> = self.ack_records[skip..].to_vec();
        list.sort_unstable();
        let body = hs::encode_ack(&list);
        if let Some((r, _)) = self.seal(epoch, CT_ACK, &body) {
            self.transmits.push_back(r);
        }
    }

    // ---- handshake messages ----

    fn handle_handshake(
        &mut self,
        now: Instant,
        epoch: u64,
        rn: (u64, u64),
        payload: &[u8],
        retransmit: &mut bool,
    ) -> Result<(), Error> {
        let Ok(frags) = hs::parse_fragments(payload) else {
            return Ok(());
        };
        if !self.ack_records.contains(&rn) {
            if self.ack_records.len() >= MAX_ACK_RECORDS {
                self.ack_records.remove(0);
            }
            self.ack_records.push(rn);
        }
        for f in frags {
            if self.expect == Expect::ClientHello
                && (f.msg_type != hs::CLIENT_HELLO || f.length > hs::MAX_CLIENT_HELLO || epoch != 0)
            {
                // Before a ClientHello only a plausibly sized one is reassembled.
                continue;
            }
            if self.expect == Expect::ClientHello && f.seq != self.recv_seq {
                // A new ClientHello (after a stateless HelloRetryRequest): restart.
                if !self.partials.contains_key(&f.seq) {
                    self.partials.clear();
                    self.recv_seq = f.seq;
                }
            }
            if f.seq < self.recv_seq {
                // The peer repeats a message we processed: our answer was lost (resend it),
                // or our ACK was (ACK again).
                *retransmit = true;
                self.ack_now = true;
                continue;
            }
            if f.seq >= self.recv_seq.saturating_add(REASSEMBLY_WINDOW) {
                continue;
            }
            let entry = self
                .partials
                .entry(f.seq)
                .or_insert_with(|| (epoch, Partial::new(&f)));
            if entry.0 != epoch {
                continue;
            }
            if f.seq > self.recv_seq || f.offset > entry.1.prefix() {
                // Out of order: tell the peer what we have (§7.1).
                self.ack_gap = true;
            }
            entry.1.add(&f);
        }
        loop {
            let ready = self
                .partials
                .get(&self.recv_seq)
                .is_some_and(|(_, p)| p.is_complete());
            if !ready {
                break;
            }
            let Some((epoch, p)) = self.partials.remove(&self.recv_seq) else {
                break;
            };
            let keep =
                matches!(self.expect, Expect::ClientHello | Expect::ServerHello).then(|| p.clone());
            let (msg_type, body) = p.into_message();
            let seq = self.recv_seq;
            self.process_message(now, epoch, msg_type, seq, &body)?;
            if self.downgrade {
                if let Some(p) = keep {
                    self.partials.insert(seq, (epoch, p));
                }
                return Ok(());
            }
            if self.recv_seq == seq {
                self.recv_seq = seq.wrapping_add(1);
            }
            if self.is_closed() {
                break;
            }
        }
        Ok(())
    }

    fn process_message(
        &mut self,
        now: Instant,
        epoch: u64,
        msg_type: u8,
        seq: u16,
        body: &[u8],
    ) -> Result<(), Error> {
        let need_epoch = match self.expect {
            Expect::ServerHello | Expect::ClientHello => 0,
            Expect::Done => 3,
            _ => 2,
        };
        let epoch_ok = if need_epoch == 3 {
            epoch >= 3
        } else {
            epoch == need_epoch
        };
        if !epoch_ok {
            return Err(unexpected("handshake message in the wrong epoch"));
        }
        let raw = hs::transcript13(msg_type, body);
        if matches!(
            self.expect,
            Expect::ClientCertificate | Expect::ClientCertificateVerify | Expect::ClientFinished
        ) {
            // The client's flight acknowledges ours.
            self.flight = None;
            self.retransmit_at = None;
        }
        match (self.expect, msg_type) {
            // ---- client ----
            (Expect::ServerHello, hs::HELLO_VERIFY_REQUEST) if self.offer12 => {
                // A DTLS 1.2 server (DTLS 1.3 has no HelloVerifyRequest).
                self.downgrade = true;
            }
            (Expect::ServerHello, hs::HELLO_VERIFY_REQUEST) => {
                return Err(Error::protocol(
                    AlertDescription::ProtocolVersion,
                    "DTLS 1.2 server",
                ));
            }
            (Expect::ServerHello, hs::SERVER_HELLO) => self.client_server_hello(now, body)?,
            (Expect::EncryptedExtensions, hs::ENCRYPTED_EXTENSIONS) => {
                self.client_encrypted_extensions(body)?;
                self.transcript.extend_from_slice(&raw);
                self.expect = if self.psk.is_some() {
                    Expect::ServerFinished
                } else {
                    Expect::CertificateOrRequest
                };
            }
            (Expect::CertificateOrRequest, hs::CERTIFICATE_REQUEST) => {
                let (ctx, schemes) = hs::parse_certificate_request13(body)?;
                if !ctx.is_empty() {
                    return Err(illegal("CertificateRequest context during the handshake"));
                }
                self.cert_request = Some((ctx, schemes));
                self.transcript.extend_from_slice(&raw);
                self.expect = Expect::ServerCertificate;
            }
            (Expect::CertificateOrRequest | Expect::ServerCertificate, hs::CERTIFICATE) => {
                let (ctx, chain) = hs::parse_certificate13(body)?;
                if !ctx.is_empty() {
                    return Err(illegal("Certificate context from the server"));
                }
                self.accept_certificate(chain)?;
                self.transcript.extend_from_slice(&raw);
                self.expect = Expect::ServerCertificateVerify;
            }
            (Expect::ServerCertificateVerify, hs::CERTIFICATE_VERIFY) => {
                self.check_certificate_verify(true, body)?;
                self.transcript.extend_from_slice(&raw);
                self.expect = Expect::ServerFinished;
            }
            (Expect::ServerFinished, hs::FINISHED) => {
                self.check_finished(true, body)?;
                self.transcript.extend_from_slice(&raw);
                self.client_final_flight(now)?;
            }
            // ---- server ----
            (Expect::ClientHello, hs::CLIENT_HELLO) => self.server_client_hello(now, seq, body)?,
            (Expect::ClientCertificate, hs::CERTIFICATE) => {
                let (ctx, chain) = hs::parse_certificate13(body)?;
                if !ctx.is_empty() {
                    return Err(illegal("Certificate context does not match"));
                }
                if chain.is_empty() {
                    if self.config.require_client_certificate {
                        return Err(Error::Certificate("client sent no certificate".into()));
                    }
                    self.expect = Expect::ClientFinished;
                } else {
                    self.accept_certificate(chain)?;
                    self.client_sent_cert = true;
                    self.expect = Expect::ClientCertificateVerify;
                }
                self.transcript.extend_from_slice(&raw);
            }
            (Expect::ClientCertificateVerify, hs::CERTIFICATE_VERIFY) => {
                self.check_certificate_verify(false, body)?;
                self.transcript.extend_from_slice(&raw);
                self.expect = Expect::ClientFinished;
            }
            (Expect::ClientFinished, hs::FINISHED) => {
                self.check_finished(false, body)?;
                self.transcript.extend_from_slice(&raw);
                self.resumption = self.derive(b"res master");
                // Our flight is answered; ACK the client's (final) one.
                self.flight = None;
                self.retransmit_at = None;
                self.ack_now = true;
                self.connected()?;
                self.maybe_send_ticket(now)?;
            }
            // ---- post-handshake ----
            (Expect::Done, hs::NEW_SESSION_TICKET) if self.role == Role::Client => {
                let t = hs::Ticket13::parse(body)?;
                self.ack_now = true;
                self.client_new_ticket(now, t);
            }
            (Expect::Done, hs::KEY_UPDATE) => {
                let requested = hs::parse_key_update(body)?;
                self.ack_now = true;
                self.peer_key_update(epoch)?;
                if requested && self.key_update_wanted.is_none() {
                    let pending_ku = self
                        .flight
                        .as_ref()
                        .is_some_and(|f| f.kind == FlightKind::KeyUpdate);
                    if !pending_ku {
                        self.update_keys(false)?;
                    }
                }
            }
            _ => return Err(unexpected("unexpected handshake message")),
        }
        Ok(())
    }

    fn hash(&self) -> PrfHash {
        self.suite.map_or(PrfHash::Sha256, CipherSuite::prf_hash)
    }

    fn transcript_hash(&self) -> Vec<u8> {
        self.hash().digest(&self.transcript)
    }

    fn derive(&self, label: &[u8]) -> Vec<u8> {
        let th = self.transcript_hash();
        self.schedule
            .as_ref()
            .map_or_else(Vec::new, |s| s.derive(label, &th))
    }

    fn check_finished(&self, server: bool, body: &[u8]) -> Result<(), Error> {
        let base = if server {
            &self.server_hs
        } else {
            &self.client_hs
        };
        let expected = ks13::finished_mac(self.hash(), base, &self.transcript_hash());
        if only_crypto::ct_eq(&expected, body) {
            Ok(())
        } else {
            Err(Error::protocol(
                AlertDescription::DecryptError,
                "bad Finished",
            ))
        }
    }

    fn finished(&self, server: bool) -> Vec<u8> {
        let base = if server {
            &self.server_hs
        } else {
            &self.client_hs
        };
        ks13::finished_mac(self.hash(), base, &self.transcript_hash())
    }

    fn check_certificate_verify(&self, server: bool, body: &[u8]) -> Result<(), Error> {
        let (scheme, sig) = hs::parse_signed(body)?;
        let offered: &[u16] = match self.role {
            Role::Server => &SIGNATURE_SCHEMES_13,
            Role::Client => &SIGNATURE_SCHEMES,
        };
        if !offered.contains(&scheme) {
            return Err(illegal("CertificateVerify scheme not offered"));
        }
        let key = self
            .peer_key
            .as_ref()
            .ok_or_else(|| unexpected("no peer key"))?;
        let input = crypto::certificate_verify_input(server, &self.transcript_hash());
        crypto::verify_signature13(key, scheme, &input, &sig)
    }

    fn accept_certificate(&mut self, chain: Vec<Vec<u8>>) -> Result<(), Error> {
        if chain.is_empty() {
            return Err(Error::Certificate("no certificate".into()));
        }
        let leaf = Certificate::from_der(chain[0].clone())
            .map_err(|e| Error::Certificate(format!("unparsable certificate: {e}")))?;
        let key = leaf.public_key().map_err(|_| {
            Error::protocol(
                AlertDescription::UnsupportedCertificate,
                "unsupported certificate key",
            )
        })?;
        self.config.verifier.verify(&chain)?;
        self.peer_key = Some(key);
        self.peer_chain = chain;
        Ok(())
    }

    /// Installs read and write keys of the handshake epoch from the handshake secrets.
    fn install_handshake_keys(&mut self) -> Result<(), Error> {
        let suite = self.suite.ok_or_else(|| handshake_failure("no suite"))?;
        let (w, r) = match self.role {
            Role::Client => (&self.client_hs, &self.server_hs),
            Role::Server => (&self.server_hs, &self.client_hs),
        };
        let wk = ks13::protection(suite, w)?;
        let rk = ks13::protection(suite, r)?;
        self.write_hs = Some(WriteEpoch {
            epoch: 2,
            keys: wk,
            seq: 0,
        });
        self.read.push(ReadEpoch {
            epoch: 2,
            keys: rk,
            window: ReplayWindow::default(),
        });
        Ok(())
    }

    /// Master secret, application traffic secrets and exporter from the transcript up to
    /// the server Finished; installs the epoch-3 keys.
    fn install_application_keys(&mut self) -> Result<(), Error> {
        let suite = self.suite.ok_or_else(|| handshake_failure("no suite"))?;
        if let Some(s) = &mut self.schedule {
            s.next(None);
        }
        self.client_ap = self.derive(b"c ap traffic");
        self.server_ap = self.derive(b"s ap traffic");
        self.exporter = self.derive(b"exp master");
        let (w, r) = match self.role {
            Role::Client => (&self.client_ap, &self.server_ap),
            Role::Server => (&self.server_ap, &self.client_ap),
        };
        let wk = ks13::protection(suite, w)?;
        let rk = ks13::protection(suite, r)?;
        self.write_app = Some(WriteEpoch {
            epoch: 3,
            keys: wk,
            seq: 0,
        });
        self.read.push(ReadEpoch {
            epoch: 3,
            keys: rk,
            window: ReplayWindow::default(),
        });
        Ok(())
    }

    /// The peer's KeyUpdate arrived in `epoch`: its next records come in `epoch + 1`.
    fn peer_key_update(&mut self, epoch: u64) -> Result<(), Error> {
        let suite = self.suite.ok_or_else(|| handshake_failure("no suite"))?;
        let newest = self.read.iter().map(|r| r.epoch).max().unwrap_or(0);
        if epoch != newest {
            // A repeated KeyUpdate (our ACK was lost): already applied.
            return Ok(());
        }
        let secret = match self.role {
            Role::Client => &mut self.server_ap,
            Role::Server => &mut self.client_ap,
        };
        *secret = ks13::next_secret(suite.prf_hash(), secret);
        let keys = ks13::protection(suite, secret)?;
        self.read.push(ReadEpoch {
            epoch: epoch + 1,
            keys,
            window: ReplayWindow::default(),
        });
        // Keep the handshake epoch (for repeats of the final flight) and two application
        // epochs (for reordered records).
        while self.read.iter().filter(|r| r.epoch >= 3).count() > 2 {
            if let Some(i) = self
                .read
                .iter()
                .enumerate()
                .filter(|(_, r)| r.epoch >= 3)
                .min_by_key(|(_, r)| r.epoch)
                .map(|(i, _)| i)
            {
                self.read.remove(i);
            }
        }
        if newest + 1 >= 6 {
            // Epoch 6 shares epoch 2's low bits.
            self.read.retain(|r| r.epoch != 2);
        }
        Ok(())
    }

    fn connected(&mut self) -> Result<(), Error> {
        self.state = State::Connected;
        self.expect = Expect::Done;
        self.partials.clear();
        self.early_records.clear();
        let suite = self.suite.ok_or_else(|| handshake_failure("no suite"))?;
        let srtp_keys = match self.srtp_profile {
            Some(p) => {
                let n = 2 * (p.master_key_len() + p.master_salt_len());
                Some(SrtpKeys::from_material(
                    p,
                    &self.export(crate::SRTP_EXPORTER_LABEL, None, n)?,
                ))
            }
            None => None,
        };
        let info = HandshakeInfo {
            cipher_suite: suite,
            peer_fingerprint: self
                .peer_chain
                .first()
                .map(|c| Fingerprint::of(FingerprintAlgorithm::Sha256, c)),
            peer_certificates: self.peer_chain.clone(),
            srtp_profile: self.srtp_profile,
            srtp_keys,
            srtp_mki: self.srtp_mki.clone(),
            extended_master_secret: true,
            version: Version::Dtls13,
            resumed: self.resumed,
            psk_identity: self.psk.as_ref().and_then(|(_, _, id)| id.clone()),
            local_connection_id: self.peer_cid.as_ref().and_then(|_| self.local_cid.clone()),
            peer_connection_id: self.peer_cid.clone(),
        };
        self.info = Some(info.clone());
        self.events.push_back(Event::Connected(Box::new(info)));
        for d in std::mem::take(&mut self.early_app) {
            self.events.push_back(Event::ApplicationData(d));
        }
        Ok(())
    }

    // ---- client ----

    fn start_client(&mut self, now: Instant, resume: Option<Session>) -> Result<(), Error> {
        let cfg = self.config.clone();
        let suites13 = suites13(&cfg);
        // The PSK to offer: a DTLS 1.3 session, else the first external PSK.
        self.offered_psk = match resume.filter(|s| s.state.version == Version::Dtls13) {
            Some(s) if suites13.contains(&s.state.suite) => Some(OfferedPsk {
                identity: s.ticket.clone(),
                key: s.state.secret.clone(),
                external: false,
                hash: s.state.suite.prf_hash(),
                session: Some(SessionState {
                    // Keep the ticket's age_add and receive time for the obfuscated age.
                    issued: u64::try_from(now.saturating_duration_since(s.received).as_millis())
                        .unwrap_or(u64::MAX),
                    ..s.state
                }),
            }),
            _ => cfg.psks.first().map(|p| OfferedPsk {
                identity: p.identity.clone(),
                key: p.key.clone(),
                external: true,
                hash: PrfHash::Sha256,
                session: None,
            }),
        };
        let group = NamedGroup::ALL[0];
        let share = KeyShare::generate(group)?;
        let mut ext = if self.offer12 {
            Conn12::client_extensions(&cfg, self.local_cid.as_deref(), None)
        } else {
            Extensions {
                groups: Some(NamedGroup::ALL.iter().map(|g| g.id()).collect()),
                signature_algorithms: Some(SIGNATURE_SCHEMES.to_vec()),
                srtp: (!cfg.srtp_profiles.is_empty()).then(|| {
                    (
                        cfg.srtp_profiles.iter().map(|p| p.id()).collect(),
                        cfg.srtp_mki.clone(),
                    )
                }),
                connection_id: self.local_cid.clone(),
                ..Extensions::default()
            }
        };
        ext.supported_versions = Some(if self.offer12 {
            vec![DTLS13, DTLS12]
        } else {
            vec![DTLS13]
        });
        ext.key_shares = Some(vec![(group.id(), share.public())]);
        if cfg.resumption || self.offered_psk.is_some() {
            ext.psk_modes = Some(vec![hs::PSK_DHE_KE]);
        }
        let mut suites: Vec<u16> = suites13.iter().map(|s| s.id()).collect();
        if self.offer12 {
            let mut ch12 = Conn12::client_hello12(&cfg, self.client_random, None, None);
            suites.append(&mut ch12.cipher_suites);
        }
        self.key_shares = vec![share];
        let ch = ClientHello {
            version: DTLS12,
            random: self.client_random,
            session_id: Vec::new(),
            cookie: Vec::new(),
            cipher_suites: suites,
            compression: vec![0],
            extensions: ext,
        };
        self.send_client_hello(now, ch, &[])
    }

    /// Adds the PSK offer with its binder (over `prefix` + the truncated ClientHello), sends
    /// the ClientHello as the current flight.
    fn send_client_hello(
        &mut self,
        now: Instant,
        mut ch: ClientHello,
        prefix: &[u8],
    ) -> Result<(), Error> {
        ch.extensions.psk_offer = None;
        if let Some(p) = &self.offered_psk {
            if self.hrr && self.suite.is_some_and(|s| s.prf_hash() != p.hash) {
                // The HelloRetryRequest picked a suite whose hash does not fit the PSK.
                self.offered_psk = None;
            }
        }
        if let Some(p) = &self.offered_psk {
            let age = match &p.session {
                Some(s) => u32::try_from(s.issued)
                    .unwrap_or(u32::MAX)
                    .wrapping_add(s.age_add),
                None => 0,
            };
            let offer = PskOffer {
                identities: vec![(p.identity.clone(), age)],
                binders: vec![vec![0; p.hash.len()]],
            };
            let binders_len = offer.binders_len();
            ch.extensions.psk_offer = Some(offer);
            let body = ch.encode();
            let mut t = prefix.to_vec();
            t.extend_from_slice(&hs::transcript13(hs::CLIENT_HELLO, &body));
            t.truncate(t.len() - binders_len);
            let early = Schedule::early(p.hash, Some(&p.key));
            let binder =
                ks13::finished_mac(p.hash, &early.binder_key(p.external), &p.hash.digest(&t));
            if let Some(o) = &mut ch.extensions.psk_offer {
                o.binders = vec![binder];
            }
        }
        let body = ch.encode();
        let m = self.out_msg(0, hs::CLIENT_HELLO, body.clone(), false);
        self.transcript = prefix.to_vec();
        self.transcript
            .extend_from_slice(&hs::transcript13(hs::CLIENT_HELLO, &body));
        self.client_hello = Some((ch, m.seq));
        self.start_flight(now, FlightKind::Handshake, vec![m]);
        Ok(())
    }

    fn client_server_hello(&mut self, now: Instant, body: &[u8]) -> Result<(), Error> {
        let sh = ServerHello::parse(body)?;
        let selected = sh
            .extensions
            .supported_versions
            .as_ref()
            .and_then(|v| v.first().copied());
        if selected != Some(DTLS13) {
            if self.offer12 && selected.is_none() && sh.version == DTLS12 && !sh.is_hrr() {
                self.downgrade = true;
                return Ok(());
            }
            return Err(Error::protocol(
                AlertDescription::ProtocolVersion,
                "server did not select DTLS 1.3",
            ));
        }
        let Some((ch, _)) = self.client_hello.clone() else {
            return Err(unexpected("no ClientHello"));
        };
        if sh.session_id != ch.session_id {
            return Err(illegal("legacy_session_id_echo does not match"));
        }
        if sh.compression != 0 {
            return Err(illegal("compression"));
        }
        let suite = CipherSuite::from_id(sh.cipher_suite)
            .filter(|s| s.is_tls13() && ch.cipher_suites.contains(&s.id()))
            .ok_or_else(|| illegal("cipher suite not offered"))?;
        if self.hrr && self.suite != Some(suite) {
            return Err(illegal("cipher suite differs from the HelloRetryRequest's"));
        }
        let raw = hs::transcript13(hs::SERVER_HELLO, body);
        if sh.is_hrr() {
            if self.hrr {
                return Err(unexpected("second HelloRetryRequest"));
            }
            let e = &sh.extensions;
            let offered_groups: Vec<u16> = ch
                .extensions
                .key_shares
                .as_ref()
                .map(|v| v.iter().map(|(g, _)| *g).collect())
                .unwrap_or_default();
            let new_group = match e.hrr_group {
                Some(g) => {
                    let g = NamedGroup::from_id(g).ok_or_else(|| illegal("group not offered"))?;
                    if offered_groups.contains(&g.id()) {
                        return Err(illegal("HelloRetryRequest for a group already shared"));
                    }
                    Some(g)
                }
                None => None,
            };
            if new_group.is_none() && e.cookie.is_none() {
                return Err(illegal("HelloRetryRequest changes nothing"));
            }
            self.hrr = true;
            self.suite = Some(suite);
            // Transcript: message_hash(ClientHello1) + HelloRetryRequest.
            let h = suite.prf_hash().digest(&self.transcript);
            let mut prefix = hs::transcript13(hs::MESSAGE_HASH, &h);
            prefix.extend_from_slice(&raw);
            let mut ch2 = ch;
            ch2.extensions.cookie = e.cookie.clone();
            if let Some(g) = new_group {
                let share = KeyShare::generate(g)?;
                ch2.extensions.key_shares = Some(vec![(g.id(), share.public())]);
                self.key_shares = vec![share];
            }
            // The answer to our ClientHello arrived: retransmissions stop with the new one.
            return self.send_client_hello(now, ch2, &prefix);
        }
        let e = &sh.extensions;
        let (group, public) = e
            .key_shares
            .as_ref()
            .and_then(|v| v.first())
            .ok_or_else(|| Error::protocol(AlertDescription::MissingExtension, "no key_share"))?;
        let share = self
            .key_shares
            .iter()
            .find(|k| k.group().id() == *group)
            .ok_or_else(|| illegal("key share for a group not offered"))?;
        let ecdhe = share.agree(public)?;
        self.psk = match (e.psk_selected, &self.offered_psk) {
            (Some(0), Some(p)) => {
                if p.hash != suite.prf_hash() {
                    return Err(illegal("PSK selected with another hash"));
                }
                if let Some(s) = &p.session {
                    if !s.peer_chain.is_empty() {
                        self.config.verifier.verify(&s.peer_chain)?;
                        self.peer_chain.clone_from(&s.peer_chain);
                    }
                }
                self.resumed = p.session.is_some();
                Some((
                    p.key.clone(),
                    p.external,
                    p.external.then(|| p.identity.clone()),
                ))
            }
            (Some(_), _) => return Err(illegal("PSK not offered")),
            (None, _) => None,
        };
        if let Some(cid) = &e.connection_id {
            if self.local_cid.is_none() {
                return Err(Error::protocol(
                    AlertDescription::UnsupportedExtension,
                    "connection_id not offered",
                ));
            }
            self.peer_cid = Some(cid.clone());
        }
        self.suite = Some(suite);
        self.transcript.extend_from_slice(&raw);
        let mut s = Schedule::early(
            suite.prf_hash(),
            self.psk.as_ref().map(|(k, _, _)| k.as_slice()),
        );
        s.next(Some(&ecdhe));
        let th = self.transcript_hash();
        self.client_hs = s.derive(b"c hs traffic", &th);
        self.server_hs = s.derive(b"s hs traffic", &th);
        self.schedule = Some(s);
        self.install_handshake_keys()?;
        // The ServerHello acknowledges our ClientHello.
        self.flight = None;
        self.retransmit_at = None;
        self.expect = Expect::EncryptedExtensions;
        Ok(())
    }

    fn client_encrypted_extensions(&mut self, body: &[u8]) -> Result<(), Error> {
        let e = hs::parse_encrypted_extensions(body)?;
        if e.key_shares.is_some() || e.supported_versions.is_some() || e.psk_selected.is_some() {
            return Err(illegal("handshake extension in EncryptedExtensions"));
        }
        if let Some((profiles, mki)) = &e.srtp {
            let [id] = profiles.as_slice() else {
                return Err(illegal("use_srtp must select one profile"));
            };
            let p = SrtpProfile::from_id(*id)
                .filter(|p| self.config.srtp_profiles.contains(p))
                .ok_or_else(|| illegal("SRTP profile not offered"))?;
            self.srtp_mki = srtp_mki_answer(&self.config, mki)?;
            self.srtp_profile = Some(p);
        }
        if let Some(cid) = &e.connection_id {
            if self.local_cid.is_none() {
                return Err(Error::protocol(
                    AlertDescription::UnsupportedExtension,
                    "connection_id not offered",
                ));
            }
            self.peer_cid = Some(cid.clone());
        }
        if self.peer_cid.is_none() {
            self.local_cid = None;
        }
        Ok(())
    }

    /// After the server Finished: application keys, our Certificate / CertificateVerify /
    /// Finished, connected.
    fn client_final_flight(&mut self, now: Instant) -> Result<(), Error> {
        // Application secrets from the transcript up to the server Finished.
        self.install_application_keys()?;
        // install_application_keys made epoch 3 the write epoch; the final flight is epoch 2.
        let mut msgs = Vec::new();
        if let Some((ctx, schemes)) = self.cert_request.clone() {
            let identity = self.config.identity.clone();
            let chain = identity
                .as_ref()
                .map(|i| i.chain().to_vec())
                .unwrap_or_default();
            msgs.push(self.out_msg(
                2,
                hs::CERTIFICATE,
                hs::encode_certificate13(&ctx, &chain),
                true,
            ));
            if let Some(id) = identity {
                let scheme =
                    crypto::choose_scheme13(id.private_key(), &schemes).ok_or_else(|| {
                        handshake_failure("no signature scheme for the client certificate")
                    })?;
                let input = crypto::certificate_verify_input(false, &self.transcript_hash());
                let sig = crypto::sign(id.private_key(), scheme, &input)?;
                msgs.push(self.out_msg(
                    2,
                    hs::CERTIFICATE_VERIFY,
                    hs::encode_signed(scheme, &sig),
                    true,
                ));
            }
        }
        let fin = self.finished(false);
        msgs.push(self.out_msg(2, hs::FINISHED, fin, true));
        self.resumption = self.derive(b"res master");
        self.start_flight(now, FlightKind::Handshake, msgs);
        self.connected()
    }

    fn client_new_ticket(&mut self, now: Instant, t: hs::Ticket13) {
        if !self.config.resumption || t.lifetime == 0 {
            return;
        }
        let Some(suite) = self.suite else { return };
        let h = suite.prf_hash();
        let state = SessionState {
            version: Version::Dtls13,
            suite,
            secret: ks13::ticket_psk(h, &self.resumption, &t.nonce),
            ems: true,
            issued: crate::session::unix_now(),
            lifetime: t.lifetime.min(7 * 24 * 3600),
            age_add: t.age_add,
            peer_chain: self.peer_chain.clone(),
        };
        self.events.push_back(Event::NewSession(Box::new(Session {
            state,
            session_id: Vec::new(),
            ticket: t.ticket,
            received: now,
        })));
    }

    // ---- server ----

    fn server_client_hello(&mut self, now: Instant, seq: u16, body: &[u8]) -> Result<(), Error> {
        let ch = ClientHello::parse(body)?;
        if !cookie::offers13(&ch) {
            if self.config.versions.contains(&Version::Dtls12) {
                self.downgrade = true;
                return Ok(());
            }
            return Err(Error::protocol(
                AlertDescription::ProtocolVersion,
                "DTLS 1.3 required",
            ));
        }
        if !ch.compression.contains(&0) {
            return Err(illegal("null compression not offered"));
        }
        let ours = suites13(&self.config);
        // The HelloRetryRequest cookie: our earlier choices and ClientHello1's hash.
        let cookie = match &ch.extensions.cookie {
            Some(c) => {
                let parsed = match &self.hello_verifier {
                    Some(v) => v.open_hrr_cookie(now, &self.peer_addr, c),
                    // A listener's HelloVerifier checked it.
                    None => HrrCookie::decode_unverified(c),
                };
                let Some(parsed) = parsed else {
                    // Forged or expired: drop the ClientHello, keep no state.
                    self.recv_seq = seq.wrapping_add(1);
                    return Ok(());
                };
                if !ours.contains(&parsed.suite) || !ch.cipher_suites.contains(&parsed.suite.id()) {
                    return Err(handshake_failure("cookie cipher suite not usable"));
                }
                Some((parsed, c.clone()))
            }
            None => None,
        };
        let suite = match &cookie {
            Some((c, _)) => c.suite,
            None => ours
                .iter()
                .copied()
                .find(|s| ch.cipher_suites.contains(&s.id()))
                .ok_or_else(|| handshake_failure("no shared cipher suite"))?,
        };
        let e = &ch.extensions;
        let shares = e.key_shares.clone().unwrap_or_default();
        let share = NamedGroup::ALL.iter().find_map(|g| {
            shares
                .iter()
                .find(|(id, _)| *id == g.id())
                .map(|(_, k)| (*g, k.clone()))
        });
        let needs_hrr = cookie.is_none() && (self.hello_verifier.is_some() || share.is_none());
        if needs_hrr {
            // Stateless HelloRetryRequest (RFC 9147 §5.1): everything we need comes back in
            // the cookie.
            let group = cookie::hrr_group(&ch, &NamedGroup::ALL);
            if share.is_none() && group.is_none() {
                return Err(handshake_failure("no shared group"));
            }
            let verifier = match &self.hello_verifier {
                Some(v) => v.clone(),
                None => HelloVerifier::new(now)?,
            };
            let c = HrrCookie::new(suite, group, body);
            let cookie = verifier.hrr_cookie(now, &self.peer_addr, &c);
            self.hello_verifier.get_or_insert(verifier);
            let d = cookie::hrr_datagram(seq, self.last_record_seq, &ch, suite, group, &cookie);
            self.transmits.push_back(d);
            self.recv_seq = seq.wrapping_add(1);
            return Ok(());
        }
        let (group, peer_public) =
            share.ok_or_else(|| illegal("no key share for the HelloRetryRequest's group"))?;
        if let Some((c, _)) = &cookie {
            if c.group.is_some_and(|g| g != group) {
                return Err(illegal("key share does not match the HelloRetryRequest"));
            }
        }
        self.suite = Some(suite);
        let h = suite.prf_hash();
        // Transcript: (message_hash + HelloRetryRequest +) ClientHello.
        self.transcript.clear();
        if let Some((c, raw_cookie)) = &cookie {
            self.hrr = true;
            // After a stateless HelloRetryRequest (sent with ClientHello1's record number)
            // continue from ClientHello2's, so no record number repeats (RFC 9147 §5.1).
            self.epoch0_seq = self.epoch0_seq.max(self.last_record_seq);
            self.transcript
                .extend_from_slice(&hs::transcript13(hs::MESSAGE_HASH, &c.ch1_hash));
            let hrr = cookie::hrr_body(&ch.session_id, suite, c.group, raw_cookie);
            self.transcript
                .extend_from_slice(&hs::transcript13(hs::SERVER_HELLO, &hrr));
        }
        self.transcript
            .extend_from_slice(&hs::transcript13(hs::CLIENT_HELLO, body));
        self.client_random = ch.random;
        self.send_seq = seq;
        self.peer_schemes = e.signature_algorithms.clone().unwrap_or_default();
        self.peer_psk_dhe = e
            .psk_modes
            .as_ref()
            .is_some_and(|m| m.contains(&hs::PSK_DHE_KE));
        // PSK (RFC 8446 §4.2.11): the first identity we know, binder checked.
        let mut selected = None;
        if let (Some(offer), true) = (&e.psk_offer, self.peer_psk_dhe) {
            for (i, (id, _age)) in offer.identities.iter().enumerate() {
                let found = if let Some(p) = self.config.psks.iter().find(|p| p.identity == *id) {
                    (h == PrfHash::Sha256).then(|| (p.key.clone(), true, None))
                } else if self.config.resumption {
                    self.config
                        .ticket_key
                        .as_ref()
                        .and_then(|k| k.open(id))
                        .filter(|s| {
                            s.version == Version::Dtls13
                                && s.suite.prf_hash() == h
                                && (s.peer_chain.is_empty()
                                    || self.config.verifier.verify(&s.peer_chain).is_ok())
                        })
                        .map(|s| (s.secret.clone(), false, Some(s)))
                } else {
                    None
                };
                let Some((key, external, session)) = found else {
                    continue;
                };
                let mut t = self.transcript.clone();
                t.truncate(t.len() - offer.binders_len());
                let early = Schedule::early(h, Some(&key));
                let expected = ks13::finished_mac(h, &early.binder_key(external), &h.digest(&t));
                if !only_crypto::ct_eq(&expected, &offer.binders[i]) {
                    return Err(Error::protocol(
                        AlertDescription::DecryptError,
                        "bad PSK binder",
                    ));
                }
                selected = Some((i, key, external, id.clone(), session));
                break;
            }
        }
        if let Some((_, key, external, id, session)) = &selected {
            if let Some(s) = session {
                self.peer_chain.clone_from(&s.peer_chain);
                self.resumed = true;
            }
            self.psk = Some((key.clone(), *external, external.then(|| id.clone())));
        }
        self.srtp_profile = e.srtp.as_ref().and_then(|(offered, _)| {
            self.config
                .srtp_profiles
                .iter()
                .copied()
                .find(|p| offered.contains(&p.id()))
        });
        self.srtp_mki = srtp_mki_echo(&self.config, self.srtp_profile, e.srtp.as_ref());
        match (&e.connection_id, &self.local_cid) {
            (Some(peer), Some(_)) => self.peer_cid = Some(peer.clone()),
            _ => self.local_cid = None,
        }
        // ServerHello.
        let share = KeyShare::generate(group)?;
        let ecdhe = share.agree(&peer_public)?;
        let sh = ServerHello {
            version: DTLS12,
            random: random32()?,
            session_id: ch.session_id.clone(),
            cipher_suite: suite.id(),
            compression: 0,
            extensions: Extensions {
                supported_versions: Some(vec![DTLS13]),
                key_shares: Some(vec![(group.id(), share.public())]),
                psk_selected: selected.as_ref().map(|(i, ..)| *i as u16),
                connection_id: self.peer_cid.as_ref().and_then(|_| self.local_cid.clone()),
                ..Extensions::default()
            },
        };
        let mut msgs = vec![self.out_msg(0, hs::SERVER_HELLO, sh.encode(), true)];
        let mut s = Schedule::early(h, self.psk.as_ref().map(|(k, _, _)| k.as_slice()));
        s.next(Some(&ecdhe));
        let th = self.transcript_hash();
        self.client_hs = s.derive(b"c hs traffic", &th);
        self.server_hs = s.derive(b"s hs traffic", &th);
        self.schedule = Some(s);
        self.install_handshake_keys()?;
        let ee = Extensions {
            srtp: self
                .srtp_profile
                .map(|p| (vec![p.id()], self.srtp_mki.clone().unwrap_or_default())),
            ..Extensions::default()
        };
        msgs.push(self.out_msg(
            2,
            hs::ENCRYPTED_EXTENSIONS,
            hs::encode_encrypted_extensions(&ee),
            true,
        ));
        if self.psk.is_none() {
            let identity = self
                .config
                .identity
                .clone()
                .ok_or_else(|| handshake_failure("no certificate and no PSK"))?;
            self.cert_requested = self.config.require_client_certificate;
            if self.cert_requested {
                let req = hs::encode_certificate_request13(&[], &SIGNATURE_SCHEMES_13);
                msgs.push(self.out_msg(2, hs::CERTIFICATE_REQUEST, req, true));
            }
            msgs.push(self.out_msg(
                2,
                hs::CERTIFICATE,
                hs::encode_certificate13(&[], identity.chain()),
                true,
            ));
            let scheme = crypto::choose_scheme13(identity.private_key(), &self.peer_schemes)
                .ok_or_else(|| handshake_failure("no shared signature scheme"))?;
            let input = crypto::certificate_verify_input(true, &self.transcript_hash());
            let sig = crypto::sign(identity.private_key(), scheme, &input)?;
            msgs.push(self.out_msg(
                2,
                hs::CERTIFICATE_VERIFY,
                hs::encode_signed(scheme, &sig),
                true,
            ));
        }
        let fin = self.finished(true);
        msgs.push(self.out_msg(2, hs::FINISHED, fin, true));
        self.install_application_keys()?;
        self.start_flight(now, FlightKind::Handshake, msgs);
        self.expect = if self.cert_requested {
            Expect::ClientCertificate
        } else {
            Expect::ClientFinished
        };
        Ok(())
    }

    /// Server, after the handshake: one NewSessionTicket when resumption is on and the client
    /// allows `psk_dhe_ke`.
    fn maybe_send_ticket(&mut self, now: Instant) -> Result<(), Error> {
        if !self.config.resumption
            || !self.peer_psk_dhe
            || self.tickets_sent > 0
            || self.flight.is_some()
        {
            return Ok(());
        }
        let (Some(suite), Some(key)) = (self.suite, self.config.ticket_key.clone()) else {
            return Ok(());
        };
        self.tickets_sent += 1;
        let nonce = vec![self.tickets_sent];
        let mut age_add = [0u8; 4];
        only_crypto::rand::fill_random(&mut age_add)
            .map_err(|_| Error::Crypto(only_crypto::Error::Random))?;
        let lifetime = u32::try_from(self.config.ticket_lifetime.as_secs()).unwrap_or(u32::MAX);
        let state = SessionState {
            version: Version::Dtls13,
            suite,
            secret: ks13::ticket_psk(suite.prf_hash(), &self.resumption, &nonce),
            ems: true,
            issued: crate::session::unix_now(),
            lifetime,
            age_add: u32::from_be_bytes(age_add),
            peer_chain: self.peer_chain.clone(),
        };
        let Some(ticket) = key.seal(&state) else {
            return Ok(());
        };
        let t = hs::Ticket13 {
            lifetime,
            age_add: state.age_add,
            nonce,
            ticket,
        };
        let epoch = self.write_app.as_ref().map_or(3, |w| w.epoch);
        let m = self.out_msg(epoch, hs::NEW_SESSION_TICKET, t.encode(), false);
        // The ACK of the client's flight goes first.
        if self.ack_now {
            self.send_ack();
        }
        self.start_flight(now, FlightKind::Ticket, vec![m]);
        Ok(())
    }
}

impl ReplayWindow {
    /// The sequence number expected next (one past the highest accepted).
    pub(crate) fn next_expected(&self) -> u64 {
        self.top().map_or(0, |t| t + 1)
    }
}

impl KeyShare {
    pub(crate) fn group(&self) -> NamedGroup {
        match self {
            KeyShare::X25519(_) => NamedGroup::X25519,
            KeyShare::P256(_) => NamedGroup::Secp256r1,
            KeyShare::P384(_) => NamedGroup::Secp384r1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_msg_ranges() {
        let mut m = OutMsg {
            epoch: 2,
            msg_type: hs::FINISHED,
            seq: 0,
            body: vec![0; 100],
            acked: Vec::new(),
        };
        assert_eq!(m.missing(), vec![(0, 100)]);
        m.ack(10, 20);
        m.ack(50, 60);
        assert_eq!(m.missing(), vec![(0, 10), (20, 50), (60, 100)]);
        m.ack(0, 10);
        m.ack(15, 55);
        assert_eq!(m.missing(), vec![(60, 100)]);
        assert!(!m.is_acked());
        m.ack(60, 100);
        assert!(m.is_acked());
        assert!(m.missing().is_empty());
        let mut e = OutMsg {
            body: Vec::new(),
            ..m
        };
        e.acked.clear();
        assert_eq!(e.missing(), vec![(0, 0)]);
        e.ack(0, 0);
        assert!(e.is_acked());
    }
}
