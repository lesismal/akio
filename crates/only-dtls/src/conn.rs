//! The DTLS 1.2 connection state machine (client and server), sans-io: full ECDHE and PSK
//! handshakes, abbreviated handshakes (session IDs, RFC 5077 tickets) and RFC 9146 connection
//! IDs. [`Connection`](crate::Connection) wraps it (and the DTLS 1.3 machine).

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use only_crypto::pkey::PublicKey;
use only_x509::Certificate;

use crate::config::{Config, Fingerprint, FingerprintAlgorithm, SrtpKeys, SrtpProfile, Version};
use crate::cookie::{self, HelloVerifier};
use crate::crypto::{self, CipherSuite, KeyShare, NamedGroup, RecordProtection, SIGNATURE_SCHEMES};
use crate::handshake::{
    self as hs, ClientHello, Extensions, Partial, ServerHello, ServerKeyExchange,
};
use crate::record::{
    self, CT_ALERT, CT_APPLICATION_DATA, CT_CHANGE_CIPHER_SPEC, CT_HANDSHAKE, CT_TLS12_CID, DTLS12,
    Header, MAX_PLAINTEXT, ReplayWindow, Wire,
};
use crate::session::{Session, SessionState};
use crate::{AlertDescription, Error};

/// Which side of the handshake this endpoint plays (in WebRTC: `a=setup:active` is the
/// client, `passive` the server).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Sends the ClientHello.
    Client,
    /// Answers it.
    Server,
}

/// What the completed handshake established.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HandshakeInfo {
    /// The negotiated cipher suite.
    pub cipher_suite: CipherSuite,
    /// The peer's certificate chain (DER, leaf first); empty for a server whose client sent
    /// none (only with [`Config::with_require_client_certificate`] off).
    pub peer_certificates: Vec<Vec<u8>>,
    /// The SHA-256 fingerprint of the peer's leaf certificate, if it sent one.
    pub peer_fingerprint: Option<Fingerprint>,
    /// The SRTP profile negotiated with `use_srtp`, if any.
    pub srtp_profile: Option<SrtpProfile>,
    /// The SRTP master keys and salts for that profile (RFC 5764 §4.2).
    pub srtp_keys: Option<SrtpKeys>,
    /// The SRTP Master Key Identifier both sides agreed on (the client's
    /// [`Config::with_srtp_mki`], echoed by a server with [`Config::with_srtp_accept_mki`]):
    /// every SRTP and SRTCP packet protected with [`srtp_keys`](Self::srtp_keys), both
    /// directions, carries it (`only_srtp::Context::new_with_mki`). `None` without an MKI.
    pub srtp_mki: Option<Vec<u8>>,
    /// Whether the extended master secret (RFC 7627) is in use (always true in DTLS 1.3,
    /// whose key schedule binds the transcript).
    pub extended_master_secret: bool,
    /// The negotiated protocol version.
    pub version: Version,
    /// Whether this was an abbreviated handshake resuming an earlier session.
    pub resumed: bool,
    /// The identity of the external pre-shared key used, if any.
    pub psk_identity: Option<Vec<u8>>,
    /// The connection ID the peer puts in the records it sends us (RFC 9146), once
    /// negotiated.
    pub local_connection_id: Option<Vec<u8>>,
    /// The connection ID we put in the records we send.
    pub peer_connection_id: Option<Vec<u8>>,
}

/// What [`Connection::poll_event`](crate::Connection::poll_event) reports.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Event {
    /// The handshake completed; application data can flow.
    Connected(Box<HandshakeInfo>),
    /// A record of application data from the peer.
    ApplicationData(Vec<u8>),
    /// The peer closed the connection with close_notify (ours was sent in reply).
    Closed,
    /// Client with [`Config::with_session_resumption`]: a session that
    /// [`Connection::client_resume`](crate::Connection::client_resume) can resume later (a
    /// DTLS 1.2 session ID or ticket at connect, each DTLS 1.3 NewSessionTicket).
    NewSession(Box<Session>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Handshake,
    Connected,
    Closed,
    Failed,
}

/// The next handshake message expected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    // client
    ServerHello,
    ServerCertificate,
    ServerKeyExchange,
    CertificateRequestOrDone,
    ServerHelloDone,
    ServerFinished,
    /// Abbreviated handshake: the server's (NewSessionTicket,) ChangeCipherSpec and Finished.
    ServerFinishedResumed,
    // server
    ClientHello,
    ClientCertificate,
    ClientKeyExchange,
    CertificateVerify,
    ClientFinished,
    Done,
}

/// One message of an outgoing flight, kept for retransmission.
#[derive(Debug, Clone)]
struct FlightMsg {
    epoch: u16,
    /// `None`: ChangeCipherSpec.
    msg: Option<(u8, u16, Vec<u8>)>,
}

/// Records of epoch 1 that arrived before the keys, and early application data, are buffered
/// up to these counts.
const MAX_EARLY_RECORDS: usize = 32;
const MAX_EARLY_APP: usize = 16;
/// Handshake messages accepted ahead of the next expected one.
const REASSEMBLY_WINDOW: u16 = 16;
/// HelloVerifyRequests a client follows before giving up.
const MAX_HELLO_VERIFY: u32 = 3;

/// State a DTLS 1.3 connection hands over when the peer turns out to speak only DTLS 1.2
/// (`Conn13::into_handoff`): its first flight and what it received of the peer's.
#[derive(Debug)]
pub(crate) struct Handoff {
    pub(crate) config: Arc<Config>,
    pub(crate) role: Role,
    pub(crate) peer_addr: Vec<u8>,
    pub(crate) deadline: Instant,
    pub(crate) partials: BTreeMap<u16, (u16, Partial)>,
    pub(crate) recv_seq: u16,
    pub(crate) send_seq: u16,
    pub(crate) epoch0_seq: u64,
    pub(crate) last_record_seq: u64,
    /// Client: the ClientHello sent, with its message sequence number.
    pub(crate) client_hello: Option<(ClientHello, u16)>,
    pub(crate) retransmit_at: Option<Instant>,
    pub(crate) rto: Duration,
    pub(crate) local_cid: Option<Vec<u8>>,
}

/// A DTLS 1.2 connection: a sans-io state machine.
#[derive(Debug)]
pub(crate) struct Conn12 {
    config: Arc<Config>,
    role: Role,
    state: State,
    expect: Expect,
    // server cookies
    hello_verifier: Option<HelloVerifier>,
    peer_addr: Vec<u8>,
    // client hello (client: resent with the cookie)
    client_hello: Option<ClientHello>,
    hello_verify_count: u32,
    client_random: [u8; 32],
    server_random: [u8; 32],
    suite: Option<CipherSuite>,
    transcript: Vec<u8>,
    key_share: Option<KeyShare>,
    premaster: Option<Vec<u8>>,
    master_secret: Option<Vec<u8>>,
    ems: bool,
    srtp_profile: Option<SrtpProfile>,
    srtp_mki: Option<Vec<u8>>,
    peer_chain: Vec<Vec<u8>>,
    peer_key: Option<PublicKey>,
    /// Server: the client's signature_algorithms; client: the CertificateRequest's list.
    peer_schemes: Option<Vec<u16>>,
    cert_requested: bool,
    client_sent_cert: bool,
    // handshake message sequencing and reassembly
    send_seq: u16,
    recv_seq: u16,
    partials: BTreeMap<u16, (u16, Partial)>,
    flight: Vec<FlightMsg>,
    prev_peer_flight_start: Option<u16>,
    cur_peer_flight_start: u16,
    retransmit_at: Option<Instant>,
    rto: Duration,
    deadline: Instant,
    // record layer
    write_seq: [u64; 2],
    write_keys: Option<RecordProtection>,
    read_keys: Option<RecordProtection>,
    replay: ReplayWindow,
    early_records: Vec<(Header, Vec<u8>)>,
    early_app: Vec<Vec<u8>>,
    /// Record sequence number of the last epoch-0 record (mirrored by HelloVerifyRequest).
    last_record_seq: u64,
    transmits: VecDeque<Vec<u8>>,
    events: VecDeque<Event>,
    info: Option<HandshakeInfo>,
    sent_close: bool,
    // PSK, resumption, connection IDs
    /// The PSK in use (identity, key).
    psk: Option<(Vec<u8>, Vec<u8>)>,
    /// Client: the session offered.
    resume: Option<Session>,
    /// Abbreviated handshake.
    resumed: bool,
    /// Server: issue a ticket in the final flight; client: the server will send one.
    send_ticket: bool,
    /// Client: the ticket received.
    new_ticket: Option<(u32, Vec<u8>)>,
    /// Session ID of this session (server: assigned; client: echoed).
    session_id: Vec<u8>,
    /// The CID the peer puts in records to us; the CID we put in records to the peer.
    local_cid: Option<Vec<u8>>,
    peer_cid: Option<Vec<u8>>,
    /// Client: the ClientHello also offered DTLS 1.3 (check the downgrade sentinel).
    offered13: bool,
}

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

/// A fresh connection ID of `len` bytes, if CIDs are configured.
pub(crate) fn new_cid(config: &Config) -> Result<Option<Vec<u8>>, Error> {
    let Some(len) = config.connection_id else {
        return Ok(None);
    };
    let mut cid = vec![0u8; usize::from(len)];
    only_crypto::rand::fill_random(&mut cid)
        .map_err(|_| Error::Crypto(only_crypto::Error::Random))?;
    Ok(Some(cid))
}

/// Checks that `config` can run `role` with DTLS 1.2.
pub(crate) fn check_config12(config: &Config, role: Role) -> Result<(), Error> {
    let suites: Vec<CipherSuite> = config
        .cipher_suites
        .iter()
        .copied()
        .filter(|s| !s.is_tls13() && (!s.is_psk() || !config.psks.is_empty()))
        .collect();
    if suites.is_empty() {
        return Err(Error::Config("no DTLS 1.2 cipher suites"));
    }
    if role == Role::Server {
        let cert_ok = config
            .identity
            .as_ref()
            .is_some_and(|id| suites.iter().any(|s| s.fits_key(id.private_key())));
        let psk_ok = !config.psks.is_empty() && suites.iter().any(|s| s.is_psk());
        if !cert_ok && !psk_ok {
            return Err(if config.identity.is_none() {
                Error::Config("a server needs an identity")
            } else {
                Error::Config("no cipher suite fits the server key")
            });
        }
    }
    Ok(())
}

impl Conn12 {
    /// A client connection (resuming `resume` when given); its first flight (the ClientHello)
    /// is ready in `poll_transmit`.
    pub(crate) fn client(
        config: Arc<Config>,
        now: Instant,
        resume: Option<Session>,
    ) -> Result<Conn12, Error> {
        let mut c = Conn12::new(config, Role::Client, now, &[])?;
        c.resume = resume.filter(|s| s.state.version == Version::Dtls12);
        c.start_client(now)?;
        Ok(c)
    }

    /// A connection for `role`; a server waits for a ClientHello.
    pub(crate) fn new(
        config: Arc<Config>,
        role: Role,
        now: Instant,
        peer: &[u8],
    ) -> Result<Conn12, Error> {
        check_config12(&config, role)?;
        let hello_verifier = if role == Role::Server && config.hello_verify {
            Some(HelloVerifier::new(now)?)
        } else {
            None
        };
        let local_cid = new_cid(&config)?;
        let mut c = Conn12 {
            role,
            state: State::Handshake,
            expect: match role {
                Role::Client => Expect::ServerHello,
                Role::Server => Expect::ClientHello,
            },
            hello_verifier,
            peer_addr: peer.to_vec(),
            client_hello: None,
            hello_verify_count: 0,
            client_random: [0; 32],
            server_random: [0; 32],
            suite: None,
            transcript: Vec::new(),
            key_share: None,
            premaster: None,
            master_secret: None,
            ems: false,
            srtp_profile: None,
            srtp_mki: None,
            peer_chain: Vec::new(),
            peer_key: None,
            peer_schemes: None,
            cert_requested: false,
            client_sent_cert: false,
            send_seq: 0,
            recv_seq: 0,
            partials: BTreeMap::new(),
            flight: Vec::new(),
            prev_peer_flight_start: None,
            cur_peer_flight_start: 0,
            retransmit_at: None,
            rto: config.initial_retransmit,
            deadline: now + config.handshake_timeout,
            write_seq: [0; 2],
            write_keys: None,
            read_keys: None,
            replay: ReplayWindow::default(),
            early_records: Vec::new(),
            early_app: Vec::new(),
            last_record_seq: 0,
            transmits: VecDeque::new(),
            events: VecDeque::new(),
            info: None,
            sent_close: false,
            psk: None,
            resume: None,
            resumed: false,
            send_ticket: false,
            new_ticket: None,
            session_id: Vec::new(),
            local_cid,
            peer_cid: None,
            offered13: false,
            config,
        };
        c.client_random = random32()?;
        Ok(c)
    }

    /// Continues a handshake a DTLS 1.3 connection started with a peer that only speaks
    /// DTLS 1.2. The caller feeds the datagram that revealed it again.
    pub(crate) fn from_handoff(h: Handoff, now: Instant) -> Result<Conn12, Error> {
        let mut c = Conn12::new(h.config, h.role, now, &h.peer_addr)?;
        c.deadline = h.deadline;
        c.partials = h.partials;
        c.recv_seq = h.recv_seq;
        c.send_seq = h.send_seq;
        c.write_seq[0] = h.epoch0_seq;
        c.last_record_seq = h.last_record_seq;
        c.local_cid = h.local_cid;
        c.cur_peer_flight_start = h.recv_seq;
        if let Some((ch, seq)) = h.client_hello {
            c.offered13 = true;
            c.client_random = ch.random;
            let body = ch.encode();
            c.transcript = hs::encode_message(hs::CLIENT_HELLO, seq, &body);
            c.flight = vec![FlightMsg {
                epoch: 0,
                msg: Some((hs::CLIENT_HELLO, seq, body)),
            }];
            c.client_hello = Some(ch);
            c.retransmit_at = h.retransmit_at;
            c.rto = h.rto;
        }
        Ok(c)
    }

    /// This endpoint's role.
    #[must_use]
    pub(crate) fn role(&self) -> Role {
        self.role
    }

    /// Whether the handshake completed and the connection is open.
    #[must_use]
    pub(crate) fn is_connected(&self) -> bool {
        self.state == State::Connected
    }

    /// Whether the connection is closed or failed (nothing more will be sent or received).
    #[must_use]
    pub(crate) fn is_closed(&self) -> bool {
        matches!(self.state, State::Closed | State::Failed)
    }

    /// What the handshake established, once connected.
    #[must_use]
    pub(crate) fn handshake_info(&self) -> Option<&HandshakeInfo> {
        self.info.as_ref()
    }

    /// The CID the peer puts in records to us, once negotiated.
    pub(crate) fn local_cid(&self) -> Option<&[u8]> {
        self.peer_cid.as_ref().and(self.local_cid.as_deref())
    }

    /// The next datagram to send.
    pub(crate) fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        self.transmits.pop_front()
    }

    /// The next event.
    pub(crate) fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// When `handle_timeout` must be called next (retransmission
    /// or handshake deadline); `None` once connected or closed.
    #[must_use]
    pub(crate) fn poll_timeout(&self) -> Option<Instant> {
        if self.state != State::Handshake {
            return None;
        }
        Some(match self.retransmit_at {
            Some(t) => t.min(self.deadline),
            None => self.deadline,
        })
    }

    /// Advances the timers: retransmits the current flight with exponential backoff
    /// (RFC 6347 §4.2.4) and fails the handshake with [`Error::Timeout`] at its deadline.
    pub(crate) fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        if self.state != State::Handshake {
            return Ok(());
        }
        if now >= self.deadline {
            self.fail(&Error::Timeout);
            return Err(Error::Timeout);
        }
        if let Some(t) = self.retransmit_at {
            if now >= t {
                self.transmit_flight();
                self.rto = (self.rto * 2).min(self.config.max_retransmit);
                self.retransmit_at = Some(now + self.rto);
            }
        }
        Ok(())
    }

    /// Processes one received datagram. A fatal error sends the matching alert (in
    /// `poll_transmit`) and closes the connection. Records that do
    /// not authenticate, replays and stray retransmissions are dropped silently.
    pub(crate) fn handle_datagram(&mut self, now: Instant, datagram: &[u8]) -> Result<(), Error> {
        if self.is_closed() {
            return Err(Error::Closed);
        }
        let cid_len = self.local_cid.as_ref().map_or(0, Vec::len);
        for w in record::split_cid(datagram, cid_len) {
            let Wire::Plain { h, cid, fragment } = w else {
                // A DTLS 1.3 record: not ours.
                break;
            };
            if cid.is_some_and(|c| Some(c) != self.local_cid.as_deref()) {
                continue;
            }
            let had_keys = self.read_keys.is_some();
            if let Err(e) = self.handle_record(now, h, fragment) {
                self.fail(&e);
                return Err(e);
            }
            if !had_keys && self.read_keys.is_some() {
                for (h, f) in std::mem::take(&mut self.early_records) {
                    if let Err(e) = self.handle_record(now, h, &f) {
                        self.fail(&e);
                        return Err(e);
                    }
                }
            }
            if self.is_closed() {
                break;
            }
        }
        Ok(())
    }

    /// Sends one record of application data (at most 16384 bytes; it goes out as one
    /// datagram).
    pub(crate) fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        match self.state {
            State::Connected => {}
            State::Handshake => return Err(Error::NotConnected),
            _ => return Err(Error::Closed),
        }
        if data.len() > MAX_PLAINTEXT {
            return Err(Error::TooLarge);
        }
        let r = self.seal_record(1, CT_APPLICATION_DATA, data);
        self.transmits.push_back(r);
        Ok(())
    }

    /// Keying material from the RFC 5705 exporter (`label`, optional `context`), e.g.
    /// `EXTRACTOR-dtls_srtp` for DTLS-SRTP. Only after the handshake completed.
    pub(crate) fn export_keying_material(
        &self,
        label: &str,
        context: Option<&[u8]>,
        len: usize,
    ) -> Result<Vec<u8>, Error> {
        if self.state != State::Connected {
            return Err(Error::Exporter("handshake not complete"));
        }
        const RESERVED: [&str; 5] = [
            "client finished",
            "server finished",
            "master secret",
            "extended master secret",
            "key expansion",
        ];
        if RESERVED.contains(&label) {
            return Err(Error::Exporter("reserved label"));
        }
        self.export(label, context, len)
    }

    fn export(&self, label: &str, context: Option<&[u8]>, len: usize) -> Result<Vec<u8>, Error> {
        let (Some(ms), Some(suite)) = (&self.master_secret, self.suite) else {
            return Err(Error::Exporter("no master secret"));
        };
        let mut seed = Vec::with_capacity(64 + context.map_or(0, |c| c.len() + 2));
        seed.extend_from_slice(&self.client_random);
        seed.extend_from_slice(&self.server_random);
        if let Some(c) = context {
            let n = u16::try_from(c.len()).map_err(|_| Error::Exporter("context too long"))?;
            seed.extend_from_slice(&n.to_be_bytes());
            seed.extend_from_slice(c);
        }
        let mut out = vec![0; len];
        crypto::prf(suite.prf_hash(), ms, label.as_bytes(), &seed, &mut out);
        Ok(out)
    }

    /// Sends close_notify and closes the connection.
    pub(crate) fn close(&mut self) {
        if matches!(self.state, State::Handshake | State::Connected) {
            self.send_alert(1, AlertDescription::CloseNotify);
            self.sent_close = true;
            self.state = State::Closed;
            self.retransmit_at = None;
        }
    }

    // ---- record layer ----

    fn seal_record(&mut self, epoch: u16, content_type: u8, payload: &[u8]) -> Vec<u8> {
        let e = usize::from(epoch.min(1));
        let seq = self.write_seq[e];
        self.write_seq[e] = (seq + 1).min(record::MAX_SEQ);
        let h = Header {
            content_type,
            version: DTLS12,
            epoch,
            seq,
        };
        let mut out = Vec::with_capacity(record::HEADER_LEN + payload.len() + 24);
        if epoch == 0 {
            h.encode(payload.len(), &mut out);
            out.extend_from_slice(payload);
        } else if let Some(k) = &self.write_keys {
            match self.peer_cid.as_deref().filter(|c| !c.is_empty()) {
                Some(cid) => {
                    // RFC 9146: tls12_cid record, DTLSInnerPlaintext = content || real type.
                    let h = Header {
                        content_type: CT_TLS12_CID,
                        ..h
                    };
                    let mut inner = Vec::with_capacity(payload.len() + 1);
                    inner.extend_from_slice(payload);
                    inner.push(content_type);
                    let f =
                        k.seal_aad(&h, &RecordProtection::cid_aad(&h, cid, inner.len()), &inner);
                    out.push(CT_TLS12_CID);
                    out.extend_from_slice(&DTLS12.to_be_bytes());
                    out.extend_from_slice(&epoch.to_be_bytes());
                    out.extend_from_slice(&seq.to_be_bytes()[2..]);
                    out.extend_from_slice(cid);
                    out.extend_from_slice(&(f.len() as u16).to_be_bytes());
                    out.extend_from_slice(&f);
                }
                None => {
                    let f = k.seal(&h, payload);
                    h.encode(f.len(), &mut out);
                    out.extend_from_slice(&f);
                }
            }
        }
        out
    }

    fn send_alert(&mut self, level: u8, desc: AlertDescription) {
        let epoch = u16::from(self.write_keys.is_some());
        let r = self.seal_record(epoch, CT_ALERT, &[level, desc.to_u8()]);
        self.transmits.push_back(r);
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
    }

    fn handle_record(&mut self, now: Instant, h: Header, fragment: &[u8]) -> Result<(), Error> {
        let plaintext;
        let mut content_type = h.content_type;
        let payload: &[u8] = match h.epoch {
            0 => {
                // After the handshake only retransmitted handshake records are meaningful in
                // epoch 0; unauthenticated alerts are ignored.
                if self.state == State::Connected && h.content_type != CT_HANDSHAKE {
                    return Ok(());
                }
                if matches!(h.content_type, CT_APPLICATION_DATA | CT_TLS12_CID) {
                    return Ok(());
                }
                self.last_record_seq = h.seq;
                fragment
            }
            1 => {
                let Some(keys) = &self.read_keys else {
                    if self.state == State::Handshake
                        && self.early_records.len() < MAX_EARLY_RECORDS
                    {
                        self.early_records.push((h, fragment.to_vec()));
                    }
                    return Ok(());
                };
                if h.version != DTLS12 || !self.replay.check(h.seq) {
                    return Ok(());
                }
                let opened = if h.content_type == CT_TLS12_CID {
                    let cid = self.local_cid.clone().unwrap_or_default();
                    keys.open_aad(&h, fragment, |n| RecordProtection::cid_aad(&h, &cid, n))
                        .and_then(|mut inner| {
                            // Strip the zero padding, then the real content type.
                            while inner.last() == Some(&0) {
                                inner.pop();
                            }
                            let ct = inner.pop()?;
                            content_type = ct;
                            Some(inner)
                        })
                } else {
                    keys.open(&h, fragment)
                };
                let Some(p) = opened else {
                    return Ok(());
                };
                self.replay.accept(h.seq);
                plaintext = p;
                &plaintext
            }
            _ => return Ok(()),
        };
        if payload.len() > MAX_PLAINTEXT {
            return Err(Error::protocol(
                AlertDescription::RecordOverflow,
                "record too large",
            ));
        }
        match content_type {
            CT_HANDSHAKE => self.handle_handshake(now, h.epoch, payload),
            CT_CHANGE_CIPHER_SPEC => {
                if payload != [1] {
                    return Err(Error::decode("bad ChangeCipherSpec"));
                }
                Ok(())
            }
            CT_ALERT => self.handle_alert(payload),
            CT_APPLICATION_DATA => {
                match self.state {
                    State::Connected => {
                        self.events
                            .push_back(Event::ApplicationData(payload.to_vec()));
                    }
                    State::Handshake if self.early_app.len() < MAX_EARLY_APP => {
                        self.early_app.push(payload.to_vec());
                    }
                    _ => {}
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn handle_alert(&mut self, p: &[u8]) -> Result<(), Error> {
        let [level, desc] = p else {
            return Err(Error::decode("bad alert"));
        };
        let desc = AlertDescription::from_u8(*desc);
        if desc == AlertDescription::CloseNotify {
            if !self.sent_close {
                self.send_alert(1, AlertDescription::CloseNotify);
                self.sent_close = true;
            }
            self.state = State::Closed;
            self.retransmit_at = None;
            self.events.push_back(Event::Closed);
            return Ok(());
        }
        if *level == 2 {
            return Err(Error::PeerAlert(desc));
        }
        Ok(())
    }

    // ---- handshake messaging ----

    fn handle_handshake(&mut self, now: Instant, epoch: u16, payload: &[u8]) -> Result<(), Error> {
        // Unparsable fragments are dropped like unauthenticated records.
        let Ok(frags) = hs::parse_fragments(payload) else {
            return Ok(());
        };
        let mut retransmit = false;
        for f in frags {
            if self.expect == Expect::ClientHello
                && (f.msg_type != hs::CLIENT_HELLO || f.length > hs::MAX_CLIENT_HELLO)
            {
                // Before the cookie exchange the peer's address is unproven: only a ClientHello
                // of plausible size is reassembled (and only it may restart reassembly).
                continue;
            }
            if self.state == State::Handshake
                && self.expect == Expect::ClientHello
                && f.msg_type == hs::CLIENT_HELLO
                && epoch == 0
            {
                // A (possibly repeated) ClientHello: restart reassembly at its sequence number
                // (stateless cookie exchange).
                if f.seq != self.recv_seq || !self.partials.contains_key(&f.seq) {
                    self.partials.clear();
                    self.recv_seq = f.seq;
                    self.cur_peer_flight_start = f.seq;
                }
            }
            if f.seq < self.recv_seq {
                if Some(f.seq) == self.prev_peer_flight_start && f.offset == 0 {
                    retransmit = true;
                }
                continue;
            }
            if self.state != State::Handshake {
                if self.state == State::Connected && epoch == 1 {
                    let reneg = match self.role {
                        Role::Server => f.msg_type == hs::CLIENT_HELLO,
                        Role::Client => f.msg_type == hs::HELLO_REQUEST,
                    };
                    if reneg && f.offset == 0 {
                        self.send_alert(1, AlertDescription::NoRenegotiation);
                    }
                }
                continue;
            }
            if f.seq >= self.recv_seq.saturating_add(REASSEMBLY_WINDOW) {
                continue;
            }
            let entry = self
                .partials
                .entry(f.seq)
                .or_insert_with(|| (epoch, Partial::new(&f)));
            if entry.0 == epoch {
                entry.1.add(&f);
            }
        }
        if retransmit && !self.flight.is_empty() {
            self.transmit_flight();
        }
        while self.state == State::Handshake {
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
            let (msg_type, body) = p.into_message();
            let seq = self.recv_seq;
            self.process_message(now, epoch, msg_type, seq, &body)?;
            if self.recv_seq == seq {
                self.recv_seq = seq.wrapping_add(1);
            }
        }
        Ok(())
    }

    /// Queues the current flight: fragments its messages to the MTU and packs the records
    /// into datagrams.
    fn transmit_flight(&mut self) {
        let mtu = self.config.mtu;
        let overhead = self.suite.map_or(0, CipherSuite::overhead);
        let flight = self.flight.clone();
        let mut datagram = Vec::new();
        for m in &flight {
            let mut records = Vec::new();
            match &m.msg {
                None => records.push(self.seal_record(m.epoch, CT_CHANGE_CIPHER_SPEC, &[1])),
                Some((ty, seq, body)) => {
                    let cid = self
                        .peer_cid
                        .as_ref()
                        .map_or(0, |c| if c.is_empty() { 0 } else { c.len() + 1 });
                    let room = mtu
                        - record::HEADER_LEN
                        - hs::HEADER_LEN
                        - if m.epoch == 1 { overhead + cid } else { 0 };
                    let mut off = 0;
                    loop {
                        let n = (body.len() - off).min(room);
                        let frag =
                            hs::encode_fragment(*ty, *seq, body.len(), off, &body[off..off + n]);
                        records.push(self.seal_record(m.epoch, CT_HANDSHAKE, &frag));
                        off += n;
                        if off >= body.len() {
                            break;
                        }
                    }
                }
            }
            for r in records {
                if !datagram.is_empty() && datagram.len() + r.len() > mtu {
                    self.transmits.push_back(std::mem::take(&mut datagram));
                }
                datagram.extend_from_slice(&r);
            }
        }
        if !datagram.is_empty() {
            self.transmits.push_back(datagram);
        }
    }

    /// Makes `msgs` the current flight, sends it and arms the retransmission timer (`arm`:
    /// false for the server's last flight, which is only resent when the client repeats its
    /// own).
    fn send_flight(&mut self, now: Instant, msgs: Vec<FlightMsg>, arm: bool) {
        self.prev_peer_flight_start = Some(self.cur_peer_flight_start);
        self.cur_peer_flight_start = self.recv_seq.wrapping_add(1);
        self.flight = msgs;
        self.transmit_flight();
        self.rto = self.config.initial_retransmit;
        self.retransmit_at = arm.then(|| now + self.rto);
    }

    /// A handshake message of ours: numbered, added to the transcript, kept for the flight.
    fn message(&mut self, epoch: u16, msg_type: u8, body: Vec<u8>) -> FlightMsg {
        let seq = self.send_seq;
        self.send_seq = self.send_seq.wrapping_add(1);
        self.transcript
            .extend_from_slice(&hs::encode_message(msg_type, seq, &body));
        FlightMsg {
            epoch,
            msg: Some((msg_type, seq, body)),
        }
    }

    fn hash(&self, data: &[u8]) -> Vec<u8> {
        self.suite
            .map_or_else(Vec::new, |s| s.prf_hash().digest(data))
    }

    fn verify_data(&self, label: &[u8], transcript: &[u8]) -> Vec<u8> {
        let mut out = vec![0; 12];
        if let (Some(ms), Some(s)) = (&self.master_secret, self.suite) {
            crypto::prf(s.prf_hash(), ms, label, &self.hash(transcript), &mut out);
        }
        out
    }

    /// Master secret (RFC 7627 when negotiated) and the epoch-1 keys, from the premaster
    /// secret and the transcript so far (which ends with the ClientKeyExchange).
    fn derive_keys(&mut self) -> Result<(), Error> {
        let suite = self
            .suite
            .ok_or_else(|| handshake_failure("no cipher suite"))?;
        let h = suite.prf_hash();
        let ms = match self.master_secret.take() {
            // Abbreviated handshake: the session's master secret.
            Some(ms) => ms,
            None => {
                let pms = self
                    .premaster
                    .take()
                    .ok_or_else(|| handshake_failure("no premaster secret"))?;
                let mut ms = vec![0u8; 48];
                if self.ems {
                    let session_hash = h.digest(&self.transcript);
                    crypto::prf(h, &pms, b"extended master secret", &session_hash, &mut ms);
                } else {
                    let mut seed = self.client_random.to_vec();
                    seed.extend_from_slice(&self.server_random);
                    crypto::prf(h, &pms, b"master secret", &seed, &mut ms);
                }
                ms
            }
        };
        let (k, iv) = (suite.key_len(), suite.fixed_iv_len());
        let mut block = vec![0u8; 2 * (k + iv)];
        let mut seed = self.server_random.to_vec();
        seed.extend_from_slice(&self.client_random);
        crypto::prf(h, &ms, b"key expansion", &seed, &mut block);
        let client = RecordProtection::new(suite, &block[..k], &block[2 * k..2 * k + iv])?;
        let server = RecordProtection::new(suite, &block[k..2 * k], &block[2 * k + iv..])?;
        let (w, r) = match self.role {
            Role::Client => (client, server),
            Role::Server => (server, client),
        };
        self.write_keys = Some(w);
        self.read_keys = Some(r);
        self.master_secret = Some(ms);
        Ok(())
    }

    fn connected(&mut self, now: Instant) -> Result<(), Error> {
        self.state = State::Connected;
        self.expect = Expect::Done;
        self.retransmit_at = None;
        self.partials.clear();
        self.early_records.clear();
        let suite = self
            .suite
            .ok_or_else(|| handshake_failure("no cipher suite"))?;
        let srtp_keys = match self.srtp_profile {
            Some(p) => {
                let n = 2 * (p.master_key_len() + p.master_salt_len());
                Some(SrtpKeys::from_material(
                    p,
                    &self.export("EXTRACTOR-dtls_srtp", None, n)?,
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
            extended_master_secret: self.ems,
            version: Version::Dtls12,
            resumed: self.resumed,
            psk_identity: self.psk.as_ref().map(|(id, _)| id.clone()),
            local_connection_id: self.peer_cid.as_ref().and_then(|_| self.local_cid.clone()),
            peer_connection_id: self.peer_cid.clone(),
        };
        self.info = Some(info.clone());
        self.events.push_back(Event::Connected(Box::new(info)));
        self.remember_session(now);
        for d in std::mem::take(&mut self.early_app) {
            self.events.push_back(Event::ApplicationData(d));
        }
        Ok(())
    }

    /// The resumable state of this session (DTLS 1.2: the master secret).
    fn session_state(&self) -> Option<SessionState> {
        Some(SessionState {
            version: Version::Dtls12,
            suite: self.suite?,
            secret: self.master_secret.clone()?,
            ems: self.ems,
            issued: crate::session::unix_now(),
            lifetime: u32::try_from(self.config.ticket_lifetime.as_secs()).unwrap_or(u32::MAX),
            age_add: 0,
            peer_chain: self.peer_chain.clone(),
        })
    }

    /// After a handshake with resumption on: the server caches a session ID; the client
    /// reports the session it can resume.
    fn remember_session(&mut self, now: Instant) {
        if !self.config.resumption || self.psk.is_some() {
            return;
        }
        let Some(mut state) = self.session_state() else {
            return;
        };
        match self.role {
            Role::Server => {
                if !self.resumed && !self.send_ticket && !self.session_id.is_empty() {
                    if let Some(c) = &self.config.session_cache {
                        let expires = now + self.config.ticket_lifetime;
                        c.insert(self.session_id.clone(), state, expires);
                    }
                }
            }
            Role::Client => {
                let (ticket, session_id) = match self.new_ticket.take() {
                    Some((lifetime, t)) => {
                        if lifetime != 0 {
                            state.lifetime = state.lifetime.min(lifetime);
                        }
                        let mut id = vec![0u8; 32];
                        if only_crypto::rand::fill_random(&mut id).is_err() {
                            return;
                        }
                        (t, id)
                    }
                    None if self.resumed => return,
                    None if !self.session_id.is_empty() => (Vec::new(), self.session_id.clone()),
                    None => return,
                };
                self.events.push_back(Event::NewSession(Box::new(Session {
                    state,
                    session_id,
                    ticket,
                    received: now,
                })));
            }
        }
    }

    /// Checks and stores the peer's certificate chain.
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

    fn process_message(
        &mut self,
        now: Instant,
        epoch: u16,
        msg_type: u8,
        seq: u16,
        body: &[u8],
    ) -> Result<(), Error> {
        let raw = hs::encode_message(msg_type, seq, body);
        // Finished is the only handshake message protected by the new epoch.
        if (msg_type == hs::FINISHED) != (epoch == 1) {
            return Err(unexpected("handshake message in the wrong epoch"));
        }
        match (self.expect, msg_type) {
            // ---- client ----
            (Expect::ServerHello, hs::HELLO_VERIFY_REQUEST) => {
                self.hello_verify_count += 1;
                if self.hello_verify_count > MAX_HELLO_VERIFY {
                    return Err(unexpected("too many HelloVerifyRequests"));
                }
                let cookie = hs::parse_hello_verify(body)?;
                let mut ch = self
                    .client_hello
                    .take()
                    .ok_or_else(|| unexpected("no ClientHello"))?;
                ch.cookie = cookie;
                // The first ClientHello and the HelloVerifyRequest are not in the transcript.
                self.transcript.clear();
                let m = self.message(0, hs::CLIENT_HELLO, ch.encode());
                self.client_hello = Some(ch);
                self.send_flight(now, vec![m], true);
            }
            (Expect::ServerHello, hs::SERVER_HELLO) => {
                self.client_server_hello(body)?;
                self.transcript.extend_from_slice(&raw);
                self.expect = if self.resumed {
                    self.derive_keys()?;
                    Expect::ServerFinishedResumed
                } else if self.suite.is_some_and(CipherSuite::is_ecdhe_psk) {
                    Expect::ServerKeyExchange
                } else if self.suite.is_some_and(CipherSuite::is_psk) {
                    Expect::CertificateRequestOrDone
                } else {
                    Expect::ServerCertificate
                };
            }
            (Expect::ServerCertificate, hs::CERTIFICATE) => {
                self.accept_certificate(hs::parse_certificate(body)?)?;
                let suite = self.suite.ok_or_else(|| unexpected("no suite"))?;
                if !self
                    .peer_key
                    .as_ref()
                    .is_some_and(|k| crypto::public_key_fits(suite, k))
                {
                    return Err(Error::protocol(
                        AlertDescription::UnsupportedCertificate,
                        "certificate key does not fit the cipher suite",
                    ));
                }
                self.transcript.extend_from_slice(&raw);
                self.expect = Expect::ServerKeyExchange;
            }
            (Expect::ServerKeyExchange, hs::SERVER_KEY_EXCHANGE) => {
                if self.suite.is_some_and(CipherSuite::is_psk) {
                    self.client_psk_key_exchange(body)?;
                } else {
                    self.client_server_key_exchange(body)?;
                }
                self.transcript.extend_from_slice(&raw);
                self.expect = Expect::CertificateRequestOrDone;
            }
            // Plain PSK: a ServerKeyExchange only carries an identity hint.
            (Expect::CertificateRequestOrDone, hs::SERVER_KEY_EXCHANGE)
                if self.suite.is_some_and(CipherSuite::is_psk) && self.key_share.is_none() =>
            {
                self.client_psk_key_exchange(body)?;
                self.transcript.extend_from_slice(&raw);
            }
            (Expect::CertificateRequestOrDone, hs::CERTIFICATE_REQUEST)
                if !self.suite.is_some_and(CipherSuite::is_psk) =>
            {
                self.peer_schemes = Some(hs::parse_certificate_request(body)?);
                self.cert_requested = true;
                self.transcript.extend_from_slice(&raw);
                self.expect = Expect::ServerHelloDone;
            }
            (Expect::CertificateRequestOrDone | Expect::ServerHelloDone, hs::SERVER_HELLO_DONE) => {
                if !body.is_empty() {
                    return Err(Error::decode("bad ServerHelloDone"));
                }
                self.transcript.extend_from_slice(&raw);
                self.client_flight5(now)?;
                self.expect = Expect::ServerFinished;
            }
            (Expect::ServerFinished | Expect::ServerFinishedResumed, hs::NEW_SESSION_TICKET)
                if self.send_ticket && self.new_ticket.is_none() =>
            {
                self.new_ticket = Some(hs::parse_ticket12(body)?);
                self.transcript.extend_from_slice(&raw);
            }
            (Expect::ServerFinished, hs::FINISHED) => {
                self.check_finished(b"server finished", body)?;
                self.transcript.extend_from_slice(&raw);
                self.connected(now)?;
            }
            (Expect::ServerFinishedResumed, hs::FINISHED) => {
                self.check_finished(b"server finished", body)?;
                self.transcript.extend_from_slice(&raw);
                let ccs = FlightMsg {
                    epoch: 0,
                    msg: None,
                };
                let vd = self.verify_data(b"client finished", &self.transcript);
                let fin = self.message(1, hs::FINISHED, vd);
                // The last flight: resent only when the server repeats its own.
                self.send_flight(now, vec![ccs, fin], false);
                self.connected(now)?;
            }
            // ---- server ----
            (Expect::ClientHello, hs::CLIENT_HELLO) => {
                self.server_client_hello(now, seq, body, &raw)?;
            }
            (Expect::ClientCertificate, hs::CERTIFICATE) => {
                let chain = hs::parse_certificate(body)?;
                if chain.is_empty() {
                    if self.config.require_client_certificate {
                        return Err(Error::Certificate("client sent no certificate".into()));
                    }
                } else {
                    self.accept_certificate(chain)?;
                    self.client_sent_cert = true;
                }
                self.transcript.extend_from_slice(&raw);
                self.expect = Expect::ClientKeyExchange;
            }
            (Expect::ClientKeyExchange, hs::CLIENT_KEY_EXCHANGE) => {
                if self.suite.is_some_and(CipherSuite::is_psk) {
                    self.server_psk_client_key_exchange(body)?;
                } else {
                    let public = hs::parse_client_key_exchange(body)?;
                    let share = self
                        .key_share
                        .take()
                        .ok_or_else(|| unexpected("no key share"))?;
                    self.premaster = Some(share.agree(&public)?);
                }
                self.transcript.extend_from_slice(&raw);
                self.derive_keys()?;
                self.expect = if self.client_sent_cert {
                    Expect::CertificateVerify
                } else {
                    Expect::ClientFinished
                };
            }
            (Expect::CertificateVerify, hs::CERTIFICATE_VERIFY) => {
                let (scheme, sig) = hs::parse_signed(body)?;
                if !self.server_cert_request_schemes().contains(&scheme) {
                    return Err(illegal("CertificateVerify scheme not requested"));
                }
                let key = self
                    .peer_key
                    .as_ref()
                    .ok_or_else(|| unexpected("no client key"))?;
                crypto::verify_signature(key, scheme, &self.transcript, &sig)?;
                self.transcript.extend_from_slice(&raw);
                self.expect = Expect::ClientFinished;
            }
            (Expect::ClientFinished, hs::FINISHED) => {
                self.check_finished(b"client finished", body)?;
                self.transcript.extend_from_slice(&raw);
                if !self.resumed {
                    let mut msgs = Vec::new();
                    if self.send_ticket {
                        let ticket = self
                            .session_state()
                            .and_then(|st| self.config.ticket_key.as_ref()?.seal(&st))
                            .unwrap_or_default();
                        let lifetime = u32::try_from(self.config.ticket_lifetime.as_secs())
                            .unwrap_or(u32::MAX);
                        msgs.push(self.message(
                            0,
                            hs::NEW_SESSION_TICKET,
                            hs::encode_ticket12(lifetime, &ticket),
                        ));
                    }
                    msgs.push(FlightMsg {
                        epoch: 0,
                        msg: None,
                    });
                    let vd = self.verify_data(b"server finished", &self.transcript);
                    msgs.push(self.message(1, hs::FINISHED, vd));
                    self.send_flight(now, msgs, false);
                }
                self.connected(now)?;
            }
            _ => return Err(unexpected("unexpected handshake message")),
        }
        Ok(())
    }

    fn check_finished(&self, label: &[u8], body: &[u8]) -> Result<(), Error> {
        let expected = self.verify_data(label, &self.transcript);
        if only_crypto::ct_eq(&expected, body) {
            Ok(())
        } else {
            Err(Error::protocol(
                AlertDescription::DecryptError,
                "bad Finished",
            ))
        }
    }

    /// The external PSK for `identity` (server), or ours (client).
    fn find_psk(&self, identity: Option<&[u8]>) -> Option<(Vec<u8>, Vec<u8>)> {
        let p = match identity {
            Some(id) => self.config.psks.iter().find(|p| p.identity == id)?,
            None => self.config.psks.first()?,
        };
        Some((p.identity.clone(), p.key.clone()))
    }

    /// The RFC 4279 / RFC 5489 premaster secret: `other_secret` (zeros for plain PSK, the
    /// ECDHE secret for ECDHE-PSK) and the PSK, each with a 2-byte length.
    fn psk_premaster(other: Option<Vec<u8>>, psk: &[u8]) -> Vec<u8> {
        let other = other.unwrap_or_else(|| vec![0; psk.len()]);
        let mut pms = Vec::with_capacity(4 + other.len() + psk.len());
        pms.extend_from_slice(&(other.len() as u16).to_be_bytes());
        pms.extend_from_slice(&other);
        pms.extend_from_slice(&(psk.len() as u16).to_be_bytes());
        pms.extend_from_slice(psk);
        pms
    }

    // ---- client ----

    /// The DTLS 1.2 cipher suites a client offers: PSK suites first when it has a PSK.
    fn client_suites(cfg: &Config) -> Vec<u16> {
        let psk = cfg
            .cipher_suites
            .iter()
            .filter(|s| s.is_psk() && !cfg.psks.is_empty());
        let cert = cfg
            .cipher_suites
            .iter()
            .filter(|s| !s.is_psk() && !s.is_tls13());
        psk.chain(cert).map(|s| s.id()).collect()
    }

    /// The DTLS 1.2 part of a client's hello extensions (DTLS 1.3 clients include it too).
    pub(crate) fn client_extensions(
        cfg: &Config,
        local_cid: Option<&[u8]>,
        ticket: Option<&[u8]>,
    ) -> Extensions {
        Extensions {
            groups: Some(NamedGroup::ALL.iter().map(|g| g.id()).collect()),
            point_formats: Some(vec![0]),
            signature_algorithms: Some(SIGNATURE_SCHEMES.to_vec()),
            srtp: (!cfg.srtp_profiles.is_empty()).then(|| {
                (
                    cfg.srtp_profiles.iter().map(|p| p.id()).collect(),
                    cfg.srtp_mki.clone(),
                )
            }),
            extended_master_secret: true,
            session_ticket: if cfg.resumption {
                Some(ticket.unwrap_or_default().to_vec())
            } else {
                None
            },
            connection_id: local_cid.map(<[u8]>::to_vec),
            ..Extensions::default()
        }
    }

    /// A DTLS 1.2 ClientHello for `cfg` (DTLS 1.3 clients extend it).
    pub(crate) fn client_hello12(
        cfg: &Config,
        random: [u8; 32],
        local_cid: Option<&[u8]>,
        resume: Option<&Session>,
    ) -> ClientHello {
        let mut suites = Conn12::client_suites(cfg);
        suites.push(hs::SCSV_RENEGOTIATION);
        let ticket = resume
            .map(|s| s.ticket.as_slice())
            .filter(|t| !t.is_empty());
        ClientHello {
            version: DTLS12,
            random,
            session_id: resume.map(|s| s.session_id.clone()).unwrap_or_default(),
            cookie: Vec::new(),
            cipher_suites: suites,
            compression: vec![0],
            extensions: Conn12::client_extensions(cfg, local_cid, ticket),
        }
    }

    fn start_client(&mut self, now: Instant) -> Result<(), Error> {
        let ch = Conn12::client_hello12(
            &self.config,
            self.client_random,
            self.local_cid.as_deref(),
            self.resume.as_ref(),
        );
        let m = self.message(0, hs::CLIENT_HELLO, ch.encode());
        self.client_hello = Some(ch);
        self.flight = vec![m];
        self.transmit_flight();
        self.cur_peer_flight_start = 0;
        self.retransmit_at = Some(now + self.rto);
        Ok(())
    }

    fn client_server_hello(&mut self, body: &[u8]) -> Result<(), Error> {
        let sh = ServerHello::parse(body)?;
        if sh.version != DTLS12 || sh.extensions.supported_versions.is_some() || sh.is_hrr() {
            return Err(Error::protocol(
                AlertDescription::ProtocolVersion,
                "not DTLS 1.2",
            ));
        }
        if self.offered13 && sh.random[24..] == hs::DOWNGRADE_12 {
            // RFC 8446 §4.1.3: a DTLS 1.3 server negotiated DTLS 1.2 with a client that
            // offered 1.3: an attacker stripped it.
            return Err(illegal("downgrade to DTLS 1.2 detected"));
        }
        let suite = CipherSuite::from_id(sh.cipher_suite)
            .filter(|s| Conn12::client_suites(&self.config).contains(&s.id()))
            .ok_or_else(|| illegal("cipher suite not offered"))?;
        if sh.compression != 0 {
            return Err(illegal("compression not offered"));
        }
        let e = &sh.extensions;
        let offered = self
            .client_hello
            .as_ref()
            .map(|c| c.extensions.clone())
            .unwrap_or_default();
        if !e.unknown.is_empty()
            || e.groups.is_some()
            || e.signature_algorithms.is_some()
            || e.key_shares.is_some()
            || e.cookie.is_some()
            || e.psk_selected.is_some()
            || (e.session_ticket.is_some() && offered.session_ticket.is_none())
            || (e.connection_id.is_some() && offered.connection_id.is_none())
        {
            return Err(Error::protocol(
                AlertDescription::UnsupportedExtension,
                "extension not offered",
            ));
        }
        if e.session_ticket.as_ref().is_some_and(|t| !t.is_empty()) {
            return Err(illegal("non-empty session_ticket in ServerHello"));
        }
        if e.renegotiation_info.as_ref().is_some_and(|r| !r.is_empty()) {
            return Err(handshake_failure("bad renegotiation_info"));
        }
        if e.point_formats.as_ref().is_some_and(|f| !f.contains(&0)) {
            return Err(illegal("uncompressed points not supported by the server"));
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
        if !e.extended_master_secret && self.config.require_extended_master_secret {
            return Err(handshake_failure("extended master secret required"));
        }
        self.peer_cid = e.connection_id.clone();
        if self.peer_cid.is_none() {
            // Not negotiated: our CID is not used either.
            self.local_cid = None;
        }
        self.ems = e.extended_master_secret;
        self.send_ticket = e.session_ticket.is_some();
        self.session_id.clone_from(&sh.session_id);
        // Resumption: the server echoed the session ID we offered.
        if let Some(sess) = self.resume.take() {
            if !sh.session_id.is_empty() && sh.session_id == sess.session_id {
                if sess.state.suite != suite {
                    return Err(illegal("resumed session with another cipher suite"));
                }
                if sess.state.ems != self.ems {
                    return Err(handshake_failure(
                        "extended master secret changed on resumption",
                    ));
                }
                if !sess.state.peer_chain.is_empty() {
                    self.config.verifier.verify(&sess.state.peer_chain)?;
                    self.peer_chain = sess.state.peer_chain.clone();
                }
                self.master_secret = Some(sess.state.secret);
                self.resumed = true;
            }
        }
        if suite.is_psk() {
            self.psk = Some(
                self.find_psk(None)
                    .ok_or_else(|| illegal("PSK suite without a PSK"))?,
            );
        }
        self.suite = Some(suite);
        self.server_random = sh.random;
        Ok(())
    }

    fn client_server_key_exchange(&mut self, body: &[u8]) -> Result<(), Error> {
        let ske = ServerKeyExchange::parse(body)?;
        let group = NamedGroup::from_id(ske.group).ok_or_else(|| illegal("group not offered"))?;
        let mut signed = self.client_random.to_vec();
        signed.extend_from_slice(&self.server_random);
        signed.extend_from_slice(&ServerKeyExchange::params(ske.group, &ske.public));
        let key = self
            .peer_key
            .as_ref()
            .ok_or_else(|| unexpected("no server key"))?;
        crypto::verify_signature(key, ske.scheme, &signed, &ske.signature)?;
        let share = KeyShare::generate(group)?;
        self.premaster = Some(share.agree(&ske.public)?);
        self.key_share = Some(share);
        Ok(())
    }

    /// A PSK ServerKeyExchange: the identity hint (ignored), and for ECDHE-PSK the unsigned
    /// ECDHE parameters.
    fn client_psk_key_exchange(&mut self, body: &[u8]) -> Result<(), Error> {
        let mut r = crate::codec::Reader::new(body);
        let _hint = r.vec16()?;
        let psk = self
            .psk
            .as_ref()
            .map(|(_, k)| k.clone())
            .ok_or_else(|| unexpected("no PSK"))?;
        if self.suite.is_some_and(CipherSuite::is_ecdhe_psk) {
            if r.u8()? != 3 {
                return Err(handshake_failure("not a named curve"));
            }
            let group =
                NamedGroup::from_id(r.u16()?).ok_or_else(|| illegal("group not offered"))?;
            let public = r.vec8()?.to_vec();
            let share = KeyShare::generate(group)?;
            let other = share.agree(&public)?;
            self.premaster = Some(Conn12::psk_premaster(Some(other), &psk));
            self.key_share = Some(share);
        }
        r.finish()?;
        Ok(())
    }

    fn client_flight5(&mut self, now: Instant) -> Result<(), Error> {
        let mut msgs = Vec::new();
        let identity = self.config.identity.clone();
        let mut sign_with = None;
        if self.cert_requested {
            let chain = identity
                .as_ref()
                .map(|i| i.chain().to_vec())
                .unwrap_or_default();
            if let Some(id) = &identity {
                let scheme = crypto::choose_scheme(id.private_key(), self.peer_schemes.as_deref())
                    .ok_or_else(|| {
                        handshake_failure("no signature scheme for the client certificate")
                    })?;
                sign_with = Some((id.private_key().clone(), scheme));
            }
            msgs.push(self.message(0, hs::CERTIFICATE, hs::encode_certificate(&chain)));
        }
        let cke = if let Some((id, psk)) = self.psk.clone() {
            let mut b = Vec::new();
            crate::codec::put_vec16(&mut b, &id);
            match self.key_share.take() {
                Some(share) => crate::codec::put_vec8(&mut b, &share.public()),
                None => self.premaster = Some(Conn12::psk_premaster(None, &psk)),
            }
            b
        } else {
            let public = self
                .key_share
                .take()
                .ok_or_else(|| unexpected("no key share"))?
                .public();
            hs::encode_client_key_exchange(&public)
        };
        msgs.push(self.message(0, hs::CLIENT_KEY_EXCHANGE, cke));
        self.derive_keys()?;
        if let Some((key, scheme)) = sign_with {
            let sig = crypto::sign(&key, scheme, &self.transcript)?;
            msgs.push(self.message(0, hs::CERTIFICATE_VERIFY, hs::encode_signed(scheme, &sig)));
        }
        msgs.push(FlightMsg {
            epoch: 0,
            msg: None,
        });
        let vd = self.verify_data(b"client finished", &self.transcript);
        msgs.push(self.message(1, hs::FINISHED, vd));
        self.send_flight(now, msgs, true);
        Ok(())
    }

    // ---- server ----

    fn server_cert_request_schemes(&self) -> Vec<u16> {
        SIGNATURE_SCHEMES.to_vec()
    }

    /// The session a ClientHello asks to resume, if we have it and it still fits.
    fn server_find_session(&self, ch: &ClientHello, now: Instant) -> Option<SessionState> {
        if !self.config.resumption {
            return None;
        }
        let state = match ch.extensions.session_ticket.as_deref() {
            Some(t) if !t.is_empty() => self.config.ticket_key.as_ref()?.open(t)?,
            _ if !ch.session_id.is_empty() => self
                .config
                .session_cache
                .as_ref()?
                .get(&ch.session_id, now)?,
            _ => return None,
        };
        let usable = state.version == Version::Dtls12
            && ch.cipher_suites.contains(&state.suite.id())
            && self.config.cipher_suites.contains(&state.suite)
            && state.ems == ch.extensions.extended_master_secret
            && (state.peer_chain.is_empty()
                || self.config.verifier.verify(&state.peer_chain).is_ok());
        usable.then_some(state)
    }

    fn server_client_hello(
        &mut self,
        now: Instant,
        seq: u16,
        body: &[u8],
        raw: &[u8],
    ) -> Result<(), Error> {
        let ch = ClientHello::parse(body)?;
        if ch.version > DTLS12 {
            // Numerically larger is older: the client does not support DTLS 1.2.
            return Err(Error::protocol(
                AlertDescription::ProtocolVersion,
                "DTLS 1.2 required",
            ));
        }
        if let Some(v) = &self.hello_verifier {
            if !v.valid(now, &self.peer_addr, &ch) {
                let cookie = v.make(now, &self.peer_addr, &ch);
                // Stateless: the HelloVerifyRequest mirrors the ClientHello's numbers and the
                // next ClientHello starts the handshake afresh.
                let d = cookie::hello_verify_datagram(seq, self.last_record_seq, &cookie);
                self.transmits.push_back(d);
                self.transcript.clear();
                self.recv_seq = seq.wrapping_add(1);
                self.cur_peer_flight_start = self.recv_seq;
                return Ok(());
            }
        }
        if !ch.compression.contains(&0) {
            return Err(illegal("null compression not offered"));
        }
        let e = &ch.extensions;
        if e.renegotiation_info.as_ref().is_some_and(|r| !r.is_empty()) {
            return Err(handshake_failure("bad renegotiation_info"));
        }
        let secure_renegotiation =
            e.renegotiation_info.is_some() || ch.cipher_suites.contains(&hs::SCSV_RENEGOTIATION);
        if e.point_formats.as_ref().is_some_and(|f| !f.contains(&0)) {
            return Err(illegal("uncompressed points not offered"));
        }
        let resumed = self.server_find_session(&ch, now);
        let key = self
            .config
            .identity
            .as_ref()
            .map(|i| i.private_key().clone());
        let has_psk = !self.config.psks.is_empty();
        let suite = match &resumed {
            Some(st) => st.suite,
            None => self
                .config
                .cipher_suites
                .iter()
                .copied()
                .filter(|s| !s.is_tls13() && ch.cipher_suites.contains(&s.id()))
                .find(|s| {
                    if s.is_psk() {
                        has_psk
                    } else {
                        key.as_ref().is_some_and(|k| s.fits_key(k))
                    }
                })
                .ok_or_else(|| handshake_failure("no shared cipher suite"))?,
        };
        let client_groups = e
            .groups
            .clone()
            .unwrap_or_else(|| vec![NamedGroup::Secp256r1.id()]);
        let group = NamedGroup::ALL
            .into_iter()
            .find(|g| client_groups.contains(&g.id()));
        if !e.extended_master_secret && self.config.require_extended_master_secret {
            return Err(handshake_failure("extended master secret required"));
        }
        self.ems = e.extended_master_secret;
        let srtp = e.srtp.as_ref().and_then(|(offered, _)| {
            self.config
                .srtp_profiles
                .iter()
                .copied()
                .find(|p| offered.contains(&p.id()))
        });
        self.srtp_profile = srtp;
        self.srtp_mki = srtp_mki_echo(&self.config, srtp, e.srtp.as_ref());
        self.peer_schemes = e.signature_algorithms.clone();
        self.client_random = ch.random;
        self.server_random = random32()?;
        if self.config.versions.contains(&Version::Dtls13) {
            // RFC 8446 §4.1.3: a DTLS 1.3 server negotiating DTLS 1.2 says so.
            self.server_random[24..].copy_from_slice(&hs::DOWNGRADE_12);
        }
        self.suite = Some(suite);
        self.transcript.clear();
        self.transcript.extend_from_slice(raw);
        self.send_seq = seq;
        // Connection IDs (RFC 9146): only when the client asked.
        match (&e.connection_id, &self.local_cid) {
            (Some(peer), Some(_)) => self.peer_cid = Some(peer.clone()),
            _ => self.local_cid = None,
        }
        let ticket_ext = self.config.resumption
            && self.config.ticket_key.is_some()
            && e.session_ticket.is_some()
            && !suite.is_psk();
        let mut sh = ServerHello {
            version: DTLS12,
            random: self.server_random,
            session_id: Vec::new(),
            cipher_suite: suite.id(),
            compression: 0,
            extensions: Extensions {
                point_formats: e.point_formats.as_ref().map(|_| vec![0]),
                srtp: srtp.map(|p| (vec![p.id()], self.srtp_mki.clone().unwrap_or_default())),
                extended_master_secret: self.ems,
                renegotiation_info: secure_renegotiation.then(Vec::new),
                connection_id: self.peer_cid.as_ref().and_then(|_| self.local_cid.clone()),
                ..Extensions::default()
            },
        };

        if let Some(st) = resumed {
            // Abbreviated handshake (RFC 5246 §7.3, RFC 5077 §3.1): ServerHello echoing the
            // session ID, ChangeCipherSpec, Finished.
            sh.session_id.clone_from(&ch.session_id);
            self.session_id.clone_from(&ch.session_id);
            if !st.peer_chain.is_empty() {
                self.peer_chain.clone_from(&st.peer_chain);
            }
            self.master_secret = Some(st.secret);
            self.resumed = true;
            let mut msgs = vec![self.message(0, hs::SERVER_HELLO, sh.encode())];
            self.derive_keys()?;
            msgs.push(FlightMsg {
                epoch: 0,
                msg: None,
            });
            let vd = self.verify_data(b"server finished", &self.transcript);
            msgs.push(self.message(1, hs::FINISHED, vd));
            self.send_flight(now, msgs, true);
            self.expect = Expect::ClientFinished;
            return Ok(());
        }

        if ticket_ext {
            sh.extensions.session_ticket = Some(Vec::new());
            self.send_ticket = true;
        } else if self.config.resumption && !suite.is_psk() {
            self.session_id = random32()?.to_vec();
            sh.session_id.clone_from(&self.session_id);
        }
        let mut msgs = vec![self.message(0, hs::SERVER_HELLO, sh.encode())];
        if suite.is_psk() {
            if suite.is_ecdhe_psk() {
                let group = group.ok_or_else(|| handshake_failure("no shared group"))?;
                let share = KeyShare::generate(group)?;
                let mut ske = Vec::new();
                crate::codec::put_vec16(&mut ske, &[]);
                ske.extend_from_slice(&ServerKeyExchange::params(group.id(), &share.public()));
                self.key_share = Some(share);
                msgs.push(self.message(0, hs::SERVER_KEY_EXCHANGE, ske));
            }
            msgs.push(self.message(0, hs::SERVER_HELLO_DONE, Vec::new()));
            self.send_flight(now, msgs, true);
            self.expect = Expect::ClientKeyExchange;
            return Ok(());
        }
        let identity = self
            .config
            .identity
            .clone()
            .ok_or(Error::Config("a server needs an identity"))?;
        let key = identity.private_key();
        let group = group.ok_or_else(|| handshake_failure("no shared group"))?;
        let scheme = crypto::choose_scheme(key, e.signature_algorithms.as_deref())
            .ok_or_else(|| handshake_failure("no shared signature scheme"))?;
        msgs.push(self.message(0, hs::CERTIFICATE, hs::encode_certificate(identity.chain())));
        let share = KeyShare::generate(group)?;
        let public = share.public();
        let mut signed = self.client_random.to_vec();
        signed.extend_from_slice(&self.server_random);
        signed.extend_from_slice(&ServerKeyExchange::params(group.id(), &public));
        let signature = crypto::sign(key, scheme, &signed)?;
        self.key_share = Some(share);
        let ske = ServerKeyExchange {
            group: group.id(),
            public,
            scheme,
            signature,
        };
        msgs.push(self.message(0, hs::SERVER_KEY_EXCHANGE, ske.encode()));
        self.cert_requested = self.config.require_client_certificate;
        if self.cert_requested {
            let req = hs::encode_certificate_request(&self.server_cert_request_schemes());
            msgs.push(self.message(0, hs::CERTIFICATE_REQUEST, req));
        }
        msgs.push(self.message(0, hs::SERVER_HELLO_DONE, Vec::new()));
        self.send_flight(now, msgs, true);
        self.expect = if self.cert_requested {
            Expect::ClientCertificate
        } else {
            Expect::ClientKeyExchange
        };
        Ok(())
    }

    /// A PSK ClientKeyExchange: identity (and the ECDHE public value for ECDHE-PSK).
    fn server_psk_client_key_exchange(&mut self, body: &[u8]) -> Result<(), Error> {
        let mut r = crate::codec::Reader::new(body);
        let id = r.vec16()?.to_vec();
        let (id, psk) = self.find_psk(Some(&id)).ok_or_else(|| {
            Error::protocol(AlertDescription::UnknownPskIdentity, "unknown PSK identity")
        })?;
        let other = match self.key_share.take() {
            Some(share) => {
                let public = r.vec8()?;
                if public.is_empty() {
                    return Err(Error::decode("empty ECDHE key"));
                }
                Some(share.agree(public)?)
            }
            None => None,
        };
        r.finish()?;
        self.premaster = Some(Conn12::psk_premaster(other, &psk));
        self.psk = Some((id, psk));
        Ok(())
    }
}

/// Client: the MKI in use after the server's `use_srtp` answer `mki` (RFC 5764 §4.1.3): none
/// when empty, ours when echoed, and a handshake failure for anything else.
pub(crate) fn srtp_mki_answer(config: &Config, mki: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    if mki.is_empty() {
        Ok(None)
    } else if mki == config.srtp_mki.as_slice() {
        Ok(Some(mki.to_vec()))
    } else {
        Err(illegal("SRTP MKI not offered"))
    }
}

/// Server: the MKI to echo for the client's `use_srtp` offer, when a profile was chosen and
/// MKIs are accepted.
pub(crate) fn srtp_mki_echo(
    config: &Config,
    chosen: Option<SrtpProfile>,
    offer: Option<&(Vec<u16>, Vec<u8>)>,
) -> Option<Vec<u8>> {
    let (_, mki) = offer?;
    (chosen.is_some() && config.srtp_accept_mki && !mki.is_empty()).then(|| mki.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Identity;

    /// A datagram holding one plaintext handshake record with one fragment.
    fn hello_fragment(seq: u64, length: usize, frag: &[u8]) -> Vec<u8> {
        let hs = hs::encode_fragment(hs::CLIENT_HELLO, 0, length, 0, frag);
        let mut d = Vec::new();
        Header {
            content_type: 22,
            version: 0xfefd,
            epoch: 0,
            seq,
        }
        .encode(hs.len(), &mut d);
        d.extend_from_slice(&hs);
        d
    }

    #[test]
    fn srtp_mki_rules() {
        let cfg = Config::without_identity().with_srtp_mki(vec![1, 2]);
        assert_eq!(srtp_mki_answer(&cfg, &[]).unwrap(), None);
        assert_eq!(srtp_mki_answer(&cfg, &[1, 2]).unwrap(), Some(vec![1, 2]));
        assert!(srtp_mki_answer(&cfg, &[1, 3]).is_err());
        let plain = Config::without_identity();
        assert!(srtp_mki_answer(&plain, &[1]).is_err());
        let offer = (vec![7u16], vec![5u8, 6]);
        let p = Some(SrtpProfile::AeadAes128Gcm);
        assert_eq!(srtp_mki_echo(&plain, p, Some(&offer)), None);
        let acc = Config::without_identity().with_srtp_accept_mki(true);
        assert_eq!(srtp_mki_echo(&acc, p, Some(&offer)), Some(vec![5, 6]));
        assert_eq!(srtp_mki_echo(&acc, None, Some(&offer)), None);
        assert_eq!(srtp_mki_echo(&acc, p, Some(&(vec![7], vec![]))), None);
        assert_eq!(srtp_mki_echo(&acc, p, None), None);
    }

    /// Before the cookie exchange a server reassembles nothing but a plausibly sized
    /// ClientHello, and what it holds grows with the bytes received, not with the length a
    /// fragment claims (just under, at and over the cap).
    #[test]
    fn pre_cookie_reassembly_is_bounded() {
        let id = Identity::generate_self_signed().unwrap();
        let now = Instant::now();
        let mut s =
            Conn12::new(Arc::new(Config::new(id)), Role::Server, now, b"10.0.0.1:1").unwrap();
        // Over the cap: dropped, nothing held.
        s.handle_datagram(now, &hello_fragment(0, hs::MAX_CLIENT_HELLO + 1, &[1; 16]))
            .unwrap();
        assert!(s.partials.is_empty());
        // At the cap and under it: held, but only as much as arrived.
        for (seq, len) in [(1, hs::MAX_CLIENT_HELLO), (2, hs::MAX_CLIENT_HELLO - 1)] {
            s.handle_datagram(now, &hello_fragment(seq, len, &[1; 16]))
                .unwrap();
            assert_eq!(s.partials.len(), 1);
            let held: usize = s.partials.values().map(|(_, p)| p.allocated()).sum();
            assert!(held < 1024, "{held}");
        }
        // Other message types are not reassembled before a ClientHello at all.
        let mut d = Vec::new();
        let cert = hs::encode_fragment(hs::CERTIFICATE, 5, hs::MAX_MESSAGE, 0, &[0; 16]);
        Header {
            content_type: 22,
            version: 0xfefd,
            epoch: 0,
            seq: 9,
        }
        .encode(cert.len(), &mut d);
        d.extend_from_slice(&cert);
        s.handle_datagram(now, &d).unwrap();
        assert!(s.partials.keys().all(|k| *k == 0));
    }
}
