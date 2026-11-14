//! The DTLS 1.2 connection state machine (client and server), sans-io.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use only_crypto::pkey::PublicKey;
use only_x509::Certificate;

use crate::config::{Config, Fingerprint, FingerprintAlgorithm, SrtpKeys, SrtpProfile};
use crate::cookie::{self, HelloVerifier};
use crate::crypto::{self, CipherSuite, KeyShare, NamedGroup, RecordProtection, SIGNATURE_SCHEMES};
use crate::handshake::{
    self as hs, ClientHello, Extensions, Partial, ServerHello, ServerKeyExchange,
};
use crate::record::{
    self, CT_ALERT, CT_APPLICATION_DATA, CT_CHANGE_CIPHER_SPEC, CT_HANDSHAKE, DTLS12, Header,
    MAX_PLAINTEXT, ReplayWindow,
};
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
    /// Whether the extended master secret (RFC 7627) is in use.
    pub extended_master_secret: bool,
}

/// What [`Connection::poll_event`] reports.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Event {
    /// The handshake completed; application data can flow.
    Connected(Box<HandshakeInfo>),
    /// A record of application data from the peer.
    ApplicationData(Vec<u8>),
    /// The peer closed the connection with close_notify (ours was sent in reply).
    Closed,
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

/// A DTLS 1.2 connection: a sans-io state machine. Feed it datagrams
/// ([`handle_datagram`](Connection::handle_datagram)) and timer expiries
/// ([`handle_timeout`](Connection::handle_timeout) at [`poll_timeout`](Connection::poll_timeout));
/// send what [`poll_transmit`](Connection::poll_transmit) returns and act on
/// [`poll_event`](Connection::poll_event).
#[derive(Debug)]
pub struct Connection {
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

impl Connection {
    /// A client connection; its first flight (the ClientHello) is ready in
    /// [`poll_transmit`](Connection::poll_transmit).
    pub fn client(config: Arc<Config>, now: Instant) -> Result<Connection, Error> {
        let mut c = Connection::new(config, Role::Client, now, &[])?;
        c.start_client(now)?;
        Ok(c)
    }

    /// A server connection for the peer at `peer` (any stable encoding of its transport
    /// address; it is bound into HelloVerifyRequest cookies). It waits for a ClientHello.
    pub fn server(config: Arc<Config>, now: Instant, peer: &[u8]) -> Result<Connection, Error> {
        Connection::new(config, Role::Server, now, peer)
    }

    /// A connection for `role` (WebRTC decides the role from `a=setup`).
    pub fn new(
        config: Arc<Config>,
        role: Role,
        now: Instant,
        peer: &[u8],
    ) -> Result<Connection, Error> {
        if config.cipher_suites.is_empty() {
            return Err(Error::Config("no cipher suites"));
        }
        if role == Role::Server {
            let id = config
                .identity
                .as_ref()
                .ok_or(Error::Config("a server needs an identity"))?;
            if !config
                .cipher_suites
                .iter()
                .any(|s| s.fits_key(id.private_key()))
            {
                return Err(Error::Config("no cipher suite fits the server key"));
            }
        }
        let hello_verifier = if role == Role::Server && config.hello_verify {
            Some(HelloVerifier::new(now)?)
        } else {
            None
        };
        let mut c = Connection {
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
            config,
        };
        c.client_random = random32()?;
        Ok(c)
    }

    /// This endpoint's role.
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }

    /// Whether the handshake completed and the connection is open.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.state == State::Connected
    }

    /// Whether the connection is closed or failed (nothing more will be sent or received).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        matches!(self.state, State::Closed | State::Failed)
    }

    /// What the handshake established, once connected.
    #[must_use]
    pub fn handshake_info(&self) -> Option<&HandshakeInfo> {
        self.info.as_ref()
    }

    /// The next datagram to send.
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        self.transmits.pop_front()
    }

    /// The next event.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// When [`handle_timeout`](Connection::handle_timeout) must be called next (retransmission
    /// or handshake deadline); `None` once connected or closed.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
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
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
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
    /// [`poll_transmit`](Connection::poll_transmit)) and closes the connection. Records that do
    /// not authenticate, replays and stray retransmissions are dropped silently.
    pub fn handle_datagram(&mut self, now: Instant, datagram: &[u8]) -> Result<(), Error> {
        if self.is_closed() {
            return Err(Error::Closed);
        }
        for (h, fragment) in record::split(datagram) {
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
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
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
    pub fn export_keying_material(
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
    pub fn close(&mut self) {
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
            let f = k.seal(&h, payload);
            h.encode(f.len(), &mut out);
            out.extend_from_slice(&f);
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
        let payload: &[u8] = match h.epoch {
            0 => {
                // After the handshake only retransmitted handshake records are meaningful in
                // epoch 0; unauthenticated alerts are ignored.
                if self.state == State::Connected && h.content_type != CT_HANDSHAKE {
                    return Ok(());
                }
                if h.content_type == CT_APPLICATION_DATA {
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
                let Some(p) = keys.open(&h, fragment) else {
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
        match h.content_type {
            CT_HANDSHAKE => self.handle_handshake(now, h.epoch, payload),
            CT_CHANGE_CIPHER_SPEC => {
                if payload != [1] {
                    return Err(Error::decode("bad ChangeCipherSpec"));
                }
                Ok(())
            }
            CT_ALERT => self.handle_alert(payload),
            _ => {
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
            if self.expect == Expect::ClientHello && f.msg_type != hs::CLIENT_HELLO {
                continue;
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
                    let room = mtu
                        - record::HEADER_LEN
                        - hs::HEADER_LEN
                        - if m.epoch == 1 { overhead } else { 0 };
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
        let pms = self
            .premaster
            .take()
            .ok_or_else(|| handshake_failure("no premaster secret"))?;
        let h = suite.prf_hash();
        let mut ms = vec![0u8; 48];
        if self.ems {
            let session_hash = h.digest(&self.transcript);
            crypto::prf(h, &pms, b"extended master secret", &session_hash, &mut ms);
        } else {
            let mut seed = self.client_random.to_vec();
            seed.extend_from_slice(&self.server_random);
            crypto::prf(h, &pms, b"master secret", &seed, &mut ms);
        }
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

    fn connected(&mut self) -> Result<(), Error> {
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
            extended_master_secret: self.ems,
        };
        self.info = Some(info.clone());
        self.events.push_back(Event::Connected(Box::new(info)));
        for d in std::mem::take(&mut self.early_app) {
            self.events.push_back(Event::ApplicationData(d));
        }
        Ok(())
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
                self.expect = Expect::ServerCertificate;
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
                self.client_server_key_exchange(body)?;
                self.transcript.extend_from_slice(&raw);
                self.expect = Expect::CertificateRequestOrDone;
            }
            (Expect::CertificateRequestOrDone, hs::CERTIFICATE_REQUEST) => {
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
            (Expect::ServerFinished, hs::FINISHED) => {
                let expected = self.verify_data(b"server finished", &self.transcript);
                if !only_crypto::ct_eq(&expected, body) {
                    return Err(Error::protocol(
                        AlertDescription::DecryptError,
                        "bad Finished",
                    ));
                }
                self.transcript.extend_from_slice(&raw);
                self.connected()?;
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
                let public = hs::parse_client_key_exchange(body)?;
                let share = self
                    .key_share
                    .take()
                    .ok_or_else(|| unexpected("no key share"))?;
                self.premaster = Some(share.agree(&public)?);
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
                let expected = self.verify_data(b"client finished", &self.transcript);
                if !only_crypto::ct_eq(&expected, body) {
                    return Err(Error::protocol(
                        AlertDescription::DecryptError,
                        "bad Finished",
                    ));
                }
                self.transcript.extend_from_slice(&raw);
                let ccs = FlightMsg {
                    epoch: 0,
                    msg: None,
                };
                let vd = self.verify_data(b"server finished", &self.transcript);
                let fin = self.message(1, hs::FINISHED, vd);
                self.send_flight(now, vec![ccs, fin], false);
                self.connected()?;
            }
            _ => return Err(unexpected("unexpected handshake message")),
        }
        Ok(())
    }

    // ---- client ----

    fn start_client(&mut self, now: Instant) -> Result<(), Error> {
        let cfg = &self.config;
        let mut suites: Vec<u16> = cfg.cipher_suites.iter().map(|s| s.id()).collect();
        suites.push(hs::SCSV_RENEGOTIATION);
        let extensions = Extensions {
            groups: Some(NamedGroup::ALL.iter().map(|g| g.id()).collect()),
            point_formats: Some(vec![0]),
            signature_algorithms: Some(SIGNATURE_SCHEMES.to_vec()),
            srtp: (!cfg.srtp_profiles.is_empty()).then(|| {
                (
                    cfg.srtp_profiles.iter().map(|p| p.id()).collect(),
                    Vec::new(),
                )
            }),
            extended_master_secret: true,
            renegotiation_info: None,
            unknown: Vec::new(),
        };
        let ch = ClientHello {
            version: DTLS12,
            random: self.client_random,
            session_id: Vec::new(),
            cookie: Vec::new(),
            cipher_suites: suites,
            compression: vec![0],
            extensions,
        };
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
        if sh.version != DTLS12 {
            return Err(Error::protocol(
                AlertDescription::ProtocolVersion,
                "not DTLS 1.2",
            ));
        }
        let suite = CipherSuite::from_id(sh.cipher_suite)
            .filter(|s| self.config.cipher_suites.contains(s))
            .ok_or_else(|| illegal("cipher suite not offered"))?;
        if sh.compression != 0 {
            return Err(illegal("compression not offered"));
        }
        let e = &sh.extensions;
        if !e.unknown.is_empty() || e.groups.is_some() || e.signature_algorithms.is_some() {
            return Err(Error::protocol(
                AlertDescription::UnsupportedExtension,
                "extension not offered",
            ));
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
            if !mki.is_empty() {
                return Err(illegal("SRTP MKI not offered"));
            }
            self.srtp_profile = Some(p);
        }
        if !e.extended_master_secret && self.config.require_extended_master_secret {
            return Err(handshake_failure("extended master secret required"));
        }
        self.ems = e.extended_master_secret;
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
        let public = self
            .key_share
            .take()
            .ok_or_else(|| unexpected("no key share"))?
            .public();
        msgs.push(self.message(
            0,
            hs::CLIENT_KEY_EXCHANGE,
            hs::encode_client_key_exchange(&public),
        ));
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
        let identity = self
            .config
            .identity
            .clone()
            .ok_or(Error::Config("a server needs an identity"))?;
        let key = identity.private_key();
        let suite = self
            .config
            .cipher_suites
            .iter()
            .copied()
            .find(|s| s.fits_key(key) && ch.cipher_suites.contains(&s.id()))
            .ok_or_else(|| handshake_failure("no shared cipher suite"))?;
        let client_groups = e
            .groups
            .clone()
            .unwrap_or_else(|| vec![NamedGroup::Secp256r1.id()]);
        let group = NamedGroup::ALL
            .into_iter()
            .find(|g| client_groups.contains(&g.id()))
            .ok_or_else(|| handshake_failure("no shared group"))?;
        let scheme = crypto::choose_scheme(key, e.signature_algorithms.as_deref())
            .ok_or_else(|| handshake_failure("no shared signature scheme"))?;
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
        self.peer_schemes = e.signature_algorithms.clone();
        self.client_random = ch.random;
        self.server_random = random32()?;
        self.suite = Some(suite);
        self.transcript.clear();
        self.transcript.extend_from_slice(raw);
        self.send_seq = seq;

        let sh = ServerHello {
            version: DTLS12,
            random: self.server_random,
            session_id: Vec::new(),
            cipher_suite: suite.id(),
            compression: 0,
            extensions: Extensions {
                point_formats: e.point_formats.as_ref().map(|_| vec![0]),
                srtp: srtp.map(|p| (vec![p.id()], Vec::new())),
                extended_master_secret: self.ems,
                renegotiation_info: secure_renegotiation.then(Vec::new),
                ..Extensions::default()
            },
        };
        let mut msgs = vec![self.message(0, hs::SERVER_HELLO, sh.encode())];
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
}
