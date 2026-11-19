//! The client handshake: TLS 1.3 (RFC 8446) with HelloRetryRequest, PSK resumption and client
//! certificates, falling back to TLS 1.2 (RFC 5246 with RFC 7627 / RFC 5746 / RFC 5077) when
//! the server picks it.

use std::sync::Arc;

use only_crypto::ct_eq;
use only_crypto::pkey::PublicKey;

use super::alert::{Alert, Fatal, fatal};
use super::codec::{Reader, put_u8, put_u16, put_vec, put_vec8, put_vec16};
use super::common::{
    Action, CertKey, ClientSettings, EarlyData, Keys, Level, Schedule, Transcript,
    check_stapled_ocsp, finished_mac, leaf_key, next_secret, now_millis, now_secs, random,
    verify_chain,
};
use super::conn::MAX_HANDSHAKE;
use super::kx::{Group, KeyShare};
use super::msgs::*;
use super::session::{Resume12, Session, Ticket13};
use super::sig;
use super::suites::{self, Auth12, EMPTY_RENEGOTIATION_INFO_SCSV, Suite};
use super::tls12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum St {
    WaitServerHello,
    WaitEncryptedExtensions,
    WaitCertOrRequest,
    WaitCert,
    WaitCertVerify,
    WaitFinished,
    Done13,
    WaitCert12,
    WaitServerKx12,
    WaitHelloDone12,
    WaitCcs12,
    WaitFinished12,
    Done12,
}

/// A client handshake in progress (and, afterwards, its post-handshake messages).
pub(crate) struct Client {
    cfg: Arc<ClientSettings>,
    /// The name the certificate must match (DNS name or IP address), also the cache key.
    name: String,
    sni: Option<String>,
    quic: Option<Vec<u8>>,
    /// TLS 1.2 is offered (never for QUIC).
    tls12: bool,
    st: St,
    t: Transcript,
    random: [u8; 32],
    session_id: Vec<u8>,
    share: Option<KeyShare>,
    offered_suites: Vec<u16>,
    sent_exts: Vec<u16>,
    psk13: Option<Ticket13>,
    resume12: Option<Resume12>,
    hrr_suite: Option<&'static Suite>,
    cookie: Option<Vec<u8>>,
    pub(crate) suite: Option<&'static Suite>,
    pub(crate) version: u16,
    sched: Option<Schedule>,
    c_hs: Vec<u8>,
    s_hs: Vec<u8>,
    c_ap: Vec<u8>,
    s_ap: Vec<u8>,
    res_master: Vec<u8>,
    pub(crate) resumed: bool,
    /// QUIC: the version new tickets are kept under (RFC 9369 section 5), the one the
    /// connection started in until compatible version negotiation moves it.
    pub(crate) quic_ticket_version: u32,
    cert_req: Option<(Vec<u8>, Vec<u16>)>,
    pub(crate) peer_chain: Vec<Vec<u8>>,
    peer_key: Option<PublicKey>,
    pub(crate) alpn: Option<Vec<u8>>,
    pub(crate) peer_quic: Option<Vec<u8>>,
    ccs_sent: bool,
    // TLS 1.2
    server_random: [u8; 32],
    ems: bool,
    master: Vec<u8>,
    ske: Option<(Group, Vec<u8>)>,
    ticket_expected: bool,
    new_ticket12: Option<(u32, Vec<u8>)>,
    sh_session_id: Vec<u8>,
    // TLS 1.3 early data.
    pub(crate) early: EarlyData,
    /// Over TCP, the handshake write keys wait until EndOfEarlyData is sent.
    deferred_write: Option<Keys>,
    /// The OCSP response stapled to the server's certificate (when asked for).
    pub(crate) ocsp: Option<Vec<u8>>,
    /// The algorithm the server's certificate came compressed with (RFC 8879).
    pub(crate) cert_compressed: Option<u16>,
    /// The certificate compression algorithms the server's CertificateRequest accepts and we
    /// have on (RFC 8879).
    peer_cert_comp: CompAlgs,
    /// TLS 1.2: the ServerHello announced a CertificateStatus.
    status12: bool,
    /// The verified leaf and its issuer, kept for the stapled OCSP check (policy not off).
    ocsp_certs: Option<Box<(only_x509::Certificate, only_x509::Certificate)>>,
    /// The record_size_limit the server advertised (0: none), kept with tickets for the early
    /// data of a later connection.
    peer_record_limit: u16,
}

impl Client {
    /// Starts a handshake with `name` (a DNS name or an IP address); `quic` carries our QUIC
    /// transport parameters for a QUIC handshake.
    /// `early`: offer early data (0-RTT) when the ticket allows it. `quic_version`: the QUIC
    /// version the connection starts in, only tickets of which are offered (0: TCP, or a QUIC
    /// handshake not bound to a version).
    pub(crate) fn new(
        cfg: Arc<ClientSettings>,
        name: &str,
        quic: Option<Vec<u8>>,
        early: bool,
        quic_version: u32,
    ) -> Result<Client, Fatal> {
        let is_ip = name.parse::<std::net::IpAddr>().is_ok();
        let sni = (cfg.sni && !is_ip).then(|| name.trim_end_matches('.').to_ascii_lowercase());
        let now = now_secs();
        let psk13 = match &cfg.cache {
            Some(c) if cfg.tls13 => c.take_ticket13(name, now, quic_version),
            _ => None,
        };
        let resume12 = match &cfg.cache {
            Some(c) if cfg.tls12 && quic.is_none() => c.tls12(name, now),
            _ => None,
        };
        let session_id = if quic.is_some() {
            Vec::new()
        } else {
            match &resume12 {
                Some(r) if r.ticket.is_none() && !r.session_id.is_empty() => r.session_id.clone(),
                _ => random::<32>()?.to_vec(),
            }
        };
        let group = *cfg
            .groups
            .first()
            .ok_or_else(|| Fatal::new(Alert::InternalError, "no groups"))?;
        let share = if cfg.tls13 {
            Some(group.generate()?)
        } else {
            None
        };
        // Early data goes with the first PSK (ours is the only one), under its suite, and only
        // for the ALPN protocol and (QUIC) transport parameters it was issued with
        // (RFC 8446 section 4.2.10, RFC 9001 section 4.6.1).
        let early = early
            && psk13.as_ref().is_some_and(|p| {
                p.session.max_early_data > 0
                    && cfg.suites.iter().any(|s| s.id == p.session.suite)
                    && p.session
                        .alpn
                        .as_ref()
                        .is_none_or(|a| cfg.alpn.iter().any(|x| x == a))
                    && (quic.is_none() || !p.session.early_ctx.is_empty())
            });
        Ok(Client {
            tls12: cfg.tls12 && quic.is_none(),
            name: name.to_owned(),
            sni,
            quic,
            st: St::WaitServerHello,
            t: Transcript::default(),
            random: random()?,
            session_id,
            share,
            offered_suites: Vec::new(),
            sent_exts: Vec::new(),
            psk13,
            resume12,
            hrr_suite: None,
            cookie: None,
            suite: None,
            version: 0,
            sched: None,
            c_hs: Vec::new(),
            s_hs: Vec::new(),
            c_ap: Vec::new(),
            s_ap: Vec::new(),
            res_master: Vec::new(),
            resumed: false,
            quic_ticket_version: quic_version,
            cert_req: None,
            peer_chain: Vec::new(),
            peer_key: None,
            alpn: None,
            peer_quic: None,
            ccs_sent: false,
            server_random: [0; 32],
            ems: false,
            master: Vec::new(),
            ske: None,
            ticket_expected: false,
            new_ticket12: None,
            sh_session_id: Vec::new(),
            early: if early {
                EarlyData::Pending
            } else {
                EarlyData::NotAttempted
            },
            deferred_write: None,
            ocsp: None,
            cert_compressed: None,
            peer_cert_comp: CompAlgs::NONE,
            status12: false,
            ocsp_certs: None,
            peer_record_limit: 0,
            cfg,
        })
    }

    /// Emits the ClientHello.
    pub(crate) fn start(&mut self, out: &mut Vec<Action>) -> Result<(), Fatal> {
        let ch = self.client_hello();
        self.t.add(&ch);
        let early = self.early_keys(&ch)?;
        out.push(Action::Msg(Level::Initial, ch));
        if let Some((max, keys)) = early {
            if self.compat() {
                // Middlebox compatibility: the CCS goes before the first protected record.
                self.ccs_sent = true;
                out.push(Action::Ccs);
            }
            out.push(Action::EarlyOffered(max));
            // Early data goes under the record_size_limit of the connection that issued the
            // ticket (RFC 8449 section 4: the limits of the handshake that made the keys).
            if let Some(l) = self
                .psk13
                .as_ref()
                .map(|p| p.record_limit)
                .filter(|l| *l > 0)
            {
                out.push(Action::RecordLimit { read: 0, write: l });
            }
            out.push(Action::WriteKeys(Level::EarlyData, keys));
        }
        Ok(())
    }

    /// The early traffic keys over ClientHello `ch` and the ticket's early data limit, when
    /// early data is offered.
    fn early_keys(&self, ch: &[u8]) -> Result<Option<(u32, Keys)>, Fatal> {
        if self.early != EarlyData::Pending {
            return Ok(None);
        }
        let p = self
            .psk13
            .as_ref()
            .ok_or_else(|| Fatal::new(Alert::InternalError, "early data without a ticket"))?;
        let suite = suites::by_id(p.session.suite)
            .ok_or_else(|| Fatal::new(Alert::InternalError, "ticket suite"))?;
        let h = suite.hash;
        let secret =
            Schedule::early(h, Some(&p.session.secret)).derive(b"c e traffic", &h.digest(ch));
        Ok(Some((
            p.session.max_early_data,
            Keys::Tls13 { suite, secret },
        )))
    }

    /// The server's transport parameters remembered with the ticket early data is sent with
    /// (QUIC 0-RTT, RFC 9000 section 7.4.1).
    pub(crate) fn early_params(&self) -> Option<&[u8]> {
        match (&self.early, &self.psk13) {
            (EarlyData::Pending | EarlyData::Accepted, Some(p)) => Some(&p.session.early_ctx),
            _ => None,
        }
    }

    /// Early data is rejected: say so, and (TCP) use the handshake write keys held back.
    fn reject_early(&mut self, out: &mut Vec<Action>) {
        if self.early != EarlyData::Pending {
            return;
        }
        self.early = EarlyData::Rejected;
        out.push(Action::RejectEarlyData);
        if let Some(k) = self.deferred_write.take() {
            out.push(Action::WriteKeys(Level::Handshake, k));
        }
    }

    pub(crate) fn handshaking(&self) -> bool {
        !matches!(self.st, St::Done13 | St::Done12)
    }

    fn compat(&self) -> bool {
        self.quic.is_none()
    }

    fn client_hello(&mut self) -> Vec<u8> {
        let cfg = self.cfg.clone();
        let tls12 = self.tls12;
        let mut suites_list: Vec<u16> = Vec::new();
        for s in &cfg.suites {
            if (s.is_tls13() && cfg.tls13) || (!s.is_tls13() && tls12) {
                suites_list.push(s.id);
            }
        }
        self.offered_suites = suites_list.clone();
        let mut sent = Vec::new();
        let psk_hash = self
            .psk13
            .as_ref()
            .and_then(|p| suites::by_id(p.session.suite))
            .map(|s| s.hash);
        let mut msg = message(CLIENT_HELLO, |o| {
            put_u16(o, TLS12);
            o.extend_from_slice(&self.random);
            put_vec8(o, &self.session_id);
            put_vec(o, 2, |o| {
                for s in &suites_list {
                    put_u16(o, *s);
                }
                if tls12 {
                    put_u16(o, EMPTY_RENEGOTIATION_INFO_SCSV);
                }
            });
            put_vec8(o, &[0]);
            put_vec(o, 2, |o| {
                let mut e = |t: u16, o: &mut Vec<u8>, f: &dyn Fn(&mut Vec<u8>)| {
                    sent.push(t);
                    ext(o, t, f);
                };
                if let Some(n) = &self.sni {
                    e(EXT_SERVER_NAME, o, &|o| {
                        put_vec(o, 2, |o| {
                            put_u8(o, 0);
                            put_vec16(o, n.as_bytes());
                        });
                    });
                }
                if tls12 {
                    e(EXT_EC_POINT_FORMATS, o, &|o| put_vec8(o, &[0]));
                    e(EXT_EXTENDED_MASTER_SECRET, o, &|_| {});
                    if cfg.cache.is_some() {
                        let tk = self
                            .resume12
                            .as_ref()
                            .and_then(|r| r.ticket.clone())
                            .unwrap_or_default();
                        e(EXT_SESSION_TICKET, o, &|o| o.extend_from_slice(&tk));
                    }
                }
                e(EXT_SUPPORTED_GROUPS, o, &|o| {
                    put_vec(o, 2, |o| {
                        for g in &cfg.groups {
                            put_u16(o, g.id());
                        }
                    });
                });
                e(EXT_SIGNATURE_ALGORITHMS, o, &|o| {
                    sig_algs_body(o, sig::SUPPORTED);
                });
                if !cfg.alpn.is_empty() {
                    e(EXT_ALPN, o, &|o| alpn_body(o, &cfg.alpn));
                }
                if cfg.ocsp {
                    // status_request: OCSP, no responder IDs, no request extensions.
                    e(EXT_STATUS_REQUEST, o, &|o| {
                        put_u8(o, STATUS_OCSP);
                        put_u16(o, 0);
                        put_u16(o, 0);
                    });
                }
                if self.quic.is_none() {
                    // QUIC has no records (RFC 9001 section 4).
                    e(EXT_RECORD_SIZE_LIMIT, o, &|o| put_u16(o, cfg.record_limit));
                }
                if cfg.tls13 && !cfg.cert_compression.is_empty() {
                    e(EXT_COMPRESS_CERTIFICATE, o, &|o| {
                        cert_comp_body(o, cfg.cert_compression);
                    });
                }
                if cfg.tls13 {
                    e(EXT_SUPPORTED_VERSIONS, o, &|o| {
                        put_vec(o, 1, |o| {
                            put_u16(o, TLS13);
                            if tls12 {
                                put_u16(o, TLS12);
                            }
                        });
                    });
                    if let Some(share) = &self.share {
                        e(EXT_KEY_SHARE, o, &|o| {
                            put_vec(o, 2, |o| {
                                put_u16(o, share.group().id());
                                put_vec16(o, &share.public());
                            });
                        });
                    }
                    if cfg.cache.is_some() {
                        e(EXT_PSK_MODES, o, &|o| put_vec8(o, &[PSK_DHE_KE]));
                    }
                    if let Some(c) = &self.cookie {
                        e(EXT_COOKIE, o, &|o| put_vec16(o, c));
                    }
                    if self.early == EarlyData::Pending && self.hrr_suite.is_none() {
                        e(EXT_EARLY_DATA, o, &|_| {});
                    }
                }
                if let Some(q) = &self.quic {
                    e(EXT_QUIC_TRANSPORT_PARAMETERS, o, &|o| {
                        o.extend_from_slice(q);
                    });
                }
                if let (Some(p), Some(h)) = (&self.psk13, psk_hash) {
                    let age = (now_millis().saturating_sub(p.received_ms) as u32)
                        .wrapping_add(p.session.age_add);
                    e(EXT_PRE_SHARED_KEY, o, &|o| {
                        put_vec(o, 2, |o| {
                            put_vec16(o, &p.ticket);
                            o.extend_from_slice(&age.to_be_bytes());
                        });
                        put_vec(o, 2, |o| put_vec8(o, &vec![0u8; h.len()]));
                    });
                }
            });
        });
        if tls12 {
            // Answered by the server's renegotiation_info (RFC 5746, the SCSV above).
            sent.push(EXT_RENEGOTIATION_INFO);
        }
        self.sent_exts = sent;
        if let (Some(p), Some(h)) = (&self.psk13, psk_hash) {
            // The binder covers the ClientHello up to the binders list.
            let blen = 2 + 1 + h.len();
            let cut = msg.len() - blen;
            let th = self.t.hash_with(h, &msg[..cut]);
            let bk = Schedule::early(h, Some(&p.session.secret)).binder_key(false);
            let binder = finished_mac(h, &bk, &th);
            let l = msg.len();
            msg[l - h.len()..].copy_from_slice(&binder);
        }
        msg
    }

    /// Handles one complete handshake message (`msg` includes the 4-byte header).
    pub(crate) fn handle(&mut self, msg: &[u8], out: &mut Vec<Action>) -> Result<(), Fatal> {
        let typ = msg[0];
        let body = &msg[4..];
        match (self.st, typ) {
            (St::WaitServerHello, SERVER_HELLO) => self.server_hello(msg, body, out),
            (St::WaitEncryptedExtensions, ENCRYPTED_EXTENSIONS) => {
                self.encrypted_extensions(msg, body, out)
            }
            (St::WaitCertOrRequest, CERTIFICATE_REQUEST) => self.certificate_request13(msg, body),
            (St::WaitCertOrRequest | St::WaitCert, CERTIFICATE) => self.certificate13(msg, body),
            (St::WaitCertOrRequest | St::WaitCert, COMPRESSED_CERTIFICATE)
                if self.sent_exts.contains(&EXT_COMPRESS_CERTIFICATE) =>
            {
                let (plain, alg) =
                    decompress_certificate(body, MAX_HANDSHAKE, self.cfg.cert_compression)?;
                self.cert_compressed = Some(alg);
                self.certificate13(msg, &plain)
            }
            (St::WaitCertVerify, CERTIFICATE_VERIFY) => self.certificate_verify13(msg, body),
            (St::WaitFinished, FINISHED) => self.finished13(msg, body, out),
            (St::Done13, NEW_SESSION_TICKET) => self.new_session_ticket13(body),
            (St::Done13, KEY_UPDATE) if self.quic.is_none() => self.key_update(body, out),
            (St::WaitCert12, CERTIFICATE) => self.certificate12(msg, body),
            (St::WaitServerKx12, CERTIFICATE_STATUS) if self.status12 && self.ocsp.is_none() => {
                let mut r = Reader::new(body);
                let resp = parse_certificate_status(&mut r)?;
                r.finish()?;
                self.t.add(msg);
                self.ocsp = Some(resp);
                Ok(())
            }
            (St::WaitServerKx12, SERVER_KEY_EXCHANGE) => self.server_key_exchange(msg, body),
            (St::WaitHelloDone12, CERTIFICATE_REQUEST) if self.cert_req.is_none() => {
                self.certificate_request12(msg, body)
            }
            (St::WaitHelloDone12, SERVER_HELLO_DONE) => self.server_hello_done(msg, body, out),
            (St::WaitCcs12, NEW_SESSION_TICKET)
                if self.ticket_expected && self.new_ticket12.is_none() =>
            {
                let mut r = Reader::new(body);
                let life = r.u32()?;
                let tk = r.vec16()?.to_vec();
                r.finish()?;
                self.t.add(msg);
                self.new_ticket12 = Some((life, tk));
                Ok(())
            }
            (St::WaitFinished12, FINISHED) => self.finished12(msg, body, out),
            (St::Done12, HELLO_REQUEST) if body.is_empty() => {
                out.push(Action::Warning(Alert::NoRenegotiation));
                Ok(())
            }
            _ => fatal(Alert::UnexpectedMessage, "unexpected handshake message"),
        }
    }

    /// A ChangeCipherSpec record (TLS 1.2 only; the TLS 1.3 compatibility ones are dropped by
    /// the record layer).
    pub(crate) fn change_cipher_spec(&mut self, out: &mut Vec<Action>) -> Result<(), Fatal> {
        if self.st != St::WaitCcs12 || (self.ticket_expected && self.new_ticket12.is_none()) {
            return fatal(Alert::UnexpectedMessage, "unexpected ChangeCipherSpec");
        }
        let suite = self.suite_or_err()?;
        let (_, s) = tls12::keys(suite, &self.master, &self.random, &self.server_random);
        out.push(Action::ReadKeys(Level::Application, s));
        self.st = St::WaitFinished12;
        Ok(())
    }

    fn suite_or_err(&self) -> Result<&'static Suite, Fatal> {
        self.suite
            .ok_or_else(|| Fatal::new(Alert::InternalError, "no suite"))
    }

    fn check_exts(&self, exts: &[(u16, &[u8])]) -> Result<(), Fatal> {
        for (t, _) in exts {
            if !self.sent_exts.contains(t) {
                return fatal(Alert::UnsupportedExtension, "unsolicited extension");
            }
        }
        Ok(())
    }

    fn check_alpn(&mut self, alpn: Option<Vec<u8>>) -> Result<(), Fatal> {
        if let Some(p) = &alpn {
            if !self.cfg.alpn.iter().any(|a| a == p) {
                return fatal(
                    Alert::IllegalParameter,
                    "server selected an ALPN protocol not offered",
                );
            }
        } else if self.quic.is_some() && !self.cfg.alpn.is_empty() {
            return fatal(Alert::NoApplicationProtocol, "QUIC needs ALPN");
        }
        self.alpn = alpn;
        Ok(())
    }

    fn server_hello(
        &mut self,
        msg: &[u8],
        body: &[u8],
        out: &mut Vec<Action>,
    ) -> Result<(), Fatal> {
        let sh = ServerHello::parse(body)?;
        if sh.random == HRR_RANDOM {
            return self.hello_retry(msg, &sh, out);
        }
        let version = match sh.version {
            Some(TLS13) if self.cfg.tls13 => TLS13,
            Some(_) => return fatal(Alert::IllegalParameter, "bad supported_versions"),
            None if sh.legacy_version == TLS12 && self.tls12 && self.hrr_suite.is_none() => TLS12,
            None => return fatal(Alert::ProtocolVersion, "unsupported protocol version"),
        };
        if version == TLS12
            && self.cfg.tls13
            && (sh.random[24..] == DOWNGRADE_TLS12 || sh.random[24..] == DOWNGRADE_TLS11)
        {
            return fatal(Alert::IllegalParameter, "downgrade detected");
        }
        let suite = match suites::by_id(sh.suite) {
            Some(s)
                if self.offered_suites.contains(&s.id) && s.is_tls13() == (version == TLS13) =>
            {
                s
            }
            _ => return fatal(Alert::IllegalParameter, "server chose a suite not offered"),
        };
        if self.hrr_suite.is_some_and(|h| h.id != suite.id) {
            return fatal(
                Alert::IllegalParameter,
                "suite differs from HelloRetryRequest",
            );
        }
        self.check_exts(&sh.exts)?;
        self.suite = Some(suite);
        self.version = version;
        self.t.set_hash(suite.hash);
        self.t.add(msg);
        if version == TLS12 {
            return self.server_hello12(&sh, suite, out);
        }
        if sh.session_id != self.session_id.as_slice() {
            return fatal(Alert::IllegalParameter, "session id not echoed");
        }
        for (t, _) in &sh.exts {
            if !matches!(
                *t,
                EXT_SUPPORTED_VERSIONS | EXT_KEY_SHARE | EXT_PRE_SHARED_KEY
            ) {
                return fatal(
                    Alert::IllegalParameter,
                    "extension not allowed in ServerHello",
                );
            }
        }
        let Some((g, public)) = sh.key_share else {
            return fatal(Alert::MissingExtension, "no key_share");
        };
        let share = match &self.share {
            Some(s) if s.group().id() == g => s,
            _ => return fatal(Alert::IllegalParameter, "key share for a group not offered"),
        };
        let shared = share.agree(public)?;
        let psk = match (sh.psk_index, &self.psk13) {
            (None, _) => None,
            (Some(0), Some(p)) => {
                if suites::by_id(p.session.suite).map(|s| s.hash) != Some(suite.hash) {
                    return fatal(Alert::IllegalParameter, "PSK hash mismatch");
                }
                Some(p.session.secret.clone())
            }
            _ => return fatal(Alert::IllegalParameter, "bad selected PSK"),
        };
        if psk.is_some() {
            self.resumed = true;
        }
        // Early data needs the first PSK accepted, under the ticket's own suite.
        let early_suite = self.psk13.as_ref().map(|p| p.session.suite);
        if psk.is_none() || early_suite != Some(suite.id) {
            self.reject_early(out);
        }
        let mut sched = Schedule::early(suite.hash, psk.as_deref());
        sched.next(Some(&shared));
        let th = self.t.hash();
        self.c_hs = sched.derive(b"c hs traffic", &th);
        self.s_hs = sched.derive(b"s hs traffic", &th);
        self.sched = Some(sched);
        if self.compat() && !self.ccs_sent {
            self.ccs_sent = true;
            out.push(Action::Ccs);
        }
        out.push(Action::ReadKeys(
            Level::Handshake,
            Keys::Tls13 {
                suite,
                secret: self.s_hs.clone(),
            },
        ));
        let hs_write = Keys::Tls13 {
            suite,
            secret: self.c_hs.clone(),
        };
        if self.early == EarlyData::Pending && self.compat() {
            // Over TCP early data stays under its keys up to EndOfEarlyData.
            self.deferred_write = Some(hs_write);
        } else {
            out.push(Action::WriteKeys(Level::Handshake, hs_write));
        }
        self.st = St::WaitEncryptedExtensions;
        Ok(())
    }

    fn hello_retry(
        &mut self,
        msg: &[u8],
        sh: &ServerHello<'_>,
        out: &mut Vec<Action>,
    ) -> Result<(), Fatal> {
        if self.hrr_suite.is_some() || !self.cfg.tls13 {
            return fatal(Alert::UnexpectedMessage, "second HelloRetryRequest");
        }
        if sh.version != Some(TLS13) {
            return fatal(Alert::IllegalParameter, "HelloRetryRequest without TLS 1.3");
        }
        let suite = match suites::by_id(sh.suite) {
            Some(s) if s.is_tls13() && self.offered_suites.contains(&s.id) => s,
            _ => return fatal(Alert::IllegalParameter, "server chose a suite not offered"),
        };
        if sh.session_id != self.session_id.as_slice() {
            return fatal(Alert::IllegalParameter, "session id not echoed");
        }
        for (t, _) in &sh.exts {
            if !matches!(*t, EXT_SUPPORTED_VERSIONS | EXT_KEY_SHARE | EXT_COOKIE) {
                return fatal(Alert::UnsupportedExtension, "extension not allowed in HRR");
            }
        }
        if sh.key_share.is_none() && sh.cookie.is_none() {
            return fatal(Alert::IllegalParameter, "HelloRetryRequest changes nothing");
        }
        if let Some((g, _)) = sh.key_share {
            let group = Group::from_id(g)
                .filter(|gr| self.cfg.groups.contains(gr))
                .ok_or_else(|| Fatal::new(Alert::IllegalParameter, "HRR group not offered"))?;
            if self.share.as_ref().is_some_and(|s| s.group() == group) {
                return fatal(
                    Alert::IllegalParameter,
                    "HRR asks for the group already sent",
                );
            }
            self.share = Some(group.generate()?);
        }
        self.cookie = sh.cookie.map(<[u8]>::to_vec);
        // No early data after a HelloRetryRequest (RFC 8446 section 4.2.10).
        self.reject_early(out);
        if self
            .psk13
            .as_ref()
            .is_some_and(|p| suites::by_id(p.session.suite).map(|s| s.hash) != Some(suite.hash))
        {
            self.psk13 = None;
        }
        self.hrr_suite = Some(suite);
        self.version = TLS13;
        self.t.rollup_for_hrr(suite.hash);
        self.t.add(msg);
        let ch = self.client_hello();
        self.t.add(&ch);
        out.push(Action::Msg(Level::Initial, ch));
        Ok(())
    }

    fn encrypted_extensions(
        &mut self,
        msg: &[u8],
        body: &[u8],
        out: &mut Vec<Action>,
    ) -> Result<(), Fatal> {
        let mut r = Reader::new(body);
        let exts = extensions(&mut r)?;
        r.finish()?;
        if body.len() < 2 {
            return fatal(Alert::DecodeError, "EncryptedExtensions without extensions");
        }
        let mut alpn = None;
        let mut early = false;
        let mut record_limit = 0;
        for (t, d) in &exts {
            match *t {
                EXT_RECORD_SIZE_LIMIT if self.sent_exts.contains(&EXT_RECORD_SIZE_LIMIT) => {
                    let mut x = Reader::new(d);
                    record_limit = parse_record_limit(&mut x)?;
                    x.finish()?;
                }
                EXT_EARLY_DATA if self.early == EarlyData::Pending => {
                    if !d.is_empty() {
                        return fatal(Alert::DecodeError, "bad early_data answer");
                    }
                    early = true;
                }
                EXT_SERVER_NAME => {
                    if !d.is_empty() || self.sni.is_none() {
                        return fatal(Alert::IllegalParameter, "bad server_name answer");
                    }
                }
                EXT_ALPN if self.sent_exts.contains(&EXT_ALPN) => {
                    alpn = Some(parse_alpn_selected(d)?);
                }
                EXT_SUPPORTED_GROUPS => {}
                EXT_QUIC_TRANSPORT_PARAMETERS if self.quic.is_some() => {
                    self.peer_quic = Some(d.to_vec());
                }
                _ => return fatal(Alert::UnsupportedExtension, "unsolicited extension"),
            }
        }
        if self.quic.is_some() && self.peer_quic.is_none() {
            return fatal(Alert::MissingExtension, "no QUIC transport parameters");
        }
        self.check_alpn(alpn)?;
        if self.quic.is_none() {
            // Ours applies once the server answered with its own (RFC 8449 section 4); also
            // drops a limit early data went under.
            self.peer_record_limit = record_limit;
            out.push(Action::RecordLimit {
                read: if record_limit > 0 {
                    self.cfg.record_limit
                } else {
                    0
                },
                write: record_limit,
            });
        }
        if early {
            // Accepted early data was for the ticket's protocol (RFC 8446 section 4.2.10).
            if self.psk13.as_ref().map(|p| &p.session.alpn) != Some(&self.alpn) {
                return fatal(
                    Alert::IllegalParameter,
                    "early data accepted for another ALPN protocol",
                );
            }
            self.early = EarlyData::Accepted;
        } else {
            self.reject_early(out);
        }
        self.t.add(msg);
        self.st = if self.resumed {
            St::WaitFinished
        } else {
            St::WaitCertOrRequest
        };
        Ok(())
    }

    fn certificate_request13(&mut self, msg: &[u8], body: &[u8]) -> Result<(), Fatal> {
        let mut r = Reader::new(body);
        let ctx = r.vec8()?.to_vec();
        let exts = extensions(&mut r)?;
        r.finish()?;
        let mut algs = None;
        for (t, d) in exts {
            let mut x = Reader::new(d);
            match t {
                EXT_SIGNATURE_ALGORITHMS => algs = Some(x.u16_list()?),
                EXT_COMPRESS_CERTIFICATE => {
                    self.peer_cert_comp = CompAlgs::from_ids(&parse_cert_comp(&mut x)?)
                        .and(self.cfg.cert_compression);
                }
                _ => {
                    x.rest();
                }
            }
            x.finish()?;
        }
        let Some(algs) = algs else {
            return fatal(
                Alert::MissingExtension,
                "CertificateRequest without signature_algorithms",
            );
        };
        self.cert_req = Some((ctx, algs));
        self.t.add(msg);
        self.st = St::WaitCert;
        Ok(())
    }

    fn peer_certificate(&mut self, chain: Vec<Vec<u8>>) -> Result<(), Fatal> {
        if chain.is_empty() {
            return fatal(Alert::DecodeError, "server sent no certificate");
        }
        let key = if self.cfg.insecure {
            leaf_key(&chain)?
        } else {
            let v = verify_chain(
                &self.cfg.roots,
                &chain,
                Some(&self.name),
                self.cfg.crls.as_ref(),
            )?;
            if self.cfg.ocsp_policy != crate::RevocationPolicy::Off {
                self.ocsp_certs = Some(Box::new((v.leaf, v.issuer)));
            }
            v.key
        };
        self.peer_key = Some(key);
        self.peer_chain = chain;
        Ok(())
    }

    /// The server's Certificate (`body`; decompressed when `msg` is a CompressedCertificate,
    /// which is what the transcript takes).
    fn certificate13(&mut self, msg: &[u8], body: &[u8]) -> Result<(), Fatal> {
        let c = parse_certificate13(body)?;
        if !c.context.is_empty() {
            return fatal(Alert::IllegalParameter, "server certificate with a context");
        }
        self.peer_certificate(c.chain)?;
        if self.cfg.ocsp {
            self.ocsp = c.ocsp;
        }
        self.check_ocsp()?;
        self.t.add(msg);
        self.st = St::WaitCertVerify;
        Ok(())
    }

    fn certificate_verify13(&mut self, msg: &[u8], body: &[u8]) -> Result<(), Fatal> {
        let mut r = Reader::new(body);
        let (scheme, signature) = parse_signature(&mut r)?;
        r.finish()?;
        let key = self
            .peer_key
            .as_ref()
            .ok_or_else(|| Fatal::new(Alert::InternalError, "no peer key"))?;
        let content = sig::tls13_content(true, &self.t.hash());
        sig::verify(key, scheme, &content, signature, true)?;
        self.t.add(msg);
        self.st = St::WaitFinished;
        Ok(())
    }

    fn finished13(&mut self, msg: &[u8], body: &[u8], out: &mut Vec<Action>) -> Result<(), Fatal> {
        let suite = self.suite_or_err()?;
        let h = suite.hash;
        let expect = finished_mac(h, &self.s_hs, &self.t.hash());
        if body.len() != expect.len() {
            return fatal(Alert::DecodeError, "Finished of the wrong length");
        }
        if !ct_eq(&expect, body) {
            return fatal(Alert::DecryptError, "server Finished does not verify");
        }
        self.t.add(msg);
        let th = self.t.hash();
        let sched = self
            .sched
            .as_mut()
            .ok_or_else(|| Fatal::new(Alert::InternalError, "no key schedule"))?;
        sched.next(None);
        self.c_ap = sched.derive(b"c ap traffic", &th);
        self.s_ap = sched.derive(b"s ap traffic", &th);
        out.push(Action::ReadKeys(
            Level::Application,
            Keys::Tls13 {
                suite,
                secret: self.s_ap.clone(),
            },
        ));
        if self.early == EarlyData::Accepted && self.compat() {
            // The end of the early data, under the early keys (not in QUIC).
            let m = message(END_OF_EARLY_DATA, |_| {});
            self.t.add(&m);
            out.push(Action::Msg(Level::EarlyData, m));
        }
        if let Some(k) = self.deferred_write.take() {
            out.push(Action::WriteKeys(Level::Handshake, k));
        }
        if let Some((ctx, algs)) = self.cert_req.take() {
            let chosen = self
                .cfg
                .cert
                .as_ref()
                .and_then(|c| sig::choose(&c.key, &algs, true).map(|s| (c.clone(), s)));
            match chosen {
                Some((ck, scheme)) => {
                    let m = ck.certificate13(&ctx, false, self.peer_cert_comp);
                    self.t.add(&m);
                    out.push(Action::Msg(Level::Handshake, m));
                    let content = sig::tls13_content(false, &self.t.hash());
                    let s = sig::sign(&ck.key, scheme, &content)?;
                    let m = certificate_verify(scheme, &s);
                    self.t.add(&m);
                    out.push(Action::Msg(Level::Handshake, m));
                }
                None => {
                    let m = certificate13(&ctx, &[]);
                    self.t.add(&m);
                    out.push(Action::Msg(Level::Handshake, m));
                }
            }
        }
        let fin = finished_mac(h, &self.c_hs, &self.t.hash());
        let m = message(FINISHED, |o| o.extend_from_slice(&fin));
        self.t.add(&m);
        out.push(Action::Msg(Level::Handshake, m));
        out.push(Action::WriteKeys(
            Level::Application,
            Keys::Tls13 {
                suite,
                secret: self.c_ap.clone(),
            },
        ));
        let th = self.t.hash();
        if let Some(s) = &self.sched {
            self.res_master = s.derive(b"res master", &th);
        }
        self.st = St::Done13;
        self.t = Transcript::default();
        out.push(Action::Done);
        Ok(())
    }

    fn new_session_ticket13(&self, body: &[u8]) -> Result<(), Fatal> {
        let mut r = Reader::new(body);
        let lifetime = r.u32()?;
        let age_add = r.u32()?;
        let nonce = r.vec8()?;
        let ticket = r.vec16()?;
        let exts = extensions(&mut r)?;
        r.finish()?;
        if ticket.is_empty() {
            return fatal(Alert::DecodeError, "empty ticket");
        }
        if lifetime > 604_800 {
            return fatal(Alert::IllegalParameter, "ticket lifetime over 7 days");
        }
        let mut max_early_data = 0;
        for (t, d) in exts {
            // Unknown NewSessionTicket extensions are ignored (RFC 8446 section 4.6.1).
            if t == EXT_EARLY_DATA {
                let mut x = Reader::new(d);
                max_early_data = x.u32()?;
                x.finish()?;
            }
        }
        let (Some(cache), Some(suite)) = (&self.cfg.cache, self.suite) else {
            return Ok(());
        };
        if lifetime == 0 {
            return Ok(());
        }
        let psk = suite
            .hash
            .expand_label(&self.res_master, b"resumption", nonce, suite.hash.len());
        cache.add_ticket13(
            &self.name,
            Ticket13 {
                ticket: ticket.to_vec(),
                session: Session {
                    version: TLS13,
                    suite: suite.id,
                    secret: psk,
                    created: now_secs(),
                    lifetime,
                    age_add,
                    alpn: self.alpn.clone(),
                    sni: self.sni.clone(),
                    ems: false,
                    peer_chain: Vec::new(),
                    max_early_data,
                    early_ctx: self.peer_quic.clone().unwrap_or_default(),
                    quic_version: self.quic_ticket_version,
                },
                received_ms: now_millis(),
                record_limit: self.peer_record_limit,
            },
        );
        Ok(())
    }

    fn key_update(&mut self, body: &[u8], out: &mut Vec<Action>) -> Result<(), Fatal> {
        let suite = self.suite_or_err()?;
        let (read, write) = (&mut self.s_ap, &mut self.c_ap);
        key_update(suite, body, read, write, out)
    }

    /// Sends a KeyUpdate (not requesting one back) and moves to the next write secret.
    pub(crate) fn initiate_key_update(&mut self, out: &mut Vec<Action>) -> Result<(), Fatal> {
        let suite = self.suite_or_err()?;
        send_key_update(suite, &mut self.c_ap, false, out);
        Ok(())
    }

    // ---- TLS 1.2 ----

    fn server_hello12(
        &mut self,
        sh: &ServerHello<'_>,
        suite: &'static Suite,
        out: &mut Vec<Action>,
    ) -> Result<(), Fatal> {
        if let Some(ri) = sh.reneg_info {
            if !ri.is_empty() {
                return fatal(Alert::HandshakeFailure, "non-empty renegotiation_info");
            }
        }
        if let Some(f) = sh.ec_point_formats {
            if !f.contains(&0) {
                return fatal(Alert::IllegalParameter, "no uncompressed point format");
            }
        }
        self.check_alpn(sh.alpn.clone())?;
        if let Some(l) = sh.record_limit {
            // Protected records only (after the CCS); solicited (check_exts).
            out.push(Action::RecordLimit {
                read: self.cfg.record_limit,
                write: l,
            });
        }
        self.status12 = sh.status_request;
        self.server_random = sh.random;
        self.ems = sh.ems;
        self.ticket_expected = sh.session_ticket;
        self.sh_session_id = sh.session_id.to_vec();
        let resumable = self.resume12.as_ref().is_some_and(|_| {
            !sh.session_id.is_empty() && sh.session_id == self.session_id.as_slice()
        });
        if resumable {
            let r = self
                .resume12
                .clone()
                .ok_or_else(|| Fatal::new(Alert::InternalError, "no session"))?;
            if r.session.suite != suite.id || r.session.ems != self.ems || !self.ems {
                return fatal(Alert::HandshakeFailure, "resumed session parameters differ");
            }
            self.master = r.session.secret;
            self.resumed = true;
            self.st = St::WaitCcs12;
        } else {
            self.st = St::WaitCert12;
        }
        Ok(())
    }

    fn certificate12(&mut self, msg: &[u8], body: &[u8]) -> Result<(), Fatal> {
        let chain = parse_certificate12(body)?;
        self.peer_certificate(chain)?;
        self.t.add(msg);
        self.st = St::WaitServerKx12;
        Ok(())
    }

    /// The stapled OCSP check, once the response had its chance to arrive (TLS 1.3: in the
    /// Certificate; TLS 1.2: in a CertificateStatus before the ServerKeyExchange).
    fn check_ocsp(&mut self) -> Result<(), Fatal> {
        match self.ocsp_certs.take() {
            Some(c) => check_stapled_ocsp(self.cfg.ocsp_policy, self.ocsp.as_deref(), &c.0, &c.1),
            None => Ok(()),
        }
    }

    fn server_key_exchange(&mut self, msg: &[u8], body: &[u8]) -> Result<(), Fatal> {
        self.check_ocsp()?;
        let suite = self.suite_or_err()?;
        let mut r = Reader::new(body);
        if r.u8()? != 3 {
            return fatal(Alert::IllegalParameter, "not a named curve");
        }
        let g = r.u16()?;
        let point = r.vec8()?;
        let params_len = body.len() - r.clone().rest().len();
        let (scheme, signature) = parse_signature(&mut r)?;
        r.finish()?;
        let group = Group::from_id(g)
            .filter(|gr| self.cfg.groups.contains(gr))
            .ok_or_else(|| Fatal::new(Alert::IllegalParameter, "group not offered"))?;
        let key = self
            .peer_key
            .as_ref()
            .ok_or_else(|| Fatal::new(Alert::InternalError, "no peer key"))?;
        let ok_key = match suite.tls12 {
            Some(Auth12::Rsa) => matches!(key, PublicKey::Rsa(_)),
            _ => matches!(
                key,
                PublicKey::P256(_)
                    | PublicKey::P384(_)
                    | PublicKey::Ed25519(_)
                    | PublicKey::Ed448(_)
            ),
        };
        if !ok_key {
            return fatal(
                Alert::IllegalParameter,
                "certificate key does not fit the suite",
            );
        }
        let mut signed = Vec::with_capacity(64 + params_len);
        signed.extend_from_slice(&self.random);
        signed.extend_from_slice(&self.server_random);
        signed.extend_from_slice(&body[..params_len]);
        sig::verify(key, scheme, &signed, signature, false)?;
        self.ske = Some((group, point.to_vec()));
        self.t.add(msg);
        self.st = St::WaitHelloDone12;
        Ok(())
    }

    fn certificate_request12(&mut self, msg: &[u8], body: &[u8]) -> Result<(), Fatal> {
        let mut r = Reader::new(body);
        let _types = r.vec8()?;
        let algs = r.u16_list()?;
        let _cas = r.vec16()?;
        r.finish()?;
        self.cert_req = Some((Vec::new(), algs));
        self.t.add(msg);
        Ok(())
    }

    fn server_hello_done(
        &mut self,
        msg: &[u8],
        body: &[u8],
        out: &mut Vec<Action>,
    ) -> Result<(), Fatal> {
        if !body.is_empty() {
            return fatal(Alert::DecodeError, "ServerHelloDone with a body");
        }
        let suite = self.suite_or_err()?;
        self.t.add(msg);
        let mut signer: Option<(Arc<CertKey>, u16)> = None;
        if let Some((_, algs)) = self.cert_req.take() {
            signer = self
                .cfg
                .cert
                .as_ref()
                .and_then(|c| sig::choose(&c.key, &algs, false).map(|s| (c.clone(), s)));
            let chain = signer
                .as_ref()
                .map(|(c, _)| c.chain.clone())
                .unwrap_or_default();
            let m = certificate12(&chain);
            self.t.add(&m);
            out.push(Action::Msg(Level::Initial, m));
        }
        let (group, point) = self
            .ske
            .take()
            .ok_or_else(|| Fatal::new(Alert::InternalError, "no key exchange"))?;
        let share = group.generate()?;
        let pms = share.agree(&point)?;
        let cke = message(CLIENT_KEY_EXCHANGE, |o| put_vec8(o, &share.public()));
        self.t.add(&cke);
        out.push(Action::Msg(Level::Initial, cke));
        self.master = tls12::master_secret(
            suite,
            &pms,
            self.ems,
            &self.t.hash(),
            &self.random,
            &self.server_random,
        );
        if let Some((ck, scheme)) = signer {
            let s = sig::sign(&ck.key, scheme, self.t.raw())?;
            let m = certificate_verify(scheme, &s);
            self.t.add(&m);
            out.push(Action::Msg(Level::Initial, m));
        }
        let (c, _) = tls12::keys(suite, &self.master, &self.random, &self.server_random);
        out.push(Action::Ccs);
        out.push(Action::WriteKeys(Level::Application, c));
        let vd = suite
            .hash
            .prf(&self.master, b"client finished", &self.t.hash(), 12);
        let m = message(FINISHED, |o| o.extend_from_slice(&vd));
        self.t.add(&m);
        out.push(Action::Msg(Level::Application, m));
        self.st = St::WaitCcs12;
        Ok(())
    }

    fn finished12(&mut self, msg: &[u8], body: &[u8], out: &mut Vec<Action>) -> Result<(), Fatal> {
        let suite = self.suite_or_err()?;
        let expect = suite
            .hash
            .prf(&self.master, b"server finished", &self.t.hash(), 12);
        if body.len() != expect.len() {
            return fatal(Alert::DecodeError, "Finished of the wrong length");
        }
        if !ct_eq(&expect, body) {
            return fatal(Alert::DecryptError, "server Finished does not verify");
        }
        self.t.add(msg);
        if self.resumed {
            let (c, _) = tls12::keys(suite, &self.master, &self.random, &self.server_random);
            out.push(Action::Ccs);
            out.push(Action::WriteKeys(Level::Application, c));
            let vd = suite
                .hash
                .prf(&self.master, b"client finished", &self.t.hash(), 12);
            let m = message(FINISHED, |o| o.extend_from_slice(&vd));
            out.push(Action::Msg(Level::Application, m));
        }
        if let Some(cache) = &self.cfg.cache {
            let old_ticket = self.resume12.as_ref().and_then(|r| r.ticket.clone());
            let (lifetime, ticket) = match self.new_ticket12.take() {
                Some((l, t)) => (if l == 0 { 7200 } else { l.min(604_800) }, Some(t)),
                None if self.resumed => (7200, old_ticket),
                None => (7200, None),
            };
            if self.ems && (ticket.is_some() || !self.sh_session_id.is_empty()) {
                cache.set_tls12(
                    &self.name,
                    Some(Resume12 {
                        session_id: self.sh_session_id.clone(),
                        ticket,
                        session: Session {
                            version: TLS12,
                            suite: suite.id,
                            secret: self.master.clone(),
                            created: now_secs(),
                            lifetime,
                            age_add: 0,
                            alpn: self.alpn.clone(),
                            sni: self.sni.clone(),
                            ems: true,
                            peer_chain: Vec::new(),
                            max_early_data: 0,
                            early_ctx: Vec::new(),
                            quic_version: 0,
                        },
                    }),
                );
            }
        }
        self.st = St::Done12;
        self.t = Transcript::default();
        out.push(Action::Done);
        Ok(())
    }
}

/// Handles a received TLS 1.3 KeyUpdate: next read secret, and a KeyUpdate back if requested.
pub(crate) fn key_update(
    suite: &'static Suite,
    body: &[u8],
    read: &mut Vec<u8>,
    write: &mut Vec<u8>,
    out: &mut Vec<Action>,
) -> Result<(), Fatal> {
    let requested = match body {
        [0] => false,
        [1] => true,
        // RFC 8446 section 4.6.3: another value is illegal_parameter; another length does not
        // decode.
        [_] => return fatal(Alert::IllegalParameter, "bad KeyUpdate request_update"),
        _ => return fatal(Alert::DecodeError, "KeyUpdate of the wrong length"),
    };
    *read = next_secret(suite.hash, read);
    out.push(Action::ReadKeys(
        Level::Application,
        Keys::Tls13 {
            suite,
            secret: read.clone(),
        },
    ));
    if requested {
        send_key_update(suite, write, false, out);
    }
    Ok(())
}

/// Sends a KeyUpdate under the current write secret, then moves to the next one.
pub(crate) fn send_key_update(
    suite: &'static Suite,
    write: &mut Vec<u8>,
    request: bool,
    out: &mut Vec<Action>,
) {
    let m = message(KEY_UPDATE, |o| put_u8(o, u8::from(request)));
    out.push(Action::Msg(Level::Application, m));
    *write = next_secret(suite.hash, write);
    out.push(Action::WriteKeys(
        Level::Application,
        Keys::Tls13 {
            suite,
            secret: write.clone(),
        },
    ));
}
