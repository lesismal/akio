//! The server handshake: TLS 1.3 (HelloRetryRequest, PSK resumption with stateless or cached
//! tickets, client certificates, early data when enabled, with replay protection) and TLS 1.2 (ECDHE, extended master secret,
//! session IDs and tickets, client certificates, renegotiation refused).

use std::sync::Arc;

use only_crypto::ct_eq;
use only_crypto::pkey::PublicKey;

use super::alert::{Alert, Fatal, fatal};
use super::client::{key_update, send_key_update};
use super::codec::{Reader, put_u16, put_u32, put_vec, put_vec8, put_vec16};
use super::common::{
    Action, CertKey, EarlyData, Keys, Level, Schedule, ServerSettings, Transcript, finished_mac,
    now_millis, now_secs, random, verify_chain,
};
use super::conn::MAX_HANDSHAKE;
use super::kx::{Group, KeyShare};
use super::msgs::*;
use super::session::Session;
use super::sig;
use super::suites::{self, Auth12, EMPTY_RENEGOTIATION_INFO_SCSV, FALLBACK_SCSV, Suite};
use super::tls12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum St {
    WaitClientHello,
    WaitClientHello2,
    WaitEndOfEarlyData,
    WaitCert13,
    WaitCertVerify13,
    WaitFinished13,
    Done13,
    WaitCert12,
    WaitClientKx12,
    WaitCertVerify12,
    WaitCcs12,
    WaitFinished12,
    Done12,
}

/// A server handshake in progress (and its post-handshake messages).
pub(crate) struct Server {
    cfg: Arc<ServerSettings>,
    quic: Option<Vec<u8>>,
    st: St,
    t: Transcript,
    pub(crate) suite: Option<&'static Suite>,
    pub(crate) version: u16,
    client_random: [u8; 32],
    server_random: [u8; 32],
    pub(crate) sni: Option<String>,
    pub(crate) alpn: Option<Vec<u8>>,
    cert: Option<Arc<CertKey>>,
    sched: Option<Schedule>,
    c_hs: Vec<u8>,
    c_ap: Vec<u8>,
    s_ap: Vec<u8>,
    hrr: Option<(&'static Suite, Group)>,
    /// What ClientHello1 fixed, for checking ClientHello2 (RFC 8446 4.1.2).
    ch1: Option<Ch1>,
    ccs_sent: bool,
    pub(crate) resumed: bool,
    cert_requested: bool,
    pub(crate) peer_chain: Vec<Vec<u8>>,
    peer_key: Option<PublicKey>,
    pub(crate) peer_quic: Option<Vec<u8>>,
    /// The algorithm the client's certificate came compressed with (RFC 8879).
    pub(crate) cert_compressed: Option<u16>,
    // TLS 1.2
    ems: bool,
    master: Vec<u8>,
    share: Option<KeyShare>,
    session_id: Vec<u8>,
    send_ticket12: bool,
    /// TLS 1.2: our record_size_limit for the ServerHello, when the client sent one.
    record_limit12: Option<u16>,
    /// TLS 1.2: the OCSP response goes in a CertificateStatus (status_request in the
    /// ServerHello).
    staple12: bool,
    // TLS 1.3 early data.
    pub(crate) early: EarlyData,
    /// QUIC with 0-RTT enabled: what the early data is bound to besides the ticket (the
    /// transport parameters 0-RTT may use).
    early_ctx: Option<Vec<u8>>,
    /// QUIC: the version a resumed ticket must have been issued in, the client's first
    /// (RFC 9369 section 5); 0 for TCP or a QUIC handshake not bound to a version.
    pub(crate) quic_accept_version: u32,
    /// QUIC: the version tickets are issued in, the negotiated one.
    pub(crate) quic_ticket_version: u32,
}

/// The parts of ClientHello1 that ClientHello2 must repeat: everything but the key shares,
/// cookie, early_data, pre_shared_key and padding.
#[derive(PartialEq, Eq)]
struct Ch1 {
    random: [u8; 32],
    session_id: Vec<u8>,
    suites: Vec<u16>,
    compression: Vec<u8>,
    exts: Vec<(u16, Vec<u8>)>,
}

impl Ch1 {
    fn of(ch: &ClientHello<'_>) -> Ch1 {
        Ch1 {
            random: ch.random,
            session_id: ch.session_id.to_vec(),
            suites: ch.suites.clone(),
            compression: ch.compression.to_vec(),
            exts: ch
                .exts
                .iter()
                .filter(|(t, _)| {
                    !matches!(
                        *t,
                        EXT_KEY_SHARE | EXT_COOKIE | EXT_EARLY_DATA | EXT_PRE_SHARED_KEY | 21
                    )
                })
                .map(|(t, d)| (*t, d.to_vec()))
                .collect(),
        }
    }
}

/// Lifetime hint of TLS 1.2 tickets and lifetime of cached TLS 1.2 sessions.
const LIFETIME12: u32 = 6 * 3600;

impl Server {
    /// `early_ctx`: QUIC with 0-RTT, see [`Server::early_ctx`].
    pub(crate) fn new(
        cfg: Arc<ServerSettings>,
        quic: Option<Vec<u8>>,
        early_ctx: Option<Vec<u8>>,
    ) -> Server {
        Server {
            cfg,
            quic,
            st: St::WaitClientHello,
            t: Transcript::default(),
            suite: None,
            version: 0,
            client_random: [0; 32],
            server_random: [0; 32],
            sni: None,
            alpn: None,
            cert: None,
            sched: None,
            c_hs: Vec::new(),
            c_ap: Vec::new(),
            s_ap: Vec::new(),
            hrr: None,
            ch1: None,
            ccs_sent: false,
            resumed: false,
            cert_requested: false,
            peer_chain: Vec::new(),
            peer_key: None,
            peer_quic: None,
            cert_compressed: None,
            ems: false,
            master: Vec::new(),
            share: None,
            session_id: Vec::new(),
            send_ticket12: false,
            record_limit12: None,
            staple12: false,
            early: EarlyData::NotAttempted,
            early_ctx,
            quic_accept_version: 0,
            quic_ticket_version: 0,
        }
    }

    /// The early data limit tickets carry and accepted early data is held to: QUIC 0-RTT
    /// uses 0xffffffff (RFC 9001 section 4.6.1), TCP the configured size; 0 when off.
    pub(crate) fn max_early_data(&self) -> u32 {
        match (&self.quic, &self.early_ctx) {
            (Some(_), Some(_)) => u32::MAX,
            (Some(_), None) => 0,
            (None, _) => self.cfg.max_early_data,
        }
    }

    /// Whether the early data of a ClientHello resuming `s` with PSK identity `index`
    /// (obfuscated age `age`, first binder `binder`) is accepted (RFC 8446 section 4.2.10):
    /// enabled here, the first identity, a ticket allowing it, the same suite, ALPN protocol,
    /// SNI name (checked with the ticket) and QUIC parameters, fresh and not a replay.
    fn accept_early(
        &self,
        suite: &'static Suite,
        s: &Session,
        index: usize,
        age: u32,
        binder: &[u8],
    ) -> bool {
        if self.max_early_data() == 0
            || index != 0
            || self.hrr.is_some()
            || s.max_early_data == 0
            || s.suite != suite.id
            || s.alpn != self.alpn
            || self.early_ctx.as_ref().is_some_and(|c| *c != s.early_ctx)
        {
            return false;
        }
        let now = now_millis();
        let ar = &self.cfg.anti_replay;
        ar.fresh(s.created * 1000, age.wrapping_sub(s.age_add), now) && ar.record(binder)
    }

    pub(crate) fn handshaking(&self) -> bool {
        !matches!(self.st, St::Done13 | St::Done12)
    }

    /// Whether a TLS 1.3 handshake is (or will be) used: known after the ClientHello.
    pub(crate) fn handle(&mut self, msg: &[u8], out: &mut Vec<Action>) -> Result<(), Fatal> {
        let typ = msg[0];
        let body = &msg[4..];
        match (self.st, typ) {
            (St::WaitClientHello | St::WaitClientHello2, CLIENT_HELLO) => {
                self.client_hello(msg, body, out)
            }
            (St::WaitEndOfEarlyData, END_OF_EARLY_DATA) => self.end_of_early_data(msg, body, out),
            (St::WaitCert13, CERTIFICATE) => self.certificate13(msg, body),
            // Offered in our CertificateRequest when compression is on (RFC 8879).
            (St::WaitCert13, COMPRESSED_CERTIFICATE) if !self.cfg.cert_compression.is_empty() => {
                let (plain, alg) =
                    decompress_certificate(body, MAX_HANDSHAKE, self.cfg.cert_compression)?;
                self.cert_compressed = Some(alg);
                self.certificate13(msg, &plain)
            }
            (St::WaitCertVerify13, CERTIFICATE_VERIFY) => self.certificate_verify13(msg, body),
            (St::WaitFinished13, FINISHED) => self.finished13(msg, body, out),
            (St::Done13, KEY_UPDATE) if self.quic.is_none() => {
                let suite = self.suite_or_err()?;
                key_update(suite, body, &mut self.c_ap, &mut self.s_ap, out)
            }
            (St::WaitCert12, CERTIFICATE) => self.certificate12(msg, body),
            (St::WaitClientKx12, CLIENT_KEY_EXCHANGE) => self.client_key_exchange(msg, body),
            (St::WaitCertVerify12, CERTIFICATE_VERIFY) => self.certificate_verify12(msg, body),
            (St::WaitFinished12, FINISHED) => self.finished12(msg, body, out),
            (St::Done12, CLIENT_HELLO) => {
                out.push(Action::Warning(Alert::NoRenegotiation));
                Ok(())
            }
            _ => fatal(Alert::UnexpectedMessage, "unexpected handshake message"),
        }
    }

    pub(crate) fn change_cipher_spec(&mut self, out: &mut Vec<Action>) -> Result<(), Fatal> {
        if self.st != St::WaitCcs12 {
            return fatal(Alert::UnexpectedMessage, "unexpected ChangeCipherSpec");
        }
        let suite = self.suite_or_err()?;
        let (c, _) = tls12::keys(
            suite,
            &self.master,
            &self.client_random,
            &self.server_random,
        );
        out.push(Action::ReadKeys(Level::Application, c));
        self.st = St::WaitFinished12;
        Ok(())
    }

    /// Sends a KeyUpdate and moves to the next write secret.
    pub(crate) fn initiate_key_update(&mut self, out: &mut Vec<Action>) -> Result<(), Fatal> {
        let suite = self.suite_or_err()?;
        send_key_update(suite, &mut self.s_ap, false, out);
        Ok(())
    }

    fn suite_or_err(&self) -> Result<&'static Suite, Fatal> {
        self.suite
            .ok_or_else(|| Fatal::new(Alert::InternalError, "no suite"))
    }

    fn pick_cert(&mut self, sni: Option<&String>) -> Arc<CertKey> {
        let c = sni
            .and_then(|n| self.cfg.sni.get(n))
            .unwrap_or(&self.cfg.cert)
            .clone();
        self.cert = Some(c.clone());
        c
    }

    fn pick_alpn(&mut self, offered: Option<&Vec<&[u8]>>) -> Result<(), Fatal> {
        if let Some(offered) = offered {
            if !self.cfg.alpn.is_empty() {
                match self
                    .cfg
                    .alpn
                    .iter()
                    .find(|p| offered.contains(&p.as_slice()))
                {
                    Some(p) => self.alpn = Some(p.clone()),
                    None => {
                        return fatal(Alert::NoApplicationProtocol, "no common ALPN protocol");
                    }
                }
            }
        }
        if self.quic.is_some() && self.alpn.is_none() {
            return fatal(Alert::NoApplicationProtocol, "QUIC needs ALPN");
        }
        Ok(())
    }

    fn client_hello(
        &mut self,
        msg: &[u8],
        body: &[u8],
        out: &mut Vec<Action>,
    ) -> Result<(), Fatal> {
        let ch = ClientHello::parse(body)?;
        if ch.legacy_version < 0x0301 {
            return fatal(
                Alert::ProtocolVersion,
                "ClientHello legacy_version below TLS 1.0",
            );
        }
        let tls13 = match &ch.versions {
            Some(v) if v.contains(&TLS13) && self.cfg.tls13 => true,
            Some(v) if v.contains(&TLS12) && self.cfg.tls12 => false,
            None if ch.legacy_version >= TLS12 && self.cfg.tls12 => false,
            _ => return fatal(Alert::ProtocolVersion, "no supported protocol version"),
        };
        if self.quic.is_some() && !tls13 {
            return fatal(Alert::ProtocolVersion, "QUIC needs TLS 1.3");
        }
        if self.st == St::WaitClientHello2 && !tls13 {
            return fatal(Alert::IllegalParameter, "second ClientHello is not TLS 1.3");
        }
        if !tls13 && ch.suites.contains(&FALLBACK_SCSV) {
            return fatal(
                Alert::InappropriateFallback,
                "client fell back from TLS 1.3",
            );
        }
        if tls13 {
            self.hello13(msg, &ch, out)
        } else {
            self.hello12(msg, &ch, out)
        }
    }

    // ---- TLS 1.3 ----

    fn hello13(
        &mut self,
        msg: &[u8],
        ch: &ClientHello<'_>,
        out: &mut Vec<Action>,
    ) -> Result<(), Fatal> {
        if ch.compression != [0] {
            return fatal(Alert::IllegalParameter, "TLS 1.3 forbids compression");
        }
        let suite = self
            .cfg
            .suites
            .iter()
            .copied()
            .find(|s| s.is_tls13() && ch.suites.contains(&s.id))
            .ok_or_else(|| Fatal::new(Alert::HandshakeFailure, "no common cipher suite"))?;
        if let Some((hs, _)) = self.hrr {
            if hs.id != suite.id {
                return fatal(
                    Alert::IllegalParameter,
                    "suite changed after HelloRetryRequest",
                );
            }
        }
        // No key_share at all (a psk_ke-only client): like an empty one, a retry may fix it.
        let no_shares = Vec::new();
        let shares = ch.key_shares.as_ref().unwrap_or(&no_shares);
        let client_groups = ch
            .groups
            .as_ref()
            .ok_or_else(|| Fatal::new(Alert::MissingExtension, "no supported_groups"))?;
        let skip_shares = self.cfg.force_hrr && self.hrr.is_none();
        let chosen = self.cfg.groups.iter().copied().find_map(|g| {
            shares
                .iter()
                .find(|(id, _)| *id == g.id())
                .map(|(_, k)| (g, *k))
                .filter(|_| !skip_shares)
        });
        let Some((group, client_share)) = chosen else {
            if self.hrr.is_some() {
                return fatal(Alert::IllegalParameter, "no usable key share after HRR");
            }
            // A group the client supports but sent no share for (a forced retry must ask for
            // something new).
            let g = self
                .cfg
                .groups
                .iter()
                .copied()
                .find(|g| {
                    client_groups.contains(&g.id()) && !shares.iter().any(|(id, _)| *id == g.id())
                })
                .ok_or_else(|| Fatal::new(Alert::HandshakeFailure, "no common group"))?;
            return self.hello_retry(msg, ch, suite, g, out);
        };
        if let Some((_, hg)) = self.hrr {
            if hg != group || shares.len() != 1 {
                return fatal(Alert::IllegalParameter, "wrong key share after HRR");
            }
            if ch.early_data || self.ch1.as_ref() != Some(&Ch1::of(ch)) {
                return fatal(Alert::IllegalParameter, "ClientHello changed after HRR");
            }
        }
        self.sni.clone_from(&ch.sni);
        let cert = self.pick_cert(ch.sni.as_ref());
        self.pick_alpn(ch.alpn.as_ref())?;
        if self.quic.is_some() {
            self.peer_quic = Some(
                ch.quic_params
                    .ok_or_else(|| {
                        Fatal::new(Alert::MissingExtension, "no QUIC transport parameters")
                    })?
                    .to_vec(),
            );
        }
        // PSK resumption.
        if ch.psk.is_some() && ch.psk_modes.is_none() {
            return fatal(
                Alert::MissingExtension,
                "pre_shared_key without psk_key_exchange_modes",
            );
        }
        let mut psk: Option<(usize, Session)> = None;
        let mut early = false;
        if let (Some(offer), true) = (&ch.psk, self.cfg.resumption()) {
            let dhe = ch.psk_modes.is_some_and(|m| m.contains(&PSK_DHE_KE));
            if dhe {
                let now = now_secs();
                for (i, (identity, age)) in offer.identities.iter().enumerate() {
                    let s = match (&self.cfg.ticketer, &self.cfg.cache) {
                        (Some(t), _) => t.open(identity),
                        (None, Some(c)) => c.take(identity),
                        _ => None,
                    };
                    let Some(s) = s else { continue };
                    let usable = s.version == TLS13
                        && !s.expired(now)
                        && suites::by_id(s.suite).is_some_and(|x| x.hash == suite.hash)
                        && s.sni == self.sni
                        && s.quic_version == self.quic_accept_version;
                    if !usable {
                        continue;
                    }
                    let truncated = &msg[..msg.len() - offer.binders_len];
                    let th = self.t.hash_with(suite.hash, truncated);
                    let bk = Schedule::early(suite.hash, Some(&s.secret)).binder_key(false);
                    let expect = finished_mac(suite.hash, &bk, &th);
                    if !ct_eq(&expect, offer.binders[i]) {
                        return fatal(Alert::DecryptError, "PSK binder does not verify");
                    }
                    early =
                        ch.early_data && self.accept_early(suite, &s, i, *age, offer.binders[i]);
                    psk = Some((i, s));
                    break;
                }
            }
        }
        let scheme =
            if psk.is_some() {
                None
            } else {
                let algs = ch.sig_algs.as_ref().ok_or_else(|| {
                    Fatal::new(Alert::MissingExtension, "no signature_algorithms")
                })?;
                Some(sig::choose(&cert.key, algs, true).ok_or_else(|| {
                    Fatal::new(Alert::HandshakeFailure, "no common signature scheme")
                })?)
            };
        if early {
            self.early = EarlyData::Accepted;
        } else if ch.early_data {
            self.early = EarlyData::Rejected;
            out.push(Action::RejectEarlyData);
        }
        self.suite = Some(suite);
        self.version = TLS13;
        self.client_random = ch.random;
        self.t.set_hash(suite.hash);
        self.t.add(msg);
        let share = group.generate()?;
        let shared = share.agree(client_share)?;
        self.server_random = random()?;
        let sh = message(SERVER_HELLO, |o| {
            put_u16(o, TLS12);
            o.extend_from_slice(&self.server_random);
            put_vec8(o, ch.session_id);
            put_u16(o, suite.id);
            o.push(0);
            put_vec(o, 2, |o| {
                ext(o, EXT_SUPPORTED_VERSIONS, |o| put_u16(o, TLS13));
                ext(o, EXT_KEY_SHARE, |o| {
                    put_u16(o, group.id());
                    put_vec16(o, &share.public());
                });
                if let Some((i, _)) = &psk {
                    ext(o, EXT_PRE_SHARED_KEY, |o| put_u16(o, *i as u16));
                }
            });
        });
        self.t.add(&sh);
        out.push(Action::Msg(Level::Initial, sh));
        if self.quic.is_none() && !ch.session_id.is_empty() && !self.ccs_sent {
            self.ccs_sent = true;
            out.push(Action::Ccs);
        }
        // record_size_limit (RFC 8449; not in QUIC): answered with ours, and the client's
        // applies to everything we protect from here on.
        let record_limit = ch.record_limit.filter(|_| self.quic.is_none()).map(|peer| {
            let ours = self.cfg.record_limit.min(MAX_RECORD_LIMIT13);
            out.push(Action::RecordLimit {
                read: ours,
                write: peer,
            });
            ours
        });
        let psk_secret = psk.as_ref().map(|(_, s)| s.secret.clone());
        let early_keys = match (&psk_secret, early) {
            (Some(p), true) => Some(Keys::Tls13 {
                suite,
                secret: Schedule::early(suite.hash, Some(p))
                    .derive(b"c e traffic", &suite.hash.digest(msg)),
            }),
            _ => None,
        };
        if let Some((_, s)) = psk {
            self.resumed = true;
            self.peer_chain = s.peer_chain;
        }
        let mut sched = Schedule::early(suite.hash, psk_secret.as_deref());
        sched.next(Some(&shared));
        let th = self.t.hash();
        self.c_hs = sched.derive(b"c hs traffic", &th);
        let s_hs = sched.derive(b"s hs traffic", &th);
        out.push(Action::WriteKeys(
            Level::Handshake,
            Keys::Tls13 {
                suite,
                secret: s_hs.clone(),
            },
        ));
        let hs_read = Keys::Tls13 {
            suite,
            secret: self.c_hs.clone(),
        };
        let mut wait_eoed = false;
        if let Some(k) = early_keys {
            out.push(Action::EarlyAccepted(self.max_early_data()));
            out.push(Action::ReadKeys(Level::EarlyData, k));
            // Over TCP the early data ends with EndOfEarlyData; QUIC has its own packets.
            if self.quic.is_none() {
                wait_eoed = true;
            } else {
                out.push(Action::ReadKeys(Level::Handshake, hs_read));
            }
        } else {
            out.push(Action::ReadKeys(Level::Handshake, hs_read));
        }
        let accepted = self.early == EarlyData::Accepted;
        let ee = message(ENCRYPTED_EXTENSIONS, |o| {
            put_vec(o, 2, |o| {
                if let Some(p) = &self.alpn {
                    ext(o, EXT_ALPN, |o| alpn_body(o, &[p]));
                }
                if self.sni.is_some() && !self.resumed {
                    ext(o, EXT_SERVER_NAME, |_| {});
                }
                if let Some(q) = &self.quic {
                    ext(o, EXT_QUIC_TRANSPORT_PARAMETERS, |o| o.extend_from_slice(q));
                }
                if accepted {
                    ext(o, EXT_EARLY_DATA, |_| {});
                }
                if let Some(l) = record_limit {
                    ext(o, EXT_RECORD_SIZE_LIMIT, |o| put_u16(o, l));
                }
            });
        });
        self.t.add(&ee);
        out.push(Action::Msg(Level::Handshake, ee));
        if let Some(scheme) = scheme {
            if self.cfg.client_auth.is_some() {
                let cr = message(CERTIFICATE_REQUEST, |o| {
                    put_vec8(o, &[]);
                    put_vec(o, 2, |o| {
                        ext(o, EXT_SIGNATURE_ALGORITHMS, |o| {
                            sig_algs_body(o, sig::SUPPORTED);
                        });
                        let algs = self.cfg.cert_compression;
                        if !algs.is_empty() {
                            ext(o, EXT_COMPRESS_CERTIFICATE, |o| cert_comp_body(o, algs));
                        }
                    });
                });
                self.t.add(&cr);
                out.push(Action::Msg(Level::Handshake, cr));
                self.cert_requested = true;
            }
            // OCSP stapled to the leaf when asked for; compressed with the algorithm, of those
            // both sides take, that makes it smallest.
            let algs = ch
                .cert_comp
                .as_deref()
                .map_or(CompAlgs::NONE, CompAlgs::from_ids)
                .and(self.cfg.cert_compression);
            let c = cert.certificate13(&[], ch.status_request, algs);
            self.t.add(&c);
            out.push(Action::Msg(Level::Handshake, c));
            let content = sig::tls13_content(true, &self.t.hash());
            let s = sig::sign(&cert.key, scheme, &content)?;
            let cv = certificate_verify(scheme, &s);
            self.t.add(&cv);
            out.push(Action::Msg(Level::Handshake, cv));
        }
        let fin = finished_mac(suite.hash, &s_hs, &self.t.hash());
        let f = message(FINISHED, |o| o.extend_from_slice(&fin));
        self.t.add(&f);
        out.push(Action::Msg(Level::Handshake, f));
        let th = self.t.hash();
        sched.next(None);
        self.c_ap = sched.derive(b"c ap traffic", &th);
        self.s_ap = sched.derive(b"s ap traffic", &th);
        self.sched = Some(sched);
        out.push(Action::WriteKeys(
            Level::Application,
            Keys::Tls13 {
                suite,
                secret: self.s_ap.clone(),
            },
        ));
        self.st = if wait_eoed {
            St::WaitEndOfEarlyData
        } else if self.cert_requested {
            St::WaitCert13
        } else {
            St::WaitFinished13
        };
        Ok(())
    }

    /// EndOfEarlyData (TCP): the client's handshake keys follow.
    fn end_of_early_data(
        &mut self,
        msg: &[u8],
        body: &[u8],
        out: &mut Vec<Action>,
    ) -> Result<(), Fatal> {
        if !body.is_empty() {
            return fatal(Alert::DecodeError, "EndOfEarlyData with a body");
        }
        let suite = self.suite_or_err()?;
        self.t.add(msg);
        out.push(Action::ReadKeys(
            Level::Handshake,
            Keys::Tls13 {
                suite,
                secret: self.c_hs.clone(),
            },
        ));
        self.st = if self.cert_requested {
            St::WaitCert13
        } else {
            St::WaitFinished13
        };
        Ok(())
    }

    fn hello_retry(
        &mut self,
        msg: &[u8],
        ch: &ClientHello<'_>,
        suite: &'static Suite,
        group: Group,
        out: &mut Vec<Action>,
    ) -> Result<(), Fatal> {
        let hrr = message(SERVER_HELLO, |o| {
            put_u16(o, TLS12);
            o.extend_from_slice(&HRR_RANDOM);
            put_vec8(o, ch.session_id);
            put_u16(o, suite.id);
            o.push(0);
            put_vec(o, 2, |o| {
                ext(o, EXT_SUPPORTED_VERSIONS, |o| put_u16(o, TLS13));
                ext(o, EXT_KEY_SHARE, |o| put_u16(o, group.id()));
            });
        });
        self.t.add(msg);
        self.t.rollup_for_hrr(suite.hash);
        self.t.add(&hrr);
        out.push(Action::Msg(Level::Initial, hrr));
        if self.quic.is_none() && !ch.session_id.is_empty() {
            self.ccs_sent = true;
            out.push(Action::Ccs);
        }
        if ch.early_data {
            self.early = EarlyData::Rejected;
            out.push(Action::RejectEarlyData);
        }
        self.hrr = Some((suite, group));
        self.ch1 = Some(Ch1::of(ch));
        self.version = TLS13;
        self.st = St::WaitClientHello2;
        Ok(())
    }

    /// A client Certificate (`body`; decompressed when `msg` is a CompressedCertificate, which
    /// is what the transcript takes).
    fn certificate13(&mut self, msg: &[u8], body: &[u8]) -> Result<(), Fatal> {
        let Certificate13 {
            context: ctx,
            chain,
            ..
        } = parse_certificate13(body)?;
        if !ctx.is_empty() {
            return fatal(Alert::IllegalParameter, "certificate context mismatch");
        }
        self.t.add(msg);
        if chain.is_empty() {
            if self.cfg.client_auth.as_ref().is_some_and(|c| c.1) {
                return fatal(Alert::CertificateRequired, "client certificate required");
            }
            self.st = St::WaitFinished13;
            return Ok(());
        }
        self.client_chain(chain)?;
        self.st = St::WaitCertVerify13;
        Ok(())
    }

    fn client_chain(&mut self, chain: Vec<Vec<u8>>) -> Result<(), Fatal> {
        let roots = self
            .cfg
            .client_auth
            .as_ref()
            .map(|c| c.0.clone())
            .ok_or_else(|| Fatal::new(Alert::InternalError, "no client roots"))?;
        self.peer_key =
            Some(verify_chain(&roots, &chain, None, self.cfg.client_crls.as_ref())?.key);
        self.peer_chain = chain;
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
        let content = sig::tls13_content(false, &self.t.hash());
        sig::verify(key, scheme, &content, signature, true)?;
        self.t.add(msg);
        self.st = St::WaitFinished13;
        Ok(())
    }

    fn finished13(&mut self, msg: &[u8], body: &[u8], out: &mut Vec<Action>) -> Result<(), Fatal> {
        let suite = self.suite_or_err()?;
        let expect = finished_mac(suite.hash, &self.c_hs, &self.t.hash());
        if body.len() != expect.len() {
            return fatal(Alert::DecodeError, "Finished of the wrong length");
        }
        if !ct_eq(&expect, body) {
            return fatal(Alert::DecryptError, "client Finished does not verify");
        }
        self.t.add(msg);
        out.push(Action::ReadKeys(
            Level::Application,
            Keys::Tls13 {
                suite,
                secret: self.c_ap.clone(),
            },
        ));
        let th = self.t.hash();
        let res_master = self
            .sched
            .as_ref()
            .map(|s| s.derive(b"res master", &th))
            .unwrap_or_default();
        let max_early_data = self.max_early_data();
        if self.cfg.resumption() {
            for i in 0..self.cfg.tickets13 {
                let nonce = [i as u8];
                let psk =
                    suite
                        .hash
                        .expand_label(&res_master, b"resumption", &nonce, suite.hash.len());
                let age_add = u32::from_be_bytes(random::<4>()?);
                let session = Session {
                    version: TLS13,
                    suite: suite.id,
                    secret: psk,
                    created: now_secs(),
                    lifetime: self.cfg.ticket_lifetime,
                    age_add,
                    alpn: self.alpn.clone(),
                    sni: self.sni.clone(),
                    ems: false,
                    peer_chain: self.peer_chain.clone(),
                    max_early_data,
                    early_ctx: self.early_ctx.clone().unwrap_or_default(),
                    quic_version: self.quic_ticket_version,
                };
                let ticket = match (&self.cfg.ticketer, &self.cfg.cache) {
                    (Some(t), _) => t.seal(&session),
                    (None, Some(c)) => {
                        let id = random::<32>()?.to_vec();
                        c.put(id.clone(), session);
                        Some(id)
                    }
                    _ => None,
                };
                let Some(ticket) = ticket else { continue };
                let nst = message(NEW_SESSION_TICKET, |o| {
                    put_u32(o, self.cfg.ticket_lifetime);
                    put_u32(o, age_add);
                    put_vec8(o, &nonce);
                    put_vec16(o, &ticket);
                    put_vec(o, 2, |o| {
                        if max_early_data > 0 {
                            ext(o, EXT_EARLY_DATA, |o| put_u32(o, max_early_data));
                        }
                    });
                });
                out.push(Action::Msg(Level::Application, nst));
            }
        }
        self.st = St::Done13;
        self.t = Transcript::default();
        out.push(Action::Done);
        Ok(())
    }

    // ---- TLS 1.2 ----

    fn hello12(
        &mut self,
        msg: &[u8],
        ch: &ClientHello<'_>,
        out: &mut Vec<Action>,
    ) -> Result<(), Fatal> {
        if !ch.compression.contains(&0) {
            return fatal(Alert::IllegalParameter, "no null compression");
        }
        if let Some(ri) = ch.reneg_info {
            if !ri.is_empty() {
                return fatal(Alert::HandshakeFailure, "non-empty renegotiation_info");
            }
        }
        let secure_reneg =
            ch.reneg_info.is_some() || ch.suites.contains(&EMPTY_RENEGOTIATION_INFO_SCSV);
        if let Some(f) = ch.ec_point_formats {
            if !f.contains(&0) {
                return fatal(Alert::IllegalParameter, "no uncompressed point format");
            }
        }
        self.ems = ch.ems;
        self.client_random = ch.random;
        self.sni.clone_from(&ch.sni);
        if let Some(peer) = ch.record_limit {
            // record_size_limit (RFC 8449): protected records only, after the CCS.
            let ours = self.cfg.record_limit.min(MAX_RECORD_LIMIT12);
            self.record_limit12 = Some(ours);
            out.push(Action::RecordLimit {
                read: ours,
                write: peer,
            });
        }
        let cert = self.pick_cert(ch.sni.as_ref());
        let auth = if sig::is_rsa(&cert.key) {
            Auth12::Rsa
        } else {
            Auth12::Ecdsa
        };
        self.pick_alpn(ch.alpn.as_ref())?;
        let mut sr = random::<32>()?;
        if self.cfg.suites.iter().any(|s| s.is_tls13()) {
            sr[24..].copy_from_slice(&DOWNGRADE_TLS12);
        }
        self.server_random = sr;
        self.version = TLS12;

        // Resumption by ticket or session id.
        let now = now_secs();
        let resumed = match (ch.session_ticket, &self.cfg.ticketer) {
            (Some(tk), Some(t)) if !tk.is_empty() => t.open(tk),
            _ => None,
        }
        .or_else(|| match &self.cfg.cache {
            Some(c) if !ch.session_id.is_empty() => c.get(ch.session_id),
            _ => None,
        })
        .filter(|s| {
            s.version == TLS12
                && !s.expired(now)
                && s.ems
                && self.ems
                && ch.suites.contains(&s.suite)
                && s.sni == self.sni
                && suites::by_id(s.suite).is_some_and(|x| x.tls12.is_some())
        });
        if let Some(s) = resumed {
            let suite = suites::by_id(s.suite)
                .ok_or_else(|| Fatal::new(Alert::InternalError, "session suite"))?;
            self.suite = Some(suite);
            self.master = s.secret;
            self.peer_chain = s.peer_chain;
            self.resumed = true;
            self.session_id = ch.session_id.to_vec();
            self.t.set_hash(suite.hash);
            self.t.add(msg);
            let sh = self.server_hello12(suite, secure_reneg, ch.ec_point_formats.is_some());
            self.t.add(&sh);
            out.push(Action::Msg(Level::Initial, sh));
            let (_, s) = tls12::keys(
                suite,
                &self.master,
                &self.client_random,
                &self.server_random,
            );
            out.push(Action::Ccs);
            out.push(Action::WriteKeys(Level::Application, s));
            let vd = suite
                .hash
                .prf(&self.master, b"server finished", &self.t.hash(), 12);
            let f = message(FINISHED, |o| o.extend_from_slice(&vd));
            self.t.add(&f);
            out.push(Action::Msg(Level::Application, f));
            self.st = St::WaitCcs12;
            return Ok(());
        }

        let suite = self
            .cfg
            .suites
            .iter()
            .copied()
            .find(|s| s.tls12 == Some(auth) && ch.suites.contains(&s.id))
            .ok_or_else(|| Fatal::new(Alert::HandshakeFailure, "no common cipher suite"))?;
        let default_groups = [Group::Secp256r1.id()];
        let client_groups = ch.groups.as_deref().unwrap_or(&default_groups);
        let group = self
            .cfg
            .groups
            .iter()
            .copied()
            .find(|g| client_groups.contains(&g.id()))
            .ok_or_else(|| Fatal::new(Alert::HandshakeFailure, "no common group"))?;
        let default_algs = [
            sig::PKCS1_SHA256,
            sig::ECDSA_P256_SHA256,
            sig::ECDSA_P384_SHA384,
        ];
        let algs = ch.sig_algs.as_deref().unwrap_or(&default_algs);
        let scheme = sig::choose(&cert.key, algs, false)
            .ok_or_else(|| Fatal::new(Alert::HandshakeFailure, "no common signature scheme"))?;
        self.suite = Some(suite);
        self.staple12 = ch.status_request && cert.ocsp.is_some();
        self.send_ticket12 = ch.session_ticket.is_some() && self.cfg.ticketer.is_some();
        self.session_id = if self.cfg.cache.is_some() && !self.send_ticket12 {
            random::<32>()?.to_vec()
        } else {
            Vec::new()
        };
        self.t.set_hash(suite.hash);
        self.t.add(msg);
        let sh = self.server_hello12(suite, secure_reneg, ch.ec_point_formats.is_some());
        self.t.add(&sh);
        out.push(Action::Msg(Level::Initial, sh));
        let c = certificate12(&cert.chain);
        self.t.add(&c);
        out.push(Action::Msg(Level::Initial, c));
        if let (true, Some(r)) = (self.staple12, &cert.ocsp) {
            let cs = message(CERTIFICATE_STATUS, |o| certificate_status_body(o, r));
            self.t.add(&cs);
            out.push(Action::Msg(Level::Initial, cs));
        }
        let share = group.generate()?;
        let mut params = vec![3u8];
        params.extend_from_slice(&group.id().to_be_bytes());
        put_vec8(&mut params, &share.public());
        let mut signed = Vec::with_capacity(64 + params.len());
        signed.extend_from_slice(&self.client_random);
        signed.extend_from_slice(&self.server_random);
        signed.extend_from_slice(&params);
        let s = sig::sign(&cert.key, scheme, &signed)?;
        let ske = message(SERVER_KEY_EXCHANGE, |o| {
            o.extend_from_slice(&params);
            put_u16(o, scheme);
            put_vec16(o, &s);
        });
        self.t.add(&ske);
        out.push(Action::Msg(Level::Initial, ske));
        self.share = Some(share);
        if self.cfg.client_auth.is_some() {
            let cr = message(CERTIFICATE_REQUEST, |o| {
                put_vec8(o, &[1, 64]);
                sig_algs_body(o, sig::SUPPORTED);
                put_u16(o, 0);
            });
            self.t.add(&cr);
            out.push(Action::Msg(Level::Initial, cr));
            self.cert_requested = true;
        }
        let shd = message(SERVER_HELLO_DONE, |_| {});
        self.t.add(&shd);
        out.push(Action::Msg(Level::Initial, shd));
        self.st = if self.cert_requested {
            St::WaitCert12
        } else {
            St::WaitClientKx12
        };
        Ok(())
    }

    fn server_hello12(&self, suite: &Suite, secure_reneg: bool, point_formats: bool) -> Vec<u8> {
        message(SERVER_HELLO, |o| {
            put_u16(o, TLS12);
            o.extend_from_slice(&self.server_random);
            put_vec8(o, &self.session_id);
            put_u16(o, suite.id);
            o.push(0);
            put_vec(o, 2, |o| {
                if secure_reneg {
                    ext(o, EXT_RENEGOTIATION_INFO, |o| put_vec8(o, &[]));
                }
                if self.ems {
                    ext(o, EXT_EXTENDED_MASTER_SECRET, |_| {});
                }
                if point_formats && !self.resumed {
                    ext(o, EXT_EC_POINT_FORMATS, |o| put_vec8(o, &[0]));
                }
                if let Some(p) = &self.alpn {
                    ext(o, EXT_ALPN, |o| alpn_body(o, &[p]));
                }
                if self.send_ticket12 && !self.resumed {
                    ext(o, EXT_SESSION_TICKET, |_| {});
                }
                if self.staple12 && !self.resumed {
                    ext(o, EXT_STATUS_REQUEST, |_| {});
                }
                if let Some(l) = self.record_limit12 {
                    ext(o, EXT_RECORD_SIZE_LIMIT, |o| put_u16(o, l));
                }
            });
        })
    }

    fn certificate12(&mut self, msg: &[u8], body: &[u8]) -> Result<(), Fatal> {
        let chain = parse_certificate12(body)?;
        self.t.add(msg);
        if chain.is_empty() {
            if self.cfg.client_auth.as_ref().is_some_and(|c| c.1) {
                return fatal(Alert::HandshakeFailure, "client certificate required");
            }
        } else {
            self.client_chain(chain)?;
        }
        self.st = St::WaitClientKx12;
        Ok(())
    }

    fn client_key_exchange(&mut self, msg: &[u8], body: &[u8]) -> Result<(), Fatal> {
        let suite = self.suite_or_err()?;
        let mut r = Reader::new(body);
        let point = r.vec8()?;
        r.finish()?;
        let share = self
            .share
            .take()
            .ok_or_else(|| Fatal::new(Alert::InternalError, "no key share"))?;
        let pms = share.agree(point)?;
        self.t.add(msg);
        self.master = tls12::master_secret(
            suite,
            &pms,
            self.ems,
            &self.t.hash(),
            &self.client_random,
            &self.server_random,
        );
        self.st = if self.peer_key.is_some() {
            St::WaitCertVerify12
        } else {
            St::WaitCcs12
        };
        Ok(())
    }

    fn certificate_verify12(&mut self, msg: &[u8], body: &[u8]) -> Result<(), Fatal> {
        let mut r = Reader::new(body);
        let (scheme, signature) = parse_signature(&mut r)?;
        r.finish()?;
        let key = self
            .peer_key
            .as_ref()
            .ok_or_else(|| Fatal::new(Alert::InternalError, "no peer key"))?;
        sig::verify(key, scheme, self.t.raw(), signature, false)?;
        self.t.add(msg);
        self.st = St::WaitCcs12;
        Ok(())
    }

    fn finished12(&mut self, msg: &[u8], body: &[u8], out: &mut Vec<Action>) -> Result<(), Fatal> {
        let suite = self.suite_or_err()?;
        let expect = suite
            .hash
            .prf(&self.master, b"client finished", &self.t.hash(), 12);
        if body.len() != expect.len() {
            return fatal(Alert::DecodeError, "Finished of the wrong length");
        }
        if !ct_eq(&expect, body) {
            return fatal(Alert::DecryptError, "client Finished does not verify");
        }
        self.t.add(msg);
        if !self.resumed {
            let session = Session {
                version: TLS12,
                suite: suite.id,
                secret: self.master.clone(),
                created: now_secs(),
                lifetime: LIFETIME12,
                age_add: 0,
                alpn: self.alpn.clone(),
                sni: self.sni.clone(),
                ems: self.ems,
                peer_chain: self.peer_chain.clone(),
                max_early_data: 0,
                early_ctx: Vec::new(),
                quic_version: 0,
            };
            if self.send_ticket12 {
                let ticket = self
                    .cfg
                    .ticketer
                    .as_ref()
                    .and_then(|t| t.seal(&session))
                    .unwrap_or_default();
                let nst = message(NEW_SESSION_TICKET, |o| {
                    put_u32(o, LIFETIME12);
                    put_vec16(o, &ticket);
                });
                self.t.add(&nst);
                out.push(Action::Msg(Level::Initial, nst));
            }
            if let Some(c) = &self.cfg.cache {
                if !self.session_id.is_empty() && self.ems {
                    c.put(self.session_id.clone(), session);
                }
            }
            let (_, s) = tls12::keys(
                suite,
                &self.master,
                &self.client_random,
                &self.server_random,
            );
            out.push(Action::Ccs);
            out.push(Action::WriteKeys(Level::Application, s));
            let vd = suite
                .hash
                .prf(&self.master, b"server finished", &self.t.hash(), 12);
            let f = message(FINISHED, |o| o.extend_from_slice(&vd));
            out.push(Action::Msg(Level::Application, f));
        }
        self.st = St::Done12;
        self.t = Transcript::default();
        out.push(Action::Done);
        Ok(())
    }
}
