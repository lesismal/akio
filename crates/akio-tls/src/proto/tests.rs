//! Protocol tests: RFC 8448 trace vectors, in-memory handshakes between the client and server
//! machines over every suite / group / key type / version, resumption, client authentication,
//! HelloRetryRequest, KeyUpdate, fragmentation, and negative cases.

use akio_crypto::pkey;

use super::alert::{Alert, Fatal};
use super::codec::Reader;
use super::common::{Keys, Schedule, Transcript, finished_mac};
use super::conn::Connection;
use super::msgs::{self, ClientHello, ServerHello};
use super::record::{CT_ALERT, CT_APPLICATION_DATA, CT_HANDSHAKE, RecordLayer};
use super::rfc8448 as v;
use super::suites::{self, HashAlg};
use crate::{
    Certificate, ClientConfig, ClientConfigBuilder, PrivateKey, RootCerts, ServerConfig,
    ServerConfigBuilder,
};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ---- RFC 8448 ----

#[test]
fn rfc8448_simple_key_schedule() {
    let h = HashAlg::Sha256;
    let c_priv: [u8; 32] = unhex(v::S_C_PRIV).try_into().unwrap();
    let s_pub: [u8; 32] = unhex(v::S_S_PUB).try_into().unwrap();
    let shared = akio_crypto::x25519::x25519(&c_priv, &s_pub);
    assert_eq!(shared.to_vec(), unhex(v::S_ECDHE));

    let mut sched = Schedule::early(h, None);
    assert_eq!(sched.current, unhex(v::S_EARLY));
    sched.next(Some(&shared));
    assert_eq!(sched.current, unhex(v::S_HS_SECRET));
    let mut t = Transcript::default();
    t.add(&unhex(v::S_CH));
    t.set_hash(h);
    t.add(&unhex(v::S_SH));
    let c_hs = sched.derive(b"c hs traffic", &t.hash());
    let s_hs = sched.derive(b"s hs traffic", &t.hash());
    assert_eq!(c_hs, unhex(v::S_C_HS));
    assert_eq!(s_hs, unhex(v::S_S_HS));
    assert_eq!(h.expand_label(&s_hs, b"key", &[], 16), unhex(v::S_S_HS_KEY));
    assert_eq!(h.expand_label(&s_hs, b"iv", &[], 12), unhex(v::S_S_HS_IV));
    for m in [v::S_EE, v::S_CERT, v::S_CV] {
        t.add(&unhex(m));
    }
    let sfin = unhex(v::S_S_FIN);
    assert_eq!(finished_mac(h, &s_hs, &t.hash()), sfin[4..]);
    t.add(&sfin);
    sched.next(None);
    assert_eq!(sched.current, unhex(v::S_MASTER));
    assert_eq!(sched.derive(b"c ap traffic", &t.hash()), unhex(v::S_C_AP));
    assert_eq!(sched.derive(b"s ap traffic", &t.hash()), unhex(v::S_S_AP));
    assert_eq!(sched.derive(b"exp master", &t.hash()), unhex(v::S_EXP));
    let cfin = unhex(v::S_C_FIN);
    assert_eq!(finished_mac(h, &c_hs, &t.hash()), cfin[4..]);
    t.add(&cfin);
    let res = sched.derive(b"res master", &t.hash());
    assert_eq!(res, unhex(v::S_RES_MASTER));
    // The NewSessionTicket carries nonce 00 00.
    let nst = unhex(v::S_NST);
    let mut r = Reader::new(&nst[4..]);
    let _lifetime = r.u32().unwrap();
    let _age_add = r.u32().unwrap();
    let nonce = r.vec8().unwrap();
    assert_eq!(nonce, [0, 0]);
    assert_eq!(
        h.expand_label(&res, b"resumption", nonce, 32),
        unhex(v::S_PSK)
    );
}

#[test]
fn rfc8448_simple_records() {
    let s = &suites::TLS13_AES_128_GCM_SHA256;
    let keys = |hex: &str| Keys::Tls13 {
        suite: s,
        secret: unhex(hex),
    };
    // The server's encrypted flight, byte for byte.
    let mut w = RecordLayer::new();
    w.set_write(&keys(v::S_S_HS));
    let mut out = Vec::new();
    w.seal(CT_HANDSHAKE, &unhex(v::S_S_FLIGHT), &mut out)
        .unwrap();
    assert_eq!(out, unhex(v::S_S_FLIGHT_REC));
    // The client's Finished, decrypted.
    let mut r = RecordLayer::new();
    r.set_read(&keys(v::S_C_HS));
    let mut rec = unhex(v::S_C_FIN_REC);
    let o = r.open(&mut rec).unwrap();
    assert_eq!(
        (o.typ, &rec[o.start..o.end]),
        (CT_HANDSHAKE, &unhex(v::S_C_FIN)[..])
    );
    // Server application keys: the ticket, then data.
    let mut r = RecordLayer::new();
    r.set_read(&keys(v::S_S_AP));
    let mut rec = unhex(v::S_NST_REC);
    let o = r.open(&mut rec).unwrap();
    assert_eq!(&rec[o.start..o.end], &unhex(v::S_NST)[..]);
    let mut rec = unhex(v::S_S_DATA_REC);
    let o = r.open(&mut rec).unwrap();
    assert_eq!(
        (o.typ, &rec[o.start..o.end]),
        (CT_APPLICATION_DATA, &unhex(v::S_C_DATA)[..])
    );
    // Client application keys: data, then close_notify, matching the trace when sealed.
    let mut w = RecordLayer::new();
    w.set_write(&keys(v::S_C_AP));
    let mut out = Vec::new();
    w.seal(CT_APPLICATION_DATA, &unhex(v::S_C_DATA), &mut out)
        .unwrap();
    assert_eq!(out, unhex(v::S_C_DATA_REC));
    let mut out = Vec::new();
    w.seal(CT_ALERT, &[1, 0], &mut out).unwrap();
    assert_eq!(out, unhex(v::S_C_ALERT_REC));
}

#[test]
fn rfc8448_messages_parse() {
    let ch_raw = unhex(v::S_CH);
    let ch = ClientHello::parse(&ch_raw[4..]).unwrap();
    assert_eq!(ch.sni.as_deref(), Some("server"));
    assert_eq!(ch.suites, vec![0x1301, 0x1303, 0x1302]);
    assert_eq!(ch.versions, Some(vec![0x0304]));
    assert_eq!(ch.key_shares.as_ref().unwrap()[0].0, 0x001d);
    let sh_raw = unhex(v::S_SH);
    let sh = ServerHello::parse(&sh_raw[4..]).unwrap();
    assert_eq!((sh.suite, sh.version), (0x1301, Some(0x0304)));
    let msgs::Certificate13 {
        context: ctx,
        chain,
        ..
    } = msgs::parse_certificate13(&unhex(v::S_CERT)[4..], false).unwrap();
    assert!(ctx.is_empty());
    assert_eq!(chain.len(), 1);
    let hrr_raw = unhex(v::H_HRR);
    let hrr = ServerHello::parse(&hrr_raw[4..]).unwrap();
    assert_eq!(hrr.random, msgs::HRR_RANDOM);
    assert_eq!(hrr.key_share.map(|k| k.0), Some(0x0017));
    assert!(hrr.cookie.is_some());
    let ch2_raw = unhex(v::H_CH2);
    let ch2 = ClientHello::parse(&ch2_raw[4..]).unwrap();
    assert_eq!(ch2.cookie, hrr.cookie);
}

#[test]
fn rfc8448_resumption_binder() {
    let h = HashAlg::Sha256;
    let psk = unhex(v::S_PSK);
    let sched = Schedule::early(h, Some(&psk));
    assert_eq!(sched.current, unhex(v::R_EARLY));
    let ch_raw = unhex(v::R_CH);
    let ch = ClientHello::parse(&ch_raw[4..]).unwrap();
    let offer = ch.psk.clone().unwrap();
    assert_eq!(offer.binders_len, 2 + 1 + 32);
    assert!(ch.early_data);
    let truncated = &ch_raw[..ch_raw.len() - offer.binders_len];
    let th = h.digest(truncated);
    assert_eq!(th, unhex(v::R_BINDER_HASH));
    let binder = finished_mac(h, &sched.binder_key(false), &th);
    assert_eq!(binder, unhex(v::R_BINDER));
    assert_eq!(offer.binders[0], &binder[..]);
    // The early traffic secret over the whole ClientHello.
    assert_eq!(
        sched.derive(b"c e traffic", &h.digest(&ch_raw)),
        unhex(v::R_C_E)
    );
}

#[test]
fn rfc8448_hello_retry_request_transcript() {
    let h = HashAlg::Sha256;
    let c_priv = akio_crypto::p256::SecretKey::from_bytes(&unhex(v::H_C_PRIV)).unwrap();
    let s_pub = akio_crypto::p256::PublicKey::from_sec1(&unhex(v::H_S_PUB)).unwrap();
    let shared = c_priv.diffie_hellman(&s_pub);
    assert_eq!(shared.to_vec(), unhex(v::H_ECDHE));
    let mut t = Transcript::default();
    t.add(&unhex(v::H_CH1));
    t.rollup_for_hrr(h);
    for m in [v::H_HRR, v::H_CH2, v::H_SH] {
        t.add(&unhex(m));
    }
    let mut sched = Schedule::early(h, None);
    sched.next(Some(&shared));
    let c_hs = sched.derive(b"c hs traffic", &t.hash());
    let s_hs = sched.derive(b"s hs traffic", &t.hash());
    assert_eq!(c_hs, unhex(v::H_C_HS));
    assert_eq!(s_hs, unhex(v::H_S_HS));
    for m in [v::H_EE, v::H_CERT, v::H_CV] {
        t.add(&unhex(m));
    }
    let sfin = unhex(v::H_S_FIN);
    assert_eq!(finished_mac(h, &s_hs, &t.hash()), sfin[4..]);
    t.add(&sfin);
    sched.next(None);
    assert_eq!(sched.derive(b"c ap traffic", &t.hash()), unhex(v::H_C_AP));
    assert_eq!(sched.derive(b"s ap traffic", &t.hash()), unhex(v::H_S_AP));
}

#[test]
fn rfc8448_client_hello_drives_our_server() {
    // The trace's ClientHello (x25519, suites 1301/1303/1302, SNI "server", record_size_limit)
    // gets a TLS 1.3 ServerHello for x25519 / TLS_AES_128_GCM_SHA256 from our server.
    let p = pki(Kind::P256, &["server"]);
    let cfg = ServerConfig::builder(p.chain.clone(), p.key)
        .build()
        .unwrap();
    let mut s = crate::__proto::server(&cfg);
    let ch = unhex(v::S_CH);
    let mut rec = vec![22, 3, 1];
    rec.extend_from_slice(&(ch.len() as u16).to_be_bytes());
    rec.extend_from_slice(&ch);
    let (mut plain, mut out) = (Vec::new(), Vec::new());
    s.recv(&rec, &mut plain, &mut out).unwrap();
    assert_eq!(out[..3], [22, 3, 3], "a server's records carry 0x0303");
    let n = RecordLayer::frame(&out).unwrap().unwrap();
    let sh = ServerHello::parse(&out[9..n]).unwrap();
    assert_eq!((sh.suite, sh.version), (0x1301, Some(0x0304)));
    assert_eq!(sh.key_share.unwrap().0, 0x001d);
    // Everything after the ServerHello is protected.
    assert_eq!(out[n], 23);
    assert_eq!(s.server_name(), Some("server"));
}

// ---- in-memory handshakes ----

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    P256,
    P384,
    P521,
    Ed25519,
    Ed448,
    Rsa,
    /// The RSA test key as `id-RSASSA-PSS`, restricted to SHA-256 (rsa_pss_pss_sha256).
    RsaPss,
}

pub(crate) struct Pki {
    pub(crate) chain: Vec<Certificate>,
    pub(crate) key: PrivateKey,
    pub(crate) roots: RootCerts,
}

pub(crate) fn private_key(kind: Kind) -> pkey::PrivateKey {
    match kind {
        Kind::P256 => pkey::PrivateKey::P256(akio_crypto::p256::SecretKey::generate().unwrap()),
        Kind::P384 => pkey::PrivateKey::P384(akio_crypto::p384::SecretKey::generate().unwrap()),
        Kind::Ed25519 => {
            pkey::PrivateKey::Ed25519(akio_crypto::ed25519::SigningKey::generate().unwrap())
        }
        Kind::Ed448 => pkey::PrivateKey::Ed448(akio_crypto::ed448::SigningKey::generate().unwrap()),
        Kind::P521 => pkey::PrivateKey::P521(akio_crypto::p521::SecretKey::generate().unwrap()),
        Kind::Rsa => pkey::PrivateKey::from_pem(include_bytes!("../testdata/rsa2048.pem")).unwrap(),
        Kind::RsaPss => match private_key(Kind::Rsa) {
            pkey::PrivateKey::Rsa(k) => pkey::PrivateKey::RsaPss(
                k,
                Some(pkey::PssParams::new(akio_crypto::rsa::HashAlg::Sha256, 32)),
            ),
            _ => unreachable!(),
        },
    }
}

pub(crate) fn pki(kind: Kind, names: &[&str]) -> Pki {
    let key = private_key(kind);
    let cert = akio_x509::CertificateParams::new(names.iter().copied())
        .self_signed(&key)
        .unwrap();
    let c = Certificate::from_der(cert.as_der().to_vec());
    let mut roots = RootCerts::empty();
    roots.add(&c).unwrap();
    Pki {
        chain: vec![c],
        key: PrivateKey::from_pkcs8_der(key.to_pkcs8_der()),
        roots,
    }
}

pub(crate) fn server(p: &Pki) -> ServerConfigBuilder {
    ServerConfig::builder(p.chain.clone(), p.key.clone())
}

pub(crate) fn client(p: &Pki) -> ClientConfigBuilder {
    ClientConfig::builder().roots(p.roots.clone())
}

/// Which side failed.
#[derive(Debug)]
pub(crate) enum Side {
    Client(Fatal),
    Server(Fatal),
}

impl Side {
    fn alert(&self) -> Alert {
        match self {
            Side::Client(f) | Side::Server(f) => f.alert,
        }
    }
}

/// Shuttles bytes between the two until both are idle; `chunk` limits each delivery.
pub(crate) fn shuttle(c: &mut Connection, s: &mut Connection, chunk: usize) -> Result<(), Side> {
    let (mut c2s, mut s2c) = (Vec::new(), Vec::new());
    let mut plain = Vec::new();
    c.recv(&[], &mut plain, &mut c2s).map_err(Side::Client)?;
    for _ in 0..100_000 {
        if c2s.is_empty() && s2c.is_empty() {
            break;
        }
        let n = c2s.len().min(chunk);
        let part: Vec<u8> = c2s.drain(..n).collect();
        let mut out = Vec::new();
        let r = s.recv(&part, &mut plain, &mut out);
        s2c.extend_from_slice(&out);
        if let Err(e) = r {
            // Deliver the alert, then report.
            let _ = c.recv(&s2c, &mut plain, &mut Vec::new());
            return Err(Side::Server(e));
        }
        let n = s2c.len().min(chunk);
        let part: Vec<u8> = s2c.drain(..n).collect();
        let mut out = Vec::new();
        let r = c.recv(&part, &mut plain, &mut out);
        c2s.extend_from_slice(&out);
        if let Err(e) = r {
            let _ = s.recv(&c2s, &mut plain, &mut Vec::new());
            return Err(Side::Client(e));
        }
    }
    assert!(plain.is_empty(), "no application data expected");
    Ok(())
}

pub(crate) fn connect(
    scfg: &ServerConfig,
    ccfg: &ClientConfig,
    name: &str,
) -> Result<(Connection, Connection), Side> {
    let mut c = crate::__proto::client(ccfg, name).map_err(Side::Client)?;
    let mut s = crate::__proto::server(scfg);
    shuttle(&mut c, &mut s, usize::MAX)?;
    assert!(!c.handshaking() && !s.handshaking());
    Ok((c, s))
}

/// Sends `data` from `a` to `b` and checks it arrives intact.
pub(crate) fn transfer(a: &mut Connection, b: &mut Connection, data: &[u8]) {
    let mut wire = Vec::new();
    a.seal(data, &mut wire).unwrap();
    let (mut plain, mut back) = (Vec::new(), Vec::new());
    b.recv(&wire, &mut plain, &mut back).unwrap();
    assert_eq!(plain, data);
    if !back.is_empty() {
        let mut p2 = Vec::new();
        a.recv(&back, &mut p2, &mut Vec::new()).unwrap();
        assert!(p2.is_empty());
    }
}

pub(crate) fn exchange(c: &mut Connection, s: &mut Connection) {
    transfer(c, s, b"ping from the client");
    transfer(s, c, b"pong from the server");
}

#[test]
fn tls13_suites_and_groups() {
    let p = pki(Kind::P256, &["localhost"]);
    for suite in [0x1301u16, 0x1302, 0x1303] {
        for group in [0x001du16, 0x0017, 0x0018, 0x001e] {
            let s = server(&p).__suites(&[suite]).build().unwrap();
            let c = client(&p).__groups(&[group]).build().unwrap();
            let (mut c, mut s) = connect(&s, &c, "localhost").unwrap();
            assert_eq!(c.suite().unwrap().id, suite);
            assert_eq!(c.version_name(), Some("TLSv1_3"));
            assert_eq!(s.version_name(), Some("TLSv1_3"));
            exchange(&mut c, &mut s);
        }
    }
}

#[test]
fn tls13_certificate_types() {
    for kind in [
        Kind::P256,
        Kind::P384,
        Kind::P521,
        Kind::Ed25519,
        Kind::Ed448,
        Kind::Rsa,
        Kind::RsaPss,
    ] {
        let p = pki(kind, &["localhost"]);
        let (mut c, mut s) = connect(
            &server(&p).build().unwrap(),
            &client(&p).build().unwrap(),
            "localhost",
        )
        .unwrap();
        assert_eq!(c.peer_certificates().len(), 1, "{kind:?}");
        exchange(&mut c, &mut s);
    }
}

#[test]
fn tls12_suites_and_keys() {
    let cases: &[(Kind, &[u16])] = &[
        (Kind::P256, &[0xc02b, 0xc02c, 0xcca9]),
        (Kind::P384, &[0xc02b, 0xc02c]),
        (Kind::Ed25519, &[0xc02b, 0xcca9]),
        (Kind::Ed448, &[0xc02c]),
        (Kind::Rsa, &[0xc02f, 0xc030, 0xcca8]),
        (Kind::P521, &[0xc02c]),
        (Kind::RsaPss, &[0xc02f, 0xcca8]),
    ];
    for (kind, suites) in cases {
        let p = pki(*kind, &["localhost"]);
        for suite in *suites {
            for group in [0x001du16, 0x0017, 0x0018, 0x001e, 0x0019] {
                let s = server(&p)
                    .__suites(&[*suite])
                    .__groups(&[group])
                    .build()
                    .unwrap();
                let c = client(&p).__tls12_only(true).build().unwrap();
                let (mut c, mut s) = connect(&s, &c, "localhost").unwrap();
                assert_eq!(c.version_name(), Some("TLSv1_2"), "{kind:?} {suite:#x}");
                assert_eq!(c.suite().unwrap().id, *suite);
                exchange(&mut c, &mut s);
            }
        }
    }
}

#[test]
fn version_negotiation() {
    let p = pki(Kind::P256, &["localhost"]);
    // A TLS 1.2-only client gets TLS 1.2 from a dual server.
    let (c, _) = connect(
        &server(&p).build().unwrap(),
        &client(&p).__tls12_only(true).build().unwrap(),
        "localhost",
    )
    .unwrap();
    assert_eq!(c.version_name(), Some("TLSv1_2"));
    // A dual client gets TLS 1.2 from a TLS 1.2-only server (no downgrade sentinel there).
    let (c, _) = connect(
        &server(&p).__tls12_only(true).build().unwrap(),
        &client(&p).build().unwrap(),
        "localhost",
    )
    .unwrap();
    assert_eq!(c.version_name(), Some("TLSv1_2"));
    // TLS 1.3-only server, TLS 1.2-only client: protocol_version.
    let e = connect(
        &server(&p).tls13_only(true).build().unwrap(),
        &client(&p).__tls12_only(true).build().unwrap(),
        "localhost",
    )
    .unwrap_err();
    assert_eq!(e.alert(), Alert::ProtocolVersion);
    // TLS 1.3-only client, TLS 1.2-only server.
    let e = connect(
        &server(&p).__tls12_only(true).build().unwrap(),
        &client(&p).tls13_only(true).build().unwrap(),
        "localhost",
    )
    .unwrap_err();
    assert_eq!(e.alert(), Alert::ProtocolVersion);
}

/// Rewrites the first ClientHello in `wire`: renames extension `from` to `to` (same length).
pub(crate) fn rename_extension(wire: &mut [u8], from: u16, to: u16) {
    let ch = ClientHello::parse(&wire[9..]).unwrap();
    assert!(ch.exts.iter().any(|(t, _)| *t == from));
    // Walk the extensions to find the type field.
    let body = &wire[9..];
    let mut r = Reader::new(body);
    r.bytes(2 + 32).unwrap();
    r.vec8().unwrap();
    r.vec16().unwrap();
    r.vec8().unwrap();
    let ext_start = body.len() - r.rest().len() + 2;
    let mut pos = 9 + ext_start;
    loop {
        let t = u16::from_be_bytes([wire[pos], wire[pos + 1]]);
        let l = usize::from(u16::from_be_bytes([wire[pos + 2], wire[pos + 3]]));
        if t == from {
            wire[pos..pos + 2].copy_from_slice(&to.to_be_bytes());
            return;
        }
        pos += 4 + l;
    }
}

#[test]
fn downgrade_to_tls12_is_detected() {
    let p = pki(Kind::P256, &["localhost"]);
    let scfg = server(&p).build().unwrap();
    let ccfg = client(&p).build().unwrap();
    let mut c = crate::__proto::client(&ccfg, "localhost").unwrap();
    let mut s = crate::__proto::server(&scfg);
    let (mut plain, mut ch) = (Vec::new(), Vec::new());
    c.recv(&[], &mut plain, &mut ch).unwrap();
    // An attacker hides supported_versions: the server answers TLS 1.2 with the sentinel.
    rename_extension(&mut ch, msgs::EXT_SUPPORTED_VERSIONS, 0x7a7a);
    let mut flight = Vec::new();
    s.recv(&ch, &mut plain, &mut flight).unwrap();
    let e = c.recv(&flight, &mut plain, &mut Vec::new()).unwrap_err();
    assert_eq!(e.alert, Alert::IllegalParameter);
    assert!(e.message().contains("downgrade"));
}

#[test]
fn hello_retry_request() {
    let p = pki(Kind::P256, &["localhost"]);
    // The client sends an X25519 share; the server only does P-384.
    let s = server(&p).__groups(&[0x0018]).build().unwrap();
    let c = client(&p).build().unwrap();
    let (mut c, mut s) = connect(&s, &c, "localhost").unwrap();
    exchange(&mut c, &mut s);
    // Forced HRR with a usable share, for every suite.
    for suite in [0x1301u16, 0x1302, 0x1303] {
        let s = server(&p)
            .__force_hello_retry(true)
            .__suites(&[suite])
            .build()
            .unwrap();
        let (mut c, mut s) = connect(&s, &client(&p).build().unwrap(), "localhost").unwrap();
        exchange(&mut c, &mut s);
    }
    // No common group at all.
    let s = server(&p).__groups(&[0x0018]).build().unwrap();
    let e = connect(
        &s,
        &client(&p).__groups(&[0x001d]).build().unwrap(),
        "localhost",
    )
    .unwrap_err();
    assert_eq!(e.alert(), Alert::HandshakeFailure);
}

#[test]
fn tls13_resumption() {
    let p = pki(Kind::P256, &["localhost"]);
    for tickets in [true, false] {
        let ccfg = client(&p).alpn(["h2"]).build().unwrap();
        let s = server(&p)
            .session_tickets(tickets)
            .alpn(["h2"])
            .build()
            .unwrap();
        let (c1, s1) = connect(&s, &ccfg, "localhost").unwrap();
        assert!(!c1.resumed() && !s1.resumed());
        for _ in 0..2 {
            let (mut c2, mut s2) = connect(&s, &ccfg, "localhost").unwrap();
            assert!(c2.resumed(), "tickets={tickets}");
            assert!(s2.resumed());
            assert_eq!(c2.alpn(), Some(&b"h2"[..]));
            exchange(&mut c2, &mut s2);
        }
        // Resumption with HelloRetryRequest.
        let s_hrr = server(&p)
            .session_tickets(true)
            .__force_hello_retry(true)
            .build()
            .unwrap();
        let ccfg2 = client(&p).build().unwrap();
        connect(&s_hrr, &ccfg2, "localhost").unwrap();
        let (c3, _) = connect(&s_hrr, &ccfg2, "localhost").unwrap();
        assert!(c3.resumed());
    }
    // Client resumption off.
    let s = server(&p).session_tickets(true).build().unwrap();
    let ccfg = client(&p).resumption(false).build().unwrap();
    connect(&s, &ccfg, "localhost").unwrap();
    let (c, _) = connect(&s, &ccfg, "localhost").unwrap();
    assert!(!c.resumed());
    // Server resumption off: the ticket is ignored, full handshake.
    let s_off = server(&p).session_cache(0).build().unwrap();
    let ccfg = client(&p).build().unwrap();
    connect(&s, &ccfg, "localhost").unwrap();
    let (c, _) = connect(&s_off, &ccfg, "localhost").unwrap();
    assert!(!c.resumed());
}

#[test]
fn tls12_resumption() {
    let p = pki(Kind::P256, &["localhost"]);
    for tickets in [true, false] {
        let s = server(&p).session_tickets(tickets).build().unwrap();
        let ccfg = client(&p).__tls12_only(true).build().unwrap();
        let (c1, _) = connect(&s, &ccfg, "localhost").unwrap();
        assert!(!c1.resumed());
        for _ in 0..2 {
            let (mut c2, mut s2) = connect(&s, &ccfg, "localhost").unwrap();
            assert!(c2.resumed(), "tickets={tickets}");
            assert!(s2.resumed());
            assert_eq!(c2.version_name(), Some("TLSv1_2"));
            exchange(&mut c2, &mut s2);
        }
    }
}

#[test]
fn client_authentication() {
    let sp = pki(Kind::P256, &["localhost"]);
    for kind in [
        Kind::P256,
        Kind::P521,
        Kind::Ed25519,
        Kind::Rsa,
        Kind::RsaPss,
    ] {
        let cp = pki(kind, &["client"]);
        for tls12 in [false, true] {
            let s = server(&sp)
                .client_auth_required(cp.roots.clone())
                .build()
                .unwrap();
            let c = client(&sp)
                .client_cert(cp.chain.clone(), cp.key.clone())
                .__tls12_only(tls12)
                .build()
                .unwrap();
            let (mut c, mut s) = connect(&s, &c, "localhost").unwrap();
            assert_eq!(s.peer_certificates().len(), 1, "{kind:?} tls12={tls12}");
            exchange(&mut c, &mut s);
        }
    }
    let cp = pki(Kind::P256, &["client"]);
    for tls12 in [false, true] {
        // Required, none sent.
        let s = server(&sp)
            .client_auth_required(cp.roots.clone())
            .build()
            .unwrap();
        let e = connect(
            &s,
            &client(&sp).__tls12_only(tls12).build().unwrap(),
            "localhost",
        )
        .unwrap_err();
        assert!(matches!(e, Side::Server(_)));
        assert!(matches!(
            e.alert(),
            Alert::CertificateRequired | Alert::HandshakeFailure
        ));
        // Optional, none sent.
        let s = server(&sp)
            .client_auth_optional(cp.roots.clone())
            .build()
            .unwrap();
        let (_, s) = connect(
            &s,
            &client(&sp).__tls12_only(tls12).build().unwrap(),
            "localhost",
        )
        .unwrap();
        assert!(s.peer_certificates().is_empty());
        // Untrusted client certificate.
        let other = pki(Kind::P256, &["other"]);
        let s = server(&sp)
            .client_auth_required(cp.roots.clone())
            .build()
            .unwrap();
        let c = client(&sp)
            .client_cert(other.chain.clone(), other.key)
            .__tls12_only(tls12)
            .build()
            .unwrap();
        let e = connect(&s, &c, "localhost").unwrap_err();
        assert_eq!(e.alert(), Alert::UnknownCa);
    }
    // The client certificate survives resumption.
    let s = server(&sp)
        .client_auth_required(cp.roots.clone())
        .session_tickets(true)
        .build()
        .unwrap();
    let c = client(&sp)
        .client_cert(cp.chain.clone(), cp.key)
        .build()
        .unwrap();
    connect(&s, &c, "localhost").unwrap();
    let (c2, s2) = connect(&s, &c, "localhost").unwrap();
    assert!(c2.resumed());
    assert_eq!(s2.peer_certificates().len(), 1);
}

#[test]
fn alpn_and_sni() {
    let a = pki(Kind::P256, &["a.test"]);
    let b = pki(Kind::Ed25519, &["b.test"]);
    let s = server(&a)
        .sni_cert("B.test", b.chain.clone(), b.key.clone())
        .alpn(["h2", "http/1.1"])
        .build()
        .unwrap();
    for tls12 in [false, true] {
        let c = client(&b)
            .alpn(["http/1.1"])
            .__tls12_only(tls12)
            .build()
            .unwrap();
        let (c, s2) = connect(&s, &c, "b.test").unwrap();
        assert_eq!(c.alpn(), Some(&b"http/1.1"[..]));
        assert_eq!(s2.server_name(), Some("b.test"));
        let c = client(&a)
            .alpn(["h2", "x"])
            .__tls12_only(tls12)
            .build()
            .unwrap();
        let (c, _) = connect(&s, &c, "a.test").unwrap();
        assert_eq!(c.alpn(), Some(&b"h2"[..]));
        // No common protocol.
        let c = client(&a)
            .alpn(["spdy"])
            .__tls12_only(tls12)
            .build()
            .unwrap();
        let e = connect(&s, &c, "a.test").unwrap_err();
        assert_eq!(e.alert(), Alert::NoApplicationProtocol);
    }
    // A server without ALPN ignores the client's list.
    let s = server(&a).build().unwrap();
    let (c, _) = connect(&s, &client(&a).alpn(["h2"]).build().unwrap(), "a.test").unwrap();
    assert_eq!(c.alpn(), None);
    // SNI off: the default certificate, which does not match b.test.
    let s = server(&a)
        .sni_cert("b.test", b.chain.clone(), b.key.clone())
        .build()
        .unwrap();
    let e = connect(&s, &client(&b).sni(false).build().unwrap(), "b.test").unwrap_err();
    assert!(matches!(e, Side::Client(_)));
}

#[test]
fn certificate_verification_failures() {
    let p = pki(Kind::P256, &["localhost"]);
    let other = pki(Kind::P256, &["localhost"]);
    let s = server(&p).build().unwrap();
    for tls12 in [false, true] {
        let e = connect(
            &s,
            &client(&p).__tls12_only(tls12).build().unwrap(),
            "example.com",
        )
        .unwrap_err();
        assert_eq!(e.alert(), Alert::BadCertificate);
        // Same subject name, another key: the signature does not verify.
        let e = connect(
            &s,
            &client(&other).__tls12_only(tls12).build().unwrap(),
            "localhost",
        )
        .unwrap_err();
        assert!(matches!(
            e.alert(),
            Alert::UnknownCa | Alert::BadCertificate
        ));
        let stranger = pki(Kind::P256, &["stranger.test"]);
        let e = connect(
            &s,
            &client(&stranger).__tls12_only(tls12).build().unwrap(),
            "localhost",
        )
        .unwrap_err();
        assert_eq!(e.alert(), Alert::UnknownCa);
        let c = ClientConfig::builder()
            .insecure_skip_verify()
            .__tls12_only(tls12)
            .build()
            .unwrap();
        connect(&s, &c, "anything.test").unwrap();
    }
    // IP address names: no SNI, matched against the certificate's IP SAN.
    let ip = pki(Kind::P256, &["127.0.0.1"]);
    let (c, s) = connect(
        &server(&ip).build().unwrap(),
        &client(&ip).build().unwrap(),
        "127.0.0.1",
    )
    .unwrap();
    assert!(c.server_name().is_none() && s.server_name().is_none());
}

#[test]
fn fragmentation_and_coalescing() {
    let p = pki(Kind::P256, &["localhost"]);
    for tls12 in [false, true] {
        for chunk in [1usize, 7, 300] {
            let scfg = server(&p)
                .client_auth_optional(p.roots.clone())
                .build()
                .unwrap();
            let ccfg = client(&p)
                .client_cert(p.chain.clone(), p.key.clone())
                .__tls12_only(tls12)
                .build()
                .unwrap();
            let mut c = crate::__proto::client(&ccfg, "localhost").unwrap();
            let mut s = crate::__proto::server(&scfg);
            shuttle(&mut c, &mut s, chunk).unwrap();
            assert!(!c.handshaking() && !s.handshaking());
            // Application data byte by byte too.
            let mut wire = Vec::new();
            c.seal(b"fragmented", &mut wire).unwrap();
            let mut plain = Vec::new();
            for b in wire {
                s.recv(&[b], &mut plain, &mut Vec::new()).unwrap();
            }
            assert_eq!(plain, b"fragmented");
        }
    }
}

#[test]
fn bulk_data_and_key_update() {
    let p = pki(Kind::P256, &["localhost"]);
    let (mut c, mut s) = connect(
        &server(&p).build().unwrap(),
        &client(&p).build().unwrap(),
        "localhost",
    )
    .unwrap();
    let big: Vec<u8> = (0..1_000_000u32).map(|i| i as u8).collect();
    transfer(&mut c, &mut s, &big);
    transfer(&mut s, &mut c, &big);
    // KeyUpdate every few records, both directions.
    c.set_key_update_after(3);
    s.set_key_update_after(2);
    for i in 0..20u8 {
        transfer(&mut c, &mut s, &[i; 100]);
        transfer(&mut s, &mut c, &[i; 50]);
    }
    transfer(&mut c, &mut s, &big);
}

/// Records opened straight from the input (whole ones) and through the receive buffer (split
/// ones), with KeyUpdates and a close_notify among them, in reads of awkward sizes.
#[test]
fn records_split_across_reads() {
    let p = pki(Kind::P256, &["localhost"]);
    for tls12 in [false, true] {
        for chunk in [3usize, 5, 4096, 16 * 1024 + 21, 16 * 1024 + 23, 70_000] {
            let (mut c, mut s) = connect(
                &server(&p).build().unwrap(),
                &client(&p).__tls12_only(tls12).build().unwrap(),
                "localhost",
            )
            .unwrap();
            c.set_key_update_after(2);
            let mut wire = Vec::new();
            let mut want = Vec::new();
            for i in 0..12u32 {
                let part: Vec<u8> = (0..=(i * 7919 % 40_000)).map(|j| (i + j) as u8).collect();
                c.seal(&part, &mut wire).unwrap();
                want.extend_from_slice(&part);
            }
            c.close(&mut wire);
            let mut plain = Vec::new();
            for part in wire.chunks(chunk) {
                s.recv(part, &mut plain, &mut Vec::new()).unwrap();
            }
            assert_eq!(plain.len(), want.len(), "tls12 {tls12} chunk {chunk}");
            assert!(plain == want, "tls12 {tls12} chunk {chunk}");
            assert!(s.received_close_notify());
        }
    }
}

#[test]
fn data_before_handshake_completion_is_queued() {
    let p = pki(Kind::P256, &["localhost"]);
    let mut c = crate::__proto::client(&client(&p).build().unwrap(), "localhost").unwrap();
    let mut s = crate::__proto::server(&server(&p).build().unwrap());
    let mut first = Vec::new();
    c.seal(b"early bird", &mut first).unwrap();
    // Only the ClientHello went out.
    assert_eq!(first[0], 22);
    let (mut plain_s, mut plain_c) = (Vec::new(), Vec::new());
    let mut to_c = Vec::new();
    s.recv(&first, &mut plain_s, &mut to_c).unwrap();
    let mut to_s = Vec::new();
    c.recv(&to_c, &mut plain_c, &mut to_s).unwrap();
    let mut back = Vec::new();
    s.recv(&to_s, &mut plain_s, &mut back).unwrap();
    assert_eq!(plain_s, b"early bird");
}

#[test]
fn close_notify() {
    let p = pki(Kind::P256, &["localhost"]);
    for tls12 in [false, true] {
        let (mut c, mut s) = connect(
            &server(&p).build().unwrap(),
            &client(&p).__tls12_only(tls12).build().unwrap(),
            "localhost",
        )
        .unwrap();
        let mut wire = Vec::new();
        c.seal(b"bye", &mut wire).unwrap();
        c.close(&mut wire);
        c.close(&mut wire); // once only
        assert!(c.seal(b"more", &mut Vec::new()).is_err());
        let mut plain = Vec::new();
        s.recv(&wire, &mut plain, &mut Vec::new()).unwrap();
        assert_eq!(plain, b"bye");
        assert!(s.received_close_notify());
        // Anything after close_notify is ignored.
        s.recv(b"garbage", &mut plain, &mut Vec::new()).unwrap();
    }
}

#[test]
fn tampering_is_fatal() {
    let p = pki(Kind::P256, &["localhost"]);
    for tls12 in [false, true] {
        let ccfg = client(&p).__tls12_only(tls12).build().unwrap();
        let scfg = server(&p).build().unwrap();
        let mut c = crate::__proto::client(&ccfg, "localhost").unwrap();
        let mut s = crate::__proto::server(&scfg);
        let (mut plain, mut ch) = (Vec::new(), Vec::new());
        c.recv(&[], &mut plain, &mut ch).unwrap();
        let mut flight = Vec::new();
        s.recv(&ch, &mut plain, &mut flight).unwrap();
        // Flip a byte near the end (inside the signed / encrypted part).
        let n = flight.len();
        flight[n - 20] ^= 0x40;
        let mut alert = Vec::new();
        let e = c.recv(&flight, &mut plain, &mut alert).unwrap_err();
        assert!(!e.from_peer);
        // A fatal alert goes out (protected under the TLS 1.3 handshake keys).
        let want = if tls12 { 21 } else { 23 };
        assert_eq!(last_record_type(&alert), Some(want));
        // The connection stays failed.
        assert!(c.recv(&[], &mut plain, &mut Vec::new()).is_err());
        assert!(c.seal(b"x", &mut Vec::new()).is_err());
        // The server, given the alert, fails with the peer's alert.
        let e = s.recv(&alert, &mut plain, &mut Vec::new()).unwrap_err();
        assert!(e.from_peer);
    }
}

fn last_record_type(mut wire: &[u8]) -> Option<u8> {
    let mut last = None;
    while let Ok(Some(n)) = RecordLayer::frame(wire) {
        last = Some(wire[0]);
        wire = &wire[n..];
    }
    last
}

#[test]
fn unexpected_records_and_garbage() {
    let p = pki(Kind::P256, &["localhost"]);
    let scfg = server(&p).build().unwrap();
    let cases: &[&[u8]] = &[
        &[23, 3, 3, 0, 1, 0],             // application data first
        &[21, 3, 3, 0, 3, 1, 0, 0],       // bad alert length
        &[20, 3, 3, 0, 1, 1],             // ChangeCipherSpec first
        &[22, 3, 1, 0, 0],                // empty handshake record
        &[22, 3, 1, 0, 4, 2, 0, 0, 0],    // ServerHello to a server
        &[22, 3, 1, 0, 4, 1, 0, 0, 0],    // empty ClientHello
        &[22, 3, 1, 0, 4, 1, 0xff, 0, 0], // over-long ClientHello
        &[24, 3, 3, 0, 0],                // unknown content type
        b"GET / HTTP/1.1\r\n\r\n",        // not TLS
    ];
    for case in cases {
        let mut s = crate::__proto::server(&scfg);
        let (mut plain, mut out) = (Vec::new(), Vec::new());
        assert!(s.recv(case, &mut plain, &mut out).is_err(), "{case:?}");
    }
    // A fatal alert from the client.
    let mut s = crate::__proto::server(&scfg);
    let e = s
        .recv(&[21, 3, 3, 0, 2, 2, 40], &mut Vec::new(), &mut Vec::new())
        .unwrap_err();
    assert!(e.from_peer);
    assert_eq!(e.alert, Alert::HandshakeFailure);
    // Random input never panics.
    let mut rng = akio_crypto::rand::ChaChaRng::from_seed([7; 32]);
    for _ in 0..200 {
        let mut s = crate::__proto::server(&scfg);
        let mut buf = vec![0u8; (rng.next_u32() % 600) as usize];
        rng.fill(&mut buf);
        if rng.next_u32() % 2 == 0 && buf.len() > 5 {
            buf[..3].copy_from_slice(&[22, 3, 1]);
            let l = (buf.len() - 5) as u16;
            buf[3..5].copy_from_slice(&l.to_be_bytes());
        }
        let _ = s.recv(&buf, &mut Vec::new(), &mut Vec::new());
    }
}

#[test]
fn rejected_early_data_is_skipped() {
    let p = pki(Kind::P256, &["localhost"]);
    let scfg = server(&p).build().unwrap();
    let ccfg = client(&p).build().unwrap();
    let mut c = crate::__proto::client(&ccfg, "localhost").unwrap();
    let (mut plain, mut ch) = (Vec::new(), Vec::new());
    c.recv(&[], &mut plain, &mut ch).unwrap();
    // Turn an extension the server ignores (ec_point_formats is TLS 1.2 only) into
    // early_data by appending: re-encode the hello with an extra empty early_data extension.
    let body = &ch[9..];
    let mut r = Reader::new(body);
    r.bytes(2 + 32).unwrap();
    r.vec8().unwrap();
    r.vec16().unwrap();
    r.vec8().unwrap();
    let head_len = body.len() - r.clone().rest().len();
    let exts = r.vec16().unwrap();
    let mut nb = body[..head_len].to_vec();
    let mut e2 = exts.to_vec();
    e2.extend_from_slice(&[0, 42, 0, 0]);
    nb.extend_from_slice(&(e2.len() as u16).to_be_bytes());
    nb.extend_from_slice(&e2);
    let mut msg = vec![1];
    msg.extend_from_slice(&(nb.len() as u32).to_be_bytes()[1..]);
    msg.extend_from_slice(&nb);
    let mut rec = vec![22, 3, 1];
    rec.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    rec.extend_from_slice(&msg);
    // Followed by "0-RTT" records the server cannot decrypt.
    rec.extend_from_slice(&[23, 3, 3, 0, 40]);
    rec.extend_from_slice(&[0x55; 40]);
    rec.extend_from_slice(&[23, 3, 3, 0, 20]);
    rec.extend_from_slice(&[0x66; 20]);
    let mut s = crate::__proto::server(&scfg);
    let mut out = Vec::new();
    s.recv(&rec, &mut plain, &mut out).unwrap();
    assert!(s.handshaking());
    assert_eq!(out[0], 22);
}

#[test]
fn renegotiation_is_refused() {
    let p = pki(Kind::P256, &["localhost"]);
    let (mut c, mut s) = connect(
        &server(&p).build().unwrap(),
        &client(&p).__tls12_only(true).build().unwrap(),
        "localhost",
    )
    .unwrap();
    // A second ClientHello from a fresh client, sent over the established connection.
    let mut c2 =
        crate::__proto::client(&client(&p).__tls12_only(true).build().unwrap(), "localhost")
            .unwrap();
    let mut ch = Vec::new();
    c2.recv(&[], &mut Vec::new(), &mut ch).unwrap();
    let hello = &ch[5..];
    let mut wire = Vec::new();
    c.rec_seal_for_test(CT_HANDSHAKE, hello, &mut wire);
    let (mut plain, mut back) = (Vec::new(), Vec::new());
    s.recv(&wire, &mut plain, &mut back).unwrap();
    // The server answers with a no_renegotiation warning and keeps the session.
    let mut p2 = Vec::new();
    c.recv(&back, &mut p2, &mut Vec::new()).unwrap();
    exchange(&mut c, &mut s);
}

impl Connection {
    fn rec_seal_for_test(&mut self, typ: u8, data: &[u8], out: &mut Vec<u8>) {
        self.test_record_layer().seal(typ, data, out).unwrap();
    }
}

#[test]
fn quic_tls_ext_order_in_client_hello() {
    // pre_shared_key is the last extension of a resuming ClientHello.
    let p = pki(Kind::P256, &["localhost"]);
    let scfg = server(&p).session_tickets(true).build().unwrap();
    let ccfg = client(&p).build().unwrap();
    connect(&scfg, &ccfg, "localhost").unwrap();
    let mut c = crate::__proto::client(&ccfg, "localhost").unwrap();
    let mut ch = Vec::new();
    c.recv(&[], &mut Vec::new(), &mut ch).unwrap();
    let hello = ClientHello::parse(&ch[9..]).unwrap();
    assert_eq!(hello.exts.last().unwrap().0, msgs::EXT_PRE_SHARED_KEY);
    assert_eq!(hello.session_id.len(), 32);
    assert!(
        hello
            .suites
            .contains(&suites::EMPTY_RENEGOTIATION_INFO_SCSV)
    );
}

/// Wraps a handshake message in a plaintext record.
fn hs_record(msg: &[u8]) -> Vec<u8> {
    let mut r = vec![22, 3, 3];
    r.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    r.extend_from_slice(msg);
    r
}

#[test]
fn out_of_order_messages_are_fatal() {
    let p = pki(Kind::P256, &["localhost"]);
    let ccfg = client(&p).build().unwrap();
    // A client that sent its ClientHello gets a Certificate, a Finished, a ClientHello ...
    for m in [
        msgs::certificate13(&[], &[vec![1]]),
        msgs::message(msgs::FINISHED, |o| o.extend_from_slice(&[0; 32])),
        msgs::message(msgs::CLIENT_HELLO, |_| {}),
        msgs::message(msgs::NEW_SESSION_TICKET, |_| {}),
        msgs::message(99, |_| {}),
    ] {
        let mut c = crate::__proto::client(&ccfg, "localhost").unwrap();
        let (mut plain, mut out) = (Vec::new(), Vec::new());
        c.recv(&[], &mut plain, &mut out).unwrap();
        let e = c.recv(&hs_record(&m), &mut plain, &mut out).unwrap_err();
        assert!(
            matches!(e.alert, Alert::UnexpectedMessage | Alert::DecodeError),
            "{e}"
        );
    }
    // A server that has the ClientHello gets it again.
    let scfg = server(&p).build().unwrap();
    let mut c = crate::__proto::client(&ccfg, "localhost").unwrap();
    let mut s = crate::__proto::server(&scfg);
    let (mut plain, mut ch) = (Vec::new(), Vec::new());
    c.recv(&[], &mut plain, &mut ch).unwrap();
    s.recv(&ch, &mut plain, &mut Vec::new()).unwrap();
    let e = s.recv(&ch, &mut plain, &mut Vec::new()).unwrap_err();
    assert_eq!(e.alert, Alert::UnexpectedMessage);
    // A second HelloRetryRequest is refused by the client.
    let hrr_server = server(&p).__force_hello_retry(true).build().unwrap();
    let mut c = crate::__proto::client(&ccfg, "localhost").unwrap();
    let mut s = crate::__proto::server(&hrr_server);
    let mut ch = Vec::new();
    c.recv(&[], &mut plain, &mut ch).unwrap();
    let mut hrr = Vec::new();
    s.recv(&ch, &mut plain, &mut hrr).unwrap();
    let n = RecordLayer::frame(&hrr).unwrap().unwrap();
    let first = hrr[..n].to_vec();
    c.recv(&first, &mut plain, &mut Vec::new()).unwrap();
    let e = c.recv(&first, &mut plain, &mut Vec::new()).unwrap_err();
    assert_eq!(e.alert, Alert::UnexpectedMessage);
}

#[test]
fn client_hello2_must_match_client_hello1() {
    let p = pki(Kind::P256, &["localhost"]);
    let scfg = server(&p).__force_hello_retry(true).build().unwrap();
    let ccfg = client(&p).build().unwrap();
    let mut s = crate::__proto::server(&scfg);
    let mut c1 = crate::__proto::client(&ccfg, "localhost").unwrap();
    let (mut plain, mut ch1) = (Vec::new(), Vec::new());
    c1.recv(&[], &mut plain, &mut ch1).unwrap();
    let mut hrr = Vec::new();
    s.recv(&ch1, &mut plain, &mut hrr).unwrap();
    // A different client's ClientHello (another random) as the second one.
    let mut c2 = crate::__proto::client(&ccfg, "localhost").unwrap();
    let mut ch2 = Vec::new();
    c2.recv(&[], &mut plain, &mut ch2).unwrap();
    let e = s.recv(&ch2, &mut plain, &mut Vec::new()).unwrap_err();
    assert_eq!(e.alert, Alert::IllegalParameter);
}

#[test]
fn psk_without_modes_is_refused() {
    let p = pki(Kind::P256, &["localhost"]);
    let scfg = server(&p).session_tickets(true).build().unwrap();
    let ccfg = client(&p).build().unwrap();
    connect(&scfg, &ccfg, "localhost").unwrap();
    let mut c = crate::__proto::client(&ccfg, "localhost").unwrap();
    let mut ch = Vec::new();
    c.recv(&[], &mut Vec::new(), &mut ch).unwrap();
    rename_extension(&mut ch, msgs::EXT_PSK_MODES, 0x7a7a);
    let mut s = crate::__proto::server(&scfg);
    let e = s.recv(&ch, &mut Vec::new(), &mut Vec::new()).unwrap_err();
    assert_eq!(e.alert, Alert::MissingExtension);
}

#[test]
fn malformed_records_and_finished() {
    let p = pki(Kind::P256, &["localhost"]);
    let scfg = server(&p).build().unwrap();
    // Empty alert, double CCS, SSL 3.0 hello.
    for (case, want) in [
        (&[21u8, 3, 3, 0, 0][..], Alert::UnexpectedMessage),
        (&[20, 3, 3, 0, 2, 1, 1][..], Alert::UnexpectedMessage),
    ] {
        let mut s = crate::__proto::server(&scfg);
        let e = s.recv(case, &mut Vec::new(), &mut Vec::new()).unwrap_err();
        assert_eq!(e.alert, want);
    }
    let ccfg = client(&p).build().unwrap();
    let mut c = crate::__proto::client(&ccfg, "localhost").unwrap();
    let mut ch = Vec::new();
    c.recv(&[], &mut Vec::new(), &mut ch).unwrap();
    ch[9..11].copy_from_slice(&[3, 0]);
    let mut s = crate::__proto::server(&scfg);
    let e = s.recv(&ch, &mut Vec::new(), &mut Vec::new()).unwrap_err();
    assert_eq!(e.alert, Alert::ProtocolVersion);
}

#[cfg(feature = "ktls")]
#[path = "ktls_tests.rs"]
mod ktls;

/// secp521r1 as the only group on either side, TLS 1.3 (key share in the first ClientHello, or
/// after a HelloRetryRequest when the client led with X25519).
#[test]
fn tls13_secp521r1() {
    let p = pki(Kind::P521, &["localhost"]);
    for client_groups in [&[0x0019u16][..], &[0x001d, 0x0019]] {
        let s = server(&p).__groups(&[0x0019]).build().unwrap();
        let c = client(&p).__groups(client_groups).build().unwrap();
        let (mut c, mut s) = connect(&s, &c, "localhost").unwrap();
        assert_eq!(c.version_name(), Some("TLSv1_3"));
        exchange(&mut c, &mut s);
    }
}
