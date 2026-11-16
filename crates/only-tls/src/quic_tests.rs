//! The QUIC-facing handshake: levels, secrets, transport parameters, ALPN, resumption, and the
//! RFC 9001 Appendix A key derivation vectors.

use super::*;
use crate::proto::tests::{Kind, pki};
use crate::{ClientConfig, ServerConfig};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// What one side saw, by level.
#[derive(Default, Debug)]
struct Seen {
    read: Vec<(Level, Vec<u8>)>,
    write: Vec<(Level, Vec<u8>)>,
    done: bool,
}

fn secret(k: &Keys) -> Vec<u8> {
    match k {
        Keys::Tls13 { secret, .. } => secret.clone(),
        Keys::Tls12 { .. } => panic!("TLS 1.2 keys in QUIC"),
    }
}

/// Runs both sides to completion, checking that each side's write secret at a level is the
/// other side's read secret there.
fn run(c: &mut QuicTls, s: &mut QuicTls) -> Result<(Seen, Seen), Fatal> {
    let (mut sc, mut ss) = (Seen::default(), Seen::default());
    for _ in 0..20 {
        let mut moved = false;
        while let Some(e) = c.poll_event() {
            moved = true;
            match e {
                Event::Data(l, b) => s.read_handshake(l, &b)?,
                Event::ReadKeys(l, k) => sc.read.push((l, secret(&k))),
                Event::WriteKeys(l, k) => sc.write.push((l, secret(&k))),
                Event::Done => sc.done = true,
            }
        }
        while let Some(e) = s.poll_event() {
            moved = true;
            match e {
                Event::Data(l, b) => c.read_handshake(l, &b)?,
                Event::ReadKeys(l, k) => ss.read.push((l, secret(&k))),
                Event::WriteKeys(l, k) => ss.write.push((l, secret(&k))),
                Event::Done => ss.done = true,
            }
        }
        if !moved {
            break;
        }
    }
    Ok((sc, ss))
}

fn configs(alpn: &[&str]) -> (ServerConfig, ClientConfig) {
    let p = pki(Kind::P256, &["localhost"]);
    let s = ServerConfig::builder(p.chain.clone(), p.key.clone())
        .alpn(alpn)
        .session_tickets(true)
        .build()
        .unwrap();
    let c = ClientConfig::builder()
        .roots(p.roots)
        .alpn(["h3"])
        .build()
        .unwrap();
    (s, c)
}

#[test]
fn handshake_levels_and_secrets() {
    let (scfg, ccfg) = configs(&["h3"]);
    let mut c = QuicTls::client(&ccfg, "localhost", b"cp".to_vec()).unwrap();
    let mut s = QuicTls::server(&scfg, b"sp".to_vec());
    let (sc, ss) = run(&mut c, &mut s).unwrap();
    assert!(sc.done && ss.done);
    assert!(!c.handshaking() && !s.handshaking());
    assert_eq!(c.peer_transport_params(), Some(&b"sp"[..]));
    assert_eq!(s.peer_transport_params(), Some(&b"cp"[..]));
    assert_eq!(c.alpn(), Some(&b"h3"[..]));
    assert_eq!(s.server_name(), Some("localhost"));
    assert_eq!(c.peer_certificates().len(), 1);
    assert!(!c.early_data_accepted());
    // Handshake and 1-RTT keys in both directions, matching across sides.
    for l in [Level::Handshake, Level::Application] {
        let cw = &sc.write.iter().find(|x| x.0 == l).unwrap().1;
        let sr = &ss.read.iter().find(|x| x.0 == l).unwrap().1;
        assert_eq!(cw, sr, "{l:?}");
        let sw = &ss.write.iter().find(|x| x.0 == l).unwrap().1;
        let cr = &sc.read.iter().find(|x| x.0 == l).unwrap().1;
        assert_eq!(sw, cr, "{l:?}");
        assert_ne!(cw, sw);
    }
    let suite = c.suite().unwrap();
    let (k, iv, hp) = packet_keys(suite, &sc.write[0].1);
    assert_eq!((k.len(), iv.len(), hp.len()), (16, 12, 16));
    assert_ne!(next_secret(suite, &sc.write[0].1), sc.write[0].1);
}

#[test]
fn resumption_over_quic() {
    let (scfg, ccfg) = configs(&["h3"]);
    let mut c = QuicTls::client(&ccfg, "localhost", vec![1]).unwrap();
    let mut s = QuicTls::server(&scfg, vec![2]);
    run(&mut c, &mut s).unwrap();
    assert!(!c.resumed());
    let mut c = QuicTls::client(&ccfg, "localhost", vec![1]).unwrap();
    let mut s = QuicTls::server(&scfg, vec![2]);
    run(&mut c, &mut s).unwrap();
    assert!(c.resumed() && s.resumed());
}

#[test]
fn alpn_is_required() {
    // The server has no ALPN configured: QUIC refuses.
    let (scfg, ccfg) = configs(&[]);
    let mut c = QuicTls::client(&ccfg, "localhost", vec![]).unwrap();
    let mut s = QuicTls::server(&scfg, vec![]);
    let e = run(&mut c, &mut s).unwrap_err();
    assert_eq!(e.alert, Alert::NoApplicationProtocol);
    // A later call keeps failing.
    assert!(s.read_handshake(Level::Initial, &[]).is_err());
}

#[test]
fn wrong_level_is_refused() {
    let (scfg, ccfg) = configs(&["h3"]);
    let mut c = QuicTls::client(&ccfg, "localhost", vec![]).unwrap();
    let Some(Event::Data(Level::Initial, ch)) = c.poll_event() else {
        panic!("no ClientHello");
    };
    let mut s = QuicTls::server(&scfg, vec![]);
    let e = s.read_handshake(Level::Handshake, &ch).unwrap_err();
    assert_eq!(e.alert, Alert::UnexpectedMessage);
    // Split across calls at the right level: fine.
    let mut s = QuicTls::server(&scfg, vec![]);
    for b in &ch {
        s.read_handshake(Level::Initial, &[*b]).unwrap();
    }
    assert!(matches!(
        s.poll_event(),
        Some(Event::Data(Level::Initial, _))
    ));
}

#[test]
fn no_tls12_and_no_compat_in_quic() {
    let (_, ccfg) = configs(&["h3"]);
    let mut c = QuicTls::client(&ccfg, "localhost", vec![9]).unwrap();
    let Some(Event::Data(_, ch)) = c.poll_event() else {
        panic!("no ClientHello");
    };
    let hello = crate::proto::msgs::ClientHello::parse(&ch[4..]).unwrap();
    assert!(hello.session_id.is_empty());
    assert_eq!(hello.versions, Some(vec![0x0304]));
    assert_eq!(hello.quic_params, Some(&[9u8][..]));
    assert!(hello.suites.iter().all(|s| (0x1301..=0x1303).contains(s)));
    // QUIC has no records: no record_size_limit (RFC 9001 section 4). Certificate compression
    // is off by default on clients.
    assert_eq!(hello.record_limit, None);
    assert_eq!(hello.cert_comp, None);
}

#[test]
fn rfc9001_initial_secrets() {
    // RFC 9001 Appendix A.1.
    let dcid = unhex("8394c8f03e515708");
    let (client, server) = initial_secrets(&V1_INITIAL_SALT, &dcid);
    assert_eq!(
        client,
        unhex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
    );
    assert_eq!(
        server,
        unhex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
    );
    let (k, iv, hp) = packet_keys(&crate::proto::suites::TLS13_AES_128_GCM_SHA256, &client);
    assert_eq!(k, unhex("1f369613dd76d5467730efcbe3b1a22d"));
    assert_eq!(iv, unhex("fa044b2f42a3fd3b46fb255c"));
    assert_eq!(hp, unhex("9f50449e04a0e810283a1e9933adedd2"));
    // RFC 9001 Appendix A.5: ChaCha20-Poly1305 key update.
    let s = &crate::proto::suites::TLS13_CHACHA20_POLY1305_SHA256;
    let secret = unhex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    let (k, iv, hp) = packet_keys(s, &secret);
    assert_eq!(
        k,
        unhex("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8")
    );
    assert_eq!(iv, unhex("e0459b3474bdd0e44a41c144"));
    assert_eq!(
        hp,
        unhex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
    );
    assert_eq!(
        next_secret(s, &secret),
        unhex("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")
    );
    assert_eq!(
        hkdf_expand_label(HashAlg::Sha256, &secret, b"quic iv", &[], 12),
        iv
    );
}

#[test]
fn zero_rtt_over_quic() {
    let (scfg, ccfg) = configs(&["h3"]);
    let ctx = b"limits v1".to_vec();
    // First connection: a ticket allowing 0-RTT, with the server's parameters remembered.
    let mut c = QuicTls::client_early(&ccfg, "localhost", vec![1], true).unwrap();
    let mut s = QuicTls::server_early(&scfg, b"server params".to_vec(), Some(ctx.clone()));
    run(&mut c, &mut s).unwrap();
    assert_eq!(c.early_data(), EarlyData::NotAttempted);
    assert!(c.early_params().is_none());
    // Resumed with 0-RTT: early keys on both sides, the same, no EndOfEarlyData.
    let mut c = QuicTls::client_early(&ccfg, "localhost", vec![1], true).unwrap();
    assert_eq!(c.early_params(), Some(&b"server params"[..]));
    let mut s = QuicTls::server_early(&scfg, b"server params".to_vec(), Some(ctx.clone()));
    let (sc, ss) = run(&mut c, &mut s).unwrap();
    assert!(c.early_data_accepted() && s.early_data_accepted());
    let cw = &sc.write.iter().find(|x| x.0 == Level::EarlyData).unwrap().1;
    let sr = &ss.read.iter().find(|x| x.0 == Level::EarlyData).unwrap().1;
    assert_eq!(cw, sr);
    assert!(sc.done && ss.done);
    // Changed transport parameters on the server: 0-RTT rejected, resumption goes on.
    let mut c = QuicTls::client_early(&ccfg, "localhost", vec![1], true).unwrap();
    let mut s = QuicTls::server_early(&scfg, b"server params".to_vec(), Some(b"v2".to_vec()));
    let (_, ss) = run(&mut c, &mut s).unwrap();
    assert!(c.resumed());
    assert_eq!(c.early_data(), EarlyData::Rejected);
    assert_eq!(s.early_data(), EarlyData::Rejected);
    assert!(!ss.read.iter().any(|x| x.0 == Level::EarlyData));
    // A server without 0-RTT rejects it, and its tickets do not allow it.
    let mut c = QuicTls::client_early(&ccfg, "localhost", vec![1], true).unwrap();
    let mut s = QuicTls::server(&scfg, b"server params".to_vec());
    run(&mut c, &mut s).unwrap();
    assert_eq!(c.early_data(), EarlyData::Rejected);
    // The client without 0-RTT does not offer it.
    let mut c = QuicTls::client(&ccfg, "localhost", vec![1]).unwrap();
    assert!(c.early_params().is_none());
    let mut s = QuicTls::server_early(&scfg, b"server params".to_vec(), Some(ctx));
    run(&mut c, &mut s).unwrap();
    assert_eq!(s.early_data(), EarlyData::NotAttempted);
}

#[test]
fn client_hello_transport_params_peek() {
    let p = pki(Kind::P256, &["localhost"]);
    let ccfg = ClientConfig::builder()
        .roots(p.roots.clone())
        .alpn(["h3"])
        .build()
        .unwrap();
    let mut c = QuicTls::client(&ccfg, "localhost", b"client params".to_vec()).unwrap();
    let Some(Event::Data(Level::Initial, hello)) = c.poll_event() else {
        panic!("no ClientHello");
    };
    assert_eq!(client_hello_len(&hello), Some(hello.len()));
    assert_eq!(client_hello_len(&hello[..3]), None);
    assert_eq!(
        client_hello_transport_params(&hello),
        Some(&b"client params"[..])
    );
    // Incomplete, another message, or garbage: nothing.
    assert_eq!(
        client_hello_transport_params(&hello[..hello.len() - 1]),
        None
    );
    let mut other = hello.clone();
    other[0] = 2;
    assert_eq!(client_hello_transport_params(&other), None);
    assert_eq!(client_hello_transport_params(&[1, 0, 0, 2, 3, 3]), None);
    // What was peeked does not disturb the handshake.
    let scfg = ServerConfig::builder(p.chain.clone(), p.key)
        .alpn(["h3"])
        .build()
        .unwrap();
    let mut s = QuicTls::server(&scfg, b"server params".to_vec());
    s.read_handshake(Level::Initial, &hello).unwrap();
    assert_eq!(s.peer_transport_params(), Some(&b"client params"[..]));
}
