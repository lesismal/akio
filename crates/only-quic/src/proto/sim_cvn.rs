//! Compatible version negotiation (RFC 9368 section 4, RFC 9369 section 4.1) on the simulated
//! network: a server preferring version 2 moves version 1 clients to it within the handshake,
//! with a Retry, loss, a ClientHello over several packets and 0-RTT; no switch without the
//! preference or when the client does not list version 2; a forged Initial of the other
//! version does not move a client.

use super::zero_rtt::{prime, request, zcfg};
use super::*;
use crate::proto::packet::{PacketType, VERSION_1, VERSION_2};
use only_tls::EarlyData;

/// A server configuration preferring version 2.
fn prefer_v2() -> ConnConfig {
    let mut c = ConnConfig::new(TransportConfig::default(), true);
    c.prefer_version = Some(VERSION_2);
    c
}

fn client_cfg() -> ConnConfig {
    ConnConfig::new(TransportConfig::default(), true)
}

/// Connects until both sides are connected: the time it took.
fn timed_handshake(
    sim: &mut Sim,
    tls: &only_tls::ClientConfig,
    cfg: ConnConfig,
) -> (ConnHandle, Duration) {
    let start = sim.now;
    let h = sim.handshake(tls, cfg);
    (h, sim.now - start)
}

#[test]
fn version_1_client_moves_to_version_2_without_a_round_trip() {
    // The same handshake without and with the server's preference.
    let (s, tls) = certs();
    let mut plain = Sim::new(60, client_cfg(), s, false);
    let (hp, t_plain) = timed_handshake(&mut plain, &tls, client_cfg());
    assert_eq!(plain.cconn(hp).version(), VERSION_1);
    assert_eq!(plain.sconn().orig_version(), None);

    let (s, tls) = certs();
    let mut sim = Sim::new(60, prefer_v2(), s, false);
    sim.record_long = true;
    let mut cfg = client_cfg();
    cfg.key_update_interval = 200;
    let (h, t) = timed_handshake(&mut sim, &tls, cfg);
    assert_eq!(sim.cconn(h).version(), VERSION_2);
    assert_eq!(sim.sconn().version(), VERSION_2);
    assert_eq!(sim.cconn(h).orig_version(), Some(VERSION_1));
    assert_eq!(sim.sconn().orig_version(), Some(VERSION_1));
    // No extra round trip.
    assert!(t <= t_plain + sim.link.delay / 2, "{t:?} vs {t_plain:?}");
    // The client's first Initial was version 1; everything the server sent was version 2,
    // and so was everything the client sent once it heard from the server.
    let seen = sim.long_seen.clone();
    assert_eq!(seen[0], (true, PacketType::Initial, VERSION_1));
    assert!(
        seen.iter().filter(|p| !p.0).all(|p| p.2 == VERSION_2),
        "{seen:?}"
    );
    assert!(seen.contains(&(true, PacketType::Handshake, VERSION_2)));
    assert!(
        !seen
            .iter()
            .any(|p| p.0 && p.1 == PacketType::Handshake && p.2 == VERSION_1)
    );
    // Bulk data with key updates in version 2.
    bulk(&mut sim, h, &[300_000, 1000], Duration::from_secs(30));
    assert_eq!(sim.cconn(h).version(), VERSION_2);
}

#[test]
fn compatible_switch_with_retry_and_loss() {
    for seed in [61u8, 62, 63, 64] {
        let (s, tls) = certs();
        let mut sim = Sim::new(seed, prefer_v2(), s, true);
        sim.link.loss = 0.15;
        let h = sim.handshake(&tls, client_cfg());
        assert!(sim.sconn().retry_scid.is_some());
        assert_eq!(sim.cconn(h).version(), VERSION_2);
        assert_eq!(sim.sconn().version(), VERSION_2);
        bulk(&mut sim, h, &[50_000], Duration::from_secs(30));
    }
}

/// TLS configurations whose ClientHello does not fit one Initial packet (a long ALPN list).
fn big_hello_certs() -> (only_tls::ServerConfig, only_tls::ClientConfig) {
    let (cert, key) = only_x509::generate_simple_self_signed(["localhost"]).expect("cert");
    let chain = vec![only_tls::Certificate::from_der(cert.as_der().to_vec())];
    let mut roots = only_tls::RootCerts::empty();
    roots.add(&chain[0]).expect("root");
    let key = only_tls::PrivateKey::from_pkcs8_der(key.to_pkcs8_der());
    let s = only_tls::ServerConfig::builder(chain, key)
        .alpn(["sim"])
        .tls13_only(true)
        .build()
        .expect("server tls");
    let mut alpn: Vec<String> = (0..80).map(|i| format!("unused-protocol-{i:04}")).collect();
    alpn.push("sim".into());
    let c = only_tls::ClientConfig::builder()
        .roots(roots)
        .alpn(alpn)
        .tls13_only(true)
        .build()
        .expect("client tls");
    (s, c)
}

#[test]
fn client_hello_over_several_packets() {
    for (seed, loss) in [(65u8, 0.0), (66, 0.2), (67, 0.2)] {
        let (s, tls) = big_hello_certs();
        let mut sim = Sim::new(seed, prefer_v2(), s, false);
        sim.link.loss = loss;
        sim.record_long = true;
        let h = sim.handshake(&tls, client_cfg());
        let first_flight = sim
            .long_seen
            .iter()
            .filter(|p| p.0 && p.1 == PacketType::Initial && p.2 == VERSION_1)
            .count();
        assert!(first_flight >= 2, "{:?}", sim.long_seen);
        assert_eq!(sim.cconn(h).version(), VERSION_2);
        assert_eq!(sim.sconn().version(), VERSION_2);
        bulk(&mut sim, h, &[10_000], Duration::from_secs(30));
    }
}

#[test]
fn no_switch_without_preference_or_client_support() {
    // No preference (the default): the server answers in the client's version.
    let (mut sim, tls) = Sim::default_pair(68);
    let h = sim.handshake(&tls, client_cfg());
    assert_eq!(sim.cconn(h).version(), VERSION_1);
    assert_eq!(sim.cconn(h).orig_version(), None);
    // A client that does not list version 2 stays in version 1.
    let (s, tls) = certs();
    let mut sim = Sim::new(69, prefer_v2(), s, false);
    let mut cfg = client_cfg();
    cfg.versions = vec![VERSION_1];
    let h = sim.handshake(&tls, cfg);
    assert_eq!(sim.cconn(h).version(), VERSION_1);
    assert_eq!(sim.sconn().version(), VERSION_1);
    assert_eq!(sim.sconn().orig_version(), None);
    // A version 2 client of a server preferring version 2: nothing to switch.
    let (s, tls) = certs();
    let mut sim = Sim::new(70, prefer_v2(), s, false);
    let mut cfg = client_cfg();
    cfg.version = VERSION_2;
    let h = sim.handshake(&tls, cfg);
    assert_eq!(sim.cconn(h).version(), VERSION_2);
    assert_eq!(sim.sconn().orig_version(), None);
    // A server preferring version 1 moves version 2 clients down to it, as compatible
    // negotiation allows in both directions.
    let (s, tls) = certs();
    let mut scfg = client_cfg();
    scfg.prefer_version = Some(VERSION_1);
    let mut sim = Sim::new(71, scfg, s, false);
    let mut cfg = client_cfg();
    cfg.version = VERSION_2;
    let h = sim.handshake(&tls, cfg);
    assert_eq!(sim.cconn(h).version(), VERSION_1);
    assert_eq!(sim.sconn().orig_version(), Some(VERSION_2));
    bulk(&mut sim, h, &[10_000], Duration::from_secs(30));
}

#[test]
fn zero_rtt_across_a_compatible_switch() {
    let (s, tls) = certs();
    // The ticket comes from a version 1 connection; then the server starts preferring
    // version 2 (a rollout), and moves the resuming client there.
    let mut scfg = client_cfg();
    scfg.zero_rtt = true;
    let mut sim = Sim::new(72, scfg, s, false);
    prime(&mut sim, &tls, zcfg());
    sim.server
        .ep
        .server_cfg_mut()
        .expect("server")
        .prefer_version = Some(VERSION_2);
    sim.record_0rtt = true;
    let o = request(&mut sim, &tls, zcfg(), b"GET /early");
    assert_eq!(sim.cconn(o.h).early_data(), EarlyData::Accepted);
    assert_eq!(sim.sconn().early_data(), EarlyData::Accepted);
    assert!(o.data_before_connected && o.early_stream);
    assert_eq!(sim.cconn(o.h).version(), VERSION_2);
    // The 0-RTT packets stayed in version 1 (RFC 9369 section 4.1).
    assert!(!sim.zero_rtt_seen.is_empty());
    assert!(sim.zero_rtt_seen.iter().all(|&v| v == VERSION_1));
    bulk(&mut sim, o.h, &[20_000], Duration::from_secs(30));
}

#[test]
fn tickets_and_tokens_follow_the_negotiated_version() {
    // A version 1 client moved to version 2: the ticket and the token it got are version
    // 2's (RFC 9369 section 5), so the next connection starts in version 2 and uses both:
    // resumed with 0-RTT, the address validated by the token, no switch needed.
    let (s, tls) = certs();
    let mut scfg = prefer_v2();
    scfg.zero_rtt = true;
    let mut sim = Sim::new(74, scfg, s, false);
    let h = sim.handshake(&tls, zcfg());
    assert_eq!(sim.cconn(h).orig_version(), Some(VERSION_1));
    assert!(sim.run_until(Duration::from_secs(5), |s| !s.client.tokens.is_empty()));
    let token = sim.client.tokens[0].clone();
    assert_eq!(token.version, VERSION_2);
    assert_eq!(
        only_tls::quic::ticket_version(&tls, "localhost"),
        Some(VERSION_2)
    );
    let n = sim.now;
    sim.cconn(h).close(n, 0, b"");
    sim.run_until(Duration::from_secs(5), |s| {
        s.client.conns.is_empty() && s.server.conns.is_empty()
    });
    sim.record_long = true;
    sim.long_seen.clear();
    // Configured to start in version 1, as before.
    let h = sim.connect(&tls, zcfg(), Some(token));
    // The token validated the address with the first Initial.
    assert!(sim.run_until(Duration::from_secs(5), |s| s.server_handle().is_some()));
    assert!(sim.sconn().path.validated);
    let ok = sim.run_until(Duration::from_secs(10), |s| {
        s.connected(false, h) && s.server_handle().is_some_and(|sh| s.connected(true, sh))
    });
    assert!(ok);
    assert_eq!(sim.long_seen[0], (true, PacketType::Initial, VERSION_2));
    assert_eq!(sim.cconn(h).version(), VERSION_2);
    assert_eq!(sim.cconn(h).orig_version(), None);
    assert_eq!(sim.sconn().orig_version(), None);
    assert!(sim.cconn(h).resumed());
    assert_eq!(sim.cconn(h).early_data(), EarlyData::Accepted);
}

#[test]
fn a_version_1_ticket_is_not_used_in_version_2() {
    // A ticket and token from a version 1 connection; the client is then configured to start
    // in version 2. It must not use them there (RFC 9369 section 5): it starts in version 1,
    // the version they belong to, and resumes.
    let (s, tls) = certs();
    let mut scfg = client_cfg();
    scfg.zero_rtt = true;
    let mut sim = Sim::new(75, scfg, s, false);
    prime(&mut sim, &tls, zcfg());
    let token = sim.client.tokens.last().cloned().expect("token");
    assert_eq!(token.version, VERSION_1);
    let mut cfg = zcfg();
    cfg.version = VERSION_2;
    let h = sim.connect(&tls, cfg.clone(), Some(token.clone()));
    assert!(sim.run_until(Duration::from_secs(5), |s| s.server_handle().is_some()));
    assert!(sim.sconn().path.validated);
    let ok = sim.run_until(Duration::from_secs(10), |s| {
        s.connected(false, h) && s.server_handle().is_some_and(|sh| s.connected(true, sh))
    });
    assert!(ok);
    assert_eq!(sim.cconn(h).version(), VERSION_1);
    assert!(sim.cconn(h).resumed());
    let n = sim.now;
    sim.cconn(h).close(n, 0, b"");
    sim.run_until(Duration::from_secs(5), |s| {
        s.client.conns.is_empty() && s.server.conns.is_empty()
    });
    // A client that speaks only version 2 starts there without them: a full handshake,
    // the address not validated.
    cfg.versions = vec![VERSION_2];
    let h = sim.connect(&tls, cfg, Some(token));
    assert!(sim.run_until(Duration::from_secs(5), |s| s.server_handle().is_some()));
    assert!(!sim.sconn().path.validated);
    let ok = sim.run_until(Duration::from_secs(10), |s| {
        s.connected(false, h) && s.server_handle().is_some_and(|sh| s.connected(true, sh))
    });
    assert!(ok);
    assert_eq!(sim.cconn(h).version(), VERSION_2);
    assert!(!sim.cconn(h).resumed());
    assert_eq!(sim.cconn(h).early_data(), EarlyData::NotAttempted);
}

#[test]
fn forged_initial_of_another_version_is_ignored() {
    let (mut sim, tls) = Sim::default_pair(73);
    let h = sim.connect(&tls, client_cfg(), None);
    let now = sim.now;
    let first = sim.cconn(h).poll_transmit(now, 1).expect("initial").data;
    // The client's own Initial, relabelled as a version 2 Initial (type bits 01): it parses,
    // but does not decrypt with version 2's keys.
    let mut forged = first;
    forged[0] = (forged[0] & !0x30) | 0x10;
    forged[1..5].copy_from_slice(&VERSION_2.to_be_bytes());
    let hdr = crate::proto::packet::parse_header(&forged, 8).expect("header");
    assert_eq!((hdr.ty, hdr.version), (PacketType::Initial, VERSION_2));
    let server = sim.server.addr;
    sim.cconn(h).handle_datagram(now, server, forged);
    assert_eq!(sim.cconn(h).version(), VERSION_1);
    assert_eq!(sim.cconn(h).orig_version(), None);
    // The client goes on in version 1 (its first Initial counts as lost and goes again).
    let ok = sim.run_until(Duration::from_secs(10), |s| {
        s.connected(false, h) && s.server_handle().is_some_and(|sh| s.connected(true, sh))
    });
    assert!(ok);
    assert_eq!(sim.cconn(h).version(), VERSION_1);
}
