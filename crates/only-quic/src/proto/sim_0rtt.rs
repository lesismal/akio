//! 0-RTT on the simulated network (RFC 9001 section 4.6, RFC 9000 sections 7.4.1 and 17.2.3):
//! accepted, rejected (changed limits, server without 0-RTT) with the data sent again in
//! 1-RTT, lost 0-RTT packets, Retry with 0-RTT, a replayed first flight (also to another server
//! sharing tickets and the anti-replay store), and QUIC version 2.

use super::*;
use crate::proto::packet::{PacketType, VERSION_2, parse_header};
use only_tls::EarlyData;

pub(super) fn zcfg() -> ConnConfig {
    let mut c = ConnConfig::new(TransportConfig::default(), true);
    c.zero_rtt = true;
    c
}

/// A server accepting 0-RTT (or not), and its client TLS config.
fn zsim(seed: u8, server_0rtt: bool, retry: bool) -> (Sim, only_tls::ClientConfig) {
    let (s, c) = certs();
    let mut cfg = ConnConfig::new(TransportConfig::default(), true);
    cfg.zero_rtt = server_0rtt;
    (Sim::new(seed, cfg, s, retry), c)
}

/// A first connection, closed once the tickets arrived.
pub(super) fn prime(sim: &mut Sim, tls: &only_tls::ClientConfig, cfg: ConnConfig) {
    let h = sim.handshake(tls, cfg);
    // The tickets come with HANDSHAKE_DONE.
    assert!(sim.run_until(Duration::from_secs(5), |s| s.cconn(h).is_confirmed()));
    let n = sim.now;
    sim.cconn(h).close(n, 0, b"");
    sim.run_until(Duration::from_secs(5), |s| {
        s.client.conns.is_empty() && s.server.conns.is_empty()
    });
    sim.client.events.clear();
    sim.server.events.clear();
}

/// What the server saw of a request sent in 0-RTT, and when the client had its echo.
pub(super) struct Outcome {
    pub(super) h: ConnHandle,
    /// The server had the stream data before the handshake completed.
    pub(super) data_before_connected: bool,
    /// The server flagged the stream as early.
    pub(super) early_stream: bool,
    /// Time from the connect to the echo.
    pub(super) elapsed: Duration,
}

/// Connects and sends `req` on a stream opened right away (0-RTT if possible, else after the
/// handshake); the server echoes it.
pub(super) fn request(
    sim: &mut Sim,
    tls: &only_tls::ClientConfig,
    cfg: ConnConfig,
    req: &[u8],
) -> Outcome {
    let start = sim.now;
    let h = sim.connect(tls, cfg, None);
    let mut id = sim.cconn(h).open(Dir::Bi);
    if let Some(id) = id {
        sim.cconn(h)
            .write(id, Bytes::copy_from_slice(req))
            .expect("write");
        sim.cconn(h).finish(id).expect("finish");
    }
    let mut server = Collector::default();
    let (mut early_stream, mut data_before_connected, mut s_connected) = (false, false, false);
    let mut client = Collector::default();
    let mut echoed = false;
    let ok = sim.run_until(Duration::from_secs(60), |s| {
        if id.is_none() && s.connected(false, h) {
            let i = s.cconn(h).open(Dir::Bi).expect("stream");
            s.cconn(h)
                .write(i, Bytes::copy_from_slice(req))
                .expect("write");
            s.cconn(h).finish(i).expect("finish");
            id = Some(i);
        }
        if let Some(sh) = s.server_handle() {
            let evs = s.events(true, sh);
            for e in &evs {
                match e {
                    Event::Connected => s_connected = true,
                    Event::StreamData(sid, ..) => {
                        early_stream |= s.sconn().is_early(*sid);
                        data_before_connected |= !s_connected;
                    }
                    _ => {}
                }
            }
            server.take(evs);
            for (sid, d) in std::mem::take(&mut server.finished) {
                if !echoed {
                    let sc = s.sconn();
                    sc.write(sid, Bytes::from(d)).expect("echo");
                    sc.finish(sid).expect("echo finish");
                    echoed = true;
                }
            }
        }
        let evs = s.events(false, h);
        client.take(evs);
        !client.finished.is_empty()
    });
    assert!(ok, "no echo");
    let got = client.finished.values().next().expect("echo");
    assert_eq!(got, req);
    Outcome {
        h,
        data_before_connected,
        early_stream,
        elapsed: sim.now - start,
    }
}

#[test]
fn zero_rtt_accepted() {
    let (mut sim, tls) = zsim(40, true, false);
    let rtt = sim.link.delay * 2;
    prime(&mut sim, &tls, zcfg());
    // Without 0-RTT the client waits for the handshake: about two round trips to the echo.
    let full = request(
        &mut sim,
        &tls,
        ConnConfig::new(TransportConfig::default(), true),
        b"x",
    );
    assert!(!full.data_before_connected && !full.early_stream);
    assert_eq!(sim.cconn(full.h).early_data(), EarlyData::NotAttempted);
    prime(&mut sim, &tls, zcfg());
    let o = request(&mut sim, &tls, zcfg(), b"GET /index.html");
    assert_eq!(sim.cconn(o.h).early_data(), EarlyData::Accepted);
    assert_eq!(sim.sconn().early_data(), EarlyData::Accepted);
    assert!(sim.cconn(o.h).resumed());
    assert!(o.data_before_connected, "the request did not come in 0-RTT");
    assert!(o.early_stream);
    // One round trip saved: the server answers in 0.5-RTT.
    assert!(
        o.elapsed + rtt / 2 < full.elapsed,
        "0-RTT {:?} vs 1-RTT {:?}",
        o.elapsed,
        full.elapsed
    );
    assert!(o.elapsed < rtt * 3 / 2, "{:?}", o.elapsed);
    // The connection goes on in 1-RTT.
    bulk(&mut sim, o.h, &[50_000], Duration::from_secs(30));
}

#[test]
fn zero_rtt_rejected_data_goes_again() {
    // A server without 0-RTT: tickets do not allow it, the client does not try.
    let (mut sim, tls) = zsim(41, false, false);
    prime(&mut sim, &tls, zcfg());
    let o = request(&mut sim, &tls, zcfg(), b"no 0-rtt");
    assert_eq!(sim.cconn(o.h).early_data(), EarlyData::NotAttempted);
    assert!(!o.data_before_connected);
    // A ticket allowing 0-RTT, presented to a server whose limits changed: rejected, the
    // stream data goes again in 1-RTT.
    let (mut sim, tls) = zsim(42, true, false);
    prime(&mut sim, &tls, zcfg());
    let mut t = TransportConfig::default();
    t.stream_receive_window /= 2;
    let mut scfg = ConnConfig::new(t, true);
    scfg.zero_rtt = true;
    let tls_server = sim.server.ep.server_tls().expect("server");
    let mut sim2 = Sim::new(43, scfg, tls_server, false);
    let o = request(&mut sim2, &tls, zcfg(), b"rejected request");
    assert_eq!(sim2.cconn(o.h).early_data(), EarlyData::Rejected);
    assert_eq!(sim2.sconn().early_data(), EarlyData::Rejected);
    assert!(sim2.cconn(o.h).resumed());
    assert!(!o.data_before_connected && !o.early_stream);
    bulk(&mut sim2, o.h, &[20_000], Duration::from_secs(30));
}

#[test]
fn zero_rtt_packets_lost() {
    for seed in [44u8, 45, 46] {
        let (mut sim, tls) = zsim(seed, true, false);
        prime(&mut sim, &tls, zcfg());
        // A lossy link: 0-RTT packets lost go again (as 0-RTT, or in 1-RTT once the handshake
        // is done).
        sim.link.loss = 0.15;
        let req = body(20_000, seed);
        let o = request(&mut sim, &tls, zcfg(), &req);
        assert_eq!(sim.cconn(o.h).early_data(), EarlyData::Accepted);
        sim.link.loss = 0.0;
    }
    // All 0-RTT packets lost (the server drops them): the data goes again in 1-RTT.
    let (mut sim, tls) = zsim(47, true, false);
    prime(&mut sim, &tls, zcfg());
    sim.drop_zero_rtt = true;
    let o = request(&mut sim, &tls, zcfg(), &body(5000, 1));
    assert_eq!(sim.cconn(o.h).early_data(), EarlyData::Accepted);
    assert!(!o.data_before_connected);
    assert!(sim.cconn(o.h).stats().lost_packets > 0);
}

#[test]
fn zero_rtt_with_retry() {
    let (mut sim, tls) = zsim(48, true, true);
    prime(&mut sim, &tls, zcfg());
    let o = request(&mut sim, &tls, zcfg(), b"after retry");
    assert!(sim.cconn(o.h).retry_scid.is_some());
    assert_eq!(sim.cconn(o.h).early_data(), EarlyData::Accepted);
    assert!(o.data_before_connected && o.early_stream);
}

#[test]
fn zero_rtt_in_version_2() {
    let (mut sim, tls) = zsim(49, true, false);
    let mut cfg = zcfg();
    cfg.version = VERSION_2;
    prime(&mut sim, &tls, cfg.clone());
    sim.record_0rtt = true;
    let o = request(&mut sim, &tls, cfg, b"v2 early");
    assert_eq!(sim.cconn(o.h).version(), VERSION_2);
    assert_eq!(sim.cconn(o.h).early_data(), EarlyData::Accepted);
    assert!(o.data_before_connected);
    // The 0-RTT packets carried version 2's type bits.
    assert!(!sim.zero_rtt_seen.is_empty());
}

#[test]
fn replayed_zero_rtt_flight_is_rejected() {
    let (mut sim, tls) = zsim(50, true, false);
    prime(&mut sim, &tls, zcfg());
    sim.record_0rtt = true;
    let o = request(&mut sim, &tls, zcfg(), b"POST /pay");
    assert!(o.data_before_connected);
    let first_flight = sim.first_client_datagram.clone().expect("recorded");
    // Once the connection is gone, an attacker sends the client's first datagram again.
    let n = sim.now;
    sim.cconn(o.h).close(n, 0, b"");
    sim.run_until(Duration::from_secs(5), |s| {
        s.client.conns.is_empty() && s.server.conns.is_empty()
    });
    let attacker: SocketAddr = "10.0.0.9:6000".parse().expect("addr");
    let to = sim.server.addr;
    sim.inject(attacker, to, first_flight);
    sim.run_until(Duration::from_millis(100), |_| false);
    let replayed: Vec<&Connection> = sim
        .server
        .conns
        .values()
        .filter(|c| c.remote_addr() == attacker)
        .collect();
    assert_eq!(replayed.len(), 1);
    // The ClientHello was seen before: its 0-RTT is rejected, nothing reaches the application.
    assert_eq!(replayed[0].early_data(), EarlyData::Rejected);
    let rh = sim
        .server
        .conns
        .iter()
        .find(|(_, c)| c.remote_addr() == attacker)
        .map(|(h, _)| *h)
        .expect("handle");
    let evs = sim.events(true, rh);
    assert!(
        !evs.iter().any(|e| matches!(e, Event::StreamData(..))),
        "replayed 0-RTT data reached the application"
    );
}

/// An anti-replay store standing for a shared remote one (Redis or similar).
#[derive(Default)]
struct SharedStore(std::sync::Mutex<std::collections::HashSet<Vec<u8>>>);

impl only_tls::AntiReplayStore for SharedStore {
    fn check_and_insert(&self, binder: &[u8], _ttl: Duration) -> std::io::Result<bool> {
        Ok(self.0.lock().expect("store").insert(binder.to_vec()))
    }
}

/// Server TLS configurations sharing a certificate and a ticket key, each with `store` (or
/// its own record), and the client's.
fn shared_tls(
    stores: &[Option<std::sync::Arc<SharedStore>>],
) -> (Vec<only_tls::ServerConfig>, only_tls::ClientConfig) {
    let (cert, key) = only_x509::generate_simple_self_signed(["localhost"]).expect("cert");
    let chain = vec![only_tls::Certificate::from_der(cert.as_der().to_vec())];
    let mut roots = only_tls::RootCerts::empty();
    roots.add(&chain[0]).expect("root");
    let key = only_tls::PrivateKey::from_pkcs8_der(key.to_pkcs8_der());
    let servers = stores
        .iter()
        .map(|st| {
            let mut b = only_tls::ServerConfig::builder(chain.clone(), key.clone())
                .alpn(["sim"])
                .tls13_only(true)
                .session_ticket_key([0x42; 48]);
            if let Some(st) = st {
                b = b.anti_replay_store(st.clone());
            }
            b.build().expect("server tls")
        })
        .collect();
    let c = only_tls::ClientConfig::builder()
        .roots(roots)
        .alpn(["sim"])
        .tls13_only(true)
        .build()
        .expect("client tls");
    (servers, c)
}

/// What a server made of `flight`, a client's first datagram replayed by an attacker.
fn replay_first_flight(seed: u8, tls: only_tls::ServerConfig, flight: Vec<u8>) -> EarlyData {
    let mut cfg = ConnConfig::new(TransportConfig::default(), true);
    cfg.zero_rtt = true;
    let mut sim = Sim::new(seed, cfg, tls, false);
    let attacker: SocketAddr = "10.0.0.9:6000".parse().expect("addr");
    let to = sim.server.addr;
    sim.inject(attacker, to, flight);
    sim.run_until(Duration::from_millis(100), |_| false);
    let c = sim
        .server
        .conns
        .values()
        .find(|c| c.remote_addr() == attacker)
        .expect("replayed connection");
    c.early_data()
}

#[test]
fn replay_to_another_server_sharing_the_anti_replay_store() {
    let store = std::sync::Arc::new(SharedStore::default());
    let (servers, tls) = shared_tls(&[Some(store.clone()), Some(store), None]);
    // A client's 0-RTT request to server A.
    let mut cfg = ConnConfig::new(TransportConfig::default(), true);
    cfg.zero_rtt = true;
    let mut sim = Sim::new(53, cfg, servers[0].clone(), false);
    prime(&mut sim, &tls, zcfg());
    sim.record_0rtt = true;
    let o = request(&mut sim, &tls, zcfg(), b"POST /pay");
    assert!(o.data_before_connected);
    let flight = sim.first_client_datagram.clone().expect("recorded");
    // Replayed to server B, which accepts the ticket and shares A's store: rejected.
    assert_eq!(
        replay_first_flight(54, servers[1].clone(), flight.clone()),
        EarlyData::Rejected
    );
    // Server C accepts the ticket but keeps its own record: the replay gets through there.
    assert_eq!(
        replay_first_flight(55, servers[2].clone(), flight),
        EarlyData::Accepted
    );
}

/// Seeds for the `quic_packet` fuzz target: a client's first datagram with an Initial and a
/// coalesced 0-RTT packet, in QUIC v1 and v2.
/// `cargo test -p only-quic --lib write_zero_rtt_corpus -- --ignored`.
#[test]
#[ignore = "writes fuzz/corpus"]
fn write_zero_rtt_corpus() {
    let dir = format!(
        "{}/../../fuzz/corpus/quic_packet",
        env!("CARGO_MANIFEST_DIR")
    );
    for (name, version) in [("zero_rtt_v1", None), ("zero_rtt_v2", Some(VERSION_2))] {
        let (mut sim, tls) = zsim(52, true, false);
        let mut cfg = zcfg();
        if let Some(v) = version {
            cfg.version = v;
        }
        prime(&mut sim, &tls, cfg.clone());
        sim.record_0rtt = true;
        request(&mut sim, &tls, cfg, b"GET /");
        let d = sim.first_client_datagram.clone().expect("recorded");
        std::fs::write(format!("{dir}/{name}"), d).expect("write");
    }
}

#[test]
fn zero_rtt_packet_types_on_the_wire() {
    let (mut sim, tls) = zsim(51, true, false);
    prime(&mut sim, &tls, zcfg());
    sim.record_0rtt = true;
    request(&mut sim, &tls, zcfg(), b"v1");
    let d = sim.first_client_datagram.clone().expect("recorded");
    // Initial, then a coalesced 0-RTT packet under the same connection IDs.
    let h = parse_header(&d, 8).expect("initial");
    assert_eq!(h.ty, PacketType::Initial);
    let z = parse_header(&d[h.len..], 8).expect("0-rtt");
    assert_eq!(z.ty, PacketType::ZeroRtt);
    assert_eq!(z.dcid, h.dcid);
}
