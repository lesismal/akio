//! RTCP on its own port (ICE component 2, no rtcp-mux, ADR-058) between two `Endpoint`s over
//! loopback: media and RTCP over two components with DTLS-SRTP (a handshake per component)
//! and SDES-SRTP, the mux policies, and RTCP XR receipt blocks negotiated end to end.
#![allow(missing_docs)]

use std::net::UdpSocket;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use akio::{Engine, Listener};
use akio_turn::{TurnConfig, TurnServer, static_auth, stun};
use akio_webrtc::{
    Codec, Direction, Endpoint, Event, Frequency, MediaData, MediaKind, MediaTime, Mid, Peer,
    PeerHandler, RtcConfig, RtcServer, RtcpMuxPolicy, XrBlocks, rtc_config,
};

const T: Duration = Duration::from_secs(10);

fn engine() -> Arc<Engine> {
    let e = Arc::new(Engine::builder().udp_client_threads(1).build().unwrap());
    e.start().unwrap();
    e
}

/// An endpoint with an RTCP socket.
fn endpoint(e: &Engine, cfg: fn() -> RtcConfig) -> Endpoint {
    let ep = Endpoint::bind(e, "127.0.0.1:0".parse().unwrap())
        .unwrap()
        .config(cfg);
    let rtcp = ep.bind_rtcp(e, "127.0.0.1:0".parse().unwrap()).unwrap();
    assert_eq!(ep.rtcp_addr(), Some(rtcp));
    assert_ne!(Some(rtcp), ep.local_addr());
    assert!(ep.bind_rtcp(e, "127.0.0.1:0".parse().unwrap()).is_err());
    ep
}

#[derive(Debug)]
enum Got {
    Connected,
    Media(Mid),
    Event(String),
}

/// Echoes media and reports what it sees.
struct Probe {
    tx: Mutex<Sender<Got>>,
    echo: bool,
}

impl Probe {
    fn new(echo: bool) -> (Probe, Receiver<Got>) {
        let (tx, rx) = channel();
        (
            Probe {
                tx: Mutex::new(tx),
                echo,
            },
            rx,
        )
    }
}

impl PeerHandler for Probe {
    fn on_connected(&mut self, _p: &Peer) {
        let _ = self.tx.lock().unwrap().send(Got::Connected);
    }
    fn on_media_data(&mut self, p: &Peer, d: &MediaData) {
        if self.echo {
            let _ = p.write_media(d.mid, d.pt, Instant::now(), d.time, &d.data);
        }
        let _ = self.tx.lock().unwrap().send(Got::Media(d.mid));
    }
    fn on_event(&mut self, _p: &Peer, e: &Event) {
        let _ = self.tx.lock().unwrap().send(Got::Event(format!("{e:?}")));
    }
}

fn wait_connected(rx: &Receiver<Got>) {
    let deadline = Instant::now() + T;
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Got::Connected) => return,
            Ok(_) => {}
            Err(_) => panic!("not connected"),
        }
    }
}

/// Sends Opus on `mid` for `secs` seconds (20 ms packets); returns the packets echoed back
/// and the events seen.
fn exchange(p: &Peer, rx: &Receiver<Got>, mid: Mid, secs: u64) -> (usize, Vec<String>) {
    let pt = p.payload_type(mid, Codec::Opus).expect("opus");
    let (mut echoed, mut events) = (0, Vec::new());
    for i in 0..secs * 50 {
        let t = MediaTime::new(i * 960, Frequency::FORTY_EIGHT_KHZ);
        p.write_media(mid, pt, Instant::now(), t, &[0xfc, i as u8, 1, 2, 3])
            .unwrap();
        let until = Instant::now() + Duration::from_millis(20);
        while let Ok(g) = rx.recv_timeout(until.saturating_duration_since(Instant::now())) {
            match g {
                Got::Media(m) if m == mid => echoed += 1,
                Got::Event(e) => events.push(e),
                _ => {}
            }
        }
    }
    while let Ok(g) = rx.recv_timeout(Duration::from_millis(300)) {
        if let Got::Event(e) = g {
            events.push(e);
        }
    }
    (echoed, events)
}

fn off() -> RtcConfig {
    rtc_config()
        .set_rtcp_mux_policy(RtcpMuxPolicy::Off)
        .set_stats_interval(Some(Duration::from_millis(500)))
}

fn stats() -> RtcConfig {
    rtc_config().set_stats_interval(Some(Duration::from_millis(500)))
}

/// Media one way and echoed back, with `offerer` / `answerer` configurations; checks the SDP
/// with `check`; returns the offerer's events.
fn session(
    e: &Engine,
    offerer: fn() -> RtcConfig,
    answerer: fn() -> RtcConfig,
    check: impl Fn(&str, &str),
    secs: u64,
) -> Vec<String> {
    let a = endpoint(e, offerer);
    let b = endpoint(e, answerer);
    let (probe, rx) = Probe::new(false);
    let mut audio = None;
    let (pa, offer) = a
        .create_offer(probe, |api| {
            audio = Some(api.add_media(MediaKind::Audio, Direction::SendRecv, None, None));
        })
        .unwrap();
    let (echo, _rxb) = Probe::new(true);
    let (pb, answer) = b.accept_offer(&offer, echo).unwrap();
    check(&offer, &answer);
    pa.accept_answer(&answer).unwrap();
    wait_connected(&rx);
    let (echoed, events) = exchange(&pa, &rx, audio.unwrap(), secs);
    assert!(echoed as u64 >= secs * 45, "{echoed} packets echoed");
    pa.close();
    pb.close();
    a.close();
    b.close();
    events
}

fn has(events: &[String], what: &str) -> bool {
    events.iter().any(|e| e.contains(what))
}

#[test]
fn media_and_rtcp_over_two_components_with_dtls_srtp() {
    let e = engine();
    let events = session(
        &e,
        off,
        stats,
        |offer, answer| {
            for sdp in [offer, answer] {
                assert!(
                    !sdp.contains("a=rtcp-mux") && sdp.contains("a=rtcp:"),
                    "{sdp}"
                );
                assert!(sdp.contains(" 2 udp "), "{sdp}");
                assert!(sdp.contains("a=fingerprint:"), "{sdp}");
            }
        },
        3,
    );
    // Sender and receiver reports crossed component 2 (with its own DTLS keys): the
    // offerer got sender reports and an RTT from the reports about its stream.
    assert!(has(&events, "SenderReport"), "{events:#?}");
    assert!(has(&events, "rtcp_mux: false"), "{events:#?}");
    assert!(
        events
            .iter()
            .any(|e| e.contains("PeerStats") && e.contains("rtt_ms: Some(")),
        "{events:#?}"
    );
    e.shutdown();
}

#[test]
fn media_and_rtcp_over_two_components_with_sdes() {
    let e = engine();
    let events = session(
        &e,
        || off().enable_sdes_srtp(true),
        || stats().enable_sdes_srtp(true),
        |offer, answer| {
            for sdp in [offer, answer] {
                assert!(
                    !sdp.contains("a=rtcp-mux") && sdp.contains("a=crypto:"),
                    "{sdp}"
                );
            }
        },
        2,
    );
    assert!(has(&events, "SenderReport") && has(&events, "rtcp_mux: false"));
    e.shutdown();
}

#[test]
fn negotiate_policy_and_browser_like_offers() {
    let e = engine();
    // `Negotiate` toward a peer that muxes: rtcp-mux.
    let events = session(
        &e,
        || stats().set_rtcp_mux_policy(RtcpMuxPolicy::Negotiate),
        stats,
        |offer, answer| {
            assert!(offer.contains("a=rtcp-mux") && offer.contains("a=rtcp:"));
            assert!(offer.contains(" 2 udp "));
            assert!(answer.contains("a=rtcp-mux") && !answer.contains("a=rtcp:"));
            assert!(!answer.contains(" 2 udp "));
        },
        2,
    );
    assert!(has(&events, "rtcp_mux: true") && has(&events, "SenderReport"));
    // The default policy: nothing changes for browsers, even with an RTCP socket.
    let events = session(
        &e,
        stats,
        stats,
        |offer, answer| {
            for sdp in [offer, answer] {
                assert!(sdp.contains("a=rtcp-mux") && sdp.contains("a=group:BUNDLE"));
                assert!(
                    !sdp.contains("a=rtcp:") && !sdp.contains(" 2 udp "),
                    "{sdp}"
                );
            }
        },
        1,
    );
    assert!(has(&events, "rtcp_mux: true"));
    e.shutdown();
}

#[test]
fn xr_receipt_blocks_between_endpoints() {
    let e = engine();
    let xr = || stats().enable_rtcp_xr_blocks(XrBlocks::ALL);
    let events = session(
        &e,
        xr,
        xr,
        |offer, answer| {
            let line = "a=rtcp-xr:pkt-loss-rle pkt-dup-rle pkt-rcpt-times voip-metrics";
            assert!(offer.contains(line) && answer.contains(line), "{answer}");
        },
        3,
    );
    // The echoing side's receipt blocks and VoIP metrics about the offerer's stream.
    assert!(has(&events, "XrReceipts"), "{events:#?}");
    assert!(has(&events, "VoipMetrics"), "{events:#?}");
    assert!(has(&events, "SourceDescription"), "{events:#?}");
    e.shutdown();
}

#[test]
fn rtcp_socket_sends_from_its_own_port() {
    // A peer's RTCP leaves from the RTCP socket: a raw socket standing in for the remote's
    // RTCP port sees datagrams from it, never from the RTP socket.
    let e = engine();
    let a = endpoint(&e, off);
    let (probe, _rx) = Probe::new(false);
    let (pa, offer) = a
        .create_offer(probe, |api| {
            api.add_media(MediaKind::Audio, Direction::SendRecv, None, None);
        })
        .unwrap();
    assert!(offer.contains(&format!(" {} typ host", a.rtcp_addr().unwrap().port())));
    let rtcp = UdpSocket::bind("127.0.0.1:0").unwrap();
    rtcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let port = rtcp.local_addr().unwrap().port();
    // A remote with an RTCP candidate only reachable on component 2: the checks reach it.
    let answer = offer
        .lines()
        .filter(|l| !l.starts_with("a=candidate:") && !l.starts_with("a=end-of"))
        .map(|l| match l {
            l if l.starts_with("a=ice-ufrag:") => "a=ice-ufrag:rmte".to_owned(),
            l if l.starts_with("a=ice-pwd:") => "a=ice-pwd:remotepasswordremotepassw".to_owned(),
            l if l.starts_with("a=setup:") => "a=setup:active".to_owned(),
            l if l.starts_with("a=mid:") => {
                format!("{l}\r\na=candidate:1 2 udp 2130706430 127.0.0.1 {port} typ host")
            }
            l => l.to_owned(),
        })
        .map(|l| format!("{l}\r\n"))
        .collect::<String>();
    pa.accept_answer(&answer).unwrap();
    let mut buf = [0u8; 1500];
    let (n, from) = rtcp.recv_from(&mut buf).expect("a check on component 2");
    assert!(n >= 20 && buf[0] < 4, "a STUN check");
    assert_eq!(Some(from), a.rtcp_addr());
    pa.close();
    a.close();
    e.shutdown();
}

fn turn() -> (Arc<Engine>, TurnServer, std::net::SocketAddr) {
    let auth = static_auth("akio", [("alice", "wonderland")]);
    let cfg = TurnConfig::new("akio", auth, "127.0.0.1".parse().unwrap()).allow_private_peers(true);
    let t = TurnServer::new(cfg);
    let e = Arc::new(
        Engine::builder()
            .listen(
                Listener::udp("127.0.0.1:0".parse().unwrap())
                    .threads(1)
                    .serve(t.clone()),
            )
            .build()
            .unwrap(),
    );
    t.set_engine(&e);
    e.start().unwrap();
    let a = e.local_addrs()[0];
    (e, t, a)
}

/// The component of a candidate (its SDP line's second field).
fn component(c: &akio_webrtc::Candidate) -> u16 {
    c.to_sdp()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

/// Keeps only the relayed candidates of an SDP.
fn relay_only(sdp: &str) -> String {
    sdp.lines()
        .filter(|l| !l.starts_with("a=candidate") || l.contains(" typ relay"))
        .map(|l| format!("{l}\r\n"))
        .collect()
}

#[test]
fn rtcp_through_relayed_candidates() {
    // Both endpoints allocate for component 1 and, from their RTCP sockets, component 2; the
    // session signals relayed candidates only, so RTP and RTCP each cross the TURN server.
    let (te, turn, server) = turn();
    let e = engine();
    let a = endpoint(&e, off);
    let b = endpoint(&e, stats);
    let ra = a.gather_relay(server, "alice", "wonderland", T).unwrap();
    b.gather_relay(server, "alice", "wonderland", T).unwrap();
    assert_eq!(turn.stats().allocations, 4);
    let relayed = |ep: &Endpoint, comp: u16| {
        ep.candidates()
            .iter()
            .filter(|c| c.to_sdp().contains(" typ relay") && component(c) == comp)
            .count()
    };
    assert_eq!((relayed(&a, 1), relayed(&a, 2)), (1, 1));
    assert_eq!((relayed(&b, 1), relayed(&b, 2)), (1, 1));
    // A second one on the same server is refused for either component.
    assert!(a.gather_relay(server, "alice", "wonderland", T).is_err());
    assert_eq!(turn.stats().allocations, 4);

    let (probe, rx) = Probe::new(false);
    let mut audio = None;
    let (pa, offer) = a
        .create_offer(probe, |api| {
            audio = Some(api.add_media(MediaKind::Audio, Direction::SendRecv, None, None));
        })
        .unwrap();
    let offer = relay_only(&offer);
    assert!(offer.contains(&format!("{} {} typ relay", ra.ip(), ra.port())));
    assert!(
        offer
            .lines()
            .any(|l| l.contains(" 2 udp ") && l.contains(" typ relay")),
        "{offer}"
    );
    let (echo, _rxb) = Probe::new(true);
    let (pb, answer) = b.accept_offer(&offer, echo).unwrap();
    let answer = relay_only(&answer);
    assert!(
        answer.contains("a=rtcp:") && !answer.contains("a=rtcp-mux"),
        "{answer}"
    );
    pa.accept_answer(&answer).unwrap();
    wait_connected(&rx);
    let before = turn.stats();
    let (echoed, events) = exchange(&pa, &rx, audio.unwrap(), 2);
    assert!(echoed >= 90, "{echoed} packets echoed");
    assert!(
        has(&events, "SenderReport") && has(&events, "rtcp_mux: false"),
        "{events:#?}"
    );
    assert!(turn.stats().to_peer > before.to_peer);
    pa.close();
    pb.close();
    a.close();
    b.close();
    let t = Instant::now();
    while turn.stats().allocations != 0 {
        assert!(t.elapsed() < T, "{:?}", turn.stats());
        std::thread::sleep(Duration::from_millis(10));
    }
    e.shutdown();
    te.shutdown();
}

#[test]
fn rtcp_server_reflexive_candidate() {
    // A STUN server that reports every client 1000 ports up, so the mapped addresses differ
    // from the host candidates.
    let stun_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let stun_addr = stun_sock.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = stun_sock.recv_from(&mut buf) {
            let mapped = std::net::SocketAddr::new(from.ip(), from.port().wrapping_add(1000));
            if let Some(r) = stun::binding_response(&buf[..n], mapped, None) {
                let _ = stun_sock.send_to(&r, from);
            }
        }
    });
    let e = engine();
    let a = endpoint(&e, off);
    let main = a.local_addr().unwrap();
    let rtcp = a.rtcp_addr().unwrap();
    let mapped = a.gather_srflx(stun_addr, T).unwrap();
    assert_eq!(mapped.port(), main.port().wrapping_add(1000));
    let srflx: Vec<(u16, u16)> = a
        .candidates()
        .iter()
        .filter(|c| c.to_sdp().contains(" typ srflx"))
        .map(|c| (component(c), c.addr().port()))
        .collect();
    assert!(
        srflx.contains(&(1, main.port().wrapping_add(1000))),
        "{srflx:?}"
    );
    assert!(
        srflx.contains(&(2, rtcp.port().wrapping_add(1000))),
        "{srflx:?}"
    );
    // Both go into an offer without rtcp-mux, related to their own host candidates.
    let (probe, _rx) = Probe::new(false);
    let (pa, offer) = a
        .create_offer(probe, |api| {
            api.add_media(MediaKind::Audio, Direction::SendRecv, None, None);
        })
        .unwrap();
    let line = |comp: u16| {
        offer
            .lines()
            .find(|l| l.contains(&format!(" {comp} udp ")) && l.contains(" typ srflx"))
            .unwrap_or_else(|| panic!("{offer}"))
            .to_owned()
    };
    assert!(
        line(2).ends_with(&format!("rport {}", rtcp.port())),
        "{}",
        line(2)
    );
    assert!(
        line(1).ends_with(&format!("rport {}", main.port())),
        "{}",
        line(1)
    );
    pa.close();
    a.close();
    e.shutdown();
}

#[test]
fn ice_lite_server_with_an_rtcp_listener() {
    // An RtcServer with a second listener for component 2 answers an offer without
    // rtcp-mux with RTCP on that listener.
    let pick = || {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap()
    };
    let (main, rtcp) = (pick(), pick());
    let server = RtcServer::new(vec![main])
        .config(stats)
        .rtcp_candidates(vec![rtcp]);
    let e = Arc::new(
        Engine::builder()
            .udp_client_threads(1)
            .listen(Listener::udp(main).threads(1).serve(server.clone()))
            .listen(Listener::udp(rtcp).threads(1).serve(server.rtcp()))
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    let a = endpoint(&e, off);
    let (probe, rx) = Probe::new(false);
    let mut audio = None;
    let (pa, offer) = a
        .create_offer(probe, |api| {
            audio = Some(api.add_media(MediaKind::Audio, Direction::SendRecv, None, None));
        })
        .unwrap();
    let (echo, _rxb) = Probe::new(true);
    let (ps, answer) = server.accept_offer(&offer, echo).unwrap();
    assert!(
        answer.contains("a=ice-lite") && answer.contains("a=rtcp:"),
        "{answer}"
    );
    assert!(!answer.contains("a=rtcp-mux"), "{answer}");
    assert!(
        answer
            .lines()
            .any(|l| l.contains(" 2 udp ") && l.contains(&format!(" {} typ host", rtcp.port()))),
        "{answer}"
    );
    pa.accept_answer(&answer).unwrap();
    wait_connected(&rx);
    let (echoed, events) = exchange(&pa, &rx, audio.unwrap(), 2);
    assert!(echoed >= 90, "{echoed} packets echoed");
    assert!(
        has(&events, "SenderReport") && has(&events, "rtcp_mux: false"),
        "{events:#?}"
    );
    pa.close();
    ps.close();
    a.close();
    e.shutdown();
}
