//! RTCP on its own port (ICE component 2, no rtcp-mux, ADR-058) between two `Endpoint`s over
//! loopback: media and RTCP over two components with DTLS-SRTP (a handshake per component)
//! and SDES-SRTP, the mux policies, and RTCP XR receipt blocks negotiated end to end.
#![allow(missing_docs)]

use std::net::UdpSocket;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use only::Engine;
use only_webrtc::{
    Codec, Direction, Endpoint, Event, Frequency, MediaData, MediaKind, MediaTime, Mid, Peer,
    PeerHandler, RtcConfig, RtcpMuxPolicy, XrBlocks, rtc_config,
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
