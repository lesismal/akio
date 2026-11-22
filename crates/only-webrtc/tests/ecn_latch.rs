//! ADR-077 between two `Endpoint`s over loopback: ECN-capable RTP through the kernel's UDP
//! sockets (marked, received, validated), latching media without ICE onto the address a
//! "phone" really sends from when its description names another, and congestion control
//! across the transports of a session without BUNDLE.
#![allow(missing_docs)]

use std::net::UdpSocket;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use only::Engine;
use only_webrtc::{
    BundlePolicy, Codec, Direction, EcnMarking, Endpoint, Event, Frequency, Latching, MediaData,
    MediaKind, MediaTime, Mid, Peer, PeerHandler, RtcConfig, rtc_config,
};

const T: Duration = Duration::from_secs(10);

fn engine() -> Arc<Engine> {
    let e = Arc::new(Engine::builder().udp_client_threads(1).build().unwrap());
    e.start().unwrap();
    e
}

#[derive(Debug)]
enum Got {
    Connected,
    Media,
    Event(String),
}

/// Reports what happens; echoes media back when `echo`.
struct Probe {
    tx: Mutex<Sender<Got>>,
    echo: bool,
}

fn probe(echo: bool) -> (Probe, Receiver<Got>) {
    let (tx, rx) = channel();
    (
        Probe {
            tx: Mutex::new(tx),
            echo,
        },
        rx,
    )
}

impl PeerHandler for Probe {
    fn on_connected(&mut self, _p: &Peer) {
        let _ = self.tx.lock().unwrap().send(Got::Connected);
    }
    fn on_media_data(&mut self, p: &Peer, d: &MediaData) {
        if self.echo {
            let _ = p.write_media(d.mid, d.pt, Instant::now(), d.time, &d.data);
        }
        let _ = self.tx.lock().unwrap().send(Got::Media);
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

/// Sends audio (and video) from `p` for `secs` seconds; returns the media that came back
/// and the events seen.
fn send(
    p: &Peer,
    rx: &Receiver<Got>,
    audio: Mid,
    video: Option<Mid>,
    secs: u64,
) -> (usize, Vec<String>) {
    let opus = p.payload_type(audio, Codec::Opus).expect("opus");
    let vp8 = video.map(|v| p.payload_type(v, Codec::Vp8).expect("vp8"));
    let frame: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
    let (mut back, mut events) = (0, Vec::new());
    for i in 0..secs * 50 {
        let t = MediaTime::new(i * 960, Frequency::FORTY_EIGHT_KHZ);
        let _ = p.write_media(audio, opus, Instant::now(), t, &[0xfc, i as u8, 1, 2, 3]);
        if let (Some(v), Some(pt)) = (video, vp8) {
            let mut f = frame.clone();
            f[0] = if i == 0 { 0x10 } else { 0x11 };
            let t = MediaTime::new(i * 1800, Frequency::NINETY_KHZ);
            let _ = p.write_media(v, pt, Instant::now(), t, &f);
        }
        let until = Instant::now() + Duration::from_millis(20);
        while let Ok(g) = rx.recv_timeout(until.saturating_duration_since(Instant::now())) {
            match g {
                Got::Media => back += 1,
                Got::Event(e) => events.push(e),
                Got::Connected => {}
            }
        }
    }
    events.extend(self::events(rx));
    (back, events)
}

/// Events of `rx` in the next second (statistics come every 400 ms).
fn events(rx: &Receiver<Got>) -> Vec<String> {
    let mut v = Vec::new();
    let until = Instant::now() + Duration::from_secs(1);
    while let Ok(g) = rx.recv_timeout(until.saturating_duration_since(Instant::now())) {
        if let Got::Event(e) = g {
            v.push(e);
        }
    }
    v
}

/// The value of `field` in the last statistics event.
fn stat<'a>(events: &'a [String], field: &str) -> &'a str {
    let e = events
        .iter()
        .rev()
        .find(|e| e.contains("PeerStats"))
        .expect("statistics");
    let at = e.find(&format!("{field}: ")).expect(field) + field.len() + 2;
    let rest = &e[at..];
    &rest[..rest.find([',', ' ', '}']).unwrap_or(rest.len())]
}

fn num(events: &[String], field: &str) -> u64 {
    stat(events, field).parse().unwrap()
}

fn stats(c: RtcConfig) -> RtcConfig {
    c.set_stats_interval(Some(Duration::from_millis(400)))
}

#[test]
fn ecn_marks_survive_loopback() {
    if std::env::var("ONLY_UDP_ECN").as_deref() == Ok("0") {
        return;
    }
    let e = engine();
    let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap())
        .unwrap()
        .config(|| {
            stats(rtc_config())
                .enable_ccfb(true)
                .enable_bwe(Some(1_000_000))
                .set_ecn_marking(EcnMarking::Ect1)
        });
    let b = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap())
        .unwrap()
        .config(|| stats(rtc_config()).enable_ccfb(true).enable_bwe(None));
    let (ha, rxa) = probe(false);
    let (hb, rxb) = probe(true);
    let (mut audio, mut video) = (None, None);
    let (pa, offer) = a
        .create_offer(ha, |api| {
            audio = Some(api.add_media(MediaKind::Audio, Direction::SendRecv, None, None));
            video = Some(api.add_media(MediaKind::Video, Direction::SendRecv, None, None));
        })
        .unwrap();
    let (_pb, answer) = b.accept_offer(&offer, hb).unwrap();
    assert!(answer.contains("ack ccfb"), "{answer}");
    pa.accept_answer(&answer).unwrap();
    wait_connected(&rxa);
    let (back, ev) = send(&pa, &rxa, audio.unwrap(), video, 3);
    assert!(back > 100, "{back}");
    assert_eq!(stat(&ev, "ecn_state"), "\"capable\"", "{:?}", ev.last());
    assert!(num(&ev, "ecn_marked_sent") > 200);
    assert_eq!(num(&ev, "ecn_failures"), 0);
    // The receiver saw the marks through its socket; it marks nothing itself.
    let evb = events(&rxb);
    assert!(num(&evb, "ecn_ect_received") > 200, "{:?}", evb.last());
    assert_eq!(num(&evb, "ecn_marked_sent"), 0);
    // Nothing marked came back to a.
    assert_eq!(num(&ev, "ecn_ect_received"), 0);
    pa.close();
    a.close();
    b.close();
    e.shutdown();
}

/// A gateway latching as `latching` and a phone whose answer names a port nothing listens
/// on (as a phone behind a NAT names its private address). The phone sends first; returns
/// the media echoed back to it and the gateway's events.
fn sip(latching: Latching) -> (usize, Vec<String>) {
    sip_keyed(latching, true)
}

/// [`sip`] with SDES-SRTP keys (`sdes`) or DTLS-SRTP, whose handshake latches (ADR-082).
fn sip_keyed(latching: Latching, sdes: bool) -> (usize, Vec<String>) {
    let e = engine();
    let gw = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap())
        .unwrap()
        .config(move || {
            stats(rtc_config())
                .enable_sdes_srtp(sdes)
                .enable_ice(false)
                .set_latching(latching)
        });
    let phone = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap())
        .unwrap()
        .config(move || rtc_config().enable_sdes_srtp(sdes).enable_ice(false));
    let nowhere = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (hg, rxg) = probe(true);
    let (hp, rxp) = probe(false);
    let mut audio = None;
    let (pg, offer) = gw
        .create_offer(hg, |api| {
            audio = Some(api.add_media(MediaKind::Audio, Direction::SendRecv, None, None));
        })
        .unwrap();
    assert!(!offer.contains("ice-ufrag"), "{offer}");
    let (pp, answer) = phone.accept_offer(&offer, hp).unwrap();
    let port = phone.local_addr().unwrap().port();
    let wrong = nowhere.local_addr().unwrap().port();
    let answer = answer.replace(&format!("m=audio {port} "), &format!("m=audio {wrong} "));
    assert!(answer.contains(&format!("m=audio {wrong} ")), "{answer}");
    pg.accept_answer(&answer).unwrap();
    wait_connected(&rxp);
    let (back, _) = send(&pp, &rxp, audio.unwrap(), None, 2);
    let ev = events(&rxg);
    pp.close();
    pg.close();
    gw.close();
    phone.close();
    e.shutdown();
    (back, ev)
}

#[test]
fn latching_finds_the_phone() {
    let (back, ev) = sip(Latching::Once);
    assert!(back > 60, "{back}");
    assert_eq!(num(&ev, "latched"), 1);
}

#[test]
fn dtls_handshake_latches_onto_the_phone() {
    let (back, ev) = sip_keyed(Latching::Once, false);
    assert!(back > 60, "{back}");
    assert_eq!(num(&ev, "latched"), 1);
}

#[test]
fn without_latching_the_phone_is_not_heard() {
    let (back, ev) = sip(Latching::Off);
    assert_eq!(back, 0);
    assert_eq!(num(&ev, "latched"), 0);
}

#[test]
fn congestion_control_without_bundle() {
    let e = engine();
    let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap())
        .unwrap()
        .config(|| {
            stats(rtc_config())
                .set_bundle_policy(BundlePolicy::Disabled)
                .enable_bwe(Some(300_000))
        });
    a.bind_transport_socket(&e, "127.0.0.1:0".parse().unwrap())
        .unwrap();
    let b = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap())
        .unwrap()
        .config(|| stats(rtc_config()).enable_bwe(Some(300_000)));
    let (ha, rxa) = probe(false);
    let (hb, rxb) = probe(true);
    let (mut audio, mut video) = (None, None);
    let (pa, offer) = a
        .create_offer(ha, |api| {
            audio = Some(api.add_media(MediaKind::Audio, Direction::SendRecv, None, None));
            video = Some(api.add_media(MediaKind::Video, Direction::SendRecv, None, None));
        })
        .unwrap();
    assert!(!offer.contains("a=group:BUNDLE") && offer.contains("transport-cc"));
    let (_pb, answer) = b.accept_offer(&offer, hb).unwrap();
    assert!(!answer.contains("a=group:BUNDLE") && answer.contains("transport-cc"));
    pa.accept_answer(&answer).unwrap();
    wait_connected(&rxa);
    let (back, ev) = send(&pa, &rxa, audio.unwrap(), video, 3);
    assert!(back > 150, "{back}");
    // b echoes on both transports in one numbering space, which a recognises; a's
    // estimate rose from its start on the feedback of both.
    assert_eq!(stat(&ev, "twcc_spaces"), "Some(\"shared\")");
    let top = ev
        .iter()
        .filter_map(|e| {
            let i = e.find("EgressBitrateEstimate(")? + "EgressBitrateEstimate(".len();
            e[i..].split(')').next()?.parse::<u64>().ok()
        })
        .max()
        .unwrap_or(0);
    assert!(top > 1_000_000, "{top}");
    let evb = events(&rxb);
    assert_eq!(stat(&evb, "twcc_spaces"), "Some(\"shared\")");
    pa.close();
    a.close();
    b.close();
    e.shutdown();
}
