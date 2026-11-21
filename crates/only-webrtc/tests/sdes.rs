//! SDES-SRTP (RFC 4568) between two `Endpoint`s: `a=crypto` keys in the SDP instead of
//! DTLS-SRTP, every offered suite, renegotiation, without ICE (SIP style, RTCP on its own
//! port), MKIs, data channels next to SDES media, and the refusals (SDES off, browsers' DTLS
//! offers left alone).
#![allow(missing_docs)]

use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use only::Engine;
use only_webrtc::{
    Codec, Direction, Endpoint, Error, Frequency, MediaData, MediaKind, MediaTime, Mid, Peer,
    PeerHandler, rtc_config,
};

const T: Duration = Duration::from_secs(10);

fn engine() -> Arc<Engine> {
    let e = Arc::new(Engine::builder().udp_client_threads(1).build().unwrap());
    e.start().unwrap();
    e
}

fn endpoint(e: &Engine, sdes: bool) -> Endpoint {
    Endpoint::bind(e, "127.0.0.1:0".parse().unwrap())
        .unwrap()
        .config(move || rtc_config().enable_sdes_srtp(sdes))
}

struct Echo;
impl PeerHandler for Echo {
    fn on_media_data(&mut self, p: &Peer, d: &MediaData) {
        let _ = p.write_media(d.mid, d.pt, Instant::now(), d.time, &d.data);
    }
}

#[derive(Debug)]
enum Got {
    Connected,
    Media(Mid, Vec<u8>),
}

struct Probe(Mutex<Sender<Got>>);
impl PeerHandler for Probe {
    fn on_connected(&mut self, _p: &Peer) {
        let _ = self.0.lock().unwrap().send(Got::Connected);
    }
    fn on_media_data(&mut self, _p: &Peer, d: &MediaData) {
        let _ = self
            .0
            .lock()
            .unwrap()
            .send(Got::Media(d.mid, d.data.to_vec()));
    }
}

fn wait_connected(rx: &Receiver<Got>) {
    let deadline = Instant::now() + T;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(Got::Connected) => return,
            Ok(_) => {}
            Err(_) => panic!("not connected"),
        }
    }
}

/// Opus packets from `p` on `mid` until one comes back.
fn echo(p: &Peer, rx: &Receiver<Got>, mid: Mid, tag: u8) {
    let pt = p.payload_type(mid, Codec::Opus).expect("opus");
    let start = Instant::now();
    for i in 0..500u64 {
        let pkt = [0xfc, tag, i as u8, 1, 2, 3];
        p.write_media(
            mid,
            pt,
            Instant::now(),
            MediaTime::new(i * 960, Frequency::FORTY_EIGHT_KHZ),
            &pkt,
        )
        .unwrap();
        while let Ok(g) = rx.recv_timeout(Duration::from_millis(20)) {
            if let Got::Media(m, d) = g {
                if m == mid && d.get(1) == Some(&tag) {
                    assert_eq!(&d[3..], &[1, 2, 3]);
                    return;
                }
            }
        }
        assert!(start.elapsed() < T, "no media echo");
    }
    panic!("no media echo");
}

fn crypto_lines(sdp: &str) -> Vec<&str> {
    sdp.lines().filter(|l| l.starts_with("a=crypto:")).collect()
}

/// Keeps only the `a=crypto` lines of the offer whose suite is `suite`.
fn only_suite(offer: &str, suite: &str) -> String {
    offer
        .lines()
        .filter(|l| !l.starts_with("a=crypto:") || l.split(' ').nth(1) == Some(suite))
        .map(|l| format!("{l}\r\n"))
        .collect()
}

#[test]
fn media_over_sdes_with_every_suite() {
    let e = engine();
    for suite in [
        "AEAD_AES_256_GCM",
        "AEAD_AES_128_GCM",
        "AES_256_CM_HMAC_SHA1_80",
        "AES_CM_128_HMAC_SHA1_80",
        "AES_CM_128_HMAC_SHA1_32",
    ] {
        let a = endpoint(&e, true);
        let b = endpoint(&e, true);
        let (tx, rx) = channel();
        let mut audio = None;
        let (pa, offer) = a
            .create_offer(Probe(Mutex::new(tx)), |api| {
                audio = Some(api.add_media(MediaKind::Audio, Direction::SendRecv, None, None));
                api.add_media(MediaKind::Video, Direction::SendRecv, None, None);
            })
            .unwrap();
        // An SDES offer: RTP/SAVPF, a line per suite in every section, no DTLS.
        assert!(offer.contains("m=audio 9 RTP/SAVPF "), "{offer}");
        assert!(!offer.contains("a=fingerprint") && !offer.contains("a=setup"));
        assert_eq!(crypto_lines(&offer).len(), 2 * 5, "{offer}");
        let (_pb, answer) = b.accept_offer(&only_suite(&offer, suite), Echo).unwrap();
        let lines = crypto_lines(&answer);
        assert_eq!(lines.len(), 2, "{answer}");
        assert!(lines.iter().all(|l| l.contains(suite)), "{answer}");
        assert!(answer.contains("RTP/SAVPF") && !answer.contains("a=fingerprint"));
        pa.accept_answer(&answer).unwrap();
        wait_connected(&rx);
        echo(&pa, &rx, audio.unwrap(), 1);
        pa.close();
        a.close();
        b.close();
    }
    e.shutdown();
}

#[test]
fn sdes_renegotiation_keeps_the_keys() {
    let e = engine();
    let a = endpoint(&e, true);
    let b = endpoint(&e, true);
    let (tx, rx) = channel();
    let mut audio = None;
    let (pa, offer) = a
        .create_offer(Probe(Mutex::new(tx)), |api| {
            audio = Some(api.add_media(MediaKind::Audio, Direction::SendRecv, None, None));
        })
        .unwrap();
    let (pb, answer) = b.accept_offer(&offer, Echo).unwrap();
    pa.accept_answer(&answer).unwrap();
    wait_connected(&rx);
    let audio = audio.unwrap();
    echo(&pa, &rx, audio, 1);
    // A second offer from `a` (a video line added): the same keys, media goes on.
    let offer2 = pa
        .renegotiate(|api| {
            api.add_media(MediaKind::Video, Direction::SendRecv, None, None);
        })
        .unwrap()
        .expect("an offer");
    assert_eq!(
        crypto_lines(&offer2)[..5],
        crypto_lines(&offer)[..5],
        "{offer2}"
    );
    let answer2 = pb.accept_offer(&offer2).unwrap();
    assert_eq!(crypto_lines(&answer2)[0], crypto_lines(&answer)[0]);
    pa.accept_answer(&answer2).unwrap();
    echo(&pa, &rx, audio, 2);
    // An offer from `b` the other way.
    let offer3 = pb
        .renegotiate(|api| api.ice_restart(true))
        .unwrap()
        .expect("an offer");
    assert!(offer3.contains("a=crypto:") && !offer3.contains("a=fingerprint"));
    let answer3 = pa.accept_offer(&offer3).unwrap();
    pb.accept_answer(&answer3).unwrap();
    echo(&pa, &rx, audio, 3);
    pa.close();
    a.close();
    b.close();
    e.shutdown();
}

#[test]
fn sdes_refusals_and_dtls_unchanged() {
    let e = engine();
    let sdes = endpoint(&e, true);
    let dtls = endpoint(&e, false);
    // Data channels next to SDES media: DTLS in the application section only.
    let (_pc, offer) = sdes
        .create_offer(Echo, |api| {
            api.add_media(MediaKind::Audio, Direction::SendRecv, None, None);
            api.add_channel("c");
        })
        .unwrap();
    let app = &offer[offer.find("m=application").expect("an application section")..];
    let media = &offer[..offer.find("m=application").unwrap()];
    assert!(
        app.contains("a=fingerprint:") && !app.contains("a=crypto:"),
        "{offer}"
    );
    assert!(
        media.contains("a=crypto:") && !media.contains("a=fingerprint:"),
        "{offer}"
    );
    // An SDES offer to an endpoint with SDES off.
    let (_p, offer) = sdes
        .create_offer(Echo, |api| {
            api.add_media(MediaKind::Audio, Direction::SendRecv, None, None);
        })
        .unwrap();
    assert!(matches!(
        dtls.accept_offer(&offer, Echo),
        Err(Error::Sdp(_))
    ));
    // An SDES offer whose lines are all unusable (a session parameter changing the
    // transform).
    let kdr: String = offer
        .lines()
        .map(|l| {
            if l.starts_with("a=crypto:") {
                format!("{l} KDR=1\r\n")
            } else {
                format!("{l}\r\n")
            }
        })
        .collect();
    assert!(matches!(sdes.accept_offer(&kdr, Echo), Err(Error::Sdp(_))));
    // A DTLS-SRTP offer (a browser's) to an SDES endpoint: answered with DTLS-SRTP, no
    // a=crypto, and the session works with data channels.
    let (tx, rx) = channel();
    let (pd, offer) = dtls
        .create_offer(Probe(Mutex::new(tx)), |api| {
            api.add_media(MediaKind::Audio, Direction::SendRecv, None, None);
            api.add_channel("c");
        })
        .unwrap();
    assert!(!offer.contains("a=crypto"));
    let (_ps, answer) = sdes.accept_offer(&offer, Echo).unwrap();
    assert!(!answer.contains("a=crypto"), "{answer}");
    assert!(answer.contains("a=fingerprint") && answer.contains("UDP/TLS/RTP/SAVPF"));
    pd.accept_answer(&answer).unwrap();
    wait_connected(&rx);
    pd.close();
    sdes.close();
    dtls.close();
    e.shutdown();
}

#[derive(Debug)]
enum Seen {
    Connected,
    Open,
    Data(Vec<u8>),
    Media,
}

struct Watch(Mutex<Sender<Seen>>);
impl PeerHandler for Watch {
    fn on_connected(&mut self, _p: &Peer) {
        let _ = self.0.lock().unwrap().send(Seen::Connected);
    }
    fn on_channel_open(&mut self, _p: &Peer, _id: only_webrtc::ChannelId, _label: &str) {
        let _ = self.0.lock().unwrap().send(Seen::Open);
    }
    fn on_channel_data(&mut self, _p: &Peer, _id: only_webrtc::ChannelId, d: &[u8], _b: bool) {
        let _ = self.0.lock().unwrap().send(Seen::Data(d.to_vec()));
    }
    fn on_media_data(&mut self, _p: &Peer, _d: &MediaData) {
        let _ = self.0.lock().unwrap().send(Seen::Media);
    }
}

struct EchoAll;
impl PeerHandler for EchoAll {
    fn on_media_data(&mut self, p: &Peer, d: &MediaData) {
        let _ = p.write_media(d.mid, d.pt, Instant::now(), d.time, &d.data);
    }
    fn on_channel_data(&mut self, p: &Peer, id: only_webrtc::ChannelId, d: &[u8], b: bool) {
        let _ = p.send(id, d, b);
    }
}

fn seen(rx: &Receiver<Seen>, what: &str, f: impl Fn(&Seen) -> bool) {
    let deadline = Instant::now() + T;
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(g) if f(&g) => return,
            Ok(_) => {}
            Err(_) => panic!("timed out waiting for {what}"),
        }
    }
}

#[test]
fn sdes_without_ice_between_endpoints() {
    // SIP style: no ICE, media to c= / m= port, RTCP on the endpoints' RTCP sockets; MKIs.
    let e = engine();
    let plain = || {
        rtc_config()
            .enable_sdes_srtp(true)
            .enable_ice(false)
            .set_sdes_mki_length(4)
            .set_rtcp_mux_policy(only_webrtc::RtcpMuxPolicy::Off)
    };
    let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap())
        .unwrap()
        .config(plain);
    let a_rtcp = a.bind_rtcp(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let b = endpoint(&e, true);
    let b_rtcp = b.bind_rtcp(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let (tx, rx) = channel();
    let mut audio = None;
    let (pa, offer) = a
        .create_offer(Probe(Mutex::new(tx)), |api| {
            audio = Some(api.add_media(MediaKind::Audio, Direction::SendRecv, None, None));
        })
        .unwrap();
    let port = a.local_addr().unwrap().port();
    assert!(
        offer.contains(&format!("m=audio {port} RTP/SAVPF")),
        "{offer}"
    );
    assert!(offer.contains("c=IN IP4 127.0.0.1"), "{offer}");
    assert!(
        offer.contains(&format!("a=rtcp:{} IN IP4 127.0.0.1", a_rtcp.port())),
        "{offer}"
    );
    assert!(
        !offer.contains("a=ice-ufrag") && offer.contains("|1:4"),
        "{offer}"
    );
    let (_pb, answer) = b.accept_offer(&offer, Echo).unwrap();
    assert!(!answer.contains("a=ice-ufrag"), "{answer}");
    assert!(
        answer.contains(&format!("a=rtcp:{} IN IP4 127.0.0.1", b_rtcp.port())),
        "{answer}"
    );
    pa.accept_answer(&answer).unwrap();
    wait_connected(&rx);
    echo(&pa, &rx, audio.unwrap(), 9);
    pa.close();
    a.close();
    b.close();
    e.shutdown();
}

#[test]
fn sdes_media_and_data_channels_between_endpoints() {
    let e = engine();
    let a = endpoint(&e, true);
    let b = endpoint(&e, true);
    let (tx, rx) = channel();
    let (mut audio, mut ch) = (None, None);
    let (pa, offer) = a
        .create_offer(Watch(Mutex::new(tx)), |api| {
            audio = Some(api.add_media(MediaKind::Audio, Direction::SendRecv, None, None));
            ch = Some(api.add_channel("c"));
        })
        .unwrap();
    let (_pb, answer) = b.accept_offer(&offer, EchoAll).unwrap();
    pa.accept_answer(&answer).unwrap();
    seen(&rx, "connected", |g| matches!(g, Seen::Connected));
    seen(&rx, "open", |g| matches!(g, Seen::Open));
    pa.send(ch.unwrap(), b"over dtls", true).unwrap();
    seen(
        &rx,
        "echo",
        |g| matches!(g, Seen::Data(d) if d == b"over dtls"),
    );
    let (audio, pt) = (
        audio.unwrap(),
        pa.payload_type(audio.unwrap(), Codec::Opus).unwrap(),
    );
    for i in 0..50u64 {
        let t = MediaTime::new(i * 960, Frequency::FORTY_EIGHT_KHZ);
        pa.write_media(audio, pt, Instant::now(), t, &[0xfc, 1, 2])
            .unwrap();
        std::thread::sleep(Duration::from_millis(5));
    }
    seen(&rx, "media echo", |g| matches!(g, Seen::Media));
    pa.close();
    a.close();
    b.close();
    e.shutdown();
}
