//! SDES-SRTP (RFC 4568) between two `Endpoint`s: `a=crypto` keys in the SDP instead of
//! DTLS-SRTP, every offered suite, renegotiation, and the refusals (data channels, SDES off,
//! browsers' DTLS offers left alone).
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
    // No data channels in an SDES session.
    let r = sdes.create_offer(Echo, |api| {
        api.add_media(MediaKind::Audio, Direction::SendRecv, None, None);
        api.add_channel("c");
    });
    assert!(matches!(r, Err(Error::Rtc(_))), "{r:?}");
    // An SDES offer to an endpoint with SDES off.
    let (_p, offer) = sdes
        .create_offer(Echo, |api| {
            api.add_media(MediaKind::Audio, Direction::SendRecv, None, None);
        })
        .unwrap();
    assert!(matches!(dtls.accept_offer(&offer, Echo), Err(Error::Sdp(_))));
    // An SDES offer whose lines are all unusable (MKIs).
    let mki: String = offer
        .lines()
        .map(|l| {
            if l.starts_with("a=crypto:") {
                format!("{l}|2^31|1:4\r\n")
            } else {
                format!("{l}\r\n")
            }
        })
        .collect();
    assert!(matches!(sdes.accept_offer(&mki, Echo), Err(Error::Sdp(_))));
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
