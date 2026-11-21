//! Sessions without BUNDLE between two `Endpoint`s over loopback (ADR-068): an ICE agent,
//! DTLS association and SRTP keys per section, with the sections of one side on sockets of
//! their own.
#![allow(missing_docs)]

use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use only::Engine;
use only_webrtc::{
    BundlePolicy, ChannelId, Codec, Direction, Endpoint, Frequency, MediaData, MediaKind,
    MediaTime, Mid, Peer, PeerHandler, rtc_config,
};

const T: Duration = Duration::from_secs(10);

type Cfg = fn() -> only_webrtc::RtcConfig;

fn engine() -> Arc<Engine> {
    let e = Arc::new(Engine::builder().udp_client_threads(1).build().unwrap());
    e.start().unwrap();
    e
}

#[derive(Debug)]
enum Got {
    Connected,
    Open,
    Data(Vec<u8>),
    Media(Mid),
}

struct Probe(Mutex<Sender<Got>>);
impl PeerHandler for Probe {
    fn on_connected(&mut self, _p: &Peer) {
        let _ = self.0.lock().unwrap().send(Got::Connected);
    }
    fn on_channel_open(&mut self, _p: &Peer, _id: ChannelId, _label: &str) {
        let _ = self.0.lock().unwrap().send(Got::Open);
    }
    fn on_channel_data(&mut self, _p: &Peer, _id: ChannelId, d: &[u8], _b: bool) {
        let _ = self.0.lock().unwrap().send(Got::Data(d.to_vec()));
    }
    fn on_media_data(&mut self, _p: &Peer, d: &MediaData) {
        let _ = self.0.lock().unwrap().send(Got::Media(d.mid));
    }
}

struct Echo;
impl PeerHandler for Echo {
    fn on_media_data(&mut self, p: &Peer, d: &MediaData) {
        let _ = p.write_media(d.mid, d.pt, Instant::now(), d.time, &d.data);
    }
    fn on_channel_data(&mut self, p: &Peer, id: ChannelId, d: &[u8], b: bool) {
        let _ = p.send(id, d, b);
    }
}

fn wait(rx: &Receiver<Got>, what: &str, f: impl Fn(&Got) -> bool) {
    let deadline = Instant::now() + T;
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(g) if f(&g) => return,
            Ok(_) => {}
            Err(_) => panic!("timed out waiting for {what}"),
        }
    }
}

fn session(offerer_splits: bool) {
    let e = engine();
    let (cfg_a, cfg_b): (Cfg, Cfg) = if offerer_splits {
        (
            || rtc_config().set_bundle_policy(BundlePolicy::Disabled),
            rtc_config,
        )
    } else {
        (rtc_config, || {
            rtc_config().set_bundle_policy(BundlePolicy::Disabled)
        })
    };
    let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap())
        .unwrap()
        .config(cfg_a);
    let b = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap())
        .unwrap()
        .config(cfg_b);
    // The side that does not bundle has a socket per section.
    let splitter = if offerer_splits { &a } else { &b };
    let s1 = splitter
        .bind_transport_socket(&e, "127.0.0.1:0".parse().unwrap())
        .unwrap();
    let s2 = splitter
        .bind_transport_socket(&e, "127.0.0.1:0".parse().unwrap())
        .unwrap();
    let (tx, rx) = channel();
    let (mut audio, mut video, mut ch) = (None, None, None);
    let (pa, offer) = a
        .create_offer(Probe(Mutex::new(tx)), |api| {
            audio = Some(api.add_media(MediaKind::Audio, Direction::SendRecv, None, None));
            video = Some(api.add_media(MediaKind::Video, Direction::SendRecv, None, None));
            ch = Some(api.add_channel("c"));
        })
        .unwrap();
    assert_eq!(offer.contains("a=group:BUNDLE"), !offerer_splits, "{offer}");
    let (_pb, answer) = b.accept_offer(&offer, Echo).unwrap();
    assert!(!answer.contains("a=group:BUNDLE"), "{answer}");
    let sdp = if offerer_splits { &offer } else { &answer };
    for p in [s1.port(), s2.port()] {
        assert!(sdp.contains(&format!(" {p} typ host")), "{sdp}");
    }
    pa.accept_answer(&answer).unwrap();
    wait(&rx, "connected", |g| matches!(g, Got::Connected));
    wait(&rx, "open", |g| matches!(g, Got::Open));
    pa.send(ch.unwrap(), b"hello", true).unwrap();
    wait(&rx, "echo", |g| matches!(g, Got::Data(d) if d == b"hello"));
    let (audio, video) = (audio.unwrap(), video.unwrap());
    let (opus, vp8) = (
        pa.payload_type(audio, Codec::Opus).unwrap(),
        pa.payload_type(video, Codec::Vp8).unwrap(),
    );
    let (mut got_a, mut got_v) = (0, 0);
    for i in 0..100u64 {
        let ta = MediaTime::new(i * 960, Frequency::FORTY_EIGHT_KHZ);
        let tv = MediaTime::new(i * 3600, Frequency::NINETY_KHZ);
        pa.write_media(audio, opus, Instant::now(), ta, &[0xfc, i as u8])
            .unwrap();
        let key = if i == 0 { 0x10 } else { 0x11 };
        pa.write_media(video, vp8, Instant::now(), tv, &[key, i as u8, 9, 9])
            .unwrap();
        while let Ok(g) = rx.recv_timeout(Duration::from_millis(10)) {
            match g {
                Got::Media(m) if m == audio => got_a += 1,
                Got::Media(m) if m == video => got_v += 1,
                _ => {}
            }
        }
        if got_a >= 20 && got_v >= 20 {
            break;
        }
    }
    assert!(
        got_a >= 20 && got_v >= 20,
        "{got_a} audio, {got_v} video echoed"
    );
    pa.close();
    a.close();
    b.close();
    e.shutdown();
}

#[test]
fn offerer_without_bundle() {
    session(true);
}

#[test]
fn answerer_refusing_bundle() {
    session(false);
}
