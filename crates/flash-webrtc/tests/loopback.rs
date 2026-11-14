//! flash <-> flash over loopback: an `Endpoint` (full ICE) against an `RtcServer` (ICE-lite) and
//! against another `Endpoint`, with data channels and media.
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use flash::{Engine, Listener};
use flash_webrtc::str0m::format::Codec;
use flash_webrtc::{
    ChannelConfig, ChannelId, Direction, Endpoint, Frequency, MediaAdded, MediaData, MediaKind,
    MediaTime, Mid, Peer, PeerHandler, Reliability, RtcServer,
};

const T: Duration = Duration::from_secs(10);

fn engine_with(server: Option<RtcServer>) -> (Arc<Engine>, Option<SocketAddr>) {
    let mut b = Engine::builder().udp_client_threads(1);
    if let Some(s) = server {
        b = b.listen(
            Listener::udp("127.0.0.1:0".parse().unwrap())
                .threads(1)
                .serve(s),
        );
    }
    let e = Arc::new(b.build().unwrap());
    e.start().unwrap();
    let addr = e.local_addrs().first().copied();
    (e, addr)
}

/// Echoes data channel messages and media samples.
struct Echo;
impl PeerHandler for Echo {
    fn on_channel_data(&mut self, p: &Peer, id: ChannelId, data: &[u8], binary: bool) {
        p.send(id, data, binary).unwrap();
    }
    fn on_media_data(&mut self, p: &Peer, d: &MediaData) {
        let _ = p.write_media(d.mid, d.pt, Instant::now(), d.time, &d.data);
    }
}

#[derive(Debug)]
enum Got {
    Open(ChannelId, String),
    Data(ChannelId, Vec<u8>, bool),
    Media(Mid, Vec<u8>),
    MediaAdded,
    Connected,
    Closed,
}

struct Probe(Mutex<Sender<Got>>);
impl PeerHandler for Probe {
    fn on_connected(&mut self, _p: &Peer) {
        let _ = self.0.lock().unwrap().send(Got::Connected);
    }
    fn on_channel_open(&mut self, _p: &Peer, id: ChannelId, label: &str) {
        let _ = self.0.lock().unwrap().send(Got::Open(id, label.to_owned()));
    }
    fn on_channel_data(&mut self, _p: &Peer, id: ChannelId, data: &[u8], binary: bool) {
        let _ = self
            .0
            .lock()
            .unwrap()
            .send(Got::Data(id, data.to_vec(), binary));
    }
    fn on_media_added(&mut self, _p: &Peer, m: &MediaAdded) {
        let _ = (m.mid, self.0.lock().unwrap().send(Got::MediaAdded));
    }
    fn on_media_data(&mut self, _p: &Peer, d: &MediaData) {
        let _ = self
            .0
            .lock()
            .unwrap()
            .send(Got::Media(d.mid, d.data.to_vec()));
    }
    fn on_close(&mut self, _p: &Peer) {
        let _ = self.0.lock().unwrap().send(Got::Closed);
    }
}

fn wait<F: FnMut(&Got) -> bool>(rx: &std::sync::mpsc::Receiver<Got>, what: &str, mut f: F) -> Got {
    let deadline = Instant::now() + T;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let g = rx
            .recv_timeout(left)
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
        if f(&g) {
            return g;
        }
    }
}

#[test]
fn data_channels_endpoint_to_ice_lite_server() {
    // The server's host candidate is its listener address.
    let probe_port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = probe_port.local_addr().unwrap().port();
    drop(probe_port);
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let server = RtcServer::new(vec![addr]);
    let e = Arc::new(
        Engine::builder()
            .udp_client_threads(1)
            .listen(Listener::udp(addr).threads(1).serve(server.clone()))
            .build()
            .unwrap(),
    );
    e.start().unwrap();

    let ep = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let (tx, rx) = channel();
    let mut reliable = None;
    let mut lossy = None;
    let (client, offer) = ep
        .create_offer(Probe(Mutex::new(tx)), |api| {
            reliable = Some(api.add_channel("reliable".into()));
            lossy = Some(api.add_channel_with_config(ChannelConfig {
                label: "lossy".into(),
                ordered: false,
                reliability: Reliability::MaxRetransmits { retransmits: 0 },
                ..Default::default()
            }));
        })
        .unwrap();
    assert!(offer.contains("a=candidate"), "{offer}");
    let (_sp, answer) = server.accept_offer(&offer, Echo).unwrap();
    assert!(answer.contains("a=ice-lite"), "{answer}");
    client.accept_answer(&answer).unwrap();
    wait(&rx, "connected", |g| matches!(g, Got::Connected));
    let (reliable, lossy) = (reliable.unwrap(), lossy.unwrap());
    let mut opened = Vec::new();
    while opened.len() < 2 {
        if let Got::Open(id, label) = wait(&rx, "open", |g| matches!(g, Got::Open(..))) {
            opened.push((id, label));
        }
    }
    assert!(opened.contains(&(reliable, "reliable".into())));
    assert!(opened.contains(&(lossy, "lossy".into())));

    // Text and binary, both channels; large messages go through SCTP fragmentation.
    let big: Vec<u8> = (0..60_000u32).map(|i| i as u8).collect();
    client.send(reliable, b"hello", false).unwrap();
    client.send(reliable, &big, true).unwrap();
    client.send(lossy, b"fast", true).unwrap();
    let mut seen = 0;
    while seen < 3 {
        if let Got::Data(id, d, bin) = wait(&rx, "echo", |g| matches!(g, Got::Data(..))) {
            match (id == reliable, d.len()) {
                (true, 5) => assert_eq!((d.as_slice(), bin), (&b"hello"[..], false)),
                (true, _) => assert_eq!((d, bin), (big.clone(), true)),
                (false, _) => assert_eq!(d, b"fast"),
            }
            seen += 1;
        }
    }

    // A channel opened later needs no renegotiation.
    let (late, offer) = client
        .open_channel(ChannelConfig {
            label: "late".into(),
            ..Default::default()
        })
        .unwrap();
    assert!(offer.is_none());
    wait(
        &rx,
        "late open",
        |g| matches!(g, Got::Open(id, _) if *id == late),
    );
    client.send(late, b"again", true).unwrap();
    wait(
        &rx,
        "late echo",
        |g| matches!(g, Got::Data(id, d, _) if *id == late && d == b"again"),
    );
    assert_eq!(server.peers(), 1);

    client.close();
    wait(&rx, "closed", |g| matches!(g, Got::Closed));
    assert_eq!(ep.peers(), 0);
    // The server notices the DTLS close (or consent loss) and drops its peer.
    let t = Instant::now();
    while server.peers() > 0 && t.elapsed() < Duration::from_secs(40) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(server.peers(), 0);
    e.shutdown();
    e.wait();
}

#[test]
fn media_echo_between_two_full_ice_endpoints() {
    let (e, _) = engine_with(None);
    let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let b = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let (tx, rx) = channel();
    let mut audio = None;
    let mut video = None;
    let (pa, offer) = a
        .create_offer(Probe(Mutex::new(tx)), |api| {
            audio = Some(api.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None));
            video = Some(api.add_media(MediaKind::Video, Direction::SendRecv, None, None, None));
            api.add_channel("ctl".into());
        })
        .unwrap();
    let (_pb, answer) = b.accept_offer(&offer, Echo).unwrap();
    assert!(!answer.contains("ice-lite"));
    pa.accept_answer(&answer).unwrap();
    wait(&rx, "connected", |g| matches!(g, Got::Connected));
    let (audio, video) = (audio.unwrap(), video.unwrap());
    let opus = pa
        .payload_type(audio, Codec::Opus)
        .expect("opus negotiated");
    let vp8 = pa.payload_type(video, Codec::Vp8).expect("vp8 negotiated");

    // Opus packets: one sample each; VP8 frames bigger than an MTU get split and reassembled.
    let start = Instant::now();
    let frame: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
    let mut got_audio = false;
    let mut got_video = false;
    for i in 0..200u64 {
        let pkt = [0xfc, i as u8, 1, 2, 3];
        pa.write_media(
            audio,
            opus,
            Instant::now(),
            MediaTime::new(i * 960, Frequency::FORTY_EIGHT_KHZ),
            &pkt,
        )
        .unwrap();
        let mut f = frame.clone();
        f[0] = 0x10; // a VP8 keyframe-ish first byte
        pa.write_media(
            video,
            vp8,
            Instant::now(),
            MediaTime::new(i * 3000, Frequency::NINETY_KHZ),
            &f,
        )
        .unwrap();
        while let Ok(g) = rx.recv_timeout(Duration::from_millis(20)) {
            match g {
                Got::Media(m, d) if m == audio => {
                    assert_eq!(&d[2..], &[1, 2, 3]);
                    got_audio = true;
                }
                Got::Media(m, d) if m == video => {
                    assert_eq!(d.len(), frame.len());
                    assert_eq!(&d[1..], &frame[1..]);
                    got_video = true;
                }
                _ => {}
            }
        }
        if got_audio && got_video {
            break;
        }
        assert!(start.elapsed() < T, "no media echo");
    }
    assert!(got_audio && got_video);
    pa.close();
    a.close();
    b.close();
    e.shutdown();
    e.wait();
}
