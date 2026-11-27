//! An SFU over loopback (ADR-187): `Endpoint` publishers send audio and video to an
//! `RtcServer` whose peers run in RTP mode, each with a configuration of its own (the codecs
//! picked for the stream); the server writes every RTP packet as it arrives to the viewers'
//! peers (`Peer::write_rtp`), and `Endpoint` viewers get the frames intact, from one
//! publisher and then from the one that replaced it. Keyframe requests go from the viewers
//! through the server to the publisher, and the server caps the publisher with REMB.
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use akio::{Engine, Listener};
use akio_webrtc::{
    Codec, Direction, Endpoint, Event, Frequency, KeyframeRequest, KeyframeRequestKind, MediaData,
    MediaKind, MediaTime, Mid, Peer, PeerHandler, RtcConfig, RtcServer, RtpPacket,
};

const T: Duration = Duration::from_secs(10);
const FRAME: usize = 2500;

/// The stream's codecs: what the server answers its publisher and its viewers with.
fn picked() -> RtcConfig {
    akio_webrtc::rtc_config()
        .clear_codecs()
        .enable_opus(true)
        .enable_vp8(true)
}

/// The viewers' peers on the server: (peer, audio mid, video mid).
type Viewers = Arc<Mutex<Vec<(Peer, Mid, Mid)>>>;
/// The publisher being forwarded: its peer on the server and its video mid.
type Current = Arc<Mutex<Option<(Peer, Mid)>>>;

/// A publisher's peer on the server: forwards its packets while it is the current one.
struct Forward {
    viewers: Viewers,
    current: Current,
}

impl PeerHandler for Forward {
    fn on_connected(&mut self, p: &Peer) {
        p.set_receive_bitrate_cap(Some(300_000));
    }
    fn on_rtp(&mut self, p: &Peer, pkt: &RtpPacket) {
        let current = self.current.lock().unwrap().as_ref().map(|c| c.0.id());
        if current != Some(p.id()) {
            return;
        }
        for (v, audio, video) in self.viewers.lock().unwrap().iter() {
            let mid = match pkt.codec.map(Codec::kind) {
                Some(MediaKind::Audio) => *audio,
                _ => *video,
            };
            v.write_rtp(mid, pkt).unwrap();
        }
    }
}

/// A viewer's peer on the server: its keyframe requests go to the current publisher.
struct ViewerSide {
    current: Current,
}

impl PeerHandler for ViewerSide {
    fn on_keyframe_request(&mut self, _p: &Peer, _req: &KeyframeRequest) {
        if let Some((p, mid)) = self.current.lock().unwrap().as_ref() {
            p.request_keyframe(*mid, KeyframeRequestKind::Pli).unwrap();
        }
    }
}

#[derive(Debug)]
enum Got {
    Connected,
    Frame(Vec<u8>),
    Audio(Vec<u8>),
    Keyframe,
    Remb(String),
}

/// The client side of a publisher or a viewer.
struct Client {
    tx: Mutex<Sender<Got>>,
}

impl Client {
    fn send(&self, g: Got) {
        let _ = self.tx.lock().unwrap().send(g);
    }
}

impl PeerHandler for Client {
    fn on_connected(&mut self, _p: &Peer) {
        self.send(Got::Connected);
    }
    fn on_media_data(&mut self, _p: &Peer, d: &MediaData) {
        if d.codec.map(Codec::kind) == Some(MediaKind::Video) {
            self.send(Got::Frame(d.data.to_vec()));
        } else {
            self.send(Got::Audio(d.data.to_vec()));
        }
    }
    fn on_keyframe_request(&mut self, _p: &Peer, _req: &KeyframeRequest) {
        self.send(Got::Keyframe);
    }
    fn on_event(&mut self, _p: &Peer, e: &Event) {
        let s = format!("{e:?}");
        if s.contains("RemoteBitrateEstimate") {
            self.send(Got::Remb(s));
        }
    }
}

fn wait(rx: &Receiver<Got>, what: &str, mut f: impl FnMut(&Got) -> bool) -> Got {
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

fn frame(publisher: u8, i: u64) -> Vec<u8> {
    let mut f: Vec<u8> = (0..FRAME as u32).map(|k| (k * 31) as u8).collect();
    f[0] = if i == 0 { 0x10 } else { 0x11 };
    f[1] = i as u8;
    f[2] = publisher;
    f
}

struct Pub {
    _ep: Endpoint,
    peer: Peer,
    rx: Receiver<Got>,
    audio: Mid,
    video: Mid,
}

/// A publisher endpoint whose offer the server answers with the picked codecs, in RTP mode.
fn publish(e: &Engine, server: &RtcServer, viewers: &Viewers, current: &Current) -> Pub {
    let ep = Endpoint::bind(e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let (tx, rx) = channel();
    let mut mids = None;
    let (peer, offer) = ep
        .create_offer(Client { tx: Mutex::new(tx) }, |api| {
            mids = Some((
                api.add_media(MediaKind::Audio, Direction::SendOnly, None, None),
                api.add_media(MediaKind::Video, Direction::SendOnly, None, None),
            ));
        })
        .unwrap();
    // The publisher offers every codec it has; the answer has the picked ones only.
    assert!(offer.contains("H264"), "{offer}");
    let (sp, answer) = server
        .accept_offer_with(
            picked().set_rtp_mode(true),
            &offer,
            Forward {
                viewers: viewers.clone(),
                current: current.clone(),
            },
        )
        .unwrap();
    assert!(
        answer.contains("VP8") && !answer.contains("H264"),
        "{answer}"
    );
    peer.accept_answer(&answer).unwrap();
    wait(&rx, "publisher connected", |g| matches!(g, Got::Connected));
    let (audio, video) = mids.unwrap();
    *current.lock().unwrap() = Some((sp, video));
    Pub {
        _ep: ep,
        peer,
        rx,
        audio,
        video,
    }
}

#[test]
fn sfu_forwards_publishers_to_viewers() {
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr: SocketAddr = probe.local_addr().unwrap();
    drop(probe);
    let server = RtcServer::new(vec![addr]);
    let e = Arc::new(
        Engine::builder()
            .udp_client_threads(1)
            .listen(Listener::udp(addr).threads(1).serve(server.clone()))
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    let viewers: Viewers = Arc::new(Mutex::new(Vec::new()));
    let current: Current = Arc::new(Mutex::new(None));

    let p1 = publish(&e, &server, &viewers, &current);
    // The server caps the publisher with REMB as soon as it is connected.
    let Got::Remb(remb) = wait(&p1.rx, "REMB", |g| matches!(g, Got::Remb(_))) else {
        unreachable!()
    };
    assert!(remb.contains("bitrate: 300000"), "{remb}");

    // Two viewers, answered with the stream's codecs.
    let mut vs = Vec::new();
    for _ in 0..2 {
        let ep = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
        let (tx, rx) = channel();
        let mut mids = None;
        let (peer, offer) = ep
            .create_offer(Client { tx: Mutex::new(tx) }, |api| {
                mids = Some((
                    api.add_media(MediaKind::Audio, Direction::RecvOnly, None, None),
                    api.add_media(MediaKind::Video, Direction::RecvOnly, None, None),
                ));
            })
            .unwrap();
        let (audio, video) = mids.unwrap();
        let (sp, answer) = server
            .accept_offer_with(
                picked(),
                &offer,
                ViewerSide {
                    current: current.clone(),
                },
            )
            .unwrap();
        assert!(
            answer.contains("VP8") && !answer.contains("H264"),
            "{answer}"
        );
        peer.accept_answer(&answer).unwrap();
        wait(&rx, "viewer connected", |g| matches!(g, Got::Connected));
        viewers.lock().unwrap().push((sp, audio, video));
        vs.push((ep, peer, rx, video));
    }

    // Frames from publisher 1, then from publisher 2 after it replaced the first: each
    // reaches both viewers whole, one hop later.
    let send = |p: &Pub, id: u8, n: u64| {
        let opus = p.peer.payload_type(p.audio, Codec::Opus).unwrap();
        let vp8 = p.peer.payload_type(p.video, Codec::Vp8).unwrap();
        for i in 0..n {
            let t = MediaTime::new(i * 3000, Frequency::NINETY_KHZ);
            let f = frame(id, i);
            p.peer
                .write_media(p.video, vp8, Instant::now(), t, &f)
                .unwrap();
            let t = MediaTime::new(i * 960, Frequency::FORTY_EIGHT_KHZ);
            p.peer
                .write_media(p.audio, opus, Instant::now(), t, &[0xfc, id, i as u8])
                .unwrap();
            for (_, _, rx, _) in &vs {
                let got = wait(rx, "frame", |g| matches!(g, Got::Frame(_)));
                let Got::Frame(d) = got else { unreachable!() };
                assert_eq!(d, f, "frame {i} of publisher {id}");
                wait(
                    rx,
                    "audio",
                    |g| matches!(g, Got::Audio(a) if a[..] == [0xfc, id, i as u8]),
                );
            }
        }
    };
    send(&p1, 1, 30);

    // A viewer asks for a keyframe: the server passes it to the publisher.
    let (_, vp, _, vmid) = &vs[0];
    vp.request_keyframe(*vmid, KeyframeRequestKind::Pli)
        .unwrap();
    wait(&p1.rx, "keyframe request", |g| matches!(g, Got::Keyframe));

    let p2 = publish(&e, &server, &viewers, &current);
    send(&p2, 2, 30);
    assert_eq!(server.peers(), 4);
    e.shutdown();
    e.wait();
}
