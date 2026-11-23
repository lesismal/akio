//! `akio` <-> `akio` over loopback: an `Endpoint` (full ICE) against an `RtcServer` (ICE-lite) and
//! against another `Endpoint`, with data channels and media.
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use akio::{Engine, Listener};
use akio_webrtc::{
    ChannelConfig, ChannelId, Codec, Direction, Endpoint, Frequency, MediaAdded, MediaData,
    MediaKind, MediaTime, Mid, Peer, PeerHandler, Reliability, RtcServer,
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
            reliable = Some(api.add_channel("reliable"));
            let mut cfg = ChannelConfig::new("lossy");
            cfg.ordered = false;
            cfg.reliability = Reliability::MaxRetransmits { retransmits: 0 };
            lossy = Some(api.add_channel_with_config(&cfg));
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
    let (late, offer) = client.open_channel(&ChannelConfig::new("late")).unwrap();
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
            audio = Some(api.add_media(MediaKind::Audio, Direction::SendRecv, None, None));
            video = Some(api.add_media(MediaKind::Video, Direction::SendRecv, None, None));
            api.add_channel("ctl");
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

#[test]
fn echoes_stay_in_order_while_an_app_thread_sends() {
    // The application thread drives the peer (sends) while the I/O thread drives it with the
    // echoes coming back: events and datagrams must keep the stack's order.
    let (e, _) = engine_with(None);
    let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let b = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let (tx, rx) = channel();
    let mut ch = None;
    let (pa, offer) = a
        .create_offer(Probe(Mutex::new(tx)), |api| {
            ch = Some(api.add_channel("o"));
        })
        .unwrap();
    let (_pb, answer) = b.accept_offer(&offer, Echo).unwrap();
    pa.accept_answer(&answer).unwrap();
    let ch = ch.unwrap();
    wait(&rx, "open", |g| matches!(g, Got::Open(..)));
    const N: usize = 500;
    let sender = {
        std::thread::spawn(move || {
            for i in 0..N {
                let m = (i as u32).to_be_bytes();
                while !pa.send(ch, &m, true).unwrap() {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        })
    };
    let mut next = 0u32;
    while (next as usize) < N {
        if let Got::Data(_, d, _) = wait(&rx, "echo", |g| matches!(g, Got::Data(..))) {
            assert_eq!(d, next.to_be_bytes(), "echo out of order");
            next += 1;
        }
    }
    sender.join().unwrap();
    a.close();
    b.close();
    e.shutdown();
    e.wait();
}

#[test]
fn srflx_candidate_from_a_only_stun_server() {
    let e = Arc::new(
        Engine::builder()
            .udp_client_threads(1)
            .listen(
                Listener::udp("127.0.0.1:0".parse().unwrap())
                    .threads(1)
                    .serve(akio_turn::StunServer::new()),
            )
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    let stun = e.local_addrs()[0];
    let ep = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let mapped = ep.gather_srflx(stun, T).unwrap();
    // On loopback the reflexive address is the socket itself.
    assert_eq!(Some(mapped), ep.local_addr());
    // A silent server times out.
    let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let err = ep
        .gather_srflx(dead.local_addr().unwrap(), Duration::from_millis(300))
        .unwrap_err();
    assert!(matches!(err, akio_webrtc::Error::Timeout), "{err}");
    ep.close();
    e.shutdown();
    e.wait();
}

#[test]
fn a_peer_that_never_connects_is_closed() {
    let server = RtcServer::new(vec!["127.0.0.1:9".parse().unwrap()])
        .connect_timeout(Some(Duration::from_millis(300)));
    let (e, _) = engine_with(Some(server.clone()));
    let ep = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let (tx, rx) = channel();
    let (_client, offer) = ep
        .create_offer(Echo, |api| {
            api.add_channel("x");
        })
        .unwrap();
    // The answer never reaches the client: nothing connects.
    let (_p, _answer) = server.accept_offer(&offer, Probe(Mutex::new(tx))).unwrap();
    assert_eq!(server.peers(), 1);
    wait(&rx, "closed", |g| matches!(g, Got::Closed));
    assert_eq!(server.peers(), 0);
    ep.close();
    e.shutdown();
    e.wait();
}

/// Peers are bounded with a safe default: offers just under and at the limit are accepted,
/// over it they fail with `TooManyPeers`, and closing a peer makes room again.
#[test]
fn peers_are_bounded() {
    assert_eq!(akio_webrtc::DEFAULT_MAX_PEERS, 1024);
    let server = RtcServer::new(vec!["127.0.0.1:9".parse().unwrap()]).max_peers(2);
    let (e, _) = engine_with(Some(server.clone()));
    let ep = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let offer = || {
        ep.create_offer(Echo, |api| {
            api.add_channel("x");
        })
        .unwrap()
        .1
    };
    let (p1, _) = server.accept_offer(&offer(), Echo).unwrap();
    let (_p2, _) = server.accept_offer(&offer(), Echo).unwrap();
    assert_eq!(server.peers(), 2);
    let err = server.accept_offer(&offer(), Echo).unwrap_err();
    assert!(matches!(err, akio_webrtc::Error::TooManyPeers), "{err}");
    assert_eq!(server.peers(), 2);
    p1.close();
    let t = Instant::now();
    while server.peers() > 1 && t.elapsed() < T {
        std::thread::sleep(Duration::from_millis(10));
    }
    server.accept_offer(&offer(), Echo).unwrap();
    // The endpoint side is bounded the same way.
    let small = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap())
        .unwrap()
        .max_peers(1);
    small
        .create_offer(Echo, |api| {
            api.add_channel("x");
        })
        .unwrap();
    assert!(matches!(
        small.create_offer(Echo, |api| {
            api.add_channel("x");
        }),
        Err(akio_webrtc::Error::TooManyPeers)
    ));
    small.close();
    ep.close();
    e.shutdown();
    e.wait();
}

/// Reports ICE state changes.
struct IceWatch(Mutex<Sender<akio_webrtc::IceConnectionState>>);
impl PeerHandler for IceWatch {
    fn on_ice_state(&mut self, _p: &Peer, s: akio_webrtc::IceConnectionState) {
        let _ = self.0.lock().unwrap().send(s);
    }
}

/// ICMP for a host candidate (RFC 8445 section 7.2.5.2.2, ADR-091): the endpoint's socket hears
/// the port unreachable its first check to a closed port draws (Linux `IP_RECVERR`, macOS the
/// loop's ICMP socket), the agent fails the pair at once and, with no other pair and the
/// remote's candidates complete, ICE fails (reported as `Disconnected`) well within a second,
/// where without ICMP the check would be sent seven times over about six seconds first.
#[test]
fn icmp_fails_a_host_check_to_a_closed_port() {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return;
    }
    let (e, _) = engine_with(None);
    let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let b = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let (tx, rx) = channel();
    let (pa, offer) = a
        .create_offer(IceWatch(Mutex::new(tx)), |api| {
            api.add_channel("c");
        })
        .unwrap();
    // B never hears of A's candidates (so it cannot check A, which would let A learn B's
    // real address from the check), and A hears only of a closed port.
    let no_candidates = |sdp: &str| -> String {
        sdp.lines()
            .filter(|l| !l.starts_with("a=candidate") && !l.starts_with("a=end-of-candidates"))
            .map(|l| format!("{l}\r\n"))
            .collect()
    };
    let (_pb, answer) = b.accept_offer(&no_candidates(&offer), Echo).unwrap();
    let closed = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut answer = no_candidates(&answer);
    answer.push_str(&format!(
        "a=candidate:1 1 udp 2130706431 127.0.0.1 {} typ host\r\na=end-of-candidates\r\n",
        closed.port()
    ));
    let t0 = Instant::now();
    pa.accept_answer(&answer).unwrap();
    let deadline = t0 + T;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let s = rx.recv_timeout(left).expect("ICE never failed");
        if s == akio_webrtc::IceConnectionState::Disconnected {
            break;
        }
    }
    let took = t0.elapsed();
    assert!(took < Duration::from_secs(1), "ICE failed after {took:?}");
    a.close();
    b.close();
    e.shutdown();
}
