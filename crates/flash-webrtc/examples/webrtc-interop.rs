//! Interop peer for `tools/interop/webrtc/run.sh` (against pion).
//!
//! ```text
//! webrtc-interop server <udp-addr> <http-addr>         ICE-lite RtcServer: data channel and media
//!                                                      echo; offers are POSTed to http://<http-addr>/
//! webrtc-interop client <http-addr> dc|media           an Endpoint (full ICE) offering to a server
//! webrtc-interop turn <udp-addr> <relay-ip> <user> <password>
//!                                                      a TURN server (realm "flash")
//! ```
//! Signalling is one HTTP POST: the offer as the body, the answer as the response body.
#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use flash::{Config, Engine, Listener};
use flash_turn::{TurnConfig, TurnServer, static_auth};
use flash_webrtc::{
    ChannelId, Codec, Direction, Endpoint, Frequency, KeyframeRequest, MediaData, MediaKind,
    MediaTime, Peer, PeerHandler, RtcServer,
};

/// Echoes data channel messages and media samples; answers a keyframe request with a text
/// message on the first data channel.
struct Echo {
    first: Option<ChannelId>,
    media: u64,
}

impl PeerHandler for Echo {
    fn on_channel_open(&mut self, _p: &Peer, id: ChannelId, label: &str) {
        eprintln!("server: channel {label:?} open");
        self.first.get_or_insert(id);
    }
    fn on_channel_data(&mut self, p: &Peer, id: ChannelId, data: &[u8], binary: bool) {
        let _ = p.send(id, data, binary);
    }
    fn on_media_data(&mut self, p: &Peer, d: &MediaData) {
        self.media += 1;
        let _ = p.write_media(d.mid, d.pt, Instant::now(), d.time, &d.data);
    }
    fn on_keyframe_request(&mut self, p: &Peer, r: &KeyframeRequest) {
        eprintln!("server: keyframe request {:?} on {}", r.kind, r.mid);
        if let Some(id) = self.first {
            let _ = p.send(id, b"keyframe-request", false);
        }
    }
    fn on_close(&mut self, _p: &Peer) {
        eprintln!("server: peer closed after {} media samples", self.media);
    }
}

fn read_http(s: &mut TcpStream) -> (String, String) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        let n = s.read(&mut tmp).expect("read");
        assert!(n > 0, "connection closed before the headers");
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let len = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    while buf.len() < head_end + len {
        let n = s.read(&mut tmp).expect("read");
        assert!(n > 0, "connection closed in the body");
        buf.extend_from_slice(&tmp[..n]);
    }
    (
        head,
        String::from_utf8_lossy(&buf[head_end..head_end + len]).to_string(),
    )
}

fn server(udp: SocketAddr, http: SocketAddr) {
    let rtc = RtcServer::new(vec![udp]);
    let engine = Engine::builder()
        .listen(Listener::udp(udp).threads(1).serve(rtc.clone()))
        .build()
        .expect("engine");
    engine.start().expect("start");
    let l = TcpListener::bind(http).expect("http bind");
    eprintln!("server: udp {udp}, signalling http://{http}/");
    for s in l.incoming() {
        let Ok(mut s) = s else { continue };
        let (_, offer) = read_http(&mut s);
        let resp = match rtc.accept_offer(
            &offer,
            Echo {
                first: None,
                media: 0,
            },
        ) {
            Ok((_p, answer)) => format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{answer}",
                answer.len()
            ),
            Err(e) => {
                let m = e.to_string();
                format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\n\r\n{m}",
                    m.len()
                )
            }
        };
        let _ = s.write_all(resp.as_bytes());
    }
}

fn post(http: &str, offer: &str) -> String {
    let mut s = TcpStream::connect(http).expect("connect signalling");
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {http}\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{offer}",
        offer.len()
    );
    s.write_all(req.as_bytes()).expect("write");
    let (head, body) = read_http(&mut s);
    assert!(
        head.starts_with("HTTP/1.1 2"),
        "signalling failed: {head}{body}"
    );
    body
}

#[derive(Debug)]
enum Got {
    Connected,
    Open(ChannelId),
    Data(Vec<u8>),
    Media(Vec<u8>),
}

struct Probe(Mutex<Sender<Got>>);

impl PeerHandler for Probe {
    fn on_connected(&mut self, _p: &Peer) {
        let _ = self.0.lock().expect("lock").send(Got::Connected);
    }
    fn on_channel_open(&mut self, _p: &Peer, id: ChannelId, _label: &str) {
        let _ = self.0.lock().expect("lock").send(Got::Open(id));
    }
    fn on_channel_data(&mut self, _p: &Peer, _id: ChannelId, data: &[u8], _binary: bool) {
        let _ = self.0.lock().expect("lock").send(Got::Data(data.to_vec()));
    }
    fn on_media_data(&mut self, _p: &Peer, d: &MediaData) {
        let _ = self
            .0
            .lock()
            .expect("lock")
            .send(Got::Media(d.data.to_vec()));
    }
}

fn client(http: &str, what: &str) {
    let engine = Arc::new(
        Engine::builder()
            .udp_client_threads(1)
            .build()
            .expect("engine"),
    );
    engine.start().expect("start");
    let ep = Endpoint::bind(&engine, "127.0.0.1:0".parse().expect("addr")).expect("bind");
    let (tx, rx) = channel();
    let mut audio = None;
    let (peer, offer) = ep
        .create_offer(Probe(Mutex::new(tx)), |api| {
            api.add_channel("interop");
            if what == "media" {
                audio = Some(api.add_media(MediaKind::Audio, Direction::SendRecv, None, None));
            }
        })
        .expect("offer");
    let answer = post(http, &offer);
    peer.accept_answer(&answer).expect("answer");
    let deadline = Instant::now() + Duration::from_secs(15);
    let next = || {
        rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("timed out")
    };
    let ch = loop {
        if let Got::Open(id) = next() {
            break id;
        }
    };
    eprintln!("client: connected={}, channel open", peer.is_connected());
    if what == "dc" {
        for i in 0..100 {
            let msg = format!("flash message {i}");
            // `Ok(false)`: the SCTP send buffer is full; wait for it to drain and retry.
            while !peer.send(ch, msg.as_bytes(), i % 2 == 0).expect("send") {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        let mut n = 0;
        while n < 100 {
            if let Got::Data(d) = next() {
                assert_eq!(d, format!("flash message {n}").into_bytes(), "ordered echo");
                n += 1;
            }
        }
        println!("ok: 100 data channel messages echoed in order");
    } else {
        let mid = audio.expect("audio");
        let pt = peer.payload_type(mid, Codec::Opus).expect("opus");
        let mut n = 0;
        let mut i = 0u64;
        while n < 50 {
            let payload = [0xfc, (i % 256) as u8, 0xaa, 0xbb];
            let t = MediaTime::new(i * 960, Frequency::FORTY_EIGHT_KHZ);
            peer.write_media(mid, pt, Instant::now(), t, &payload)
                .expect("write");
            i += 1;
            while let Ok(g) = rx.recv_timeout(Duration::from_millis(20)) {
                if let Got::Media(d) = g {
                    assert_eq!(&d[2..], &[0xaa, 0xbb]);
                    n += 1;
                }
            }
            assert!(Instant::now() < deadline, "media echo timed out ({n} back)");
        }
        println!("ok: {n} Opus samples echoed (sent {i})");
    }
    peer.close();
}

fn turn(udp: SocketAddr, relay: &str, user: &str, pass: &str) {
    let auth = static_auth("flash", [(user, pass)]);
    let cfg =
        TurnConfig::new("flash", auth, relay.parse().expect("relay ip")).allow_private_peers(true);
    let turn = TurnServer::new(cfg);
    let mut c = Config::default();
    c.udp_idle_timeout = Duration::from_secs(600);
    let engine = Arc::new(
        Engine::builder()
            .config(c)
            .listen(Listener::udp(udp).threads(1).serve(turn.clone()))
            .build()
            .expect("engine"),
    );
    turn.set_engine(&engine);
    eprintln!("turn: listening on {udp}, relaying from {relay}");
    engine.run().expect("run");
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("server") => server(a[2].parse().expect("udp"), a[3].parse().expect("http")),
        Some("client") => client(&a[2], &a[3]),
        Some("turn") => turn(a[2].parse().expect("udp"), &a[3], &a[4], &a[5]),
        _ => eprintln!("usage: webrtc-interop server|client|turn ..."),
    }
}
