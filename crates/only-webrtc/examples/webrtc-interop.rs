//! Interop peer for `tools/interop/webrtc/run.sh` (against pion).
//!
//! ```text
//! webrtc-interop server <udp-addr> <http-addr>         ICE-lite RtcServer: data channel and media
//!                                                      echo; offers are POSTed to http://<http-addr>/
//! webrtc-interop client <http-addr> dc|media           an Endpoint (full ICE) offering to a server
//! webrtc-interop client <http-addr> dc-relay <turn> <user> <password>
//!                                                      the same offering relayed candidates only
//!                                                      (an allocation on the TURN server at <turn>)
//! webrtc-interop client <http-addr> dc-tcp             the same offering its passive ICE-TCP
//!                                                      candidate only
//! webrtc-interop client <http-addr> simulcast          offers VP8 simulcast h/m/l and a "stats"
//!                                                      channel; checks the answerer got all three
//! webrtc-interop turn <udp-addr> <relay-ip> <user> <password> [<tcp-addr> [<tls-addr>]]
//!                                                      a TURN server (realm "only"), also on TCP
//!                                                      and TLS (self-signed) when given
//! webrtc-interop turn-client udp|tcp|tls <server> <user> <password> [<relay-port-check>]
//!                                                      the only_turn client: allocate, then 20
//!                                                      datagrams through a channel to a local
//!                                                      echo peer and back
//! ```
//! Signalling is one HTTP POST: the offer as the body, the answer as the response body.
#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use only::tls;
use only::{Config, Engine, Listener};
use only_turn::client::{Client, ClientConfig, ClientEvent, ClientState};
use only_turn::framing::FrameReader;
use only_turn::{TurnConfig, TurnServer, static_auth};
use only_webrtc::{
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

/// Keeps only the candidate lines `keep` accepts.
fn filter_candidates(sdp: &str, keep: impl Fn(&str) -> bool) -> String {
    sdp.lines()
        .filter(|l| !l.starts_with("a=candidate") || keep(l))
        .map(|l| format!("{l}\r\n"))
        .collect()
}

fn client(http: &str, what: &str, args: &[String]) {
    let engine = Arc::new(
        Engine::builder()
            .udp_client_threads(1)
            .client_threads(1)
            .build()
            .expect("engine"),
    );
    engine.start().expect("start");
    let ep = Endpoint::bind(&engine, "127.0.0.1:0".parse().expect("addr")).expect("bind");
    if what == "dc-relay" {
        let turn: SocketAddr = args[0].parse().expect("turn addr");
        let r = ep
            .gather_relay(turn, &args[1], &args[2], Duration::from_secs(10))
            .expect("allocate");
        eprintln!("client: relayed candidate {r}");
    }
    if what == "dc-tcp" {
        let p = ep
            .listen_tcp(&engine, "127.0.0.1:0".parse().expect("addr"))
            .expect("listen tcp");
        eprintln!("client: passive ICE-TCP candidate {p}");
    }
    let (tx, rx) = channel();
    let mut audio = None;
    let mut video = None;
    let (peer, offer) = ep
        .create_offer(Probe(Mutex::new(tx)), |api| {
            api.add_channel(if what == "simulcast" {
                "stats"
            } else {
                "interop"
            });
            if what == "media" {
                audio = Some(api.add_media(MediaKind::Audio, Direction::SendRecv, None, None));
            }
            if what == "simulcast" {
                video = Some(
                    api.add_simulcast_media(
                        MediaKind::Video,
                        Direction::SendOnly,
                        &["h", "m", "l"],
                        None,
                        None,
                    )
                    .expect("simulcast"),
                );
            }
        })
        .expect("offer");
    let offer = match what {
        "dc-relay" => filter_candidates(&offer, |l| l.contains(" typ relay")),
        "dc-tcp" => filter_candidates(&offer, |l| l.contains(" tcp ")),
        _ => offer,
    };
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
    if what == "simulcast" {
        let mid = video.expect("video");
        let pt = peer.payload_type(mid, Codec::Vp8).expect("vp8");
        let mut i = 0u64;
        loop {
            let t = MediaTime::new(i * 3000, Frequency::NINETY_KHZ);
            // A VP8 key frame header then filler, at three sizes.
            for (rid, size) in [("h", 6000usize), ("m", 2500), ("l", 700)] {
                let mut f = vec![0x10u8, 0x02, 0x00, 0x9d, 0x01, 0x2a, 0x40, 0x01, 0xf0, 0x00];
                f.resize(size, (i % 251) as u8);
                peer.write_simulcast(mid, rid, pt, Instant::now(), t, &f)
                    .expect("write");
            }
            i += 1;
            if let Ok(Got::Data(d)) = rx.recv_timeout(Duration::from_millis(33)) {
                let s = String::from_utf8_lossy(&d).to_string();
                let n = |k: &str| -> u64 {
                    s.split_whitespace()
                        .find_map(|kv| kv.strip_prefix(k).and_then(|v| v.parse().ok()))
                        .unwrap_or(0)
                };
                if n("h=") > 100 && n("m=") > 50 && n("l=") > 30 && s.contains("ssrcs=3") {
                    println!("ok: simulcast: the answerer received three RID streams ({s})");
                    break;
                }
            }
            assert!(
                Instant::now() < deadline,
                "simulcast not received (sent {i} frames)"
            );
        }
        peer.close();
        return;
    }
    if what.starts_with("dc") {
        for i in 0..100 {
            let msg = format!("only message {i}");
            // `Ok(false)`: the SCTP send buffer is full; wait for it to drain and retry.
            while !peer.send(ch, msg.as_bytes(), i % 2 == 0).expect("send") {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        let mut n = 0;
        while n < 100 {
            if let Got::Data(d) = next() {
                assert_eq!(d, format!("only message {n}").into_bytes(), "ordered echo");
                n += 1;
            }
        }
        println!("ok: 100 data channel messages echoed in order ({what})");
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

fn turn(udp: SocketAddr, relay: &str, user: &str, pass: &str, streams: &[String]) {
    let auth = static_auth("only", [(user, pass)]);
    let cfg =
        TurnConfig::new("only", auth, relay.parse().expect("relay ip")).allow_private_peers(true);
    let turn = TurnServer::new(cfg);
    let mut c = Config::default();
    c.udp_idle_timeout = Duration::from_secs(600);
    let mut b = Engine::builder()
        .config(c)
        .listen(Listener::udp(udp).threads(1).serve(turn.clone()));
    if let Some(tcp) = streams.first() {
        b = b.listen(
            Listener::tcp(tcp.parse().expect("tcp addr"))
                .threads(1)
                .serve(turn.stream()),
        );
    }
    if let Some(tl) = streams.get(1) {
        let ck = only_x509::generate_simple_self_signed(["localhost"]).expect("cert");
        let scfg = tls::ServerConfig::builder(
            vec![tls::Certificate::from_der(ck.0.as_der().to_vec())],
            tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
        )
        .build()
        .expect("tls config");
        b = b.listen(
            Listener::tcp(tl.parse().expect("tls addr"))
                .threads(1)
                .serve(tls::Tls::server(scfg, turn.stream())),
        );
    }
    let engine = Arc::new(b.build().expect("engine"));
    turn.set_engine(&engine);
    eprintln!("turn: listening on {udp} {streams:?}, relaying from {relay}");
    engine.run().expect("run");
}

/// A blocking transport to a TURN server for the client mode.
enum Wire {
    Udp(std::net::UdpSocket, SocketAddr),
    Tcp(TcpStream),
    Tls(Box<tls::stream::Stream<TcpStream>>),
}

impl Wire {
    fn send(&mut self, m: &[u8]) {
        match self {
            Wire::Udp(s, to) => {
                s.send_to(m, *to).expect("send");
            }
            Wire::Tcp(s) => s.write_all(m).expect("write"),
            Wire::Tls(s) => {
                s.write_all(m).expect("write");
                s.flush().expect("flush");
            }
        }
    }

    /// Bytes from the server (a datagram, or what the stream had).
    fn recv(&mut self, buf: &mut [u8]) -> Option<usize> {
        let r = match self {
            Wire::Udp(s, _) => s.recv(buf),
            Wire::Tcp(s) => s.read(buf),
            Wire::Tls(s) => s.read(buf),
        };
        match r {
            Ok(n) => Some(n),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                None
            }
            Err(e) => panic!("read: {e}"),
        }
    }
}

fn turn_client(transport: &str, server: &str, user: &str, pass: &str) {
    let addr: SocketAddr = server.parse().expect("server addr");
    let short = Some(Duration::from_millis(20));
    let wire = match transport {
        "udp" => {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            s.set_read_timeout(short).expect("timeout");
            Wire::Udp(s, addr)
        }
        "tcp" | "tls" => {
            let s = TcpStream::connect(addr).expect("connect");
            s.set_read_timeout(short).expect("timeout");
            s.set_nodelay(true).expect("nodelay");
            if transport == "tcp" {
                Wire::Tcp(s)
            } else {
                let cfg = tls::ClientConfig::builder()
                    .insecure_skip_verify()
                    .build()
                    .expect("tls config");
                Wire::Tls(Box::new(
                    tls::stream::Stream::client(&cfg, "localhost", s).expect("tls"),
                ))
            }
        }
        t => panic!("unknown transport {t}"),
    };
    let mut wire = wire;
    let stream = transport != "udp";
    let mut c = Client::new(
        ClientConfig::new(addr, user, pass).stream(stream),
        Instant::now(),
    );
    // The peer: a local UDP socket echoing what reaches it.
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer");
    let pa = peer.local_addr().expect("peer addr");
    std::thread::spawn(move || {
        let mut b = [0u8; 2048];
        while let Ok((n, from)) = peer.recv_from(&mut b) {
            let _ = peer.send_to(&b[..n], from);
        }
    });
    let mut reader = FrameReader::new();
    let mut buf = vec![0u8; 65536];
    let mut got: Vec<Vec<u8>> = Vec::new();
    let mut relayed = None;
    let mut sent = 0u32;
    let deadline = Instant::now() + Duration::from_secs(20);
    while got.len() < 20 {
        assert!(
            Instant::now() < deadline,
            "timed out: {c:?}, {} back",
            got.len()
        );
        while let Some(m) = c.poll_transmit() {
            wire.send(&m);
        }
        if let Some(n) = wire.recv(&mut buf) {
            assert!(n > 0, "server closed the connection");
            let mut msgs = Vec::new();
            if stream {
                reader
                    .push(&buf[..n], |m| msgs.push(m.to_vec()))
                    .expect("framing");
            } else {
                msgs.push(buf[..n].to_vec());
            }
            for m in msgs {
                if let Some((from, d)) = c.handle_input(Instant::now(), &m) {
                    assert_eq!(from, pa);
                    got.push(d.to_vec());
                }
            }
        }
        c.handle_timeout(Instant::now());
        while let Some(e) = c.poll_event() {
            match e {
                ClientEvent::Allocated {
                    relayed: r,
                    mapped,
                    lifetime,
                } => {
                    eprintln!("turn-client: allocated {r} (mapped {mapped:?}, {lifetime:?})");
                    relayed = Some(r);
                }
                e => panic!("turn-client: {e:?}"),
            }
        }
        if relayed.is_some() && sent < 20 && sent as usize <= got.len() {
            let msg = format!("through the relay {sent}");
            assert!(c.send_to(Instant::now(), pa, msg.as_bytes()));
            sent += 1;
        }
    }
    for (i, d) in got.iter().enumerate() {
        assert_eq!(d, format!("through the relay {i}").as_bytes());
    }
    c.close(Instant::now());
    let end = Instant::now() + Duration::from_secs(5);
    while c.state() != ClientState::Closed && Instant::now() < end {
        while let Some(m) = c.poll_transmit() {
            wire.send(&m);
        }
        if let Some(n) = wire.recv(&mut buf) {
            if n == 0 {
                break;
            }
            if stream {
                let _ = reader.push(&buf[..n], |m| {
                    c.handle_input(Instant::now(), m);
                });
            } else {
                c.handle_input(Instant::now(), &buf[..n]);
            }
        }
        c.handle_timeout(Instant::now());
    }
    println!(
        "ok: only_turn client over {transport}: allocation {}, channel, 20 datagrams relayed both ways, deleted ({:?})",
        relayed.expect("relayed"),
        c.state()
    );
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("server") => server(a[2].parse().expect("udp"), a[3].parse().expect("http")),
        Some("client") => client(&a[2], &a[3], &a[4..]),
        Some("turn") => turn(a[2].parse().expect("udp"), &a[3], &a[4], &a[5], &a[6..]),
        Some("turn-client") => turn_client(&a[2], &a[3], &a[4], &a[5]),
        _ => eprintln!("usage: webrtc-interop server|client|turn|turn-client ..."),
    }
}
